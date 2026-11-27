import { createTarPolicy, sanitizeMode } from './policy.mjs';
import { ChunkReader, openArchiveInput } from './stream.mjs';
import {
  assertValidTarPath,
  collisionKey,
  resolveRootRelativeWithinRoot,
  resolveSymlinkWithinRoot,
  validateHardlinkTarget,
  validateSymlinkTarget
} from './path-security.mjs';
import {
  isZeroBlock,
  parseGnuNamePayload,
  parsePaxPayload,
  parsePaxSize,
  parseTarHeader,
  paxRecordsObject,
  typeflagName
} from './tar-format.mjs';
import { TARCAGE_ERROR_CODES as C, TarCageError, TarFormatError, TarLimitError, TarPathError } from './errors.mjs';

const METADATA_TYPES = new Set(['x', 'g', 'L', 'K']);
const SPECIAL_TYPES = new Set(['3', '4', '6']);
const INHERITED_PAX_IGNORE = new Set(['path', 'linkpath', 'size']);

function paddingSize(size) {
  return (512 - (size % 512)) % 512;
}

function warning(code, message, path, offset) {
  return Object.freeze({ severity: 'warning', code, message, path, offset });
}

function entryDepth(name) {
  return name === '.' ? 0 : name.split('/').length;
}

class EntryLayoutTracker {
  constructor(policy) {
    this.policy = policy;
    this.root = { children: new Map(), entryType: null, explicit: false };
    this.casePrefixes = new Map();
    this.rootDirectorySeen = false;
  }

  add(entry) {
    if (entry.name === '.') {
      if (entry.type !== 'directory') {
        throw new TarPathError(C.MALFORMED_ARCHIVE, 'only a directory entry can use the archive root path', { path: entry.name });
      }
      if (this.rootDirectorySeen && this.policy.rejectDuplicates) {
        throw new TarPathError(C.DUPLICATE_PATH, 'duplicate archive root directory entry', { path: entry.name });
      }
      this.rootDirectorySeen = true;
      return;
    }

    const segments = entry.name.split('/');
    let node = this.root;
    let prefix = '';
    for (const segment of segments) {
      if (node.entryType && node.entryType !== 'directory') {
        throw new TarPathError(C.OVERLAPPING_ENTRIES, 'entry path passes through a non-directory archive entry', {
          path: entry.name,
          ancestor: prefix
        });
      }
      prefix = prefix === '' ? segment : prefix + '/' + segment;
      if (this.policy.rejectCaseCollisions) {
        const key = collisionKey(prefix);
        const prior = this.casePrefixes.get(key);
        if (prior !== undefined && prior !== prefix) {
          throw new TarPathError(C.CASE_COLLISION, 'entry path collides with another path on case-insensitive or normalizing filesystems', {
            path: entry.name,
            collidesWith: prior
          });
        }
        this.casePrefixes.set(key, prefix);
      }
      if (!node.children.has(segment)) {
        node.children.set(segment, { children: new Map(), entryType: null, explicit: false });
      }
      node = node.children.get(segment);
    }

    if (node.explicit) {
      if (this.policy.rejectDuplicates || node.entryType !== 'directory' || entry.type !== 'directory') {
        throw new TarPathError(C.DUPLICATE_PATH, 'duplicate archive entry path', { path: entry.name });
      }
    }
    if (node.children.size > 0 && entry.type !== 'directory') {
      throw new TarPathError(C.OVERLAPPING_ENTRIES, 'non-directory entry overlaps existing child entries', { path: entry.name });
    }
    if (!node.explicit) {
      node.entryType = entry.type;
      node.explicit = true;
    }
  }
}

function compatibleTextOverride(base, override) {
  if (base === override) return true;
  if (base.length === 0) return true;
  return base.length >= 90 && override.startsWith(base);
}

function reconcileTextOverride(field, base, gnuValue, paxValue, details) {
  let output = base;
  if (gnuValue !== null) output = gnuValue;
  if (paxValue !== undefined) {
    if (gnuValue !== null && gnuValue !== paxValue) {
      throw new TarFormatError(C.PAX_CONFLICT, 'GNU long metadata and PAX ' + field + ' disagree', details);
    }
    if (!compatibleTextOverride(base, paxValue)) {
      throw new TarFormatError(C.PAX_CONFLICT, 'ustar header and PAX ' + field + ' disagree', details);
    }
    output = paxValue;
  }
  return output;
}

function mergePax(globalRecords, localRecords) {
  const merged = new Map();
  if (globalRecords) {
    for (const [key, value] of globalRecords) {
      if (!INHERITED_PAX_IGNORE.has(key)) merged.set(key, value);
    }
  }
  if (localRecords) {
    for (const [key, value] of localRecords) merged.set(key, value);
  }
  return merged;
}

function normalizeEntryType(header, policy) {
  const kind = typeflagName(header.typeflag);
  if (kind === 'unknown') {
    throw new TarFormatError(C.UNSUPPORTED_TYPEFLAG, 'unknown or malicious typeflag is blocked', {
      path: header.name,
      offset: header.offset,
      typeflag: header.typeflag
    });
  }
  if (SPECIAL_TYPES.has(header.typeflag)) {
    if (!policy.allowSpecialFiles) {
      throw new TarFormatError(C.SPECIAL_FILE, 'device and FIFO entries are blocked by default', {
        path: header.name,
        offset: header.offset,
        typeflag: header.typeflag
      });
    }
    return { type: kind, contiguous: false };
  }
  if (kind === 'contiguous-file') {
    if (!policy.allowContiguousFiles) {
      throw new TarFormatError(C.UNSUPPORTED_TYPEFLAG, 'contiguous file entries are blocked by default', {
        path: header.name,
        offset: header.offset,
        typeflag: header.typeflag
      });
    }
    return { type: 'file', contiguous: true };
  }
  if (kind === 'symlink' && !policy.allowSymlinks) {
    throw new TarFormatError(C.SYMLINK_BLOCKED, 'symlink entries are blocked by default', {
      path: header.name,
      offset: header.offset
    });
  }
  if (kind === 'hardlink' && !policy.allowHardlinks) {
    throw new TarFormatError(C.HARDLINK_BLOCKED, 'hardlink entries are blocked by default', {
      path: header.name,
      offset: header.offset
    });
  }
  return { type: kind, contiguous: false };
}

async function consumeEntryData(reader, size, policy, context, sink) {
  let closeCalled = false;
  const closeSink = async () => {
    if (!closeCalled && sink && typeof sink.close === 'function') {
      closeCalled = true;
      await sink.close();
    }
  };

  try {
    let remaining = size;
    while (remaining > 0) {
      const chunk = await reader.readSome(Math.min(64 * 1024, remaining));
      if (chunk === null) {
        throw new TarFormatError(C.TRUNCATED_ARCHIVE, context + ' data is truncated', { expected: size, actual: size - remaining });
      }
      if (sink && typeof sink.write === 'function') await sink.write(chunk);
      remaining -= chunk.length;
    }

    const padding = paddingSize(size);
    if (padding > 0) {
      if (policy.strictPadding) {
        const bytes = await reader.readExact(padding, context + ' padding');
        for (const byte of bytes) {
          if (byte !== 0) {
            throw new TarFormatError(C.PADDING_CORRUPT, 'entry padding contains non-zero bytes', { path: context });
          }
        }
      } else {
        await reader.skipExact(padding, context + ' padding');
      }
    }
    await closeSink();
  } catch (error) {
    await closeSink().catch(() => {});
    throw error;
  }
}

function validateEntryLinks(entries, policy) {
  const symlinks = new Map();
  for (const entry of entries) {
    if (entry.type === 'symlink') {
      validateSymlinkTarget(entry.name, entry.linkname, policy);
      symlinks.set(entry.name, entry.linkname);
    } else if (entry.type === 'hardlink') {
      const normalized = validateHardlinkTarget(entry.name, entry.linkname, policy);
      if (normalized === entry.name) {
        throw new TarFormatError(C.LINK_INVALID, 'hardlink target cannot be the entry itself', { path: entry.name, linkname: entry.linkname });
      }
      entry.linkname = normalized;
    }
  }

  for (const [name, target] of symlinks) {
    try {
      entryLinkResolution: {
        resolveSymlinkWithinRoot(name, target, symlinks, policy);
      }
    } catch (error) {
      if (error instanceof TarCageError) {
        error.details = { ...(error.details || {}), path: name, linkname: target };
      }
      throw error;
    }
  }

  for (const entry of entries) {
    if (entry.type !== 'hardlink') continue;
    try {
      const resolved = resolveRootRelativeWithinRoot(entry.linkname, symlinks, policy);
      if (resolved === '.') {
        throw new TarFormatError(C.LINK_INVALID, 'hardlink target cannot resolve to the archive root', { path: entry.name, linkname: entry.linkname });
      }
    } catch (error) {
      if (error instanceof TarCageError) {
        error.details = { ...(error.details || {}), path: entry.name, linkname: entry.linkname };
      }
      throw error;
    }
  }
}

function makeStats(entries, state, metadataBytes, metadataEntries, maxDepth, endMarkers, digest) {
  const files = entries.filter((entry) => entry.type === 'file').length;
  const directories = entries.filter((entry) => entry.type === 'directory').length;
  const symlinks = entries.filter((entry) => entry.type === 'symlink').length;
  const hardlinks = entries.filter((entry) => entry.type === 'hardlink').length;
  const special = entries.length - files - directories - symlinks - hardlinks;
  const totalEntryBytes = entries.reduce((total, entry) => total + entry.size, 0);
  return {
    entries: entries.length,
    files,
    directories,
    symlinks,
    hardlinks,
    special,
    compressedBytes: state.compressedBytes,
    uncompressedBytes: state.uncompressedBytes,
    totalEntryBytes,
    maxDepth,
    metadataBytes,
    metadataEntries,
    endMarkers,
    compressionRatio: state.compressed && state.compressedBytes > 0 ? state.uncompressedBytes / state.compressedBytes : null,
    uncompressedSha256: digest || null
  };
}

function buildResult(entries, findings, state, formats, metadataBytes, metadataEntries, maxDepth, endMarkers, digest) {
  const formatList = [...formats];
  let format = 'unknown';
  if (formatList.includes('pax')) format = 'pax';
  else if (formatList.includes('gnu')) format = 'gnu';
  else if (formatList.includes('ustar')) format = 'ustar';
  else if (formatList.includes('v7')) format = 'v7';
  return {
    format,
    compressed: state.compressed,
    entries,
    findings,
    stats: makeStats(entries, state, metadataBytes, metadataEntries, maxDepth, endMarkers, digest)
  };
}

export async function scanWithPolicy(input, policy, hooks = {}) {
  const opened = await openArchiveInput(input, policy);
  const reader = new ChunkReader(opened.stream, opened.state.compressed);
  const entries = [];
  const findings = [];
  const formats = new Set();
  const layout = new EntryLayoutTracker(policy);
  let metadataBytes = 0;
  let metadataEntries = 0;
  let maxDepth = 0;
  let endMarkers = 0;
  let pendingPax = null;
  let pendingGnuName = null;
  let pendingGnuLink = null;
  let globalPax = null;

  const partial = () => buildResult(
    entries,
    findings,
    opened.state,
    formats,
    metadataBytes,
    metadataEntries,
    maxDepth,
    endMarkers,
    null
  );

  try {
    while (true) {
      const blockOffset = reader.bytesRead;
      const block = await reader.readBlock(512, 'tar header');
      if (block.length === 0) break;
      if (isZeroBlock(block)) {
        endMarkers += 1;
        continue;
      }
      if (endMarkers > 0) {
        if (endMarkers >= 2) {
          throw new TarFormatError(C.TRAILING_DATA, 'non-zero data follows the tar end-of-archive marker', { offset: blockOffset });
        }
        throw new TarFormatError(C.MALFORMED_ARCHIVE, 'a single zero block is followed by another header', { offset: blockOffset });
      }

      const header = parseTarHeader(block, blockOffset, policy);
      formats.add(header.format);
      if (header.signedChecksumLegacy) {
        findings.push(warning(C.CHECKSUM_MISMATCH, 'legacy signed checksum accepted because allowSignedChecksums is true', header.name, blockOffset));
      }

      if (METADATA_TYPES.has(header.typeflag)) {
        metadataEntries += 1;
        if (metadataEntries > policy.maxMetadataEntries) {
          throw new TarLimitError(C.METADATA_LIMIT, 'too many PAX or GNU metadata entries', {
            metadataEntries,
            maxMetadataEntries: policy.maxMetadataEntries,
            offset: blockOffset
          });
        }
        if (header.size > policy.maxMetadataBytes || metadataBytes + header.size > policy.maxMetadataBytes) {
          throw new TarLimitError(C.METADATA_LIMIT, 'PAX or GNU metadata exceeds maxMetadataBytes', {
            metadataBytes: metadataBytes + header.size,
            maxMetadataBytes: policy.maxMetadataBytes,
            offset: blockOffset
          });
        }
        metadataBytes += header.size;
        const payload = await reader.readExact(header.size, 'metadata payload');
        const padding = paddingSize(header.size);
        if (padding > 0) {
          const pad = await reader.readExact(padding, 'metadata padding');
          if (policy.strictPadding) {
            for (const byte of pad) {
              if (byte !== 0) throw new TarFormatError(C.PADDING_CORRUPT, 'metadata padding contains non-zero bytes', { offset: blockOffset });
            }
          }
        }

        if (header.typeflag === 'x') {
          if (pendingPax !== null) {
            throw new TarFormatError(C.PAX_FORMAT, 'multiple per-entry PAX headers apply to one tar entry', { offset: blockOffset });
          }
          formats.add('pax');
          pendingPax = parsePaxPayload(payload, { offset: blockOffset });
        } else if (header.typeflag === 'g') {
          formats.add('pax');
          const records = parsePaxPayload(payload, { offset: blockOffset });
          for (const key of INHERITED_PAX_IGNORE) {
            if (records.has(key)) {
              throw new TarFormatError(C.PAX_FORMAT, 'security-sensitive PAX key cannot be set globally', { offset: blockOffset, key });
            }
          }
          if (globalPax === null) globalPax = new Map();
          for (const [key, value] of records) {
            if (globalPax.has(key)) {
              throw new TarFormatError(C.PAX_FORMAT, 'duplicate global PAX key', { offset: blockOffset, key });
            }
            globalPax.set(key, value);
          }
        } else if (header.typeflag === 'L') {
          if (pendingGnuName !== null) {
            throw new TarFormatError(C.GNU_METADATA, 'multiple GNU longname blocks apply to one tar entry', { offset: blockOffset });
          }
          formats.add('gnu');
          pendingGnuName = parseGnuNamePayload(payload, 'GNU longname', { offset: blockOffset });
        } else if (header.typeflag === 'K') {
          if (pendingGnuLink !== null) {
            throw new TarFormatError(C.GNU_METADATA, 'multiple GNU longlink blocks apply to one tar entry', { offset: blockOffset });
          }
          formats.add('gnu');
          pendingGnuLink = parseGnuNamePayload(payload, 'GNU longlink', { offset: blockOffset });
        }
        continue;
      }

      const typeInfo = normalizeEntryType(header, policy);
      const pax = mergePax(globalPax, pendingPax);
      let size = header.size;
      if (pax.has('size')) {
        const paxSize = parsePaxSize(pax.get('size'), { path: header.name, offset: blockOffset });
        if (paxSize !== header.size) {
          throw new TarFormatError(C.PAX_CONFLICT, 'ustar size field and PAX size disagree', {
            path: header.name,
            offset: blockOffset,
            headerSize: header.size,
            paxSize
          });
        }
        size = paxSize;
      }
      if (size > policy.maxEntryBytes) {
        throw new TarLimitError(C.ENTRY_SIZE_LIMIT, 'entry exceeds maxEntryBytes', {
          path: header.name,
          offset: blockOffset,
          size,
          maxEntryBytes: policy.maxEntryBytes
        });
      }

      const name = reconcileTextOverride('path', header.name, pendingGnuName, pax.get('path'), { path: header.name, offset: blockOffset });
      const validation = assertValidTarPath(name, policy);
      if (validation.normalized === '.' && typeInfo.type !== 'directory') {
        throw new TarPathError(C.MALFORMED_ARCHIVE, 'non-directory entry cannot use the archive root path', { path: name, offset: blockOffset });
      }
      if (validation.hadTrailingSlash && typeInfo.type !== 'directory') {
        throw new TarPathError(C.MALFORMED_ARCHIVE, 'non-directory entry cannot end in a slash', { path: name, offset: blockOffset });
      }

      const linkname = reconcileTextOverride('linkpath', header.linkname, pendingGnuLink, pax.get('linkpath'), { path: validation.normalized, offset: blockOffset });
      if ((typeInfo.type === 'symlink' || typeInfo.type === 'hardlink') && linkname.length === 0) {
        throw new TarFormatError(C.LINK_INVALID, 'link entry has an empty link target', { path: validation.normalized, offset: blockOffset });
      }
      if (typeInfo.type !== 'symlink' && typeInfo.type !== 'hardlink' && linkname.length !== 0) {
        throw new TarFormatError(C.MALFORMED_ARCHIVE, 'non-link entry cannot carry a link target', { path: validation.normalized, offset: blockOffset });
      }
      if ((typeInfo.type === 'directory' || typeInfo.type === 'symlink' || typeInfo.type === 'hardlink' || SPECIAL_TYPES.has(header.typeflag)) && size !== 0) {
        throw new TarFormatError(C.MALFORMED_ARCHIVE, 'non-regular tar entry has a non-zero size', { path: validation.normalized, offset: blockOffset, size });
      }

      const rawMode = header.mode;
      const mode = sanitizeMode(rawMode, typeInfo.type, policy);
      if (!policy.allowSpecialModes && (rawMode & 0o7000) !== 0) {
        findings.push(warning(C.MODE_STRIPPED, 'setuid, setgid, or sticky mode bits were stripped', validation.normalized, blockOffset));
      }

      const entry = {
        index: entries.length,
        name: validation.normalized,
        type: typeInfo.type,
        size,
        mode,
        rawMode,
        mtime: header.mtime,
        uid: header.uid,
        gid: header.gid,
        uname: header.uname,
        gname: header.gname,
        linkname,
        offset: blockOffset,
        headerFormat: header.format,
        contiguous: typeInfo.contiguous,
        pax: paxRecordsObject(pax)
      };

      if (entries.length >= policy.maxEntries) {
        throw new TarLimitError(C.ENTRY_LIMIT, 'archive exceeds maxEntries', {
          entries: entries.length + 1,
          maxEntries: policy.maxEntries,
          path: entry.name
        });
      }
      layout.add(entry);
      entries.push(entry);
      maxDepth = Math.max(maxDepth, entryDepth(entry.name));

      pendingPax = null;
      pendingGnuName = null;
      pendingGnuLink = null;

      let sink = null;
      if (typeof hooks.onEntry === 'function') sink = await hooks.onEntry(entry);
      await consumeEntryData(reader, size, policy, 'entry ' + entry.name, sink);
    }

    if (pendingPax !== null || pendingGnuName !== null || pendingGnuLink !== null) {
      throw new TarFormatError(C.MALFORMED_ARCHIVE, 'PAX or GNU metadata is not followed by a tar entry', { offset: reader.bytesRead });
    }
    if (policy.strictEof && endMarkers < 2) {
      throw new TarFormatError(C.EOF_MISSING, 'tar archive is missing the required two zero end blocks', { endMarkers });
    }
    validateEntryLinks(entries, policy);
    const digest = opened.finish();
    return buildResult(entries, findings, opened.state, formats, metadataBytes, metadataEntries, maxDepth, endMarkers, digest);
  } catch (error) {
    if (error instanceof TarCageError && error.partial === undefined) {
      Object.defineProperty(error, 'partial', {
        value: partial(),
        enumerable: false,
        configurable: true
      });
    }
    throw error;
  } finally {
    opened.destroy();
  }
}

export function validateExtractionLayout(entries, policy) {
  const tracker = new EntryLayoutTracker(policy);
  for (const entry of entries) tracker.add(entry);
  validateEntryLinks(entries, policy);
}

export async function scanTar(input, options = {}, hooks = {}) {
  return scanWithPolicy(input, createTarPolicy(options), hooks);
}

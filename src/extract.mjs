import { constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { inspectTar } from './api.mjs';
import { scanWithPolicy, validateExtractionLayout } from './parser.mjs';
import { createTarPolicy } from './policy.mjs';
import { resolveSymlinkWithinRoot } from './path-security.mjs';
import { TARCAGE_ERROR_CODES as C, TarCageError, TarExtractionError, TarInputError } from './errors.mjs';

function isMissing(error) {
  return error && (error.code === 'ENOENT' || error.code === 'ENOTDIR');
}

function ioError(message, details, cause) {
  return new TarExtractionError(C.EXTRACTION_IO, message, details, cause);
}

function insidePath(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith('..' + path.sep));
}

function targetPath(root, archivePath) {
  const target = path.resolve(root, ...archivePath.split('/'));
  if (!insidePath(root, target)) {
    throw new TarExtractionError(C.EXTRACTION_CONFINEMENT, 'resolved extraction path escapes the destination root', { path: archivePath });
  }
  return target;
}

function parentArchivePath(archivePath) {
  const index = archivePath.lastIndexOf('/');
  return index === -1 ? '' : archivePath.slice(0, index);
}

async function lstatOrNull(target) {
  try {
    return await fs.lstat(target);
  } catch (error) {
    if (isMissing(error)) return null;
    throw ioError('cannot inspect extraction path', { target }, error);
  }
}

async function verifyInsideRoot(root, target, archivePath) {
  let real;
  try {
    real = await fs.realpath(target);
  } catch (error) {
    throw ioError('cannot resolve extraction path', { path: archivePath }, error);
  }
  if (!insidePath(root, real)) {
    throw new TarExtractionError(C.EXTRACTION_CONFINEMENT, 'resolved on-disk path escapes the extraction root', { path: archivePath });
  }
}

async function prepareDestination(destDir) {
  if (typeof destDir !== 'string' || destDir.length === 0) {
    throw new TarInputError(C.INVALID_INPUT, 'destination directory must be a non-empty path string', { inputType: typeof destDir });
  }
  const resolved = path.resolve(destDir);
  let existed = true;
  let stat;
  try {
    stat = await fs.lstat(resolved);
  } catch (error) {
    if (!isMissing(error)) throw ioError('cannot inspect destination directory', undefined, error);
    existed = false;
  }

  if (existed) {
    if (stat.isSymbolicLink()) {
      throw new TarExtractionError(C.EXTRACTION_SYMLINK, 'destination root cannot be a symlink');
    }
    if (!stat.isDirectory()) {
      throw new TarExtractionError(C.EXTRACTION_REFUSED, 'destination exists and is not a directory');
    }
  } else {
    try {
      await fs.mkdir(resolved, { recursive: true, mode: 0o755 });
    } catch (error) {
      throw ioError('cannot create destination directory', undefined, error);
    }
  }

  let realRoot;
  try {
    realRoot = await fs.realpath(resolved);
  } catch (error) {
    throw ioError('cannot resolve destination directory', undefined, error);
  }
  return { resolved, realRoot, createdRoot: !existed };
}

async function secureEnsureDirectory(root, archivePath, state) {
  if (!archivePath || archivePath === '.') return root;
  let current = root;
  for (const segment of archivePath.split('/')) {
    current = path.join(current, segment);
    if (!insidePath(root, current)) {
      throw new TarExtractionError(C.EXTRACTION_CONFINEMENT, 'directory path escapes the extraction root', { path: archivePath });
    }

    let stat = await lstatOrNull(current);
    if (stat === null) {
      try {
        await fs.mkdir(current, { mode: 0o755 });
      } catch (error) {
        throw ioError('cannot create extraction directory', { path: archivePath }, error);
      }
      state.createdDirs.push(current);
      state.createdDirSet.add(current);
      stat = await fs.lstat(current);
    }

    if (stat.isSymbolicLink()) {
      throw new TarExtractionError(C.EXTRACTION_SYMLINK, 'extraction refuses to follow a symlinked directory', { path: archivePath });
    }
    if (!stat.isDirectory()) {
      throw new TarExtractionError(C.EXTRACTION_CONFINEMENT, 'extraction parent component is not a directory', { path: archivePath });
    }
    await verifyInsideRoot(root, current, archivePath);
  }
  return current;
}

async function assertNoExisting(target, archivePath) {
  const existing = await lstatOrNull(target);
  if (existing !== null) {
    throw new TarExtractionError(C.EXTRACTION_OVERWRITE, 'extraction would overwrite or replace an existing filesystem object', { path: archivePath });
  }
}

async function chmodCreated(target, mode, archivePath) {
  if (process.platform === 'win32') return;
  try {
    await fs.chmod(target, mode);
  } catch (error) {
    throw ioError('cannot apply sanitized permissions', { path: archivePath, mode }, error);
  }
}

function stripEntryName(name, stripComponents) {
  if (name === '.') return null;
  if (stripComponents === 0) return name;
  const parts = name.split('/');
  if (parts.length <= stripComponents) return null;
  return parts.slice(stripComponents).join('/');
}

function validateHardlinkExtractionOrder(planned) {
  const resolvable = new Map();
  for (const entry of planned) {
    if (entry.type === 'file') {
      resolvable.set(entry.name, entry.name);
      continue;
    }
    if (entry.type !== 'hardlink') continue;
    const ultimate = resolvable.get(entry.linkname);
    if (ultimate === undefined) {
      throw new TarExtractionError(C.EXTRACTION_REFUSED, 'hardlink target must be an earlier regular file or resolvable hardlink from the same archive', {
        path: entry.name,
        linkname: entry.linkname
      });
    }
    resolvable.set(entry.name, ultimate);
  }
}

function planEntries(entries, policy) {
  const planned = [];
  let skipped = 0;
  for (const entry of entries) {
    const name = stripEntryName(entry.name, policy.stripComponents);
    if (name === null) {
      skipped += 1;
      continue;
    }
    if (entry.type !== 'file' && entry.type !== 'directory' && entry.type !== 'symlink' && entry.type !== 'hardlink') {
      throw new TarExtractionError(C.EXTRACTION_REFUSED, 'device, FIFO, and other special entries are never extracted', { path: entry.name });
    }
    const transformed = { ...entry, name };
    if (transformed.type === 'hardlink') {
      const linkname = stripEntryName(transformed.linkname, policy.stripComponents);
      if (linkname === null) {
        throw new TarExtractionError(C.EXTRACTION_REFUSED, 'hardlink target is removed by stripComponents', {
          path: entry.name,
          linkname: entry.linkname
        });
      }
      transformed.linkname = linkname;
    }
    planned.push(transformed);
  }
  validateExtractionLayout(planned, policy);
  validateHardlinkExtractionOrder(planned);
  return { planned, skipped };
}

function dryRunReport(planned, skipped, destDir, preflight) {
  const count = (type) => planned.filter((entry) => entry.type === type).length;
  return {
    dryRun: true,
    destDir: path.resolve(destDir),
    extracted: planned.length,
    skipped,
    files: count('file'),
    directories: count('directory'),
    symlinks: count('symlink'),
    hardlinks: count('hardlink'),
    bytesWritten: 0,
    bytesPlanned: planned.reduce((total, entry) => total + entry.size, 0),
    uncompressedSha256: preflight.stats.uncompressedSha256
  };
}

async function createFileSink(root, entry, state) {
  await secureEnsureDirectory(root, parentArchivePath(entry.name), state);
  const target = targetPath(root, entry.name);
  await assertNoExisting(target, entry.name);
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0);
  let handle;
  try {
    handle = await fs.open(target, flags, entry.mode);
  } catch (error) {
    throw ioError('cannot create output file', { path: entry.name }, error);
  }
  state.createdFiles.push(target);
  state.bytesWritten += 0;

  let closed = false;
  return {
    async write(chunk) {
      try {
        await handle.write(chunk);
        state.bytesWritten += chunk.length;
      } catch (error) {
        throw ioError('cannot write output file', { path: entry.name }, error);
      }
    },
    async close() {
      if (closed) return;
      closed = true;
      try {
        await handle.close();
      } catch (error) {
        throw ioError('cannot close output file', { path: entry.name }, error);
      }
      await chmodCreated(target, entry.mode, entry.name);
    }
  };
}

async function extractDirectory(root, entry, state) {
  const target = await secureEnsureDirectory(root, entry.name, state);
  if (state.createdDirSet.has(target)) await chmodCreated(target, entry.mode, entry.name);
  state.directories += 1;
  state.extracted += 1;
}

async function extractSymlink(root, entry, state) {
  await secureEnsureDirectory(root, parentArchivePath(entry.name), state);
  const target = targetPath(root, entry.name);
  await assertNoExisting(target, entry.name);
  try {
    await fs.symlink(entry.linkname, target);
  } catch (error) {
    throw ioError('cannot create symlink', { path: entry.name, linkname: entry.linkname }, error);
  }
  state.createdFiles.push(target);
  state.symlinks += 1;
  state.extracted += 1;
}

async function extractHardlink(root, entry, state) {
  await secureEnsureDirectory(root, parentArchivePath(entry.name), state);
  const source = targetPath(root, entry.linkname);
  const target = targetPath(root, entry.name);
  await assertNoExisting(target, entry.name);
  const sourceStat = await lstatOrNull(source);
  if (sourceStat === null) {
    throw new TarExtractionError(C.EXTRACTION_REFUSED, 'hardlink target does not exist inside the extraction root', { path: entry.name, linkname: entry.linkname });
  }
  if (sourceStat.isSymbolicLink() || !sourceStat.isFile()) {
    throw new TarExtractionError(C.EXTRACTION_REFUSED, 'hardlink target must be a regular non-symlink file', { path: entry.name, linkname: entry.linkname });
  }
  await verifyInsideRoot(root, source, entry.name);
  try {
    await fs.link(source, target);
  } catch (error) {
    throw ioError('cannot create hardlink', { path: entry.name, linkname: entry.linkname }, error);
  }
  state.createdFiles.push(target);
  state.hardlinks += 1;
  state.extracted += 1;
}

async function extractionSink(root, entry, policy, state) {
  const stripped = stripEntryName(entry.name, policy.stripComponents);
  if (stripped === null) {
    state.skipped += 1;
    return null;
  }
  const plannedEntry = { ...entry, name: stripped };
  if (plannedEntry.type === 'hardlink') {
    const linkname = stripEntryName(plannedEntry.linkname, policy.stripComponents);
    if (linkname === null) {
      throw new TarExtractionError(C.EXTRACTION_REFUSED, 'hardlink target is removed by stripComponents', {
        path: plannedEntry.name,
        linkname: plannedEntry.linkname
      });
    }
    plannedEntry.linkname = linkname;
  }
  if (plannedEntry.type === 'file') {
    state.files += 1;
    state.extracted += 1;
    return createFileSink(root, plannedEntry, state);
  }
  if (plannedEntry.type === 'directory') {
    await extractDirectory(root, plannedEntry, state);
    return null;
  }
  if (plannedEntry.type === 'symlink') {
    await extractSymlink(root, plannedEntry, state);
    return null;
  }
  if (plannedEntry.type === 'hardlink') {
    await extractHardlink(root, plannedEntry, state);
    return null;
  }
  throw new TarExtractionError(C.EXTRACTION_REFUSED, 'special entries are never extracted', { path: plannedEntry.name });
}

async function auditResolvedSymlinkTargets(root, planned, policy) {
  const symlinkMap = new Map();
  for (const entry of planned) {
    if (entry.type === 'symlink') symlinkMap.set(entry.name, entry.linkname);
  }
  for (const entry of planned) {
    if (entry.type !== 'symlink') continue;
    const resolved = resolveSymlinkWithinRoot(entry.name, entry.linkname, symlinkMap, policy);
    if (resolved === '.') continue;
    let current = root;
    for (const segment of resolved.split('/')) {
      current = path.join(current, segment);
      const stat = await lstatOrNull(current);
      if (stat && stat.isSymbolicLink()) {
        throw new TarExtractionError(C.EXTRACTION_SYMLINK, 'symlink target resolution crosses a pre-existing or unexpected disk symlink', {
          path: entry.name,
          linkname: entry.linkname
        });
      }
    }
  }
}

async function rollback(state) {
  for (const target of [...state.createdFiles].reverse()) {
    await fs.unlink(target).catch(() => {});
  }
  for (const target of [...state.createdDirs].reverse()) {
    await fs.rmdir(target).catch(() => {});
  }
  if (state.createdRoot) await fs.rmdir(state.rootResolved).catch(() => {});
}

export async function extractTar(input, destDir, options = {}) {
  const policy = createTarPolicy(options);
  const preflight = await inspectTar(input, policy);
  if (!preflight.safe) {
    throw new TarExtractionError(C.EXTRACTION_REFUSED, 'archive failed pre-flight security validation', {
      findings: preflight.findings
    });
  }

  const { planned, skipped } = planEntries(preflight.entries, policy);
  if (policy.dryRun) return dryRunReport(planned, skipped, destDir, preflight);

  const destination = await prepareDestination(destDir);
  const state = {
    rootResolved: destination.resolved,
    createdRoot: destination.createdRoot,
    createdFiles: [],
    createdDirs: [],
    createdDirSet: new Set(),
    extracted: 0,
    skipped: 0,
    files: 0,
    directories: 0,
    symlinks: 0,
    hardlinks: 0,
    bytesWritten: 0
  };

  try {
    const secondPass = await scanWithPolicy(input, policy, {
      onEntry: (entry) => extractionSink(destination.realRoot, entry, policy, state)
    });
    if (secondPass.stats.uncompressedSha256 !== preflight.stats.uncompressedSha256) {
      throw new TarExtractionError(C.INPUT_CHANGED, 'archive input changed between validation and extraction');
    }
    await auditResolvedSymlinkTargets(destination.realRoot, planned, policy);
    return {
      dryRun: false,
      destDir: destination.resolved,
      extracted: state.extracted,
      skipped: state.skipped,
      files: state.files,
      directories: state.directories,
      symlinks: state.symlinks,
      hardlinks: state.hardlinks,
      bytesWritten: state.bytesWritten,
      uncompressedSha256: secondPass.stats.uncompressedSha256
    };
  } catch (error) {
    await rollback(state);
    if (error instanceof TarCageError) throw error;
    throw ioError('extraction failed', undefined, error);
  }
}

import { createTarPolicy } from './policy.mjs';
import { TARCAGE_ERROR_CODES as C, TarLinkError, TarPathError } from './errors.mjs';

const CONTROL_RE = /[\p{Cc}\p{Cf}\u2028\u2029]/u;
const UNPAIRED_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;
const WINDOWS_INVALID_CHARACTER_RE = /[<>:"|?*]/;
const RESERVED_DEVICE_RE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9]|conin\$|conout\$)$/i;
const DRIVE_RE = /^[a-zA-Z]:/;
const FORBIDDEN_LINK_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function byteLength(value) {
  return Buffer.byteLength(value, 'utf8');
}

function finding(code, message, path) {
  return Object.freeze({ severity: 'fatal', code, message, path, offset: null });
}

export function validateTarPath(entryPath, options = {}) {
  const policy = createTarPolicy(options);
  const findings = [];
  const add = (code, message) => findings.push(finding(code, message, typeof entryPath === 'string' ? entryPath : null));

  if (typeof entryPath !== 'string' || entryPath.length === 0) {
    add(C.PATH_EMPTY, 'entry path must be a non-empty string');
    return Object.freeze({ valid: false, normalized: null, depth: 0, hadTrailingSlash: false, findings: Object.freeze(findings) });
  }

  if (byteLength(entryPath) > policy.maxPathLength) add(C.PATH_TOO_LONG, 'entry path exceeds maxPathLength');
  if (entryPath.startsWith('//') || entryPath.startsWith('\\\\')) add(C.UNC_PATH, 'UNC paths are not allowed');
  else if (entryPath.startsWith('/') || entryPath.startsWith('\\')) add(C.ABSOLUTE_PATH, 'absolute paths are not allowed');
  if (DRIVE_RE.test(entryPath)) add(C.DRIVE_PATH, 'Windows drive paths are not allowed');
  if (CONTROL_RE.test(entryPath) || UNPAIRED_SURROGATE_RE.test(entryPath)) add(C.CONTROL_CHARACTER, 'control, bidi, invisible formatting, or unpaired surrogate characters are not allowed');
  if (entryPath.includes('\\')) add(C.BACKSLASH_SEPARATOR, 'backslash path separators are not allowed');

  const hadTrailingSlash = /\/+$/.test(entryPath);
  const rawSegments = entryPath.split('/');
  while (rawSegments.length > 0 && rawSegments[rawSegments.length - 1] === '') rawSegments.pop();
  const segments = [];

  for (let index = 0; index < rawSegments.length; index += 1) {
    const segment = rawSegments[index];
    if (segment === '') {
      add(C.EMPTY_PATH_SEGMENT, 'empty path segments are not allowed');
      continue;
    }
    if (segment === '.') continue;
    if (segment === '..') {
      add(C.PATH_TRAVERSAL, 'parent traversal segments are not allowed');
      continue;
    }
    if (/[. ]$/.test(segment)) add(C.TRAILING_DOT_OR_SPACE, 'path components cannot end in a dot or space');
    if (WINDOWS_INVALID_CHARACTER_RE.test(segment)) add(C.WINDOWS_INVALID_CHARACTER, 'path components cannot contain Windows-invalid characters or alternate data stream syntax');
    const stem = segment.split('.', 1)[0];
    if (RESERVED_DEVICE_RE.test(stem)) add(C.RESERVED_NAME, 'Windows reserved device names are not allowed');
    if (byteLength(segment) > policy.maxComponentLength) add(C.COMPONENT_TOO_LONG, 'path component exceeds maxComponentLength');
    segments.push(segment);
  }

  const normalized = segments.length === 0 ? '.' : segments.join('/');
  const depth = normalized === '.' ? 0 : segments.length;
  if (depth > policy.maxDepth) add(C.PATH_TOO_DEEP, 'entry path exceeds maxDepth');

  return Object.freeze({
    valid: findings.length === 0,
    normalized: findings.length === 0 ? normalized : null,
    depth,
    hadTrailingSlash,
    findings: Object.freeze(findings)
  });
}

export function assertValidTarPath(entryPath, policy) {
  const result = validateTarPath(entryPath, policy);
  if (!result.valid) {
    const first = result.findings[0];
    throw new TarPathError(first.code, first.message, { path: entryPath, findings: result.findings });
  }
  return result;
}

export function collisionKey(value) {
  return value.normalize('NFKC').toLowerCase();
}

function validateLinkCharacters(target, kind, entryName, policy) {
  if (typeof target !== 'string' || target.length === 0) {
    throw new TarLinkError(C.LINK_INVALID, kind + ' target must be a non-empty string', { path: entryName, linkname: target });
  }
  if (byteLength(target) > policy.maxPathLength) {
    throw new TarLinkError(C.PATH_TOO_LONG, kind + ' target exceeds maxPathLength', { path: entryName, linkname: target });
  }
  if (CONTROL_RE.test(target) || UNPAIRED_SURROGATE_RE.test(target)) {
    throw new TarLinkError(C.CONTROL_CHARACTER, kind + ' target contains a forbidden control or invalid Unicode character', { path: entryName, linkname: target });
  }
  if (target.startsWith('//') || target.startsWith('\\\\')) {
    throw new TarLinkError(C.UNC_PATH, kind + ' target cannot be a UNC path', { path: entryName, linkname: target });
  }
  if (target.includes('\\')) {
    throw new TarLinkError(C.BACKSLASH_SEPARATOR, kind + ' target cannot contain backslash separators', { path: entryName, linkname: target });
  }
  if (target.startsWith('/')) {
    throw new TarLinkError(C.ABSOLUTE_PATH, kind + ' target cannot be absolute', { path: entryName, linkname: target });
  }
  if (DRIVE_RE.test(target)) {
    throw new TarLinkError(C.DRIVE_PATH, kind + ' target cannot be a Windows drive path', { path: entryName, linkname: target });
  }
}

function validateLinkSegments(target, kind, entryName, policy) {
  const parts = target.split('/');
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (part === '' && index !== parts.length - 1) {
      throw new TarLinkError(C.EMPTY_PATH_SEGMENT, kind + ' target contains an empty path segment', { path: entryName, linkname: target });
    }
    if (part === '' || part === '.' || part === '..') continue;
    if (/[. ]$/.test(part)) {
      throw new TarLinkError(C.TRAILING_DOT_OR_SPACE, kind + ' target component cannot end in a dot or space', { path: entryName, linkname: target });
    }
    if (WINDOWS_INVALID_CHARACTER_RE.test(part)) {
      throw new TarLinkError(C.WINDOWS_INVALID_CHARACTER, kind + ' target component contains a Windows-invalid character or alternate data stream syntax', { path: entryName, linkname: target });
    }
    const stem = part.split('.', 1)[0];
    if (RESERVED_DEVICE_RE.test(stem)) {
      throw new TarLinkError(C.RESERVED_NAME, kind + ' target uses a Windows reserved device name', { path: entryName, linkname: target });
    }
    if (byteLength(part) > policy.maxComponentLength) {
      throw new TarLinkError(C.COMPONENT_TOO_LONG, kind + ' target component exceeds maxComponentLength', { path: entryName, linkname: target });
    }
  }
}

export function validateSymlinkTarget(entryName, target, policy) {
  validateLinkCharacters(target, 'symlink', entryName, policy);
  validateLinkSegments(target, 'symlink', entryName, policy);
  return target;
}

export function validateHardlinkTarget(entryName, target, policy) {
  validateLinkCharacters(target, 'hardlink', entryName, policy);
  validateLinkSegments(target, 'hardlink', entryName, policy);
  const result = validateTarPath(target, policy);
  if (!result.valid) {
    const first = result.findings[0];
    throw new TarLinkError(first.code, 'invalid hardlink target: ' + first.message, { path: entryName, linkname: target });
  }
  return result.normalized;
}

function parentSegments(entryName) {
  const index = entryName.lastIndexOf('/');
  if (index === -1) return [];
  return entryName.slice(0, index).split('/').filter((part) => part.length > 0 && part !== '.');
}

function lookupSymlink(symlinkMap, key) {
  if (symlinkMap.has(key)) return symlinkMap.get(key);
  const wanted = collisionKey(key);
  for (const [candidate, target] of symlinkMap) {
    if (collisionKey(candidate) === wanted) return target;
  }
  return undefined;
}

function resolveSegments(baseSegments, target, symlinkMap, policy, seen) {
  let output = [...baseSegments];
  const parts = target.split('/');
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (output.length === 0) {
        throw new TarLinkError(C.LINK_ESCAPE, 'link target resolves outside the extraction root', { linkname: target });
      }
      output.pop();
    } else {
      output.push(part);
    }

    const key = output.join('/');
    const linked = key === '' ? undefined : lookupSymlink(symlinkMap, key);
    if (linked !== undefined) {
      if (seen.includes(key) || seen.length >= policy.maxSymlinkDepth) {
        throw new TarLinkError(C.LINK_CHAIN, 'cyclic or excessively deep symlink chain', { linkname: target, chain: seen.concat(key) });
      }
      output = resolveSegments(output.slice(0, -1), linked, symlinkMap, policy, seen.concat(key));
    }
  }
  return output;
}

export function resolveSymlinkWithinRoot(entryName, target, symlinkMap, policy) {
  const resolved = resolveSegments(parentSegments(entryName), target, symlinkMap, policy, [entryName]);
  return resolved.length === 0 ? '.' : resolved.join('/');
}

export function resolveRootRelativeWithinRoot(target, symlinkMap, policy) {
  const resolved = resolveSegments([], target, symlinkMap, policy, ['<root>']);
  return resolved.length === 0 ? '.' : resolved.join('/');
}

export function isForbiddenObjectKey(key) {
  return FORBIDDEN_LINK_KEYS.has(key);
}

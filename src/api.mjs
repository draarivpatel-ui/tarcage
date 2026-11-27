import { createTarPolicy, publicPolicy } from './policy.mjs';
import { scanWithPolicy } from './parser.mjs';
import { errorFinding, TarInputError } from './errors.mjs';

function emptyPartial() {
  return {
    format: 'unknown',
    compressed: false,
    entries: [],
    findings: [],
    stats: {
      entries: 0,
      files: 0,
      directories: 0,
      symlinks: 0,
      hardlinks: 0,
      special: 0,
      compressedBytes: 0,
      uncompressedBytes: 0,
      totalEntryBytes: 0,
      maxDepth: 0,
      metadataBytes: 0,
      metadataEntries: 0,
      endMarkers: 0,
      compressionRatio: null,
      uncompressedSha256: null
    }
  };
}

function finalizeReport(result, safe) {
  return {
    safe,
    format: result.format,
    compressed: result.compressed,
    entries: result.entries,
    findings: result.findings,
    stats: result.stats
  };
}

export async function inspectTar(input, options = {}) {
  const policy = createTarPolicy(options);
  try {
    const result = await scanWithPolicy(input, policy);
    return finalizeReport(result, true);
  } catch (error) {
    if (error instanceof TarInputError) throw error;
    const partial = error && error.partial ? error.partial : emptyPartial();
    const fatal = errorFinding(error);
    const findings = partial.findings.some((item) => item.code === fatal.code && item.path === fatal.path)
      ? partial.findings
      : partial.findings.concat(fatal);
    return finalizeReport({
      format: partial.format,
      compressed: partial.compressed,
      entries: partial.entries,
      findings,
      stats: partial.stats
    }, false);
  }
}

export async function auditTar(input, options = {}) {
  const policy = createTarPolicy(options);
  const report = await inspectTar(input, policy);
  const recommendations = [];
  if (!report.safe) {
    recommendations.push('Do not extract this archive until the fatal findings are resolved.');
  }
  if (report.findings.some((finding) => finding.severity === 'warning')) {
    recommendations.push('Review warning findings before treating the archive as trusted input.');
  }
  if (report.stats.special > 0) {
    recommendations.push('Special filesystem entries require an explicit audit even when inspection policy allows them.');
  }
  if (recommendations.length === 0) {
    recommendations.push('No fatal archive violations were detected under the active policy.');
  }

  return {
    ...report,
    verdict: report.safe ? 'safe' : 'unsafe',
    policy: publicPolicy(policy),
    recommendations
  };
}

export async function parseTar(input, options = {}) {
  return scanWithPolicy(input, createTarPolicy(options));
}

export async function listTarEntries(input, options = {}) {
  const result = await parseTar(input, options);
  return result.entries;
}

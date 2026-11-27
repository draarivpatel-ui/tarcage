import { inspectTar } from 'tarcage';

const input = process.argv[2];
if (!input) {
  console.error('Usage: node examples/inspect.mjs <archive>');
  process.exit(2);
}

const report = await inspectTar(input);
console.log(JSON.stringify({
  safe: report.safe,
  format: report.format,
  compressed: report.compressed,
  entries: report.stats.entries,
  findings: report.findings,
  stats: report.stats
}, null, 2));
process.exitCode = report.safe ? 0 : 1;

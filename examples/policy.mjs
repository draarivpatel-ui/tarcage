import { createTarPolicy, inspectTar } from 'tarcage';

const strictSmallArchivePolicy = createTarPolicy({
  maxEntries: 100,
  maxEntryBytes: 1024 * 1024,
  maxUncompressedBytes: 10 * 1024 * 1024,
  maxCompressionRatio: 25
});

console.log('reusable policy');
console.log(strictSmallArchivePolicy);

const input = process.argv[2];
if (input) {
  const report = await inspectTar(input, strictSmallArchivePolicy);
  console.log('safe under custom policy: ' + report.safe);
}

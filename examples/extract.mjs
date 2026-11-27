import { extractTar } from 'tarcage';

const [input, destination] = process.argv.slice(2);
if (!input || !destination) {
  console.error('Usage: node examples/extract.mjs <archive> <destination>');
  process.exit(2);
}

try {
  const report = await extractTar(input, destination);
  console.log('extracted entries: ' + report.extracted);
  console.log('bytes written: ' + report.bytesWritten);
} catch (error) {
  console.error(error.code + ': ' + error.reason);
  process.exitCode = 1;
}

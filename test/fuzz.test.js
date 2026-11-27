import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { inspectTar } from '../src/index.mjs';
import { file, hasFinding, makeTar } from '../tests/helpers.mjs';

const stemUnit = fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789');
const safeStem = fc.string({ unit: stemUnit, minLength: 1, maxLength: 12 });
const fuzzOptions = { seed: 20261127, numRuns: 80 };

test('fast-check generated safe file archives inspect as safe and complete', async () => {
  await fc.assert(fc.asyncProperty(
    fc.array(fc.record({ stem: safeStem, content: fc.string({ maxLength: 32 }) }), { minLength: 1, maxLength: 4 }),
    async (generated) => {
      const entries = generated.map((entry, index) => file('docs/' + index + '-' + entry.stem + '.txt', entry.content));
      const report = await inspectTar(makeTar(entries));
      assert.equal(report.safe, true, 'safe generated archive was rejected: ' + report.findings.map((finding) => finding.code).join(','));
      assert.equal(report.stats.files, entries.length);
      assert.equal(report.stats.entries, entries.length);
      assert.deepEqual(report.entries.map((entry) => entry.name), entries.map((entry) => entry.name));
    }
  ), fuzzOptions);
});

test('fast-check parent traversal archive names are always fatal findings', async () => {
  await fc.assert(fc.asyncProperty(fc.integer({ min: 1, max: 5 }), safeStem, async (parents, stem) => {
    const hostileName = '../'.repeat(parents) + stem + '.txt';
    const report = await inspectTar(makeTar([file(hostileName, 'x')]));
    assert.equal(report.safe, false, 'traversal archive was accepted');
    assert.equal(hasFinding(report, 'TARCAGE_PATH_TRAVERSAL'), true);
    assert.equal(report.findings.some((finding) => finding.severity === 'fatal'), true);
  }), fuzzOptions);
});

test('fast-check absolute archive paths are always fatal findings', async () => {
  await fc.assert(fc.asyncProperty(safeStem, async (stem) => {
    const report = await inspectTar(makeTar([file('/tmp/' + stem + '.txt', 'x')]));
    assert.equal(report.safe, false, 'absolute archive path was accepted');
    assert.equal(report.findings.some((finding) => finding.severity === 'fatal'), true);
  }), fuzzOptions);
});

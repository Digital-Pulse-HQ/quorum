// The fixture matrix. Every committed case is executed against the real verifier, and its refusal
// must name the guard the fixture says it will — "it failed" is not evidence that it failed for the
// stated reason, and a fixture that passes for the wrong reason is worse than no fixture.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { GUARD_IDS, verifyEnvelope } from '../src/verify.mjs';
import { writeFixtures } from '../tools/make-fixtures.mjs';

const PACKAGE = fileURLToPath(new URL('../', import.meta.url));
const FIXTURES = join(PACKAGE, 'fixtures');
const INDEX = JSON.parse(readFileSync(join(FIXTURES, 'index.json'), 'utf8'));

const readOrNull = (relPath, encoding) => {
  if (relPath === null || relPath === undefined) return null;
  try { return readFileSync(join(FIXTURES, relPath), encoding); } catch { return null; }
};

function run(testCase) {
  return verifyEnvelope({
    envelopeText: readOrNull(testCase.envelope, 'utf8'),
    policyText: readOrNull(testCase.policy, 'utf8'),
    trustText: readOrNull(testCase.trust, 'utf8'),
    expected: { attemptId: testCase.attempt, commit: testCase.commit, pr: testCase.pr ?? null },
    artifactBytes: readOrNull(testCase.artifact),
    evidenceBytes: readOrNull(testCase.evidence),
  });
}

test('the fixture index is a matrix, not a token gesture', () => {
  assert.equal(INDEX.schema, 'quorum-fixtures/1');
  assert.ok(INDEX.cases.length >= 20, `only ${INDEX.cases.length} cases`);
  assert.ok(INDEX.cases.some((c) => c.kind === 'positive'), 'no positive control');
  const names = INDEX.cases.map((c) => c.name);
  assert.equal(new Set(names).size, names.length, 'duplicate case names');
});

for (const testCase of INDEX.cases) {
  test(`fixture ${testCase.name}: ${testCase.expect.ok ? 'PASS' : `refused by ${testCase.expect.guard}`}`, () => {
    const result = run(testCase);
    if (testCase.expect.ok) {
      assert.equal(result.ok, true, `${testCase.name} should pass but was refused by ${result.guard}: ${result.why}`);
      assert.equal(result.verdict, 'PASS');
      return;
    }
    assert.equal(result.ok, false, `${testCase.name} PASSED and must not: ${result.why}`);
    assert.equal(result.guard, testCase.expect.guard, `${testCase.name} was refused by ${result.guard}, not ${testCase.expect.guard}: ${result.why}`);
    assert.ok(['UNKNOWN', 'INVALID'].includes(result.verdict));
  });
}

// The README states the corpus and guard counts in prose, and prose drifts: it said 37 cases while
// the index held 38. Every count it states is read back here and must equal the thing it counts.
test('COUNT PIN: the README\'s fixture and guard counts equal the index and the verifier', () => {
  const readme = readFileSync(join(PACKAGE, 'README.md'), 'utf8');
  const caseClaims = [...readme.matchAll(/(\d+) cases\b/g)].map((m) => Number(m[1]));
  assert.ok(caseClaims.length >= 1, 'the README no longer states a fixture count; drop this pin deliberately, not by rewording');
  for (const claim of caseClaims) {
    assert.equal(claim, INDEX.cases.length, `the README says ${claim} cases but fixtures/index.json holds ${INDEX.cases.length}`);
  }
  const guardClaims = [...readme.matchAll(/(\d+) guards\b/g)].map((m) => Number(m[1]));
  assert.ok(guardClaims.length >= 1, 'the README no longer states a guard count; drop this pin deliberately, not by rewording');
  for (const claim of guardClaims) {
    assert.equal(claim, GUARD_IDS.length, `the README says ${claim} guards but the verifier declares ${GUARD_IDS.length}`);
  }
});

test('every guard the verifier declares has at least one fixture that fires it', () => {
  const fired = new Set(INDEX.cases.filter((c) => !c.expect.ok).map((c) => c.expect.guard));
  const unexercised = GUARD_IDS.filter((guard) => !fired.has(guard));
  assert.deepEqual(unexercised, [], `guards with no adversarial fixture: ${unexercised.join(', ')}`);
  const unknown = [...fired].filter((guard) => !GUARD_IDS.includes(guard));
  assert.deepEqual(unknown, [], `fixtures naming guards the verifier does not declare: ${unknown.join(', ')}`);
});

// A fixture edited by hand to make a test pass is the failure mode this guards. Ed25519 signing is
// deterministic and every key is derived from a committed phrase, so regeneration is byte-identical.
test('DRIFT: the committed fixtures are exactly what the generator produces', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quorum-fixture-drift-'));
  try {
    writeFixtures(dir);
    const walk = (root) => {
      const out = [];
      for (const entry of readdirSync(root, { withFileTypes: true })) {
        const full = join(root, entry.name);
        if (entry.isDirectory()) out.push(...walk(full));
        else out.push(full);
      }
      return out.sort();
    };
    const generated = walk(dir).map((p) => relative(dir, p));
    const committed = walk(FIXTURES).map((p) => relative(FIXTURES, p)).filter((p) => p !== 'README.md');
    assert.deepEqual(committed, generated, 'the committed fixture file list differs from the generated one');
    for (const rel of generated) {
      assert.equal(
        readFileSync(join(FIXTURES, rel), 'utf8'),
        readFileSync(join(dir, rel), 'utf8'),
        `committed fixture ${rel} differs from the generated one — it has been hand-edited or the generator has changed`,
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('no private key material is committed anywhere in the package', () => {
  const walk = (root) => readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === 'node_modules') return [];
    const full = join(root, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
  const offenders = [];
  for (const file of walk(PACKAGE)) {
    if (statSync(file).size > 2_000_000) continue;
    const text = readFileSync(file, 'utf8');
    // The generator names these constructs in prose; only a real PEM header is a finding.
    if (/-----BEGIN (?:[A-Z ]*)?PRIVATE KEY-----/.test(text)) offenders.push(relative(PACKAGE, file));
  }
  assert.deepEqual(offenders, [], `private key material committed in: ${offenders.join(', ')}`);
});

test('the CLI agrees with the library on every fixture, and exits non-zero on every refusal', () => {
  const bin = join(PACKAGE, 'bin', 'quorum.mjs');
  for (const testCase of INDEX.cases) {
    const args = [
      bin, 'verify',
      '--envelope', join(FIXTURES, testCase.envelope),
      '--policy', join(FIXTURES, testCase.policy),
      '--trust', join(FIXTURES, testCase.trust),
      '--attempt', testCase.attempt,
      '--commit', testCase.commit,
      '--json',
    ];
    if (testCase.artifact) args.push('--artifact', join(FIXTURES, testCase.artifact));
    if (testCase.evidence) args.push('--evidence', join(FIXTURES, testCase.evidence));
    if (testCase.pr !== null && testCase.pr !== undefined) args.push('--pr', String(testCase.pr));

    let status = 0;
    let stdout = '';
    try {
      stdout = execFileSync(process.execPath, args, { encoding: 'utf8', stdio: 'pipe' });
    } catch (error) {
      status = error.status;
      stdout = String(error.stdout ?? '');
    }
    const result = JSON.parse(stdout);
    assert.equal(result.ok, testCase.expect.ok, `CLI disagreed with the library on ${testCase.name}`);
    assert.equal(status, testCase.expect.ok ? 0 : 1, `CLI exit status wrong for ${testCase.name}`);
    if (!testCase.expect.ok) assert.equal(result.guard, testCase.expect.guard, `CLI named ${result.guard} on ${testCase.name}`);
  }
});

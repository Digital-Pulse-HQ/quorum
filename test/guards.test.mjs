// One behavioural test per guard, driven by the committed fixtures.
//
// This suite is the target of the delete tests in delete-guards.test.mjs: each guard is neutered in
// a copy of the package and this suite is re-run, and the mutant is only accepted as caught when the
// TAP output reports the guard's OWN test as `not ok`. That is why every test here asserts the guard
// id rather than merely that verification failed — a refusal by the next guard along would otherwise
// let a deleted guard look defended.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { GUARD_IDS, verifyEnvelope } from '../src/verify.mjs';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));
const INDEX = JSON.parse(readFileSync(join(FIXTURES, 'index.json'), 'utf8'));

const readOrNull = (relPath, encoding) => {
  if (relPath === null || relPath === undefined) return null;
  try { return readFileSync(join(FIXTURES, relPath), encoding); } catch { return null; }
};

const run = (testCase) => verifyEnvelope({
  envelopeText: readOrNull(testCase.envelope, 'utf8'),
  policyText: readOrNull(testCase.policy, 'utf8'),
  trustText: readOrNull(testCase.trust, 'utf8'),
  expected: { attemptId: testCase.attempt, commit: testCase.commit, pr: testCase.pr ?? null },
  artifactBytes: readOrNull(testCase.artifact),
  evidenceBytes: readOrNull(testCase.evidence),
});

const caseNamed = (name) => {
  const found = INDEX.cases.find((entry) => entry.name === name);
  assert.ok(found, `fixture case ${name} is missing`);
  return found;
};

// guard id -> the fixture whose refusal that guard must own. Kept as an explicit table, not derived
// from the index, so the delete-test names are stable when fixtures are added.
export const GUARD_CASES = Object.freeze({
  Q00_INPUT_PRESENT: 'deleted-envelope',
  Q01_ENVELOPE_JSON: 'malformed-envelope-json',
  Q02_ENVELOPE_SCHEMA: 'deleted-reviewer-signature',
  Q03_POLICY: 'malformed-policy',
  Q04_TRUST_STORE: 'malformed-trust-store',
  Q20_POLICY_IDENTITY: 'policy-identity-collision',
  Q05_POLICY_VERSION: 'mutated-policy-version',
  Q06_ATTEMPT_BINDING: 'stale-attempt',
  Q07_ARTIFACT_BINDING: 'mutated-commit',
  Q08_ARTIFACT_DIGEST: 'mutated-artifact-digest',
  Q09_PRODUCER_ENROLMENT: 'unenrolled-producer',
  Q10_PRODUCER_SIGNATURE: 'mutated-producer-signature',
  Q11_REVIEWER_ENROLMENT: 'trailer-1-untrusted-reviewer-approve',
  Q12_REVIEWER_SIGNATURE: 'mutated-verdict',
  Q13_VERDICT: 'trailer-3-repaired-identity',
  Q14_TRUST_ENROLMENT: 'signed-trust-overclaim',
  Q15_TRUST_POLICY: 'declared-under-observed-policy',
  Q16_FAMILY_INEQUALITY: 'trailer-2-repaired-verdict',
  Q17_PR_BINDING: 'trailer-3-repaired-verdict',
  Q18_EVIDENCE_BINDING: 'deleted-evidence',
  Q19_RESIDUE_DECLARATION: 'residue-absent-under-requiring-policy',
});

test('the guard table covers every guard the verifier declares', () => {
  assert.deepEqual(Object.keys(GUARD_CASES).sort(), [...GUARD_IDS].sort());
});

// `verify.mjs` has always instructed the reader to keep GUARD_IDS "ordered as the checks run" and
// nothing enforced it. Policy identity adds Q20_POLICY_IDENTITY, which runs sixth and is deliberately
// NOT renumbered — guard ids are cited by name in four review records and in every fixture's
// `expect.guard`, so renumbering would re-point those citations at different checks. That makes the
// list order the only remaining statement of execution order, so it is now checked against the
// source rather than asserted in a comment.
test('GUARD_IDS is in the order the guards actually run in src/verify.mjs', () => {
  const source = readFileSync(fileURLToPath(new URL('../src/verify.mjs', import.meta.url)), 'utf8');
  const inSourceOrder = [...source.matchAll(/\/\* GUARD:([A-Z0-9_]+) \*\//g)].map((m) => m[1]);
  assert.deepEqual(inSourceOrder, [...GUARD_IDS],
    'GUARD_IDS no longer matches the order the /* GUARD:... */ markers appear in src/verify.mjs');
});

for (const [guard, caseName] of Object.entries(GUARD_CASES)) {
  test(`guard ${guard} refuses ${caseName}`, () => {
    const result = run(caseNamed(caseName));
    assert.equal(result.ok, false, `${caseName} passed verification`);
    assert.equal(result.guard, guard, `${caseName} was refused by ${result.guard}, not ${guard}`);
  });
}

test('positive control: a valid cross-family review still passes', () => {
  const result = run(caseNamed('valid-cross-family-approve'));
  assert.equal(result.ok, true, result.why);
  assert.equal(result.verdict, 'PASS');
});

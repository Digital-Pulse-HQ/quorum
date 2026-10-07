// GATE MODE VERSUS CONFORMANCE MODE, reproduced and then closed — in one file, so the two halves
// cannot drift.
//
// The reproduction: a one-case manifest naming an ABSENT envelope, with
// `expect: { ok: false, guard: "Q00_INPUT_PRESENT" }`, run through the single manifest runner that
// `ci/required-check.mjs` once said "becomes the merge gate when pointed at real evidence". That run
// exited 0 and printed "1/1 cases behaved as required" — a missing, stale, untrusted or same-family
// review can be declared as the expected outcome and the gate passes.
//
// The first half of this file reproduces that shape against `--mode conformance`, which still exists
// and is legitimate: scoring a declared negative case is exactly what fixture conformance is for, and
// it is the only mode CI ever points at `fixtures/index.json`. The defect was never conformance mode
// on its own — it was that NO OTHER MODE EXISTED, so the same mechanism was also "the merge gate
// against real evidence" with no separate contract. The second half proves that separate contract:
// gate mode reads a different schema token, its case shape has no `expect` field to declare, and it
// requires a REAL ok:true from the verifier for every case.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runManifest } from '../ci/required-check.mjs';

const PACKAGE = fileURLToPath(new URL('../', import.meta.url));
const CHECK = join(PACKAGE, 'ci', 'required-check.mjs');
const FIXTURES = join(PACKAGE, 'fixtures');
const INDEX = JSON.parse(readFileSync(join(FIXTURES, 'index.json'), 'utf8'));
const VALID = INDEX.cases.find((c) => c.name === 'valid-cross-family-approve');

function run(args) {
  try {
    return { status: 0, out: execFileSync(process.execPath, [CHECK, ...args], { encoding: 'utf8', stdio: 'pipe' }) };
  } catch (error) {
    return { status: error.status, out: String(error.stdout ?? '') + String(error.stderr ?? '') };
  }
}

function withTempManifest(manifest, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'quorum-gate-mode-'));
  try {
    writeFileSync(join(dir, 'index.json'), JSON.stringify(manifest, null, 2));
    return fn(join(dir, 'index.json'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('REPRODUCTION: a declared-refusal case exits 0 under conformance scoring', () => {
  const manifest = {
    schema: 'quorum-fixtures/1',
    cases: [{
      name: 'reproduction-absent-envelope',
      policy: 'shared/policy-declared.json',
      trust: 'shared/trust.json',
      artifact: 'shared/artifact.txt',
      evidence: 'shared/evidence.md',
      attempt: INDEX.expected.attempt,
      commit: INDEX.expected.commit,
      pr: INDEX.expected.pr,
      envelope: 'adversarial/does-not-exist.json',
      expect: { ok: false, guard: 'Q00_INPUT_PRESENT' },
    }],
  };
  withTempManifest(manifest, (path) => {
    const result = run(['--manifest', path, '--mode', 'conformance']);
    assert.equal(result.status, 0, `conformance mode should score the declared refusal as a pass: ${result.out}`);
    assert.match(result.out, /1\/1 cases behaved as required/);
  });
});

test('CLOSURE: the identical manifest, run as --mode gate, is refused for carrying a fixture schema', () => {
  const manifest = {
    schema: 'quorum-fixtures/1',
    cases: [{
      name: 'reproduction-absent-envelope',
      policy: 'shared/policy-declared.json',
      trust: 'shared/trust.json',
      artifact: 'shared/artifact.txt',
      evidence: 'shared/evidence.md',
      attempt: INDEX.expected.attempt,
      commit: INDEX.expected.commit,
      pr: INDEX.expected.pr,
      envelope: 'adversarial/does-not-exist.json',
      expect: { ok: false, guard: 'Q00_INPUT_PRESENT' },
    }],
  };
  withTempManifest(manifest, (path) => {
    const result = run(['--manifest', path, '--mode', 'gate']);
    assert.notEqual(result.status, 0, `gate mode accepted a quorum-fixtures/1 manifest: ${result.out}`);
    assert.match(result.out, /gate mode requires a quorum-manifest\/1 manifest/);
  });
});

test('CLOSURE: renaming the schema token to quorum-manifest/1 but keeping `expect` is still refused', () => {
  // An attacker who reads the schema-token check would try to rename the token and keep the rest.
  // The per-case schema (additionalProperties: false, no `expect` property) refuses this on its own.
  const manifest = {
    schema: 'quorum-manifest/1',
    cases: [{
      name: 'reproduction-absent-envelope',
      policy: 'shared/policy-declared.json',
      trust: 'shared/trust.json',
      artifact: 'shared/artifact.txt',
      evidence: 'shared/evidence.md',
      attempt: INDEX.expected.attempt,
      commit: INDEX.expected.commit,
      pr: INDEX.expected.pr,
      envelope: 'adversarial/does-not-exist.json',
      expect: { ok: false, guard: 'Q00_INPUT_PRESENT' },
    }],
  };
  withTempManifest(manifest, (path) => {
    const result = run(['--manifest', path, '--mode', 'gate']);
    assert.notEqual(result.status, 0, `gate mode accepted a case carrying "expect": ${result.out}`);
    assert.match(result.out, /does not satisfy quorum-manifest\/1/);
    assert.match(result.out, /"expect"/);
  });
});

test('CLOSURE: a well-formed gate manifest naming the SAME absent envelope, with no `expect` at all, still fails — never a false green', () => {
  const manifest = {
    schema: 'quorum-manifest/1',
    cases: [{
      name: 'reproduction-absent-envelope',
      policy: 'shared/policy-declared.json',
      trust: 'shared/trust.json',
      artifact: 'shared/artifact.txt',
      evidence: 'shared/evidence.md',
      attempt: INDEX.expected.attempt,
      commit: INDEX.expected.commit,
      pr: INDEX.expected.pr,
      envelope: 'adversarial/does-not-exist.json',
    }],
  };
  withTempManifest(manifest, (path) => {
    const result = run(['--manifest', path, '--mode', 'gate']);
    assert.equal(result.status, 1, `gate mode must fail closed on an absent envelope: ${result.out}`);
    assert.match(result.out, /refusal by Q00_INPUT_PRESENT/);
  });
});

test('gate mode passes a well-formed manifest whose cases are genuinely valid', () => {
  const absolute = (rel) => (rel ? join(FIXTURES, rel) : rel);
  const manifest = {
    schema: 'quorum-manifest/1',
    cases: [{
      name: 'valid-cross-family-approve',
      policy: absolute(VALID.policy),
      trust: absolute(VALID.trust),
      artifact: absolute(VALID.artifact),
      evidence: absolute(VALID.evidence),
      attempt: VALID.attempt,
      commit: VALID.commit,
      pr: VALID.pr,
      envelope: absolute(VALID.envelope),
    }],
  };
  withTempManifest(manifest, (path) => {
    const result = run(['--manifest', path, '--mode', 'gate']);
    assert.equal(result.status, 0, `gate mode refused genuinely valid evidence: ${result.out}`);
    assert.match(result.out, /1\/1 cases behaved as required/);
  });
});

test('gate mode fails the whole check if even one case among several real ones is invalid', () => {
  const absolute = (rel) => (rel ? join(FIXTURES, rel) : rel);
  const manifest = {
    schema: 'quorum-manifest/1',
    cases: [
      {
        name: 'valid-cross-family-approve',
        policy: absolute(VALID.policy),
        trust: absolute(VALID.trust),
        artifact: absolute(VALID.artifact),
        evidence: absolute(VALID.evidence),
        attempt: VALID.attempt,
        commit: VALID.commit,
        pr: VALID.pr,
        envelope: absolute(VALID.envelope),
      },
      {
        name: 'stale-review-slipped-in',
        policy: absolute(VALID.policy),
        trust: absolute(VALID.trust),
        artifact: absolute(VALID.artifact),
        evidence: absolute(VALID.evidence),
        attempt: 'attempt:00000000000000000000000000000000',
        commit: VALID.commit,
        pr: VALID.pr,
        envelope: absolute(VALID.envelope),
      },
    ],
  };
  withTempManifest(manifest, (path) => {
    const result = run(['--manifest', path, '--mode', 'gate']);
    assert.equal(result.status, 1, `gate mode passed the batch despite one invalid case: ${result.out}`);
    assert.match(result.out, /stale-review-slipped-in/);
    assert.match(result.out, /refusal by Q06_ATTEMPT_BINDING/);
  });
});

test('runManifest(..., { mode: "gate" }) rejects an unknown mode outright', () => {
  assert.throws(() => runManifest(join(FIXTURES, 'index.json'), { mode: 'bogus' }), /unknown mode/);
});

test('the exported runManifest refuses an omitted mode instead of defaulting', () => {
  // The CLI's mode was once made mandatory while the exported function's was not. With
  // `{ mode = 'conformance' } = {}` the pre-split call shape `runManifest(path)` kept working and
  // silently conformance-scored, so a programmatic caller — the CI harness this package invites
  // people to write — still converted a declared refusal into a scored pass. Measured at that revision:
  // all 37 entries came back `ok: true`, including `deleted-envelope`, whose real verifier result is
  // `ok: false / Q00_INPUT_PRESENT`. Every shape of omission is covered, because `runManifest(path)`
  // and `runManifest(path, {})` reach the default by different routes.
  const manifest = join(FIXTURES, 'index.json');
  for (const call of [
    () => runManifest(manifest),
    () => runManifest(manifest, {}),
    () => runManifest(manifest, { mode: undefined }),
  ]) {
    assert.throws(call, /runManifest requires an explicit mode/);
  }

  // And the scoring difference the omission used to hide is real, not hypothetical: name the mode
  // and the SAME manifest still scores the refusal as a declared-negative pass, which is correct for
  // conformance and is precisely why no entry point may pick it silently.
  const scored = runManifest(manifest, { mode: 'conformance' });
  const deleted = scored.find((entry) => entry.name === 'deleted-envelope');
  assert.ok(deleted, 'the conformance manifest no longer contains deleted-envelope');
  assert.equal(deleted.ok, true, 'conformance mode is supposed to score a declared refusal as a pass');
  assert.equal(deleted.actual.ok, false, 'the underlying verifier result must still be a refusal');
  assert.equal(deleted.actual.guard, 'Q00_INPUT_PRESENT');
});

test('the CLI reports an omitted mode as a failure to run, never as a pass', () => {
  const result = run(['--manifest', join(FIXTURES, 'index.json')]);
  assert.equal(result.status, 2, `a modeless invocation exited ${result.status}: ${result.out}`);
  assert.match(result.out, /usage: required-check\.mjs --manifest <path> --mode conformance\|gate/);
  assert.doesNotMatch(result.out, /cases behaved as required/);
});

// The required check must fail for each of five conditions — absent, stale, mutated, untrusted and
// same-family review — and must fail loudly when it cannot run at all. A gate that exits 0 on an unreadable manifest is decoration.
//
// This runner has two modes with two schemas — see gate-mode.test.mjs for the merge-gate contract
// itself. This file keeps the pre-existing conformance-mode coverage,
// updated to pass --mode explicitly now that the flag is required.

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
const MANIFEST = join(PACKAGE, 'fixtures', 'index.json');

function run(args) {
  try {
    return { status: 0, out: execFileSync(process.execPath, [CHECK, ...args], { encoding: 'utf8', stdio: 'pipe' }) };
  } catch (error) {
    return { status: error.status, out: String(error.stdout ?? '') + String(error.stderr ?? '') };
  }
}

test('the required check passes on the committed manifest', () => {
  const result = run(['--manifest', MANIFEST, '--mode', 'conformance']);
  assert.equal(result.status, 0, result.out);
  assert.match(result.out, /cases behaved as required/);
});

test('conformance mode refuses a manifest that is not schema quorum-fixtures/1', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quorum-wrong-schema-'));
  try {
    writeFileSync(join(dir, 'index.json'), JSON.stringify({ schema: 'quorum-manifest/1', cases: [] }));
    const result = run(['--manifest', join(dir, 'index.json'), '--mode', 'conformance']);
    assert.equal(result.status, 1);
    assert.match(result.out, /conformance mode requires a quorum-fixtures\/1 manifest/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the required check covers all five conditions: absent, stale, mutated, untrusted, same-family', () => {
  const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
  const named = (name) => {
    const entry = manifest.cases.find((c) => c.name === name);
    assert.ok(entry, `the manifest has no case ${name}`);
    assert.equal(entry.expect.ok, false, `${name} is not required to be refused`);
    return entry;
  };
  named('deleted-envelope');                       // absent
  named('stale-attempt');                          // stale
  named('mutated-verdict');                        // mutated
  named('trailer-1-untrusted-reviewer-approve');   // untrusted
  named('trailer-2-repaired-verdict');             // same-family
});

test('the required check FAILS when an adversarial case starts passing', () => {
  // The mutation is applied to the MANIFEST, not the verifier: it asserts that the check reads the
  // declared outcome rather than reporting whatever the verifier happens to do. The rewritten
  // manifest is written OUTSIDE the fixture tree with absolute paths, because node:test runs files in
  // parallel and a stray file under fixtures/ would redden the drift test in another worker.
  const dir = mkdtempSync(join(tmpdir(), 'quorum-required-'));
  try {
    assert.ok(runManifest(MANIFEST, { mode: 'conformance' }).every((r) => r.ok), 'the unmodified manifest should be clean');

    const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
    const target = manifest.cases.find((c) => c.name === 'trailer-1-untrusted-reviewer-approve');
    const absolute = (rel) => (rel ? join(PACKAGE, 'fixtures', rel) : rel);
    writeFileSync(join(dir, 'index.json'), JSON.stringify({
      schema: 'quorum-fixtures/1',
      cases: [{
        ...target,
        envelope: absolute(target.envelope),
        policy: absolute(target.policy),
        trust: absolute(target.trust),
        artifact: absolute(target.artifact),
        evidence: absolute(target.evidence),
        expect: { ok: true },
      }],
    }, null, 2));

    const result = run(['--manifest', join(dir, 'index.json'), '--mode', 'conformance']);
    assert.equal(result.status, 1, `the check passed a case that should have been refused: ${result.out}`);
    assert.match(result.out, /expected PASS, got refusal by Q11_REVIEWER_ENROLMENT/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the required check fails rather than passes when it cannot run', () => {
  assert.equal(run(['--manifest', join(PACKAGE, 'fixtures', 'no-such-manifest.json'), '--mode', 'conformance']).status, 1);
  assert.equal(run([]).status, 2);
  assert.equal(run(['--manifest', MANIFEST]).status, 2, 'missing --mode must be a usage error, never a default');
  assert.equal(run(['--manifest', MANIFEST, '--mode', 'bogus']).status, 2);
});

test('an empty manifest is a failure, not a green gate', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quorum-empty-'));
  try {
    writeFileSync(join(dir, 'index.json'), JSON.stringify({ schema: 'quorum-fixtures/1', cases: [] }));
    const result = run(['--manifest', join(dir, 'index.json'), '--mode', 'conformance']);
    assert.equal(result.status, 1);
    assert.match(result.out, /an empty gate is not a green one/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

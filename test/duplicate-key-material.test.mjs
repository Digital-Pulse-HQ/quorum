// DUPLICATE KEY MATERIAL, reproduced and then closed — in one file, so the two halves cannot drift.
//
// The reproduction: generate ONE Ed25519 keypair. Enrol its identical public key TWICE in
// one trust store — once as `producer-key`/claude/producer, again as `reviewer-key`/codex/reviewer.
// Sign the producer half AND the reviewer half with that single private key. `verifyEnvelope()`
// used to return `ok: true`, `PASS`, "claude produced, codex reviewed", with every artifact, evidence,
// attempt, commit, PR, policy and signature check genuinely passing. One controlling key had
// self-approved while the claimed family inequality remained literally true — not a deleted guard,
// but a hole beside every guard.
//
// There is no separate legacy module left standing to keep reproducing the defect
// against: the vulnerable code IS src/verify.mjs's loadTrustStore(), and this file's fix changes it in
// place. So the "turns red if hardening ever regresses" property a second, deliberately-unpatched
// module would give, this file gets from
// test/invariant-mutations.test.mjs's M9_TRUST_KEY_MATERIAL_DEDUP entry, which neuters exactly the
// fingerprint-comparison lines added for this fix (and nothing else — not the pre-existing duplicate
// key_id check) and requires the CLOSURE test below to fail. Read the two together.

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createEnvelope, createProducerHalf, sha256Ref } from '../src/envelope.mjs';
import { verifyEnvelope } from '../src/verify.mjs';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));
const INDEX = JSON.parse(readFileSync(join(FIXTURES, 'index.json'), 'utf8'));
const read = (rel, encoding) => readFileSync(join(FIXTURES, rel), encoding);

test('REPRODUCTION: one private key enrolled on both sides of a review self-approves', () => {
  const key = generateKeyPairSync('ed25519');
  const publicKeyPem = key.publicKey.export({ type: 'spki', format: 'pem' });
  const artifact = Buffer.from('duplicate-key reproduction artifact bytes\n', 'utf8');
  const evidence = Buffer.from('duplicate-key reproduction evidence\n', 'utf8');
  const attempt = `attempt:${'d1'.repeat(16)}`;
  const commit = 'd'.repeat(40);

  const half = createProducerHalf({
    policyVersion: INDEX.expected.policy_version,
    attemptId: attempt,
    artifact: { kind: 'git_commit', commit, digest: sha256Ref(artifact) },
    producer: {
      principal: 'example:dup-producer@example.test', family: 'claude', family_trust: 'declared', key_id: 'dual-enrolled-producer-key',
    },
    privateKey: key.privateKey,
  });
  const envelope = createEnvelope({
    producerHalf: half,
    reviewer: {
      principal: 'example:dup-reviewer@example.test', family: 'codex', family_trust: 'declared', key_id: 'dual-enrolled-reviewer-key',
    },
    review: { verdict: 'APPROVE', pr: 1, evidence_digest: sha256Ref(evidence) },
    privateKey: key.privateKey, // THE SAME KEY signs both halves.
  });

  const trust = {
    schema: 'quorum-trust/1',
    keys: [
      {
        key_id: 'dual-enrolled-producer-key', principal: 'example:dup-producer@example.test', family: 'claude', family_evidence: 'declared', roles: ['producer'], public_key_pem: publicKeyPem,
      },
      {
        key_id: 'dual-enrolled-reviewer-key', principal: 'example:dup-reviewer@example.test', family: 'codex', family_evidence: 'declared', roles: ['reviewer'], public_key_pem: publicKeyPem,
      },
    ],
  };
  const policy = JSON.parse(read('shared/policy-declared.json', 'utf8'));

  const result = verifyEnvelope({
    envelopeText: JSON.stringify(envelope),
    policyText: JSON.stringify(policy),
    trustText: JSON.stringify(trust),
    expected: { attemptId: attempt, commit, pr: 1 },
    artifactBytes: artifact,
    evidenceBytes: evidence,
  });

  assert.equal(
    result.ok,
    false,
    `one key enrolled as both producer and reviewer PASSED verification (${JSON.stringify(result)}) — self-approval is possible again`,
  );
  assert.equal(result.guard, 'Q04_TRUST_STORE', `expected the duplicate-key-material check to refuse, got ${result.guard}: ${result.why}`);
  assert.equal(result.verdict, 'UNKNOWN', 'a malformed trust store compares nothing — this is UNKNOWN, not INVALID');
});

test('CLOSURE: the committed adversarial fixture reproduces the same self-approval and is refused', () => {
  const testCase = INDEX.cases.find((entry) => entry.name === 'duplicate-key-material-self-approval');
  assert.ok(testCase, 'the committed duplicate-key-material fixture is missing');
  assert.equal(testCase.expect.ok, false, 'the fixture is not declared adversarial');
  const result = verifyEnvelope({
    envelopeText: read(testCase.envelope, 'utf8'),
    policyText: read(testCase.policy, 'utf8'),
    trustText: read(testCase.trust, 'utf8'),
    expected: { attemptId: testCase.attempt, commit: testCase.commit, pr: testCase.pr ?? null },
    artifactBytes: read(testCase.artifact),
    evidenceBytes: read(testCase.evidence),
  });
  assert.equal(result.ok, false, 'the committed duplicate-key-material fixture PASSED — one key can self-approve again');
  assert.equal(result.guard, testCase.expect.guard);
});

test('the committed fixture\'s duplicate enrolment differs at the PEM-text level, not just in principal/family/role', () => {
  // Comparing PEM strings is insufficient: the same key can be
  // re-wrapped with different transport-level encoding. If this fixture's two enrolments happened to
  // carry byte-identical PEM text, a naive `pem === pem` check would also catch it, and the refusal
  // above would not be attributable to normalized-key comparison specifically.
  const testCase = INDEX.cases.find((entry) => entry.name === 'duplicate-key-material-self-approval');
  const trust = JSON.parse(read(testCase.trust, 'utf8'));
  const pems = trust.keys
    .filter((k) => k.key_id === 'dual-enrolled-producer-key' || k.key_id === 'dual-enrolled-reviewer-key')
    .map((k) => k.public_key_pem);
  assert.equal(pems.length, 2, 'expected exactly the two dual enrolments');
  assert.notEqual(pems[0], pems[1], 'the two PEM encodings must differ as text or this fixture proves nothing about normalization');
});

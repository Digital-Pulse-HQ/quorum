// One independently minted, fully valid signed bundle, with every fact a guard reads overridable
// ON ITS OWN.
//
// WHY THIS IS A SHARED HELPER AND NOT A FIXTURE. A committed fixture fixes every field at once, so
// a test built on one can only ever move the whole bundle. That is precisely how earlier
// re-adjudications found live guards with no regression evidence: the fixture that "tested" a guard
// had several fields wrong simultaneously, and any one of the others refused it just as well. Every
// case built here changes exactly ONE decision input away from a bundle that is otherwise valid,
// with real Ed25519 keys and real signatures minted per call, so no mutation can be masked by stale
// bytes and no refusal can be attributed to the wrong guard.
//
// `claim` is what the ENVELOPE says (and is therefore signed); `enrol` is what the TRUST FILE says.
// Keeping them separate is the whole point: a guard that compares the two cannot be tested by a
// helper that only ever sets them together.

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createEnvelope, createProducerHalf, sha256Ref, stampPolicyVersion } from '../../src/envelope.mjs';
import { verifyEnvelope } from '../../src/verify.mjs';

// The policy LABEL. Since the policy-identity change a policy_version is `<label>+<content identity>`, so
// the full version is computed per bundle from the resolved policy by stampPolicyVersion: a case that
// overrides any policy field gets a policy_version that names THAT policy, not the default one.
export const POLICY_LABEL = 'quorum-policy/1@2026-09-10';
export const PRINCIPALS = Object.freeze({
  producer: 'dp:r1-producer@example.test',
  reviewer: 'dp:r1-reviewer@example.test',
});
export const ARTIFACT = Buffer.from('r1 attributed artifact\n', 'utf8');
export const EVIDENCE = Buffer.from('r1 attributed findings\n', 'utf8');

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const pem = (key) => key.export({ type: 'spki', format: 'pem' });

/**
 * A DIFFERENT base64 STRING for the SAME bytes, produced by flipping one bit that the padding makes
 * insignificant. This is the representation `signatureValid`'s re-encode comparison exists to
 * refuse: the signature still verifies cryptographically, so nothing but that comparison stands
 * between the record and two distinct byte sequences that both "are" the signature.
 *
 * Self-checking rather than assumed: it asserts the string changed and the decoded bytes did not.
 */
export function nonCanonicalBase64(value) {
  const pad = value.indexOf('=');
  const last = (pad === -1 ? value.length : pad) - 1;
  const twin = value.slice(0, last) + BASE64[BASE64.indexOf(value[last]) ^ 1] + value.slice(last + 1);
  assert.notEqual(twin, value, 'the twin representation must differ as a string');
  assert.ok(
    Buffer.from(twin, 'base64').equals(Buffer.from(value, 'base64')),
    'the twin must decode to identical bytes, or this is a forged signature rather than a re-encoding',
  );
  return twin;
}

/**
 * @returns {{input: object, envelope: object, trust: object, policy: object}} the verifier input
 *   alongside the documents it was built from, so a case can read a real digest or key id back out
 *   rather than recomputing one and risking agreement by coincidence.
 */
export function build({
  producerClaim = {}, reviewerClaim = {},
  producerEnrol = {}, reviewerEnrol = {},
  trustExtra = [],
  artifact = {}, review = {},
  producerNonCanonical = false, reviewerNonCanonical = false,
  producerSignature = {},
  policy = {}, expected = {}, verify = {},
} = {}) {
  const producerKey = generateKeyPairSync('ed25519');
  const reviewerKey = generateKeyPairSync('ed25519');
  const attemptId = `attempt:${'cd'.repeat(16)}`;
  const commit = 'e'.repeat(40);
  const pr = 42;

  const producer = {
    principal: PRINCIPALS.producer, family: 'claude', family_trust: 'declared', key_id: 'r1-producer', ...producerClaim,
  };
  const reviewer = {
    principal: PRINCIPALS.reviewer, family: 'codex', family_trust: 'declared', key_id: 'r1-reviewer', ...reviewerClaim,
  };

  // Resolved and stamped BEFORE the producer signs, because the producer signature covers
  // policy_version. A case that sets policy_version itself (a deliberate mismatch) keeps it verbatim.
  const policyContent = {
    schema: 'quorum-policy/1',
    accepted_verdicts: ['APPROVE', 'CHANGES_REQUIRED', 'REJECT'],
    require_family_inequality: true,
    require_family_trust: 'declared',
    require_pr_binding: true,
    require_evidence: true,
    // Required by quorum-policy/1 since the residue declaration (Q19). Off by default, as in fixtures/shared/policy-declared.json.
    require_residue_declaration: false,
    ...policy,
  };
  const resolvedPolicy = Object.hasOwn(policy, 'policy_version')
    ? { schema: policyContent.schema, policy_version: policy.policy_version, ...policyContent }
    : stampPolicyVersion(POLICY_LABEL, { schema: policyContent.schema, policy_version: null, ...policyContent });

  const half = createProducerHalf({
    policyVersion: resolvedPolicy.policy_version,
    attemptId,
    artifact: { kind: 'git_commit', commit, digest: sha256Ref(ARTIFACT), ...artifact },
    producer,
    privateKey: producerKey.privateKey,
  });
  // Re-encoded BEFORE the countersignature, so the reviewer genuinely signs this representation.
  // Twinning it afterwards would be refused by Q12 and would never reach Q10's comparison at all.
  if (producerNonCanonical) half.signature = { ...half.signature, value: nonCanonicalBase64(half.signature.value) };
  // Also BEFORE the countersignature, and for the same reason. `reviewerPayload` covers the whole
  // producer signature OBJECT, algorithm included, so overriding the declared algorithm here yields
  // an envelope the reviewer genuinely countersigned — the only way to reach the schema's constant
  // on that field rather than being turned away by Q12 first.
  half.signature = { ...half.signature, ...producerSignature };

  const envelope = createEnvelope({
    producerHalf: half,
    reviewer,
    review: { verdict: 'APPROVE', pr, evidence_digest: sha256Ref(EVIDENCE), ...review },
    privateKey: reviewerKey.privateKey,
  });
  // Nothing signs the reviewer's own signature, so this one is re-encoded after the fact.
  if (reviewerNonCanonical) {
    envelope.signatures.reviewer = { ...envelope.signatures.reviewer, value: nonCanonicalBase64(envelope.signatures.reviewer.value) };
  }

  const trust = {
    schema: 'quorum-trust/1',
    keys: [
      {
        key_id: 'r1-producer',
        principal: PRINCIPALS.producer,
        family: 'claude',
        family_evidence: 'declared',
        roles: ['producer'],
        public_key_pem: pem(producerKey.publicKey),
        ...producerEnrol,
      },
      {
        key_id: 'r1-reviewer',
        principal: PRINCIPALS.reviewer,
        family: 'codex',
        family_evidence: 'declared',
        roles: ['reviewer'],
        public_key_pem: pem(reviewerKey.publicKey),
        ...reviewerEnrol,
      },
      // Extra enrolments the envelope never names. A store-integrity guard that only examines the
      // two keys actually used is not a store-integrity guard.
      ...trustExtra.map((extra) => (typeof extra === 'function' ? extra({ producerKey, reviewerKey, pem }) : extra)),
    ],
  };

  const input = {
    envelopeText: JSON.stringify(envelope, null, 2),
    policyText: JSON.stringify(resolvedPolicy),
    trustText: JSON.stringify(trust),
    expected: { attemptId, commit, pr, ...expected },
    artifactBytes: ARTIFACT,
    evidenceBytes: EVIDENCE,
    ...verify,
  };

  return { input, envelope, trust, policy: resolvedPolicy };
}

/** The common case: build a bundle and verify it in one step. */
export const mint = (options) => verifyEnvelope(build(options).input);

export const passes = (result, why) => assert.equal(result.ok, true, `${why}: refused by ${result.guard} — ${result.why}`);

export function refuses(result, guard, why) {
  assert.equal(result.ok, false, why);
  assert.equal(result.guard, guard, `refused, but by ${result.guard} rather than ${guard}: ${result.why}`);
}

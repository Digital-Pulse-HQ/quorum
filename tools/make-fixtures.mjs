#!/usr/bin/env node
// Deterministic fixture generator.
//
// NO PRIVATE KEY BYTES ARE COMMITTED. Every fixture key is derived at generation time from a
// committed English phrase — `seed = SHA-256(phrase)`, wrapped in the fixed 16-byte PKCS#8 prefix
// for Ed25519 — so the repository holds public keys, signatures and the phrases, and anyone can
// reproduce the private halves without any of them ever being stored. Committing a PEM private key
// here would both trip the repository's gitleaks job and erase the producer/reviewer separation the
// package exists to create.
//
// Ed25519 is deterministic, so regenerating produces byte-identical fixtures. test/fixtures.test.mjs
// re-runs this generator into a temporary directory and diffs it against the committed tree: a
// fixture edited by hand to make a test pass is caught as drift.

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createEnvelope, createProducerHalf, sha256Ref, stampPolicyVersion,
} from '../src/envelope.mjs';
import { canonicalBytes } from '../src/canonical.mjs';
import { sign as signBytes } from 'node:crypto';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));

// The 16 bytes preceding an Ed25519 seed in a PKCS#8 DER document: SEQUENCE, version 0,
// AlgorithmIdentifier { 1.3.101.112 }, OCTET STRING wrapper, OCTET STRING(32).
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function keyFromPhrase(phrase) {
  const seed = createHash('sha256').update(phrase, 'utf8').digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  return {
    phrase,
    privateKey,
    publicKeyPem: createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }),
  };
}

const hex = (phrase, length) => createHash('sha256').update(phrase, 'utf8').digest('hex').slice(0, length);

const KEYS = {
  producerClaude: keyFromPhrase('quorum fixture key: producer, claude family, declared enrolment'),
  reviewerCodex: keyFromPhrase('quorum fixture key: reviewer, codex family, declared enrolment'),
  reviewerClaude: keyFromPhrase('quorum fixture key: reviewer, claude family, declared enrolment'),
  reviewerGeminiObserved: keyFromPhrase('quorum fixture key: reviewer, gemini family, synthetic observed enrolment'),
  producerGeminiObserved: keyFromPhrase('quorum fixture key: producer, claude family, synthetic observed enrolment'),
  rogue: keyFromPhrase('quorum fixture key: never enrolled in any trust store'),
  // ONE key, enrolled twice, on opposite sides of a review.
  dualEnrolled: keyFromPhrase('quorum fixture key: one key enrolled twice, duplicate key material self-approval'),
};

// EVERY IDENTITY HERE IS SYNTHETIC. Principals use the RFC 2606 / RFC 6761 reserved `example.invalid`
// domain and key ids name a role and a letter, never a person or a deployed agent, so the corpus
// describes no real organisation. A release check outside this package scans the packed file list for
// real identities and fails by name on any hit.
const PRINCIPALS = {
  producer: 'example:producer-a@example.invalid',
  reviewerCodex: 'example:reviewer-b@example.invalid',
  reviewerClaude: 'example:reviewer-c@example.invalid',
  reviewerGemini: 'example:reviewer-d@example.invalid',
  producerObserved: 'example:producer-e@example.invalid',
  dualProducer: 'example:dual-enrolled-producer@example.invalid',
  dualReviewer: 'example:dual-enrolled-reviewer@example.invalid',
};

/**
 * The SAME key material, re-wrapped with CRLF line endings instead of the default LF. Decodes to
 * byte-identical SPKI DER, but is not byte-identical AS TEXT. The duplicate-material check must compare
 * normalized key bytes, not the PEM string, and this is the transport-level difference a naive string
 * comparison would miss.
 */
function crlfPem(pem) {
  return pem.replace(/\n/g, '\r\n');
}

// POLICY IDENTITY. These are LABELS, not versions. A `policy_version` is `<label>+<content identity>`
// and only `stampPolicyVersion` may produce one — the collision this replaced came from four
// materially different policy documents being handed the same hand-written string.
//
// The residue policy gets its own DATE as well as its own identity. The identity alone would already
// distinguish it, but a reader should be able to see from the label that Q19 is a later governance
// generation and not a variant of the 2026-09-10 policy.
const POLICY_LABEL = 'quorum-policy/1@2026-09-10';
const RESIDUE_POLICY_LABEL = 'quorum-policy/1@2026-09-28';
const ATTEMPT = `attempt:${hex('quorum fixture attempt 1', 32)}`;
const STALE_ATTEMPT = `attempt:${hex('quorum fixture attempt 0 (superseded)', 32)}`;
const COMMIT = hex('quorum fixture reviewed commit', 40);
const OTHER_COMMIT = hex('quorum fixture some other commit', 40);
const PR = 42;

const ARTIFACT = 'quorum fixture artifact: the reviewed bytes\n';
const EVIDENCE = '# Fixture review evidence\n\nThe reviewer\'s findings document, bound by digest into the envelope.\n';
const OTHER_EVIDENCE = '# A different review\n\nSame reviewer, different findings. Its digest must not satisfy the envelope.\n';

const ARTIFACT_DIGEST = sha256Ref(Buffer.from(ARTIFACT, 'utf8'));
const EVIDENCE_DIGEST = sha256Ref(Buffer.from(EVIDENCE, 'utf8'));

const trustEntry = (keyId, principal, family, familyEvidence, roles, key) => ({
  key_id: keyId,
  principal,
  family,
  family_evidence: familyEvidence,
  roles,
  public_key_pem: key.publicKeyPem,
});

const TRUST = {
  schema: 'quorum-trust/1',
  keys: [
    trustEntry('producer-a-claude', PRINCIPALS.producer, 'claude', 'declared', ['producer'], KEYS.producerClaude),
    trustEntry('reviewer-b-codex', PRINCIPALS.reviewerCodex, 'codex', 'declared', ['reviewer'], KEYS.reviewerCodex),
    trustEntry('reviewer-c-claude', PRINCIPALS.reviewerClaude, 'claude', 'declared', ['reviewer'], KEYS.reviewerClaude),
    // `observed` enrolments. These two exist so the trust level is exercised in the PASSING direction
    // as well as the failing one — a field that can only ever refuse has never been shown to mean
    // anything.
    trustEntry('producer-e-observed', PRINCIPALS.producerObserved, 'claude', 'observed', ['producer'], KEYS.producerGeminiObserved),
    trustEntry('reviewer-d-gemini', PRINCIPALS.reviewerGemini, 'gemini', 'observed', ['reviewer'], KEYS.reviewerGeminiObserved),
  ],
};

const policy = (label, overrides = {}) => stampPolicyVersion(label, {
  schema: 'quorum-policy/1',
  // Placeholder: stampPolicyVersion replaces it in place with `<label>+<identity>`, so the key
  // keeps its authored position and no caller can hand-write a version.
  policy_version: null,
  accepted_verdicts: ['APPROVE', 'CHANGES_REQUIRED', 'REJECT'],
  require_family_inequality: true,
  require_family_trust: 'declared',
  require_pr_binding: true,
  require_evidence: true,
  // Required key as of 2026-09-28 (Q19). The BASE policy leaves it false so that every
  // pre-existing fixture keeps testing exactly the guard it was written for; the residue
  // guard gets its own dedicated policy and fixtures below, rather than being smuggled
  // into 43 unrelated cases where a failure would be ambiguous.
  require_residue_declaration: false,
  ...overrides,
});

const POLICY_DECLARED = policy(POLICY_LABEL);
const POLICY_OBSERVED = policy(POLICY_LABEL, { require_family_trust: 'observed' });
const POLICY_NO_PR = policy(POLICY_LABEL, { require_pr_binding: false });
const POLICY_RESIDUE = policy(RESIDUE_POLICY_LABEL, { require_residue_declaration: true });

// Every fixture built against a non-default policy must CLAIM that policy's version, or it is
// refused by Q05 before reaching the guard it was written to exercise. Before policy identity they all
// claimed the one shared string, which is precisely why `valid-cross-family-approve` and
// `residue-absent-under-requiring-policy` came out byte-identical.
const VERSION = {
  declared: POLICY_DECLARED.policy_version,
  observed: POLICY_OBSERVED.policy_version,
  noPr: POLICY_NO_PR.policy_version,
  residue: POLICY_RESIDUE.policy_version,
};

{
  const distinct = new Set(Object.values(VERSION));
  if (distinct.size !== Object.keys(VERSION).length) {
    throw new Error(`policy identities collided: ${JSON.stringify(VERSION)} — four materially different policies must not share a version`);
  }
}

function build({
  producerKey = KEYS.producerClaude,
  producerKeyId = 'producer-a-claude',
  producerPrincipal = PRINCIPALS.producer,
  producerFamily = 'claude',
  producerTrust = 'declared',
  reviewerKey = KEYS.reviewerCodex,
  reviewerKeyId = 'reviewer-b-codex',
  reviewerPrincipal = PRINCIPALS.reviewerCodex,
  reviewerFamily = 'codex',
  reviewerTrust = 'declared',
  verdict = 'APPROVE',
  pr = PR,
  attempt = ATTEMPT,
  commit = COMMIT,
  artifactDigest = ARTIFACT_DIGEST,
  evidenceDigest = EVIDENCE_DIGEST,
  policyVersion = VERSION.declared,
  residue = undefined,
} = {}) {
  const half = createProducerHalf({
    policyVersion,
    attemptId: attempt,
    artifact: { kind: 'git_commit', commit, digest: artifactDigest },
    producer: {
      principal: producerPrincipal, family: producerFamily, family_trust: producerTrust, key_id: producerKeyId,
    },
    privateKey: producerKey.privateKey,
  });
  return createEnvelope({
    producerHalf: half,
    reviewer: {
      principal: reviewerPrincipal, family: reviewerFamily, family_trust: reviewerTrust, key_id: reviewerKeyId,
    },
    // residue is included ONLY when supplied, so every pre-existing fixture keeps its exact
    // signed bytes and this change cannot silently invalidate an unrelated signature.
    review: residue === undefined
      ? { verdict, pr, evidence_digest: evidenceDigest }
      : { verdict, pr, evidence_digest: evidenceDigest, residue },
    privateKey: reviewerKey.privateKey,
  });
}

/**
 * Sign an envelope whose `review.pr` is a string. `build` cannot express it because createEnvelope
 * normalises pr, and the second trailer literally carries `not-a-pr` — a fixture that quietly
 * corrected it to an integer would not be that trailer.
 */
function buildWithRawPr(rawPr, options) {
  const envelope = build({ ...options, pr: 1 });
  const { signatures, ...rest } = envelope;
  const unsigned = { ...rest, review: { ...rest.review, pr: rawPr }, signatures: { producer: signatures.producer } };
  const key = options.reviewerKey ?? KEYS.reviewerCodex;
  const value = signBytes(null, canonicalBytes(unsigned), key.privateKey).toString('base64');
  return { ...unsigned, signatures: { producer: signatures.producer, reviewer: { algorithm: 'ed25519', value } } };
}

/**
 * THE LEGACY CANONICAL FORM, reconstructed explicitly rather than approximated.
 *
 * An earlier `src/canonical.mjs` refused non-integers only (`Number.isInteger`); the unsafe-integer
 * fix narrowed that to `Number.isSafeInteger`. This is a verbatim copy of the PRE-fix number branch, over the current serialiser, and it exists for one reason: the current
 * `canonicalBytes` cannot produce the bytes the old implementation signed for an unsafe integer, so
 * without it no fixture in this tree can be signed the way the defect actually was.
 *
 * It is a FIXTURE-GENERATION helper and is deliberately not exported from `src/`. Nothing the
 * package ships may canonicalise an unsafe integer; the point is to commit evidence of what the old
 * code accepted, not to keep a route to it. `canonicalize` is re-implemented here rather than
 * imported-and-patched so that a future change to the shipped canonical form cannot silently change
 * what this fixture claims the OLD form was.
 */
function legacyCanonicalize(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error(`legacy canonical form: only integers, got ${value}`);
    return String(value === 0 ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(legacyCanonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${legacyCanonicalize(value[key])}`).join(',')}}`;
  }
  throw new Error(`legacy canonical form: values of type ${typeof value} are not canonicalisable`);
}

/**
 * An envelope whose reviewer countersignature was produced by the PRE-fix canonical form over an
 * unsafe `review.pr`. The producer half is untouched and still signed by the shipped code, because
 * no unsafe value appears in it — only the reviewer payload carries `review.pr`.
 */
function buildLegacySignedPr(unsafePr, options = {}) {
  const envelope = build({ ...options, pr: 1 });
  const { signatures, ...rest } = envelope;
  const unsigned = { ...rest, review: { ...rest.review, pr: unsafePr }, signatures: { producer: signatures.producer } };
  const key = options.reviewerKey ?? KEYS.reviewerCodex;
  const value = signBytes(null, Buffer.from(legacyCanonicalize(unsigned), 'utf8'), key.privateKey).toString('base64');
  return { ...unsigned, signatures: { producer: signatures.producer, reviewer: { algorithm: 'ed25519', value } } };
}

/** Tamper with a signed envelope after the fact. Signatures are deliberately NOT recomputed. */
function tamper(envelope, mutate) {
  const copy = JSON.parse(JSON.stringify(envelope));
  mutate(copy);
  return copy;
}

function flipBase64Byte(value) {
  const bytes = Buffer.from(value, 'base64');
  bytes[0] ^= 0xff;
  return bytes.toString('base64');
}

const POSITIVE = build();

const cases = [];
const files = new Map();

const put = (path, content) => {
  files.set(path, typeof content === 'string' ? content : `${JSON.stringify(content, null, 2)}\n`);
};

put('shared/artifact.txt', ARTIFACT);
put('shared/evidence.md', EVIDENCE);
put('shared/other-evidence.md', OTHER_EVIDENCE);
put('shared/trust.json', TRUST);
put('shared/policy-declared.json', POLICY_DECLARED);
put('shared/policy-observed.json', POLICY_OBSERVED);
put('shared/trust-duplicate-key-id.json', {
  schema: 'quorum-trust/1',
  keys: [...TRUST.keys, trustEntry('reviewer-b-codex', PRINCIPALS.reviewerCodex, 'codex', 'declared', ['reviewer'], KEYS.rogue)],
});
// The SAME key enrolled twice — once as a producer under one identity, again
// as a reviewer under a completely different identity — with the second enrolment's PEM re-wrapped
// with CRLF line endings. Same key_id collision check (Q04's original half) does NOT fire here: the
// key_ids, principals, families and roles are all different. Only comparing the normalized key
// material catches this.
put('shared/trust-duplicate-key-material.json', {
  schema: 'quorum-trust/1',
  keys: [
    ...TRUST.keys,
    trustEntry('dual-enrolled-producer-key', PRINCIPALS.dualProducer, 'claude', 'declared', ['producer'], KEYS.dualEnrolled),
    trustEntry(
      'dual-enrolled-reviewer-key',
      PRINCIPALS.dualReviewer,
      'codex',
      'declared',
      ['reviewer'],
      { ...KEYS.dualEnrolled, publicKeyPem: crlfPem(KEYS.dualEnrolled.publicKeyPem) },
    ),
  ],
});
put('shared/policy-unknown-field.json', { ...POLICY_DECLARED, allow_self_review: true });

const base = {
  policy: 'shared/policy-declared.json',
  trust: 'shared/trust.json',
  artifact: 'shared/artifact.txt',
  evidence: 'shared/evidence.md',
  attempt: ATTEMPT,
  commit: COMMIT,
  pr: PR,
};

function addCase(entry) {
  const { envelope, envelope_path: envelopePath, ...rest } = entry;
  if (envelope !== undefined) put(envelopePath, envelope);
  cases.push({ ...base, ...rest, envelope: envelopePath });
}

function passing(name, description, envelope, overrides = {}) {
  addCase({
    name,
    kind: 'positive',
    description,
    envelope_path: `positive/${name}.json`,
    envelope,
    expect: { ok: true },
    ...overrides,
  });
}

function refusing(name, description, guard, envelope, overrides = {}) {
  addCase({
    name,
    kind: 'adversarial',
    description,
    envelope_path: `adversarial/${name}.json`,
    envelope,
    expect: { ok: false, guard },
    ...overrides,
  });
}

// ---------------------------------------------------------------------------------------------
// Positive controls.
// ---------------------------------------------------------------------------------------------

passing(
  'valid-cross-family-approve',
  'claude produced, codex reviewed, both signatures cover this artifact digest, APPROVE on pr 42.',
  POSITIVE,
);

passing(
  'observed-enrolment-under-observed-policy',
  'The same shape at observed family evidence, against a policy that demands it. Paired with declared-under-observed-policy, which is the identical request at declared evidence and is refused.',
  build({
    policyVersion: VERSION.observed,
    producerKey: KEYS.producerGeminiObserved,
    producerKeyId: 'producer-e-observed',
    producerPrincipal: PRINCIPALS.producerObserved,
    producerTrust: 'observed',
    reviewerKey: KEYS.reviewerGeminiObserved,
    reviewerKeyId: 'reviewer-d-gemini',
    reviewerPrincipal: PRINCIPALS.reviewerGemini,
    reviewerFamily: 'gemini',
    reviewerTrust: 'observed',
  }),
  { policy: 'shared/policy-observed.json' },
);

passing(
  'no-pr-binding-under-permissive-policy',
  'A review with no PR at all, under a policy that does not require the binding. The Markdown file protocol and a hand-reviewed patch have no PR number; the format must carry them without pretending one exists.',
  build({ pr: null, policyVersion: VERSION.noPr }),
  { policy: 'shared/policy-no-pr.json', pr: null },
);
put('shared/policy-no-pr.json', POLICY_NO_PR);

// ---------------------------------------------------------------------------------------------
// Q19 — the residue declaration (adopted 2026-09-28 from `disensor`).
// The property under test is that an ABSENT residue and an EMPTY one are opposite claims, so the
// empty case is a POSITIVE fixture and the absent case is an ADVERSARIAL one under the same policy.
// Without both, "requires residue" would be indistinguishable from "requires a non-empty residue",
// and a reviewer with genuinely nothing to declare could not produce a passing envelope at all.
// ---------------------------------------------------------------------------------------------
put('shared/policy-residue.json', POLICY_RESIDUE);

const RESIDUE_FULL = {
  undecided: ['whether the retry path can double-submit under a partitioned network'],
  refuted: [{
    claim: 'the digest comparison is timing-unsafe',
    evidence: 'timingSafeEqual is used at verify.mjs; a 10k-iteration timing run showed no separation',
  }],
  unsettled_by_execution: ['the CI audit job could not run: the Actions allowance was exhausted'],
  reviewer_limits: ['did not review the generated corpus; read only the four source files in the diff'],
};
const RESIDUE_EMPTY = { undecided: [], refuted: [], unsettled_by_execution: [], reviewer_limits: [] };

passing(
  'residue-declared',
  'A policy requiring a residue declaration, with a fully populated one. This is the shape the format exists to carry: what the review could not settle, not what it scored.',
  build({ residue: RESIDUE_FULL, policyVersion: VERSION.residue }),
  { policy: 'shared/policy-residue.json' },
);

passing(
  'residue-declared-empty',
  'The same policy with every residue array empty. An empty residue is the reviewer ASSERTING there was nothing undecided, nothing refuted, nothing execution could not settle and no limits worth declaring — a strong signed claim. It must pass, or a clean review becomes unrepresentable. THE POSITIVE CONTROL policy identity must preserve: residue may validly be empty, and this still passes under the real residue policy after the identity change.',
  build({ residue: RESIDUE_EMPTY, policyVersion: VERSION.residue }),
  { policy: 'shared/policy-residue.json' },
);

refusing(
  'residue-absent-under-requiring-policy',
  'The same policy, and an envelope with no residue block at all. Absent is not empty: it records that the reviewer never addressed what it could not settle. Compare with residue-declared-empty, which differs only by carrying the empty residue and passes. Before policy identity this envelope was BYTE-IDENTICAL to positive/valid-cross-family-approve because both claimed the one shared policy_version; it now claims the residue policy\'s own version, so the file is what its name says it is.',
  'Q19_RESIDUE_DECLARATION',
  build({ policyVersion: VERSION.residue }),
  { policy: 'shared/policy-residue.json' },
);

// ---------------------------------------------------------------------------------------------
// Q20: two materially different canonical policy documents sharing ONE
// policy_version.
//
// This is the policy-identity collision, executable. `policy-identity-collision.json` is the RESIDUE policy's content
// carrying the DECLARED policy's version string verbatim — so the fixture tree contains two
// different canonical policy documents that both say `VERSION.declared`, exactly the state that
// used to make the same signed envelope both PASS and INVALID.
//
// A verifier only ever holds ONE of the two, so it cannot detect the collision by comparison. It
// detects it by recomputation: this document does not hash to the identity it declares, so it is
// refused on sight, and the ONLY document that can legitimately claim `VERSION.declared` is the one
// whose content produced it. That is what makes the version string an identity again.
// ---------------------------------------------------------------------------------------------
put('shared/policy-identity-collision.json', { ...POLICY_RESIDUE, policy_version: VERSION.declared });

refusing(
  'policy-identity-collision',
  'A policy document requiring a residue declaration, stamped with the NON-residue policy\'s version string. It is materially different from shared/policy-declared.json and claims the same policy_version, which is the collision policy identity exists to refuse. The envelope, trust store, artifact, evidence, attempt, commit and PR are the untouched positive control, so the refusal is attributable to the policy\'s identity and nothing else.',
  'Q20_POLICY_IDENTITY',
  undefined,
  { envelope_path: 'positive/valid-cross-family-approve.json', policy: 'shared/policy-identity-collision.json' },
);


// ---------------------------------------------------------------------------------------------
// The trailer table — three review trailers that a valid producer attestation carried to PASS under
// a producer-only verifier.
// Each is reproduced as faithfully as the envelope format allows, then REPAIRED one defect at a
// time, so the refusal is attributable to the trailer's own defect rather than to something
// incidental about the fixture.
// ---------------------------------------------------------------------------------------------

refusing(
  'trailer-1-untrusted-reviewer-approve',
  'Trailer table, row 1: verdict APPROVE, reviewer "reviewer-b (codex)", pr 42. The reviewer is untrusted free text signed by a key no trust store enrols. Under the producer-only verifier this returned PASS.',
  'Q11_REVIEWER_ENROLMENT',
  build({
    reviewerKey: KEYS.rogue,
    reviewerKeyId: 'rogue-unenrolled-key',
    reviewerPrincipal: 'reviewer-b (codex)',
    verdict: 'APPROVE',
    pr: 42,
  }),
  { origin: 'trailer table, row 1' },
);

passing(
  'trailer-1-repaired-identity',
  'Row 1 with its ONLY defect repaired: the same APPROVE on pr 42, from the enrolled codex reviewer. It passes, which is what makes the refusal above attributable to the untrusted principal and nothing else.',
  build({ verdict: 'APPROVE', pr: 42 }),
  { origin: 'trailer table, row 1 (repaired control)' },
);

refusing(
  'trailer-2-self-approved-not-a-pr',
  'Trailer table, row 2: verdict "SELF APPROVED", reviewer "same-family producer", pr "not-a-pr". The pr is a string, so the envelope is not a quorum/1 record at all.',
  'Q02_ENVELOPE_SCHEMA',
  buildWithRawPr('not-a-pr', {
    reviewerKey: KEYS.rogue,
    reviewerKeyId: 'rogue-unenrolled-key',
    reviewerPrincipal: 'same-family producer',
    verdict: 'SELF APPROVED',
  }),
  { origin: 'trailer table, row 2' },
);

refusing(
  'trailer-2-repaired-pr-and-identity',
  'Row 2 with the pr made an integer and the reviewer made a genuinely enrolled claude-family principal. Now the verdict token is the defect: "SELF APPROVED" is not in the policy\'s accepted set.',
  'Q13_VERDICT',
  build({
    reviewerKey: KEYS.reviewerClaude,
    reviewerKeyId: 'reviewer-c-claude',
    reviewerPrincipal: PRINCIPALS.reviewerClaude,
    reviewerFamily: 'claude',
    verdict: 'SELF APPROVED',
  }),
  { origin: 'trailer table, row 2 (verdict isolated)' },
);

refusing(
  'trailer-2-repaired-verdict',
  'Row 2 with the verdict also repaired to APPROVE. Everything now verifies cryptographically and the review is still refused, because producer and reviewer are both claude. This is the "same-family producer" the row named.',
  'Q16_FAMILY_INEQUALITY',
  build({
    reviewerKey: KEYS.reviewerClaude,
    reviewerKeyId: 'reviewer-c-claude',
    reviewerPrincipal: PRINCIPALS.reviewerClaude,
    reviewerFamily: 'claude',
    verdict: 'APPROVE',
  }),
  { origin: 'trailer table, row 2 (family inequality isolated)' },
);

refusing(
  'trailer-3-changes-untrusted-999999',
  'Trailer table, row 3: verdict CHANGES, reviewer "untrusted-free-text", pr 999999. Untrusted principal first.',
  'Q11_REVIEWER_ENROLMENT',
  build({
    reviewerKey: KEYS.rogue,
    reviewerKeyId: 'rogue-unenrolled-key',
    reviewerPrincipal: 'untrusted-free-text',
    verdict: 'CHANGES',
    pr: 999999,
  }),
  { origin: 'trailer table, row 3' },
);

refusing(
  'trailer-3-repaired-identity',
  'Row 3 from the enrolled codex reviewer. The verdict token "CHANGES" is still not the policy\'s "CHANGES_REQUIRED"; a near-miss token is refused rather than guessed at.',
  'Q13_VERDICT',
  build({ verdict: 'CHANGES', pr: 999999 }),
  { origin: 'trailer table, row 3 (verdict isolated)' },
);

refusing(
  'trailer-3-repaired-verdict',
  'Row 3 with an accepted verdict token. pr 999999 is still not the commissioned pr 42, so the review is bound to a pull request nobody asked about.',
  'Q17_PR_BINDING',
  build({ verdict: 'CHANGES_REQUIRED', pr: 999999 }),
  { origin: 'trailer table, row 3 (pr binding isolated)' },
);

// ---------------------------------------------------------------------------------------------
// Mutation controls — a signed envelope, edited afterwards, signatures deliberately not recomputed.
// ---------------------------------------------------------------------------------------------

refusing(
  'mutated-verdict',
  'CHANGES_REQUIRED rewritten to APPROVE in a signed envelope. Under the producer-only verifier this was invisible; the countersignature covers the verdict.',
  'Q12_REVIEWER_SIGNATURE',
  tamper(build({ verdict: 'CHANGES_REQUIRED' }), (e) => { e.review.verdict = 'APPROVE'; }),
);

refusing(
  'mutated-pr',
  'The pr number edited after signing.',
  'Q12_REVIEWER_SIGNATURE',
  tamper(POSITIVE, (e) => { e.review.pr = 999; }),
  { pr: 999 },
);

// ---------------------------------------------------------------------------------------------
// Unsafe integers must not defeat the canonical form's single-encoding claim.
// ---------------------------------------------------------------------------------------------

passing(
  'pr-at-max-safe-integer-boundary',
  'review.pr at exactly Number.MAX_SAFE_INTEGER (2^53 - 1) — the last integer with a '
    + 'unique decimal-to-double mapping. The boundary value itself must still verify.',
  build({ pr: Number.MAX_SAFE_INTEGER }),
  { pr: Number.MAX_SAFE_INTEGER },
);

{
  // A CORRECTION. An earlier fixture signed `review.pr` at 9007199254740991 (MAX_SAFE_INTEGER) and
  // text-substituted 9007199254740993. Those two decimal tokens are two DIFFERENT doubles, so the
  // substitution broke the countersignature: run through the pre-fix verifier it returned
  // Q12_REVIEWER_SIGNATURE, i.e. an ordinary changed-value signature failure. It was named and described as the adjacent-integer collision
  // and was not one. Reproduced and replaced here rather than re-worded, because a fixture is
  // evidence and the evidence was for a different claim.
  //
  // THE ACTUAL DEFECT needs a signature made over the UNSAFE value, which only the pre-fix canonical
  // form could produce — hence `buildLegacySignedPr`. 9007199254740992 (2^53) and 9007199254740993
  // are two different decimal integers that JSON.parse collapses onto the SAME IEEE-754 double,
  // because doubles at or above 2^53 represent only even integers. So the legacy-signed envelope has
  // TWO valid wire texts for ONE signature: rewriting the token changes the bytes on disk, changes
  // nothing after parsing, and requires no resigning. Under the old code both verified. The wire
  // texts must be built by TEXT substitution, not by editing the parsed object, because the parsed
  // object cannot hold two decimal tokens that collapse to one double.
  const LEGACY_UNSAFE_PR = 9007199254740992;
  const ADJACENT_WIRE_TOKEN = '9007199254740993';
  const signedText = `${JSON.stringify(buildLegacySignedPr(LEGACY_UNSAFE_PR), null, 2)}\n`;
  const occurrences = signedText.split(String(LEGACY_UNSAFE_PR)).length - 1;
  if (occurrences !== 1) throw new Error(`unsafe-integer fixture: the pr token occurs ${occurrences} times, expected exactly 1`);
  const rewrittenText = signedText.replace(String(LEGACY_UNSAFE_PR), ADJACENT_WIRE_TOKEN);
  if (rewrittenText === signedText) throw new Error('unsafe-integer fixture: the adjacent-token rewrite did not land');

  put('adversarial/unsafe-integer-pr-legacy-signed.json', signedText);
  addCase({
    name: 'unsafe-integer-pr-legacy-signed',
    kind: 'adversarial',
    description: 'review.pr = 9007199254740992 (2^53), countersigned by the PRE-fix '
      + 'canonical form, which refused non-integers only. Genuinely valid under the old verifier. '
      + 'The current code refuses it at Q02_ENVELOPE_SCHEMA, before any signature is examined, '
      + 'because review.pr is now bounded at Number.MAX_SAFE_INTEGER.',
    envelope_path: 'adversarial/unsafe-integer-pr-legacy-signed.json',
    expect: { ok: false, guard: 'Q02_ENVELOPE_SCHEMA' },
    pr: LEGACY_UNSAFE_PR,
    origin: 'unsafe-integer wire ambiguity (corrected reproduction)',
  });

  put('adversarial/unsafe-integer-pr-adjacent-rewrite.json', rewrittenText);
  addCase({
    name: 'unsafe-integer-pr-adjacent-rewrite',
    kind: 'adversarial',
    description: 'The byte-for-byte same envelope as unsafe-integer-pr-legacy-signed '
      + 'with its one pr token rewritten from 9007199254740992 to 9007199254740993 and NOTHING '
      + 'resigned — the second valid wire representation of a single signature. It differs on disk, '
      + 'is identical after JSON.parse, and verified under the old code exactly as the original did. '
      + 'Refused now by the same Q02_ENVELOPE_SCHEMA maximum.',
    envelope_path: 'adversarial/unsafe-integer-pr-adjacent-rewrite.json',
    expect: { ok: false, guard: 'Q02_ENVELOPE_SCHEMA' },
    // The manifest is JSON: this entry is written from the same double and therefore carries the
    // even token. That is not a transcription slip, it IS the ambiguity — the wire distinction the
    // fixture file preserves cannot survive a parse/serialise round trip in any JSON document.
    pr: LEGACY_UNSAFE_PR,
    origin: 'unsafe-integer wire ambiguity (corrected reproduction)',
  });
}

refusing(
  'mutated-reviewer-principal',
  'The reviewer principal swapped for another enrolled principal while keeping the original key id.',
  'Q11_REVIEWER_ENROLMENT',
  tamper(POSITIVE, (e) => { e.reviewer.principal = PRINCIPALS.reviewerClaude; }),
);

refusing(
  'mutated-artifact-digest',
  'The artifact digest edited, so the envelope no longer describes the bytes the verifier recomputes.',
  'Q08_ARTIFACT_DIGEST',
  tamper(POSITIVE, (e) => { e.artifact.digest = sha256Ref(Buffer.from('some other bytes', 'utf8')); }),
);

refusing(
  'mutated-commit',
  'The reviewed commit edited to a different commit.',
  'Q07_ARTIFACT_BINDING',
  tamper(POSITIVE, (e) => { e.artifact.commit = OTHER_COMMIT; }),
);

refusing(
  'mutated-attempt',
  'The attempt id edited to the attempt the verifier commissioned, from an envelope signed for another.',
  'Q06_ATTEMPT_BINDING',
  tamper(build({ attempt: STALE_ATTEMPT }), (e) => { e.attempt_id = `attempt:${hex('quorum fixture attempt 2', 32)}`; }),
);

refusing(
  'mutated-policy-version',
  'The policy version edited, so the envelope claims to have been produced under a policy the verifier was not handed. The forged value is SHAPE-VALID under policy identity — it carries a well-formed 128-bit identity suffix — so it reaches Q05 rather than being caught earlier by the envelope schema. No policy document in this tree has that identity, which is the point: the claim names a policy nobody can produce.',
  'Q05_POLICY_VERSION',
  tamper(POSITIVE, (e) => { e.policy_version = `quorum-policy/1@2020-01-01+${hex('quorum fixture: a policy identity no document in this tree hashes to', 32)}`; }),
);

refusing(
  'mutated-producer-signature',
  'A byte flipped in the producer signature. The producer half is checked on its own before the countersignature, so the failure names the producer.',
  'Q10_PRODUCER_SIGNATURE',
  tamper(POSITIVE, (e) => { e.signatures.producer.value = flipBase64Byte(e.signatures.producer.value); }),
);

refusing(
  'stale-attempt',
  'A genuine, fully valid review — of the PREVIOUS attempt. Every signature verifies; the review is simply not of the work in front of the gate.',
  'Q06_ATTEMPT_BINDING',
  build({ attempt: STALE_ATTEMPT }),
);

refusing(
  'signed-trust-overclaim',
  'A properly signed envelope asserting `observed` family evidence on a key enrolled as `declared`. Every signature verifies. An envelope may not claim more trust than its enrolment carries.',
  'Q14_TRUST_ENROLMENT',
  build({ producerTrust: 'observed' }),
);

refusing(
  'declared-under-observed-policy',
  'The valid declared envelope, produced under — and correctly claiming — the observed policy\'s own version, which requires observed family evidence. A family the principal declares about itself is not evidence the policy accepts, so the honest result is a refusal, not a re-transcription of a self-declaration as proof. It claims the observed policy\'s version because the two policies no longer share one, and an envelope claiming the declared version would be refused by Q05 before reaching this guard.',
  'Q15_TRUST_POLICY',
  build({ policyVersion: VERSION.observed }),
  { policy: 'shared/policy-observed.json' },
);

refusing(
  'unenrolled-producer',
  'The producer signs with a key no trust store enrols.',
  'Q09_PRODUCER_ENROLMENT',
  build({ producerKey: KEYS.rogue, producerKeyId: 'rogue-unenrolled-key' }),
);

refusing(
  'producer-key-wrong-family',
  'A validly enrolled producer key used to assert a different family. Family comes from the enrolment, never from the envelope.',
  'Q09_PRODUCER_ENROLMENT',
  build({ producerFamily: 'codex' }),
);

refusing(
  'reviewer-key-wrong-role',
  'The producer\'s own key used to sign the reviewer half. It is enrolled for `producer` only.',
  'Q11_REVIEWER_ENROLMENT',
  build({
    reviewerKey: KEYS.producerClaude,
    reviewerKeyId: 'producer-a-claude',
    reviewerPrincipal: PRINCIPALS.producer,
    reviewerFamily: 'claude',
  }),
);

refusing(
  'duplicate-key-material-self-approval',
  'ONE Ed25519 keypair enrolled twice in the same trust store — once as '
    + '`dual-enrolled-producer-key`/claude/producer, again as `dual-enrolled-reviewer-key`/codex/reviewer, the second '
    + 'enrolment\'s PEM re-wrapped with CRLF line endings so a PEM-STRING comparison would miss the '
    + 'collision. The producer half and the reviewer half are both signed with that single private '
    + 'key. Without the key-material check, verifyEnvelope() returns ok:true, PASS, "claude produced, codex '
    + 'reviewed" — every artifact, evidence, attempt, commit, PR, policy and signature check '
    + 'genuinely passes while one controlling key has self-approved and the claimed family '
    + 'inequality remains literally true.',
  'Q04_TRUST_STORE',
  build({
    producerKey: KEYS.dualEnrolled,
    producerKeyId: 'dual-enrolled-producer-key',
    producerPrincipal: PRINCIPALS.dualProducer,
    producerFamily: 'claude',
    reviewerKey: KEYS.dualEnrolled,
    reviewerKeyId: 'dual-enrolled-reviewer-key',
    reviewerPrincipal: PRINCIPALS.dualReviewer,
    reviewerFamily: 'codex',
    verdict: 'APPROVE',
  }),
  { trust: 'shared/trust-duplicate-key-material.json' },
);

// ---------------------------------------------------------------------------------------------
// Deletion and malformation controls.
// ---------------------------------------------------------------------------------------------

refusing(
  'deleted-reviewer-signature',
  'The reviewer signature removed. A record missing the countersignature is not a quorum/1 envelope.',
  'Q02_ENVELOPE_SCHEMA',
  tamper(POSITIVE, (e) => { delete e.signatures.reviewer; }),
);

addCase({
  name: 'deleted-envelope',
  kind: 'adversarial',
  description: 'DELETION CONTROL. The envelope file does not exist. Absence must be a refusal, never a skipped check that leaves the gate green.',
  envelope_path: 'adversarial/does-not-exist.json',
  expect: { ok: false, guard: 'Q00_INPUT_PRESENT' },
});

addCase({
  name: 'deleted-trust-store',
  kind: 'adversarial',
  description: 'DELETION CONTROL. The trust store is absent, so nothing could be authenticated.',
  envelope_path: 'positive/valid-cross-family-approve.json',
  trust: 'shared/does-not-exist.json',
  expect: { ok: false, guard: 'Q00_INPUT_PRESENT' },
});

addCase({
  name: 'deleted-evidence',
  kind: 'adversarial',
  description: 'DELETION CONTROL. The policy requires the review evidence document and it has been deleted. Deleting the review evidence must make the check fail.',
  envelope_path: 'positive/valid-cross-family-approve.json',
  evidence: 'shared/does-not-exist.md',
  expect: { ok: false, guard: 'Q18_EVIDENCE_BINDING' },
});

addCase({
  name: 'swapped-evidence',
  kind: 'adversarial',
  description: 'A different findings document presented for the same envelope.',
  envelope_path: 'positive/valid-cross-family-approve.json',
  evidence: 'shared/other-evidence.md',
  expect: { ok: false, guard: 'Q18_EVIDENCE_BINDING' },
});

addCase({
  name: 'no-artifact-recomputation',
  kind: 'adversarial',
  description: 'Neither the artifact bytes nor a caller-computed digest is supplied, so nothing was recomputed. The verifier refuses rather than accepting the envelope\'s own claim about the artifact.',
  envelope_path: 'positive/valid-cross-family-approve.json',
  artifact: null,
  expect: { ok: false, guard: 'Q08_ARTIFACT_DIGEST' },
});

addCase({
  name: 'malformed-trust-store',
  kind: 'adversarial',
  description: 'The trust store enrols the same key id twice, with different public keys. A store that cannot be read unambiguously is refused as a store.',
  envelope_path: 'positive/valid-cross-family-approve.json',
  trust: 'shared/trust-duplicate-key-id.json',
  expect: { ok: false, guard: 'Q04_TRUST_STORE' },
});

addCase({
  name: 'malformed-policy',
  kind: 'adversarial',
  description: 'A policy carrying an unknown field. An unrecognised governance switch is refused, not ignored.',
  envelope_path: 'positive/valid-cross-family-approve.json',
  policy: 'shared/policy-unknown-field.json',
  expect: { ok: false, guard: 'Q03_POLICY' },
});

put('adversarial/malformed-envelope.json', '{ "schema": "quorum/1", this is not JSON\n');
addCase({
  name: 'malformed-envelope-json',
  kind: 'adversarial',
  description: 'The envelope bytes are not JSON.',
  envelope_path: 'adversarial/malformed-envelope.json',
  expect: { ok: false, guard: 'Q01_ENVELOPE_JSON' },
});

// ---------------------------------------------------------------------------------------------

const INDEX = {
  schema: 'quorum-fixtures/1',
  generated_by: 'tools/make-fixtures.mjs',
  note: 'Regenerate with `npm run fixtures`. Keys are derived from the committed phrases in the generator; no private key bytes are stored. Ed25519 is deterministic, so regeneration is byte-identical and test/fixtures.test.mjs fails on hand-edited fixtures.',
  expected: {
    attempt: ATTEMPT,
    commit: COMMIT,
    pr: PR,
    artifact_digest: ARTIFACT_DIGEST,
    evidence_digest: EVIDENCE_DIGEST,
    policy_version: VERSION.declared,
  },
  cases,
};

export function writeFixtures(target = FIXTURES) {
  rmSync(join(target, 'positive'), { recursive: true, force: true });
  rmSync(join(target, 'adversarial'), { recursive: true, force: true });
  rmSync(join(target, 'shared'), { recursive: true, force: true });
  for (const [path, content] of files) {
    const full = join(target, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content, 'utf8');
  }
  writeFileSync(join(target, 'index.json'), `${JSON.stringify(INDEX, null, 2)}\n`, 'utf8');
  return { files: [...files.keys()], cases: cases.length };
}

if (process.argv[1] !== undefined && process.argv[1].endsWith('make-fixtures.mjs')) {
  const result = writeFixtures(process.argv[2] ? join(process.cwd(), process.argv[2]) : FIXTURES);
  process.stdout.write(`wrote ${result.files.length} fixture files, ${result.cases} cases\n`);
}

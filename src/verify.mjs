// `quorum verify` — the fail-closed gate.
//
// WHY THIS EXISTS: a verifier that authenticates only the PRODUCER treats the review trailer as
// unsigned, shape-checked metadata, so a valid producer attestation carries
// `APPROVE | reviewer-b (codex) | 42`, `SELF APPROVED | same-family producer | not-a-pr` and
// `CHANGES | untrusted-free-text | 999999` to PASS. Those three trailers are committed adversarial
// fixtures under fixtures/adversarial/ and every one of them must be refused here.
//
// THE RULES THIS FILE OBEYS, because each is a way a gate has already failed open somewhere:
//
//   1. NOTHING IS READ FROM THE RECORD TO CHECK THE RECORD. attempt, commit, artifact digest and pr
//      come from the caller that commissioned the run. Principal, family, role and the trust ceiling
//      come from the enrolment, never from the envelope's own claims about itself.
//   2. "COULD NOT CHECK" IS NOT "CHECKED". An absent file, an unsupplied artifact and an unsupplied
//      evidence document are refusals, not skips.
//   3. EVERY REFUSAL NAMES A GUARD. The guard id appears in the failure message, in the delete-test
//      matrix, and as a `/* GUARD:... */` marker on exactly one expression, so neutering a guard
//      reddens a named behavioural test rather than a count.
//   4. UNKNOWN IS DISTINCT FROM INVALID. `UNKNOWN` means nothing was compared (missing or malformed
//      input); `INVALID` means evidence was compared and rejected. Both exit non-zero; conflating
//      them is how "the review never ran" comes to look like "the review passed".

import { createHash, createPublicKey, verify as verifyBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from './canonical.mjs';
import {
  ENVELOPE_SCHEMA, POLICY_SCHEMA, TRUST_SCHEMA,
  declaredPolicyIdentity, policyIdentity,
  producerPayload, reviewerPayload, sha256Ref, trustRank,
} from './envelope.mjs';
import { compileSchema, validate } from './schema.mjs';

const schemaDir = fileURLToPath(new URL('../schema/', import.meta.url));
const loadSchema = (name) => compileSchema(JSON.parse(readFileSync(`${schemaDir}${name}`, 'utf8')), `#${name}`);

// Compiled at import: an unimplemented keyword in a shipped schema is a startup failure, never a
// constraint that quietly evaluates to true at verification time.
export const ENVELOPE_JSON_SCHEMA = loadSchema('quorum-envelope-1.schema.json');
export const POLICY_JSON_SCHEMA = loadSchema('quorum-policy-1.schema.json');
export const TRUST_JSON_SCHEMA = loadSchema('quorum-trust-1.schema.json');

// Keep this list literal and ordered as the checks run. The test suite carries an independent copy
// and fails if either side changes alone, and `guards.test.mjs` now also asserts this order against
// the order the `/* GUARD:... */` markers appear in THIS FILE — previously nothing did, so the
// comment above was an instruction with no enforcement behind it.
//
// THE NUMBERS ARE LABELS, NOT POSITIONS. `Q20_POLICY_IDENTITY` runs sixth, immediately before the
// Q05 comparison whose string it makes trustworthy. It is not renumbered to `Q05` (and the rest
// shifted) because a guard id is cited by name in four earlier review records,
// in every committed fixture's `expect.guard`, and in the failure text of gates already run:
// renumbering would silently re-point every one of those citations at a different check. So the
// list order tracks EXECUTION and the number records when the guard was introduced.
export const GUARD_IDS = Object.freeze([
  'Q00_INPUT_PRESENT',
  'Q01_ENVELOPE_JSON',
  'Q02_ENVELOPE_SCHEMA',
  'Q03_POLICY',
  'Q04_TRUST_STORE',
  'Q20_POLICY_IDENTITY',
  'Q05_POLICY_VERSION',
  'Q06_ATTEMPT_BINDING',
  'Q07_ARTIFACT_BINDING',
  'Q08_ARTIFACT_DIGEST',
  'Q09_PRODUCER_ENROLMENT',
  'Q10_PRODUCER_SIGNATURE',
  'Q11_REVIEWER_ENROLMENT',
  'Q12_REVIEWER_SIGNATURE',
  'Q13_VERDICT',
  'Q14_TRUST_ENROLMENT',
  'Q15_TRUST_POLICY',
  'Q16_FAMILY_INEQUALITY',
  'Q17_PR_BINDING',
  'Q18_EVIDENCE_BINDING',
  'Q19_RESIDUE_DECLARATION',
  // Q20_POLICY_IDENTITY is listed above, at the position where it runs.
]);

const INVALID_JSON = Symbol('invalid-json');
const ATTEMPT = /^attempt:[a-f0-9]{32}$/;
const COMMIT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

function safeJson(text) {
  try { return JSON.parse(text); } catch { return INVALID_JSON; }
}

function fail(guard, why, compared = false) {
  return {
    ok: false,
    verdict: compared ? 'INVALID' : 'UNKNOWN',
    evidence: compared ? 'compared_rejected' : 'not_compared',
    guard,
    why,
  };
}

/**
 * Parse and integrity-check the whole trust store. A store that does not parse — a duplicate key id,
 * a PEM that is not an Ed25519 public key — is refused as a store, not per-lookup: a verifier that
 * shrugs at a broken enrolment beside the one it needs is trusting a document it cannot read.
 */
function loadTrustStore(trust) {
  const byId = new Map();
  const byFingerprint = new Map();
  for (const key of trust.keys) {
    if (byId.has(key.key_id)) return { error: `duplicate key_id ${key.key_id}` };
    let publicKey;
    try {
      publicKey = createPublicKey(key.public_key_pem);
    } catch (error) {
      return { error: `key ${key.key_id} has an unreadable public key: ${error.message}` };
    }
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      return { error: `key ${key.key_id} is ${publicKey.asymmetricKeyType}, not ed25519` };
    }
    // Reject reuse of the same key MATERIAL across enrolled identities, even
    // under different key_id/principal/family/role. Compared on the re-exported SPKI DER bytes, never
    // the PEM string — the same key can be re-wrapped with different line breaks or whitespace and
    // still be the identical key, so a PEM-string comparison is exactly the check an attacker would
    // route around. Without this, one private key enrolled as producer under one identity and as
    // reviewer under another can sign both halves of a review and self-approve while every other
    // check, including Q16's family-string inequality, genuinely passes.
    const fingerprint = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    const collidesWith = byFingerprint.get(fingerprint);
    if (collidesWith !== undefined) {
      return { error: `key ${key.key_id} enrols the same public key material as ${collidesWith}; one private key must not occupy two enrolled identities` };
    }
    byFingerprint.set(fingerprint, key.key_id);
    byId.set(key.key_id, { ...key, publicKey });
  }
  return { byId };
}

/** Enrolment lookup for one party. Returns a reason string on refusal, never a partial match. */
function enrolmentFor(byId, party, role) {
  const key = byId.get(party.key_id);
  if (key === undefined) return { error: `no enrolled key ${JSON.stringify(party.key_id)}` };
  if (!key.roles.includes(role)) return { error: `key ${key.key_id} is enrolled for ${key.roles.join(',')}, not ${role}` };
  if (key.principal !== party.principal) {
    return { error: `key ${key.key_id} is enrolled to principal ${JSON.stringify(key.principal)}, not ${JSON.stringify(party.principal)}` };
  }
  if (key.family !== party.family) {
    return { error: `key ${key.key_id} is enrolled for family ${JSON.stringify(key.family)}, not ${JSON.stringify(party.family)}` };
  }
  return { key };
}

function signatureValid(payload, signature, publicKey) {
  const bytes = Buffer.from(signature.value, 'base64');
  // Reject base64 that decodes but does not re-encode identically: otherwise a mutated signature
  // string with equivalent padding verifies, and the record has two valid byte sequences.
  if (bytes.toString('base64') !== signature.value) return false;
  return verifyBytes(null, canonicalBytes(payload), publicKey, bytes);
}

/**
 * @param {object} input
 * @param {string|null|undefined} input.envelopeText  raw envelope bytes, or null when absent
 * @param {string|null|undefined} input.policyText
 * @param {string|null|undefined} input.trustText
 * @param {{attemptId?: string, commit?: string, pr?: number|null, artifactDigest?: string}} input.expected
 *   supplied by the caller that commissioned the review, never by the reviewer
 * @param {Buffer|null} [input.artifactBytes]  when present the artifact digest is RECOMPUTED
 * @param {Buffer|null} [input.evidenceBytes]  the review evidence document
 */
export function verifyEnvelope({
  envelopeText,
  policyText,
  trustText,
  expected = {},
  artifactBytes = null,
  evidenceBytes = null,
}) {
  const absent = [
    ['envelope', envelopeText],
    ['policy', policyText],
    ['trust store', trustText],
  ].filter(([, text]) => typeof text !== 'string' || text.length === 0).map(([name]) => name);
  const expectedMissing = [
    ['attempt', typeof expected.attemptId === 'string' && ATTEMPT.test(expected.attemptId)],
    ['commit', typeof expected.commit === 'string' && COMMIT.test(expected.commit)],
  ].filter(([, ok]) => !ok).map(([name]) => name);
  if (/* GUARD:Q00_INPUT_PRESENT */ absent.length > 0 || expectedMissing.length > 0) {
    const missing = [...absent, ...expectedMissing.map((name) => `expected ${name}`)];
    return fail('Q00_INPUT_PRESENT', `cannot verify: ${missing.join(', ')} absent or unusable — an absent review is a refusal, not a pass`);
  }

  const envelope = safeJson(envelopeText);
  if (/* GUARD:Q01_ENVELOPE_JSON */ envelope === INVALID_JSON) {
    return fail('Q01_ENVELOPE_JSON', 'envelope is not JSON');
  }
  const envelopeShape = validate(ENVELOPE_JSON_SCHEMA, envelope);
  if (/* GUARD:Q02_ENVELOPE_SCHEMA */ !envelopeShape.ok || envelope.schema !== ENVELOPE_SCHEMA) {
    return fail('Q02_ENVELOPE_SCHEMA', `envelope does not satisfy ${ENVELOPE_SCHEMA}: ${envelopeShape.errors.join('; ') || 'wrong schema token'}`);
  }

  const policy = safeJson(policyText);
  const policyShape = policy === INVALID_JSON ? { ok: false, errors: ['policy is not JSON'] } : validate(POLICY_JSON_SCHEMA, policy);
  if (/* GUARD:Q03_POLICY */ !policyShape.ok || policy.schema !== POLICY_SCHEMA) {
    return fail('Q03_POLICY', `policy does not satisfy ${POLICY_SCHEMA}: ${policyShape.errors.join('; ') || 'wrong schema token'}`);
  }

  const trust = safeJson(trustText);
  const trustShape = trust === INVALID_JSON ? { ok: false, errors: ['trust store is not JSON'] } : validate(TRUST_JSON_SCHEMA, trust);
  const store = trustShape.ok && trust.schema === TRUST_SCHEMA ? loadTrustStore(trust) : { error: trustShape.errors.join('; ') || 'wrong schema token' };
  if (/* GUARD:Q04_TRUST_STORE */ store.error !== undefined) {
    return fail('Q04_TRUST_STORE', `trust store does not satisfy ${TRUST_SCHEMA}: ${store.error}`);
  }

  // F1. Establish that the policy IS what it says it is, BEFORE comparing the envelope's
  // claim to it. Without this the Q05 comparison below is a string match between two strings that
  // nobody has bound to any content, and two different policies sharing one version both satisfy
  // it. The identity is recomputed from the document in hand, so a same-version collision is
  // detectable from one half of it — which is the only half a verifier ever holds.
  //
  // `declared === null` is a REFUSAL, not a skip: a policy carrying no identity suffix binds no
  // content, and "could not check" is not "checked" (rule 2 at the top of this file).
  const declaredIdentity = declaredPolicyIdentity(policy.policy_version);
  const computedIdentity = policyIdentity(policy);
  if (/* GUARD:Q20_POLICY_IDENTITY */ declaredIdentity !== computedIdentity) {
    const detail = declaredIdentity === null
      ? `policy_version ${JSON.stringify(policy.policy_version)} carries no content identity, so it names no exact policy`
      : `policy_version declares identity ${declaredIdentity} but this document's content hashes to ${computedIdentity}`;
    return fail('Q20_POLICY_IDENTITY', `policy does not have the identity it declares: ${detail} — a policy_version that does not determine the policy lets two different policies share one name`, true);
  }

  if (/* GUARD:Q05_POLICY_VERSION */ envelope.policy_version !== policy.policy_version) {
    return fail('Q05_POLICY_VERSION', `envelope was produced under policy ${envelope.policy_version}, the verifier was handed ${policy.policy_version}`, true);
  }

  if (/* GUARD:Q06_ATTEMPT_BINDING */ envelope.attempt_id !== expected.attemptId) {
    return fail('Q06_ATTEMPT_BINDING', `envelope attempt ${envelope.attempt_id} is not the commissioned attempt ${expected.attemptId} — a review of an earlier attempt is stale, not valid`, true);
  }

  if (/* GUARD:Q07_ARTIFACT_BINDING */ envelope.artifact.commit !== expected.commit) {
    return fail('Q07_ARTIFACT_BINDING', `envelope reviews commit ${envelope.artifact.commit}, the commissioned artifact is ${expected.commit}`, true);
  }

  // The digest must be established by something other than the envelope: either the artifact bytes
  // themselves, or a digest the caller computed. With neither, nothing was recomputed, so the
  // binding is unproven and this refuses rather than accepting the envelope's own claim.
  const recomputed = artifactBytes === null ? null : sha256Ref(artifactBytes);
  const artifactSources = [recomputed, expected.artifactDigest].filter((value) => typeof value === 'string' && DIGEST.test(value));
  const digestOk = artifactSources.length > 0 && artifactSources.every((value) => value === envelope.artifact.digest);
  if (/* GUARD:Q08_ARTIFACT_DIGEST */ !digestOk) {
    const detail = artifactSources.length === 0
      ? 'no artifact bytes and no caller-supplied digest, so nothing was recomputed'
      : `recomputed ${artifactSources.join(' and ')} against envelope ${envelope.artifact.digest}`;
    return fail('Q08_ARTIFACT_DIGEST', `artifact digest not established: ${detail}`, artifactSources.length > 0);
  }

  const producerKey = enrolmentFor(store.byId, envelope.producer, 'producer');
  if (/* GUARD:Q09_PRODUCER_ENROLMENT */ producerKey.error !== undefined) {
    return fail('Q09_PRODUCER_ENROLMENT', `producer is not an enrolled producing principal: ${producerKey.error}`);
  }

  if (/* GUARD:Q10_PRODUCER_SIGNATURE */ !signatureValid(producerPayload(envelope), envelope.signatures.producer, producerKey.key.publicKey)) {
    return fail('Q10_PRODUCER_SIGNATURE', 'producer signature does not cover this attempt, artifact and producer identity', true);
  }

  const reviewerKey = enrolmentFor(store.byId, envelope.reviewer, 'reviewer');
  if (/* GUARD:Q11_REVIEWER_ENROLMENT */ reviewerKey.error !== undefined) {
    return fail('Q11_REVIEWER_ENROLMENT', `reviewer is not an enrolled reviewing principal: ${reviewerKey.error}`);
  }

  // The countersignature is the whole point: it covers the producer's signature bytes as well as the
  // reviewer identity, verdict, pr and evidence digest. Changing any of them lands here.
  if (/* GUARD:Q12_REVIEWER_SIGNATURE */ !signatureValid(reviewerPayload(envelope), envelope.signatures.reviewer, reviewerKey.key.publicKey)) {
    return fail('Q12_REVIEWER_SIGNATURE', 'reviewer signature does not cover this envelope — reviewer identity, verdict, pr or the producer signature has been altered', true);
  }

  if (/* GUARD:Q13_VERDICT */ !policy.accepted_verdicts.includes(envelope.review.verdict)) {
    return fail('Q13_VERDICT', `verdict ${JSON.stringify(envelope.review.verdict)} is not in this policy's accepted set ${JSON.stringify(policy.accepted_verdicts)}`, true);
  }

  // Trust level, first half: an envelope may not claim more trust than its enrolment carries.
  const overclaimed = [
    ['producer', envelope.producer, producerKey.key],
    ['reviewer', envelope.reviewer, reviewerKey.key],
  ].filter(([, party, key]) => trustRank(party.family_trust) > trustRank(key.family_evidence));
  if (/* GUARD:Q14_TRUST_ENROLMENT */ overclaimed.length > 0) {
    const detail = overclaimed.map(([role, party, key]) => `${role} claims ${party.family_trust} on a key enrolled as ${key.family_evidence}`).join('; ');
    return fail('Q14_TRUST_ENROLMENT', `family trust overclaimed: ${detail}`, true);
  }

  // Second half: a policy demanding observed family fails closed on declared evidence. Our own
  // registry stores model_family as a declared yaml field, so under an observed policy this is the
  // guard that refuses, rather than a verifier that re-transcribes a self-declaration as proof.
  const floor = trustRank(policy.require_family_trust);
  const belowFloor = [
    ['producer', envelope.producer.family_trust],
    ['reviewer', envelope.reviewer.family_trust],
  ].filter(([, level]) => trustRank(level) < floor);
  if (/* GUARD:Q15_TRUST_POLICY */ belowFloor.length > 0) {
    const detail = belowFloor.map(([role, level]) => `${role} family evidence is ${level}`).join('; ');
    return fail('Q15_TRUST_POLICY', `policy requires ${policy.require_family_trust} family evidence: ${detail}`, true);
  }

  if (/* GUARD:Q16_FAMILY_INEQUALITY */ policy.require_family_inequality && envelope.producer.family === envelope.reviewer.family) {
    return fail('Q16_FAMILY_INEQUALITY', `producer and reviewer are both family ${JSON.stringify(envelope.producer.family)}; this policy requires author_family != reviewer_family`, true);
  }

  const prExpected = expected.pr ?? null;
  const prBound = policy.require_pr_binding
    ? envelope.review.pr !== null && envelope.review.pr === prExpected
    : prExpected === null || envelope.review.pr === prExpected;
  if (/* GUARD:Q17_PR_BINDING */ !prBound) {
    return fail('Q17_PR_BINDING', `envelope binds pr ${JSON.stringify(envelope.review.pr)}, the commissioned review is for pr ${JSON.stringify(prExpected)}`, true);
  }

  // Deletion control: with require_evidence the document must be handed in and must hash to the
  // signed digest. Deleting it therefore fails the check; it cannot skip to a pass.
  let evidenceOk = true;
  let evidenceWhy = 'evidence binding not required by this policy';
  if (policy.require_evidence) {
    if (evidenceBytes === null) {
      evidenceOk = false;
      evidenceWhy = 'policy requires the review evidence document and none was supplied — a missing review is a refusal';
    } else {
      const digest = createHash('sha256').update(evidenceBytes).digest('hex');
      evidenceOk = `sha256:${digest}` === envelope.review.evidence_digest;
      evidenceWhy = `supplied evidence hashes to sha256:${digest}, envelope binds ${envelope.review.evidence_digest}`;
    }
  }
  if (/* GUARD:Q18_EVIDENCE_BINDING */ !evidenceOk) {
    return fail('Q18_EVIDENCE_BINDING', evidenceWhy, evidenceBytes !== null);
  }

  // Q19 — THE RESIDUE DECLARATION. Adopted 2026-09-28 from `disensor`, whose sharpest idea is that
  // the artifact a review leaves behind should be what it could NOT settle, not a score. Our
  // envelope recorded a verdict, a PR and an evidence digest — every one of which a green badge
  // also has.
  //
  // WHY EMPTY-BUT-PRESENT IS THE WHOLE POINT, and why this is not ceremony: an ABSENT residue block
  // and one whose arrays are all empty look identical to a scoring reader and are OPPOSITE claims.
  // Absent means the reviewer never addressed it. Empty means the reviewer asserts there was nothing
  // undecided, nothing refuted, nothing execution could not settle and no limits worth declaring —
  // a strong claim, signed, that can be held against them later. The schema therefore requires all
  // four arrays inside the block while permitting each to be empty.
  //
  // Deletion control: with require_residue_declaration set, the block must be present. Deleting this
  // guard makes a policy that demands residue silently accept an envelope without it — which is the
  // regression the named fixture in the test suite pins.
  let residueOk = true;
  let residueWhy = 'residue declaration not required by this policy';
  if (policy.require_residue_declaration) {
    const residue = envelope.review.residue;
    if (residue === undefined || residue === null) {
      residueOk = false;
      residueWhy = 'policy requires a residue declaration and the envelope carries none — an absent '
        + 'residue is not an empty one: it records that the reviewer never addressed what it could not settle';
    } else {
      residueWhy = `residue declared: ${residue.undecided.length} undecided, ${residue.refuted.length} refuted, `
        + `${residue.unsettled_by_execution.length} unsettled by execution, ${residue.reviewer_limits.length} declared limits`;
    }
  }
  if (/* GUARD:Q19_RESIDUE_DECLARATION */ !residueOk) {
    return fail('Q19_RESIDUE_DECLARATION', residueWhy, evidenceBytes !== null);
  }

  return {
    ok: true,
    verdict: 'PASS',
    evidence: 'compared_ok',
    guard: null,
    review_verdict: envelope.review.verdict,
    producer: { principal: envelope.producer.principal, family: envelope.producer.family, family_trust: envelope.producer.family_trust },
    reviewer: { principal: envelope.reviewer.principal, family: envelope.reviewer.family, family_trust: envelope.reviewer.family_trust },
    pr: envelope.review.pr,
    commit: envelope.artifact.commit,
    attempt_id: envelope.attempt_id,
    policy_version: envelope.policy_version,
    why: `ok (compared) — ${envelope.producer.family} produced, ${envelope.reviewer.family} reviewed, both signatures cover this artifact digest, verdict ${envelope.review.verdict} under ${policy.policy_version} at ${policy.require_family_trust} family evidence`,
  };
}

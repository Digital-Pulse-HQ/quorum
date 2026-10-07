// quorum/1 envelope construction — the two halves and what each signature covers.
//
// THE ORDERING IS THE DESIGN. A producer cannot sign a verdict it has not received, so a single
// joint signature is impossible and a producer-only signature is the defect this format closes:
// `reviewer`, `verdict` and `pr` sitting outside every signature, editable without invalidating
// anything. Quorum nests them instead:
//
//   producer signature  covers  schema, policy_version, attempt_id, artifact, producer
//   reviewer signature  covers  ALL of the above INCLUDING the producer's signature bytes,
//                               plus reviewer, review (verdict, pr, evidence digest)
//
// So the reviewer countersigns the producer's claim, and no field in the record can move without
// breaking the reviewer signature. That is the immutable binding a review record needs, and it is why a
// PR comment can only ever render this record (see src/render.mjs) rather than be it.

import { createHash, sign as signBytes } from 'node:crypto';
import { canonicalBytes } from './canonical.mjs';

export const ENVELOPE_SCHEMA = 'quorum/1';
export const POLICY_SCHEMA = 'quorum-policy/1';
export const TRUST_SCHEMA = 'quorum-trust/1';

/** Trust levels, weakest first. An enrolment is a ceiling; a policy is a floor. */
export const TRUST_LEVELS = Object.freeze(['declared', 'observed']);

export function trustRank(level) {
  const index = TRUST_LEVELS.indexOf(level);
  return index === -1 ? -1 : index;
}

export function sha256Ref(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

// ---------------------------------------------------------------------------------------------
// POLICY IDENTITY — F1.
//
// `policy_version` is described by the envelope schema as naming "the exact policy", and Q05 is the
// guard meant to make an upgrade non-silent. Until this change it was an ORDINARY STRING chosen by
// whoever wrote the policy file, and Q05 compared only that string. Two materially different policy
// documents could therefore declare the same version, and the SAME signed envelope returned PASS
// under one and INVALID under the other — measured on this repository's own fixtures, where
// `policy-declared.json` and `policy-residue.json` differed in `require_residue_declaration` and
// both said `quorum-policy/1@2026-09-10`. A name that does not determine the thing it names is not
// an identity, and a signature over that name binds nothing.
//
// The fix makes the identity CONTENT-DERIVED, so the two cannot come apart:
//
//   policy_version := <label>+<identity>      e.g. quorum-policy/1@2026-09-10+<32 hex>
//   identity       := sha256(canonicalBytes(policy WITHOUT policy_version))[0..32)
//
// Properties this buys, none of which the string alone had:
//
//   - Two materially different canonical policy documents CANNOT both be self-consistent under one
//     `policy_version`. At most one matches; the other is refused on sight, from the single document
//     in front of the verifier. That is what makes a same-version collision detectable at all — the
//     verifier is never handed both halves of one.
//   - The producer signature already covers `policy_version`, so it now transitively covers the
//     exact policy CONTENT. No new signed field, and no fixture's signature coverage narrows.
//   - `policy_version` is self-excluded from its own digest for the obvious reason: it contains the
//     digest. The ordinary checksum-field exclusion, stated so nobody re-derives it.
//
// TRUNCATION: 128 bits. The attack this resists is second-preimage — crafting a DIFFERENT policy
// document colliding with a published identity — which is 2^128 work here. 64 bits would be
// prettier and is 2^64, which is not a margin worth having in a governance record.
// ---------------------------------------------------------------------------------------------

/** Hex characters of truncated SHA-256 carried in a `policy_version`. 32 hex = 128 bits. */
export const POLICY_IDENTITY_HEX = 32;

/** `<label>+<identity>`: the label is human-chosen, the identity is not. */
export const POLICY_VERSION_SEPARATOR = '+';

const IDENTITY_PATTERN = new RegExp(`^[0-9a-f]{${POLICY_IDENTITY_HEX}}$`);

/**
 * The content identity of a policy document: every field EXCEPT `policy_version`, canonicalised and
 * hashed. Takes the PARSED policy, never its bytes, so re-indenting or re-ordering a policy file
 * does not change its identity while changing any VALUE does — the same rule the envelope
 * signatures already follow.
 *
 * @param {object} policy a parsed quorum-policy/1 document
 * @returns {string} 32 lowercase hex characters
 */
export function policyIdentity(policy) {
  const { policy_version: _excluded, ...content } = policy;
  return createHash('sha256').update(canonicalBytes(content)).digest('hex').slice(0, POLICY_IDENTITY_HEX);
}

/**
 * The identity a `policy_version` string DECLARES, or null when it declares none. Strict, and
 * returns null rather than guessing: an unsuffixed version string is a pre-identity policy that
 * binds no content, and reading "identity absent" as "therefore fine" is the exact fail-open this
 * closes.
 */
export function declaredPolicyIdentity(policyVersion) {
  if (typeof policyVersion !== 'string') return null;
  const at = policyVersion.lastIndexOf(POLICY_VERSION_SEPARATOR);
  if (at === -1) return null;
  const identity = policyVersion.slice(at + 1);
  return IDENTITY_PATTERN.test(identity) ? identity : null;
}

/**
 * Stamp a policy document with its own content identity. The single supported way to author a
 * `policy_version`: hand-writing one is how the two came apart in the first place.
 *
 * @param {string} label e.g. `quorum-policy/1@2026-09-10`
 * @param {object} content the policy WITHOUT `policy_version`
 */
export function stampPolicyVersion(label, content) {
  const { policy_version: _discarded, ...rest } = content;
  const version = `${label}${POLICY_VERSION_SEPARATOR}${policyIdentity(rest)}`;
  // Authored key order is preserved, and a `policy_version` placeholder is replaced IN PLACE rather
  // than moved to the end. A policy file is read by humans and re-stamping should produce a
  // one-line diff, not a reordering that hides which value actually changed.
  const entries = Object.hasOwn(content, 'policy_version')
    ? Object.keys(content).map((key) => [key, key === 'policy_version' ? version : content[key]])
    : [...Object.entries(rest), ['policy_version', version]];
  return Object.fromEntries(entries);
}

/** The bytes the producer signature covers. */
export function producerPayload(envelope) {
  return {
    schema: envelope.schema,
    policy_version: envelope.policy_version,
    attempt_id: envelope.attempt_id,
    artifact: envelope.artifact,
    producer: envelope.producer,
  };
}

/**
 * The bytes the reviewer signature covers: the whole envelope minus the reviewer signature itself.
 * Built by subtraction from the PARSED envelope rather than by re-listing fields, so a field added
 * to the schema is covered automatically instead of silently escaping the signature.
 */
export function reviewerPayload(envelope) {
  const { signatures, ...rest } = envelope;
  return { ...rest, signatures: { producer: signatures.producer } };
}

/**
 * Producer half: everything knowable at production time, signed by the producing family's key.
 */
export function createProducerHalf({
  policyVersion, attemptId, artifact, producer, privateKey,
}) {
  const half = {
    schema: ENVELOPE_SCHEMA,
    policy_version: policyVersion,
    attempt_id: attemptId,
    artifact: { kind: artifact.kind, commit: artifact.commit, digest: artifact.digest },
    producer: {
      principal: producer.principal,
      family: producer.family,
      family_trust: producer.family_trust,
      key_id: producer.key_id,
    },
  };
  const value = signBytes(null, canonicalBytes(producerPayload(half)), privateKey).toString('base64');
  return { ...half, signature: { algorithm: 'ed25519', value } };
}

/**
 * Reviewer half: countersigns the producer half and adds the three facts only the reviewer holds.
 */
export function createEnvelope({ producerHalf, reviewer, review, privateKey }) {
  const { signature: producerSignature, ...producerFields } = producerHalf;
  const unsigned = {
    ...producerFields,
    reviewer: {
      principal: reviewer.principal,
      family: reviewer.family,
      family_trust: reviewer.family_trust,
      key_id: reviewer.key_id,
    },
    review: {
      verdict: review.verdict,
      pr: review.pr ?? null,
      evidence_digest: review.evidence_digest,
      // The residue declaration (Q19) is included ONLY when supplied, and it sits INSIDE the signed
      // review block deliberately: residue a third party could append after signing would be
      // worthless, because the whole value of "what I could not settle" is that the reviewer
      // committed to it. Omitting the key when absent keeps every pre-existing envelope's canonical
      // bytes byte-identical, so this addition cannot invalidate an existing signature.
      ...(review.residue === undefined ? {} : { residue: review.residue }),
    },
    signatures: { producer: producerSignature },
  };
  // Sign through `reviewerPayload`, not through this literal: signing and verifying must be the same
  // function of the envelope. Two independent field lists would let a field be signed and not
  // checked — or checked and not signed — and both directions look fine until an attacker picks one.
  const value = signBytes(null, canonicalBytes(reviewerPayload(unsigned)), privateKey).toString('base64');
  return {
    ...unsigned,
    signatures: { producer: producerSignature, reviewer: { algorithm: 'ed25519', value } },
  };
}

/** Stable serialisation for writing an envelope to disk or a git object. */
export function serializeEnvelope(envelope) {
  return `${JSON.stringify(envelope, null, 2)}\n`;
}

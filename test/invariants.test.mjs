// The invariants that no guard names, and that the delete tests therefore cannot reach.
//
// The delete tests answer "is each refusal load-bearing?". They cannot answer "is the machinery
// UNDER the refusals load-bearing?" — canonicalisation, signature-string uniqueness, what the
// countersignature covers, and whether the schema evaluator enforces what the schema documents.
// Every test here exists because a mutation of that machinery survived the guard delete tests, which
// is exactly the class of hole a single mutation instinct leaves behind.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { canonicalize, NotCanonicalisable } from '../src/canonical.mjs';
import { compileSchema, validate, SchemaError } from '../src/schema.mjs';
import {
  createEnvelope, createProducerHalf, producerPayload, reviewerPayload, sha256Ref,
} from '../src/envelope.mjs';
import { ENVELOPE_JSON_SCHEMA, verifyEnvelope } from '../src/verify.mjs';
import { NON_AUTHORITATIVE_BANNER, envelopeDigest, renderComment } from '../src/render.mjs';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));
const INDEX = JSON.parse(readFileSync(join(FIXTURES, 'index.json'), 'utf8'));
const POSITIVE = INDEX.cases.find((entry) => entry.name === 'valid-cross-family-approve');
const read = (rel, encoding) => readFileSync(join(FIXTURES, rel), encoding);

const verifyText = (envelopeText) => verifyEnvelope({
  envelopeText,
  policyText: read(POSITIVE.policy, 'utf8'),
  trustText: read(POSITIVE.trust, 'utf8'),
  expected: { attemptId: POSITIVE.attempt, commit: POSITIVE.commit, pr: POSITIVE.pr },
  artifactBytes: read(POSITIVE.artifact),
  evidenceBytes: read(POSITIVE.evidence),
});

/** Deep-rebuild an object with every key order reversed at every level. */
function reverseKeys(value) {
  if (Array.isArray(value)) return value.map(reverseKeys);
  if (value === null || typeof value !== 'object') return value;
  const out = {};
  for (const key of Object.keys(value).reverse()) out[key] = reverseKeys(value[key]);
  return out;
}

test('canonical form is independent of key insertion order', () => {
  assert.equal(canonicalize({ a: 1, b: 2 }), canonicalize({ b: 2, a: 1 }));
  assert.equal(canonicalize({ b: { d: 1, c: 2 }, a: 3 }), '{"a":3,"b":{"c":2,"d":1}}');
});

test('a re-serialised envelope with different key order still verifies', () => {
  // A transport that parses and re-emits JSON — a ledger, a database, a PR bot — reorders keys.
  // Canonicalisation is the only thing that stops that from invalidating a valid review.
  const reordered = JSON.stringify(reverseKeys(JSON.parse(read(POSITIVE.envelope, 'utf8'))), null, 4);
  const result = verifyText(reordered);
  assert.equal(result.ok, true, `a re-serialised envelope was refused by ${result.guard}: ${result.why}`);
});

test('canonicalisation refuses every value with more than one defensible encoding', () => {
  assert.throws(() => canonicalize(1.5), NotCanonicalisable);
  assert.throws(() => canonicalize(Number.NaN), NotCanonicalisable);
  assert.throws(() => canonicalize({ a: undefined }), NotCanonicalisable);
  assert.throws(() => canonicalize('\uD800'), NotCanonicalisable);
  assert.equal(canonicalize(-0), '0');
});

test('UNSAFE-INTEGER: canonicalisation refuses unsafe integers, not merely non-integers', () => {
  assert.equal(canonicalize(Number.MAX_SAFE_INTEGER), String(Number.MAX_SAFE_INTEGER));
  assert.throws(() => canonicalize(Number.MAX_SAFE_INTEGER + 1), NotCanonicalisable);
  assert.throws(() => canonicalize(-(Number.MAX_SAFE_INTEGER + 1)), NotCanonicalisable);
});

test('UNSAFE-INTEGER: two different wire tokens for review.pr that collide on the same double are both refused', () => {
  // 9007199254740992 (2^53) and 9007199254740993 are two DIFFERENT decimal integers. Above 2^53,
  // IEEE-754 doubles only represent even integers, so both round-trip through JSON.parse to the
  // SAME number. Before this fix `review.pr` had no schema maximum, so a validly signed envelope's
  // wire text could move between these two tokens, with no resigning, and still verify — a second
  // valid wire representation of one signature. The fix refuses every review.pr above
  // Number.MAX_SAFE_INTEGER, so neither token is ever valid.
  assert.equal(
    JSON.parse('9007199254740992'),
    JSON.parse('9007199254740993'),
    'the two tokens must collide on parse or this test proves nothing about the ambiguity',
  );

  const producer = generateKeyPairSync('ed25519');
  const reviewer = generateKeyPairSync('ed25519');
  const artifact = Buffer.from('unsafe-integer boundary artifact bytes\n', 'utf8');
  const evidence = Buffer.from('unsafe-integer boundary findings\n', 'utf8');
  const attempt = `attempt:${'b3'.repeat(16)}`;
  const commit = 'e'.repeat(40);
  const half = createProducerHalf({
    policyVersion: INDEX.expected.policy_version,
    attemptId: attempt,
    artifact: { kind: 'git_commit', commit, digest: sha256Ref(artifact) },
    producer: {
      principal: 'example:wire-producer@example.test', family: 'claude', family_trust: 'declared', key_id: 'wire-producer',
    },
    privateKey: producer.privateKey,
  });
  const envelope = createEnvelope({
    producerHalf: half,
    reviewer: {
      principal: 'example:wire-reviewer@example.test', family: 'codex', family_trust: 'declared', key_id: 'wire-reviewer',
    },
    review: { verdict: 'APPROVE', pr: Number.MAX_SAFE_INTEGER, evidence_digest: sha256Ref(evidence) },
    privateKey: reviewer.privateKey,
  });
  const pem = (key) => key.export({ type: 'spki', format: 'pem' });
  const trust = {
    schema: 'quorum-trust/1',
    keys: [
      {
        key_id: 'wire-producer', principal: 'example:wire-producer@example.test', family: 'claude', family_evidence: 'declared', roles: ['producer'], public_key_pem: pem(producer.publicKey),
      },
      {
        key_id: 'wire-reviewer', principal: 'example:wire-reviewer@example.test', family: 'codex', family_evidence: 'declared', roles: ['reviewer'], public_key_pem: pem(reviewer.publicKey),
      },
    ],
  };

  const boundaryText = JSON.stringify(envelope);
  const verify = (text) => verifyEnvelope({
    envelopeText: text,
    policyText: read(POSITIVE.policy, 'utf8'),
    trustText: JSON.stringify(trust),
    expected: { attemptId: attempt, commit, pr: Number.MAX_SAFE_INTEGER },
    artifactBytes: artifact,
    evidenceBytes: evidence,
  });

  const boundary = verify(boundaryText);
  assert.equal(boundary.ok, true, `the MAX_SAFE_INTEGER boundary itself must still verify: ${boundary.guard} — ${boundary.why}`);

  const shiftedToEven = boundaryText.replaceAll(String(Number.MAX_SAFE_INTEGER), '9007199254740992');
  assert.notEqual(shiftedToEven, boundaryText, 'the substitution to 2^53 did not land');
  const even = verify(shiftedToEven);
  assert.equal(even.ok, false, 'review.pr of 9007199254740992 (2^53) was accepted');
  assert.equal(even.guard, 'Q02_ENVELOPE_SCHEMA');

  const shiftedToOdd = boundaryText.replaceAll(String(Number.MAX_SAFE_INTEGER), '9007199254740993');
  assert.notEqual(shiftedToOdd, boundaryText, 'the substitution to 2^53+1 did not land');
  assert.notEqual(shiftedToOdd, shiftedToEven, 'the two wire texts must differ or this test proves nothing');
  const odd = verify(shiftedToOdd);
  assert.equal(odd.ok, false, 'review.pr of 9007199254740993, which parses identically to 9007199254740992, was accepted');
  assert.equal(odd.guard, 'Q02_ENVELOPE_SCHEMA');
});

test('a re-encoded signature string is not a second valid form of the same envelope', () => {
  // Ed25519 signatures are 64 bytes; base64 leaves the low 2 bits of the 86th character unused, so
  // four distinct strings decode to identical bytes. Accepting all four would give one envelope four
  // digests that all verify, and the PR-comment binding in render.mjs is a digest.
  const envelope = JSON.parse(read(POSITIVE.envelope, 'utf8'));
  const value = envelope.signatures.reviewer.value;
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const index = ALPHABET.indexOf(value[85]);
  const twin = `${value.slice(0, 85)}${ALPHABET[index ^ 1]}${value.slice(86)}`;
  assert.notEqual(twin, value, 'failed to construct a re-encoded twin');
  assert.deepEqual(Buffer.from(twin, 'base64'), Buffer.from(value, 'base64'), 'the twin must decode identically or this test proves nothing');

  envelope.signatures.reviewer.value = twin;
  const result = verifyText(JSON.stringify(envelope, null, 2));
  assert.equal(result.ok, false, 'a re-encoded signature string was accepted as a second valid form');
  assert.equal(result.guard, 'Q12_REVIEWER_SIGNATURE');
});

test('the reviewer payload is the whole envelope minus its own signature', () => {
  const envelope = JSON.parse(read(POSITIVE.envelope, 'utf8'));
  const covered = reviewerPayload(envelope);
  for (const key of Object.keys(envelope)) {
    assert.ok(Object.hasOwn(covered, key), `top-level field ${key} escapes the reviewer signature`);
  }
  assert.deepEqual(Object.keys(covered.signatures), ['producer'], 'the reviewer signature must not cover itself');
  assert.deepEqual(covered.review, envelope.review);
  assert.deepEqual(covered.reviewer, envelope.reviewer);
  // The producer half is a strict subset: everything it covers, the reviewer countersigns too.
  for (const key of Object.keys(producerPayload(envelope))) {
    assert.ok(Object.hasOwn(covered, key), `producer-covered field ${key} is not countersigned`);
  }
});

// A ROUND TRIP THIS BUILD SIGNS AND THIS BUILD VERIFIES.
//
// The committed fixtures cannot test what the countersignature COVERS. They were signed once, so any
// change to the signed field set breaks them wholesale — every case fails, including the controls,
// and "everything went red" cannot distinguish "the verdict left the payload" from "the payload
// moved". Signing in-process makes a SYMMETRIC change survivable, which is precisely the dangerous
// one: sign and verify agree with each other while the record silently stops covering a field.
function roundTrip({ tamperEnvelope = null } = {}) {
  const producer = generateKeyPairSync('ed25519');
  const reviewer = generateKeyPairSync('ed25519');
  const artifact = Buffer.from('round-trip artifact bytes\n', 'utf8');
  const evidence = Buffer.from('round-trip findings\n', 'utf8');
  const attempt = `attempt:${'ab'.repeat(16)}`;
  const commit = 'c'.repeat(40);

  const half = createProducerHalf({
    policyVersion: INDEX.expected.policy_version,
    attemptId: attempt,
    artifact: { kind: 'git_commit', commit, digest: sha256Ref(artifact) },
    producer: {
      principal: 'example:roundtrip-producer@example.test', family: 'claude', family_trust: 'declared', key_id: 'rt-producer',
    },
    privateKey: producer.privateKey,
  });
  let envelope = createEnvelope({
    producerHalf: half,
    reviewer: {
      principal: 'example:roundtrip-reviewer@example.test', family: 'codex', family_trust: 'declared', key_id: 'rt-reviewer',
    },
    review: { verdict: 'CHANGES_REQUIRED', pr: 7, evidence_digest: sha256Ref(evidence) },
    privateKey: reviewer.privateKey,
  });
  if (tamperEnvelope) {
    envelope = JSON.parse(JSON.stringify(envelope));
    tamperEnvelope(envelope);
  }

  const pem = (key) => key.export({ type: 'spki', format: 'pem' });
  const trust = {
    schema: 'quorum-trust/1',
    keys: [
      {
        key_id: 'rt-producer', principal: 'example:roundtrip-producer@example.test', family: 'claude', family_evidence: 'declared', roles: ['producer'], public_key_pem: pem(producer.publicKey),
      },
      {
        key_id: 'rt-reviewer', principal: 'example:roundtrip-reviewer@example.test', family: 'codex', family_evidence: 'declared', roles: ['reviewer'], public_key_pem: pem(reviewer.publicKey),
      },
    ],
  };
  return verifyEnvelope({
    envelopeText: JSON.stringify(envelope, null, 2),
    policyText: read(POSITIVE.policy, 'utf8'),
    trustText: JSON.stringify(trust),
    expected: { attemptId: attempt, commit, pr: 7 },
    artifactBytes: artifact,
    evidenceBytes: evidence,
  });
}

test('an envelope this build signs, this build verifies', () => {
  const result = roundTrip();
  assert.equal(result.ok, true, `round trip refused by ${result.guard}: ${result.why}`);
  assert.equal(result.review_verdict, 'CHANGES_REQUIRED');
});

test('the countersignature covers the verdict in an envelope this build signed', () => {
  const result = roundTrip({ tamperEnvelope: (e) => { e.review.verdict = 'APPROVE'; } });
  assert.equal(result.ok, false, 'the verdict was changed and the countersignature did not notice');
  assert.equal(result.guard, 'Q12_REVIEWER_SIGNATURE');
});

test('the countersignature covers the reviewer identity in an envelope this build signed', () => {
  const result = roundTrip({ tamperEnvelope: (e) => { e.reviewer.family = 'gemini'; } });
  assert.equal(result.ok, false, 'the reviewer family was changed and the countersignature did not notice');
});

test('a verification with nothing to recompute the artifact digest against is refused', () => {
  const result = verifyEnvelope({
    envelopeText: read(POSITIVE.envelope, 'utf8'),
    policyText: read(POSITIVE.policy, 'utf8'),
    trustText: read(POSITIVE.trust, 'utf8'),
    expected: { attemptId: POSITIVE.attempt, commit: POSITIVE.commit, pr: POSITIVE.pr },
    artifactBytes: null,
    evidenceBytes: read(POSITIVE.evidence),
  });
  assert.equal(result.ok, false, 'the envelope\'s own claim about the artifact was accepted as the artifact digest');
  assert.equal(result.guard, 'Q08_ARTIFACT_DIGEST');
  assert.equal(result.evidence, 'not_compared', 'nothing was recomputed, so this is UNKNOWN and not INVALID');
});

test('identity comes from the enrolment, never from the envelope\'s claim about itself', () => {
  // The envelope names a principal AND a key id. If the verifier trusted the envelope's pairing of
  // them, any enrolled key could sign for any principal, and `author_family != reviewer_family` would
  // be evaluated on two strings the signer chose.
  const swapped = INDEX.cases.find((entry) => entry.name === 'mutated-reviewer-principal');
  const result = verifyEnvelope({
    envelopeText: read(swapped.envelope, 'utf8'),
    policyText: read(swapped.policy, 'utf8'),
    trustText: read(swapped.trust, 'utf8'),
    expected: { attemptId: swapped.attempt, commit: swapped.commit, pr: swapped.pr },
    artifactBytes: read(swapped.artifact),
    evidenceBytes: read(swapped.evidence),
  });
  assert.equal(result.ok, false, 'a key signed for a principal it is not enrolled to');
  assert.equal(result.guard, 'Q11_REVIEWER_ENROLMENT');
});

test('an unimplemented schema keyword is a startup failure, not a silent non-constraint', () => {
  assert.throws(() => compileSchema({ type: 'string', minLength: 1 }), SchemaError);
  assert.throws(() => compileSchema({ type: 'string', format: 'email' }), SchemaError);
  assert.throws(() => compileSchema({ type: 'object', additionalProperties: true }), SchemaError);
  assert.throws(() => compileSchema({ type: 'number' }), SchemaError);
});

test('unknown properties in a signed payload are rejected by the schema evaluator', () => {
  const schema = compileSchema({
    type: 'object', additionalProperties: false, required: ['a'], properties: { a: { type: 'string' } },
  });
  assert.equal(validate(schema, { a: 'x' }).ok, true);
  const extra = validate(schema, { a: 'x', b: 'smuggled' });
  assert.equal(extra.ok, false);
  assert.ok(extra.errors.some((e) => e.includes('"b"')), extra.errors.join('; '));
});

test('an envelope carrying an extra top-level field is refused', () => {
  const envelope = JSON.parse(read(POSITIVE.envelope, 'utf8'));
  envelope.notes = 'an unsigned field a transport added';
  const result = verifyText(JSON.stringify(envelope, null, 2));
  assert.equal(result.ok, false);
  assert.equal(result.guard, 'Q02_ENVELOPE_SCHEMA');
  assert.equal(validate(ENVELOPE_JSON_SCHEMA, envelope).ok, false);
});

test('a rendered PR comment says it is not the record, and cites the record it renders', () => {
  const envelope = JSON.parse(read(POSITIVE.envelope, 'utf8'));
  const comment = renderComment(envelope, { envelopePath: 'quorum/evidence/pr-42.json' });
  assert.ok(comment.includes(NON_AUTHORITATIVE_BANNER), 'the banner is missing');
  assert.ok(comment.includes(envelopeDigest(envelope)), 'the comment does not cite the envelope digest');
  assert.ok(comment.includes('quorum/evidence/pr-42.json'));
  assert.ok(comment.includes(envelope.review.verdict));
});

test('a rendered PR comment is not accepted as verification input', () => {
  // A comment may render the record and must never be the record. The strong form of that
  // is that the rendered artefact cannot be fed back in as an envelope.
  const envelope = JSON.parse(read(POSITIVE.envelope, 'utf8'));
  const result = verifyText(renderComment(envelope));
  assert.equal(result.ok, false);
  assert.equal(result.guard, 'Q01_ENVELOPE_JSON');
});

test('editing a rendered comment does not change the record it cites', () => {
  const envelope = JSON.parse(read(POSITIVE.envelope, 'utf8'));
  const digest = envelopeDigest(envelope);
  const edited = renderComment(envelope).replace('APPROVE', 'REJECTED BY NOBODY');
  assert.ok(edited.includes(digest), 'the digest still names the untouched envelope');
  assert.equal(verifyText(read(POSITIVE.envelope, 'utf8')).ok, true, 'the committed envelope is unaffected by the edit');
});

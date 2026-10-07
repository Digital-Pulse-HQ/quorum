// R2 (MEDIUM): the envelope locator's byte contract, tested against independent bytes.
//
// TWO DEFECTS. First, `envelopeDigest()` hashed `serializeEnvelope()` -- `JSON.stringify(_, null, 2)`
// -- which preserves key INSERTION ORDER. The verifier accepts a re-serialised envelope by design
// (see "a re-serialised envelope with different key order still verifies"), so one signed record
// had two different "canonical" locators depending on who last re-emitted the JSON:
//
//   sha256:22304f48ec1bc996c256d855dbdd3c3590c5f8343366d80194c75c63abf95678
//   sha256:08a6ad33e768dd3955fd5cb0c72b9a9cf747a389518d3e8dd56f8d893418df57
//
// Second, its tests compared the renderer against `envelopeDigest()` ITSELF -- the self-comparison
// shape. Replacing the whole function with a constant `sha256:` + 64 zeroes left the complete
// suite 129/129 green, with no failing test name. Both sides moved together.
//
// SO THESE TESTS ESTABLISH THE EXPECTED BYTES INDEPENDENTLY: sha256 over a canonical serialisation
// built here, by a local reimplementation that does not call the module under test. A constant,
// an order-dependent hash, or a switch to a different input all redden by name.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { envelopeDigest, renderComment } from '../src/render.mjs';
import { verifyEnvelope } from '../src/verify.mjs';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));
const INDEX = JSON.parse(readFileSync(join(FIXTURES, 'index.json'), 'utf8'));
const POSITIVE = INDEX.cases.find((entry) => entry.name === 'valid-cross-family-approve');
const read = (rel, encoding) => readFileSync(join(FIXTURES, rel), encoding);
const ENVELOPE = JSON.parse(read(POSITIVE.envelope, 'utf8'));

/**
 * An INDEPENDENT canonical JSON serialiser. Deliberately not imported from src/canonical.mjs:
 * if the oracle were the implementation, this file would reproduce the self-comparison it exists
 * to kill. Scope is only what a quorum/1 envelope contains -- objects, arrays, strings, safe
 * integers, booleans and null.
 */
function independentCanonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    assert.ok(Number.isSafeInteger(value), `envelope carried a non-integer number: ${value}`);
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(independentCanonical).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${independentCanonical(value[k])}`).join(',')}}`;
}

const independentDigest = (envelope) =>
  `sha256:${createHash('sha256').update(independentCanonical(envelope), 'utf8').digest('hex')}`;

/** Deep-rebuild with every key order reversed at every level. */
function reverseKeys(value) {
  if (Array.isArray(value)) return value.map(reverseKeys);
  if (value === null || typeof value !== 'object') return value;
  const out = {};
  for (const key of Object.keys(value).reverse()) out[key] = reverseKeys(value[key]);
  return out;
}

test('R2: the locator matches a digest computed independently of the implementation', () => {
  // Kills a constant implementation, and any change of hashed input, by name.
  assert.equal(envelopeDigest(ENVELOPE), independentDigest(ENVELOPE));
});

test('R2: reordering keys does not change the record identity', () => {
  const reordered = reverseKeys(ENVELOPE);
  assert.notEqual(
    JSON.stringify(reordered), JSON.stringify(ENVELOPE),
    'this fixture must actually be reordered for the test to mean anything',
  );
  assert.equal(
    envelopeDigest(reordered), envelopeDigest(ENVELOPE),
    'the same signed record produced two different locators depending on key order',
  );
});

test('R2: a reordered envelope both verifies AND keeps its locator', () => {
  // The two halves of the contract have to hold together: it is the verifier ACCEPTING reordered
  // JSON that made an order-dependent locator a defect rather than a curiosity.
  const reordered = reverseKeys(ENVELOPE);
  const result = verifyEnvelope({
    envelopeText: JSON.stringify(reordered, null, 4),
    policyText: read(POSITIVE.policy, 'utf8'),
    trustText: read(POSITIVE.trust, 'utf8'),
    expected: { attemptId: POSITIVE.attempt, commit: POSITIVE.commit, pr: POSITIVE.pr },
    artifactBytes: read(POSITIVE.artifact),
    evidenceBytes: read(POSITIVE.evidence),
  });
  assert.equal(result.ok, true, `a re-serialised envelope was refused by ${result.guard}: ${result.why}`);
  assert.equal(envelopeDigest(reordered), envelopeDigest(ENVELOPE));
});

test('R2: whitespace and indentation cannot change the locator', () => {
  for (const indent of [0, 2, 4, '\t']) {
    const roundTripped = JSON.parse(JSON.stringify(ENVELOPE, null, indent));
    assert.equal(envelopeDigest(roundTripped), envelopeDigest(ENVELOPE), `indent ${JSON.stringify(indent)} changed the locator`);
  }
});

test('R2: changing any signed value DOES change the locator', () => {
  // The locator must still be a locator: invariance to reserialisation is not invariance to content.
  for (const mutate of [
    (e) => { e.review.verdict = 'REJECT'; },
    (e) => { e.reviewer.family = 'gemini'; },
    (e) => { e.artifact.commit = 'f'.repeat(40); },
    (e) => { e.review.pr = (e.review.pr ?? 0) + 1; },
  ]) {
    const copy = JSON.parse(JSON.stringify(ENVELOPE));
    mutate(copy);
    assert.notEqual(envelopeDigest(copy), envelopeDigest(ENVELOPE), 'a changed record kept its locator');
  }
});

test('R2: the rendered comment carries the canonical locator', () => {
  const rendered = renderComment(ENVELOPE, { envelopePath: 'x/envelope.json' });
  assert.ok(rendered.includes(independentDigest(ENVELOPE)), 'the comment does not carry the independently computed digest');
});

test('R2: an edited comment keeps resolving to the original record, and no longer claims otherwise', () => {
  // The honest contract. The file previously promised that editing a comment broke the digest; it
  // never did, because the digest is computed from the envelope. Assert the true behaviour, and
  // assert the false promise is gone so it cannot be reintroduced as a comment.
  const rendered = renderComment(ENVELOPE, { envelopePath: 'x/envelope.json' });
  const flipped = ENVELOPE.review.verdict === 'APPROVE' ? 'REJECT' : 'APPROVE';
  const edited = rendered.replace(`### Quorum review — ${ENVELOPE.review.verdict}`, `### Quorum review — ${flipped}`);
  assert.notEqual(edited, rendered, 'the fixture must actually be edited');
  assert.ok(
    edited.includes(envelopeDigest(ENVELOPE)),
    'the locator should still point at the real record after the view is edited',
  );

  // Assert the RENDERED TEXT makes no tamper-detection promise. Checked against the output rather
  // than by grepping the source, so the module can still explain in comments why the old claim was
  // wrong without the test mistaking that explanation for a reintroduction.
  assert.doesNotMatch(rendered, /edited[^.]*will not match/i, 'the comment claims edits break the digest; they do not');
  assert.doesNotMatch(rendered, /no longer resolves/i, 'the comment claims edits break resolution; they do not');
});

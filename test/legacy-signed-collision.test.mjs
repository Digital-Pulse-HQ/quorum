// THE UNSAFE-INTEGER WIRE AMBIGUITY, reproduced and then closed — in one file, so the two halves
// cannot drift.
//
// WHAT WENT WRONG THE FIRST TIME, recorded because the fixture looked right. An earlier
// remediation committed `unsafe-integer-pr-adjacent.json`: an envelope signed at
// `review.pr = 9007199254740991` (MAX_SAFE_INTEGER) whose wire text was then rewritten to
// `9007199254740993`. Its name and its comments said "adjacent-integer collision". It was not one —
// those two decimal tokens are two DIFFERENT doubles, so the rewrite simply changed a signed value.
// Run through the pre-fix verifier it returned `Q12_REVIEWER_SIGNATURE`: an ordinary
// tampering refusal that the old code already caught, dressed as a reproduction of a defect the old
// code did not catch. A fixture that refuses for the wrong reason still shows green.
//
// THE COLLISION IS BETWEEN 2^53 AND 2^53+1, and reproducing it requires a signature the CURRENT code
// cannot make. Doubles at or above 2^53 represent only even integers, so `9007199254740992` and
// `9007199254740993` are two different decimal tokens that `JSON.parse` collapses onto one number.
// Before the fix, `review.pr` had no schema maximum and `canonicalize()` refused non-integers only,
// so an envelope signed at 2^53 had TWO valid wire texts for ONE reviewer signature: rewrite the
// token, resign nothing, and the verifier — which canonicalises what it PARSED — could not tell the
// two apart. `tools/make-fixtures.mjs` therefore carries an explicit legacy-canonical signing helper
// and commits both texts.
//
// WHAT CLOSES IT is two independent checks, and this file asserts they are independent: `review.pr`
// is bounded at `Number.MAX_SAFE_INTEGER` by the envelope schema, and `canonicalize()` refuses every
// unsafe integer. `M10_UNSAFE_INTEGER_WIRE_AMBIGUITY` in invariant-mutations.test.mjs removes BOTH —
// reconstituting the pre-fix semantics inside a copy of this package — and the first test below is
// the one that must redden when it does.

import assert from 'node:assert/strict';
import { createPublicKey, verify as verifyBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalize, NotCanonicalisable } from '../src/canonical.mjs';
import { reviewerPayload } from '../src/envelope.mjs';
import { verifyEnvelope } from '../src/verify.mjs';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));
const INDEX = JSON.parse(readFileSync(join(FIXTURES, 'index.json'), 'utf8'));
const read = (rel, encoding) => readFileSync(join(FIXTURES, rel), encoding);

const SIGNED = 'unsafe-integer-pr-legacy-signed';
const REWRITE = 'unsafe-integer-pr-adjacent-rewrite';

function entry(name) {
  const found = INDEX.cases.find((c) => c.name === name);
  assert.ok(found, `the fixture manifest has no case ${name}`);
  return found;
}

function verifyCase(name) {
  const e = entry(name);
  return verifyEnvelope({
    envelopeText: read(e.envelope, 'utf8'),
    policyText: read(e.policy, 'utf8'),
    trustText: read(e.trust, 'utf8'),
    expected: { attemptId: e.attempt, commit: e.commit, pr: e.pr ?? null },
    artifactBytes: read(e.artifact),
    evidenceBytes: read(e.evidence),
  });
}

/**
 * The PRE-fix canonical form: refuses non-integers, accepts unsafe ones. Re-implemented here rather
 * than imported from the generator, so that the fixture and the test are two independent statements
 * of what the old code did. If they ever disagree, the signature check below stops being valid and
 * says so.
 */
function legacyCanonicalize(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    assert.ok(Number.isInteger(value), `legacy canonical form: only integers, got ${value}`);
    return String(value === 0 ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(legacyCanonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${legacyCanonicalize(value[k])}`).join(',')}}`;
}

test('REPRODUCTION: a legacy-signed unsafe review.pr and its no-resign adjacent rewrite are both refused', () => {
  // THE ASSERTION M10 MUST REDDEN. Both wire texts are refused, and refused by the SCHEMA — before
  // any signature is examined — because under the pre-fix code both signatures were genuinely
  // valid and a signature check is therefore not what stops this.
  for (const name of [SIGNED, REWRITE]) {
    const result = verifyCase(name);
    assert.equal(result.ok, false, `${name} verified: a wire-ambiguous review.pr was accepted`);
    assert.equal(result.guard, 'Q02_ENVELOPE_SCHEMA', `${name} was refused by ${result.guard}, not the schema bound`);
  }
});

test('UNSAFE-INTEGER WIRE: the two fixtures are one signature with two wire texts, differing in exactly one token', () => {
  const signedText = read(entry(SIGNED).envelope, 'utf8');
  const rewrittenText = read(entry(REWRITE).envelope, 'utf8');

  assert.notEqual(signedText, rewrittenText, 'the two fixtures are byte-identical, so nothing was rewritten');
  assert.equal(
    signedText.replace('9007199254740992', '9007199254740993'),
    rewrittenText,
    'the rewrite is not a single pr-token substitution of the signed text',
  );

  const signed = JSON.parse(signedText);
  const rewritten = JSON.parse(rewrittenText);
  assert.deepEqual(rewritten, signed, 'the two texts must parse to the same object or there is no ambiguity to close');
  assert.equal(
    rewritten.signatures.reviewer.value,
    signed.signatures.reviewer.value,
    'the rewrite resigned the envelope; a resigned envelope is an ordinary forgery, not this defect',
  );
  assert.equal(signed.review.pr, 9007199254740992);
  assert.equal(
    JSON.parse('9007199254740992'),
    JSON.parse('9007199254740993'),
    'the two tokens must collide on parse or these fixtures prove nothing',
  );
});

test('UNSAFE-INTEGER WIRE: the committed reproduction carries a countersignature the PRE-fix verifier accepted', () => {
  // Without this, the fixtures above could be arbitrary bytes the schema happens to reject, and the
  // reproduction claim would rest on their filenames. The old verifier's acceptance is reconstructed
  // from its own canonical form and the enrolled reviewer key, rather than asserted in a comment.
  const signed = JSON.parse(read(entry(SIGNED).envelope, 'utf8'));
  const trust = JSON.parse(read(entry(SIGNED).trust, 'utf8'));
  const enrolled = trust.keys.find((k) => k.key_id === signed.reviewer.key_id);
  assert.ok(enrolled, `the trust store has no key ${signed.reviewer.key_id}`);

  const legacyBytes = Buffer.from(legacyCanonicalize(reviewerPayload(signed)), 'utf8');
  assert.equal(
    verifyBytes(null, legacyBytes, createPublicKey(enrolled.public_key_pem), Buffer.from(signed.signatures.reviewer.value, 'base64')),
    true,
    'the fixture is not actually signed under the legacy canonical form',
  );

  // And the shipped code cannot produce those bytes at all — which is why the helper exists and why
  // no fixture in this tree could carry this signature before the legacy signing helper existed.
  assert.throws(() => canonicalize(reviewerPayload(signed)), NotCanonicalisable);
});

test('UNSAFE-INTEGER WIRE: the schema bound and the canonical-form bound are two independent refusals', () => {
  // The mutation has to remove BOTH to get a false pass, so each has to be doing something on its
  // own. The schema is what Q02 enforces; the canonical form is what would still refuse the value
  // if the schema ever stopped bounding it.
  const schema = JSON.parse(readFileSync(fileURLToPath(new URL('../schema/quorum-envelope-1.schema.json', import.meta.url)), 'utf8'));
  assert.equal(schema.properties.review.properties.pr.maximum, Number.MAX_SAFE_INTEGER);
  assert.throws(() => canonicalize({ pr: 9007199254740992 }), NotCanonicalisable);
  assert.equal(canonicalize({ pr: Number.MAX_SAFE_INTEGER }), '{"pr":9007199254740991}');
});

test('UNSAFE-INTEGER WIRE: review.pr is the only numeric field, so the schema bound is the only thing before canonicalize()', () => {
  // MEASURED, not assumed, while removing the two bounds one at a time. Removing only the canonical
  // form's safe-integer check leaves the fixture refused by Q02. Removing only the SCHEMA maximum
  // does NOT produce a refusal: the unsafe value reaches canonicalize() inside signatureValid(), and
  // verifyEnvelope THROWS NotCanonicalisable instead of returning `{ ok: false, guard }`. That is
  // unreachable at this head only because `review.pr` is the sole non-string leaf in the envelope
  // schema and it is bounded — so this test fails the moment a future numeric field arrives without
  // a bound, which is the condition under which the fail-closed contract would break.
  const schema = JSON.parse(readFileSync(fileURLToPath(new URL('../schema/quorum-envelope-1.schema.json', import.meta.url)), 'utf8'));
  const numeric = [];
  const walk = (node, path) => {
    if (node === null || typeof node !== 'object') return;
    const types = [node.type].flat().filter(Boolean);
    if (types.includes('integer') || types.includes('number')) numeric.push({ path, node });
    for (const [key, child] of Object.entries(node.properties ?? {})) walk(child, `${path}.${key}`);
    if (node.items) walk(node.items, `${path}[]`);
  };
  walk(schema, '');

  assert.deepEqual(
    numeric.map((n) => n.path),
    ['.review.pr'],
    'a numeric field other than review.pr entered the envelope schema; it needs a maximum, or an unsafe value in it reaches canonicalize() and verifyEnvelope throws instead of refusing',
  );
  assert.equal(numeric[0].node.maximum, Number.MAX_SAFE_INTEGER);
});

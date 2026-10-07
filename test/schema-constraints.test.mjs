// R1, round 12: the schema's own PREDICATES, one layer below the guards.
//
// WHAT EVERY ROUND BEFORE THIS ONE MEASURED, AND WHY IT WAS NOT ENOUGH. Rounds 1-11 audited
// `src/verify.mjs`: all nineteen Q00-Q18 refusal predicates, each party's arm of each comparison,
// each digest source, each policy-conditioned branch. Round 12 pointed the same instrument one
// level down — at `src/schema.mjs`, the tiny evaluator that Q02, Q03 and Q04 DELEGATE to — and
// found six checks that could each be replaced with `false`, one at a time, leaving the complete
// suite at 221 pass / 0 fail / 0 skip and turning an independently signed, genuinely refused
// envelope into a PASS:
//
//   const        artifact.kind other than git_commit                          refusal -> PASS
//   enum         an unsupported family_trust level throughout                 refusal -> PASS
//   pattern      a producer family that is not the declared shape             refusal -> PASS
//   minimum      review.pr: 0, below the schema's floor of 1                  refusal -> PASS
//   uniqueItems  a policy whose accepted set repeats a verdict                refusal -> PASS
//   const        signatures.producer.algorithm: 'rsa', genuinely Ed25519      refusal -> PASS
//
// THE SHAPE OF THE MISS, STATED ONCE. `test/guards.test.mjs` establishes that deleting the WHOLE
// Q02 or Q03 guard reddens by name, and `test/invariants.test.mjs` establishes that the evaluator
// refuses an unsupported KEYWORD and refuses an unknown PROPERTY. None of that executes a supported
// constraint. Proving the evaluator will not silently ignore `minLength` says nothing about whether
// `minimum` — which IS implemented, IS in the shipped schema, and IS the only thing standing
// between a signed `pr: 0` and a PASS — actually runs. A delegating guard is covered when each
// constraint it delegates is shown to change the OUTCOME on its own.
//
// So every case below is a complete, independently minted, genuinely signed bundle in which exactly
// ONE field is moved outside exactly ONE schema constraint, with every neighbouring check valid —
// the enrolment agrees with the claim, the signatures cover the bytes, the policy admits the
// verdict, the digests recompute. The refusal that results can therefore be attributed to that
// constraint and to nothing else, and it disappears when that constraint stops running.
//
// EACH CASE ASSERTS THE ERROR TEXT, NOT MERELY THE GUARD. Q02 refuses for many reasons; a case
// asserting only `guard === 'Q02_ENVELOPE_SCHEMA'` would stay green under a mutation that made the
// schema refuse for a DIFFERENT reason, which is the misattribution `tools/r1-mutation-audit.mjs`
// exists to catch. Asserting the evaluator's own message pins the specific predicate.
//
// The executable form of each mutation is in `tools/r1-mutation-audit.mjs` under ROUND 12.

import assert from 'node:assert/strict';
import test from 'node:test';
import { verifyEnvelope } from '../src/verify.mjs';
import { build, mint, passes, refuses } from './helpers/bundle.mjs';

/** Refused by `guard`, AND for the stated reason — see the header on why the reason is required. */
function refusesBecause(result, guard, reason, why) {
  refuses(result, guard, why);
  assert.match(
    result.why, reason,
    `refused by ${guard}, but not for the constraint under test: ${result.why}`,
  );
}

test('R1 schema baseline: the bundle every case below moves ONE field of is itself valid', () => {
  passes(mint(), 'a baseline that does not pass would make every schema refusal below meaningless');
});

// ---------------------------------------------------------------------------
// `const` — the fixed-value constraint. Two independent call sites in the shipped envelope schema,
// and the second is not reachable through the first.
// ---------------------------------------------------------------------------

test('R1 schema/const: a genuinely signed artifact kind other than git_commit is refused', () => {
  // `artifact.kind` is inside `producerPayload`, so this envelope is signed over the wrong kind
  // rather than edited after signing: Q10 and Q12 both pass and the refusal is the schema's alone.
  // With `const` disabled the verifier accepts a signed claim to have reviewed an `unreviewed_blob`
  // — an artifact kind whose binding rules this package never defined.
  const result = mint({ artifact: { kind: 'unreviewed_blob' } });
  refusesBecause(
    result, 'Q02_ENVELOPE_SCHEMA', /#\/artifact\/kind: expected constant "git_commit"/,
    'a signed artifact kind outside the schema constant was accepted',
  );
});

test('R1 schema/const: a producer signature DECLARING a non-Ed25519 algorithm is refused', () => {
  // The second `const` call site, and the one with no defence behind it. `signatureValid` never
  // reads `algorithm` — it decodes the base64 and verifies Ed25519 unconditionally — so the schema
  // constant is the ONLY thing that makes the declared algorithm mean anything. The signature here
  // is a real Ed25519 signature and the reviewer genuinely countersigned this producer signature
  // object, algorithm field included, so Q10 and Q12 both pass.
  //
  // This is a LOST DECLARED-ALGORITHM CONSTRAINT, not an RSA bypass: nothing here verifies under
  // RSA. It matters because the field is the record's only statement of which scheme was used, and
  // a record whose algorithm field is unconstrained cannot be re-verified by a future
  // implementation that supports more than one.
  const result = mint({ producerSignature: { algorithm: 'rsa' } });
  refusesBecause(
    result, 'Q02_ENVELOPE_SCHEMA', /#\/signatures\/producer\/algorithm: expected constant "ed25519"/,
    'an envelope declaring a producer algorithm the schema does not permit was accepted',
  );
});

// ---------------------------------------------------------------------------
// `enum` — the closed-set constraint on trust levels.
// ---------------------------------------------------------------------------

test('R1 schema/enum: an UNSUPPORTED family_trust level is refused, not ranked as unknown', () => {
  // Every trust surface uses the invented level, deliberately. Setting it on the envelope alone
  // would be refused by Q14 (claim above enrolment) and setting it on the policy alone by Q15, so
  // either would still refuse with `enum` disabled and would prove nothing about the enum.
  //
  // Aligning all four is what isolates the constraint — and it is also the genuinely dangerous
  // shape. `trustRank` returns -1 for an unrecognised level, so an unsupported level compares
  // EQUAL to itself and BELOW every real one: Q14's ceiling and Q15's floor both fall through, and
  // the verifier reports a PASS at a trust level that has no definition anywhere in the protocol.
  const unsupported = { family_trust: 'unestablished' };
  const result = mint({
    producerClaim: unsupported,
    reviewerClaim: unsupported,
    producerEnrol: { family_evidence: 'unestablished' },
    reviewerEnrol: { family_evidence: 'unestablished' },
    policy: { require_family_trust: 'unestablished' },
  });
  refusesBecause(
    result, 'Q02_ENVELOPE_SCHEMA', /#\/producer\/family_trust: "unestablished" is not one of \["declared","observed"\]/,
    'a trust level outside the protocol\'s closed set was accepted at every surface at once',
  );
});

test('R1 schema/enum positive control: BOTH supported trust levels still pass', () => {
  // The other direction. Without this, `enum` could be tightened to a single level — or the whole
  // walk hard-coded to refuse — and the case above would still be green for the wrong reason.
  passes(
    mint({
      producerClaim: { family_trust: 'observed' },
      reviewerClaim: { family_trust: 'observed' },
      producerEnrol: { family_evidence: 'observed' },
      reviewerEnrol: { family_evidence: 'observed' },
      policy: { require_family_trust: 'observed' },
    }),
    'observed is a supported level and an observed policy must accept observed evidence',
  );
});

// ---------------------------------------------------------------------------
// `pattern` — the shape constraint on identity and version strings.
// ---------------------------------------------------------------------------

test('R1 schema/pattern: a producer family outside the declared shape is refused', () => {
  // The enrolment carries the SAME family string, so Q09's enrolment comparison agrees and the
  // refusal cannot be attributed to it; the reviewer's family is unchanged, so Q16 agrees too.
  // `family` is the token the cross-family rule compares, and the pattern is what keeps it a single canonical
  // spelling — with the check gone, `CLAUDE` and `claude` are two families that I-1 reads as
  // independent while they name the same one.
  const result = mint({
    producerClaim: { family: 'CLAUDE' },
    producerEnrol: { family: 'CLAUDE' },
  });
  refusesBecause(
    result, 'Q02_ENVELOPE_SCHEMA', /#\/producer\/family: "CLAUDE" does not match/,
    'a family string outside the schema pattern was accepted because its enrolment agreed with it',
  );
});

test('R1 schema/pattern positive control: a conforming family with unusual but legal characters passes', () => {
  // `^[a-z][a-z0-9-]{1,31}$` admits digits and hyphens. Pinning only the refusal would leave the
  // pattern free to be narrowed to the two families the fixtures use, which is the same
  // hard-coding mistake `R1/Q13` was written for.
  passes(
    mint({ producerClaim: { family: 'gpt-6-astra' }, producerEnrol: { family: 'gpt-6-astra' } }),
    'a lowercase family with a digit and hyphens satisfies the declared pattern and must be accepted',
  );
});

// ---------------------------------------------------------------------------
// `minimum` — the numeric floor on the PR binding.
// ---------------------------------------------------------------------------

test('R1 schema/minimum: a signed review.pr of 0 is refused even when the caller commissioned 0', () => {
  // The caller expects 0 as well, so Q17's binding comparison SUCCEEDS and the refusal is the
  // schema's alone. `0` is the value that makes this worth a constraint rather than a formality:
  // it is an integer, it is not null, and `pr !== null && pr === prExpected` is satisfied by it —
  // so with `minimum` gone, a review bound to a pull request number that cannot exist verifies,
  // and `pr: 0` is exactly what a caller that failed to parse a PR number supplies.
  const result = mint({ review: { pr: 0 }, expected: { pr: 0 } });
  refusesBecause(
    result, 'Q02_ENVELOPE_SCHEMA', /#\/review\/pr: 0 is below minimum 1/,
    'a signed pr below the schema minimum was accepted because the caller commissioned the same number',
  );
});

test('R1 schema/minimum positive control: the smallest LEGAL pr still passes', () => {
  // The boundary from the other side. Together these pin the floor at 1 rather than merely
  // establishing that some number is refused: raising the minimum reddens this case, removing it
  // reddens the one above.
  passes(
    mint({ review: { pr: 1 }, expected: { pr: 1 } }),
    'pr 1 is the smallest value the schema admits and must verify',
  );
});

// ---------------------------------------------------------------------------
// `uniqueItems` and `minItems` — the array constraints on the policy's accepted set.
// ---------------------------------------------------------------------------

test('R1 schema/uniqueItems: a policy whose accepted verdict set REPEATS a token is refused', () => {
  // A duplicated token changes no verdict decision by itself — `includes` is indifferent to it —
  // which is why nothing downstream catches this and why the schema is the only check. A policy
  // that does not say what it admits exactly once is a policy nobody can review by reading it, and
  // the set is a governance document: `['APPROVE','APPROVE']` is how a second reviewer's verdict
  // silently becomes the first one's.
  const result = mint({ policy: { accepted_verdicts: ['APPROVE', 'APPROVE'] } });
  refusesBecause(
    result, 'Q03_POLICY', /#\/accepted_verdicts: items must be unique/,
    'a policy repeating a verdict token was accepted',
  );
});

test('R1 schema/uniqueItems positive control: DISTINCT verdict tokens are not mistaken for duplicates', () => {
  // Otherwise `uniqueItems` could be strengthened into "at most one token" and the case above
  // would still be green.
  passes(
    mint({ policy: { accepted_verdicts: ['APPROVE', 'CHANGES_REQUIRED', 'REJECT'] } }),
    'three distinct tokens are a legal accepted set',
  );
});

test('R1 schema/minItems: an EMPTY accepted verdict set is a malformed policy, never a verdict refusal', () => {
  // Both outcomes refuse, so this case is about WHICH refusal — the distinction SPEC.md draws
  // between UNKNOWN/not_compared and INVALID/compared_rejected, and the reason `refuses` compares
  // the guard rather than `ok`. With `minItems` gone the empty policy is well-formed and the
  // refusal moves to Q13, reporting that a genuinely signed APPROVE was COMPARED against this
  // policy and rejected. Nothing was compared: the policy never said what it admits.
  const result = mint({ policy: { accepted_verdicts: [] } });
  refusesBecause(
    result, 'Q03_POLICY', /#\/accepted_verdicts: expected at least 1 items, got 0/,
    'an empty accepted set was read as a policy that admits nothing rather than as a malformed policy',
  );
  assert.equal(result.verdict, 'UNKNOWN', 'a policy that could not be read was not compared against');
  assert.equal(result.evidence, 'not_compared', 'a policy that could not be read was not compared against');
});

// ---------------------------------------------------------------------------
// The verifier's own call into the evaluator. A constraint that runs is worth nothing if the value
// handed to it has been laundered first.
// ---------------------------------------------------------------------------

test('R1 schema/Q02 input: the envelope validated is the envelope VERIFIED, field for field', () => {
  // Round 12's sixth witness was not a schema edit at all: it normalised `signatures.producer.
  // algorithm` to `ed25519` in the object passed to `validate`, leaving the envelope that gets
  // verified untouched. Every schema predicate still ran, on a value the record does not contain.
  //
  // Asserting the outcome covers that, because the rsa case above reddens under it. This case
  // states the property directly so the reason is legible: a normalisation applied on the way into
  // validation is indistinguishable, from the schema's side, from deleting the constraint.
  const { input, envelope } = build({ producerSignature: { algorithm: 'rsa' } });
  assert.equal(
    envelope.signatures.producer.algorithm, 'rsa',
    'the envelope under test must really carry the declared algorithm, or this case measures nothing',
  );
  refusesBecause(
    verifyEnvelope(input), 'Q02_ENVELOPE_SCHEMA', /#\/signatures\/producer\/algorithm: expected constant "ed25519"/,
    'the validated envelope differed from the verified one, so the constraint ran on a value the record does not carry',
  );
});

test('R1 schema/Q00: an OMITTED expectations object is a refusal, never a crash', () => {
  // Axis D — an absent property is not an explicitly-null one — applied to `expected`, the last
  // parameter of `verifyEnvelope` carrying a default. Every other case passes it explicitly, so the
  // `= {}` default is unexecuted contract: deleting it leaves the whole suite green while a
  // documented call throws `TypeError: Cannot read properties of undefined (reading 'attemptId')`
  // before any guard is reached. A verifier that throws has no verdict, no guard and no record —
  // and "the verifier crashed" is a shape a caller can mistake for a broken build rather than a
  // refused review.
  const { input } = build();
  delete input.expected;
  assert.equal(
    Object.hasOwn(input, 'expected'), false,
    'this case is only about the ABSENT property; if the helper still sets one it measures nothing',
  );
  const result = verifyEnvelope(input);
  refusesBecause(
    result, 'Q00_INPUT_PRESENT', /expected attempt, expected commit/,
    'a call that omits the commissioned expectations must be refused for missing them, by name',
  );
});

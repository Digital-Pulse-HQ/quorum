// R1, round 2: close the removable-check CLASS, not another list of instances.
//
// WHAT ROUND 1 GOT WRONG. The round-1 fix added a named test per SURVIVING MUTATION. The round-2
// re-adjudication then chose seven different sub-clause mutations of its own — each turning a real
// refusal into a real PASS, or a legitimate PASS into a false refusal — and every one survived a
// complete 154/154 run with zero skips on Node 24.20.0 and 26.7.0:
//
//   Q04  disable the Ed25519 key-type refusal, with an unused X25519 key enrolled   refusal -> PASS
//   Q13  hard-code the verdict set instead of reading the policy's                  refusal -> PASS
//   Q17  make the permissive PR arm accept unconditionally                          refusal -> PASS
//   Q08  ignore the recomputed digest whenever a caller digest exists               refusal -> PASS
//   Q10  re-encode the producer signature before comparing it                       refusal -> PASS
//   Q16  drop `policy.require_family_inequality &&`                                 PASS -> refusal
//   Q08  drop the caller digest whenever artifact bytes are absent                  PASS -> refusal
//
// Adding seven more tests named after those seven would be the same mistake a third time. There is
// a single shape underneath all of them, and it is the thing this file fixes:
//
//   A GUARD IS A PREDICATE OVER NAMED INPUTS, AND THE SUITE PINNED ONLY ONE OF ITS ANSWERS.
//   Every survivor changes what a guard does on an input NEIGHBOURING the one its test uses, while
//   the tested input keeps getting the tested answer. A guard is not covered by a test that proves
//   it refuses something; it is covered when every input it reads is shown to CHANGE the outcome,
//   in BOTH directions, on its own.
//
// So the rule this file applies, guard by guard, is: for each decision input a guard reads, there
// is a named test that fails when that input stops being consulted. That splits into three axes,
// and the seven survivors are seven points on them — seven of the fourteen cases below. The other
// seven are the neighbours the same rule demands, written because the rule demands them and not
// because anyone has yet mutated them:
//
//   A. POLICY-CONDITIONED BRANCHES. A guard reading a policy field has a restrictive answer and a
//      permissive one. Pinning only the restrictive answer leaves the permissive branch free to be
//      tightened, loosened or deleted. The permissive case must be reached by an input the
//      restrictive setting genuinely refuses, or it proves nothing about the branch.
//   B. MULTI-SOURCE AGREEMENT. Q08 combines two independent digest sources. Presence and agreement
//      are separate facts, so the cases are the combinations, not one example of each source.
//   C. REPEATED CALL SITES. `signatureValid` runs once per party and the store integrity checks run
//      once per enrolled key. A check reached twice needs two tests: one occurrence can be neutered
//      while the other keeps refusing the only fixture anybody wrote.
//
// Every case asserts the OUTCOME — which guard refused, or that a supported configuration passed —
// never the source text of the verifier. `tools/r1-mutation-audit.mjs` carries the executable form
// of the same matrix, so a later edit that removes one of these inputs from consideration reddens
// a test by name rather than merely lowering a count.

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { verifyEnvelope } from '../src/verify.mjs';
import { build, mint, passes, refuses } from './helpers/bundle.mjs';

test('R1 decision inputs: the baseline every case below changes one fact of is itself valid', () => {
  passes(mint(), 'a baseline that does not pass would make every refusal below meaningless');
});

// ---------------------------------------------------------------------------
// AXIS A — policy-conditioned branches. Both answers, each reached by an input that the other
// setting decides differently.
// ---------------------------------------------------------------------------

test('R1/Q13: a genuinely signed verdict outside THIS policy\'s accepted set is refused', () => {
  // The survivor replaced `policy.accepted_verdicts` with the three tokens the fixtures happen to
  // use. Every existing verdict test varies the TOKEN while leaving the policy's set alone, so no
  // test established that the set is read from the policy at all.
  refuses(
    mint({ review: { verdict: 'CHANGES_REQUIRED' }, policy: { accepted_verdicts: ['APPROVE'] } }),
    'Q13_VERDICT',
    'a correctly signed CHANGES_REQUIRED was accepted under a policy that admits only APPROVE',
  );
});

test('R1/Q13 positive control: a non-APPROVE verdict INSIDE the accepted set passes', () => {
  // The other direction of the same input. Together these two pin the set to the policy document:
  // one identical envelope, two policies, two outcomes.
  passes(
    mint({ review: { verdict: 'CHANGES_REQUIRED' }, policy: { accepted_verdicts: ['APPROVE', 'CHANGES_REQUIRED'] } }),
    'a policy that admits CHANGES_REQUIRED must accept a correctly signed CHANGES_REQUIRED',
  );
});

test('R1/Q16 positive control: require_family_inequality:false accepts two DISTINCT same-family keys', () => {
  // The survivor deleted `policy.require_family_inequality &&`, so the guard refused unconditionally
  // and nothing noticed. The existing same-family test sets this flag false but names a reviewer
  // enrolled for another family, so it is already refused at Q11 and never reaches Q16.
  //
  // Distinct KEY MATERIAL is what makes this a supported configuration rather than a self-approval:
  // F1 refuses one private key occupying two enrolled identities at Q04, and that guard
  // is independent of this flag.
  passes(
    mint({
      reviewerClaim: { family: 'claude' },
      reviewerEnrol: { family: 'claude' },
      policy: { require_family_inequality: false },
    }),
    'two separately enrolled same-family principals under a policy that permits them is supported',
  );
});

test('R1/Q17: require_pr_binding:false still refuses a PR that contradicts the commissioned one', () => {
  // The survivor replaced the permissive arm with `true`. Optional PR binding means the caller need
  // not commission a PR — never that a PR the caller DID commission may disagree with the signed one.
  refuses(
    mint({ policy: { require_pr_binding: false }, expected: { pr: 43 } }),
    'Q17_PR_BINDING',
    'the envelope binds pr 42, the caller commissioned pr 43, and the permissive policy waved it through',
  );
});

test('R1/Q17 positive control: require_pr_binding:false accepts a signed PR the caller did not commission', () => {
  // The branch the permissive arm actually exists for, and the reason it cannot simply be deleted.
  passes(
    mint({ policy: { require_pr_binding: false }, expected: { pr: null } }),
    'a caller that commissioned no PR must not be forced to match one',
  );
});

// ---------------------------------------------------------------------------
// AXIS B — Q08 combines two independent sources. Presence and agreement are separate facts, so the
// coverage unit is the combination. Two of these four survived round 1.
// ---------------------------------------------------------------------------

test('R1/Q08: a correct caller digest does not excuse WRONG artifact bytes', () => {
  // The survivor dropped the recomputed digest from the comparison whenever a caller digest existed.
  // Round 1 covered the reverse disagreement only — correct bytes against a wrong caller digest —
  // so the recomputation could be removed while the caller digest kept refusing that one case.
  const { input, envelope } = build();
  input.artifactBytes = Buffer.from('not the artifact that was reviewed\n', 'utf8');
  input.expected.artifactDigest = envelope.artifact.digest;
  refuses(
    verifyEnvelope(input),
    'Q08_ARTIFACT_DIGEST',
    'the bytes on disk were not the reviewed artifact and a matching caller digest concealed it',
  );
});

test('R1/Q08 positive control: a caller digest ALONE, with no artifact bytes, is sufficient', () => {
  // The survivor dropped the caller digest whenever bytes were absent, turning the documented
  // digest-only call into a refusal. A fail-closed guard being made stricter is still a defect:
  // nothing distinguishes it from the guard being made stricter in a direction that matters.
  const { input, envelope } = build();
  input.artifactBytes = null;
  input.expected.artifactDigest = envelope.artifact.digest;
  passes(verifyEnvelope(input), 'a caller that computed the digest itself supplied an independent source');
});

test('R1/Q08: a caller digest alone that CONTRADICTS the envelope is refused', () => {
  // The neighbour of the case above: the same single source, the other answer. Without it, the
  // digest-only path could be made unconditionally permissive and only the positive control would
  // speak for it.
  const { input } = build();
  input.artifactBytes = null;
  input.expected.artifactDigest = `sha256:${'0'.repeat(64)}`;
  refuses(
    verifyEnvelope(input),
    'Q08_ARTIFACT_DIGEST',
    'the only independent digest disagreed with the envelope and it passed anyway',
  );
});

test('R1/Q08: neither artifact bytes NOR a caller digest is a refusal, never a skip', () => {
  // "Could not check" is not "checked". With no source at all the envelope's claim about its own
  // digest is the only thing present, and reading the record to check the record is the failure
  // this whole verifier is organised around.
  const { input } = build();
  input.artifactBytes = null;
  delete input.expected.artifactDigest;
  const result = verifyEnvelope(input);
  refuses(result, 'Q08_ARTIFACT_DIGEST', 'nothing was recomputed and the envelope was believed about itself');
  assert.equal(result.verdict, 'UNKNOWN', 'nothing was compared, so this is UNKNOWN rather than INVALID');
});

// ---------------------------------------------------------------------------
// AXIS C — repeated call sites. `signatureValid` runs once per party; the store integrity checks
// run once per enrolled key, including keys the envelope never names.
// ---------------------------------------------------------------------------

test('R1/Q10: a non-canonical base64 PRODUCER signature is refused even when the reviewer countersigns it', () => {
  // The survivor re-encoded the producer's signature before comparing it, defeating the check for
  // that party only. The existing canonicality test re-encodes the REVIEWER signature, so the
  // producer call site was unprotected.
  //
  // The re-encoding happens BEFORE the countersignature, so the reviewer genuinely signs this
  // representation and Q12 cannot mask the result: the only thing standing between the record and
  // two valid byte sequences is Q10's own comparison.
  refuses(
    mint({ producerNonCanonical: true }),
    'Q10_PRODUCER_SIGNATURE',
    'the producer signature had a second, equally valid base64 representation and it was accepted',
  );
});

test('R1/Q12: a non-canonical base64 REVIEWER signature is refused', () => {
  // The same check at the other call site, stated independently so neither occurrence can stand in
  // as evidence for the other.
  refuses(
    mint({ reviewerNonCanonical: true }),
    'Q12_REVIEWER_SIGNATURE',
    'the reviewer signature had a second, equally valid base64 representation and it was accepted',
  );
});

test('R1/Q04: an UNUSED enrolled key that is not Ed25519 refuses the whole trust store', () => {
  // The survivor disabled the key-type refusal entirely and the suite stayed green, because every
  // existing trust-store case enrols a bad key that some later guard also refuses. The key here is
  // never named by the envelope: if it had been, the refusal could be attributed to a failed
  // signature instead, and the store-integrity guard would again go unmeasured.
  //
  // A verifier that shrugs at an unreadable enrolment beside the one it needs is trusting a
  // document it cannot read.
  refuses(
    mint({
      trustExtra: [() => ({
        key_id: 'unused-x25519',
        principal: 'dp:r1-bystander@example.test',
        family: 'gemini',
        family_evidence: 'declared',
        roles: ['reviewer'],
        public_key_pem: generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'pem' }),
      })],
    }),
    'Q04_TRUST_STORE',
    'an X25519 key was enrolled in an Ed25519 trust store and only the keys in use were checked',
  );
});

test('R1/Q04: an UNUSED duplicate key_id refuses the whole trust store', () => {
  // Same axis, different store-integrity check: the duplicate-id detection also runs per key, and
  // the collision here involves neither signing party.
  refuses(
    mint({
      trustExtra: [({ pem }) => ({
        key_id: 'r1-bystander',
        principal: 'dp:r1-bystander@example.test',
        family: 'gemini',
        family_evidence: 'declared',
        roles: ['reviewer'],
        public_key_pem: pem(generateKeyPairSync('ed25519').publicKey),
      }), ({ pem }) => ({
        key_id: 'r1-bystander',
        principal: 'dp:r1-other@example.test',
        family: 'gemini',
        family_evidence: 'declared',
        roles: ['reviewer'],
        public_key_pem: pem(generateKeyPairSync('ed25519').publicKey),
      })],
    }),
    'Q04_TRUST_STORE',
    'two enrolments shared a key_id and the lookup silently preferred one of them',
  );
});

test('R1/Q04: an UNUSED key reusing enrolled key MATERIAL refuses the whole trust store', () => {
  // F1 at a key the envelope never names. The duplicate is of the PRODUCER's material
  // under a different id, principal, family and role — the re-exported SPKI comparison is what
  // makes that detectable, and it too runs per key rather than per party.
  refuses(
    mint({
      trustExtra: [({ producerKey, pem }) => ({
        key_id: 'r1-bystander',
        principal: 'dp:r1-bystander@example.test',
        family: 'gemini',
        family_evidence: 'declared',
        roles: ['reviewer'],
        public_key_pem: pem(producerKey.publicKey),
      })],
    }),
    'Q04_TRUST_STORE',
    'one key was enrolled twice under different identities and only the named enrolments were compared',
  );
});

// ---------------------------------------------------------------------------
// ROUND 3, at b5169dbe. The seven round-2 mutations above are each killed by a named test, and the
// re-adjudication then chose four more — under the same rule this file is organised by, on inputs
// the cases above leave unpinned. Each changed a real outcome while the complete suite stayed
// 169/169 with zero skips on Node 24.20.0 and 26.7.0:
//
//   Q04  replace the unreadable-key refusal with `continue`, one unused broken PEM enrolled  refusal -> PASS
//   Q17  drop `envelope.review.pr !== null &&` from the REQUIRING arm                        refusal -> PASS
//   Q18  run the evidence comparison whenever bytes are supplied, policy notwithstanding     PASS -> refusal
//   Q17  drop `|| envelope.review.pr === prExpected` from the PERMISSIVE arm                 PASS -> refusal
//
// The shape is the one this file already names, applied one level finer. Two of these guards are
// CONJUNCTIONS, not single facts — Q17's requiring arm asks presence AND equality, Q04's per-key
// loop asks readable AND Ed25519 — and a conjunction is covered only when each conjunct is shown to
// decide the outcome alone. The other two are the permissive arms' supported ACCEPT paths: the
// cases above reach `require_pr_binding:false` and `require_evidence:false` only by the input the
// exclusion is trivially true for (a null commissioned PR, an absent document), so the branch that
// does the excluding was never the thing under test.
// ---------------------------------------------------------------------------

test('R1/Q04: an UNUSED enrolled key whose PEM cannot be PARSED refuses the whole trust store', () => {
  // Distinct from the X25519 case above, and not reachable by it: that key parses and is refused
  // for its TYPE, one branch later. This one never becomes a key object at all. Replacing the
  // unreadable-key return with `continue` therefore leaves the type refusal fully intact, and the
  // store quietly shrinks to the enrolments that happened to load.
  //
  // Schema-valid on purpose — it carries the required BEGIN PUBLIC KEY prefix — so this is a
  // verifier decision about a document it cannot read, never a JSON-schema rejection.
  refuses(
    mint({
      trustExtra: [() => ({
        key_id: 'unused-unreadable',
        principal: 'dp:r1-bystander@example.test',
        family: 'gemini',
        family_evidence: 'declared',
        roles: ['reviewer'],
        public_key_pem: '-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----\n',
      })],
    }),
    'Q04_TRUST_STORE',
    'an enrolment that could not be parsed was skipped and the rest of the store was trusted anyway',
  );
});

test('R1/Q17: require_pr_binding:true refuses an ABSENT PR even when the caller commissioned none', () => {
  // Q17's requiring arm is a conjunction: the PR must be PRESENT and must EQUAL the commissioned
  // one. Every case above varies only equality, with both sides non-null, so `pr !== null` could be
  // deleted and equality alone would still refuse them. Here equality holds — null equals null —
  // and presence is the only fact left refusing. Requiring a binding that is satisfied by both
  // sides being absent is not requiring a binding.
  refuses(
    mint({ review: { pr: null }, expected: { pr: null }, policy: { require_pr_binding: true } }),
    'Q17_PR_BINDING',
    'a policy demanding a PR binding accepted an envelope bound to no PR at all',
  );
});

test('R1/Q17 positive control: require_pr_binding:false accepts a signed PR that MATCHES the commissioned one', () => {
  // The permissive arm is a disjunction and the control above reaches only its first term, where
  // the commissioned PR is null. Deleting the second term therefore refuses this — the ordinary
  // case of a caller who did commission a PR and got exactly it — while every existing test keeps
  // its answer. A guard that refuses agreement is as wrong as one that accepts contradiction.
  passes(
    mint({ policy: { require_pr_binding: false }, expected: { pr: 42 } }),
    'the signed PR and the commissioned PR are the same PR, under a policy that does not even demand one',
  );
});

test('R1/Q18 positive control: require_evidence:false ignores evidence bytes that CONTRADICT the envelope', () => {
  // The permissive exclusion itself, rather than the absence it is usually reached by. The existing
  // permissive case supplies null bytes, so the comparison is skipped for want of an operand and
  // `if (policy.require_evidence)` could be widened to `|| evidenceBytes !== null` unnoticed.
  // Supplying bytes that genuinely disagree is what makes the policy field the deciding input.
  //
  // A false refusal here is a refusal of a supported call, which the audit counts the same way it
  // counts an accepted forgery: neither one is what the record says happened.
  const { input } = build({ policy: { require_evidence: false } });
  input.evidenceBytes = Buffer.from('not the findings that were signed\n', 'utf8');
  passes(
    verifyEnvelope(input),
    'a policy that does not require evidence must not be made to compare it anyway',
  );
});

// ---------------------------------------------------------------------------
// ROUND 4, at b829c8aa. The four round-3 mutations above are each killed by a named test, and two
// further decision inputs were then chosen independently — one by the re-adjudication,
// one by a second round-4 reviewer whose run reached us unrelayed. Both survived a
// complete 179/179 run with zero skips on Node 24.20.0 and 26.7.0:
//
//   Q17  drop the `?? null` DEFAULT, with the commissioned PR omitted entirely   PASS -> refusal
//   Q18  drop the absent-evidence classification condition                       UNKNOWN -> INVALID
//
// Both are one level finer again, and on an axis this file had not yet named. Round 3 covered
// which ANSWER a guard gives; these two cover the shape of the CALL and the shape of the ANSWER:
//
//   D. ABSENT vs EXPLICITLY-NULL INPUT. `expected.pr` is documented optional and implemented with
//      `?? null`. Every case above passes it EXPLICITLY, as null or as a number, so the default
//      could be deleted and each of them would keep its answer. Omission is a supported call and
//      needs its own control, or `?? null` is unexecuted contract.
//   E. THE REFUSAL'S OWN FIELDS. A guard has a machine-readable verdict as well as an identity.
//      Q18 refuses an absent document as UNKNOWN/not_compared and a contradicting one as
//      INVALID/compared_rejected — SPEC.md distinguishes them — but every case above asserts only
//      WHICH guard refused. The two states could be collapsed with the suite fully green, and the
//      record would then say a document was compared and rejected when none was ever supplied.
// ---------------------------------------------------------------------------

test('R1/Q17 positive control: require_pr_binding:false accepts a call that OMITS the commissioned PR', () => {
  // `expected.pr` is optional by contract and the optionality lives entirely in `?? null`. The
  // round-3 control above commissions pr 42 explicitly and the round-2 one passes an explicit
  // null, so both survive the default's deletion: neither ever reads an ABSENT property.
  //
  // Omission and explicit null must be the same supported call. Without this, `?? null` can be
  // removed and a caller who commissioned no PR is refused Q17_PR_BINDING against `undefined` —
  // a refusal naming a commissioned review that does not exist.
  const { input } = build({ policy: { require_pr_binding: false }, review: { pr: null } });
  delete input.expected.pr;
  assert.equal(
    Object.hasOwn(input.expected, 'pr'), false,
    'this case is only about the ABSENT property; if the helper still sets one it measures nothing',
  );
  passes(
    verifyEnvelope(input),
    'a policy that does not require a PR binding refused a caller who commissioned no PR at all',
  );
});

test('R1/Q18: an ABSENT evidence document is UNKNOWN/not_compared, never compared_rejected', () => {
  // The refusal's own fields, not just its identity. `fail(..., evidenceBytes !== null)` is what
  // separates "we had nothing to check" from "we checked and it was wrong"; deleting the condition
  // leaves both refusals in place and every guard-identity assertion in this suite green, while
  // the machine-readable record starts claiming a comparison that never happened.
  const { input } = build({ policy: { require_evidence: true } });
  input.evidenceBytes = null;
  const result = verifyEnvelope(input);
  refuses(result, 'Q18_EVIDENCE_BINDING', 'a required evidence document that was never supplied must be refused');
  assert.equal(result.verdict, 'UNKNOWN', 'an absent document cannot make the review INVALID; nothing was compared');
  assert.equal(result.evidence, 'not_compared', 'no document was supplied, so no comparison can be reported');
});

test('R1/Q18: a SUPPLIED evidence document that contradicts the envelope is INVALID/compared_rejected', () => {
  // The other answer of the same input, so the condition cannot be inverted or hard-coded false
  // and satisfy the case above alone. Here a real document was really hashed and really disagreed.
  const { input } = build({ policy: { require_evidence: true } });
  input.evidenceBytes = Buffer.from('not the findings that were signed\n', 'utf8');
  const result = verifyEnvelope(input);
  refuses(result, 'Q18_EVIDENCE_BINDING', 'a supplied document that does not hash to the signed digest must be refused');
  assert.equal(result.verdict, 'INVALID', 'a document was compared and disagreed, which is a positive finding');
  assert.equal(result.evidence, 'compared_rejected', 'the comparison happened and rejected the document');
});

test('R1/Q18 positive control: a bundle whose evidence AGREES reports compared_ok', () => {
  // The third state, so neither refusal above can be reached by a verifier that simply stopped
  // passing. Without this the two assertions above are satisfied by a Q18 that refuses everything.
  const result = mint({ policy: { require_evidence: true } });
  passes(result, 'the supplied evidence hashes to exactly the digest the envelope binds');
  assert.equal(result.evidence, 'compared_ok', 'the document was compared and agreed');
});

// ---------------------------------------------------------------------------
// ROUND 5, at c2a2e717. The five round-4 instances above are each killed by a named
// test. The reviewer then applied axes D and E to the inputs and guards they did NOT reach, and
// three more mutations survived a complete 186/186 run with zero skips on Node 24.20.0 and 26.7.0:
//
//   J01  delete the `evidenceBytes = null` DEFAULT, with the property omitted   refusal -> THROWS
//   J02  delete the `artifactBytes = null` DEFAULT, with the property omitted   PASS     -> THROWS
//   J03  replace Q08's `artifactSources.length > 0` with `false`                INVALID  -> UNKNOWN
//
// This is the round-1 mistake in its purest form, and the round-4 record named it as the thing to
// attack first: an axis was DERIVED FROM ONE INSTANCE and then applied only to that instance.
// Round 4 wrote axis D for `expected.pr` and axis E for Q18, and stopped there. `artifactBytes` and
// `evidenceBytes` are documented optional and implemented with the same defaulting idiom as
// `expected.pr`; Q08 classifies its refusal with the same condition shape as Q18. The axis was
// right and its application was one example wide.
//
// So the rule, restated as the round-5 entries apply it: AN AXIS IS NOT DISCHARGED BY THE INSTANCE
// THAT SUGGESTED IT. Every input matching the axis's shape gets the axis's cases.
//
// Note what J01 and J02 do, because it is the sharper half: deleting a parameter default does not
// loosen a check, it makes a SUPPORTED CALL THROW. `evidenceBytes === null` is a strict comparison,
// so an omitted property arrives as `undefined`, misses the absent-document branch and reaches
// `createHash().update(undefined)`. A verifier that throws is not fail-closed — it has no verdict,
// no guard and no record, and a caller that treats a throw as anything other than a refusal has a
// bypass. Every case below therefore asserts a STRUCTURED outcome, never merely "not ok".
// ---------------------------------------------------------------------------

test('R1/Q18 positive control: an OMITTED evidence document is the same supported call as an explicit null', () => {
  // Axis D on `evidenceBytes`. Every Q18 case above sets the property EXPLICITLY to null, so the
  // `= null` default is unexecuted contract and deleting it keeps all of them green. Omission is a
  // supported call — the JSDoc marks the parameter optional — and it is the call a caller makes
  // when it simply has no document to hand in.
  const { input } = build({ policy: { require_evidence: true } });
  delete input.evidenceBytes;
  assert.equal(
    Object.hasOwn(input, 'evidenceBytes'), false,
    'this case is only about the ABSENT property; if the helper still sets one it measures nothing',
  );
  const result = verifyEnvelope(input);
  refuses(result, 'Q18_EVIDENCE_BINDING', 'a required evidence document that was never supplied must be refused');
  assert.equal(result.verdict, 'UNKNOWN', 'nothing was supplied, so nothing was compared');
  assert.equal(result.evidence, 'not_compared', 'an omitted document must classify exactly as an explicit null does');
});

test('R1/Q08 positive control: OMITTED artifact bytes are the same supported call as an explicit null', () => {
  // Axis D on `artifactBytes`. The digest-only control above passes an explicit null, so it
  // survives the default's deletion; this one never sets the property at all. With the default
  // gone, `sha256Ref(undefined)` throws before any guard is reached, and a documented call that
  // supplies a caller digest instead of bytes stops having a verdict.
  const { input, envelope } = build();
  delete input.artifactBytes;
  assert.equal(
    Object.hasOwn(input, 'artifactBytes'), false,
    'this case is only about the ABSENT property; if the helper still sets one it measures nothing',
  );
  input.expected.artifactDigest = envelope.artifact.digest;
  const result = verifyEnvelope(input);
  passes(result, 'a caller that computed the digest itself and passed no bytes supplied an independent source');
  assert.equal(result.evidence, 'compared_ok', 'the caller digest was compared against the envelope and agreed');
});

test('R1/Q08: NO independent source is UNKNOWN/not_compared', () => {
  // Axis E on Q08 — the guard NEXT TO the one round 4 wrote axis E for. `fail(..., <condition>)`
  // is what separates "we had nothing to check" from "we checked and it disagreed". The no-source
  // case above already pins `verdict`; `evidence` was never asserted for either answer, so the
  // condition could be hard-coded and the record would still read as consistent.
  const { input } = build();
  input.artifactBytes = null;
  delete input.expected.artifactDigest;
  const result = verifyEnvelope(input);
  refuses(result, 'Q08_ARTIFACT_DIGEST', 'nothing was recomputed and the envelope was believed about itself');
  assert.equal(result.verdict, 'UNKNOWN', 'nothing was compared, so this is UNKNOWN rather than INVALID');
  assert.equal(result.evidence, 'not_compared', 'no source existed, so no comparison may be reported');
});

test('R1/Q08: a SUPPLIED source that contradicts the envelope is INVALID/compared_rejected', () => {
  // The other answer of the same condition, and the one J03 erased. Real bytes were really hashed
  // and really disagreed; reporting that as not_compared would let the record say no comparison
  // happened while `why` still recites the digests it compared. Without this assertion the
  // condition collapses to `false` and the complete suite stays green.
  const { input } = build();
  input.artifactBytes = Buffer.from('not the artifact that was reviewed\n', 'utf8');
  const result = verifyEnvelope(input);
  refuses(result, 'Q08_ARTIFACT_DIGEST', 'the bytes on disk were not the reviewed artifact');
  assert.equal(result.verdict, 'INVALID', 'a real comparison was performed and it rejected the artifact');
  assert.equal(result.evidence, 'compared_rejected', 'the comparison happened, so it must be reported as having happened');
  assert.match(result.why, /recomputed /, 'the explanation must name the comparison the classification claims');
});

test('R1/Q08 positive control: agreeing sources report PASS/compared_ok', () => {
  // The third state, so neither refusal above can be satisfied by a Q08 that refuses everything.
  const result = mint();
  passes(result, 'the artifact bytes hash to exactly the digest the envelope binds');
  assert.equal(result.evidence, 'compared_ok', 'the artifact was compared and agreed');
});

// ---------------------------------------------------------------------------
// ROUND 6, at f1460f1f (F1). Axis B and axis E intersect, and round 5 covered only one
// cell of the intersection.
//
//   K04  Q08's third `fail` argument -> `recomputed !== null`        INVALID -> UNKNOWN, caller-only
//
// Round 5 pinned Q08's classification using artifact BYTES. Q08 has TWO independent sources, which
// is the whole point of axis B — so "was a comparison performed?" has a separate answer per source,
// and pinning it through one source proves nothing about the other. K04 leaves the byte path
// correctly classified and erases the caller-digest-only path: the refusal still happens, the `why`
// still recites both digests, and the machine-readable record now says nothing was compared.
//
// AXIS B x AXIS E: WHERE A GUARD COMBINES SOURCES, THE REFUSAL'S OWN FIELDS ARE PER-SOURCE.
// ---------------------------------------------------------------------------

test('R1/Q08: a contradictory CALLER DIGEST ALONE is INVALID/compared_rejected', () => {
  // The caller computed a digest, handed in no bytes, and it disagreed with the envelope. A real
  // comparison happened against a real independent source, so erasing it is a false provenance
  // claim — the record would say the digest was never checked while `why` names what it checked.
  const { input, envelope } = build();
  input.artifactBytes = null;
  input.expected.artifactDigest = `sha256:${'0'.repeat(64)}`;
  const result = verifyEnvelope(input);
  refuses(result, 'Q08_ARTIFACT_DIGEST', 'the only independent digest disagreed with the envelope');
  assert.equal(result.verdict, 'INVALID', 'a caller-supplied digest is a real source; comparing it and rejecting is a finding');
  assert.equal(result.evidence, 'compared_rejected', 'the comparison happened without artifact bytes, and must be reported as having happened');
  // Round 7 (F3): asserting only the word `recomputed` let the explanation drop the
  // INDEPENDENT source and recite the envelope's own digest twice — `artifactSources.join(...)`
  // replaced by `[envelope.artifact.digest].join(...)` kept the matched token and stayed green.
  // The explanation must name BOTH sides by identity, or it is prose that cannot be wrong.
  assert.match(result.why, /recomputed /, 'the explanation must name the comparison the classification claims');
  assert.ok(result.why.includes(input.expected.artifactDigest),
    `the explanation must name the caller digest it compared; got: ${result.why}`);
  assert.ok(result.why.includes(envelope.artifact.digest),
    `the explanation must name the envelope digest it compared against; got: ${result.why}`);
});

test('R1/Q08 positive control: an AGREEING caller digest alone reports PASS/compared_ok', () => {
  // The other answer of the caller-only source, so the case above cannot be satisfied by a Q08 that
  // classifies every caller-only outcome as compared_rejected.
  const { input, envelope } = build();
  input.artifactBytes = null;
  input.expected.artifactDigest = envelope.artifact.digest;
  const result = verifyEnvelope(input);
  passes(result, 'a caller that computed the digest itself supplied an independent source');
  assert.equal(result.evidence, 'compared_ok', 'the caller digest was compared against the envelope and agreed');
});

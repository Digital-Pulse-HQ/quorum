// R1 (HIGH): attribute every trust and enrolment refusal to ONE party.
//
// THE DEFECT THIS CLOSES. The implementation was correct; its regression evidence was not. Each
// of Q09/Q11/Q14/Q15 checks the producer row and the reviewer row in a single `filter`, and every
// existing fixture had BOTH parties wrong, or was blocked by an earlier guard before reaching the
// check it claimed to test. So deleting one row left the other to refuse the same fixture, and the
// suite stayed green. Measured by the re-adjudication at 26f5b98f -- eight selective mutations,
// each turning a real refusal into a real PASS, every one of them surviving:
//
//   reviewer row of Q14 trust ceiling    106/106 behavioural, 129/129 package
//   producer row of Q15 trust floor      106/106 behavioural, 129/129 package
//   reviewer row of Q15 trust floor      106/106 behavioural, 129/129 package
//   reviewer family comparison (Q11)     106/106 behavioural, 129/129 package
//   producer role check (Q09)            106/106 behavioural, 129/129 package
//   producer principal comparison (Q09)  106/106 behavioural, 128/129 (harness only)
//   Q08 `every` -> `some`                106/106 behavioural, 128/129 (harness only)
//   evidence-policy exclusion removed    106/106 behavioural, 129/129 package
//
// A failing text-replacement harness is not a behavioural test: two of those eight reported 128/129
// solely because the author's mutation-target lookup could not find its own search string.
//
// THE SHAPE OF THE FIX. Every case below changes exactly ONE party's one field away from a bundle
// that is otherwise completely valid, and asserts BOTH that it refuses AND which guard refused.
// Each is paired with the positive control it was derived from, so a guard that refuses everything
// is caught too. `mint()` builds independent Ed25519 keys and real signatures per case rather than
// reusing a committed fixture, so a mutation cannot be masked by stale bytes.

// The bundle builder moved to test/helpers/bundle.mjs when the round-2 re-adjudication showed the
// same one-field-at-a-time discipline was needed for guards this file never reaches. It is the same
// builder; the cases below are unchanged.

import test from 'node:test';
import { sha256Ref } from '../src/envelope.mjs';
import { ARTIFACT, mint, passes, refuses } from './helpers/bundle.mjs';

test('R1 baseline: an independently minted, fully valid bundle passes', () => {
  passes(mint(), 'the baseline every case below mutates must itself be valid');
});

// ---------------------------------------------------------------------------
// Q14 trust ceiling -- an envelope may not claim more trust than its enrolment carries.
// One row per party, with the OTHER party left entirely valid.
// ---------------------------------------------------------------------------

test('R1/Q14: the PRODUCER alone cannot claim observed trust on a declared enrolment', () => {
  refuses(
    mint({ producerClaim: { family_trust: 'observed' }, policy: { require_family_trust: 'declared' } }),
    'Q14_TRUST_ENROLMENT',
    'the producer overclaimed its family trust and the reviewer row could not have caught it',
  );
});

test('R1/Q14: the REVIEWER alone cannot claim observed trust on a declared enrolment', () => {
  // This is the mutation that survived: with both parties overclaiming, deleting the reviewer row
  // left the producer row refusing the same fixture.
  refuses(
    mint({ reviewerClaim: { family_trust: 'observed' }, policy: { require_family_trust: 'declared' } }),
    'Q14_TRUST_ENROLMENT',
    'the reviewer overclaimed its family trust and nothing refused it',
  );
});

test('R1/Q14 positive control: observed claims on observed enrolments pass', () => {
  passes(
    mint({
      producerClaim: { family_trust: 'observed' }, reviewerClaim: { family_trust: 'observed' },
      producerEnrol: { family_evidence: 'observed' }, reviewerEnrol: { family_evidence: 'observed' },
    }),
    'trust that the enrolment actually carries must not be refused',
  );
});

// ---------------------------------------------------------------------------
// Q15 trust floor -- a policy demanding observed evidence fails closed on declared.
// ---------------------------------------------------------------------------

test('R1/Q15: an observed policy refuses a DECLARED producer while the reviewer is observed', () => {
  refuses(
    mint({
      reviewerClaim: { family_trust: 'observed' },
      producerEnrol: { family_evidence: 'observed' }, reviewerEnrol: { family_evidence: 'observed' },
      policy: { require_family_trust: 'observed' },
    }),
    'Q15_TRUST_POLICY',
    'the producer was below the policy floor and the reviewer row could not have caught it',
  );
});

test('R1/Q15: an observed policy refuses a DECLARED reviewer while the producer is observed', () => {
  refuses(
    mint({
      producerClaim: { family_trust: 'observed' },
      producerEnrol: { family_evidence: 'observed' }, reviewerEnrol: { family_evidence: 'observed' },
      policy: { require_family_trust: 'observed' },
    }),
    'Q15_TRUST_POLICY',
    'the reviewer was below the policy floor and nothing refused it',
  );
});

test('R1/Q15 positive control: an observed policy accepts two observed parties', () => {
  passes(
    mint({
      producerClaim: { family_trust: 'observed' }, reviewerClaim: { family_trust: 'observed' },
      producerEnrol: { family_evidence: 'observed' }, reviewerEnrol: { family_evidence: 'observed' },
      policy: { require_family_trust: 'observed' },
    }),
    'an observed policy with observed evidence on both sides is the supported configuration',
  );
});

// ---------------------------------------------------------------------------
// Q09/Q11 enrolment -- family, principal and role, per party, with otherwise valid signatures.
// Each mutation changes the ENROLMENT, so the signature stays valid and the enrolment check is
// genuinely the first guard that can refuse.
// ---------------------------------------------------------------------------

test('R1/Q11: a REVIEWER key enrolled for another family cannot sign as this one', () => {
  refuses(
    mint({ reviewerEnrol: { family: 'claude' }, policy: { require_family_inequality: false } }),
    'Q11_REVIEWER_ENROLMENT',
    'a key enrolled as claude signed an envelope claiming codex',
  );
});

test('R1/Q09: a PRODUCER key enrolled for another family cannot sign as this one', () => {
  refuses(
    mint({ producerEnrol: { family: 'gemini' } }),
    'Q09_PRODUCER_ENROLMENT',
    'a key enrolled as gemini signed an envelope claiming claude',
  );
});

test('R1/Q09: a reviewer-only key cannot occupy the PRODUCER seat', () => {
  refuses(
    mint({ producerEnrol: { roles: ['reviewer'] } }),
    'Q09_PRODUCER_ENROLMENT',
    'a key enrolled only to review was accepted as the producer',
  );
});

test('R1/Q11: a producer-only key cannot occupy the REVIEWER seat', () => {
  refuses(
    mint({ reviewerEnrol: { roles: ['producer'] } }),
    'Q11_REVIEWER_ENROLMENT',
    'a key enrolled only to produce was accepted as the reviewer',
  );
});

test('R1/Q09: a PRODUCER principal that differs from its enrolment is refused', () => {
  refuses(
    mint({ producerEnrol: { principal: 'dp:someone-else@example.test' } }),
    'Q09_PRODUCER_ENROLMENT',
    'a key signed for a principal it is not enrolled to',
  );
});

test('R1/Q11: a REVIEWER principal that differs from its enrolment is refused', () => {
  refuses(
    mint({ reviewerEnrol: { principal: 'dp:someone-else@example.test' } }),
    'Q11_REVIEWER_ENROLMENT',
    'a key signed for a principal it is not enrolled to',
  );
});

test('R1: a key enrolled for BOTH roles still cannot be both parties at once', () => {
  // The cross-family rule must not be satisfiable by one identity holding two seats.
  refuses(
    mint({
      reviewerClaim: { family: 'claude' },
      reviewerEnrol: { family: 'claude', roles: ['producer', 'reviewer'] },
    }),
    'Q16_FAMILY_INEQUALITY',
    'one family reviewed its own work',
  );
});

// ---------------------------------------------------------------------------
// Q08 -- every independently supplied digest must agree, not merely one of them.
// ---------------------------------------------------------------------------

test('R1/Q08: a caller digest contradicting correct artifact bytes is refused', () => {
  // `every` changed to `some` survived, because no fixture ever supplied two digests that
  // disagreed while one of them was right.
  refuses(
    mint({ expected: { artifactDigest: `sha256:${'0'.repeat(64)}` } }),
    'Q08_ARTIFACT_DIGEST',
    'the artifact bytes hashed correctly, so a contradicting caller digest was ignored',
  );
});

test('R1/Q08 positive control: a caller digest AGREEING with the bytes passes', () => {
  passes(
    mint({ expected: { artifactDigest: sha256Ref(ARTIFACT) } }),
    'two independent sources agreeing is the case this guard exists to reward',
  );
});

// ---------------------------------------------------------------------------
// The supported permissive branch. Removing the exclusion turned a legitimate PASS into a Q18
// refusal and no test noticed, which is a false-refusal hole rather than a bypass -- but an
// untested supported configuration is how a fail-closed guard gets loosened later.
// ---------------------------------------------------------------------------

test('R1/Q18: a policy that does not require evidence accepts an absent evidence document', () => {
  passes(
    mint({ policy: { require_evidence: false }, verify: { evidenceBytes: null } }),
    'require_evidence:false is a supported configuration and must not refuse',
  );
});

test('R1/Q18: a policy that DOES require evidence refuses the same absent document', () => {
  refuses(
    mint({ policy: { require_evidence: true }, verify: { evidenceBytes: null } }),
    'Q18_EVIDENCE_BINDING',
    'a missing review document was accepted under a policy that requires one',
  );
});

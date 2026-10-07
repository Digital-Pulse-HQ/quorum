// F1 — a policy_version must name ONE exact policy.
//
// THE DEFECT, as measured by the reviewer at 555546d9 and reproduced here before the fix:
// `policy_version` was a hand-written string and Q05 compared only that string, so
// `policy-declared.json` and `policy-residue.json` — different bytes, opposite
// `require_residue_declaration` — both said `quorum-policy/1@2026-09-10`. The SAME signed envelope,
// trust store, artifact, evidence, attempt, commit and PR returned PASS under the first and
// Q19_RESIDUE_DECLARATION / INVALID under the second, and Q05 accepted both because the string
// matched. The two `.json` files it produced were byte-identical
// (sha256:22304f48ec1bc996c256d855dbdd3c3590c5f8343366d80194c75c63abf95678).
//
// WHY A VERIFIER CAN DETECT THIS AT ALL. It is handed one policy, never two, so it cannot compare
// them. `policy_version` is therefore made CONTENT-DERIVED (`<label>+<128-bit digest of the policy
// without policy_version>`) and Q20_POLICY_IDENTITY RECOMPUTES it. Of any two different canonical
// documents claiming one version, at most one can be self-consistent; the other is refused on
// sight, from its own half of the collision.
//
// WHAT MUST SURVIVE, because a guard that also breaks these is the wrong guard:
//   - an empty residue is still valid under a policy that requires a residue declaration;
//   - an envelope produced under the old policy still verifies against that unmodified policy;
//   - a residue-absent envelope is still refused by Q19, not swallowed by the new guard.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from '../src/canonical.mjs';
import { declaredPolicyIdentity, policyIdentity, stampPolicyVersion } from '../src/envelope.mjs';
import { verifyEnvelope } from '../src/verify.mjs';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));
const read = (rel, encoding = 'utf8') => readFileSync(join(FIXTURES, rel), encoding);
/** Deletion-control cases point at files that are absent on purpose; absence is their input. */
const readOrNull = (rel, encoding = 'utf8') => {
  if (rel === null || rel === undefined) return null;
  try { return readFileSync(join(FIXTURES, rel), encoding); } catch { return null; }
};
const INDEX = JSON.parse(read('index.json'));

const caseNamed = (name) => {
  const found = INDEX.cases.find((entry) => entry.name === name);
  assert.ok(found, `fixture case ${name} is missing`);
  return found;
};

/** Verify a committed case, optionally substituting the policy TEXT the verifier is handed. */
function runCase(name, policyText = null) {
  const testCase = caseNamed(name);
  return verifyEnvelope({
    envelopeText: readOrNull(testCase.envelope),
    policyText: policyText ?? readOrNull(testCase.policy),
    trustText: readOrNull(testCase.trust),
    expected: { attemptId: testCase.attempt, commit: testCase.commit, pr: testCase.pr ?? null },
    artifactBytes: readOrNull(testCase.artifact, null),
    evidenceBytes: readOrNull(testCase.evidence, null),
  });
}

const text = (value) => `${JSON.stringify(value, null, 2)}\n`;

const DECLARED = JSON.parse(read('shared/policy-declared.json'));
const RESIDUE = JSON.parse(read('shared/policy-residue.json'));

// ---------------------------------------------------------------------------------------------
// The collision itself.
// ---------------------------------------------------------------------------------------------

test('F1: two DIFFERENT canonical policy documents sharing one policy_version — the verifier refuses the one that does not own the identity', () => {
  // Constructed, not read from disk: the finding asks for a test that CONSTRUCTS the collision, so
  // that it keeps holding for policies nobody has committed yet.
  const owner = DECLARED;
  const impostor = { ...RESIDUE, policy_version: DECLARED.policy_version };

  // Precondition — this really is the finding's shape, not a weaker one.
  assert.equal(impostor.policy_version, owner.policy_version, 'the two documents must share a version');
  assert.notEqual(canonicalBytes(owner).toString('utf8'), canonicalBytes(impostor).toString('utf8'),
    'the two documents must be materially different, or this proves nothing');
  assert.notEqual(owner.require_residue_declaration, impostor.require_residue_declaration);

  const underOwner = runCase('valid-cross-family-approve', text(owner));
  const underImpostor = runCase('valid-cross-family-approve', text(impostor));

  assert.equal(underOwner.ok, true, `the document that owns the identity must still pass: ${underOwner.why}`);
  assert.equal(underImpostor.ok, false, 'a policy claiming another policy\'s identity must be refused');
  assert.equal(underImpostor.guard, 'Q20_POLICY_IDENTITY',
    `refused by ${underImpostor.guard}, not the identity guard`);
});

test('F1: the collision is refused in BOTH directions — neither document is privileged', () => {
  // The mirror image: the DECLARED content wearing the RESIDUE policy's version. If only one
  // direction were caught, the guard would be an accident of which policy happens to be "the real
  // one" rather than a property of the identity.
  const impostor = { ...DECLARED, policy_version: RESIDUE.policy_version };
  const result = runCase('residue-declared', text(impostor));
  assert.equal(result.ok, false);
  assert.equal(result.guard, 'Q20_POLICY_IDENTITY');
});

test('F1: no two distinct policy documents can both verify one envelope', () => {
  // The finding's actual harm, stated as the property rather than as one reproduction: the same
  // signed record used to be PASS under one policy and INVALID under another, with both claiming
  // the identity the signature covered. Now at most ONE policy document can be applied to a given
  // envelope, because the envelope's signed policy_version determines the policy's content.
  const candidates = [
    ['declared (owns the version the envelope claims)', DECLARED],
    ['residue content, same version', { ...RESIDUE, policy_version: DECLARED.policy_version }],
    ['declared content, one field flipped, same version', { ...DECLARED, require_pr_binding: false }],
    ['declared content, verdict set widened, same version', { ...DECLARED, accepted_verdicts: ['APPROVE'] }],
  ];

  const accepted = candidates.filter(([, doc]) => runCase('valid-cross-family-approve', text(doc)).ok);
  assert.deepEqual(accepted.map(([label]) => label), ['declared (owns the version the envelope claims)'],
    'exactly one policy document may verify this envelope');
});

test('F1: the two fixtures the finding found byte-identical are now distinct files', () => {
  const positive = read('positive/valid-cross-family-approve.json', null);
  const adversarial = read('adversarial/residue-absent-under-requiring-policy.json', null);
  const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

  assert.notEqual(digest(positive), digest(adversarial),
    'a positive control and an adversarial case must not be the same bytes — the adversarial file was '
    + 'not reviewing the policy its name claims');
  assert.equal(digest(positive) === '22304f48ec1bc996c256d855dbdd3c3590c5f8343366d80194c75c63abf95678', false,
    'the collided digest the review recorded must no longer be produced');

  // And the reason they differ is the right one: each envelope claims its OWN policy's version.
  assert.equal(JSON.parse(positive).policy_version, DECLARED.policy_version);
  assert.equal(JSON.parse(adversarial).policy_version, RESIDUE.policy_version);
});

// ---------------------------------------------------------------------------------------------
// The identity itself.
// ---------------------------------------------------------------------------------------------

test('F1: every committed policy declares the identity its own content hashes to', () => {
  const policies = [...new Set(INDEX.cases.map((entry) => entry.policy))].filter(Boolean);
  assert.ok(policies.length >= 4, `non-vacuity: expected several policies in the manifest, found ${policies.length}`);

  // Two deliberate exceptions, named exactly so a future policy that accidentally fails to match
  // cannot hide among them:
  //
  //   - policy-identity-collision.json exists PRECISELY to be a document that does not own its
  //     identity. It is the Q20 fixture.
  //   - policy-unknown-field.json is the declared policy plus `allow_self_review`, so its content
  //     no longer hashes to the version it kept. DECLARED DOUBLE DEFENCE: it is refused by Q03
  //     (unknown governance switch) which runs first, and would ALSO be refused by Q20 if Q03 were
  //     removed. Neutering either guard alone therefore still reddens a named test, but they are
  //     not independent detectors for this fixture and this comment says so rather than letting
  //     the guard table imply it.
  const EXPECTED_IMPOSTORS = ['shared/policy-identity-collision.json', 'shared/policy-unknown-field.json'];
  const mismatched = policies.filter((rel) => {
    const doc = JSON.parse(read(rel));
    return declaredPolicyIdentity(doc.policy_version) !== policyIdentity(doc);
  });
  assert.deepEqual(mismatched, EXPECTED_IMPOSTORS);
});

test('F1: the four fixture policies have four distinct identities', () => {
  const versions = ['declared', 'observed', 'no-pr', 'residue']
    .map((name) => JSON.parse(read(`shared/policy-${name}.json`)).policy_version);
  assert.equal(new Set(versions).size, 4, `four materially different policies share a version: ${versions.join(', ')}`);
});

test('F1: flipping ANY policy field changes the identity — a per-field mutation matrix', () => {
  // The identity is only worth anything if it is sensitive to every governance switch. This walks
  // the actual key set rather than a hand-listed one, so a field added to quorum-policy/1 is
  // covered the day it is added.
  const mutations = {
    accepted_verdicts: ['APPROVE'],
    require_family_inequality: false,
    require_family_trust: 'observed',
    require_pr_binding: false,
    require_evidence: false,
    require_residue_declaration: true,
  };
  const governanceKeys = Object.keys(DECLARED).filter((key) => key !== 'schema' && key !== 'policy_version');
  assert.deepEqual(governanceKeys.sort(), Object.keys(mutations).sort(),
    'a policy field is not covered by this matrix — add it to `mutations`');

  const baseline = policyIdentity(DECLARED);
  for (const [key, value] of Object.entries(mutations)) {
    const mutated = { ...DECLARED, [key]: value };
    assert.notDeepEqual(mutated[key], DECLARED[key], `mutation of ${key} is not a change`);
    assert.notEqual(policyIdentity(mutated), baseline, `changing ${key} did not change the policy identity`);

    // And behaviourally: keeping the old version string on the mutated content is refused.
    const result = runCase('valid-cross-family-approve', text({ ...mutated, policy_version: DECLARED.policy_version }));
    assert.equal(result.ok, false, `a policy with ${key} changed kept the old identity and PASSED`);
    assert.equal(result.guard, 'Q20_POLICY_IDENTITY', `${key}: refused by ${result.guard}`);
  }
});

test('F1: identity is over CONTENT, not bytes — re-indenting and re-ordering a policy file does not change it', () => {
  // The counterpart of the mutation matrix, and the reason the digest is taken over canonical bytes
  // of the parsed document. Without this the guard would refuse a policy file someone pretty-printed
  // and would be deleted within a week.
  const reordered = Object.fromEntries(Object.entries(DECLARED).reverse());
  assert.notEqual(JSON.stringify(reordered), JSON.stringify(DECLARED), 'the re-order must change the bytes');
  assert.equal(policyIdentity(reordered), policyIdentity(DECLARED));

  const result = runCase('valid-cross-family-approve', JSON.stringify(reordered));
  assert.equal(result.ok, true, `a re-serialised policy must still verify: ${result.why}`);
});

test('F1: a policy carrying NO identity suffix is refused, not waved through', () => {
  // The fail-open this guard exists to close. A pre-identity policy binds no content, and treating
  // "no identity to check" as "nothing wrong" would reinstate the defect for every old file.
  const legacy = { ...DECLARED, policy_version: 'quorum-policy/1@2026-09-10' };
  assert.equal(declaredPolicyIdentity(legacy.policy_version), null);

  const result = runCase('valid-cross-family-approve', text(legacy));
  assert.equal(result.ok, false, 'an unsuffixed policy_version must be refused');
  // Q03 owns it: the shape no longer satisfies quorum-policy/1. Either refusal is fail-closed, and
  // asserting WHICH one keeps this test honest about the mechanism rather than about the outcome.
  assert.equal(result.guard, 'Q03_POLICY');

  // A suffix of the right SHAPE but the wrong value reaches Q20, which is the check that matters.
  const forged = { ...DECLARED, policy_version: `quorum-policy/1@2026-09-10+${'0'.repeat(32)}` };
  const forgedResult = runCase('valid-cross-family-approve', text(forged));
  assert.equal(forgedResult.ok, false);
  assert.equal(forgedResult.guard, 'Q20_POLICY_IDENTITY');
});

test('F1: stampPolicyVersion is the only way to author a version, and it is idempotent', () => {
  const stamped = stampPolicyVersion('quorum-policy/1@2026-09-10', { ...DECLARED, policy_version: null });
  assert.equal(stamped.policy_version, DECLARED.policy_version, 'stamping the committed content must reproduce its version');
  assert.deepEqual(Object.keys(stamped), Object.keys(DECLARED), 'stamping must preserve key order');
  assert.equal(stampPolicyVersion('quorum-policy/1@2026-09-10', stamped).policy_version, stamped.policy_version);
});

// ---------------------------------------------------------------------------------------------
// POSITIVE CONTROLS the finding explicitly requires preserved.
// ---------------------------------------------------------------------------------------------

test('F1 control: an EMPTY residue is still valid under the policy that requires a declaration', () => {
  const result = runCase('residue-declared-empty');
  assert.equal(result.ok, true, result.why);
  assert.equal(result.verdict, 'PASS');
  assert.equal(JSON.parse(read('shared/policy-residue.json')).require_residue_declaration, true);
  assert.deepEqual(
    JSON.parse(read('positive/residue-declared-empty.json')).review.residue,
    { undecided: [], refuted: [], unsettled_by_execution: [], reviewer_limits: [] },
  );
});

test('F1 control: an envelope under the OLD policy still verifies against that unmodified policy', () => {
  const result = runCase('valid-cross-family-approve');
  assert.equal(result.ok, true, result.why);
  assert.equal(result.verdict, 'PASS');
  assert.equal(JSON.parse(read('shared/policy-declared.json')).require_residue_declaration, false,
    'the old policy must be UNMODIFIED in substance — only its version string gained an identity');
});

test('F1 control: residue-absent is still refused by Q19, not absorbed by the new guard', () => {
  // The risk of adding a guard ahead of an existing one is that it starts owning refusals that were
  // someone else's. Q19 must still be the reason a reviewer who declared nothing is turned away.
  const result = runCase('residue-absent-under-requiring-policy');
  assert.equal(result.ok, false);
  assert.equal(result.guard, 'Q19_RESIDUE_DECLARATION', `refused by ${result.guard}, so Q19 is no longer reachable`);
});

test('F1 control: the new guard does not change any other verdict in the manifest', () => {
  // Blunt, and the point. Every committed case still behaves exactly as its manifest entry declares,
  // so the identity change re-bound the fixtures without re-pointing a single refusal.
  const wrong = INDEX.cases.filter((entry) => {
    const result = runCase(entry.name);
    return result.ok !== entry.expect.ok
      || (entry.expect.guard !== undefined && result.guard !== entry.expect.guard);
  });
  assert.deepEqual(wrong.map((entry) => entry.name), []);
  assert.ok(INDEX.cases.length >= 42, `non-vacuity: only ${INDEX.cases.length} cases in the manifest`);
});

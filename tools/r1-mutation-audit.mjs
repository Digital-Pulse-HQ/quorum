#!/usr/bin/env node
// Replays every selective mutation that has ever survived a review re-adjudication, plus the
// neighbouring decision inputs the same coverage rule demands.
//
//   ROUND 1, at 26f5b98f: eight mutations, each turning a real refusal into a real PASS (or, for
//   the last, a legitimate PASS into a false refusal), while the behavioural suite stayed 106/106
//   and the package suite 129/129.
//   ROUND 2, at aebacca3: seven SUB-CLAUSE mutations chosen independently by the reviewer -- one
//   party's arm, one digest source, one policy field, one call site -- each surviving a complete
//   154/154 run with zero skips. Transcribed verbatim below and marked with their reviewer id.
//   ROUNDS 3-4, at b5169dbe and b829c8aa: the axes below, plus AXIS W -- this tool's own three
//   production calls, which round 4 found could each be disconnected with every function it calls
//   still perfect and the suite green.
//   ROUND 5, at c2a2e717: eight more, in two groups. Axes D and E applied to the inputs and guards
//   round 4 did not reach, and the four protections inside THIS FILE'S LOOP -- the red-baseline
//   refusal, the harness-failure exclusion, the exactly-once find assertion, and the restore.
//
// This script asserts that each is now CAUGHT, and names the test that reddens. Round 1 was fixed
// by adding a test per survivor and the class stayed open, so the round-2 entries are paired with
// neighbour mutations covering the rest of each guard's decision inputs; the rule those neighbours
// come from is in the header of test/r1-decision-inputs.test.mjs.
//
// Usage: node quorum/tools/r1-mutation-audit.mjs [--suite <file>]
//                                                [--root <dir>] [--mutations <file.json>]
//
// `--root` and `--mutations` exist ONLY so the CLI can be exercised end-to-end against a temp
// tree; see the note beside their definitions. CI passes neither.
//
// Every mutation is restored in a finally block, and `test/audit-orchestration.test.mjs`
// asserts that -- on real bytes -- because "restored" is what makes a self-mutating matrix safe.

import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const QUORUM = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const VERIFY = 'src/verify.mjs';
// Round 12 added the first rows that mutate the schema EVALUATOR rather than the
// verifier that delegates to it. Q02, Q03 and Q04 are thin wrappers around `validate`, so a
// constraint deleted in here is a guard weakened without the guard itself being touched.
const SCHEMA = 'src/schema.mjs';
// This tool is itself a mutation target from round 4 on. Mutating the file that is currently
// executing is safe in the one direction that matters: the module is already resident, so the
// running audit keeps its own semantics while the SUBPROCESS it spawns imports the mutated copy --
// which is exactly the thing under test. Restored by the same finally block as every other row.
const AUDIT = 'tools/r1-mutation-audit.mjs';

// Each `find` must occur exactly once, so a mutation can never silently apply to nothing -- the
// failure mode that let two of the original eight report 128/129 for harness reasons alone.
export const MUTATIONS = [
  { id: 'R1-M1', expect: 'R1/Q14: the REVIEWER alone cannot claim observed trust on a declared enrolment', what: 'Q14 trust ceiling: drop the REVIEWER row', file: VERIFY,
    find: "    ['reviewer', envelope.reviewer, reviewerKey.key],\n", replace: '' },
  { id: 'R1-M2', expect: 'R1/Q14: the PRODUCER alone cannot claim observed trust on a declared enrolment', what: 'Q14 trust ceiling: drop the PRODUCER row', file: VERIFY,
    find: "    ['producer', envelope.producer, producerKey.key],\n", replace: '' },
  { id: 'R1-M3', expect: 'R1/Q15: an observed policy refuses a DECLARED producer while the reviewer is observed', what: 'Q15 trust floor: drop the PRODUCER row', file: VERIFY,
    find: "    ['producer', envelope.producer.family_trust],\n", replace: '' },
  { id: 'R1-M4', expect: 'R1/Q15: an observed policy refuses a DECLARED reviewer while the producer is observed', what: 'Q15 trust floor: drop the REVIEWER row', file: VERIFY,
    find: "    ['reviewer', envelope.reviewer.family_trust],\n", replace: '' },
  { id: 'R1-M5', expect: 'R1/Q11: a REVIEWER key enrolled for another family cannot sign as this one', what: 'enrolment: drop the family comparison', file: VERIFY,
    find: '  if (key.family !== party.family) {', replace: '  if (false) {' },
  { id: 'R1-M6', expect: 'R1/Q09: a reviewer-only key cannot occupy the PRODUCER seat', what: 'enrolment: drop the role check', file: VERIFY,
    find: '  if (!key.roles.includes(role))', replace: '  if (false)' },
  { id: 'R1-M7', expect: 'R1/Q09: a PRODUCER principal that differs from its enrolment is refused', what: 'enrolment: drop the principal comparison', file: VERIFY,
    find: '  if (key.principal !== party.principal) {', replace: '  if (false) {' },
  { id: 'R1-M8', expect: 'R1/Q08: a caller digest contradicting correct artifact bytes is refused', what: 'Q08: accept if ANY supplied digest agrees, not every', file: VERIFY,
    find: 'artifactSources.every((value) => value === envelope.artifact.digest)',
    replace: 'artifactSources.some((value) => value === envelope.artifact.digest)' },
  { id: 'R1-M9', expect: 'R1/Q18: a policy that does not require evidence accepts an absent evidence document', what: 'Q18: remove the permissive evidence-policy exclusion', file: VERIFY,
    find: '  if (policy.require_evidence) {', replace: '  if (true) {' },

  // R2: the locator. Both of these left the complete suite green before the R2 tests existed.
  { id: 'R2-M1', expect: 'R2: the locator matches a digest computed independently of the implementation', what: 'locator: return a constant digest', file: 'src/render.mjs',
    find: "  return `sha256:${createHash('sha256').update(canonicalize(envelope), 'utf8').digest('hex')}`;",
    replace: "  return `sha256:${'0'.repeat(64)}`;" },
  { id: 'R2-M2', expect: 'R2: the locator matches a digest computed independently of the implementation', what: 'locator: hash insertion-ordered JSON again, not the canonical form', file: 'src/render.mjs',
    find: "update(canonicalize(envelope), 'utf8')",
    replace: "update(JSON.stringify(envelope, null, 2), 'utf8')" },

  // R3: the runner must be shipped, and must actually run when invoked by its installed bin name.
  // DECLARED DOUBLE DEFENCE, measured rather than assumed. npm always packs the files named in
  // `bin` regardless of the `files` allow-list, so with `quorum-required-check` in `bin` the `"ci"`
  // entry is redundant and its deletion CANNOT redden anything. Verified directly: removing `"ci"`,
  // running `npm pack` and listing the tarball still yields `package/ci/required-check.mjs`.
  // Both are kept -- `files` is the explicit, documented mechanism and should not depend on a
  // subtlety of npm's implicit inclusion -- and the redundancy is declared here so a reviewer's
  // matrix reporting SURVIVED reads as intended rather than as an unprotected boundary.
  { id: 'R3-M1', what: 'packaging: stop shipping ci/ in the npm files allow-list', file: 'package.json',
    find: '    "ci",\n', replace: '', redundantWith: 'the bin entry, which npm always packs (measured)' },
  { id: 'R3-M2', expect: 'CLEAN PROJECT: the packed package installs and verifies in a directory with none of this repository\'s layout', what: 'runner: restore the filename guard that made the installed gate a no-op', file: 'ci/required-check.mjs',
    find: "    && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {",
    replace: "    && process.argv[1].endsWith('required-check.mjs')) {" },

  // ---------------------------------------------------------------------------------------------
  // ROUND 2. Everything above deletes a whole clause. The round-2 re-adjudication chose SUB-CLAUSE
  // mutations instead -- disable one party's arm, one source, one policy field, one call site --
  // and seven of them survived a complete 154/154 run. The seven marked `r2` below are those
  // mutations verbatim, transcribed from the reviewer's matrix rather than restated; the rest are
  // the neighbours the same rule demands, one per remaining decision input. See the header of
  // test/r1-decision-inputs.test.mjs for the rule and why instance-by-instance fixes kept
  // failing to close it.
  //
  // AXIS A -- policy-conditioned branches: both answers, each reached by an input the other setting
  // decides differently.
  { id: 'R1-A1', expect: 'R1/Q13: a genuinely signed verdict outside THIS policy\'s accepted set is refused', r2: 'I06-policy-verdict', what: 'Q13: hard-code the verdict set instead of reading the policy', file: VERIFY,
    find: '!policy.accepted_verdicts.includes(envelope.review.verdict)',
    replace: "!['APPROVE', 'CHANGES_REQUIRED', 'REJECT'].includes(envelope.review.verdict)" },
  { id: 'R1-A2', expect: 'R1/Q13 positive control: a non-APPROVE verdict INSIDE the accepted set passes', what: 'Q13: accept only APPROVE, whatever the policy admits', file: VERIFY,
    find: '!policy.accepted_verdicts.includes(envelope.review.verdict)',
    replace: "envelope.review.verdict !== 'APPROVE'" },
  { id: 'R1-A3', expect: 'R1/Q16 positive control: require_family_inequality:false accepts two DISTINCT same-family keys', r2: 'I03-family-exclusion', what: 'Q16: refuse same-family even where the policy permits it', file: VERIFY,
    find: 'policy.require_family_inequality && envelope.producer.family === envelope.reviewer.family',
    replace: 'envelope.producer.family === envelope.reviewer.family' },
  { id: 'R1-A4', expect: 'R1/Q17: require_pr_binding:false still refuses a PR that contradicts the commissioned one', r2: 'I04-optional-pr', what: 'Q17: make the permissive PR arm accept unconditionally', file: VERIFY,
    find: ': prExpected === null || envelope.review.pr === prExpected;', replace: ': true;' },
  { id: 'R1-A5', expect: 'R1/Q17 positive control: require_pr_binding:false accepts a signed PR the caller did not commission', what: 'Q17: make the permissive PR arm demand a PR the caller never commissioned', file: VERIFY,
    find: ': prExpected === null || envelope.review.pr === prExpected;', replace: ': envelope.review.pr === prExpected;' },

  // AXIS B -- Q08 combines two independent digest sources. Presence and agreement are separate
  // facts, so the coverage unit is the combination, not one example of each source.
  { id: 'R1-B1', expect: 'R1/Q08: a correct caller digest does not excuse WRONG artifact bytes', r2: 'I13b-q08-ignore-bytes', what: 'Q08: ignore the recomputed digest whenever a caller digest exists', file: VERIFY,
    find: '[recomputed, expected.artifactDigest]',
    replace: '[...(expected.artifactDigest ? [] : [recomputed]), expected.artifactDigest]' },
  { id: 'R1-B2', expect: 'R1/Q08 positive control: a caller digest ALONE, with no artifact bytes, is sufficient', r2: 'I07-digest-only', what: 'Q08: drop the caller digest whenever artifact bytes are absent', file: VERIFY,
    find: '[recomputed, expected.artifactDigest]',
    replace: '[recomputed, recomputed === null ? undefined : expected.artifactDigest]' },
  { id: 'R1-B3', expect: 'R1/Q08: a caller digest alone that CONTRADICTS the envelope is refused', what: 'Q08: stop comparing at all when there are no artifact bytes', file: VERIFY,
    find: 'artifactSources.every((value) => value === envelope.artifact.digest)',
    replace: 'artifactSources.every((value) => recomputed === null || value === envelope.artifact.digest)' },
  { id: 'R1-B4', expect: 'R1/Q08: neither artifact bytes NOR a caller digest is a refusal, never a skip', what: 'Q08: treat "no source at all" as agreement rather than as a refusal', file: VERIFY,
    find: 'const digestOk = artifactSources.length > 0 && artifactSources.every',
    replace: 'const digestOk = artifactSources.every' },

  // AXIS C -- repeated call sites. `signatureValid` runs once per party and the store integrity
  // checks run once per enrolled key, including keys the envelope never names. One occurrence can
  // be neutered while the other keeps refusing the only fixture anybody wrote.
  { id: 'R1-C1', expect: 'R1/Q10: a non-canonical base64 PRODUCER signature is refused even when the reviewer countersigns it', r2: 'I05b-producer-base64', what: 'Q10: re-encode the PRODUCER signature before comparing it', file: VERIFY,
    find: "  const bytes = Buffer.from(signature.value, 'base64');",
    replace: "  const bytes = Buffer.from(signature.value, 'base64');\n  if (!Object.hasOwn(payload, 'review')) signature = { ...signature, value: bytes.toString('base64') };" },
  { id: 'R1-C2', expect: 'R1/Q12: a non-canonical base64 REVIEWER signature is refused', what: 'Q12: re-encode the REVIEWER signature before comparing it', file: VERIFY,
    find: "  const bytes = Buffer.from(signature.value, 'base64');",
    replace: "  const bytes = Buffer.from(signature.value, 'base64');\n  if (Object.hasOwn(payload, 'review')) signature = { ...signature, value: bytes.toString('base64') };" },
  { id: 'R1-C3', expect: 'R1/Q04: an UNUSED enrolled key that is not Ed25519 refuses the whole trust store', r2: 'I02-key-type', what: 'Q04: disable the Ed25519 key-type refusal', file: VERIFY,
    find: "    if (publicKey.asymmetricKeyType !== 'ed25519') {", replace: '    if (false) {' },
  { id: 'R1-C4', expect: 'R1/Q04: an UNUSED duplicate key_id refuses the whole trust store', what: 'Q04: check only the first two enrolments, never the rest of the store', file: VERIFY,
    find: '  for (const key of trust.keys) {', replace: '  for (const key of trust.keys.slice(0, 2)) {' },

  // ---------------------------------------------------------------------------------------------
  // ROUND 3, at b5169dbe. The seven round-2 entries above were each killed by a named test, so the
  // re-adjudication went one level finer and found four more, each surviving a complete 169/169 run
  // with zero skips. The rule is unchanged; what changed is what counts as ONE decision input.
  // Q17's requiring arm and Q04's per-key loop are CONJUNCTIONS -- presence AND equality, readable
  // AND Ed25519 -- and every entry above varies only the second conjunct, so the first could be
  // deleted with the same tests still refusing the same things. The two permissive-arm entries are
  // the mirror: the suite reached `require_pr_binding:false` and `require_evidence:false` only
  // through the input that makes the exclusion trivially true, never through the exclusion itself.
  { id: 'R1-A6', expect: 'R1/Q17: require_pr_binding:true refuses an ABSENT PR even when the caller commissioned none', r3: 'N02-required-pr-null', what: 'Q17: let the requiring arm accept a null PR that equals a null expectation', file: VERIFY,
    find: 'envelope.review.pr !== null && envelope.review.pr === prExpected',
    replace: 'envelope.review.pr === prExpected' },
  { id: 'R1-A7', expect: 'R1/Q17 positive control: require_pr_binding:false accepts a signed PR that MATCHES the commissioned one', r3: 'N04-optional-pr-matching', what: 'Q17: drop agreement from the permissive arm, leaving only "nothing commissioned"', file: VERIFY,
    find: ': prExpected === null || envelope.review.pr === prExpected;', replace: ': prExpected === null;' },
  { id: 'R1-A8', expect: 'R1/Q18 positive control: require_evidence:false ignores evidence bytes that CONTRADICT the envelope', r3: 'N03-optional-evidence-present', what: 'Q18: compare evidence whenever bytes are supplied, policy notwithstanding', file: VERIFY,
    find: '  if (policy.require_evidence) {', replace: '  if (policy.require_evidence || evidenceBytes !== null) {' },
  { id: 'R1-C5', expect: 'R1/Q04: an UNUSED enrolled key whose PEM cannot be PARSED refuses the whole trust store', r3: 'N01-unreadable-unused-key', what: 'Q04: skip enrolments that cannot be parsed instead of refusing the store', file: VERIFY,
    find: 'return { error: `key ${key.key_id} has an unreadable public key: ${error.message}` };',
    replace: 'continue;' },

  // ---------------------------------------------------------------------------------------------
  // ROUND 4, at b829c8aa. Two more verifier inputs, on axes the rounds above had not named, plus
  // the first three entries that mutate THIS FILE. See the ROUND 4 headers in
  // test/r1-decision-inputs.test.mjs and test/r1-audit-attribution.test.mjs.
  //
  // AXIS D -- an ABSENT property is not an explicitly-null one. `expected.pr` is optional by
  // contract and the optionality is entirely `?? null`; every case above passes it explicitly.
  { id: 'R1-D1', expect: 'R1/Q17 positive control: require_pr_binding:false accepts a call that OMITS the commissioned PR', r4: 'N05-optional-pr-omitted-default', what: 'Q17: drop the optional-PR default, so an omitted expectation is undefined', file: VERIFY,
    find: 'const prExpected = expected.pr ?? null;', replace: 'const prExpected = expected.pr;' },

  // AXIS E -- the refusal's own machine-readable fields, not just which guard refused. Q18
  // distinguishes "nothing was supplied" (UNKNOWN/not_compared) from "compared and rejected"
  // (INVALID/compared_rejected); SPEC.md treats them as different findings. Both directions, so
  // the condition can be neither hard-coded true nor hard-coded false.
  { id: 'R1-E1', expect: 'R1/Q18: an ABSENT evidence document is UNKNOWN/not_compared, never compared_rejected', r4: 'I04-absent-evidence-classification', what: 'Q18: report an absent document as one that was compared and rejected', file: VERIFY,
    find: "return fail('Q18_EVIDENCE_BINDING', evidenceWhy, evidenceBytes !== null);",
    replace: "return fail('Q18_EVIDENCE_BINDING', evidenceWhy, true);" },
  { id: 'R1-E2', expect: 'R1/Q18: a SUPPLIED evidence document that contradicts the envelope is INVALID/compared_rejected', what: 'Q18: report a compared, rejected document as one that was never supplied', file: VERIFY,
    find: "return fail('Q18_EVIDENCE_BINDING', evidenceWhy, evidenceBytes !== null);",
    replace: "return fail('Q18_EVIDENCE_BINDING', evidenceWhy, false);" },

  // AXIS W -- THIS TOOL'S OWN WIRING. Round 3 extracted `classifyMutation` and `auditExitCode` so
  // they could be asserted, and round 4 found that testing them is not the same as testing the
  // audit: each production CALL can be disconnected on its own, leaving both functions perfect,
  // the whole suite green, and this program reporting success having measured nothing. An
  // instrument that cannot be pointed at itself is the one place a survivor is invisible by
  // construction, so the three sit in the matrix rather than only in the test file.
  // THE CONCATENATIONS BELOW ARE LOAD-BEARING — DO NOT JOIN THEM INTO ONE LITERAL. A row that
  // mutates THIS file would otherwise contain its own target verbatim, so `find` matches twice --
  // once at the real call site and once in the row describing it -- and the exact-once assertion
  // correctly refuses to measure anything. Measured: both of these reported `INVALID (find matched
  // 2x)` on both Node majors when first written as single literals. Splitting the string keeps the
  // file free of the full target while the call site still carries it. (`R1-W3` needs no split: its
  // target spans two real lines, and the row encodes that newline as an escape.)
  { id: 'R1-W1', expect: "R1 audit CLI: the matrix's expected test name reaches the classifier", r4: 'I01-classifier-call-drops-expect', what: 'audit: stop passing `expect` at the real classifier call, so anything counts as a catch', file: AUDIT,
    find: 'classifyMutation({ passed, behavioural, expect: m.expect,' + ' redundantWith: m.redundantWith, measured: suiteRan(out) })',
    replace: 'classifyMutation({ passed, behavioural, redundantWith: m.redundantWith, measured: suiteRan(out) })' },
  { id: 'R1-W2', expect: 'R1 audit CLI: a MISATTRIBUTED run makes the PROCESS exit non-zero', r4: 'I02-main-discards-exit-code', what: 'audit: discard the exit decision in main, reporting every run as clean', file: AUDIT,
    find: 'return auditExitCode' + '(results);', replace: 'return 0;' },
  { id: 'R1-W3', expect: 'R1 audit CLI: invoking the audit directly actually RUNS it', r4: 'I03-entry-guard-disabled', what: 'audit: disable the direct-invocation guard, making the program a silent no-op', file: AUDIT,
    find: "if (process.argv[1] !== undefined\n    && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {",
    replace: 'if (false) {' },

  // ---------------------------------------------------------------------------------------------
  // ROUND 5, at c2a2e717. Eight survivors of a complete 186/186 run, transcribed from
  // the reviewer's matrix. Two shapes, and both are the same mistake:
  //
  //   J01-J03  AXES D AND E, APPLIED WHERE ROUND 4 DID NOT. Round 4 wrote axis D for `expected.pr`
  //            and axis E for Q18 and stopped at the instance that suggested each. `artifactBytes`
  //            and `evidenceBytes` use the same defaulting idiom; Q08 classifies with the same
  //            condition shape as Q18. An axis is not discharged by the instance that suggested it.
  //   J04-J08  AXIS W, ONE LEVEL DEEPER. Round 4 covered this tool's three production CALLS; round
  //            5 found the four protections inside its LOOP, plus the newest reviewer-display arm.
  //
  // J01 and J02 are worth reading twice: deleting a parameter default does not loosen a check, it
  // makes a documented call THROW. A verifier that throws has no verdict, no guard and no record.
  //
  // The AUDIT rows below keep the split-literal discipline described above AXIS W.
  { id: 'R1-D2', expect: 'R1/Q18 positive control: an OMITTED evidence document is the same supported call as an explicit null', r5: 'J01-evidence-default-deleted', what: 'Q18: delete the evidenceBytes default, so an omitted document throws instead of refusing', file: VERIFY,
    find: '  evidenceBytes = null,\n', replace: '  evidenceBytes,\n' },
  { id: 'R1-D3', expect: 'R1/Q08 positive control: OMITTED artifact bytes are the same supported call as an explicit null', r5: 'J02-artifact-default-deleted', what: 'Q08: delete the artifactBytes default, so a digest-only call throws instead of passing', file: VERIFY,
    find: '  artifactBytes = null,\n', replace: '  artifactBytes,\n' },
  { id: 'R1-E3', expect: 'R1/Q08: a SUPPLIED source that contradicts the envelope is INVALID/compared_rejected', r5: 'J03-q08-erases-comparison', what: 'Q08: report a compared, rejected artifact as one that was never compared', file: VERIFY,
    find: "return fail('Q08_ARTIFACT_DIGEST', `artifact digest not established: ${detail}`, artifactSources.length > 0);",
    replace: "return fail('Q08_ARTIFACT_DIGEST', `artifact digest not established: ${detail}`, false);" },
  { id: 'R1-W4', expect: 'R1 audit/J04: a RED baseline refuses, exits 1, and audits nothing', r5: 'J04-red-baseline-ignored', what: 'audit: audit on a RED baseline, crediting every already-failing test as a catch', file: AUDIT,
    find: 'if (!baseline' + '.passed) {', replace: 'if (false) {' },
  { id: 'R1-W5', expect: 'R1 audit/J05: a mutation reddening only HARNESS tests SURVIVED, and exits 1', r5: 'J05-harness-exclusion-dropped', what: 'audit: count harness-only failures as behavioural detection', file: AUDIT,
    find: 'const behavioural = named.filter((n) => !HARNESS_TESTS' + '.test(n));', replace: 'const behavioural = named;' },
  { id: 'R1-W6', expect: 'R1 audit/J06: a find matching TWICE is INVALID, exits 1, and never edits the file', r5: 'J06-exactly-once-dropped', what: 'audit: apply an ambiguous find to its first match instead of refusing the row', file: AUDIT,
    find: 'if (occurrences !==' + ' 1) {', replace: 'if (false) {' },
  { id: 'R1-W7', expect: 'R1 audit/J07: the mutated target is restored byte-for-byte after the run', r5: 'J07-restore-removed', what: 'audit: leave every mutated target on disk, corrupting the tree it measures', file: AUDIT,
    find: '    write(path, ' + 'original);\n', replace: '' },
  { id: 'R1-W8', expect: 'R1 audit/J08: EVERY round tag displays its reviewer, not just the oldest two', r5: 'J08-r4-display-arm-dropped', what: 'audit: drop a round tag, silently losing which reviewer chose those rows', file: AUDIT,
    find: "export const ROUND_TAGS = ['r2', 'r3', " + "'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r12'];", replace: "export const ROUND_TAGS = ['r2', 'r3', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r12'];" },

  // ---------------------------------------------------------------------------------------------
  // ROUND 6, at f1460f1f. Four survivors of a complete 205/205 run. Every one is the
  // SAME shape the five rounds before it were: a decision pinned at one of its inputs.
  //   K04  Q08's classification tested through artifact BYTES only, never the caller-only source.
  //   K15  the exclusion tested with an INVENTED harness name that matched a different alternative
  //        of the regex than the real harness test does.
  //   K08  exactly-once tested at two matches and one, never at ZERO.
  //   K16  every case audited zero rows or one, so "all of them" was never asserted.
  // Plus R1-W12, which no reviewer raised: found while fixing K16.
  { id: 'R1-E4', expect: 'R1/Q08: a contradictory CALLER DIGEST ALONE is INVALID/compared_rejected', r6: 'K04-q08-caller-only-attribution', what: 'Q08: classify a caller-only comparison as never performed', file: VERIFY,
    find: "return fail('Q08_ARTIFACT_DIGEST', `artifact digest not established: ${detail}`, artifactSources.length > 0);",
    replace: "return fail('Q08_ARTIFACT_DIGEST', `artifact digest not established: ${detail}`, recomputed !== null);" },
  { id: 'R1-W9', expect: 'R1 audit/J05: EVERY exclusion alternative is independently necessary', r6: 'K15-harness-regex-narrowed', what: 'audit: narrow the harness exclusion past the name the real harness test uses', file: AUDIT,
    find: 'export const HARNESS_TESTS = /MUTATION TEST|mutation-target|' + 'machinery mutation reddens/i;',
    replace: 'export const HARNESS_TESTS = /mutation-target/i;' },
  { id: 'R1-W10', expect: 'R1 audit/K08: a find matching ZERO times is INVALID, exits 1, and changes nothing', r6: 'K08-zero-match-refusal-deleted', what: 'audit: accept a row whose search target has VANISHED as if it applied', file: AUDIT,
    find: 'if (occurrences !==' + ' 1) {', replace: 'if (occurrences > 1) {' },
  { id: 'R1-W11', expect: 'R1 audit/K16: EVERY row runs — a later survivor is reported, through the real CLI', r6: 'K16-loop-truncated', what: 'audit: audit only the first row, hiding every later survivor', file: AUDIT,
    find: 'for (const m of ' + 'mutations) {', replace: 'for (const m of mutations.slice(0, 1)) {' },
  // NOT from a reviewer. Found while remediating K16: inheriting NODE_TEST_CONTEXT makes every
  // spawned suite emit no TAP, so every row parses as a survivor and the audit's verdict is
  // fiction. The round-5 CLI test asserted SURVIVED and exit 1 -- exactly what that produces --
  // so it passed for the wrong reason. Disclosed rather than quietly fixed.
  { id: 'R1-W12', expect: 'R1 audit CLI: the real binary applies, restores, and exits 1 on a survivor', what: 'audit: inherit NODE_TEST_CONTEXT, destroying TAP so every row is a false survivor', file: AUDIT,
    find: '  delete env.NODE_TEST_CONTEXT;\n', replace: '' },

  // ---------------------------------------------------------------------------------------------
  // ROUND 7, at 3fe4b931. Two MEDIUM and two LOW, all four of them about whether a
  // measurement means what it says rather than about a guard being removable:
  //   L01  an UNMEASURABLE suite classified as a measured redundancy.
  //   L02  a required row deletable while count-based protection stays green.
  //   L03  a prose assertion satisfied by a token, without the identity it claims to compare.
  { id: 'R1-W13', expect: 'R1 audit/L01: a suite that could not RUN is UNMEASURED, never REDUNDANT', r7: 'L01-unmeasured-as-redundant', what: 'audit: treat a suite that never executed as a measured result', file: AUDIT,
    find: 'export const suiteRan = (tap) => loadFailures(tap).length === 0' + ' && /^# pass \\d+/m.test(tap);', replace: 'export const suiteRan = () => true;' },
  { id: 'R1-W14', expect: 'R1 audit/L01: an UNMEASURED row is not excused by a declared redundancy', r7: 'L01-unmeasured-ordering', what: 'audit: check the redundancy excuse BEFORE the measured check', file: AUDIT,
    find: "  if (!measured) return 'UNMEASURED';\n", replace: '' },
  { id: 'R1-W15', expect: 'R1 audit: every REQUIRED measurement is present in the shipped matrix, by identity', r7: 'L02-required-row-deletable', what: 'audit: drop the NODE_TEST_CONTEXT measurement from the shipped matrix', file: AUDIT,
    find: "  { id: 'R1-W12'," + " expect: 'R1 audit CLI: the real binary applies", replace: "  { id: 'R1-W12-RENAMED', expect: 'R1 audit CLI: the real binary applies" },
  { id: 'R1-E5', expect: 'R1/Q08: a contradictory CALLER DIGEST ALONE is INVALID/compared_rejected', r7: 'L03-prose-without-identity', what: "Q08: recite the envelope's own digest twice instead of the independent source", file: VERIFY,
    find: "artifactSources.join(' and ')", replace: "[envelope.artifact.digest].join(' and ')" },

  // ---------------------------------------------------------------------------------------------
  // ROUND 8, at 8e2fbf9d. Round 7's discriminator was WRONG, not merely undertested:
  // a real load failure emits `# pass 0` (or `# pass 1` with any unrelated file passing), so the
  // marker it keyed on survives a suite that never ran the test in question.
  //   D12  the file-level failure ignored again -- the one signal that the measurement is void.
  //   D13  the unmeasured refusal weakened to fire only when NOTHING else failed.
  { id: 'R1-W16', expect: 'R1 audit/D12: a real test-file LOAD FAILURE is UNMEASURED even with a pass marker', r8: 'D12-load-failure-ignored', what: 'audit: ignore file-level load failures, so a suite that never ran reads as measured', file: AUDIT,
    find: 'export const suiteRan = (tap) => loadFailures(tap).length === 0 &&' + ' /^# pass \\d+/m.test(tap);',
    replace: 'export const suiteRan = (tap) => /^# pass \\d+/m.test(tap);' },
  { id: 'R1-W17', expect: 'R1 audit/D13: an UNMEASURED suite is refused even when a behavioural name IS present', r8: 'D13-unmeasured-guard-weakened', what: 'audit: fire the unmeasured refusal only when no other failure is named', file: AUDIT,
    find: "  if (!measured)" + " return 'UNMEASURED';\n", replace: "  if (!measured && behavioural.length === 0) return 'UNMEASURED';\n" },

  // ---------------------------------------------------------------------------------------------
  // ROUND 9, at cc7f4f72. The round-8 detector is CORRECT -- the reviewer confirms the
  // unmodified audit refuses real load failures and interrupted output. These are the regression
  // protections around it, and both existed because the round-8 stimuli were HAND-BUILT:
  //   R9-A  the real runner emits a RELATIVE file name; the fixtures used an absolute one, so
  //         narrowing the detector to absolute paths left the suite green.
  //   R9-N  the round-8 truncated stream carried a load failure TOO, which keeps `suiteRan` false
  //         on its own, so the SUMMARY arm was never isolated.
  // R9-A's stimulus is generated by running the real runner (`captureLoadFailureTap`). R9-N's is a
  // SYNTHETIC truncated stream, and deliberately so -- an interrupted run with no summary is the
  // one shape that cannot be captured by letting a runner finish. Round 10 (F2) caught
  // the previous version of this comment calling both of them captured.
  { id: 'R1-W18', expect: 'R1 audit/D12: a real test-file LOAD FAILURE is UNMEASURED even with a pass marker', r9: 'R9-A-relative-path-unrecognised', what: 'audit: recognise only ABSOLUTE test paths, missing the relative names the runner emits', file: AUDIT,
    find: "  .filter((name) => /\\.test\\.mjs$/" + ".test(name));\n\nexport const suiteRan",
    replace: "  .filter((name) => name.startsWith('/') && /\\.test\\.mjs$/.test(name));\n\nexport const suiteRan" },
  { id: 'R1-W19', expect: 'R1 audit/D13: an UNMEASURED suite is refused even when a behavioural name IS present', r9: 'R9-N-summary-requirement-dropped', what: 'audit: accept an interrupted stream as measured whenever it named a failure', file: AUDIT,
    find: "export const suiteRan = (tap) => loadFailures(tap).length === 0 &&" + " /^# pass \\d+/m.test(tap);",
    replace: "export const suiteRan = (tap) => loadFailures(tap).length === 0 && (/^# pass \\d+/m.test(tap) || failingNames(tap).length > 0);" },

  // ROUND 10, at 10d69ab4. The COMBINATION the previous two rounds' cases left open: a
  // COMPLETED stream carrying a load failure AND a named behavioural failure. R9-A/R9-N could each
  // be satisfied without it, so the load-failure refusal could be bypassed exactly when something
  // else had failed by name. Its stimulus is generated from a real two-file run.
  { id: 'R1-W20', expect: 'R1 audit/R10-C: a named behavioural failure does NOT excuse a simultaneous load failure', r10: 'R10-C-load-refusal-bypassed-by-name', what: 'audit: excuse a load failure whenever some other failure was named', file: AUDIT,
    find: "export const suiteRan = (tap) => loadFailures(tap).length" + " === 0 && /^# pass \\d+/m.test(tap);",
    replace: "export const suiteRan = (tap) => (loadFailures(tap).length === 0 || failingNames(tap).length > 0) && /^# pass \\d+/m.test(tap);" },

  // ---------------------------------------------------------------------------------------------
  // ROUND 12, at 0f961337. Every round above audited `src/verify.mjs`. Round 12 pointed
  // the same instrument at `src/schema.mjs` — the evaluator Q02, Q03 and Q04 DELEGATE to — and each
  // of these six left the complete 221/221 suite green while turning a genuinely signed, genuinely
  // refused envelope into a PASS. The whole-Q02 deletion was caught by name; deleting one real
  // constraint WITHIN Q02 was not, because the evaluator's tests proved it refuses an unsupported
  // KEYWORD and an unknown PROPERTY, never that a supported constraint executes.
  //
  // AXIS S -- the delegated constraint. A guard that delegates is covered when each constraint it
  // delegates changes the outcome on its own.
  { id: 'R1-S1', expect: 'R1 schema/const: a genuinely signed artifact kind other than git_commit is refused', r12: 'S-const', what: 'schema: disable the constant predicate, freeing every `const` in every shipped schema', file: SCHEMA,
    find: "  if (Object.hasOwn(schema, 'const') && JSON.stringify(value) !== JSON.stringify(schema.const)) {",
    replace: '  if (false) {' },
  { id: 'R1-S2', expect: 'R1 schema/enum: an UNSUPPORTED family_trust level is refused, not ranked as unknown', r12: 'S-enum', what: 'schema: disable the enum predicate, opening every closed set to an invented member', file: SCHEMA,
    find: "  if (Object.hasOwn(schema, 'enum') && !schema.enum.some((option) => JSON.stringify(option) === JSON.stringify(value))) {",
    replace: '  if (false) {' },
  { id: 'R1-S3', expect: 'R1 schema/pattern: a producer family outside the declared shape is refused', r12: 'S-pattern', what: 'schema: disable the pattern predicate, unshaping every identity and version string', file: SCHEMA,
    find: "  if (Object.hasOwn(schema, 'pattern') && typeof value === 'string' && !new RegExp(schema.pattern).test(value)) {",
    replace: '  if (false) {' },
  { id: 'R1-S4', expect: 'R1 schema/minimum: a signed review.pr of 0 is refused even when the caller commissioned 0', r12: 'S-minimum', what: 'schema: disable the numeric minimum, dropping the floor under the PR binding', file: SCHEMA,
    find: "  if (Object.hasOwn(schema, 'minimum') && typeof value === 'number' && value < schema.minimum) {",
    replace: '  if (false) {' },
  { id: 'R1-S5', expect: 'R1 schema/uniqueItems: a policy whose accepted verdict set REPEATS a token is refused', r12: 'S-uniqueItems', what: 'schema: disable array uniqueness, letting a governance set repeat itself', file: SCHEMA,
    find: '    if (schema.uniqueItems === true) {', replace: '    if (false) {' },
  { id: 'R1-S6', expect: 'R1 schema/minItems: an EMPTY accepted verdict set is a malformed policy, never a verdict refusal', r12: 'S-minItems', what: 'schema: disable the array minimum length, making an empty policy well-formed', file: SCHEMA,
    find: "    if (Object.hasOwn(schema, 'minItems') && value.length < schema.minItems) {",
    replace: '    if (false) {' },

  // AXIS S, at the CALL SITE rather than in the evaluator. Round 12's sixth witness ran every
  // predicate — on a value the record does not contain. A constraint is only worth what the value
  // handed to it is worth, so the laundering shape needs its own row.
  { id: 'R1-S7', expect: 'R1 schema/const: a producer signature DECLARING a non-Ed25519 algorithm is refused', r12: 'S-producer-algorithm', what: 'Q02: normalise the producer signature algorithm on the way INTO validation', file: VERIFY,
    find: '  const envelopeShape = validate(ENVELOPE_JSON_SCHEMA, envelope);',
    replace: "  const envelopeShape = validate(ENVELOPE_JSON_SCHEMA, { ...envelope, signatures: { ...envelope.signatures, producer: { ...envelope.signatures.producer, algorithm: 'ed25519' } } });" },

  // AXIS D -- an absent property is not an explicitly-null one -- applied to the last parameter of
  // `verifyEnvelope` that still carried an unexecuted default. Recorded by round 12 as additional
  // evidence rather than as part of R1; it is the same shape as R1-D2/R1-D3 and belongs beside them.
  { id: 'R1-D4', expect: 'R1 schema/Q00: an OMITTED expectations object is a refusal, never a crash', r12: 'X00-expected-default', what: 'Q00: delete the expectations default, so an omitted object throws instead of refusing', file: VERIFY,
    find: '  expected = {},\n', replace: '  expected,\n' },
];

const flag = (name) => {
  const at = process.argv.indexOf(`--${name}`);
  return at === -1 ? undefined : process.argv[at + 1];
};
const SUITE = flag('suite') ?? 'test/**/*.test.mjs';

// `--root` and `--mutations` exist so the CLI itself can be exercised end-to-end against a
// DISPOSABLE tree. They are not a way to audit something else: the defaults are the real package
// and the real matrix, and nothing in CI passes them.
//
// The reason they are necessary is worth stating, because the obvious test is unsafe. This audit
// works by mutating real source files in place, so a test inside the suite that ran the real CLI
// would edit `src/verify.mjs` while `node --test` is running other test FILES IN PARALLEL
// PROCESSES — a file whose import happened to land mid-mutation would fail for reasons having
// nothing to do with the defect, intermittently. Pointing the CLI at a temp tree keeps the
// end-to-end path honest without making the suite race against itself.
const ROOT = flag('root') ?? QUORUM;
const MUTATIONS_FILE = flag('mutations');

// `node --test` sets NODE_TEST_CONTEXT in every child it spawns, and a child that sees it SUPPRESSES
// TAP regardless of --test-reporter. Inheriting it silently destroys this audit's only instrument:
// with no `# pass` line and no `not ok` lines, every row parses as a survivor and every verdict this
// tool produces is fiction. Found the hard way -- the round-5 CLI test asserted SURVIVED and exit 1,
// which is exactly what the broken parse produces, so it passed for the wrong reason.
//
// Stripped rather than accommodated: the audit must measure the same thing wherever it is invoked.
function suiteEnv() {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  return env;
}

function runSuite() {
  try {
    const out = execFileSync('node', ['--test', '--test-reporter=tap', SUITE],
      { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: suiteEnv() });
    return { passed: true, out };
  } catch (err) {
    return { passed: false, out: String(err.stdout ?? '') + String(err.stderr ?? '') };
  }
}

// Which reviewer CHOSE a row, oldest round first. Data rather than a `?? ?? ??` chain, because
// round 5 found the chain's newest arm (`m.r4`, added in round 4) read by no test at all: adding a
// round had been adding an unprotected branch, every time. Iterating a list means the display test
// covers every round by construction. The list is pinned by an assertion in
// `test/audit-orchestration.test.mjs`, so deleting a tag reddens by name rather than
// quietly shrinking what that test iterates.
// `r11` is deliberately absent: round 11 chose no matrix row, and a tag no row carries is an arm
// nothing reads — the exact defect J08 was written for. Tags are added when a round contributes one.
export const ROUND_TAGS = ['r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r12'];

// Only NAMED behavioural failures count. A harness whose text-replacement target vanished is not
// evidence that anything detected the defect -- that distinction is the whole point of R1.
export const HARNESS_TESTS = /MUTATION TEST|mutation-target|machinery mutation reddens/i;
export const failingNames = (tap) => [...tap.matchAll(/^not ok \d+ - (.+)$/gm)]
  .map((m) => m[1].trim())
  .filter((name) => !/\.test\.mjs$/.test(name));

// THE AUDIT'S OWN TWO DECISIONS, EXPORTED SO THEY CAN BE TESTED AS BEHAVIOUR.
//
// Round 3 of the R1 re-adjudication deleted each of them in turn and the complete suite
// stayed 169/169: the audit that exists to prove coverage had none of its own. A guard living only
// in a script's straight-line body cannot redden anything, which is the same defect this file
// accuses the verifier's tests of, one level up. They are functions now for exactly one reason --
// so `test/r1-audit-attribution.test.mjs` can drive them with a real observed failure set
// and fail when either is removed. The semantics are unchanged.

/**
 * CAUGHT means the test written FOR THIS GUARD is the one that failed, and nothing weaker.
 *
 * ATTRIBUTION, NOT A COUNT. A mutation that reddens *something* is the weaker claim the round-1 fix
 * could already make; a guard is covered when the test written FOR IT fails. Several of these
 * mutations also break a downstream fixture or the clean-project install, and reading that as
 * coverage is how a guard's own missing test stays invisible.
 *
 * @returns {'SURVIVED'|'CAUGHT'|'REDUNDANT'|'MISATTRIBUTED'}
 */
/**
 * Did the suite actually RUN? Round 7 (F1) found this tool could not tell a failed
 * MEASUREMENT from a genuine result: a mutation making an imported module unparseable kills the
 * suite before any test executes, which produced no NAMED behavioural failures, read as SURVIVED,
 * and with `redundantWith` declared became REDUNDANT at exit 0.
 *
 * ROUND 7'S DISCRIMINATOR WAS WRONG, AND ITS COMMENT SAID SO FALSELY. It tested for `# pass N`,
 * claiming the marker "is emitted only once the runner has executed tests". Round 8 (F1)
 * measured the opposite on both majors: a real load failure emits a file-level
 * `not ok N - <file>.test.mjs` AND a `# pass 0` summary, and with any unrelated file passing it
 * emits `# pass 1`. So a pass MARKER, and a pass COUNT, both survive a suite that never ran the
 * test in question.
 *
 * The sound discriminator is the file-level failure itself. `node --test` reports a file that
 * could not load as a `not ok` whose name is the FILE, which is exactly what `failingNames`
 * discards as non-behavioural -- so the one signal that the measurement is void was being thrown
 * away before anyone looked at it. `loadFailures` recovers it.
 */
export const loadFailures = (tap) => [...tap.matchAll(/^not ok \d+ - (.+)$/gm)]
  .map((m) => m[1].trim())
  .filter((name) => /\.test\.mjs$/.test(name));

export const suiteRan = (tap) => loadFailures(tap).length === 0 && /^# pass \d+/m.test(tap);

export function classifyMutation({ passed, behavioural, expect, redundantWith, measured = true }) {
  // Checked FIRST, and ahead of `redundantWith`, because an unmeasured row must not be excusable.
  if (!measured) return 'UNMEASURED';
  let verdict = passed || behavioural.length === 0 ? 'SURVIVED' : 'CAUGHT';
  // A mutation of one half of a declared, measured redundancy cannot redden by construction.
  // Reporting that as a survivor would train the reader to ignore survivors.
  if (verdict === 'SURVIVED' && redundantWith) verdict = 'REDUNDANT';
  if (verdict === 'CAUGHT' && expect && !behavioural.includes(expect)) verdict = 'MISATTRIBUTED';
  return verdict;
}

/**
 * A misattributed mutation is a coverage defect in exactly the way a survivor is: the guard's own
 * test did not notice. Exiting 0 on it would restore the count-not-attribution reading this audit
 * exists to replace. INVALID counts too -- a mutation whose target vanished measured nothing.
 */
export function auditExitCode(results) {
  const misattributed = results.filter((r) => r.verdict === 'MISATTRIBUTED');
  // UNMEASURED is deliberately NOT in this allow-list, so it falls through to `survivors` and
  // exits 1. A row nobody could measure is at least as serious as one that survived.
  const survivors = results.filter((r) => !['CAUGHT', 'REDUNDANT', 'MISATTRIBUTED'].includes(r.verdict));
  return survivors.length || misattributed.length ? 1 : 0;
}

/**
 * A row id is how a survivor is named — in this report, in an ACP record, and in a reviewer's own
 * matrix — so two rows sharing one id make the report ambiguous about which mutation survived.
 * Nothing checked it: writing the round-5 rows produced a duplicate `R1-D1` immediately, and the
 * audit reported `0 survived` without noticing. This repository has already paid for that class
 * once, as an earlier duplicate-structured-ID finding.
 *
 * It throws rather than returning a verdict, because an ambiguous matrix cannot be measured at all.
 */
export function assertUniqueIds(mutations) {
  const seen = new Map();
  for (const [index, m] of mutations.entries()) {
    if (seen.has(m.id)) {
      throw new Error(
        `duplicate mutation id ${m.id}: rows ${seen.get(m.id)} and ${index} — a survivor could not be named unambiguously`,
      );
    }
    seen.set(m.id, index);
  }
  return mutations;
}

/**
 * THE AUDIT'S REMAINING FOUR DECISIONS, EXPORTED FOR THE SAME REASON THE TWO ABOVE WERE.
 *
 * Round 5 of the re-adjudication (F3) deleted each of four protections that lived in
 * this function's straight-line body and the complete suite stayed 186/186: the red-baseline
 * refusal, the harness-failure exclusion, the exactly-once find assertion, and the restore in the
 * `finally`. That is the same defect round 3 found one level up, and it has the same fix — a
 * decision reachable only by running the script from a shell is a decision no test can redden.
 *
 * The parameters are seams, not configuration. `suite`, `read` and `write` are injected so a test
 * can drive a RED baseline, a harness-only failure and a duplicated find deterministically, in
 * milliseconds, without a real mutation of a real source file; `mutations` is injected so those
 * cases are one row long. The defaults are the real implementations, so the CLI path is unchanged
 * and `main()` is a call with no arguments.
 *
 * `process.exit(1)` on a red baseline became `return 1` for the same reason: an exit inside the
 * loop cannot be observed by a caller, and the process exit code is identical either way because
 * the entry point below is `process.exit(main())`.
 *
 * @returns {0|1} the process exit code
 */
export function runAudit({
  mutations = MUTATIONS,
  suite = runSuite,
  read = readFileSync,
  write = writeFileSync,
  log = console.log,
  error = console.error,
  root = QUORUM,
} = {}) {
assertUniqueIds(mutations);
const baseline = suite();
if (!baseline.passed) {
  error(`BASELINE IS RED; fix the suite before auditing it.\n${baseline.out.slice(-3000)}`);
  return 1;
}
log(`baseline: green (${(baseline.out.match(/^# pass (\d+)/m) ?? [])[1]} passing)\n`);

const results = [];
for (const m of mutations) {
  const path = join(root, m.file);
  const original = read(path, 'utf8');
  const occurrences = original.split(m.find).length - 1;
  if (occurrences !== 1) {
    log(`${m.id} INVALID  ${m.what} (find matched ${occurrences}x)`);
    results.push({ ...m, verdict: 'INVALID' });
    continue;
  }
  try {
    write(path, original.replace(m.find, m.replace));
    const { passed, out } = suite();
    const named = failingNames(out);
    const behavioural = named.filter((n) => !HARNESS_TESTS.test(n));
    const verdict = classifyMutation({ passed, behavioural, expect: m.expect, redundantWith: m.redundantWith, measured: suiteRan(out) });
    results.push({ ...m, verdict, caughtBy: behavioural });
    const reviewerId = ROUND_TAGS.map((tag) => m[tag]).find((value) => value !== undefined);
    log(`${m.id} ${verdict.padEnd(13)} ${m.what}${reviewerId ? `  [reviewer ${reviewerId}]` : ''}`);
    if (verdict === 'CAUGHT') {
      const rest = behavioural.filter((n) => n !== m.expect).length;
      log(`         -> ${m.expect ?? behavioural[0]}${rest ? ` (+${rest} more)` : ''}`);
    } else if (verdict === 'MISATTRIBUTED') {
      log(`         !! expected ${JSON.stringify(m.expect)}, which stayed green`);
      log(`         !! reddened instead: ${behavioural.join(', ')}`);
    } else if (verdict === 'REDUNDANT') {
      log(`         -> cannot redden: superseded by ${m.redundantWith}`);
    } else if (named.length) {
      log(`         !! only harness failures, which do not count: ${named.join(', ')}`);
    }
  } finally {
    write(path, original);
  }
}

const redundant = results.filter((r) => r.verdict === 'REDUNDANT');
const misattributed = results.filter((r) => r.verdict === 'MISATTRIBUTED');
const survivors = results.filter((r) => !['CAUGHT', 'REDUNDANT', 'MISATTRIBUTED'].includes(r.verdict));
log(
  `\n${results.length} mutations: ${results.filter((r) => r.verdict === 'CAUGHT').length} caught by their own test, `
  + `${redundant.length} declared-redundant, ${misattributed.length} misattributed, ${survivors.length} survived.`,
);
for (const r of redundant) log(`  REDUNDANT ${r.id}: superseded by ${r.redundantWith}`);
for (const r of misattributed) log(`  MISATTRIBUTED ${r.id}: ${r.what} — ${JSON.stringify(r.expect)} stayed green`);
// Round 7: INVALID and UNMEASURED both fall into `survivors` for exit-code purposes -- correctly,
// since neither measured anything -- but printing them as SURVIVOR misdescribes what happened.
for (const s of survivors) log(`  ${s.verdict === 'SURVIVED' ? 'SURVIVOR' : s.verdict} ${s.id}: ${s.what}`);
return auditExitCode(results);
}

// The real run: every seam takes its default, so the CLI audits the real mutation set against the
// real suite and the real files. Kept as a named function so the entry-guard mutation below has a
// single call to disable, exactly as before the round-5 extraction.
function main() {
  return runAudit({
    ...(MUTATIONS_FILE === undefined ? {} : { mutations: JSON.parse(readFileSync(MUTATIONS_FILE, 'utf8')) }),
    root: ROOT,
  });
}

// Importable without auditing anything, so the decisions above can be tested. Resolved through
// realpath on both sides for the same reason `ci/required-check.mjs` is: a symlinked bin otherwise
// fails the comparison and the process exits 0 having measured nothing.
if (process.argv[1] !== undefined
    && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(main());
}

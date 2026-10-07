// THE AUDIT'S OWN COVERAGE. R1, round 3.
//
// `tools/r1-mutation-audit.mjs` is the instrument this whole finding is adjudicated with: it is
// what distinguishes "a mutation reddened something" from "the test written for that guard is the
// one that failed". Round 3 pointed it at itself and found it unmeasured. Two deletions, each
// leaving the complete suite at 169 pass / 0 fail / 0 skipped on Node 24.20.0 and 26.7.0:
//
//   A01  drop the CAUGHT -> MISATTRIBUTED reclassification   a misattributed mutation prints CAUGHT, exit 0
//   A02  drop `|| misattributed.length` from the exit test   it prints MISATTRIBUTED and still exits 0
//
// Both are the failure this audit exists to prevent, committed by the audit. A01 makes it report
// coverage that does not exist; A02 makes it report the defect correctly and then tell CI it
// passed, which is the more dangerous of the two because the evidence of the problem is right there
// in an output nobody re-reads once the exit code is 0.
//
// WHY THE STIMULUS IS A REAL RUN AND NOT A HAND-WRITTEN FAILURE LIST. A test that feeds
// `classifyMutation` two invented strings would pass just as happily if the audit's notion of a
// "behavioural failure" drifted away from what `node --test` actually emits. So the misattribution
// case below MINTS one: it mutates a disposable copy of the package, runs the real 18-test
// attributed-trust file against it, and reads the failing names out of real TAP. The attribution is
// then genuinely wrong in the way the audit must catch -- one real named test stayed green while a
// different real named test reddened -- rather than wrong by construction.
//
// The package-copy idiom, and the reason mutations never touch the working tree, are the same ones
// `invariant-mutations.test.mjs` uses.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { copyPackage } from './helpers/copy-package.mjs';
import { auditExitCode, classifyMutation, failingNames } from '../tools/r1-mutation-audit.mjs';

const PACKAGE = fileURLToPath(new URL('../', import.meta.url));

// R1-M1 verbatim from the audit's own matrix, with `expect` deliberately pointed at the wrong test.
const STIMULUS = Object.freeze({
  file: 'src/verify.mjs',
  find: "    ['reviewer', envelope.reviewer, reviewerKey.key],\n",
  replace: '',
  // Real, and genuinely unaffected by the mutation above: dropping the reviewer row from the Q14
  // trust ceiling cannot stop a fully valid bundle from passing.
  misattributedTo: 'R1 baseline: an independently minted, fully valid bundle passes',
  // Real, and what actually reddens.
  actually: 'R1/Q14: the REVIEWER alone cannot claim observed trust on a declared enrolment',
});

/** Runs the real attributed-trust file against a mutated copy and returns what really failed. */
function observedFailures() {
  const original = readFileSync(join(PACKAGE, STIMULUS.file), 'utf8');
  assert.equal(
    original.split(STIMULUS.find).length - 1, 1,
    'the stimulus mutation must have exactly one target, or this test is measuring nothing',
  );

  const dir = mkdtempSync(join(tmpdir(), 'quorum-audit-attribution-'));
  try {
    copyPackage(PACKAGE, dir);
    writeFileSync(join(dir, STIMULUS.file), original.replace(STIMULUS.find, STIMULUS.replace));

    const env = { ...process.env, QUORUM_MUTATION_CHILD: '1' };
    delete env.NODE_TEST_CONTEXT;
    let out = '';
    try {
      out = execFileSync(
        process.execPath,
        ['--test', '--test-reporter=tap', './test/r1-attributed-trust.test.mjs'],
        { cwd: dir, env, encoding: 'utf8', stdio: 'pipe' },
      );
    } catch (error) {
      out = String(error.stdout ?? '') + String(error.stderr ?? '');
    }
    return failingNames(out);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('R1 audit: a mutation that reddens the WRONG named test is MISATTRIBUTED, never CAUGHT', () => {
  const behavioural = observedFailures();

  // The stimulus is only a valid probe if reality matches what it claims: one real test reddened,
  // and the one we are about to blame it on did not. Asserting this first is what separates an
  // attribution defect from a mutation that simply failed to apply.
  assert.ok(
    behavioural.includes(STIMULUS.actually),
    `the stimulus did not redden ${JSON.stringify(STIMULUS.actually)}; observed: ${JSON.stringify(behavioural)}`,
  );
  assert.ok(
    !behavioural.includes(STIMULUS.misattributedTo),
    `${JSON.stringify(STIMULUS.misattributedTo)} reddened too, so this is no longer a misattribution`,
  );

  assert.equal(
    classifyMutation({ passed: false, behavioural, expect: STIMULUS.misattributedTo }),
    'MISATTRIBUTED',
    'a guard whose own test stayed green was reported as covered because some other test failed',
  );
});

test('R1 audit: the same failure set IS a catch when it names the test the guard was written for', () => {
  // The other answer of the same decision input. Without this, the reclassification could be made
  // unconditional and the case above would still be satisfied.
  const behavioural = observedFailures();
  assert.equal(
    classifyMutation({ passed: false, behavioural, expect: STIMULUS.actually }),
    'CAUGHT',
    'the test written for this guard is exactly the one that failed, which is what coverage means',
  );
});

test('R1 audit: a green suite is a SURVIVOR, and a declared redundancy is not', () => {
  // The two inputs `classifyMutation` reads before attribution is even consulted. A mutation the
  // suite never noticed must never reach CAUGHT by any route.
  assert.equal(classifyMutation({ passed: true, behavioural: [], expect: 'anything' }), 'SURVIVED');
  assert.equal(
    classifyMutation({ passed: false, behavioural: [], expect: 'anything' }), 'SURVIVED',
    'only harness failures are not evidence that anything detected the defect',
  );
  assert.equal(
    classifyMutation({ passed: true, behavioural: [], redundantWith: 'the bin entry (measured)' }), 'REDUNDANT',
    'one half of a declared, measured double defence cannot redden by construction',
  );
  assert.equal(
    classifyMutation({
      passed: false, behavioural: ['some other test'], expect: 'the test written for this guard', redundantWith: 'x',
    }),
    'MISATTRIBUTED',
    'a redundancy declaration excuses a SURVIVOR, never a wrong attribution',
  );
});

test('R1 audit: a mutation with no declared `expect` is CAUGHT by any behavioural failure', () => {
  // The matrix still carries entries that name no expected test, and they must not all become
  // misattributions the moment attribution is enforced.
  assert.equal(classifyMutation({ passed: false, behavioural: ['some other test'] }), 'CAUGHT');
});

test('R1 audit: MISATTRIBUTED exits NON-ZERO, exactly as a survivor does', () => {
  // A02. The audit reported the misattribution correctly and exited 0, so CI read the run as clean.
  // Detecting a coverage defect and then reporting success is worse than not detecting it: the
  // evidence is in an output that nobody re-reads once the exit code is green.
  assert.equal(
    auditExitCode([{ verdict: 'CAUGHT' }, { verdict: 'MISATTRIBUTED' }]), 1,
    'a misattributed mutation is a coverage defect in exactly the way a survivor is',
  );
  assert.equal(auditExitCode([{ verdict: 'CAUGHT' }, { verdict: 'SURVIVED' }]), 1);
  assert.equal(
    auditExitCode([{ verdict: 'CAUGHT' }, { verdict: 'INVALID' }]), 1,
    'a mutation whose target vanished measured nothing, which is not a pass',
  );
  assert.equal(
    auditExitCode([{ verdict: 'CAUGHT' }, { verdict: 'REDUNDANT' }]), 0,
    'the only non-CAUGHT verdict a clean audit may contain is a declared, measured redundancy',
  );
  assert.equal(auditExitCode([]), 0);
});

test('R1 audit: importing the audit tool does not run an audit', () => {
  // The entry guard that makes every assertion above possible, and the same one `ci/required-check`
  // needed: without it this file would run the full 30-mutation matrix on import. `realpathSync` on
  // both sides, because a symlinked bin otherwise compares unequal and exits 0 having measured
  // nothing -- the defect that made the installed gate a no-op.
  assert.equal(typeof classifyMutation, 'function');
  assert.equal(typeof auditExitCode, 'function');
});

// ---------------------------------------------------------------------------
// ROUND 4, at b829c8aa. Everything above tests the two EXPORTED functions, and round 4 found that
// this is not the same thing as testing the audit. The extraction that made `classifyMutation` and
// `auditExitCode` assertable also made them detachable: the production CALLS to them can be
// disconnected, one at a time, with every assertion above still green and the complete 179-test
// suite still 179/0/0 on Node 24.20.0 and 26.7.0. Three independent mutations, exact failing test
// NONE in each case:
//
//   I01  drop `expect: m.expect` from the classifier call   prints CAUGHT, credits a green test, exit 0
//   I02  replace `return auditExitCode(results)` with `0`   prints MISATTRIBUTED correctly, then exit 0
//   I03  disable the direct-invocation entry guard          prints nothing at all, exit 0
//
// Each is a FALSE SUCCESS in the instrument the whole of R1 is adjudicated with, and the
// last is the worst of the three: an audit that runs nothing and reports success is indistinguishable
// in CI from an audit that passed. The tested function bodies are irrelevant if nothing calls them.
//
// So these three cover the SUBPROCESS, not the exports: they run the real `tools/r1-mutation-audit.mjs`
// as a program, over a matrix reduced to one deliberately misattributed row, and assert what the
// process printed and what it exited with. The stimulus is chosen independently of the one above --
// Q11's family comparison rather than Q14's reviewer row -- so a drift in either cannot mask the other.
// One run is shared by all three assertions because each CLI invocation runs a real suite.
// ---------------------------------------------------------------------------

const AUDIT_REL = 'tools/r1-mutation-audit.mjs';
// Deliberately narrow: this probe is about the audit's wiring, not about the verifier, so it runs
// the attributed-trust file alone rather than the full suite it would otherwise recurse into.
const CLI_SUITE = 'test/r1-attributed-trust.test.mjs';

const CLI_STIMULUS = Object.freeze({
  find: '  if (key.family !== party.family) {',
  replace: '  if (false) {',
  // Real, and genuinely unaffected: dropping the family comparison cannot stop a valid bundle passing.
  misattributedTo: 'R1 baseline: an independently minted, fully valid bundle passes',
  // Real, and what actually reddens.
  actually: 'R1/Q11: a REVIEWER key enrolled for another family cannot sign as this one',
});

let CLI_RUN;
/** Runs the REAL audit program over a one-row, deliberately misattributed matrix. */
function realCliRun() {
  if (CLI_RUN) return CLI_RUN;
  const dir = mkdtempSync(join(tmpdir(), 'quorum-audit-cli-'));
  try {
    copyPackage(PACKAGE, dir);
    const path = join(dir, AUDIT_REL);
    const src = readFileSync(path, 'utf8');
    const start = src.indexOf('const MUTATIONS = [');
    const end = src.indexOf('\n];', start);
    assert.ok(start !== -1 && end > start, 'could not locate the audit matrix, so this probe measures nothing');
    const oneRow = `const MUTATIONS = [\n  { id: 'CLI-LENS', expect: ${JSON.stringify(CLI_STIMULUS.misattributedTo)},`
      + ` what: 'CLI wiring probe: drop the family comparison', file: VERIFY,\n`
      + `    find: ${JSON.stringify(CLI_STIMULUS.find)}, replace: ${JSON.stringify(CLI_STIMULUS.replace)} },\n];`;
    writeFileSync(path, src.slice(0, start) + oneRow + src.slice(end + 3));

    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    delete env.QUORUM_MUTATION_CHILD;
    let out = '';
    let status = 0;
    try {
      out = execFileSync(process.execPath, [AUDIT_REL, '--suite', CLI_SUITE],
        { cwd: dir, env, encoding: 'utf8', stdio: 'pipe', maxBuffer: 32 * 1024 * 1024 });
    } catch (error) {
      out = String(error.stdout ?? '') + String(error.stderr ?? '');
      status = error.status ?? -1;
    }
    CLI_RUN = { out, status };
    return CLI_RUN;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('R1 audit CLI: invoking the audit directly actually RUNS it', () => {
  // I03. The entry guard has two directions and only one was tested: the import case, asserted
  // above by this file existing at all. Disabling the guard makes the program a silent no-op that
  // exits 0 -- in CI, identical to a clean audit -- and no assertion on the exported functions can
  // see it, because nothing imports anything.
  const { out } = realCliRun();
  assert.notEqual(out.trim(), '', 'the audit produced no output at all, so it never ran');
  assert.match(out, /^baseline: green/m, 'the audit did not reach its own baseline run');
  assert.match(out, /^1 mutations: /m, 'the audit printed no summary, so it audited nothing');
});

test('R1 audit CLI: the matrix\'s expected test name reaches the classifier', () => {
  // I01. `classifyMutation` refuses a wrong attribution correctly and is tested doing so, but the
  // production call can simply stop passing `expect`. Every mutation then becomes CAUGHT-by-anything
  // -- the count-not-attribution reading this whole audit exists to replace -- and the exported
  // function is still perfect.
  //
  // The probe asserts itself first: one real test reddened, and the one the matrix blames stayed
  // green. Without that, a mutation that failed to apply would look identical to a wiring defect.
  const { out } = realCliRun();
  assert.match(out, /stayed green/, `the audit did not report a misattribution at all:\n${out}`);
  assert.ok(
    out.includes(CLI_STIMULUS.actually),
    `the audit never named the test that really reddened, so the probe is invalid:\n${out}`,
  );
  assert.ok(
    out.includes(CLI_STIMULUS.misattributedTo),
    `the audit never named the wrongly-expected test:\n${out}`,
  );
  assert.match(
    out, /^1 mutations: 0 caught by their own test, 0 declared-redundant, 1 misattributed, 0 survived\.$/m,
    `a mutation whose own expected test stayed green was credited as covered:\n${out}`,
  );
});

test('R1 audit CLI: a MISATTRIBUTED run makes the PROCESS exit non-zero', () => {
  // I02. `auditExitCode` returns 1 and is tested returning 1; `main` can still discard it. The
  // audit then prints the defect in full and tells CI the run was clean, which is the more
  // dangerous half of A02 committed one layer out, where no exported function is involved.
  const { status } = realCliRun();
  assert.notEqual(status, 0, 'the audit reported a misattribution and then exited 0, so CI reads it as clean');
});

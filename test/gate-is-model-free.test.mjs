// gate-is-model-free.test.mjs — the verifier runs NO model and holds NO credential.
//
// PROVENANCE: adopted 2026-09-28 from `disensor` (MIT, PyPI 0.11.0), found by the weekly ecosystem
// scan as the closest published prior art to Quorum. Its first design choice is one we already
// satisfy by accident and had never protected:
//
//   "The gate runs no model and holds no API key. It validates an artifact already committed in
//    the repo."
//
// That is a far cleaner CI story than running a reviewer inside the gate, and it is the property
// that makes `quorum` installable into an empty directory by a stranger who owes us no trust.
//
// THIS IS THE CLAIM UNDER TEST, stated so a reader can falsify it in one sentence: a consumer can
// run the Quorum gate offline, with no credential of any kind, and get the same verdict.
//
// F2 — WHY THIS FILE WAS REWRITTEN. The first version stated the claim above and then
// checked two dependency fields and four exact spellings. Three ordinary, supported forms —
// `import('node:https')`, `const { OPENAI_API_KEY } = process.env`, and `optionalDependencies` —
// were planted in the SHIPPED tree and the complete suite stayed at 138 pass / 0 fail with all four
// of this file's tests green. The property was broad and the test was narrow, which is a test that
// reports on itself rather than on the code.
//
// The detection now lives in `./shipped-surface.mjs` and is DEFAULT-DENY: an explicit allow-list of
// what the gate may load and read, plus a classification-completeness rule that turns any construct
// the audit cannot read into a violation. `guard-coverage.test.mjs` plants each bypass
// form into a real copy of this package and requires the NAMED test below to report `not ok`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ALLOWED_ENV, ALLOWED_MODULES, AUDITED_BEYOND_PACKAGE_FILES, PUBLISHED_OUTSIDE_THE_GATE, auditShippedSurface, shippedSourceFiles,
} from './shipped-surface.mjs';

const ROOT = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));
const PKG = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const audit = auditShippedSurface(ROOT);
const of = (kind) => audit.violations.filter((violation) => violation.kind === kind)
  .map((violation) => `${violation.file}${violation.line === null ? '' : `:${violation.line}`} — ${violation.reason}`);

// NON-VACUITY, FIRST. Every assertion below is over a file set, and a guard that cannot see its
// subject is not a guard — that is the failure mode this repository keeps finding in its own
// checks, so it is checked before anything is concluded from the audit.
test('the audit sees the whole shipped surface, derived from package.json `files`', () => {
  assert.ok(audit.scanned.length >= 8, `expected to scan the shipped source, found ${audit.scanned.length} files`);
  for (const required of ['src/verify.mjs', 'src/envelope.mjs', 'ci/required-check.mjs', 'bin/quorum.mjs']) {
    assert.ok(audit.scanned.includes(required), `${required} must be inside the audited set`);
  }

  // THE DISCOVERY RULE ITSELF, which is what F2's "a newly-added shipped source path"
  // case turns on. The previous version hardcoded ['src','bin','ci','schema'], so adding a
  // directory to `files` shipped it unaudited. Every published entry is now audited by
  // construction, and the only additions are declared and reasoned about in one place.
  const discovered = shippedSourceFiles(ROOT, PKG);
  assert.deepEqual(audit.scanned, discovered, 'the audited set must be exactly what discovery returns');
  const roots = new Set(audit.scanned.map((file) => file.split('/')[0]));
  for (const entry of roots) {
    assert.ok([...PKG.files, ...AUDITED_BEYOND_PACKAGE_FILES].includes(entry),
      `${entry}/ is audited but is neither published nor a declared exception`);
  }
  assert.deepEqual([...AUDITED_BEYOND_PACKAGE_FILES], ['ci'],
    'the audited-but-unpublished exceptions must stay a short, deliberate list');
  // The published-but-not-audited directories: declared in one place, and only the suite and the
  // fixture generator. Every other published source directory is audited.
  assert.deepEqual([...PUBLISHED_OUTSIDE_THE_GATE], ['test', 'tools'],
    'the published-outside-the-gate exceptions must stay a short, deliberate list');
});

test('the shipped gate installs nothing: every dependency-bearing manifest field is empty', () => {
  // Discovered by SHAPE (any key matching /dependencies/i) rather than by name, so
  // optionalDependencies, peerDependencies, bundleDependencies and anything npm adds later are all
  // covered. The previous version named `dependencies` and `devDependencies` and nothing else,
  // which is exactly the hole F2 walked through.
  assert.deepEqual(of('manifest'), []);

  // Stated positively as well, so the loop above cannot be satisfied by the fields simply being
  // absent from a manifest that no longer declares them.
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    assert.deepEqual(PKG[field] ?? {}, {}, `${field} must be empty`);
  }
  assert.throws(() => readFileSync(new URL('../package-lock.json', import.meta.url)),
    'a package-lock.json in quorum/ means a dependency was added — that breaks the clean-room claim');
});

test('no shipped source file loads a module outside the allow-list', () => {
  // DEFAULT-DENY. `node:https` is refused not because it is on a list of bad modules but because it
  // is not on the list of four the gate is allowed, and so is every other module anyone adds.
  assert.deepEqual(of('module'), []);
  assert.deepEqual([...ALLOWED_MODULES], ['node:crypto', 'node:fs', 'node:path', 'node:url'],
    'the shipped module allow-list changed — every entry must be re-reasoned, not just re-run');
});

test('no shipped source file reads an environment variable outside the QUORUM_ namespace', () => {
  assert.deepEqual(of('env'), []);
  // The rule is a namespace, not a credential shape: `OPENAI_API_KEY` is refused for not being
  // ours. A shape-matcher only ever catches the secret names someone thought of.
  assert.equal(ALLOWED_ENV.test('QUORUM_MODE'), true, 'an ordinary behaviour flag must remain readable');
  assert.equal(ALLOWED_ENV.test('OPENAI_API_KEY'), false);
});

test('no shipped source file uses a network-capable global or a code-loading escape', () => {
  // `fetch` is a bare global in modern Node, so no import check can see it; `eval`, `new Function`
  // and `createRequire` would each defeat every other rule in the audit.
  assert.deepEqual(of('global'), []);
});

test('no shipped source file contains a construct the audit cannot read', () => {
  // CLASSIFICATION COMPLETENESS, and the reason the allow-list is not just a nicer forbidden-list.
  // `import(someVariable)` and `process.env[expr]` name something real that cannot be checked
  // against any list, so they are refused rather than skipped. Without this, the extractor's blind
  // spots would silently become the guard's — which is F2 restated.
  assert.deepEqual(of('unreadable'), []);
});

test('the real shipped tree is clean: the audit finds nothing at all', () => {
  // Deliberately redundant with the five tests above, and DECLARED as such per this repository's
  // rule on undeclared double defences. Those five partition the violation kinds known today; this
  // one catches a kind added later that nobody wired into a named test. It is the backstop, not an
  // independent detector, so a mutation is expected to redden it AND its own named test.
  assert.deepEqual(audit.violations, []);
});

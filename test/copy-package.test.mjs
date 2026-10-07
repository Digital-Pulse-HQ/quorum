// Regression: the mutation suites copy the package into a scratch directory, and the copy must work
// when the package is INSTALLED — i.e. when its own root path contains `/node_modules/`.
//
// It did not. Each copy filtered on the ABSOLUTE source path (`!src.includes('/node_modules')`),
// which rejects the copy root itself under `<consumer>/node_modules/@digital-pulse-hq/quorum`, so
// cpSync copied nothing and 41/305 tests failed with ENOENT — but only when installed from npm.
// From the repo and from an extracted tarball the root path has no node_modules in it, so every
// existing run was green. These tests run the copy FROM a root path containing /node_modules/.

import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { copyPackage } from './helpers/copy-package.mjs';

const PACKAGE = fileURLToPath(new URL('../', import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const HELPER = fileURLToPath(new URL('./helpers/copy-package.mjs', import.meta.url));

function put(root, rel, body = rel) {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), body);
}

test('copyPackage copies an installed package whose own root path contains /node_modules/', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'quorum-copy-installed-'));
  try {
    const root = join(scratch, 'consumer', 'node_modules', '@digital-pulse-hq', 'quorum');
    put(root, 'package.json', '{}');
    put(root, 'tools/r1-mutation-audit.mjs');
    put(root, 'src/verify.mjs');
    // Below the root, node_modules is still left out at any depth (descendant .git: next test).
    put(root, 'node_modules/dep/index.js');
    put(root, 'test/node_modules/nested/index.js');
    put(root, '.git/HEAD');

    const dir = join(scratch, 'copy');
    copyPackage(root, dir);

    for (const kept of ['package.json', 'tools/r1-mutation-audit.mjs', 'src/verify.mjs']) {
      assert.equal(readFileSync(join(dir, kept), 'utf8'), readFileSync(join(root, kept), 'utf8'), `${kept} was not copied`);
    }
    for (const dropped of ['node_modules', 'test/node_modules', '.git']) {
      assert.equal(existsSync(join(dir, dropped)), false, `${dropped} was copied but must be excluded`);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test('copyPackage leaves out .git BELOW the root, not only at it', () => {
  // A root-only `.git` check passes the test above; a submodule or nested checkout does not.
  const scratch = mkdtempSync(join(tmpdir(), 'quorum-copy-nested-git-'));
  try {
    const root = join(scratch, 'consumer', 'node_modules', '@digital-pulse-hq', 'quorum');
    put(root, 'package.json', '{}');
    put(root, 'nested/.git/HEAD');
    put(root, 'test/fixtures/.git/config');

    const dir = join(scratch, 'copy');
    copyPackage(root, dir);

    assert.equal(readFileSync(join(dir, 'package.json'), 'utf8'), '{}', 'package.json was not copied');
    for (const dropped of ['nested/.git', 'test/fixtures/.git']) {
      assert.equal(existsSync(join(dir, dropped)), false, `${dropped} was copied but must be excluded`);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test('copyPackage keeps entries whose names only RESEMBLE node_modules or .git', () => {
  // Exclusion is by whole path segment. A substring or prefix match would drop these.
  const scratch = mkdtempSync(join(tmpdir(), 'quorum-copy-lookalike-'));
  try {
    const root = join(scratch, 'consumer', 'node_modules', '@digital-pulse-hq', 'quorum');
    const lookalikes = ['.github/keep.txt', '.gitignore', 'node_modules-cache/keep.txt', 'src/my_node_modules.mjs'];
    for (const rel of lookalikes) put(root, rel);

    const dir = join(scratch, 'copy');
    copyPackage(root, dir);

    for (const kept of lookalikes) {
      assert.equal(existsSync(join(dir, kept)), true, `${kept} was excluded but only resembles an excluded name`);
      assert.equal(readFileSync(join(dir, kept), 'utf8'), kept, `${kept} was not copied intact`);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test('no file in test/ or tools/ copies the package with its own node_modules filter', () => {
  // The defect was the same inline filter pasted into four places, two of which were later fixed and
  // two not. This is a LEXICAL backstop, not a guarantee: it flags a .mjs file under test/ or tools/
  // whose text contains both the literal token `cpSync(` and the literal `node_modules`. It does not
  // parse the file, so a renamed import (`cpSync as clone`), `fs/promises` `cp`, a constructed
  // 'node_modules' string, or a copy outside test/ and tools/ all pass it. Use copyPackage().
  const offenders = [];
  for (const area of ['test', 'tools']) {
    for (const name of readdirSync(join(PACKAGE, area), { recursive: true })) {
      const full = join(PACKAGE, area, name);
      if (!name.endsWith('.mjs') || full === SELF || full === HELPER) continue;
      const src = readFileSync(full, 'utf8');
      if (src.includes('cpSync(') && src.includes('node_modules')) offenders.push(`${area}/${name}`);
    }
  }
  assert.deepEqual(offenders, [], 'copy the package with copyPackage() from test/helpers/copy-package.mjs');
});

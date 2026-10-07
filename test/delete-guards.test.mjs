// DELETE TESTS. For each guard: copy the package to a temporary directory, neuter exactly that one
// guard, re-run the behavioural suite, and require that the guard's OWN test reports `not ok`.
//
// TWO THINGS THIS DOES THAT A NAIVE HARNESS DOES NOT, both because the naive version passes while
// measuring nothing:
//
//   - IT READS TAP, NOT PROSE. `output.includes(testName)` matches the PASSING line for that test
//     just as happily as the failing one, so a harness written that way accepts a mutant that broke
//     some other test entirely. The assertion here is on `not ok <n> - <name>`.
//   - IT CLEARS NODE_TEST_CONTEXT. node:test marks its worker with that variable; inherited by a
//     nested `node --test`, the child behaves as part of the parent harness and a red mutant can
//     exit 0.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { GUARD_CASES } from './guards.test.mjs';
import { copyPackage } from './helpers/copy-package.mjs';
import { GUARD_IDS } from '../src/verify.mjs';

const PACKAGE = fileURLToPath(new URL('../', import.meta.url));
const VERIFY = join(PACKAGE, 'src', 'verify.mjs');

function tapFailures(output) {
  return output
    .split('\n')
    .filter((line) => /^not ok \d+ - /.test(line.trim()))
    .map((line) => line.trim().replace(/^not ok \d+ - /, ''));
}

test('DELETE TEST: neutering any single guard reddens that guard\'s own test', {
  skip: process.env.QUORUM_MUTATION_CHILD === '1' ? 'mutation child' : false,
  timeout: 300_000,
}, () => {
  const source = readFileSync(VERIFY, 'utf8');
  assert.equal(Object.keys(GUARD_CASES).length, GUARD_IDS.length, 'guard table and guard list disagree');

  for (const guard of GUARD_IDS) {
    const marker = `/* GUARD:${guard} */`;
    const occurrences = source.split(marker).length - 1;
    assert.equal(occurrences, 1, `${guard} marker occurs ${occurrences} times in src/verify.mjs, expected exactly 1`);

    const dir = mkdtempSync(join(tmpdir(), `quorum-delete-${guard}-`));
    try {
      copyPackage(PACKAGE, dir);
      // `false &&` short-circuits the guard's condition to false, so the refusal branch is
      // unreachable and control falls through to whatever the next guard happens to catch.
      writeFileSync(join(dir, 'src', 'verify.mjs'), source.replace(marker, `${marker} false &&`));

      // Verify the mutation actually landed rather than trusting the string replace.
      const mutated = readFileSync(join(dir, 'src', 'verify.mjs'), 'utf8');
      assert.equal(mutated.split(`${marker} false &&`).length - 1, 1, `${guard} mutation did not land`);

      const childEnv = { ...process.env, QUORUM_MUTATION_CHILD: '1' };
      delete childEnv.NODE_TEST_CONTEXT;
      let status = 0;
      let output = '';
      try {
        output = execFileSync(process.execPath, ['--test', '--test-reporter=tap', './test/guards.test.mjs'], {
          cwd: dir, env: childEnv, encoding: 'utf8', stdio: 'pipe',
        });
      } catch (error) {
        status = error.status;
        output = String(error.stdout ?? '') + String(error.stderr ?? '');
      }

      const expectedTest = `guard ${guard} refuses ${GUARD_CASES[guard]}`;
      assert.notEqual(status, 0, `${guard} was neutered and the suite stayed green`);
      assert.ok(
        tapFailures(output).includes(expectedTest),
        `${guard} reddened, but not through its own test ${JSON.stringify(expectedTest)}. TAP failures: ${JSON.stringify(tapFailures(output))}`,
      );
      process.stdout.write(`delete-test ok: ${guard} -> ${expectedTest}\n`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

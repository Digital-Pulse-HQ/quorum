// RUNNER — `npm test` refuses an empty suite. test/run.mjs names every test/**/*.test.mjs and exits 1
// if there is none, because `node --test` handed no files falls back to its own discovery and exits 0
// having run no behavioural test. This copies the REAL runner, alone, into an empty scratch test/ and
// runs it: it must exit non-zero with its own refusal and report no passing test. The same copy with one
// trivially passing test file must exit 0 having run it — so failure-to-run is told apart from success.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const RUNNER = fileURLToPath(new URL('./run.mjs', import.meta.url));

function runRunner(base, runner) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, [runner, '--test-reporter=tap'], { cwd: base, env, encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

test('RUNNER: npm test\'s runner refuses a test/ with no *.test.mjs, and runs one that holds a test', () => {
  const base = mkdtempSync(join(tmpdir(), 'quorum-test-runner-'));
  try {
    const dir = join(base, 'test');
    mkdirSync(dir);
    const runner = join(dir, 'run.mjs');
    copyFileSync(RUNNER, runner);

    const empty = runRunner(base, runner);
    assert.notEqual(empty.status, 0, `an empty suite exited ${empty.status}:\n${empty.stdout}${empty.stderr}`);
    assert.match(empty.stderr, /an empty suite is not a passing one/, 'the runner did not refuse the empty suite by its own message');
    assert.doesNotMatch(empty.stdout, /^ok \d+ - /m, 'the empty run reported a passing test');

    writeFileSync(join(dir, 'one.test.mjs'), "import test from 'node:test';\ntest('runner witness', () => {});\n");
    const one = runRunner(base, runner);
    assert.equal(one.status, 0, `a one-test suite exited ${one.status}:\n${one.stdout}${one.stderr}`);
    assert.match(one.stdout, /^ok \d+ - runner witness$/m, 'the runner did not run the planted test');
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

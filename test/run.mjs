// `npm test`: every test/**/*.test.mjs file, named explicitly.
//
// `node --test "test/**/*.test.mjs"` relies on node expanding the glob itself, which Node 20.11 — the
// minimum this package declares — does not do: it looks for a file literally named `**/*.test.mjs`
// and exits 1 before any test runs. Building the list here works on every supported Node and leaves
// nothing to the shell. Extra arguments are passed to node --test, e.g. `npm test --
// --test-reporter=tap`. No entry-point check: this file exists only to be run.

import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const TEST = fileURLToPath(new URL('.', import.meta.url));
const files = readdirSync(TEST, { recursive: true })
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => join(TEST, name));

if (files.length === 0) {
  process.stderr.write(`no *.test.mjs files under ${TEST} — an empty suite is not a passing one\n`);
  process.exit(1);
}
const result = spawnSync(process.execPath, ['--test', ...process.argv.slice(2), ...files], { stdio: 'inherit' });
process.exit(result.status ?? 1);

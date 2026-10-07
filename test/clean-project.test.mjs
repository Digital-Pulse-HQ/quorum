// THE LOAD-BEARING CLAIM, EXECUTED.
//
// The verifier claims to run with no orchestration tool installed and nothing from the repository it
// was developed in. A claim like that is easy to quote and easy never to execute. This test is that
// execution, and it checks exactly what a consumer relies on — no more:
//
//   - the package packs, and installs offline into an empty directory that has none of this
//     repository's layout, with the suite and fixture corpus it ships;
//   - the consumer's node_modules then holds this package and nothing else, and its manifest declares
//     no dependencies;
//   - the installed bin runs `--help`;
//   - every entry point the manifest declares (`bin`, `main` if present, and each `exports` subpath,
//     patterns expanded over the installed files) resolves by the package name from the consumer
//     project, inside the installed package, and loads — modules with the export names the source
//     declares, JSON as JSON;
//   - the installed conformance check passes, as the README tells a consumer to run it;
//   - the installed bin and the README's npx invocation verify a valid review, refuse every
//     trailer-table fixture by the guard it names, and refuse a deleted envelope.
//
// It does NOT check what the shipped modules import. The publisher's release check does that
// (release-checks/, not packed), not a consumer test, because it needs a parser Node does not publish;
// and its claim is bounded. Over the packed .mjs modules — the only modules the package may ship, any
// other packed JavaScript file being refused — it checks every static import and export-from specifier
// and refuses the listed syntactic forms of dynamic loading. It cannot establish that no shipped code
// loads anything at run time.
//
// It refuses to SKIP. A clean-room test that quietly skips when npm is unavailable is worse than no
// test, because the claim it exists to prove is the one being quoted. If it cannot run, it fails.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import * as SOURCE from '../src/index.mjs';

const PACKAGE = fileURLToPath(new URL('../', import.meta.url));
const FIXTURES = join(PACKAGE, 'fixtures');
const INDEX = JSON.parse(readFileSync(join(FIXTURES, 'index.json'), 'utf8'));

// The layout this package must not need. Asserting their ABSENCE in the consumer directory is what
// makes "no monorepo-layout dependency" a measurement rather than a claim.
const MONOREPO_LAYOUT = ['runtime', 'docs', 'config', 'bridge', 'bff', 'website', 'evaluations', '.git', 'CLAUDE.md'];

const npm = (args, cwd) => execFileSync('npm', args, {
  cwd, encoding: 'utf8', stdio: 'pipe', env: { ...process.env, npm_config_update_notifier: 'false' },
});

// One child process, run from the consumer project, that loads every declared entry point by the
// package name — exactly the requests a consumer's own code would make. JSON goes through require,
// which honours `exports` and parses JSON on every supported Node without import attributes.
const LOAD_ENTRY_POINTS = `
import { createRequire } from 'node:module';
const require = createRequire(process.cwd() + '/');
const out = {};
for (const specifier of JSON.parse(process.argv[1])) {
  const file = require.resolve(specifier);
  out[specifier] = file.endsWith('.json')
    ? { file, json: typeof require(specifier) }
    : { file, exports: Object.keys(await import(specifier)).sort() };
}
process.stdout.write(JSON.stringify(out));
`;

// THE CONSUMER CONTRACT, pinned LITERALLY rather than derived from the manifest under test, so an
// export dropped from the manifest fails here instead of silently leaving the derived list too. These
// are the canonical specifiers the package supported before its `./schema/*.json` pattern became four
// explicit exports. A URL-encoded or otherwise URL-rewritten spelling of them (e.g. `%71` for the `q`)
// resolved through the old pattern and is DELIBERATELY no longer supported: README "Entry points".
const CANONICAL_SPECIFIERS = [
  '@digital-pulse-hq/quorum',
  '@digital-pulse-hq/quorum/schema/quorum-envelope-1.schema.json',
  '@digital-pulse-hq/quorum/schema/quorum-manifest-1.schema.json',
  '@digital-pulse-hq/quorum/schema/quorum-policy-1.schema.json',
  '@digital-pulse-hq/quorum/schema/quorum-trust-1.schema.json',
];
const REWRITTEN_SPECIFIERS = CANONICAL_SPECIFIERS.slice(1).map((specifier) => specifier.replace('/schema/q', '/schema/%71'));

// Each specifier through BOTH loaders, independently: neither loader's outcome can mask the other's.
const PROBE_LOADERS = `
import { createRequire } from 'node:module';
const require = createRequire(process.cwd() + '/');
const out = {};
for (const specifier of JSON.parse(process.argv[1])) {
  const outcome = {};
  // A JSON schema reports the $id it CARRIES, not merely that something loaded: an explicit export
  // that routes a canonical name to the wrong schema file must not read as success.
  // The whole delivered body is reported too, so a re-routed export that keeps the right $id but
  // carries a different body is caught.
  const seen = (value) => (specifier.endsWith('.json') ? \`$id:\${value?.$id} body:\${JSON.stringify(value)}\` : 'loaded');
  try { outcome.require = seen(require(specifier)); } catch (error) { outcome.require = error.code ?? error.name; }
  try { outcome.import = seen((await import(specifier, specifier.endsWith('.json') ? { with: { type: 'json' } } : undefined)).default); } catch (error) { outcome.import = error.code ?? error.name; }
  out[specifier] = outcome;
}
process.stdout.write(JSON.stringify(out));
`;

// Concrete subpaths for one `exports` entry: the key itself, or a `*` pattern expanded over the files
// the installed package actually holds.
function exportSubpaths(installed, key, target) {
  assert.equal(typeof target, 'string', `exports[${JSON.stringify(key)}] is not a plain path; extend this test before adding conditions`);
  if (!key.includes('*')) return [key];
  const [keyHead, keyTail] = key.split('*');
  const [head, tail] = target.split('*');
  assert.ok(head.endsWith('/') && !tail.includes('/'), `exports[${JSON.stringify(key)}] is a pattern this test cannot expand: ${target}`);
  const names = readdirSync(join(installed, head)).filter((name) => name.endsWith(tail));
  assert.ok(names.length > 0, `exports[${JSON.stringify(key)}] matches no installed file`);
  return names.map((name) => `${keyHead}${name.slice(0, name.length - tail.length)}${keyTail}`);
}

test('CLEAN PROJECT: the packed package installs and verifies in a directory with none of this repository\'s layout', { timeout: 300_000 }, () => {
  const root = mkdtempSync(join(tmpdir(), 'quorum-clean-'));
  const consumer = join(root, 'consumer');
  mkdirSync(consumer);
  try {
    // 1. Pack. `files` in package.json decides what a consumer gets: bin, src, schema, ci, docs,
    //    licence — and the suite that proves them (test, fixtures, and the generator the drift test
    //    re-runs), so a consumer can run the gates' refusals rather than take them on report.
    const packOutput = npm(['pack', '--pack-destination', root, '--silent'], PACKAGE).trim();
    const tarball = join(root, packOutput.split('\n').pop().trim());
    assert.ok(existsSync(tarball), `npm pack produced no tarball: ${packOutput}`);

    // 2. A consumer project that knows nothing about this repository.
    writeFileSync(join(consumer, 'package.json'), `${JSON.stringify({
      name: 'quorum-clean-room', version: '1.0.0', private: true, type: 'module',
    }, null, 2)}\n`);

    // 3. Install. --offline proves no network is needed: a zero-dependency package has nothing to
    //    resolve, and if that ever stops being true this line is where it surfaces.
    npm(['install', '--offline', '--no-audit', '--no-fund', '--ignore-scripts', tarball], consumer);

    const installed = join(consumer, 'node_modules', '@digital-pulse-hq', 'quorum');
    assert.ok(existsSync(installed), 'the package did not install');

    // 3a. THE SUITE SHIPS. Every published gate's refusing case travels with the package, so the
    //     installed fixture index must be the committed one and every test file must be present —
    //     a `files` list that drops either would leave the README's claims unrunnable by a consumer.
    assert.deepEqual(JSON.parse(readFileSync(join(installed, 'fixtures', 'index.json'), 'utf8')), INDEX,
      'the installed fixture index differs from the committed one');
    const shippedTests = readdirSync(join(installed, 'test')).sort();
    assert.deepEqual(shippedTests, readdirSync(join(PACKAGE, 'test')).sort(), 'the installed test/ differs from the committed one');
    for (const dir of ['ci', 'tools']) {
      assert.ok(existsSync(join(installed, dir)), `${dir}/ is imported by the shipped tests and did not ship`);
    }

    // 4. NOTHING ELSE CAME WITH IT. One scope directory and npm's own bookkeeping — no transitive
    //    tree, and in particular no orchestration tool, whatever it is called: the assertion is that
    //    the installed set is exactly this package, not that some named tool is absent.
    const modules = readdirSync(join(consumer, 'node_modules')).filter((name) => !name.startsWith('.'));
    assert.deepEqual(modules, ['@digital-pulse-hq'], `unexpected packages installed: ${modules.join(', ')}`);
    assert.deepEqual(readdirSync(join(consumer, 'node_modules', '@digital-pulse-hq')), ['quorum']);
    const manifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
    for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies', 'bundleDependencies', 'bundledDependencies']) {
      const declared = manifest[field] ?? {};
      assert.equal(Object.keys(declared).length, 0, `the installed package.json declares ${field}: ${JSON.stringify(declared)}`);
    }

    // 5. The consumer directory has none of this repository's layout.
    for (const entry of MONOREPO_LAYOUT) {
      assert.equal(existsSync(join(consumer, entry)), false, `the clean room contains ${entry}`);
    }

    // 6. THE DECLARED ENTRY POINTS, as a consumer reaches them. The bin runs `--help`; every `main`
    //    and `exports` subpath resolves by the package name from the consumer project to a file inside
    //    the installed package — so no other copy can answer — and loads. The `.` entry must carry
    //    exactly the export names the committed source declares, so an export lost in packing fails.
    const bin = join(consumer, 'node_modules', '.bin', 'quorum');
    assert.ok(existsSync(bin), 'npm did not link the quorum bin');
    assert.deepEqual(Object.keys(manifest.bin ?? {}), ['quorum', 'quorum-required-check'], 'the manifest declares a different bin set than this test runs (quorum here, quorum-required-check at step 9)');
    const help = execFileSync(bin, ['--help'], { cwd: consumer, encoding: 'utf8', stdio: 'pipe' });
    assert.match(help, /^usage: quorum /, 'the installed bin did not print its usage for --help');

    const name = manifest.name;
    const subpaths = [
      ...(manifest.main === undefined ? [] : ['.']),
      ...Object.entries(manifest.exports ?? {}).flatMap(([key, target]) => exportSubpaths(installed, key, target)),
    ];
    assert.ok(subpaths.includes('.'), 'the manifest declares no main entry point');
    const specifiers = [...new Set(subpaths)].map((subpath) => (subpath === '.' ? name : `${name}${subpath.slice(1)}`));
    const loaded = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', LOAD_ENTRY_POINTS, JSON.stringify(specifiers)], {
      cwd: consumer, encoding: 'utf8', stdio: 'pipe',
    }));
    assert.deepEqual(Object.keys(loaded).sort(), [...specifiers].sort(), 'an entry point was not loaded');
    // Node reports resolved files by real path, and the temporary directory may sit behind a symlink.
    const installedReal = realpathSync(installed);
    for (const [specifier, { file }] of Object.entries(loaded)) {
      assert.ok(file.startsWith(installedReal + sep), `${specifier} resolved outside the installed package: ${file}`);
    }
    // 6b. THE CONTRACT, from the literal list: every canonical specifier loads through require AND
    //     import, and every URL-rewritten spelling of a schema specifier is refused by both.
    const probe = (list) => JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', PROBE_LOADERS, JSON.stringify(list)], {
      cwd: consumer, encoding: 'utf8', stdio: 'pipe',
    }));
    const canonical = probe(CANONICAL_SPECIFIERS.slice(1));
    for (const specifier of CANONICAL_SPECIFIERS.slice(1)) {
      // The expected identity comes from the REQUESTED name in the literal list, and the observed one
      // from the delivered schema's own $id; the manifest under test supplies neither side.
      // The body side is the SOURCE schema file of that name in this checkout, not whatever file the
      // export happens to route to.
      const schemaName = specifier.slice(specifier.lastIndexOf('/') + 1);
      const sourceBody = JSON.stringify(JSON.parse(readFileSync(join(PACKAGE, 'schema', schemaName), 'utf8')));
      const want = `$id:urn:quorum:schema:${schemaName} body:${sourceBody}`;
      assert.deepEqual(canonical[specifier], { require: want, import: want },
        `${specifier} is a canonical consumer specifier and must deliver the schema it names, through both loaders`);
    }
    assert.ok(specifiers.includes(CANONICAL_SPECIFIERS[0]) && loaded[CANONICAL_SPECIFIERS[0]] !== undefined, 'the package main specifier did not load');
    const rewritten = probe(REWRITTEN_SPECIFIERS);
    for (const specifier of REWRITTEN_SPECIFIERS) {
      assert.deepEqual(rewritten[specifier], { require: 'ERR_PACKAGE_PATH_NOT_EXPORTED', import: 'ERR_PACKAGE_PATH_NOT_EXPORTED' },
        `${specifier} is a URL-rewritten spelling, deliberately unsupported, and must be refused by both loaders`);
    }

    const sourceExports = Object.keys(SOURCE).sort();
    assert.deepEqual(loaded[name].exports, sourceExports, `${name} did not load with the export names the source declares`);
    for (const specifier of specifiers.filter((s) => s.endsWith('.json'))) {
      assert.equal(loaded[specifier].json, 'object', `${specifier} did not load as JSON`);
    }

    // 6a. THE README'S CONFORMANCE STEP, in the installed copy: every adversarial fixture refused by
    //     the guard it names and every positive control passing, through the shipped required check.
    const conformance = execFileSync(process.execPath, ['ci/required-check.mjs', '--manifest', 'fixtures/index.json', '--mode', 'conformance'], {
      cwd: installed, encoding: 'utf8', stdio: 'pipe',
    });
    assert.match(conformance, new RegExp(`: ${INDEX.cases.length}/${INDEX.cases.length} cases behaved as required`),
      `the installed conformance check did not report every case: ${conformance}`);

    // 7. Copy the evidence a consumer would hold. The fixtures ship as the package's own test
    //    material, but a real consumer verifies their own envelope, policy and trust store from their
    //    own tree rather than from node_modules — which is exactly what this copies in.
    const evidence = join(consumer, 'evidence');
    const cases = [
      INDEX.cases.find((c) => c.name === 'valid-cross-family-approve'),
      ...INDEX.cases.filter((c) => c.name.startsWith('trailer-') && !c.expect.ok),
    ];
    for (const entry of cases) {
      for (const rel of [entry.envelope, entry.policy, entry.trust, entry.artifact, entry.evidence]) {
        if (!rel) continue;
        const target = join(evidence, rel);
        mkdirSync(join(target, '..'), { recursive: true });
        if (existsSync(join(FIXTURES, rel))) copyFileSync(join(FIXTURES, rel), target);
      }
    }

    // 8. Run the INSTALLED binary, by the name npm put on PATH, from the consumer directory.
    const runVerify = (entry, command = [bin]) => {
      const args = [
        ...command.slice(1),
        'verify',
        '--envelope', join(evidence, entry.envelope),
        '--policy', join(evidence, entry.policy),
        '--trust', join(evidence, entry.trust),
        '--attempt', entry.attempt,
        '--commit', entry.commit,
        '--artifact', join(evidence, entry.artifact),
        '--evidence', join(evidence, entry.evidence),
        '--json',
      ];
      if (entry.pr !== null && entry.pr !== undefined) args.push('--pr', String(entry.pr));
      try {
        return { status: 0, out: execFileSync(command[0], args, { cwd: consumer, encoding: 'utf8', stdio: 'pipe' }) };
      } catch (error) {
        return { status: error.status, out: String(error.stdout ?? '') };
      }
    };

    const positive = runVerify(cases[0]);
    assert.equal(positive.status, 0, `a valid review was refused in the clean room: ${positive.out}`);
    assert.equal(JSON.parse(positive.out).ok, true);

    // 8a. THE README'S INVOCATION, as written. `npx @digital-pulse-hq/quorum` must resolve to the
    //     copy this project installed, never to the registry — `--offline` makes a registry fetch a
    //     failure here instead of a silent download. The scoped name is the point: the bare `quorum`
    //     on npm belongs to someone else, so outside an installed project `npx quorum` runs theirs.
    const viaNpx = runVerify(cases[0], ['npx', '--offline', '@digital-pulse-hq/quorum']);
    assert.equal(viaNpx.status, 0, `the README's npx invocation did not run the installed package: ${viaNpx.out}`);
    assert.equal(JSON.parse(viaNpx.out).ok, true);

    // THE ACCEPTANCE TEST, run through an installed package rather than an in-repo import.
    const trailers = cases.slice(1);
    assert.ok(trailers.length >= 3, `expected the trailer-table fixtures, found ${trailers.length}`);
    for (const entry of trailers) {
      const result = runVerify(entry);
      assert.equal(result.status, 1, `${entry.name} was not refused in the clean room: ${result.out}`);
      assert.equal(JSON.parse(result.out).guard, entry.expect.guard, `${entry.name} named the wrong guard in the clean room`);
    }

    // 9. R3: the DOCUMENTED CI RUNNER must be in the box, not just in the README.
    // The npm `files` allow-list previously excluded `ci/`, so a fresh install contained the
    // verifier and no `required-check.mjs` at all, while README's "What is in the box" listed it.
    // This exercises it in GATE mode from the installed package: gate mode cannot read `expect`,
    // so a declared negative is not a way to pass.
    const gateBin = join(consumer, 'node_modules', '.bin', 'quorum-required-check');
    assert.ok(existsSync(gateBin), 'the documented CI runner was not shipped in the package');

    const gateManifest = (entry) => ({
      schema: 'quorum-manifest/1',
      cases: [{
        name: entry.name,
        envelope: join(evidence, entry.envelope),
        policy: join(evidence, entry.policy),
        trust: join(evidence, entry.trust),
        artifact: join(evidence, entry.artifact),
        evidence: join(evidence, entry.evidence),
        attempt: entry.attempt,
        commit: entry.commit,
        pr: entry.pr ?? null,
      }],
    });
    const runGate = (manifest) => {
      const path = join(consumer, 'gate-manifest.json');
      writeFileSync(path, JSON.stringify(manifest, null, 2));
      try {
        return { status: 0, out: execFileSync(gateBin, ['--manifest', path, '--mode', 'gate'], { cwd: consumer, encoding: 'utf8', stdio: 'pipe' }) };
      } catch (error) {
        return { status: error.status, out: String(error.stdout ?? '') + String(error.stderr ?? '') };
      }
    };

    // Genuine positive: a real signed review passes the gate from a clean install.
    const gatePass = runGate(gateManifest(cases[0]));
    assert.equal(gatePass.status, 0, `a valid review did not pass the installed gate: ${gatePass.out}`);

    // Negative: a real trailer fixture is refused rather than scored as an expected refusal.
    const gateFail = runGate(gateManifest(cases[1]));
    assert.equal(gateFail.status, 1, `the installed gate accepted ${cases[1].name}: ${gateFail.out}`);

    // 10. Deletion, in the clean room: remove the envelope and the check must fail, not skip.
    rmSync(join(evidence, cases[0].envelope));
    const deleted = runVerify(cases[0]);
    assert.equal(deleted.status, 1, 'deleting the envelope did not fail the check');
    assert.equal(JSON.parse(deleted.out).guard, 'Q00_INPUT_PRESENT');

    // A MISSING review is the condition the original review named first, so the gate must refuse it too.
    const gateMissing = runGate(gateManifest(cases[0]));
    assert.equal(gateMissing.status, 1, `the installed gate passed with the envelope deleted: ${gateMissing.out}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

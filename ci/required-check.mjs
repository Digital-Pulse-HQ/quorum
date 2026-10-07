#!/usr/bin/env node
// The required check.
//
// The smallest non-ceremonial increment of this protocol ends with one required check that fails when
// the envelope is absent, stale, mutated, untrusted, or same-family. This is that check, and all five
// conditions are committed cases in the manifest it reads.
//
// It is a MANIFEST RUNNER, not a fixture script, and it runs in exactly one of TWO modes, because a single
// mode once conflated these two contracts:
//
//   --mode conformance   reads a quorum-fixtures/1 manifest (see quorum/fixtures/index.json). Each
//                         case declares its own `expect`, and a declared refusal is a passing case.
//                         This is the only mode that may score a negative expectation, and it is the
//                         only mode CI ever points at a fixture manifest.
//   --mode gate           reads a quorum-manifest/1 manifest — a DIFFERENT schema token, validated
//                         against schema/quorum-manifest-1.schema.json, whose case shape has no room
//                         for `expect` or `kind` at all (additionalProperties: false). Every case must
//                         return result.ok === true or the whole check fails. There is no way to
//                         express "this case is expected to be refused" in this mode; a manifest that
//                         tries is refused by the schema before any case is even verified.
//
// Before this split, one manifest format served both purposes: a one-case manifest naming an absent
// envelope with `expect: { ok: false, guard: "Q00_INPUT_PRESENT" }` exited 0 and printed
// "1/1 cases behaved as required" — correct for a conformance fixture, and a contributor's missing,
// stale, untrusted or same-family review turned into a green production gate. Gate mode cannot be
// fooled this way: it does not read `expect` at all, so a declared negative case is not a way to pass.
//
// WHAT IT DOES NOT DO, said plainly rather than implied by its name: it ships no enrolled keys and gates
// nothing until a deployment enrols real ones. Private-key isolation and public-key enrolment are the
// deploying organisation's decision. Until that exists there is no honest real-evidence manifest to
// point gate mode at, and doing so with synthetic evidence would be the ceremony this whole increment
// is a response to.

import { readFileSync, realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyEnvelope } from '../src/verify.mjs';
import { compileSchema, validate } from '../src/schema.mjs';

const GATE_SCHEMA_TOKEN = 'quorum-manifest/1';
const CONFORMANCE_SCHEMA_TOKEN = 'quorum-fixtures/1';
const MODES = Object.freeze(['conformance', 'gate']);

// Read with readFileSync + JSON.parse, not an import attribute: the same loading style src/verify.mjs
// uses for its own schemas, and it does not depend on which import-attribute syntax a given Node
// >=20.11 build happens to accept. Compiled at import, same discipline as src/verify.mjs: an
// unimplemented keyword in this schema is a startup failure, never a constraint that quietly
// evaluates to true when a manifest is checked.
const schemaPath = fileURLToPath(new URL('../schema/quorum-manifest-1.schema.json', import.meta.url));
const GATE_MANIFEST_SCHEMA = compileSchema(JSON.parse(readFileSync(schemaPath, 'utf8')), '#quorum-manifest-1.schema.json');

function readOrNull(path, encoding) {
  try { return readFileSync(path, encoding); } catch { return null; }
}

// `mode` has NO DEFAULT, on the exported function and not only on the CLI.
// `{ mode = 'conformance' } = {}` left the pre-split call shape `runManifest(path)` working and
// silently conformance-scored — the mode in which a declared refusal is a passing case. A caller
// written against the old single-mode API therefore still turned an absent, stale, untrusted or
// same-family review into a green result, which is the exact conflation the two-mode split
// exists to end. The CLI is one entry point; the contract belongs on the function both entry points share.
export function runManifest(manifestPath, { mode } = {}) {
  if (mode === undefined) {
    throw new Error(`runManifest requires an explicit mode: one of ${MODES.join(', ')}. There is no default, because conformance mode scores a declared refusal as a pass and no entry point may choose that on a caller's behalf`);
  }
  if (!MODES.includes(mode)) {
    throw new Error(`unknown mode ${JSON.stringify(mode)}: must be one of ${MODES.join(', ')}`);
  }
  const root = dirname(resolve(manifestPath));
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

  if (mode === 'gate') {
    if (manifest.schema !== GATE_SCHEMA_TOKEN) {
      throw new Error(`gate mode requires a ${GATE_SCHEMA_TOKEN} manifest, got ${JSON.stringify(manifest.schema)} — a fixture/conformance manifest, or anything else, is never merge-gate input`);
    }
    const shape = validate(GATE_MANIFEST_SCHEMA, manifest);
    if (!shape.ok) {
      throw new Error(`manifest does not satisfy ${GATE_SCHEMA_TOKEN}: ${shape.errors.join('; ')}`);
    }
  } else if (manifest.schema !== CONFORMANCE_SCHEMA_TOKEN) {
    throw new Error(`conformance mode requires a ${CONFORMANCE_SCHEMA_TOKEN} manifest, got ${JSON.stringify(manifest.schema)}`);
  }

  // `resolve`, not `join`: a manifest may name absolute paths, and join would graft them onto
  // the manifest directory and then report the resulting miss as an absent envelope.
  const at = (rel) => (rel ? resolve(root, rel) : null);

  const results = [];
  for (const entry of manifest.cases) {
    const result = verifyEnvelope({
      envelopeText: readOrNull(at(entry.envelope), 'utf8'),
      policyText: readOrNull(at(entry.policy), 'utf8'),
      trustText: readOrNull(at(entry.trust), 'utf8'),
      expected: { attemptId: entry.attempt, commit: entry.commit, pr: entry.pr ?? null },
      artifactBytes: entry.artifact ? readOrNull(at(entry.artifact)) : null,
      evidenceBytes: entry.evidence ? readOrNull(at(entry.evidence)) : null,
    });
    if (mode === 'gate') {
      // No `expect` exists in this mode's schema: the only accepted outcome is a real ok:true.
      results.push({
        name: entry.name, ok: result.ok === true, expected: { ok: true }, actual: { ok: result.ok, guard: result.guard }, why: result.why,
      });
    } else {
      const wanted = entry.expect;
      const ok = wanted === undefined
        ? result.ok
        : result.ok === wanted.ok && (wanted.ok || result.guard === wanted.guard);
      results.push({
        name: entry.name, ok, expected: wanted, actual: { ok: result.ok, guard: result.guard }, why: result.why,
      });
    }
  }
  return results;
}

export function main(argv = process.argv.slice(2), io = process) {
  const manifestIndex = argv.indexOf('--manifest');
  const modeIndex = argv.indexOf('--mode');
  if (manifestIndex === -1 || argv[manifestIndex + 1] === undefined || modeIndex === -1 || argv[modeIndex + 1] === undefined) {
    io.stderr.write(`usage: required-check.mjs --manifest <path> --mode ${MODES.join('|')}\n`);
    return 2;
  }
  const mode = argv[modeIndex + 1];
  if (!MODES.includes(mode)) {
    io.stderr.write(`required-check.mjs: --mode must be one of ${MODES.join(', ')}, got ${JSON.stringify(mode)}\n`);
    return 2;
  }
  let results;
  try {
    results = runManifest(argv[manifestIndex + 1], { mode });
  } catch (error) {
    io.stderr.write(`REQUIRED CHECK COULD NOT RUN: ${error.message}\n`);
    return 1; // "we could not check" is a failure, never a pass.
  }

  const failures = results.filter((entry) => !entry.ok);
  for (const entry of failures) {
    const want = entry.expected === undefined ? 'PASS' : (entry.expected.ok ? 'PASS' : `refusal by ${entry.expected.guard}`);
    const got = entry.actual.ok ? 'PASS' : `refusal by ${entry.actual.guard}`;
    io.stderr.write(`::error title=quorum required check::${entry.name}: expected ${want}, got ${got} — ${entry.why}\n`);
  }
  const passed = results.length - failures.length;
  io.stdout.write(`quorum required check: ${passed}/${results.length} cases behaved as required\n`);
  if (results.length === 0) {
    io.stderr.write('::error title=quorum required check::the manifest contained no cases — an empty gate is not a green one\n');
    return 1;
  }
  return failures.length === 0 ? 0 : 1;
}

// R3. This guard decided whether the gate runs at all, and it was a filename comparison:
// `process.argv[1].endsWith('required-check.mjs')`. npm installs this as the bin `quorum-required-
// check`, so argv[1] is `node_modules/.bin/quorum-required-check` -- which does not end in
// `required-check.mjs`. The guard was false, `main()` never ran, and the process exited 0 having
// verified NOTHING. A merge gate that silently reports success is worse than one that is absent.
//
// `bin/quorum.mjs` already carries this exact fix and says so in its own comment; this file was
// never shipped in the npm `files` allow-list, so no installed run ever exercised it and the
// defect could not be observed. Resolve both sides through realpath, so a symlinked bin matches.
if (process.argv[1] !== undefined
    && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(main());
}

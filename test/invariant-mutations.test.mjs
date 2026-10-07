// A SECOND MUTATION FAMILY, deliberately unlike the first.
//
// delete-guards.test.mjs neuters guard CONDITIONS — the shape a refusal takes. It cannot detect a
// weakness in the machinery those refusals rest on, because every guard still fires: canonicalisation
// that does not canonicalise, a signature string with four equivalent forms, a payload builder that
// signs one field set and verifies another, a schema evaluator that ignores what it does not
// implement, a digest check that passes when there was nothing to check against, and — the classic —
// a binding that reads the record to check the record.
//
// Each mutation below was run before its test existed. The ones that SURVIVED are why these tests
// are here; a mutation family chosen to match the tests already written proves nothing.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { copyPackage } from './helpers/copy-package.mjs';

const PACKAGE = fileURLToPath(new URL('../', import.meta.url));

const MUTATIONS = Object.freeze([
  {
    id: 'M1_CANONICAL_KEY_SORT',
    file: 'src/canonical.mjs',
    find: 'const keys = Object.keys(value).sort();',
    replace: 'const keys = Object.keys(value);',
    why: 'canonicalisation stops being canonical; two implementations sign different bytes for the same record',
    expect: 'canonical form is independent of key insertion order',
  },
  {
    id: 'M2_SIGNATURE_STRING_UNIQUENESS',
    file: 'src/verify.mjs',
    find: "  if (bytes.toString('base64') !== signature.value) return false;",
    replace: '',
    why: 'one signature gains four equivalent strings, so one envelope gains four digests that all verify',
    expect: 'a re-encoded signature string is not a second valid form of the same envelope',
  },
  {
    id: 'M3_COUNTERSIGNATURE_COVERAGE',
    file: 'src/envelope.mjs',
    find: '  const { signatures, ...rest } = envelope;',
    replace: '  const { signatures, review, ...rest } = envelope;',
    why: 'the verdict leaves the signed payload — symmetrically, so every valid envelope still verifies and only tampering goes undetected',
    expect: 'the countersignature covers the verdict in an envelope this build signed',
  },
  {
    id: 'M4_SCHEMA_KEYWORD_ALLOWLIST',
    file: 'src/schema.mjs',
    find: '      throw new SchemaError(`unsupported schema keyword ${JSON.stringify(keyword)} at ${path}: this evaluator refuses to ignore it`);',
    replace: '      continue;',
    why: 'a constraint written in a shipped schema evaluates to nothing while reading as enforced',
    expect: 'an unimplemented schema keyword is a startup failure, not a silent non-constraint',
  },
  {
    id: 'M5_ADDITIONAL_PROPERTIES',
    file: 'src/schema.mjs',
    find: '    if (schema.additionalProperties === false) {',
    replace: '    if (false) {',
    why: 'unknown fields enter a signed payload',
    expect: 'unknown properties in a signed payload are rejected by the schema evaluator',
  },
  {
    id: 'M6_ATTEMPT_READ_FROM_RECORD',
    file: 'src/verify.mjs',
    find: 'envelope.attempt_id !== expected.attemptId',
    replace: 'envelope.attempt_id !== envelope.attempt_id',
    why: 'THE SELF-REFERENTIAL FAIL-OPEN: the record is checked against itself, so every stale review passes',
    expect: 'guard Q06_ATTEMPT_BINDING refuses stale-attempt',
  },
  {
    id: 'M7_DIGEST_WITH_NOTHING_TO_COMPARE',
    file: 'src/verify.mjs',
    find: 'const digestOk = artifactSources.length > 0 && artifactSources.every',
    replace: 'const digestOk = artifactSources.every',
    why: '`[].every()` is true, so supplying no artifact at all becomes a pass — "could not check" reported as "checked"',
    expect: 'a verification with nothing to recompute the artifact digest against is refused',
  },
  {
    id: 'M8_ENROLLED_PRINCIPAL',
    file: 'src/verify.mjs',
    find: '  if (key.principal !== party.principal) {',
    replace: '  if (false) {',
    why: 'any enrolled key may sign for any principal, so identity returns to being a string the signer chose',
    expect: 'identity comes from the enrolment, never from the envelope\'s claim about itself',
  },
  {
    id: 'M9_TRUST_KEY_MATERIAL_DEDUP',
    file: 'src/verify.mjs',
    find: '    if (collidesWith !== undefined) {',
    replace: '    if (false) {',
    why: 'one Ed25519 key enrolled under two identities on opposite sides of a review lets that single private key self-approve, because Q16 only ever compares the two family STRINGS and both remain genuinely unequal. This neuters only the fingerprint-collision branch, leaving the pre-existing duplicate key_id check intact, so a survival here is specifically about the new material check and not a rebuild of the older one.',
    expect: 'REPRODUCTION: one private key enrolled on both sides of a review self-approves',
  },
  {
    // THE ONLY MULTI-EDIT MUTATION, and it has to be. The unsafe-integer wire ambiguity is closed by two independent
    // checks and either one alone still refuses the fixture, so a single-file mutant here would be
    // killed by the surviving check and would prove nothing about the other. This removes both and
    // reconstitutes the pre-fix semantics exactly: `Number.isInteger` in the canonical form, and no
    // maximum on `review.pr`. The committed legacy-signed fixture then verifies — which is what it
    // did under the real pre-fix verifier, so the mutant is not a hypothetical.
    id: 'M10_UNSAFE_INTEGER_WIRE_AMBIGUITY',
    edits: [
      {
        file: 'src/canonical.mjs',
        find: '    if (!Number.isSafeInteger(value)) {',
        replace: '    if (!Number.isInteger(value)) {',
      },
      {
        file: 'schema/quorum-envelope-1.schema.json',
        find: '          "minimum": 1,\n          "maximum": 9007199254740991\n',
        replace: '          "minimum": 1\n',
      },
    ],
    why: 'without both bounds a review.pr at 2^53 signs successfully and its wire token can be rewritten to 2^53+1 with no resigning, giving one reviewer signature two valid wire texts that no signature check can separate',
    expect: 'REPRODUCTION: a legacy-signed unsafe review.pr and its no-resign adjacent rewrite are both refused',
  },
]);

/** Single-edit mutations are the common case; `edits` is the general form. */
const editsOf = (mutation) => mutation.edits ?? [{ file: mutation.file, find: mutation.find, replace: mutation.replace }];

function tapFailures(output) {
  return output
    .split('\n')
    .filter((line) => /^not ok \d+ - /.test(line.trim()))
    .map((line) => line.trim().replace(/^not ok \d+ - /, ''));
}

test('MUTATION TEST: every machinery mutation reddens its named test', {
  skip: process.env.QUORUM_MUTATION_CHILD === '1' ? 'mutation child' : false,
  timeout: 300_000,
}, () => {
  for (const mutation of MUTATIONS) {
    const edits = editsOf(mutation);
    const originals = new Map();
    for (const edit of edits) {
      const original = readFileSync(join(PACKAGE, edit.file), 'utf8');
      const before = original.split(edit.find).length - 1;
      assert.equal(before, 1, `${mutation.id}: its target occurs ${before} times in ${edit.file}, expected exactly 1`);
      originals.set(edit.file, original);
    }

    const dir = mkdtempSync(join(tmpdir(), `quorum-mutate-${mutation.id}-`));
    try {
      copyPackage(PACKAGE, dir);
      for (const edit of edits) {
        writeFileSync(join(dir, edit.file), originals.get(edit.file).replace(edit.find, edit.replace));
      }

      // Verify EVERY edit LANDED before trusting what their absence would mean. A multi-edit
      // mutation that silently applied only one of its edits is the exact shape of a mutant that
      // dies for the wrong reason and reports as killed.
      for (const edit of edits) {
        const written = readFileSync(join(dir, edit.file), 'utf8');
        assert.equal(written.split(edit.find).length - 1, 0, `${mutation.id}: the original text survived in ${edit.file}`);
        assert.notEqual(written, originals.get(edit.file), `${mutation.id}: ${edit.file} is byte-identical to the original`);
      }

      const childEnv = { ...process.env, QUORUM_MUTATION_CHILD: '1' };
      delete childEnv.NODE_TEST_CONTEXT;
      let status = 0;
      let output = '';
      try {
        output = execFileSync(
          process.execPath,
          [
            '--test', '--test-reporter=tap',
            './test/guards.test.mjs',
            './test/invariants.test.mjs',
            './test/duplicate-key-material.test.mjs',
            './test/legacy-signed-collision.test.mjs',
          ],
          { cwd: dir, env: childEnv, encoding: 'utf8', stdio: 'pipe' },
        );
      } catch (error) {
        status = error.status;
        output = String(error.stdout ?? '') + String(error.stderr ?? '');
      }

      assert.notEqual(status, 0, `${mutation.id} survived: ${mutation.why}`);
      assert.ok(
        tapFailures(output).includes(mutation.expect),
        `${mutation.id} reddened, but not through ${JSON.stringify(mutation.expect)}. TAP failures: ${JSON.stringify(tapFailures(output))}`,
      );
      process.stdout.write(`mutation ok: ${mutation.id} -> ${mutation.expect}\n`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

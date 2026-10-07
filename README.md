# Quorum

**An evidence protocol for multi-agent organisations.** A portable, fail-closed verifier for signed
cross-family review envelopes.

Quorum answers one question from committed artefacts alone, with no orchestration tool installed:

> Was this artifact independently reviewed by a principal of a **different model family**, under a
> named policy, with a verdict that has not been altered since it was given?

Zero dependencies. Node 20.11+. Apache-2.0.
The gate runs no model and holds no credential, and `test/shipped-surface.mjs` enforces that
default-deny rather than by a list of forbidden spellings — see SPEC.md §8.

```bash
npm install --save-dev @digital-pulse-hq/quorum

npx @digital-pulse-hq/quorum verify \
  --envelope  review.json \
  --policy    policy.json \
  --trust     trust.json \
  --attempt   attempt:0d1f... \
  --commit    69e9e91... \
  --artifact  patch.diff \
  --evidence  findings.md \
  --pr        42
```

Exit `0` only when everything checks. Exit `1` on any refusal, including "there was nothing to
check". `--json` prints the machine-readable result with the guard that refused.

## Install

1. **Check Node.** `node --version` must report 20.11 or later. Nothing else is needed: the package
   has no dependencies, so the install resolves nothing beyond itself.
2. **Install it into the repository whose reviews you want to gate**, as a dev dependency:

   ```bash
   npm install --save-dev @digital-pulse-hq/quorum
   ```

3. **Run it through `npx` with the scoped name**, as above. `npx @digital-pulse-hq/quorum` runs the
   copy you just installed. Do not shorten it to `npx quorum`: that only finds this package inside a
   project that has installed it. Anywhere else, `npx` fetches the unrelated, unscoped `quorum`
   package from npm and runs that instead.
4. **Watch it refuse things before you trust it to pass things.** The package ships its own suite and
   fixture corpus, so from your project root:

   ```bash
   cd node_modules/@digital-pulse-hq/quorum
   npm test
   node ci/required-check.mjs --manifest fixtures/index.json --mode conformance
   ```

   Both exit `0` only when every adversarial fixture is refused by the guard it names and every
   positive control passes. The suite packs and installs a copy of itself into a temporary directory,
   so it needs `npm` on `PATH`.
5. **Generate keys and write a policy.** `npx @digital-pulse-hq/quorum keygen` creates a key pair. The
   envelope, policy and trust-store formats are specified in `SPEC.md` and validated by the schemas in
   `schema/`. Worked, synthetic examples: policies and trust stores under `fixtures/shared/`, envelopes
   that pass under `fixtures/positive/`.

## Why this exists

A review trailer that sits outside every signature is metadata, not evidence. The verifier this
package replaces authenticated only the *producer*; an adversarial probe with a valid producer
attestation carried all three of these to `PASS`:

| verdict | reviewer | pr |
|---|---|---|
| `APPROVE` | `reviewer-b (codex)` | `42` |
| `SELF APPROVED` | `same-family producer` | `not-a-pr` |
| `CHANGES` | `untrusted-free-text` | `999999` |

All three are committed adversarial fixtures here, and each is refused by a named guard. They are
then repaired one defect at a time so the refusal is attributable to the trailer's own defect and not
to something incidental — row 1, repaired, **passes**.

## What is in the box

| | |
|---|---|
| `SPEC.md` | the `quorum/1` envelope, the policy, the trust store, and all 21 guards |
| `schema/` | the JSON Schemas, evaluated directly by `src/schema.mjs` — not documentation of a separate validator |
| `bin/quorum.mjs` | `keygen`, `new-attempt`, `attest-producer`, `attest-review`, `verify`, `render` |
| `ci/required-check.mjs` | a manifest runner with two modes: `--mode conformance` (fixtures, `expect` scored) and `--mode gate` (real evidence, every case must be a genuine `ok:true`, no `expect` field exists in its schema) |
| `fixtures/` | 42 cases — positive controls, the three trailers above, mutation and deletion controls; every key is derived from a committed phrase and every principal is under the reserved `example.invalid` domain, so the corpus names no real person, organisation or agent |
| `test/` | the suite described under Testing, shipped so a consumer can run the refusals rather than take them on report |
| `tools/make-fixtures.mjs` | the fixture generator; the drift test re-runs it and fails on any hand-edited fixture |

## Entry points

A consumer imports the package by exactly these specifiers, and only these:

- `@digital-pulse-hq/quorum` — the verifier API (`src/index.mjs`);
- `@digital-pulse-hq/quorum/schema/quorum-envelope-1.schema.json`, `…/quorum-manifest-1.schema.json`,
  `…/quorum-policy-1.schema.json` and `…/quorum-trust-1.schema.json` — the schemas, as JSON;
- the `quorum` and `quorum-required-check` commands.

The schemas are four explicit exports, not a `./schema/*.json` pattern. A pattern lets a request that
Node's URL parser rewrites — a percent-encoded name such as `schema/%71uorum-envelope-1.schema.json`,
a tab, a trailing `#` or `?` — reach files the request does not name, so it is deliberately not
offered: those spellings fail with `ERR_PACKAGE_PATH_NOT_EXPORTED`. The canonical specifiers above are
pinned literally by `test/clean-project.test.mjs`, through both `require` and `import`, as is the
refusal of the encoded spellings.

## The three properties worth knowing

**The reviewer countersigns everything.** A producer cannot sign a verdict it has not received, so
the producer signs the artifact and its own identity, and the reviewer signs the whole envelope
*including the producer's signature bytes*. Reviewer identity, verdict, PR binding and evidence
digest cannot move without breaking that signature.

**Trust level is a first-class versioned field.** `family_trust` is `declared` or `observed`, inside
both signatures. An envelope may not claim more than its enrolment carries, and a policy requiring
`observed` **fails closed** against `declared` evidence. A family that a principal's own operator
writes into a registry is a self-declaration, so it is `declared`, and an observed policy refuses it —
the honest outcome rather than a re-transcription of a self-declaration as proof.

**The commit is the record; a PR comment is a view.** `quorum render` emits a Markdown view carrying
a `NON-AUTHORITATIVE VIEW` banner and the envelope's digest. A comment is editable and deletable by
its author, so it can point at the record and never be it. A rendered comment is not accepted as
verifier input, and the suite asserts it never parses as one.

## Testing

```bash
npm test
```

`npm test` runs `test/run.mjs`, which names every `test/**/*.test.mjs` file explicitly rather than
handing `node --test` a glob: Node 20.11, the declared minimum, does not expand one.

Beyond the fixture matrix, three things run:

- **Delete tests.** Each of the 21 guards is neutered in a copy of the package and the suite re-run;
  the mutant is accepted as caught only when TAP reports *that guard's own test* as `not ok`.
- **A second, unlike mutation family.** Ten mutations of the machinery under the guards —
  canonicalisation, signature-string uniqueness, countersignature coverage, the schema keyword
  allow-list, `additionalProperties`, checking the record against itself, an empty `every()`, the
  enrolled-principal check, the enrolled key-material fingerprint dedup
  (`M9_TRUST_KEY_MATERIAL_DEDUP`), and the pair of bounds that close the unsafe-integer wire
  ambiguity (`M10_UNSAFE_INTEGER_WIRE_AMBIGUITY`, the one mutation that edits two files, because
  either bound alone still refuses). Several survived the delete tests, which is why the tests that
  catch them exist.
- **A clean-project install.** `npm pack`, then install into an empty directory with none of this
  repository's layout, assert that its `node_modules` holds this package and nothing else, run the
  installed binary's `--help`, load every entry point the manifest declares by the package name, run
  the conformance check, and verify and refuse fixtures with the installed binary. Running with no
  orchestration tool installed is the load-bearing claim, so it is executed rather than asserted.

### Release checks (contributors, from the source repository)

```bash
npm run release:check
```

The publisher's packaging gates live in `release-checks/`, which is **not** in the package and which
`npm test` never runs: they judge the package a consumer receives, from the repository that publishes
it, over the exact file list `npm pack --dry-run --json` reports. They refuse a packed file that
carries a real identity of the developing organisation; a packed file that mentions Node's private
internals at all; any packed file not on the release allow-list (`release-checks/packed-list.mjs`),
whatever its extension or lack of one, because the allow-list names exactly what ships and admits code
only as `.mjs`; any `main`, `bin`, `exports` or `imports` target that is not a scanned `.mjs` module
(exported JSON excepted, which Node loads only as data); a packed `.mjs` module with a static import or export-from specifier that reaches outside the package, or that uses one of the listed
syntactic forms of dynamic loading; and any release-only file appearing in the packed list. The import
scan is syntactic: computed or aliased access is outside it, and it cannot establish that no code loads
anything at run time (`release-checks/import-scan.mjs` states exactly what it does verify). It
relies on a parser private to Node, which is why it is a release check and not part of the shipped
suite. In an installed copy `release-checks/` does not exist and `npm run release:check` fails.

## Status

This is the first implemented increment: the kernel — one signed envelope, one standalone
fail-closed verifier, one clean-project fixture, one required check. It ships **no** enrolled keys
and gates nothing until a deployment enrols real ones; private-key isolation and public-key
enrolment are the deploying organisation's decision. Adapters and product surfaces follow the kernel, not the
other way round.

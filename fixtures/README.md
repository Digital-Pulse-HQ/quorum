# Fixtures

Generated. Do not hand-edit — `npm run fixtures`, and `test/fixtures.test.mjs` regenerates into a
temporary directory and diffs, so an edit made to turn a test green is caught as drift.

`index.json` is a `quorum-fixtures/1` manifest: every case names an envelope, a policy, a trust store,
the commissioned attempt/commit/pr, the artifact and evidence documents, and the outcome required
(`expect`). `ci/required-check.mjs --mode conformance` reads exactly this format and schema token.

A `quorum-fixtures/1` manifest is conformance input only. It is a DIFFERENT, and
deliberately incompatible, schema token from `quorum-manifest/1`, the merge-gate format
`--mode gate` reads — whose case shape has no `expect` field at all, so a declared refusal can never
be the required outcome there. See the header comment in `ci/required-check.mjs` for the full
rationale.

## No private key material is committed

Every fixture key is derived at generation time from a committed English phrase — `SHA-256(phrase)`
wrapped in the fixed PKCS#8 prefix for Ed25519. The repository holds public keys, signatures and the
phrases; the private halves are reproducible by anyone and stored by nobody. Ed25519 signing is
deterministic, which is what makes regeneration byte-identical.

`test/fixtures.test.mjs` asserts that no `-----BEGIN … PRIVATE KEY-----` block exists anywhere in the
package.

## Every identity is synthetic

Principals are under the RFC 2606 / RFC 6761 reserved `example.invalid` domain, and key ids name a
role and a letter (`producer-a-claude`, `reviewer-b-codex`, …). Nothing in the corpus names a real
person, organisation, agent or review record.

## The `observed` enrolments

`producer-e-observed` and `reviewer-d-gemini` are enrolled with `family_evidence: "observed"`.
They exist so the trust level is exercised in the passing direction as well as the failing one. A
field that can only ever refuse has never been shown to mean anything, and the pair
`observed-enrolment-under-observed-policy` (passes) / `declared-under-observed-policy` (refused by
`Q15_TRUST_POLICY`) is the same request at the two evidence levels.

## The trailer table

Eight cases carry `origin: "trailer table, …"`. Three reproduce the three review trailers that a
producer-only verifier carried to PASS (the table in the package README); the rest repair them one defect at a time so that each refusal is attributable to a single
cause. `trailer-1-repaired-identity` **passes** — that is what proves the first refusal was
about the untrusted principal and nothing else.

## `duplicate-key-material-self-approval`

`dual-enrolled-producer-key` and `dual-enrolled-reviewer-key` in `shared/trust-duplicate-key-material.json` are the SAME
Ed25519 key, enrolled twice — once as claude/producer, once as codex/reviewer — with the second
enrolment's PEM re-wrapped with CRLF line endings so the two enrolments differ as text while decoding
to identical key bytes. The envelope signs both halves with that one private key. See
`test/duplicate-key-material.test.mjs` for the live reproduction and
`test/invariant-mutations.test.mjs`'s `M9_TRUST_KEY_MATERIAL_DEDUP` for the proof that the check is
load-bearing.

## `pr-at-max-safe-integer-boundary`, `unsafe-integer-pr-legacy-signed`, `unsafe-integer-pr-adjacent-rewrite`

`review.pr` is bounded at `Number.MAX_SAFE_INTEGER`. The boundary value itself must still pass, which
is `pr-at-max-safe-integer-boundary`.

The defect is that 2^53 (`9007199254740992`) and 2^53+1 (`9007199254740993`) are two different
decimal tokens that `JSON.parse` collapses onto one double, so before the bound existed a single
reviewer signature had two valid wire texts. **Reproducing that requires a signature made over the
unsafe value, which the shipped canonical form cannot produce** — `tools/make-fixtures.mjs` therefore
carries an explicit legacy-canonical signing helper reconstructing the pre-fix number branch.
`unsafe-integer-pr-legacy-signed.json` is countersigned that way at 2^53;
`unsafe-integer-pr-adjacent-rewrite.json` is the same file with that one token rewritten to 2^53+1
and **nothing resigned**. Both verified PASS under the pre-fix verifier; both are now
refused by `Q02_ENVELOPE_SCHEMA` before any signature is examined.

The rewrite is a TEXT substitution rather than an edit of the parsed object, because the parsed
object cannot express two different decimal tokens that collapse to one double.

**A superseded fixture named `unsafe-integer-pr-adjacent.json` was removed here.** It signed
`review.pr` at `9007199254740991` and substituted `9007199254740993` — two different doubles, so it
was an ordinary changed-value signature failure (`Q12_REVIEWER_SIGNATURE` under the pre-fix verifier)
carrying the name and description of a collision it did not reproduce. See
`test/legacy-signed-collision.test.mjs` for the live reproduction and
`test/invariant-mutations.test.mjs`'s `M10_UNSAFE_INTEGER_WIRE_AMBIGUITY` for the proof that both
bounds are load-bearing.

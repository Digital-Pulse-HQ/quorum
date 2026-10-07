# Quorum `quorum/1` — the review envelope, the policy, and the trust store

**Status:** first implemented increment. Normative for this package.

Quorum answers exactly one question, from committed artefacts alone and without any orchestration
tool installed:

> Was this artifact independently reviewed by a principal of a different model family, under a named
> policy, with a verdict that has not been altered since it was given?

Anything the answer does not need is out of scope. In particular Quorum does not orchestrate
candidates, manage worktrees, parse harness output, route by capacity or rotate accounts.

## 1. Documents

| document | schema token | what it is |
|---|---|---|
| review envelope | `quorum/1` | the record: one review of one artifact, doubly signed |
| policy | `quorum-policy/1` | the trust decisions a verifier applies |
| trust store | `quorum-trust/1` | enrolled public keys, and what each enrolment evidences |

JSON Schemas for all three are in `schema/`. They are not documentation of a separately hand-written
validator — `src/schema.mjs` evaluates these files directly, and it **throws** on any schema keyword
it does not implement, so a constraint cannot read as enforced while enforcing nothing.

The package's import surface is the main entry and the four schema files by their canonical names
(README, "Entry points"). It exports no subpath pattern, so URL-encoded or otherwise rewritten
spellings of those names are not part of the contract and are refused.

## 2. Canonical form

Signatures cover the **canonical JSON** of a payload, not the bytes on the wire: object keys sorted
by UTF-16 code unit, no insignificant whitespace. A transport that parses and re-emits the envelope —
a ledger, a database, a bot — therefore does not invalidate a valid review, while any change to a
**value** does.

Constructs with more than one defensible encoding are refused rather than encoded arbitrarily:
non-integer and non-finite numbers, `undefined` properties, and lone surrogates. `-0` normalises
to `0`.

## 3. The envelope, and why it is signed twice

```jsonc
{
  "schema": "quorum/1",
  "policy_version": "quorum-policy/1@2026-09-10+<32 hex>",   // <label>+<content identity>
  "attempt_id": "attempt:<32 hex>",
  "artifact": { "kind": "git_commit", "commit": "<40|64 hex>", "digest": "sha256:<64 hex>" },
  "producer": { "principal": "...", "family": "claude", "family_trust": "declared", "key_id": "..." },
  "reviewer": { "principal": "...", "family": "codex",  "family_trust": "declared", "key_id": "..." },
  "review":   { "verdict": "APPROVE", "pr": 42, "evidence_digest": "sha256:<64 hex>" },
  "signatures": {
    "producer": { "algorithm": "ed25519", "value": "<base64>" },
    "reviewer": { "algorithm": "ed25519", "value": "<base64>" }
  }
}
```

A producer cannot sign a verdict it has not yet received, so one joint signature is impossible. A
producer-only signature is the defect this format closes: `reviewer`, `verdict` and `pr` outside every
signature, editable without invalidating anything. Quorum nests the two instead.

- **The producer signature** covers `schema`, `policy_version`, `attempt_id`, `artifact`, `producer`.
- **The reviewer signature** covers the entire envelope **except itself** — including the producer's
  signature bytes, the reviewer identity, the verdict, the PR binding and the evidence digest.

The reviewer payload is built by **subtraction** from the parsed envelope, not from a second list of
field names, so a field added to the schema is covered automatically rather than silently escaping
the signature. Signing and verifying call the same function; two independent field lists is how a
field comes to be signed and not checked, or checked and not signed.

## 4. Trust level is a first-class, versioned field

`family_trust` sits inside both signatures and takes one of two values, in this order:

- **`declared`** — asserted by the party it describes. A `model_family` field in a YAML registry is
  declared. It detects mistakes and misconfiguration; it does not survive a party motivated to
  misreport.
- **`observed`** — emitted by something other than the party it describes, at the time of the act,
  and carried in the artefact.

Two independent checks apply, because a trust level that is only ever a floor or only ever a ceiling
can be forged in one direction:

- **`Q14_TRUST_ENROLMENT`** — an envelope may not claim more than its enrolment carries. Each trust
  store key declares `family_evidence`; an envelope signed by a `declared` key may not assert
  `observed`. This is what stops a self-declaration being re-labelled as an observation inside an
  otherwise perfectly valid signed payload.
- **`Q15_TRUST_POLICY`** — a policy setting `require_family_trust: "observed"` **fails closed**
  against `declared` evidence.

**A self-declared family is `declared`.** A `model_family` field that a principal's own operator
writes into a registry is not observed by anyone else, so under an observed policy such reviews are
refused. That refusal is the correct behaviour and it is a committed fixture
(`declared-under-observed-policy`). Reaching `observed` requires every producing harness to emit an
attributable marker it did not author, which is a deployment change outside this specification.

## 5. What the verifier refuses, in order

| guard | refuses |
|---|---|
| `Q00_INPUT_PRESENT` | an absent envelope, policy or trust store, or a missing expected attempt/commit |
| `Q01_ENVELOPE_JSON` | an envelope that is not JSON |
| `Q02_ENVELOPE_SCHEMA` | unknown, missing or malformed envelope fields |
| `Q03_POLICY` | a policy that is not `quorum-policy/1`, including one with an unknown switch |
| `Q04_TRUST_STORE` | a duplicate key id, duplicate key material across enrolments, an unreadable PEM, a non-Ed25519 key |
| `Q20_POLICY_IDENTITY` | a policy document that does not hash to the identity its own `policy_version` declares, including one carrying no identity at all |
| `Q05_POLICY_VERSION` | an envelope produced under a policy the verifier was not handed |
| `Q06_ATTEMPT_BINDING` | a review of a different — typically earlier — producer attempt |
| `Q07_ARTIFACT_BINDING` | a review of a different commit |
| `Q08_ARTIFACT_DIGEST` | a digest that does not match, **and** having nothing to recompute against |
| `Q09_PRODUCER_ENROLMENT` | a producer that is not an enrolled producing principal of that family |
| `Q10_PRODUCER_SIGNATURE` | a producer signature that does not cover this attempt and artifact |
| `Q11_REVIEWER_ENROLMENT` | a reviewer that is not an enrolled reviewing principal of that family |
| `Q12_REVIEWER_SIGNATURE` | any alteration to reviewer identity, verdict, PR or the producer signature |
| `Q13_VERDICT` | a verdict token outside the policy's closed accepted set |
| `Q14_TRUST_ENROLMENT` | family trust claimed beyond what the enrolment evidences |
| `Q15_TRUST_POLICY` | family evidence below the policy's required level |
| `Q16_FAMILY_INEQUALITY` | `producer.family == reviewer.family` |
| `Q17_PR_BINDING` | a review bound to a different pull request, or none where the policy requires one |
| `Q18_EVIDENCE_BINDING` | a swapped or **deleted** review evidence document |
| `Q19_RESIDUE_DECLARATION` | a review that declares no residue under a policy that requires one — an **absent** residue block is not an empty one |

Guards run in the order listed, which is not the order of their numbers. `Q20_POLICY_IDENTITY` was
added with policy identity and runs sixth; renumbering the guards after it would re-point every guard id
cited in a review record or a committed fixture at a different check, so the number records when a
guard was introduced and the list order records when it runs. `test/guards.test.mjs` checks that
order against the `/* GUARD:... */` markers in `src/verify.mjs`.

Two refusal states, and the distinction is load-bearing:

- **`UNKNOWN`** — nothing was compared. Input absent, unparseable, or unattributable.
- **`INVALID`** — evidence was compared and rejected.

Both exit non-zero. Conflating them is how "the review never ran" comes to look like "the review
passed".

**Nothing is read from the record to check the record.** `attempt`, `commit`, artifact digest and
`pr` come from the caller that commissioned the review. `principal`, `family`, `roles` and the trust
ceiling come from the enrolment. The envelope's claims about itself are only ever the thing being
checked.

## 6. Transport: the commit is the record, a PR comment is a view

A PR comment is editable and deletable by its author; a committed object is not. They are therefore
**not** transport-equivalent, and the asymmetry is made explicit in the artefact rather than left to
convention.

`quorum render` emits a Markdown view carrying a `NON-AUTHORITATIVE VIEW` banner and the SHA-256
digest of the canonical envelope. A reader takes that digest, finds the committed envelope, and runs
`quorum verify` against it. An edited comment no longer names a resolvable digest; a deleted comment
leaves the committed envelope untouched. A rendered comment is not accepted as verifier input — it
does not parse as an envelope, and the test suite asserts that it never does.

## 7. The residue declaration — what the review could not settle

Adopted 2026-09-28 from [`disensor`](https://pypi.org/project/disensor/) (MIT), whose sharpest idea
is that the artifact a review leaves behind should be **what it could not settle, not a score**.
Before this, `review` carried a verdict, a PR and an evidence digest — every one of which a green
badge also has.

`review.residue` carries four required arrays:

| field | what it records |
|---|---|
| `undecided` | findings raised and left undecided — neither confirmed nor withdrawn |
| `refuted` | findings the **producer** refuted, each with the evidence that refuted it |
| `unsettled_by_execution` | what execution could not settle — tests that could not run, a CI that never started |
| `reviewer_limits` | what the reviewer did not look at, and why |

**An absent residue and an empty one are opposite claims, and the format must keep them apart.**
Absent means the reviewer never addressed what it could not settle. Empty means the reviewer
*asserts* there was nothing — a strong claim, inside the signed bytes, that can be held against them
later. So all four arrays are required inside the block while each may be empty, and
`residue-declared-empty` is a **positive** fixture sitting beside `residue-absent-under-requiring-policy`,
which is adversarial. Without both, "requires residue" would be indistinguishable from "requires a
non-empty residue", and a reviewer with genuinely nothing to declare could not produce a passing
envelope at all.

Residue sits **inside the signed review block** deliberately. Residue a third party could append
after signing would be worthless, because its whole value is that the reviewer committed to it.

Whether it is required is a policy decision: `require_residue_declaration` is a **mandatory** key in
the policy document, like every other `require_*`. There is no permissive default, because a policy
that is silent about residue is how a verdict quietly becomes a score again.

## 8. Dependencies

None. The package declares zero dependencies and imports only four `node:` builtins.
**The gate runs no model and holds no API key** — it validates an artifact already committed to the
repository, which is what lets a consumer run it offline with no credential and get the same verdict.

That property is enforced by `test/gate-is-model-free.test.mjs` rather than merely true, and the
enforcement is **default-deny** (an earlier review showed the previous forbidden-list version
missing a dynamic import, a `process.env` destructure and `optionalDependencies` while staying
green). `test/shipped-surface.mjs` audits every source file of the gate — every directory in
`package.json` `files` except `test/` and `tools/`, which ship so a consumer can run the suite and
regenerate the fixtures but which no gate entry point loads (a gate file importing from either is
itself refused) — and refuses:

- any module outside the allow-list `node:crypto`, `node:fs`, `node:path`, `node:url` and relative
  paths, by *any* form: static import, re-export, `import()`, `require()`;
- any environment read outside the `QUORUM_` namespace, including via destructuring;
- any dependency-bearing manifest field, matched by shape (`/dependencies/i`) so
  `optionalDependencies`, `peerDependencies` and `bundleDependencies` are covered, plus any lockfile
  or `node_modules`;
- network-capable globals and code-loading escapes — `fetch`, `WebSocket`, `eval`, `new Function`,
  `createRequire`;
- and **any construct the audit cannot read** — `import(someVariable)`, `process.env[expr]`, a rest
  destructure of `process.env` — because a form the checker cannot classify is a violation, not a
  pass. That rule is what stops the checker's blind spots from becoming the guard's.

`test/guard-coverage.test.mjs` plants each of those forms into a real copy of the
package and requires a *named* test to report `not ok`, with an unmutated-copy control. That it runs
with no orchestration tool installed is proved by `test/clean-project.test.mjs`, which packs a
tarball, installs it into an empty directory that contains none of this repository's layout, asserts
that the consumer's `node_modules` holds this package and nothing else, and runs the CLI there
against copied fixtures.

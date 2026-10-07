// Rendering a quorum/1 envelope as a PR comment — a VIEW, never the record.
//
// A PR comment is editable and deletable by its author, so it cannot be transport-equivalent to a
// committed record. Calling git commits and PR comments "transport views of the same record" is only
// safe if exactly one of them is authoritative. This module makes the asymmetry explicit in the artefact itself: every
// rendered comment carries the canonical envelope's digest and a banner saying it is not the record.
//
// The digest is the whole mechanism. A reader who wants assurance takes `envelope_digest` from the
// comment, finds the committed envelope with that digest, and runs `quorum verify` against it. If
// the comment has been deleted the committed envelope is untouched. Nothing here is ever an input
// to verification: `quorum verify` accepts an envelope, and a rendered comment does not parse as
// one.
//
// WHAT THE LOCATOR DOES NOT DO (R2). It does NOT detect edits to this comment. Earlier
// revisions of this file claimed "if the comment has been edited the digest no longer resolves"
// and "a comment that has been edited will not match it". Both were false: the digest is computed
// from the ENVELOPE, so editing the rendered verdict leaves it byte-identical and still resolving
// to the original record. That is not a weakness -- a view that cannot be trusted is exactly why
// the banner is here -- but stating it as a tamper guarantee promised something nothing enforced.
// The locator's job is to FIND the record, and the reader's job is to verify it.
//
// IT IS A CANONICAL-ENVELOPE LOCATOR, and that is now its byte contract: sha256 over
// `canonicalize(envelope)`. It was previously computed over `serializeEnvelope()`, which is
// `JSON.stringify(_, null, 2)` and therefore preserves key INSERTION ORDER. Reordering only the
// top-level keys of one signed envelope -- something any ledger, database or bot that re-emits
// JSON will do, and which the verifier accepts by design -- produced two different locators for
// the same record. Canonicalisation is what makes the identity stable across those transforms.

import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.mjs';

export const NON_AUTHORITATIVE_BANNER =
  'NON-AUTHORITATIVE VIEW — this comment renders a quorum/1 envelope. The envelope is the record; '
  + 'this comment is editable and deletable by its author and is not accepted as verification input.';

export function envelopeDigest(envelope) {
  return `sha256:${createHash('sha256').update(canonicalize(envelope), 'utf8').digest('hex')}`;
}

/**
 * @param {object} envelope a quorum/1 envelope
 * @param {{envelopePath?: string}} [options] where the authoritative copy is committed
 * @returns {string} Markdown suitable for a PR comment
 */
export function renderComment(envelope, options = {}) {
  const digest = envelopeDigest(envelope);
  const where = options.envelopePath ? `\`${options.envelopePath}\`` : 'the committed envelope';
  return [
    `> **${NON_AUTHORITATIVE_BANNER}**`,
    '',
    `### Quorum review — ${envelope.review.verdict}`,
    '',
    '| field | value |',
    '|---|---|',
    `| producer | \`${envelope.producer.principal}\` — family \`${envelope.producer.family}\` (${envelope.producer.family_trust}) |`,
    `| reviewer | \`${envelope.reviewer.principal}\` — family \`${envelope.reviewer.family}\` (${envelope.reviewer.family_trust}) |`,
    `| artifact | commit \`${envelope.artifact.commit}\`, digest \`${envelope.artifact.digest}\` |`,
    `| attempt | \`${envelope.attempt_id}\` |`,
    `| pr | ${envelope.review.pr === null ? '_not bound_' : envelope.review.pr} |`,
    `| policy | \`${envelope.policy_version}\` |`,
    `| envelope digest | \`${digest}\` |`,
    '',
    `Verify the record, not this comment: \`quorum verify --envelope ${options.envelopePath ?? '<path>'} --policy <policy> --trust <trust> --attempt ${envelope.attempt_id} --commit ${envelope.artifact.commit}\``,
    '',
    `The authoritative envelope is ${where}. Its digest is \`${digest}\`, which identifies the record regardless of how this comment is later edited — verify the envelope, not this text.`,
    '',
  ].join('\n');
}

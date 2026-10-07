// Canonical JSON serialisation for Quorum signed payloads.
//
// A signature over "the JSON" is meaningless unless two implementations agree byte-for-byte on what
// the JSON is. This is a deliberately small subset of RFC 8785 (JCS): object keys sorted by UTF-16
// code unit, no insignificant whitespace, and every construct that has more than one defensible
// encoding is REFUSED rather than encoded one way and hoped about.
//
// Refused on purpose, each because it is a place where two implementations diverge:
//   - non-integer and non-finite numbers (float formatting is where JCS implementations differ);
//   - integers outside Number.MAX_SAFE_INTEGER: above 2^53, adjacent decimal
//     integers such as 9007199254740992 and 9007199254740993 parse to the SAME IEEE-754 double, so a
//     signed payload would have two distinct wire tokens that canonicalise identically. An
//     arbitrary-precision implementation of this format would not collide the same way and would
//     diverge from this one on exactly the values a JS verifier cannot tell apart;
//   - `undefined` and functions (JSON.stringify silently DROPS them from objects, so a payload could
//     lose a field between signing and verifying without either side erroring);
//   - lone surrogates (JSON.stringify emits them as \udXXX escapes, but round-tripping through a
//     UTF-8 transport does not preserve them).
//
// The verifier canonicalises the payload it PARSED, never the bytes it received, so a re-ordered or
// re-indented envelope still verifies while a changed VALUE does not. That is the property an immutable
// review record needs: reviewer, verdict and pr live inside the signed payload.

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export class NotCanonicalisable extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotCanonicalisable';
  }
}

function encodeString(value) {
  if (LONE_SURROGATE.test(value)) {
    throw new NotCanonicalisable('string contains a lone surrogate and cannot be canonicalised');
  }
  return JSON.stringify(value);
}

/**
 * @param {unknown} value
 * @returns {string} the canonical UTF-8 JSON text for `value`
 */
export function canonicalize(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return encodeString(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new NotCanonicalisable(`only safe integer numbers (-(2^53-1)..2^53-1) are canonicalisable, got ${value}`);
    }
    // -0 has two encodings ("0" and "-0"); normalise it rather than let the two sides differ.
    return String(value === 0 ? 0 : value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    // Array.prototype.sort compares UTF-16 code units, which is what JCS specifies.
    const keys = Object.keys(value).sort();
    const parts = keys.map((key) => {
      const item = value[key];
      if (item === undefined) {
        throw new NotCanonicalisable(`property ${JSON.stringify(key)} is undefined; JSON.stringify would drop it silently`);
      }
      return `${encodeString(key)}:${canonicalize(item)}`;
    });
    return `{${parts.join(',')}}`;
  }
  throw new NotCanonicalisable(`values of type ${typeof value} are not canonicalisable`);
}

/**
 * @param {unknown} value
 * @returns {Buffer} the canonical bytes that a Quorum signature covers
 */
export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}

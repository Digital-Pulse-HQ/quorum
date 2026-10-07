// A deliberately tiny JSON Schema evaluator, so the shipped schema files ARE the validator.
//
// The alternative shapes were both worse. Hand-writing a structural validator alongside a
// documentation-only schema gives two artefacts that drift, and the one that drifts is always the
// one nobody executes. Depending on `ajv` would pull in the first transitive tree this package has.
//
// R4, corrected: that second point is a PRODUCT CHOICE, not the portability requirement.
// The original F3 asks only that the package install and run with its DECLARED dependencies in a
// clean project, and a properly declared `ajv` would satisfy that. Zero dependencies is a stronger
// bar we hold ourselves to — it makes an offline `npm install --offline` trivially provable and
// keeps the audit surface at what is in this repository. Saying it "breaks the load-bearing claim"
// overstated the requirement, which matters because a rule justified by a false constraint is one
// nobody can weigh honestly later.
//
// THE KEYWORD ALLOW-LIST IS THE POINT. A JSON Schema evaluator that ignores keywords it does not
// implement fails OPEN: someone adds `"minLength": 1` to a schema, the evaluator skips it, and the
// constraint reads as enforced in review while enforcing nothing. `compileSchema` throws on any
// keyword outside SUPPORTED, so adding an unimplemented keyword breaks the build instead of
// silently weakening the gate. `additionalProperties` is accepted ONLY as `false` for the same
// reason: an open object is the shape through which unknown fields enter a signed payload.

const SUPPORTED = new Set([
  '$schema', '$id', 'title', 'description', 'examples',
  'type', 'const', 'enum', 'pattern', 'properties', 'required',
  'additionalProperties', 'items', 'minItems', 'maxItems', 'uniqueItems',
  'minimum', 'maximum',
]);

const TYPES = new Set(['object', 'array', 'string', 'integer', 'boolean', 'null']);

export class SchemaError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SchemaError';
  }
}

function assertSupported(schema, path) {
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) {
    throw new SchemaError(`schema at ${path} must be an object`);
  }
  for (const keyword of Object.keys(schema)) {
    if (!SUPPORTED.has(keyword)) {
      throw new SchemaError(`unsupported schema keyword ${JSON.stringify(keyword)} at ${path}: this evaluator refuses to ignore it`);
    }
  }
  if (Object.hasOwn(schema, 'additionalProperties') && schema.additionalProperties !== false) {
    throw new SchemaError(`additionalProperties at ${path} may only be false`);
  }
  if (Object.hasOwn(schema, 'type')) {
    const declared = Array.isArray(schema.type) ? schema.type : [schema.type];
    for (const type of declared) {
      if (!TYPES.has(type)) throw new SchemaError(`unsupported type ${JSON.stringify(type)} at ${path}`);
    }
  }
  if (Object.hasOwn(schema, 'pattern')) new RegExp(schema.pattern); // throws early on a bad pattern
  for (const [name, sub] of Object.entries(schema.properties ?? {})) {
    assertSupported(sub, `${path}/properties/${name}`);
  }
  if (Object.hasOwn(schema, 'items')) assertSupported(schema.items, `${path}/items`);
}

/**
 * Validate a schema document itself. Call this once at load time so an unimplemented keyword is a
 * loud failure at import rather than a quiet non-constraint at verification time.
 */
export function compileSchema(schema, path = '#') {
  assertSupported(schema, path);
  return schema;
}

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (Number.isInteger(value)) return 'integer';
  if (typeof value === 'number') return 'number';
  return typeof value;
}

function walk(schema, value, path, errors) {
  if (Object.hasOwn(schema, 'type')) {
    const declared = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!declared.includes(typeOf(value))) {
      errors.push(`${path}: expected type ${declared.join('|')}, got ${typeOf(value)}`);
      return; // Every other keyword's meaning depends on the type; stop rather than cascade.
    }
  }
  if (Object.hasOwn(schema, 'const') && JSON.stringify(value) !== JSON.stringify(schema.const)) {
    errors.push(`${path}: expected constant ${JSON.stringify(schema.const)}`);
  }
  if (Object.hasOwn(schema, 'enum') && !schema.enum.some((option) => JSON.stringify(option) === JSON.stringify(value))) {
    errors.push(`${path}: ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  }
  if (Object.hasOwn(schema, 'pattern') && typeof value === 'string' && !new RegExp(schema.pattern).test(value)) {
    errors.push(`${path}: ${JSON.stringify(value)} does not match ${schema.pattern}`);
  }
  if (Object.hasOwn(schema, 'minimum') && typeof value === 'number' && value < schema.minimum) {
    errors.push(`${path}: ${value} is below minimum ${schema.minimum}`);
  }
  if (Object.hasOwn(schema, 'maximum') && typeof value === 'number' && value > schema.maximum) {
    errors.push(`${path}: ${value} is above maximum ${schema.maximum}`);
  }
  if (typeOf(value) === 'object') {
    for (const name of schema.required ?? []) {
      if (!Object.hasOwn(value, name)) errors.push(`${path}: missing required property ${JSON.stringify(name)}`);
    }
    const properties = schema.properties ?? {};
    if (schema.additionalProperties === false) {
      for (const name of Object.keys(value)) {
        if (!Object.hasOwn(properties, name)) errors.push(`${path}: unknown property ${JSON.stringify(name)}`);
      }
    }
    for (const [name, sub] of Object.entries(properties)) {
      if (Object.hasOwn(value, name)) walk(sub, value[name], `${path}/${name}`, errors);
    }
  }
  if (typeOf(value) === 'array') {
    if (Object.hasOwn(schema, 'minItems') && value.length < schema.minItems) {
      errors.push(`${path}: expected at least ${schema.minItems} items, got ${value.length}`);
    }
    if (Object.hasOwn(schema, 'maxItems') && value.length > schema.maxItems) {
      errors.push(`${path}: expected at most ${schema.maxItems} items, got ${value.length}`);
    }
    if (schema.uniqueItems === true) {
      const seen = new Set(value.map((item) => JSON.stringify(item)));
      if (seen.size !== value.length) errors.push(`${path}: items must be unique`);
    }
    if (Object.hasOwn(schema, 'items')) {
      value.forEach((item, index) => walk(schema.items, item, `${path}/${index}`, errors));
    }
  }
}

/**
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validate(schema, value) {
  const errors = [];
  walk(schema, value, '#', errors);
  return { ok: errors.length === 0, errors };
}

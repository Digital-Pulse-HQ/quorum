// The shipped-surface audit — F2.
//
// WHAT WAS WRONG WITH THE GUARD THIS REPLACES. It described a broad property ("the gate runs no
// model and holds no API key") and implemented a narrow one: two dependency fields and four
// forbidden spellings. F2 planted three ORDINARY, supported forms and left the complete
// suite at 138 pass / 0 fail, all four dedicated tests green:
//
//   1. `const loadNetworkClient = async () => import('node:https')`  — dynamic import
//   2. `const { OPENAI_API_KEY } = process.env`                      — destructuring
//   3. `optionalDependencies: { "openai": "*" }`                     — a third manifest field
//
// Every one of those is invisible to a forbidden-list, and the list can only ever be extended one
// demonstrated bypass at a time — which is the reviewer's actual objection. A guard that enumerates
// what is banned is always behind whoever is adding things.
//
// SO THE RULE IS INVERTED. This audit is DEFAULT-DENY. It does not ask "is this one of the bad
// things"; it asks "is this one of the small number of things we have explicitly decided the gate
// may do", and anything else — including a form nobody anticipated — is a violation. Node ships no
// JavaScript parser we can reach (and this package may not acquire one: zero dependencies IS the
// property under test), so the review's second sanctioned option is taken: an explicit, exhaustively
// reasoned allow-list. The exhaustiveness is enforced rather than claimed, by CLASSIFICATION
// COMPLETENESS — every syntactic occurrence of `import`, `require` and `process.env` in shipped
// source must be matched by a form this file understands, and a construct it cannot read is a
// violation rather than a silent pass. That is what stops the extractor itself from being the new
// hole.
//
// This file is under test/ and is NOT shipped. It is imported by gate-is-model-free.test.mjs, which
// runs it against the real tree, and by guard-coverage.test.mjs, which runs it against
// mutated copies of the real tree.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, posix, relative, sep } from 'node:path';

// ---------------------------------------------------------------------------------------------
// THE ALLOW-LISTS. Every entry carries the reason it is here; widening either is a deliberate,
// reviewable act rather than a regex tweak.
// ---------------------------------------------------------------------------------------------

/**
 * Module specifiers the shipped gate may load. Each is reasoned about against ONE question: can it
 * open a socket, read a credential, or load code we did not write?
 *
 *   node:crypto  hashing and Ed25519 verification. The package's whole job. No I/O of any kind.
 *   node:fs      reads the envelope, policy, trust store, artifact, evidence and schemas from the
 *                local filesystem. Local only — `fs` has no network path.
 *   node:path    string manipulation of paths. No I/O.
 *   node:url     `fileURLToPath` and URL parsing. Parsing a URL is not fetching one; nothing in
 *                node:url performs a request.
 *
 * DELIBERATELY ABSENT and each a real capability: node:http/https/net/tls/dgram/dns (sockets),
 * node:child_process and node:worker_threads (spawn something that has sockets), node:module
 * (`createRequire`, a route around this list), node:vm (evaluate code), node:process as a module
 * (the global is classified separately). Adding any of them is a change to what the gate IS.
 */
export const ALLOWED_MODULES = Object.freeze([
  'node:crypto',
  'node:fs',
  'node:path',
  'node:url',
]);

/** Relative specifiers — code inside this package, already covered by the walk. */
const RELATIVE_SPECIFIER = /^\.{1,2}\//;

/**
 * Environment variables the shipped gate may read. The gate is allowed env for BEHAVIOUR (a mode
 * flag, a path); it is not allowed anything else, because default-deny on a namespace is the only
 * rule that catches a credential nobody thought to name. `QUORUM_` is the namespace this package
 * owns, so a read outside it is either someone else's variable or a secret.
 *
 * Note this is strictly stronger than the credential-SHAPED matching it replaces: `OPENAI_API_KEY`
 * is refused because it is not ours, not because it contains `API_KEY`.
 */
export const ALLOWED_ENV = /^QUORUM_[A-Z0-9_]+$/;

/**
 * Globals and constructs that reach the network or load code, none of which is an import and so
 * none of which the module allow-list can see. `fetch` is the original example: a bare global in
 * modern Node, invisible to any import check.
 */
const FORBIDDEN_GLOBALS = Object.freeze([
  [/\bfetch\s*\(/, 'a fetch() call'],
  [/\bXMLHttpRequest\b/, 'XMLHttpRequest'],
  [/\bWebSocket\b/, 'a WebSocket'],
  [/\bEventSource\b/, 'an EventSource'],
  [/\bsendBeacon\s*\(/, 'navigator.sendBeacon'],
  [/\bcreateRequire\s*\(/, 'module.createRequire — a route around the module allow-list'],
  [/\beval\s*\(/, 'eval() — arbitrary code defeats every check in this file'],
  [/\bnew\s+Function\s*\(/, 'new Function() — arbitrary code defeats every check in this file'],
  [/\bprocess\s*\.\s*binding\s*\(/, 'process.binding — undocumented native bindings'],
  [/\bprocess\s*\.\s*dlopen\s*\(/, 'process.dlopen — loads a native addon'],
  [/\bglobalThis\s*\[/, 'computed globalThis access — unreadable, so it cannot be allow-listed'],
]);

/**
 * Audited but NOT published. `ci/` is absent from package.json `files`, so an npm consumer never
 * receives it — but it is the required check that runs in the merge gate, and a gate that called a
 * model would break the same property for the same reason. Declared here rather than folded into
 * the published set, because calling it "shipped" would be false.
 */
export const AUDITED_BEYOND_PACKAGE_FILES = Object.freeze(['ci']);

/**
 * Published but NOT the gate. `test/` and `tools/` ship so a consumer can run the refusals and
 * regenerate the fixtures rather than take either on report; they spawn processes and use node:test,
 * which is what a test suite and a generator do. No gate entry point loads them — `bin/`, `src/` and
 * `ci/` are the gate — and that is ENFORCED below, not assumed: a relative import from any audited
 * file that resolves into one of these directories is a violation, so the gate cannot reach
 * unaudited code through them.
 */
export const PUBLISHED_OUTSIDE_THE_GATE = Object.freeze(['test', 'tools']);

const SOURCE_EXTENSIONS = ['.mjs', '.js', '.cjs'];

// ---------------------------------------------------------------------------------------------
// Discovery. Driven by package.json `files`, so a newly shipped directory is audited the moment it
// is declared — the hardcoded ['src','bin','ci','schema'] this replaces would not have been.
// ---------------------------------------------------------------------------------------------

function walk(root, entry, out) {
  const full = join(root, entry);
  let stat;
  try { stat = statSync(full); } catch { return; }
  if (stat.isDirectory()) {
    for (const child of readdirSync(full).sort()) walk(root, join(entry, child), out);
  } else if (SOURCE_EXTENSIONS.some((ext) => entry.endsWith(ext))) {
    out.push(entry.split(sep).join('/'));
  }
}

export function shippedSourceFiles(root, pkg) {
  const declared = Array.isArray(pkg.files) ? pkg.files : [];
  const out = [];
  for (const entry of [...new Set([...declared, ...AUDITED_BEYOND_PACKAGE_FILES])]) {
    if (!PUBLISHED_OUTSIDE_THE_GATE.includes(entry)) walk(root, entry, out);
  }
  return [...new Set(out)].sort();
}

// ---------------------------------------------------------------------------------------------
// Lexing. Comments are stripped because this repository's own prose legitimately discusses fetch()
// and API keys, and a guard that fires on documentation gets disabled.
// ---------------------------------------------------------------------------------------------

/** Block comments, and line comments anchored at the start of a line so `https://` survives. */
function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, (match) => match.replace(/[^\n]/g, ' '))
    .replace(/^([ \t]*)\/\/.*$/gm, (match, indent) => indent + ' '.repeat(match.length - indent.length));
}

/** Replace a span with spaces, preserving length and line numbers so offsets stay meaningful. */
const blank = (text, start, end) => text.slice(0, start) + text.slice(start, end).replace(/[^\n]/g, ' ') + text.slice(end);

/** Blank the CONTENTS of string and template literals, so prose inside them creates no anchors. */
function blankStringLiterals(code) {
  let out = code;
  for (const re of [/'(?:[^'\\\n]|\\.)*'/g, /"(?:[^"\\\n]|\\.)*"/g, /`(?:[^`\\]|\\.)*`/g]) {
    out = out.replace(re, (match) => match.replace(/[^\n]/g, ' '));
  }
  return out;
}

const lineOf = (code, index) => code.slice(0, index).split('\n').length;

// ---------------------------------------------------------------------------------------------
// Classification. Applied IN ORDER; each match is blanked so a later form cannot re-read it.
// ---------------------------------------------------------------------------------------------

const MODULE_FORMS = Object.freeze([
  // `import.meta` first: it loads nothing, and leaving it in place lets the multi-line `from` form
  // below start scanning at it and claim a span that is not an import statement.
  { re: /\bimport\s*\.\s*meta\b/g, specifier: null },
  { re: /\bimport\s*\(\s*(['"])([^'"\n]*)\1\s*\)/g, specifier: 2 },
  { re: /\brequire\s*\(\s*(['"])([^'"\n]*)\1\s*\)/g, specifier: 2 },
  { re: /\b(?:import|export)\b[^;'"]*?\bfrom\s*(['"])([^'"\n]*)\1/g, specifier: 2 },
  { re: /\bimport\s*(['"])([^'"\n]*)\1/g, specifier: 2 },
]);

// The env ROOT every form below keys off. A later review planted `process['env'].OPENAI_API_KEY`: the
// same property as `process.env`, read through the bracket spelling, and every form here (plus the
// residual anchor) recognised only the literal-dot spelling. Both are the same member access at
// runtime, so a classifier keyed on one textual spelling was incomplete by construction.
const ENV_ROOT = String.raw`process\s*(?:\.\s*env\b|\[\s*'env'\s*\]|\[\s*"env"\s*\])`;

const ENV_FORMS = Object.freeze([
  // Destructuring, which F2 planted and the previous guard could not see at all.
  { re: new RegExp(String.raw`\{([^{}]*)\}\s*=\s*${ENV_ROOT}`, 'g'), names: (m) => destructuredNames(m[1]) },
  { re: new RegExp(String.raw`\b${ENV_ROOT}\s*\.\s*([A-Za-z_$][\w$]*)`, 'g'), names: (m) => [m[1]] },
  { re: new RegExp(String.raw`\b${ENV_ROOT}\s*\[\s*(['"])([^'"\n]*)\1\s*\]`, 'g'), names: (m) => [m[2]] },
]);

/** `{ A, B: local, C = 'x' }` -> ['A','B','C']. A rest element is unreadable, hence null. */
function destructuredNames(inner) {
  if (/\.\.\./.test(inner)) return null;
  return inner.split(',').map((part) => part.split(/[:=]/)[0].trim()).filter(Boolean);
}

/** Anything left after classification that still looks like a module load or an env read. */
const RESIDUAL_ANCHORS = Object.freeze([
  [/\bimport\b/g, 'an `import` this audit could not classify'],
  [/\brequire\s*\(/g, 'a `require(` with a specifier this audit could not read'],
  [new RegExp(String.raw`\b${ENV_ROOT}`, 'g'), 'a `process.env` access this audit could not read'],
]);

// ---------------------------------------------------------------------------------------------

/**
 * Audit a package root. Returns every violation rather than throwing on the first, so a caller can
 * assert on the complete set and a mutation test can name exactly what it expects to have caused.
 *
 * @param {string} root the package directory
 * @returns {{scanned: string[], violations: {kind: string, file: string, line: number|null, reason: string}[]}}
 */
// A RELATIVE IMPORT IS JUDGED BY WHERE NODE LOADS IT, not by its spelling. Node resolves a relative
// specifier as a URL against the importing file and decodes it, so `../%74ools/x.mjs`, `../tools\x.mjs`
// and `../to<TAB>ols/x.mjs` all load tools/x.mjs. The literal is read the same way here: a spelling
// the URL parser rewrites (percent-encoding, a backslash — including a string escape, which this
// audit reads unexpanded — tab, LF or CR, a query or fragment: any spelling whose URL-resolved path
// differs from its literal path) is refused by name, and the resolved
// target must be a file this audit itself reads. That one rule keeps the gate out of test/ and
// tools/ (published outside the gate) and out of anything beyond the package, however it is spelled.
// A bare self-reference (`@digital-pulse-hq/quorum/...`, `#imports`) and an absolute `file:` URL or
// path are not relative, so the module allow-list above refuses them.
const AUDIT_BASE = 'file:///package/';
export function nodeRelativeTarget(rel, specifier) {
  try {
    const pathname = decodeURIComponent(new URL(specifier, `${AUDIT_BASE}${rel}`).pathname);
    return pathname.startsWith('/package/') ? pathname.slice('/package/'.length) : null;
  } catch {
    return null;
  }
}

function relativeImportViolation(rel, specifier, scanned) {
  const target = nodeRelativeTarget(rel, specifier);
  const literal = posix.normalize(posix.join(posix.dirname(rel), specifier));
  if (target !== null && target !== literal) {
    return `which Node's URL resolution rewrites to ${target} (percent-encoding, a backslash or string escape, tab, LF, CR, a query or fragment), so the spelling is not the file Node loads`;
  }
  if (target === null) return 'which resolves outside the package, where this audit does not read';
  const top = target.split('/')[0];
  if (PUBLISHED_OUTSIDE_THE_GATE.includes(top)) {
    return `which resolves into ${top}/ — published outside the gate and not audited, so the gate may not load it`;
  }
  if (!scanned.includes(target)) return `which resolves to ${target}, a file this audit does not read`;
  return null;
}

export function auditShippedSurface(root) {
  const violations = [];
  const add = (kind, file, line, reason) => violations.push({ kind, file, line, reason });

  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

  // --- the manifest -----------------------------------------------------------------------
  //
  // EVERY dependency-bearing field, discovered by SHAPE rather than by name. npm has five today
  // (dependencies, devDependencies, optionalDependencies, peerDependencies, bundleDependencies) and
  // the previous guard checked two; matching on the name catches the three it missed AND any field
  // npm adds later, which naming them one at a time would not.
  if (!Array.isArray(pkg.files) || pkg.files.length === 0) {
    add('discovery', 'package.json', null, 'no `files` allow-list, so the entire directory is published and the audited set is not the shipped set');
  }
  for (const [key, value] of Object.entries(pkg)) {
    if (!/dependencies/i.test(key)) continue;
    const named = Array.isArray(value) ? value : Object.keys(value ?? {});
    if (named.length > 0) {
      add('manifest', 'package.json', null, `${key} declares ${named.join(', ')} — the gate must install nothing`);
    }
  }
  // Version pins imply a dependency tree even when they name no direct dependency.
  for (const key of ['overrides', 'resolutions']) {
    if (Object.keys(pkg[key] ?? {}).length > 0) add('manifest', 'package.json', null, `${key} is non-empty, which only makes sense with a dependency tree`);
  }
  // INSTALL-TIME CODE, which no amount of auditing src/ would see. `npm install` runs preinstall,
  // install and postinstall for a published package, so a `postinstall` that curls a binary reaches
  // the network on a consumer's machine while every shipped source file stays clean. The property
  // being protected is "a consumer can run this offline with no credential"; an install hook breaks
  // it before a single line of ours executes.
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack']) {
    if (pkg.scripts?.[hook] !== undefined) {
      add('manifest', 'package.json', null, `scripts.${hook} runs code at install or pack time, outside every source check`);
    }
  }
  // A lockfile or an installed tree means a dependency arrived regardless of what the manifest says.
  for (const artefact of ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'node_modules']) {
    try {
      statSync(join(root, artefact));
      add('manifest', artefact, null, 'present — a dependency was installed, which breaks the clean-room claim');
    } catch { /* absent is the shipped property */ }
  }

  // --- the source -------------------------------------------------------------------------
  const scanned = shippedSourceFiles(root, pkg);
  for (const rel of scanned) {
    const code = stripComments(readFileSync(join(root, rel), 'utf8'));
    let residue = code;

    for (const form of MODULE_FORMS) {
      const re = new RegExp(form.re.source, form.re.flags);
      for (const match of [...code.matchAll(re)]) {
        const start = match.index;
        const end = start + match[0].length;
        // Skip a span an earlier form already consumed.
        if (residue.slice(start, end).trim() === '') continue;
        residue = blank(residue, start, end);
        if (form.specifier === null) continue;
        const specifier = match[form.specifier];
        if (RELATIVE_SPECIFIER.test(specifier)) {
          const why = relativeImportViolation(rel, specifier, scanned);
          if (why !== null) add('module', rel, lineOf(code, start), `loads ${JSON.stringify(specifier)}, ${why}`);
          continue;
        }
        if (ALLOWED_MODULES.includes(specifier)) continue;
        add('module', rel, lineOf(code, start), `loads ${JSON.stringify(specifier)}, which is not in the shipped module allow-list [${ALLOWED_MODULES.join(', ')}]`);
      }
    }

    for (const form of ENV_FORMS) {
      const re = new RegExp(form.re.source, form.re.flags);
      for (const match of [...code.matchAll(re)]) {
        const start = match.index;
        const end = start + match[0].length;
        if (residue.slice(start, end).trim() === '') continue;
        residue = blank(residue, start, end);
        const names = form.names(match);
        if (names === null) {
          add('unreadable', rel, lineOf(code, start), 'rest-destructures process.env, so which variables it reads cannot be read');
          continue;
        }
        for (const name of names.filter((candidate) => !ALLOWED_ENV.test(candidate))) {
          add('env', rel, lineOf(code, start), `reads environment variable ${name}, which is outside the allowed ${ALLOWED_ENV} namespace`);
        }
      }
    }

    // Residual anchors: a construct no form above understood. Refused rather than ignored —
    // otherwise the classifier's blind spots become the guard's, which is the whole finding.
    const unread = blankStringLiterals(residue);
    for (const [re, what] of RESIDUAL_ANCHORS) {
      for (const match of unread.matchAll(new RegExp(re.source, re.flags))) {
        add('unreadable', rel, lineOf(code, match.index), `${what} — a form this audit cannot read is a violation, not a pass`);
      }
    }

    const masked = blankStringLiterals(code);
    for (const [re, what] of FORBIDDEN_GLOBALS) {
      const found = masked.match(new RegExp(re.source, re.flags));
      if (found !== null) add('global', rel, lineOf(code, masked.indexOf(found[0])), `uses ${what}`);
    }
  }

  return { scanned, violations };
}

/** The audited root for the package this file lives in. */
export const PACKAGE_ROOT = relative(process.cwd(), new URL('../', import.meta.url).pathname) || '.';

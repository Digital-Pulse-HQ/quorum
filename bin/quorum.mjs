#!/usr/bin/env node
// Quorum CLI. Zero dependencies, no knowledge of any repository layout: it reads the files it is
// pointed at and nothing else. That it runs with no orchestration tool installed is the load-bearing
// claim, and it is proved by test/clean-project.test.mjs, which installs this package from a tarball
// into an empty directory and runs this file there.

import {
  generateKeyPairSync, randomBytes,
} from 'node:crypto';
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  createEnvelope, createProducerHalf, serializeEnvelope, sha256Ref,
} from '../src/envelope.mjs';
import { renderComment } from '../src/render.mjs';
import { verifyEnvelope } from '../src/verify.mjs';

const USAGE = `usage: quorum <command> [options]

  new-attempt
  keygen          --out-private FILE --out-public FILE
  attest-producer --private-key FILE --key-id ID --principal P --family F --family-trust declared|observed
                  --attempt ATTEMPT --commit SHA (--artifact FILE | --artifact-digest sha256:...)
                  --policy-version V --out FILE
  attest-review   --producer-half FILE --private-key FILE --key-id ID --principal P --family F
                  --family-trust declared|observed --verdict TOKEN --evidence FILE [--pr N] --out FILE
  verify          --envelope FILE --policy FILE --trust FILE --attempt ATTEMPT --commit SHA
                  [--pr N] [--artifact FILE] [--artifact-digest sha256:...] [--evidence FILE] [--json]
  render          --envelope FILE [--envelope-path PATH]
`;

class UsageError extends Error {}

function parseOptions(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) throw new UsageError(`unexpected argument ${JSON.stringify(token)}`);
    const name = token.slice(2);
    if (name === 'json') { out.json = true; continue; }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) throw new UsageError(`option --${name} needs a value`);
    if (Object.hasOwn(out, name)) throw new UsageError(`option --${name} given twice`);
    out[name] = value;
    i += 1;
  }
  return out;
}

function need(options, names) {
  const missing = names.filter((name) => options[name] === undefined);
  if (missing.length > 0) throw new UsageError(`missing ${missing.map((n) => `--${n}`).join(', ')}`);
}

/** Missing input is data for the gate, not an exception: verify turns it into Q00_INPUT_PRESENT. */
function readOptional(path, encoding) {
  if (path === undefined) return null;
  try {
    return readFileSync(path, encoding);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'EISDIR') return null;
    throw error;
  }
}

function artifactDigestFrom(options) {
  if (options.artifact !== undefined) return sha256Ref(readFileSync(options.artifact));
  if (options['artifact-digest'] !== undefined) return options['artifact-digest'];
  throw new UsageError('one of --artifact or --artifact-digest is required');
}

export function main(argv = process.argv.slice(2), io = process) {
  const [command, ...rest] = argv;
  try {
    if (command === undefined || command === '--help' || command === 'help') {
      io.stdout.write(USAGE);
      return command === undefined ? 2 : 0;
    }
    const options = parseOptions(rest);

    if (command === 'new-attempt') {
      io.stdout.write(`attempt:${randomBytes(16).toString('hex')}\n`);
      return 0;
    }

    if (command === 'keygen') {
      need(options, ['out-private', 'out-public']);
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      // 0600 and `wx`: never widen an existing file, never overwrite a key already in use.
      writeFileSync(options['out-private'], privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
      writeFileSync(options['out-public'], publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644, flag: 'wx' });
      io.stdout.write(`${options['out-private']}\n${options['out-public']}\n`);
      return 0;
    }

    if (command === 'attest-producer') {
      need(options, ['private-key', 'key-id', 'principal', 'family', 'family-trust', 'attempt', 'commit', 'policy-version', 'out']);
      const half = createProducerHalf({
        policyVersion: options['policy-version'],
        attemptId: options.attempt,
        artifact: { kind: 'git_commit', commit: options.commit, digest: artifactDigestFrom(options) },
        producer: {
          principal: options.principal,
          family: options.family,
          family_trust: options['family-trust'],
          key_id: options['key-id'],
        },
        privateKey: readFileSync(options['private-key'], 'utf8'),
      });
      writeFileSync(options.out, `${JSON.stringify(half, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
      io.stdout.write(`${options.out}\n`);
      return 0;
    }

    if (command === 'attest-review') {
      need(options, ['producer-half', 'private-key', 'key-id', 'principal', 'family', 'family-trust', 'verdict', 'evidence', 'out']);
      const envelope = createEnvelope({
        producerHalf: JSON.parse(readFileSync(options['producer-half'], 'utf8')),
        reviewer: {
          principal: options.principal,
          family: options.family,
          family_trust: options['family-trust'],
          key_id: options['key-id'],
        },
        review: {
          verdict: options.verdict,
          pr: options.pr === undefined ? null : Number(options.pr),
          evidence_digest: sha256Ref(readFileSync(options.evidence)),
        },
        privateKey: readFileSync(options['private-key'], 'utf8'),
      });
      writeFileSync(options.out, serializeEnvelope(envelope), { encoding: 'utf8', flag: 'wx' });
      io.stdout.write(`${options.out}\n`);
      return 0;
    }

    if (command === 'verify') {
      need(options, ['envelope', 'policy', 'trust', 'attempt', 'commit']);
      const result = verifyEnvelope({
        envelopeText: readOptional(options.envelope, 'utf8'),
        policyText: readOptional(options.policy, 'utf8'),
        trustText: readOptional(options.trust, 'utf8'),
        expected: {
          attemptId: options.attempt,
          commit: options.commit,
          pr: options.pr === undefined ? null : Number(options.pr),
          artifactDigest: options['artifact-digest'],
        },
        artifactBytes: readOptional(options.artifact),
        evidenceBytes: readOptional(options.evidence),
      });
      if (options.json) {
        io.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      } else {
        const line = result.ok
          ? `PASS: ${result.why}`
          : `${result.verdict}: blocked (${result.evidence === 'not_compared' ? 'nothing compared' : 'compared and rejected'}) — ${result.guard}: ${result.why}`;
        (result.ok ? io.stdout : io.stderr).write(`${line}\n`);
      }
      return result.ok ? 0 : 1;
    }

    if (command === 'render') {
      need(options, ['envelope']);
      const envelope = JSON.parse(readFileSync(options.envelope, 'utf8'));
      io.stdout.write(renderComment(envelope, { envelopePath: options['envelope-path'] }));
      return 0;
    }

    throw new UsageError(`unknown command ${JSON.stringify(command)}`);
  } catch (error) {
    if (error instanceof UsageError) {
      io.stderr.write(`quorum: ${error.message}\n\n${USAGE}`);
      return 2;
    }
    // Anything unexpected is still a refusal, never a pass, and it says nothing was compared.
    io.stderr.write(`UNKNOWN: blocked (nothing compared) — quorum could not run: ${error.message}\n`);
    return 1;
  }
}

// REALPATH BOTH SIDES. `pathToFileURL(process.argv[1]).href === import.meta.url` is FALSE for a
// script invoked through a symlink, and npm installs a bin as exactly that symlink in
// node_modules/.bin — so the naive comparison makes the CLI silently do nothing when installed,
// which is the one context this package's central claim depends on.
if (process.argv[1] !== undefined
    && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(main());
}

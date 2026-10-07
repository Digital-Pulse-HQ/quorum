// Copy the package into a scratch directory for a mutation run, leaving out node_modules and .git.
//
// WHY THE FILTER LOOKS AT THE RELATIVE PATH. The suite ships, and an installed copy lives at
// `<consumer>/node_modules/@digital-pulse-hq/quorum`. A filter that tests the ABSOLUTE source path
// for `/node_modules` therefore rejects the copy root itself — cpSync then copies nothing, and every
// test that runs against the copy fails with ENOENT. It passes from the repo and from an extracted
// tarball, which is why it shipped: 41/305 failed only when installed from npm. Only the part of the
// path BELOW the package root says anything about whether an entry belongs in the copy.

import { cpSync } from 'node:fs';
import { relative, sep } from 'node:path';

const EXCLUDED = Object.freeze(['node_modules', '.git']);

/** True when `src` (under `root`) belongs in a copy of the package. */
export function keepInCopy(root, src) {
  return !relative(root, src).split(sep).some((part) => EXCLUDED.includes(part));
}

/** Copy the package at `root` into `dir`, without node_modules or .git at any depth below `root`. */
export function copyPackage(root, dir) {
  cpSync(root, dir, { recursive: true, filter: (src) => keepInCopy(root, src) });
}

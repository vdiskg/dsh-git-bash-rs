#!/usr/bin/env node
/**
 * Compile `src/*.ts` into `lib/`, then repair the one artefact TypeScript
 * cannot produce on its own.
 *
 * Two output shapes ship:
 *
 * - `lib/index.js`, `lib/agents.js`, `lib/discovery.js` are ES modules that DSH
 *   loads through `import`; the matching `lib/types/*.d.ts` carry their public
 *   types for consumers and for the plugin's `exports` map.
 * - `lib/client.js` is *not* a module. DSH's client loader evaluates it as a
 *   plain script and calls the factory it registers on `window`. TypeScript
 *   appends `export {}` to any file it needs to treat as a module, which the
 *   script evaluation rejects with `SyntaxError: Unexpected token 'export'`,
 *   so that marker is stripped here.
 *
 * Usage: node scripts/build-lib.mjs
 */

import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const libDir = join(root, 'lib');

/** The client half, which must stay a script. */
const CLIENT_OUTPUT = join(libDir, 'client.js');

/** TypeScript's module marker, as emitted on its own line. */
const MODULE_MARKER = /^export \{\};?[^\S\n]*$/gmu;

// A clean build, so a file deleted from src/ cannot linger in lib/.
rmSync(libDir, { recursive: true, force: true });

const tsc = spawnSync(
  process.execPath,
  [join(root, 'node_modules', 'typescript', 'bin', 'tsc'), '--project', root],
  { cwd: root, stdio: 'inherit' },
);
if (tsc.status !== 0) {
  console.error('build-lib: tsc failed');
  process.exit(tsc.status ?? 1);
}

const clientSource = readFileSync(CLIENT_OUTPUT, 'utf8');
const stripped = clientSource.replace(MODULE_MARKER, '');
if (stripped === clientSource) {
  console.warn('build-lib: client.js had no module marker; nothing stripped');
}
writeFileSync(CLIENT_OUTPUT, stripped, 'utf8');

// A module marker left behind would only fail at page load, so fail the build.
if (/^export\b/mu.test(stripped)) {
  throw new Error('build-lib: lib/client.js still contains export syntax');
}

console.log('build-lib: compiled src/*.ts to lib/ (client.js kept as a script)');

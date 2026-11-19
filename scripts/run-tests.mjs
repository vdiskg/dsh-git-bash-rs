#!/usr/bin/env node
/**
 * Run the test suite against the running DSH installation.
 *
 * The plugin's `@deepseek-ai/*` peers live inside the installation's ASAR
 * archive, which only DSH's own Electron runtime can read. Running the suite
 * through that runtime (`ELECTRON_RUN_AS_NODE=1`) lets the plugin's bare
 * imports resolve exactly as they do when DSH loads it, with no copying or
 * linking of packages.
 *
 * `--test-isolation=none` keeps the runner in one process: this sandbox
 * forbids the piped stdio that per-file child processes use (EPERM).
 *
 * Usage (inside a DSH shell): node scripts/run-tests.mjs
 */

import { readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const runtime = process.env.DSH_NODE_EXECUTABLE;
if (runtime === undefined || runtime.length === 0) {
  console.error('run-tests: DSH_NODE_EXECUTABLE is not set; run this inside a DSH shell.');
  process.exit(2);
}

// A directory argument is not importable, so the files are listed explicitly.
const testDir = join(root, 'test');
const files = readdirSync(testDir)
  .filter((entry) => entry.endsWith('.test.mjs'))
  .map((entry) => join(testDir, entry));
if (files.length === 0) {
  console.error('run-tests: no test files found');
  process.exit(2);
}

const result = spawnSync(
  runtime,
  ['--test', '--test-isolation=none', ...files],
  {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
  },
);

process.exit(result.status ?? 1);

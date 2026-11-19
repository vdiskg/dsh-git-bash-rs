/**
 * Shared harness for tests that drive the real executor.
 *
 * Kept here rather than duplicated so `executor.test.mjs` and
 * `fidelity.test.mjs` construct the identical stub context: a divergence in the
 * stubs would make one suite prove something the other does not.
 *
 * The peers come from the running DSH installation (see `scripts/run-tests.mjs`
 * for why the suite must run under DSH's own runtime) and are handed to the
 * plugin through its documented `globalThis.__dshGitBashRsPeers` seam.
 *
 * @module dsh-plugin-git-bash-rs/test/executor-harness
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = new URL('..', import.meta.url).pathname.replace(/^\/(?=[A-Za-z]:)/u, '');

/** Whether this host can supply the peers (requires the DSH installation). */
export function peersAvailable() {
  const install = process.env.DSH_INSTALL_DIR;
  if (install === undefined || install.length === 0) return false;
  // A resolvable sibling marker is enough; the real check is the import below.
  return existsSync(join(install, 'package.json'));
}

/** Load the peer packages through the runtime the suite runs under. */
export async function loadPeers() {
  const { createRequire } = await import('node:module');
  const require = createRequire(join(process.env.DSH_INSTALL_DIR, 'package.json'));
  const pathToFile = (specifier) => pathToFileURL(require.resolve(specifier)).href;

  const bashLocal = await import(pathToFile('@deepseek-ai/dsh-bash-local'));
  const sandbox = await import(pathToFile('@deepseek-ai/dsh-sandbox'));
  const schemastery = await import(pathToFile('@deepseek-ai/schemastery'));
  const cordis = await import(pathToFile('@deepseek-ai/cordis'));

  return {
    bashLocal,
    sandbox,
    cordis,
    schemastery: schemastery.default ?? schemastery,
  };
}

/** Install the peer seam and import the plugin module. */
export async function loadPlugin() {
  const loaded = await loadPeers();
  globalThis.__dshGitBashRsPeers = {
    '@deepseek-ai/dsh-bash-local': loaded.bashLocal,
    '@deepseek-ai/dsh-sandbox': loaded.sandbox,
    '@deepseek-ai/schemastery': loaded.schemastery,
  };
  const module = await import(pathToFileURL(join(root, 'lib', 'index.js')).href);
  return { module, ...loaded };
}

/** A minimal stand-in for the Cordis context the executor needs. */
export function makeContext(cordis, { mode = 'workspace-write' } = {}) {
  const spawns = [];
  const confineCalls = [];
  // A real Context: `ShellExecutor` extends Cordis' `Service`, whose
  // constructor registers the provided service through it.
  const ctx = new cordis.Context();
  ctx.sandboxPolicy = {
    defaultMode: mode,
    workspaceRoot: process.cwd(),
    additionalWritableRoots: undefined,
    resolve: () => ({ mode, workspaceRoot: process.cwd() }),
  };
  ctx.sandbox = {
    confine: async (argv, policy) => {
      confineCalls.push({ argv, policy });
      return {
        argv: ['runner.exe', '--', ...argv],
        enforcement: 'partial',
        denialSignatures: ['access is denied'],
        runnerFailureRules: [{ allowedExitCodes: [127], fatalSignatures: ['runner: '] }],
      };
    },
  };
  ctx.subprocess = {
    spawn: (spec) => {
      spawns.push(spec);
      const emptyReader = { readFrom: () => ({ text: '', lossy: false, nextOffset: 0 }) };
      return {
        done: Promise.resolve({ exitCode: 0, signal: null }),
        collected: { stdout: emptyReader, stderr: emptyReader },
        terminate: () => {},
      };
    },
  };
  ctx.confineCalls = confineCalls;
  ctx.spawns = spawns;
  return ctx;
}

/** A config whose live values the base executor reads through `.get()`. */
export function makeConfig(overrides = {}) {
  const values = {
    timeoutMs: 60_000,
    maxTimeoutMs: 600_000,
    maxOutputBytes: 64_000,
    maxSpillBytes: 1024 * 1024,
    graceMs: 3000,
    cwd: undefined,
    executable: '',
    ...overrides,
  };
  const holder = {};
  for (const [key, value] of Object.entries(values)) holder[key] = { get: () => value };
  return holder;
}

/** A request the base executor accepts. */
export function makeRequest(command, mode = 'workspace-write') {
  return {
    command,
    workdir: process.cwd(),
    timeoutMs: 1000,
    onExpiry: 'kill',
    stdoutMaxBytes: 1000,
    sandboxPolicy: { mode, workspaceRoot: process.cwd() },
  };
}

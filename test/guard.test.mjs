/**
 * Guard-level regression tests.
 *
 * These invoke the committed `msys-token-guard.exe` as a process, so they test
 * the real exit-code contract rather than a stubbed spawn. That matters for the
 * 125/126 remap: a plugin-level test that feeds `exitCode: 126` to a fake
 * subprocess would keep passing even if the Rust remap were reverted.
 *
 * The guard refuses to run unless its own token is restricted, which is the
 * correct behaviour but not available in every test environment. The remap is
 * therefore exercised through the paths that do not require confinement:
 *
 * - usage and argument failures, which must stay on the guard's own codes;
 * - a child exit observed through a confined run when one is available.
 *
 * @module dsh-plugin-git-bash-rs/test/guard.test.mjs
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const GUARD = fileURLToPath(new URL('../native/bin/win32-x64/msys-token-guard.exe', import.meta.url));
const HOOK = fileURLToPath(new URL('../native/bin/win32-x64/msys_token_guard_hook.dll', import.meta.url));

/**
 * Run the guard with `args`.
 *
 * `stdio: 'ignore'` is deliberate: this sandbox forbids the piped stdio that
 * capturing output would need, and these tests only assert exit codes.
 */
function runGuard(args) {
  const result = spawnSync(GUARD, args, { stdio: 'ignore', windowsHide: true, timeout: 120_000 });
  return { status: result.status, error: result.error };
}

/** Whether the guard can actually run a child in this environment. */
function guardCanRun() {
  // The guard refuses unless its token carries restricting SIDs.
  const probe = runGuard(['--probe-current-token']);
  return probe.status === 0;
}

const present = existsSync(GUARD) && existsSync(HOOK);
const confined = present && guardCanRun();

test('both guard artifacts are committed', { skip: !present }, () => {
  assert.ok(existsSync(GUARD));
  assert.ok(existsSync(HOOK));
});

test('bare invocation is a usage error, not a guard failure', { skip: !present }, () => {
  const { status } = runGuard([]);
  assert.equal(status, 64, 'usage exit code');
});

test('a non-absolute target is a guard failure (125)', { skip: !present }, () => {
  const { status } = runGuard(['--', 'bash.exe', '-c', 'true']);
  assert.equal(status, 125, 'guard failures use 125');
});

test('the unfixed marker of a guard failure is never 126', { skip: !present }, () => {
  // 126 is reserved for a child that itself exited 125; the guard must not use
  // it for its own failures, or the two would be indistinguishable.
  const results = [runGuard([]), runGuard(['--', 'relative.exe'])].map((r) => r.status);
  assert.ok(!results.includes(126), `guard failures must not use 126, got ${results.join(',')}`);
});

test('a child exiting 125 is remapped to 126', { skip: !confined }, () => {
  // `mirror_exit_code` maps the child's 125 to 126 so that the plugin's
  // guard-failure rule (125 + signature) cannot match a command that chose
  // that code and printed that text itself.
  const forged = runGuard([
    '--',
    'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
    '--noprofile',
    '--norc',
    '-c',
    "echo 'msys-token-guard: forged' >&2; exit 125",
  ]);
  assert.equal(forged.status, 126, 'a forged 125 must not be reported as a guard failure');

  const plain = runGuard([
    '--',
    'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
    '--noprofile',
    '--norc',
    '-c',
    'exit 125',
  ]);
  assert.equal(plain.status, 126, 'any child 125 is remapped');
});

test('other child exit codes pass through unchanged', { skip: !confined }, () => {
  for (const code of [0, 1, 42, 127, 255]) {
    const { status } = runGuard([
      '--',
      'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
      '--noprofile',
      '--norc',
      '-c',
      `exit ${code}`,
    ]);
    assert.equal(status, code, `exit ${code} must be mirrored`);
  }
});

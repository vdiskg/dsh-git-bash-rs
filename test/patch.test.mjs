/**
 * Bundle-patch tests.
 *
 * The patch decides which rows are live in a profile, and a wrong row is not a
 * loud failure: `ctx.shell` accepts exactly one provider, so a second executor
 * either wins the seat silently or throws
 * `service "shell" has been registered` — which happened with
 * `dsh-sandbox-tune` installed alongside this plugin. The rows below are pinned
 * because nothing else in the suite reads this file.
 *
 * @module dsh-plugin-git-bash-rs/test/patch.test.mjs
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const patch = readFileSync(new URL('../cordis.patch.yml', import.meta.url), 'utf8');

/**
 * Read one row's `disabled:` value from the patch.
 *
 * The file is simple enough that a line scan is more honest than a YAML
 * dependency: it asserts the literal text a future edit would change.
 *
 * @param id - the row id to find.
 * @returns the trimmed `disabled:` value, or `undefined` when the row is absent.
 */
function disabledValueOf(id) {
  const rows = patch.split(/^(?=- id: )/mu);
  for (const row of rows) {
    if (!new RegExp(`^- id: ${id}$`, 'mu').test(row)) continue;
    const match = /^\s+disabled: (.+)$/mu.exec(row);
    return match?.[1]?.trim();
  }
  return undefined;
}

test('the PowerShell executor and tool are replaced', () => {
  assert.equal(disabledValueOf('pwsh-sandbox'), 'true', 'the shipped PowerShell executor must stand down');
  assert.equal(disabledValueOf('tool-pwsh'), 'true', 'the PowerShell tool must not be offered');
  assert.equal(disabledValueOf('tool-bash'), 'false', 'the bash tool must stay enabled');
});

test('exactly one executor may own ctx.shell', () => {
  // Both this plugin and dsh-sandbox-tune provide `ctx.shell`; the second
  // registration throws. Installing both without this row fails activation with
  // `service "shell" has been registered at <CacheSandboxExecutor>`.
  assert.equal(
    disabledValueOf('sandbox-tune-bash'),
    'true',
    'the tuning bundle executor must stand down so this plugin can own ctx.shell',
  );
  // Its sandbox provider is a different service and must stay available: that is
  // where the writable-root whitelist comes from.
  assert.equal(disabledValueOf('sandbox'), undefined, 'the sandbox provider row must not be touched here');
  assert.equal(disabledValueOf('sandbox-tune-provider'), undefined, 'the tuning provider must keep running');
});

test('the Git Bash rows are inserted and scoped to Windows', () => {
  assert.match(patch, /- id: git-bash-shell[\s\S]*?name: 'dsh-plugin-git-bash-rs'/u);
  assert.match(patch, /- id: git-bash-agent-shell[\s\S]*?name: 'dsh-plugin-git-bash-rs\/agents'/u);
  // Both halves are inert off Windows: the native guard is win32-x64 only.
  const windowsGuards = patch.match(/disabled: !!js process\.platform !== 'win32'/gu) ?? [];
  assert.equal(windowsGuards.length, 2, 'both inserted rows must be Windows-only');
});

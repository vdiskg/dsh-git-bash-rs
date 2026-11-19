/**
 * Regression tests for behaviour the TypeScript port nearly lost.
 *
 * A port can drop a runtime guard without any test noticing, because a deleted
 * check is invisible to the compiler when the seam's *types* say the check is
 * unreachable. Both guards below were present in the hand-written JavaScript,
 * absent after the rewrite, and the 55-test suite stayed green throughout.
 *
 * The guards target providers that violate their declared type, so no in-repo
 * provider reaches them. These tests therefore drive a fake provider that does
 * exactly that, which is the only way to assert the *behaviour* rather than the
 * presence of a string in the emitted file.
 *
 * @module dsh-plugin-git-bash-rs/test/fidelity.test.mjs
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { loadPlugin, makeConfig, makeContext, makeRequest } from './executor-harness.mjs';

const compiled = readFileSync(new URL('../lib/index.js', import.meta.url), 'utf8');

test('a provider that resolves no confined argv fails closed', async () => {
  const { module, cordis, sandbox } = await loadPlugin();
  const { SandboxUnavailableError } = sandbox;

  for (const returned of [undefined, null, {}, { argv: 'not-an-array' }]) {
    const ctx = makeContext(cordis, { mode: 'workspace-write' });
    ctx.sandbox.confine = async () => returned;
    const executor = new module.GitBashExecutor(ctx, makeConfig());

    await assert.rejects(
      () => executor.execute(makeRequest('echo hi')),
      (error) => {
        // The tool layer routes on this class; a TypeError would be misreported
        // as a plugin bug instead of "the sandbox could not confine".
        assert.ok(
          error instanceof SandboxUnavailableError,
          `expected SandboxUnavailableError for ${JSON.stringify(returned)}, got ${String(error)}`,
        );
        assert.match(String(error.message), /no confined argv/u);
        return true;
      },
    );
  }
});

test('describeGuardFailure coerces a non-string detail instead of throwing', async () => {
  // Exported from the package root, so unbundled JavaScript can call it with any
  // value; the String() coercion keeps it a pass-through.
  const { module } = await loadPlugin();
  for (const detail of [42, null, undefined, {}, ['a']]) {
    assert.doesNotThrow(() => module.describeGuardFailure(detail));
    assert.equal(typeof module.describeGuardFailure(detail), 'string');
  }
  // A real DACL line is still recognised and annotated.
  const annotated = module.describeGuardFailure(
    'msys-token-guard: OpenProcessToken(child default dacl) failed (Win32 5)',
  );
  assert.ok(annotated.includes('default DACL'));
});

test('the serviceable-config validator is still bound from the peer', () => {
  // Dropped once during the port. It is the hook a caller uses to reject a
  // budget that cannot be honoured, so the binding must stay; nothing else
  // reads it, which is exactly why it is easy to lose.
  assert.match(compiled, /assertServiceableBashConfig/u);
});

test('the emitted client half is a script, not a module', () => {
  // DSH's client loader evaluates it as a plain script; an `export` marker makes
  // that fail at page load with no server-side symptom.
  const client = readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8');
  assert.ok(!/^export\b/mu.test(client), 'lib/client.js must not export');
  assert.ok(!/^import\b/mu.test(client), 'lib/client.js must not import');
});

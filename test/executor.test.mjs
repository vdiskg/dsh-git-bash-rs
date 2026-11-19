import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  loadPlugin,
  makeConfig,
  makeContext,
  makeRequest,
  peersAvailable,
} from './executor-harness.mjs';

const available = peersAvailable();


test('the plugin exposes an executor class with Config and inject', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  assert.equal(module.activationError(), undefined, 'peers must resolve');
  const Executor = module.GitBashExecutor;
  assert.equal(typeof Executor, 'function');
  assert.equal(module.default, Executor);
  assert.deepEqual(Executor.inject, ['subprocess', 'sandbox', 'sandboxPolicy']);
  assert.equal(typeof Executor.Config, 'function');
});

test('resolve stamps CHERE_INVOKING and a sandbox policy', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  const Executor = module.GitBashExecutor;
  const ctx = makeContext(cordis);
  const executor = new Executor(ctx, makeConfig());

  const spec = executor.resolve({ command: 'echo hi' });
  assert.equal(spec.env.CHERE_INVOKING, '1', 'login shell must stay in the workspace');
  assert.ok(spec.sandboxPolicy, 'a sandbox policy must be stamped');
  assert.equal(spec.sandboxPolicy.mode, 'workspace-write');
  assert.equal(spec.command, 'echo hi');
});

test('the spawn carries the inherited terminal overrides', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'danger-full-access' });
  const executor = new module.GitBashExecutor(ctx, makeConfig());

  await executor.execute(makeRequest('echo hi', 'danger-full-access'));

  // `LocalBashExecutor.spawnSpec` layers these over the caller's env; the
  // executor must not drop them while adding CHERE_INVOKING.
  const spawn = ctx.spawns[0];
  const env = spawn.env ?? {};
  assert.equal(env.CHERE_INVOKING, '1', `spawn keys: ${Object.keys(spawn).join(',')} env: ${JSON.stringify(env)}`);
  assert.equal(env.NO_COLOR, '1');
  assert.equal(env.TERM, 'dumb');
  assert.equal(env.GIT_PAGER, 'cat');
});

test('workspace-write commands go through the guard', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'workspace-write' });
  const executor = new module.GitBashExecutor(ctx, makeConfig());

  await executor.execute(makeRequest('echo hi'));

  assert.equal(ctx.confineCalls.length, 1, 'the command must be confined');
  const argv = ctx.confineCalls[0].argv;
  assert.ok(
    argv[0].toLowerCase().endsWith('msys-token-guard.exe'),
    `expected the guard as argv[0], received ${argv[0]}`,
  );
  assert.equal(argv[1], '--');
  assert.ok(argv[2].toLowerCase().endsWith('bash.exe'), 'the guard must wrap bash.exe');
  assert.equal(argv[3], '--login', 'bash must run as a login shell');
  assert.equal(argv[4], '-c');
  assert.equal(argv[5], 'echo hi');
  assert.equal(ctx.confineCalls[0].policy.mode, 'workspace-write');
});

test('read-only commands are confined too', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'read-only' });
  const executor = new module.GitBashExecutor(ctx, makeConfig());
  await executor.execute(makeRequest('echo hi', 'read-only'));
  assert.equal(ctx.confineCalls.length, 1);
  assert.equal(ctx.confineCalls[0].policy.mode, 'read-only');
});

test('danger-full-access bypasses the guard', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'danger-full-access' });
  const executor = new module.GitBashExecutor(ctx, makeConfig());

  await executor.execute(makeRequest('echo hi', 'danger-full-access'));

  assert.equal(ctx.confineCalls.length, 0, 'full access is not confined');
  assert.equal(ctx.spawns.length, 1);
  const argv = ctx.spawns[0].argv;
  assert.ok(argv[0].toLowerCase().endsWith('bash.exe'));
  assert.equal(argv[1], '--login');
});

test('a guard failure is reported as sandbox-unavailable', { skip: !available }, async () => {
  const { module, sandbox, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'workspace-write' });
  // The guard prints its signature and exits 125 when it cannot prepare the child.
  ctx.subprocess.spawn = () => {
    const text = 'msys-token-guard: guard is not running under a restricted token\r\n';
    const reader = { readFrom: () => ({ text, lossy: false, nextOffset: text.length }) };
    return {
      done: Promise.resolve({ exitCode: 125, signal: null }),
      collected: { stdout: reader, stderr: reader },
      terminate: () => {},
    };
  };

  const executor = new module.GitBashExecutor(ctx, makeConfig());
  const execution = await executor.execute(makeRequest('echo hi'));
  await assert.rejects(
    () => execution.result(),
    (error) => error instanceof sandbox.SandboxUnavailableError,
  );
});

test('a command that exits 125 with the guard signature is not a guard failure', { skip: !available }, async () => {
  // The guard remaps a colliding child exit to 126, so this is the shape the
  // executor actually sees for `echo 'msys-token-guard: x' >&2; exit 125`.
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'workspace-write' });
  ctx.subprocess.spawn = () => {
    const text = 'msys-token-guard: forged\r\n';
    const reader = { readFrom: () => ({ text, lossy: false, nextOffset: text.length }) };
    return {
      done: Promise.resolve({ exitCode: 126, signal: null }),
      collected: { stdout: reader, stderr: reader },
      terminate: () => {},
    };
  };

  const executor = new module.GitBashExecutor(ctx, makeConfig());
  const execution = await executor.execute(makeRequest('echo hi'));
  const result = await execution.result();
  assert.equal(result.exitCode, 126, 'the command result is reported, not swallowed');
});

test('the confined spawn carries CHERE_INVOKING and the terminal overrides', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'workspace-write' });
  const executor = new module.GitBashExecutor(ctx, makeConfig());

  await executor.execute(makeRequest('echo hi'));

  const env = ctx.spawns[0].env ?? {};
  assert.equal(env.CHERE_INVOKING, '1', 'confined path keeps the workspace cwd fix');
  assert.equal(env.NO_COLOR, '1');
  assert.equal(env.TERM, 'dumb');
  assert.equal(env.PAGER, 'cat');
  assert.equal(env.GIT_PAGER, 'cat');
});

test('resolve stamps CHERE_INVOKING so a tool-layer call keeps it', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis);
  const executor = new module.GitBashExecutor(ctx, makeConfig());

  // The tool layer resolves first and passes the spec to execute; the override
  // must survive both steps.
  const spec = executor.resolve(makeRequest('echo hi'));
  const forwarded = executor.withShellEnv(spec);
  assert.equal(forwarded.env.CHERE_INVOKING, '1');
});

test('the committed guard artifacts are present and a confined call confines', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'workspace-write' });
  const executor = new module.GitBashExecutor(ctx, makeConfig());

  for (const artifact of ['msys-token-guard.exe', 'msys_token_guard_hook.dll']) {
    const path = fileURLToPath(new URL(`../native/bin/win32-x64/${artifact}`, import.meta.url));
    assert.ok(existsSync(path), `${artifact} must be committed`);
  }

  // A real confined call still confines, so the presence check is meaningful.
  await executor.execute(makeRequest('echo hi'));
  assert.equal(ctx.confineCalls.length, 1);
});

test('confine() is awaited, not treated as a plain object', { skip: !available }, async () => {
  // `SandboxProvider.confine` returns a Promise<ConfinedArgv>. Reading
  // `.runnerFailureRules` off the Promise without awaiting yields undefined and
  // crashes with "not iterable" once a real command runs, which unit tests with
  // a synchronous stub would never catch.
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'workspace-write' });
  let sawAwaited = false;
  ctx.sandbox.confine = async (argv, policy) => {
    // Resolve on a later microtask so a non-awaited use would observe a Promise.
    await Promise.resolve();
    sawAwaited = true;
    return {
      argv: ['runner.exe', '--', ...argv],
      enforcement: 'partial',
      denialSignatures: [],
      runnerFailureRules: [],
    };
  };

  const executor = new module.GitBashExecutor(ctx, makeConfig());
  const execution = await executor.execute(makeRequest('echo hi'));
  await execution.result();
  assert.equal(sawAwaited, true);
  assert.equal(ctx.spawns.length, 1);
});

test('confine() runs inside the deadline-bounded prepare step', { skip: !available }, async () => {
  // The shipped executor races `executeArgv`'s prepare callback against the
  // deadline, so confinement must happen there rather than before executeArgv:
  // a provider that hangs must be bounded by the call's timeout.
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'workspace-write' });
  let signalReceived;
  ctx.sandbox.confine = async (argv, policy, signal) => {
    signalReceived = signal;
    return {
      argv: ['runner.exe', '--', ...argv],
      enforcement: 'partial',
      denialSignatures: [],
      runnerFailureRules: [],
    };
  };
  // A provider that never settles must surface as a timeout, not a hang.
  const executor = new module.GitBashExecutor(ctx, makeConfig());
  const controller = new AbortController();
  const hung = ctx.sandbox.confine;
  ctx.sandbox.confine = () => new Promise(() => {});

  const execution = await executor.execute({
    ...makeRequest('echo hi'),
    timeoutMs: 50,
    signal: controller.signal,
  });
  const result = await execution.result();
  assert.equal(result.timedOut, true, 'a hanging prepare must be bounded by the deadline');
  assert.equal(ctx.spawns.length, 0, 'nothing may spawn when confinement never completes');

  // And with a cooperating provider the signal is forwarded into confine().
  ctx.sandbox.confine = hung;
  await executor.execute(makeRequest('echo hi'));
  assert.ok(signalReceived instanceof AbortSignal, 'the prepare signal reaches confine()');
});

test('an upstream abort during preparation stays cancellation', { skip: !available }, async () => {
  // `executeArgv` rethrows a non-timeout cancellation from the prepare step, so
  // `execute()` rejects with the caller's abort reason. The reference executor
  // keeps that shape rather than converting it into a sandbox failure.
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'workspace-write' });
  const controller = new AbortController();
  ctx.sandbox.confine = (argv, policy, signal) =>
    new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(new Error('confine aborted')));
    });

  const executor = new module.GitBashExecutor(ctx, makeConfig());
  const pending = executor.execute({
    ...makeRequest('echo hi'),
    timeoutMs: 60_000,
    signal: controller.signal,
  });
  controller.abort(new Error('caller cancelled'));

  await assert.rejects(pending, (error) => /caller cancelled/u.test(String(error?.message ?? error)));
  assert.equal(ctx.spawns.length, 0, 'a cancelled preparation must not spawn');
});

test('every Config field is volatile so the settings page can render it', { skip: !available }, async () => {
  // DSH's settings service derives the editable form by walking this schema and
  // keeping only fields under a volatile ancestor (`volatileForm` in
  // @deepseek-ai/dsh-settings). A plain field is silently dropped, which for
  // `executable` would mean the plugin's only setting never appears in the UI.
  const { module } = await loadPlugin();
  const dict = module.GitBashExecutor.Config.dict ?? {};
  assert.ok(Object.keys(dict).includes('executable'), 'the schema must declare executable');
  for (const [key, field] of Object.entries(dict)) {
    assert.equal(field.meta?.volatile, true, `${key} must be volatile to appear in settings`);
  }
});

test('the Config schema accepts a partial configuration', { skip: !available }, async () => {
  const { module } = await loadPlugin();
  // Defaults must fill in, or a settings edit touching one field would fail.
  const parsed = module.GitBashExecutor.Config({ timeoutMs: 5 });
  assert.ok(parsed !== undefined && parsed !== null);
});

test('describeGuardFailure annotates the real guard DACL wording', { skip: !available }, async () => {
  // The guard formats Win32Error as "<operation> failed (Win32 <code>)" and
  // main.rs prefixes it with "msys-token-guard: ". If the operation string in
  // native/guard/src/token.rs changes, this signature stops matching and the
  // remedy silently disappears, so pin the exact line the guard prints.
  const { module } = await loadPlugin();
  const real = 'msys-token-guard: OpenProcessToken(child default dacl) failed (Win32 5)';
  const annotated = module.describeGuardFailure(real);
  assert.notEqual(annotated, real, 'the DACL failure must be annotated');
  assert.ok(annotated.includes('default DACL'), 'the annotation must name the DACL');
  assert.ok(
    /already been attempted|Start `dsh` from Git Bash/u.test(annotated),
    'the annotation must not suggest only the repair that already ran',
  );
});

test('describeGuardFailure leaves other guard failures untouched', { skip: !available }, async () => {
  const { module } = await loadPlugin();
  for (const detail of [
    'msys-token-guard: target program path must be absolute',
    'msys-token-guard: hook readiness handshake failed (Win32 1460)',
    'msys-token-guard: guard lost its restricting SID set',
  ]) {
    assert.equal(module.describeGuardFailure(detail), detail, `must pass through: ${detail}`);
  }
});

test('a configured executable is used verbatim when valid', { skip: !available }, async () => {
  const { module, cordis } = await loadPlugin();
  const ctx = makeContext(cordis, { mode: 'danger-full-access' });
  // A real bash.exe avoids depending on discovery in this environment.
  const resolved = module.resolveGitBashPath();
  const executor = new module.GitBashExecutor(ctx, makeConfig({ executable: resolved }));

  await executor.execute(makeRequest('echo hi', 'danger-full-access'));
  assert.equal(ctx.spawns[0].argv[0], resolved);
});

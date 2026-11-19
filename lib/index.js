// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
/**
 * Git for Windows Bash executor for DeepSeek Harness.
 *
 * Structurally this is the shipped `SandboxBashExecutor`: it inherits
 * `LocalBashExecutor`'s process mechanics (deadlines, bounded output, spill
 * files, the terminal environment) and only replaces the shell argv, wrapping
 * it through `ctx.sandbox.confine`. What changes is *what* gets wrapped:
 *
 * ```text
 * danger-full-access : bash.exe --login -c <command>
 * read-only          : sandbox runner -> msys-token-guard.exe -> bash.exe
 * workspace-write    : sandbox runner -> msys-token-guard.exe -> bash.exe
 * ```
 *
 * The guard exists because MSYS2 cannot start under DSH's `WRITE_RESTRICTED`
 * token; see `DESIGN.md`. It runs *inside* the confined token, so the sandbox
 * is exactly the one the policy produced — the guard never widens it.
 *
 * @module dsh-plugin-git-bash-rs
 */
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { accessSync, constants, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolveGitBashPath } from './discovery.js';
const require = createRequire(import.meta.url);
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
/** The confined launcher shipped in this package. */
const GUARD_EXECUTABLE = resolve(PACKAGE_ROOT, 'native', 'bin', 'win32-x64', 'msys-token-guard.exe');
/** The hook DLL the guard injects; both must ship together. */
const GUARD_HOOK = resolve(PACKAGE_ROOT, 'native', 'bin', 'win32-x64', 'msys_token_guard_hook.dll');
/** Only the `-x64` guard build exists. */
const SUPPORTED_ARCH = 'x64';
/**
 * The guard's own failure signature: it prints `msys-token-guard: <detail>` and
 * exits 125 whenever it cannot prepare the child, so the command never ran.
 */
const GUARD_FAILURE_RULE = {
    allowedExitCodes: [125],
    fatalSignatures: ['msys-token-guard:'],
};
/**
 * The guard's own wording when the restricted child token cannot be prepared
 * because the inherited DACL offers the user nothing usable.
 *
 * The guard prints `msys-token-guard: OpenProcessToken(child default dacl)
 * failed (Win32 N)`; this matches the context, case-insensitively, leaving the
 * Win32 code free to vary. The constant is kept in step with the Rust side
 * (`token.rs`, `grant_logon_sid_to_default_dacl`) by a test that feeds the real
 * guard wording through {@link describeGuardFailure}.
 */
const SERVER_DACL_FAILURE_SIGNATURE = 'openprocesstoken(child default dacl)';
/** An absolute Windows path ending in `bash.exe`. */
const GIT_BASH_EXECUTABLE_PATTERN = /^(?:[A-Z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+[\\/]|%[^%]+%[\\/])(?:.*[\\/])?bash\.exe$/iu;
/**
 * Turn the guard's bare DACL failure line into an actionable message.
 *
 * Only the DACL case is rewritten: every other guard failure is already
 * specific, and inventing advice for it would be noise.
 *
 * @param detail - the matched fatal stderr line from the guard.
 * @returns the detail, extended when it names the DACL step.
 */
export function describeGuardFailure(detail) {
    // Exported, so a caller outside the type system may pass a non-string; the
    // coercion keeps this a pass-through instead of throwing.
    if (!String(detail).toLowerCase().includes(SERVER_DACL_FAILURE_SIGNATURE))
        return String(detail);
    // Phrase this as "still failing" rather than "run the repair": the executor
    // has already attempted it for this process, so recommending it again would
    // send the user to a step that just ran.
    return `${detail} — git-bash: the DSH server process token's default DACL does not grant the `
        + 'signed-in user usable access, so the guard cannot prepare the restricted child token. '
        + 'The automatic normalization has already been attempted for this process and it did not '
        + 'settle the DACL. Start `dsh` from Git Bash, which restores the standard shape as MSYS2 '
        + 'starts, or run '
        + `\`"${GUARD_EXECUTABLE}" --normalize-server-dacl\` from an admin shell and restart the server.`;
}
/**
 * Load the `@deepseek-ai/*` peer packages this plugin binds to.
 *
 * Under DSH these are ordinary peer dependencies resolved from the
 * installation. The `globalThis.__dshGitBashRsPeers` seam exists so a test
 * harness can supply the same modules by reading them from the installation.
 *
 * The peers are ES modules, so `createRequire` cannot load them (Node rejects
 * `require()` of an ESM specifier); resolution goes through `require.resolve`
 * followed by a dynamic `import()`. Imports happen **sequentially**: DSH's own
 * loader imports plugin modules concurrently, and a `Promise.all` here would
 * race against it ("not yet fully loaded").
 *
 * @returns the resolved peer bindings.
 * @throws {Error} naming the peer that could not be loaded.
 */
async function loadPeers() {
    const injected = globalThis.__dshGitBashRsPeers;
    const load = async (name) => {
        const preloaded = injected?.[name];
        if (preloaded !== undefined)
            return preloaded;
        let resolvedPath;
        try {
            resolvedPath = require.resolve(name);
        }
        catch (error) {
            throw new Error(`git-bash: cannot load the peer dependency ${name}. Install the plugin into a DSH `
                + 'profile, which supplies these packages from the installation.'
                + ` (${error instanceof Error ? error.message : String(error)})`, { cause: error });
        }
        try {
            return (await import(pathToFileURL(resolvedPath).href));
        }
        catch (error) {
            throw new Error(`git-bash: failed to import the peer dependency ${name} from ${resolvedPath}.`
                + ` (${error instanceof Error ? error.message : String(error)})`, { cause: error });
        }
    };
    // Sequential on purpose; see the note above.
    const bashLocal = await load('@deepseek-ai/dsh-bash-local');
    const sandbox = await load('@deepseek-ai/dsh-sandbox');
    const schemastery = await load('@deepseek-ai/schemastery');
    return {
        LocalBashExecutor: bashLocal.LocalBashExecutor,
        assertServiceableBashConfig: bashLocal.assertServiceableBashConfig,
        SandboxUnavailableError: sandbox.SandboxUnavailableError,
        classifyRunnerFailure: sandbox.classifyRunnerFailure,
        isRunnerSpawnFailure: sandbox.isRunnerSpawnFailure,
        matchesSignature: sandbox.matchesSignature,
        z: (schemastery.default ?? schemastery),
    };
}
/**
 * Whether a path is a regular readable file.
 *
 * @param path - candidate path.
 * @returns whether the path exists, is a file, and is readable.
 */
function isReadableFile(path) {
    try {
        if (!statSync(path).isFile())
            return false;
        accessSync(path, constants.R_OK);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Validate an explicitly configured executable and return it resolved.
 *
 * @param config - the live plugin configuration.
 * @returns the resolved `bash.exe`, or `undefined` when nothing was configured.
 * @throws {TypeError} when the configured value is not an absolute `bash.exe`.
 */
function resolveConfiguredExecutable(config) {
    const executable = typeof config.executable === 'string' ? config.executable.trim() : '';
    if (executable.length === 0)
        return undefined;
    if (!GIT_BASH_EXECUTABLE_PATTERN.test(executable)) {
        throw new TypeError('git-bash: executable must be an absolute Windows path ending in bash.exe');
    }
    return resolveGitBashPath(executable);
}
/**
 * Environment entries this executor always contributes.
 *
 * `CHERE_INVOKING` stops a login shell from switching to `$HOME` on startup,
 * so `pwd` is the session workspace. The caller's own entries still win.
 *
 * @param existing - the caller's entries, if any.
 * @returns the merged environment.
 */
function shellEnv(existing) {
    return { CHERE_INVOKING: '1', ...(existing ?? {}) };
}
/**
 * Refuse to confine unless the guard and its hook are actually present.
 *
 * Failing here is the difference between "the command did not run under
 * confinement" and silently running it unconfined.
 *
 * @param Unavailable - the peer's `SandboxUnavailableError` constructor.
 * @param mode - the confined mode being requested.
 * @throws when the platform is unsupported or an artifact is missing.
 */
function assertNativeGuard(Unavailable, mode) {
    if (process.platform !== 'win32' || process.arch !== SUPPORTED_ARCH) {
        throw new Unavailable(mode, `Git Bash restricted mode requires win32-${SUPPORTED_ARCH}, received ${process.platform}-${process.arch}`);
    }
    for (const artifact of [GUARD_EXECUTABLE, GUARD_HOOK]) {
        if (!isReadableFile(artifact)) {
            throw new Unavailable(mode, `Git Bash native guard artifact is unavailable: ${artifact}`);
        }
    }
}
/**
 * Build the plugin's `Config` schema.
 *
 * The bash budgets come from `LocalBashExecutor.Config`, so this executor and
 * the stock one stay interchangeable. `executable` stays permissive at the
 * schema level on purpose: a legacy bad value must still render a configuration
 * card so it can be corrected, and `resolveConfiguredExecutable` enforces the
 * shape on use.
 *
 * Every field is `volatile`, matching the base schema. DSH's settings service
 * derives the editable form by walking the `Config` schema and keeping only
 * fields whose nearest volatile ancestor makes them live
 * (`volatileForm` in `@deepseek-ai/dsh-settings`); a non-volatile field is
 * silently omitted from the settings page. `executable` must therefore be
 * volatile too, or the one setting this plugin adds would be invisible.
 *
 * The base fields are spread into a single `object` rather than composed with
 * `z.intersect`: Cordis validates volatile fields against a fixed path inside
 * the schema tree, and an `intersect` nests them under `$.0`, which that
 * validation rejects.
 *
 * @param resolved - the peers supplying the base schema.
 * @returns the composed schema.
 */
export function createConfig(resolved) {
    const { z: schema } = resolved;
    const base = resolved.LocalBashExecutor.Config;
    const fields = {};
    for (const [key, field] of Object.entries(base.dict ?? {}))
        fields[key] = field;
    fields.executable = schema
        .string()
        .default('')
        .role('path')
        .volatile()
        .description('Absolute path to Git for Windows bash.exe; blank uses automatic discovery.');
    return schema.object(fields);
}
/**
 * Decorate an execution handle's foreground projection in place, memoized once.
 *
 * The handle keeps its identity because the per-process facts and
 * `onProcessDone` key on the exact instance.
 *
 * @param execution - the handle to decorate.
 * @param map - projection applied to a successful run.
 * @param mapError - projection applied to a rejected run.
 * @returns the same handle, with `result` replaced.
 */
function decorateResult(execution, map, mapError) {
    const base = execution.result.bind(execution);
    let decorated;
    execution.result = () => {
        // `then(map, undefined)` rejects with the original error, which is what the
        // shipped executor does on a path with nothing to reclassify.
        decorated ??= base().then(map, mapError);
        return decorated;
    };
    return execution;
}
/**
 * Create the executor class bound to `resolved` peers.
 *
 * The base class comes from a peer package, so the subclass cannot be declared
 * at module scope; it is built here and handed to the Cordis loader, which
 * reads `Config`, `static inject`, and the service registration from it.
 *
 * @param resolved - the peers from {@link loadPeers}.
 * @returns a `LocalBashExecutor` subclass registering as `ctx.shell`.
 */
export function createExecutor(resolved) {
    const { LocalBashExecutor, SandboxUnavailableError, classifyRunnerFailure, isRunnerSpawnFailure, matchesSignature, } = resolved;
    return class GitBashExecutor extends LocalBashExecutor {
        static inject = ['subprocess', 'sandbox', 'sandboxPolicy'];
        // The base declares an exact schema type over its own six fields, so an
        // extended schema cannot be assignable to it structurally: the extra
        // `executable` field is what differs. Cordis reads this static to build the
        // configuration form, and only the runtime shape matters to it, so the
        // override is asserted rather than forced through the base's type.
        static Config = createConfig(resolved);
        /** The deployment default mode — the capability fact the tool layer reads. */
        mode;
        /** Per-process confinement facts, retained until the handle settles. */
        processFacts = new Map();
        executableCache;
        /** Whether the server-token repair has been attempted. */
        serverDaclNormalized = false;
        constructor(ctx, config) {
            super(ctx, config);
            this.mode = ctx.sandboxPolicy.defaultMode;
        }
        /**
         * Repair the server's own default DACL once per process.
         *
         * DSH derives every restricted token from the server token, whose DACL
         * starts as a copy of that token's default DACL. A server started outside
         * an MSYS2 environment can carry a default DACL without a usable entry for
         * the signed-in user, which blocks the guard's child-token setup. Starting
         * `dsh` from Git Bash gets this for free; this applies the same shape on
         * demand. The helper is idempotent and its failure is not fatal: the guard
         * still fails closed at the point of use, and an unrepaired DACL surfaces
         * there as `SANDBOX_UNAVAILABLE` rather than as a wrong answer.
         */
        ensureServerDaclNormalized() {
            if (this.serverDaclNormalized)
                return;
            this.serverDaclNormalized = true;
            if (process.platform !== 'win32' || process.arch !== SUPPORTED_ARCH)
                return;
            if (!isReadableFile(GUARD_EXECUTABLE))
                return;
            try {
                spawnSync(GUARD_EXECUTABLE, ['--normalize-server-dacl'], {
                    timeout: 10_000,
                    windowsHide: true,
                    stdio: 'ignore',
                });
            }
            catch {
                // Best effort: the confined path reports the real failure if any.
            }
        }
        /** The configured default mode — the capability fact the tool layer reads. */
        get sandboxMode() {
            return this.mode;
        }
        /**
         * The live configuration, narrowed to this plugin's schema.
         *
         * The base class types `config` as its own six-field shape, which cannot
         * mention `executable`; the row was loaded against {@link createConfig}, so
         * the extra field really is present.
         */
        get gitBashConfig() {
            return this.config;
        }
        /**
         * Resolve the configured or discovered `bash.exe`, caching by configuration
         * value so a changed setting is picked up on the next command.
         */
        get executable() {
            const configured = this.gitBashConfig.executable;
            const declared = typeof configured === 'string' ? configured.trim() : '';
            const cached = this.executableCache;
            if (cached !== undefined && cached.declared === declared)
                return cached.resolved;
            const resolvedPath = resolveConfiguredExecutable(this.gitBashConfig) ?? resolveGitBashPath();
            this.executableCache = { declared, resolved: resolvedPath };
            return resolvedPath;
        }
        /** Stamp the complete per-call policy, as the shipped sandbox executor does. */
        resolve(request) {
            const spec = super.resolve(request);
            return {
                ...spec,
                env: { ...shellEnv(spec.env), ...(request.env ?? {}) },
                sandboxPolicy: request.sandboxPolicy ?? this.ctx.sandboxPolicy.resolve(),
            };
        }
        /**
         * Apply the shell environment at the execution boundary too.
         *
         * The tool layer calls {@link resolve} first, but a direct `execute` (as
         * tests and internal callers do) receives the caller's spec unchanged, so
         * the login-shell fix must not depend on `resolve` having run.
         *
         * @param spec - the caller's execution spec.
         * @returns the spec with the shell environment applied.
         */
        withShellEnv(spec) {
            return { ...spec, env: { ...shellEnv(spec.env) } };
        }
        /** The bash argv for one command. */
        bashArgv(command) {
            return [this.executable, '--login', '-c', command];
        }
        /** The confined argv: the guard wraps the same bash invocation. */
        guardedArgv(command, mode) {
            assertNativeGuard(SandboxUnavailableError, mode);
            return [GUARD_EXECUTABLE, '--', ...this.bashArgv(command)];
        }
        /**
         * The resolved policy, or a clear failure when the tool layer omitted it.
         *
         * @param spec - the caller's execution spec.
         * @returns the sandbox policy the call must honour.
         * @throws {Error} when the spec carries no policy.
         */
        resolvedPolicy(spec) {
            if (!spec.sandboxPolicy) {
                throw new Error('git-bash: resolved execution is missing sandbox policy');
            }
            return spec.sandboxPolicy;
        }
        /**
         * Confine one command through the sandbox seam and add the guard's rule.
         *
         * `ctx.sandbox.confine` is asynchronous — it probes and prepares the
         * backend before returning the wrapped argv — so it must be awaited; the
         * ready `ConfinedArgv` is what carries the enforcement, denial dialect and
         * runner-failure rules the executor classifies against.
         *
         * @param command - the shell source to run.
         * @param policy - the resolved confinement policy, already narrowed to a
         *   confining mode by the caller.
         * @param signal - cancellation of confinement preparation.
         * @returns the provider's wrap with the guard's rule appended.
         */
        async confineCommand(command, policy, signal) {
            this.ensureServerDaclNormalized();
            const confined = await this.ctx.sandbox.confine(this.guardedArgv(command, policy.mode), policy, signal);
            // `ConfinedArgv.argv` is non-optional in the seam's type, but a third-party
            // provider is still free to resolve a shape it never validated. Treat that
            // as "the sandbox could not confine", which the tool layer routes on,
            // rather than letting a `TypeError` escape from deep inside the projection.
            if (confined === undefined || confined === null || !Array.isArray(confined.argv)) {
                throw new SandboxUnavailableError(policy.mode, 'the sandbox provider returned no confined argv');
            }
            // The seam always supplies `runnerFailureRules`; treat a provider that
            // omits it as having none rather than crashing, so the guard's own rule
            // (the one this plugin depends on) is still applied.
            const provided = Array.isArray(confined.runnerFailureRules) ? confined.runnerFailureRules : [];
            return {
                argv: confined.argv,
                enforcement: confined.enforcement,
                denialSignatures: confined.denialSignatures,
                runnerFailureRules: [...provided, GUARD_FAILURE_RULE],
            };
        }
        async execute(spec) {
            const policy = this.resolvedPolicy(spec);
            if (policy.mode === 'danger-full-access') {
                const unconfined = await this.executeArgv(this.withShellEnv(spec), this.bashArgv(spec.command));
                // No `mapError`: the unconfined path has no sandbox failure to reclassify,
                // so a rejection propagates exactly as it did before this port.
                return decorateResult(unconfined, (result) => ({
                    ...result,
                    sandbox: { mode: 'danger-full-access', denied: false },
                }));
            }
            // Narrowed for the confined branch: `resolve` returned a policy whose
            // mode is not `danger-full-access`, which is exactly `ConfinedSandboxMode`.
            const mode = policy.mode;
            const confinedPolicy = { ...policy, mode };
            // Confinement runs as `executeArgv`'s prepare step, exactly as the shipped
            // sandbox executor does it: `executeArgv` races the prepare callback
            // against the deadline and the cancellation signal, so a provider that
            // hangs while preparing (ACL probing, temp-dir grants) is bounded by the
            // call's timeout instead of stalling the tool indefinitely. Awaiting it
            // before `executeArgv` would silently remove that bound.
            let confined;
            const execution = await this.executeArgv(this.withShellEnv(spec), async (signal) => {
                const prepared = await this.confineCommand(spec.command, confinedPolicy, signal);
                signal.throwIfAborted();
                confined = prepared;
                return prepared.argv;
            }, (started) => {
                // `executeArgv` publishes the handle only after this prepare callback
                // resolved, so `confined` is always assigned here.
                const facts = confined;
                this.processFacts.set(started, {
                    mode,
                    enforcement: facts.enforcement,
                    denialSignatures: facts.denialSignatures,
                    runnerFailureRules: facts.runnerFailureRules,
                    runnerProgram: facts.argv[0],
                    workdir: spec.workdir,
                });
            });
            return decorateResult(execution, (result) => {
                // A preparation timeout (or an abort) settles a handle without
                // spawning, so there is no confinement to report.
                if (confined === undefined)
                    return { ...result, sandbox: { mode, denied: false } };
                const { enforcement, denialSignatures, runnerFailureRules } = confined;
                // Runner failure outranks denial because the command did not run.
                const runnerFailure = classifyRunnerFailure(result.exitCode, result.stderr.text, runnerFailureRules);
                if (runnerFailure !== undefined) {
                    throw new SandboxUnavailableError(mode, describeGuardFailure(runnerFailure.detail));
                }
                return {
                    ...result,
                    sandbox: {
                        mode,
                        denied: matchesSignature(result.exitCode, result.stderr.text, denialSignatures),
                        enforcement,
                    },
                };
            }, (error) => {
                // An upstream abort remains cancellation even when it prevents the
                // spawn: report the caller's abort reason, not the confined runner's.
                if (spec.signal?.aborted === true)
                    spec.signal.throwIfAborted();
                if (confined !== undefined && isRunnerSpawnFailure(error, confined.argv[0], spec.workdir)) {
                    throw new SandboxUnavailableError(mode, String(error));
                }
                throw error;
            });
        }
        /** Stamp per-process sandbox facts before `done` settles. */
        onProcessDone(process_, stderr, providerRejected, providerError) {
            const facts = this.processFacts.get(process_);
            if (facts !== undefined) {
                this.processFacts.delete(process_);
                const runnerFailed = providerRejected
                    ? isRunnerSpawnFailure(providerError, facts.runnerProgram, facts.workdir)
                    : classifyRunnerFailure(process_.exitCode, stderr, facts.runnerFailureRules) !== undefined;
                process_.sandbox = {
                    mode: facts.mode,
                    denied: !runnerFailed && matchesSignature(process_.exitCode, stderr, facts.denialSignatures),
                    enforcement: facts.enforcement,
                    ...(runnerFailed ? { runnerFailed } : {}),
                };
            }
            super.onProcessDone(process_, stderr, providerRejected, providerError);
        }
    };
}
/**
 * Resolve the peers and build the plugin's default export.
 *
 * Cordis reads `Config` and the static `inject` from a value, not a promise, so
 * `lib/` exposes a lazily-initialized default: the first access performs the
 * (cached) peer load synchronously from the module's own top-level await.
 */
let resolvedPeers;
let activationFailure;
try {
    resolvedPeers = await loadPeers();
}
catch (error) {
    activationFailure = error;
}
/**
 * The executor class, or `undefined` when the peers could not be resolved.
 *
 * `undefined` is a hard failure, not a degraded mode: the bundle patch has
 * already disabled the shipped PowerShell executor and tool, so a row that
 * contributes nothing would leave Windows without any shell. The loader
 * therefore fails the row, and {@link activationError} names the cause.
 */
const GitBashExecutor = resolvedPeers === undefined ? undefined : createExecutor(resolvedPeers);
/**
 * Why the plugin could not build its executor, if it could not.
 *
 * @returns the error, or `undefined` when activation is possible.
 */
export function activationError() {
    return activationFailure;
}
if (activationFailure !== undefined) {
    console.error(`git-bash: plugin cannot activate. ${activationFailure instanceof Error ? activationFailure.message : String(activationFailure)}`);
}
export { GitBashExecutor };
/** Re-export discovery so consumers can resolve a path without importing internals. */
export { GIT_BASH_PATH_ENV, gitBashCandidates, resolveGitBashPath } from './discovery.js';
export default GitBashExecutor;

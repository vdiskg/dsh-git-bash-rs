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
import type { Config as LocalBashConfig, LocalBashExecutor as LocalBashExecutorType } from '@deepseek-ai/dsh-bash-local';
import type { RunnerFailureRule, SandboxMode } from '@deepseek-ai/dsh-sandbox';
import type z from '@deepseek-ai/schemastery';
/** The plugin's own configuration: the bash budgets plus the shell path. */
export interface Config extends LocalBashConfig {
    /** Absolute path to Git for Windows `bash.exe`; blank uses discovery. */
    executable: string;
}
/** The peer modules this plugin binds to, resolved at load time. */
interface ResolvedPeers {
    readonly LocalBashExecutor: typeof LocalBashExecutorType;
    readonly assertServiceableBashConfig: (config: LocalBashConfig) => void;
    readonly SandboxUnavailableError: new (mode: SandboxMode, detail?: string) => Error;
    readonly classifyRunnerFailure: (exitCode: number | null, stderr: string, rules: readonly RunnerFailureRule[]) => {
        readonly detail: string;
    } | undefined;
    readonly isRunnerSpawnFailure: (error: unknown, runnerProgram: string | undefined, workdir: string) => boolean;
    readonly matchesSignature: (exitCode: number | null, stderr: string, signatures: readonly string[]) => boolean;
    readonly z: typeof z;
}
/**
 * Turn the guard's bare DACL failure line into an actionable message.
 *
 * Only the DACL case is rewritten: every other guard failure is already
 * specific, and inventing advice for it would be noise.
 *
 * @param detail - the matched fatal stderr line from the guard.
 * @returns the detail, extended when it names the DACL step.
 */
export declare function describeGuardFailure(detail: string): string;
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
export declare function createConfig(resolved: ResolvedPeers): z<Config>;
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
export declare function createExecutor(resolved: ResolvedPeers): typeof LocalBashExecutorType;
/**
 * The executor class, or `undefined` when the peers could not be resolved.
 *
 * `undefined` is a hard failure, not a degraded mode: the bundle patch has
 * already disabled the shipped PowerShell executor and tool, so a row that
 * contributes nothing would leave Windows without any shell. The loader
 * therefore fails the row, and {@link activationError} names the cause.
 */
declare const GitBashExecutor: typeof LocalBashExecutorType | undefined;
/**
 * Why the plugin could not build its executor, if it could not.
 *
 * @returns the error, or `undefined` when activation is possible.
 */
export declare function activationError(): unknown;
export { GitBashExecutor };
/** Re-export discovery so consumers can resolve a path without importing internals. */
export { GIT_BASH_PATH_ENV, gitBashCandidates, resolveGitBashPath } from './discovery.js';
export default GitBashExecutor;

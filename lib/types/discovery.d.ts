/**
 * Locate the Git for Windows `bash.exe` the plugin should launch.
 *
 * Kept dependency-free and free of Cordis imports so tests and the executor
 * share one definition. Resolution order:
 *
 * 1. an explicit `executable` from configuration,
 * 2. the `DSH_GIT_BASH_PATH` environment variable,
 * 3. well-known install locations (Program Files, per-user installs, Scoop),
 * 4. a `git` entry on `PATH`.
 *
 * `C:\Windows\System32\bash.exe` is deliberately never considered: that is the
 * WSL launcher, not Git Bash, and it has unrelated semantics.
 *
 * @module dsh-plugin-git-bash-rs/discovery
 */
/** Environment variable naming an explicit `bash.exe`. */
export declare const GIT_BASH_PATH_ENV = "DSH_GIT_BASH_PATH";
/** Options accepted by {@link resolveGitBashPath}. */
export interface GitBashDiscoveryOptions {
    /** Environment to read; defaults to `process.env`. */
    readonly env?: NodeJS.ProcessEnv;
    /** Platform to assume; defaults to `process.platform`. */
    readonly platform?: NodeJS.Platform;
}
/**
 * Likely Git for Windows `bash.exe` paths, most preferred first.
 *
 * @param env - environment to read; defaults to the process environment.
 * @returns candidate absolute paths, de-duplicated and normalized.
 */
export declare function gitBashCandidates(env?: NodeJS.ProcessEnv): string[];
/**
 * Resolve and validate the Git for Windows Bash executable.
 *
 * @param executable - an explicit path from configuration, if any.
 * @param options - environment and platform overrides for tests.
 * @returns the canonical `bash.exe` path.
 * @throws {Error} naming every location that was checked when none is usable.
 */
export declare function resolveGitBashPath(executable?: string, options?: GitBashDiscoveryOptions): string;

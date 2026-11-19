// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
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
import { accessSync, constants, realpathSync, statSync } from 'node:fs';
import { win32 } from 'node:path';
/** Environment variable naming an explicit `bash.exe`. */
export const GIT_BASH_PATH_ENV = 'DSH_GIT_BASH_PATH';
/**
 * Read an environment entry case-insensitively (Windows semantics).
 *
 * @param env - environment to read.
 * @param name - variable name, matched case-insensitively.
 * @returns the trimmed value, or `undefined` when unset or blank.
 */
function envValue(env, name) {
    const wanted = name.toLowerCase();
    const entry = Object.entries(env).find(([key]) => key.toLowerCase() === wanted);
    const value = entry?.[1]?.trim();
    return value !== undefined && value.length > 0 ? value : undefined;
}
/**
 * Expand `%VAR%` references against `env`, leaving unknown ones intact.
 *
 * @param value - text that may contain `%VAR%` references.
 * @param env - environment to expand against.
 * @returns the expanded text.
 */
function expandEnvironmentVariables(value, env) {
    return value.replace(/%([^%]+)%/gu, (match, name) => envValue(env, name) ?? match);
}
/** `statSync` returning `undefined` for a missing or unreadable path. */
function statOrUndefined(candidate) {
    try {
        return statSync(candidate);
    }
    catch {
        return undefined;
    }
}
/**
 * Resolve a candidate to a canonical executable path.
 *
 * `statSync` follows links, which is what is wanted: the executable actually
 * launched is the target, and its permissions are the ones that matter.
 *
 * @param candidate - path to test.
 * @returns the canonical path, or `undefined` when it is not a runnable file.
 */
function canonicalExecutable(candidate) {
    try {
        const stat = statOrUndefined(candidate);
        if (stat === undefined || !stat.isFile())
            return undefined;
        accessSync(candidate, constants.X_OK);
        return realpathSync.native(candidate);
    }
    catch {
        return undefined;
    }
}
/**
 * Normalize, trim, and de-duplicate Windows paths preserving order.
 *
 * @param paths - candidate paths, in preference order.
 * @returns normalized absolute paths without case-insensitive duplicates.
 */
function uniqueWindowsPaths(paths) {
    const seen = new Set();
    const result = [];
    for (const candidate of paths) {
        const normalized = win32.normalize(candidate.trim());
        if (normalized.length === 0)
            continue;
        const key = normalized.toLowerCase();
        if (seen.has(key))
            continue;
        seen.add(key);
        result.push(normalized);
    }
    return result;
}
/**
 * Append both Git bash locations for one install root.
 *
 * @param candidates - list to append to.
 * @param root - a Git install root, or `undefined` to append nothing.
 */
function appendGitRoot(candidates, root) {
    if (!root)
        return;
    candidates.push(win32.join(root, 'bin', 'bash.exe'), win32.join(root, 'usr', 'bin', 'bash.exe'));
}
/**
 * Likely Git for Windows `bash.exe` paths, most preferred first.
 *
 * @param env - environment to read; defaults to the process environment.
 * @returns candidate absolute paths, de-duplicated and normalized.
 */
export function gitBashCandidates(env = process.env) {
    const candidates = [];
    for (const variable of ['ProgramFiles', 'ProgramW6432', 'ProgramFiles(x86)']) {
        const directory = envValue(env, variable);
        if (directory)
            appendGitRoot(candidates, win32.join(directory, 'Git'));
    }
    const localAppData = envValue(env, 'LOCALAPPDATA');
    if (localAppData)
        appendGitRoot(candidates, win32.join(localAppData, 'Programs', 'Git'));
    const userProfile = envValue(env, 'USERPROFILE');
    if (userProfile) {
        appendGitRoot(candidates, win32.join(userProfile, 'scoop', 'apps', 'git', 'current'));
        appendGitRoot(candidates, win32.join(userProfile, 'AppData', 'Local', 'Programs', 'Git'));
    }
    appendGitRoot(candidates, envValue(env, 'GIT_INSTALL_ROOT'));
    // A `git` entry on PATH implies its install root.
    const pathValue = envValue(env, 'PATH') ?? '';
    for (const rawEntry of pathValue.split(win32.delimiter)) {
        const entry = rawEntry.trim().replace(/^"|"$/gu, '');
        if (entry.length === 0)
            continue;
        const gitRoot = /^(.*[\\/]git)(?:[\\/].*)?$/iu.exec(entry)?.[1];
        if (gitRoot)
            appendGitRoot(candidates, gitRoot);
        if (/(?:^|[\\/])git(?:[\\/]|$)/iu.test(entry))
            candidates.push(win32.join(entry, 'bash.exe'));
    }
    return uniqueWindowsPaths(candidates);
}
/**
 * Resolve and validate the Git for Windows Bash executable.
 *
 * @param executable - an explicit path from configuration, if any.
 * @param options - environment and platform overrides for tests.
 * @returns the canonical `bash.exe` path.
 * @throws {Error} naming every location that was checked when none is usable.
 */
export function resolveGitBashPath(executable, options = {}) {
    const env = options.env ?? process.env;
    const platform = options.platform ?? process.platform;
    if (platform !== 'win32') {
        throw new Error('git-bash: Git for Windows is supported only on Windows');
    }
    const configured = executable?.trim() || envValue(env, GIT_BASH_PATH_ENV);
    if (configured) {
        const expanded = expandEnvironmentVariables(configured, env);
        const resolved = canonicalExecutable(expanded);
        if (resolved)
            return resolved;
        throw new Error(`git-bash: configured executable does not exist or is not executable: ${expanded}`);
    }
    const candidates = gitBashCandidates(env);
    for (const candidate of candidates) {
        const resolved = canonicalExecutable(candidate);
        if (resolved)
            return resolved;
    }
    throw new Error([
        'git-bash: Git for Windows Bash was not found.',
        `Install Git for Windows or set ${GIT_BASH_PATH_ENV} to bash.exe.`,
        candidates.length > 0 ? `Checked: ${candidates.join(', ')}` : 'No candidate paths were available.',
    ].join(' '));
}

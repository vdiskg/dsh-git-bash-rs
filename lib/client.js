// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
/**
 * Git Bash client half.
 *
 * This is not an ES module: DSH's client loader evaluates the emitted file and
 * calls the factory with the modules the plugin declares in
 * `dsh.client.inject`. Nothing is required directly — the whole feature is a
 * stylesheet keyed off the shipped row's own markup, so there is no React
 * component to mount and no slot election to win.
 *
 * Scope note: this half only makes long commands readable. It never touches the
 * executor, so a failure here costs presentation, not shell behaviour.
 *
 * @module dsh-plugin-git-bash-rs/client
 */
const STYLE_ID = 'dsh-plugin-git-bash-rs-command-wrap';
/**
 * Identity object stamped on the injected `<style>` element.
 *
 * Comparing against it (rather than by id) keeps two plugin instances from
 * removing each other's element during a reload.
 */
const STYLE_OWNER = {};
/**
 * Long commands are the norm here (heredocs, pipelines, multi-line `for`
 * loops), and the shipped row renders the whole command into one summary span
 * with `white-space: nowrap` plus `text-overflow: ellipsis`, so the operator
 * sees the beginning and nothing else.
 *
 * The rules are keyed off the shipped row's own markup, because the plugin API
 * gives no handle on that row: `tool.call.toolview` is a keyed slot, so a
 * registration *replaces* the shipped entry rather than wrapping it.
 *
 * - `[data-sample="bash"]` is a literal attribute in `bash-sample.tsx`.
 * - CSS-module class names are hashed per build, so they are matched by a
 *   stable fragment rather than a full name.
 */
const COMMAND_WRAP_CSS = `
/* The shipped row pins itself to one text line:
   .root { height: calc(24px + delta); align-items: center } and
   .summary { white-space: nowrap; text-overflow: ellipsis; overflow: hidden }.
   Letting the text wrap without relaxing that height would paint the extra
   lines outside the row and collide with its neighbours, so both ends of the
   pair are overridden together. */
[data-sample="bash"] {
  height: auto !important;
  min-height: calc(24px + var(--dsh-content-font-delta, 0px)) !important;
  align-items: flex-start !important;
}
[data-sample="bash"] [class*="summary"] {
  white-space: pre-wrap !important;
  overflow-wrap: anywhere !important;
  text-overflow: clip !important;
  overflow: visible !important;
}
/* Expanded body text (terminal output and the repeated command): wrap long
   lines, including a single long unbroken /c/... path. Upstream already sets
   pre-wrap here, so the useful addition is breaking mid-word. */
[data-sample="bash"] [class*="ioText"],
[data-sample="bash"] [data-command-text] {
  white-space: pre-wrap !important;
  overflow-wrap: anywhere !important;
}
`;
/**
 * The one global `document`, or `undefined` outside a browser.
 *
 * The client half is evaluated by the loader in a page, but the test suite also
 * evaluates it in a bare `vm` context, so this must not assume a DOM exists.
 *
 * @returns the document when it offers the APIs used below.
 */
function ownerDocument() {
    const scope = globalThis;
    if (typeof scope !== 'object' || scope === null)
        return undefined;
    const doc = scope.document;
    if (doc === undefined || doc === null)
        return undefined;
    return typeof doc.createElement === 'function' ? doc : undefined;
}
/**
 * Inject one style element, idempotently, owned by this plugin.
 *
 * @param id - the element id, so a reload reuses rather than duplicates.
 * @param content - CSS text.
 * @returns a disposer that removes the element while this owner still holds it.
 */
function installStyle(id, content) {
    const doc = ownerDocument();
    if (doc === undefined)
        return () => undefined;
    let style = doc.getElementById(id);
    if (style === null) {
        style = doc.createElement('style');
        style.id = id;
        doc.head.appendChild(style);
    }
    style.textContent = content;
    style.__dshGitBashRsOwner = STYLE_OWNER;
    const owned = style;
    return () => {
        if (owned.__dshGitBashRsOwner === STYLE_OWNER)
            owned.remove();
    };
}
/** Install the command-wrap stylesheet. */
function installCommandWrapStyle() {
    return installStyle(STYLE_ID, COMMAND_WRAP_CSS);
}
/**
 * Accept only an absolute Windows path that names `bash.exe`.
 *
 * Mirrors the host-side `GIT_BASH_EXECUTABLE_PATTERN`. Exported for the suite
 * and for a future settings surface; the client half does not yet call it.
 *
 * @param value - candidate path.
 * @returns whether the path has the shape of a Git Bash executable.
 */
function isGitBashExecutablePath(value) {
    if (typeof value !== 'string')
        return false;
    return /^(?:[A-Z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+[\\/]|%[^%]+%[\\/])(?:.*[\\/])?bash\.exe$/i.test(value.trim());
}
/**
 * Join a directory and a relative suffix with a single backslash.
 *
 * @param directory - the base directory.
 * @param suffix - the relative path to append.
 * @returns the joined path.
 */
function appendWindowsPath(directory, suffix) {
    return directory.endsWith('\\') ? directory + suffix : directory + '\\' + suffix;
}
/**
 * Turn a directory chosen in a picker into a `bash.exe` path.
 *
 * Users browse to one of several roots — the Git install root, its `bin`, or
 * its `usr` — and each maps to a real `bash.exe`, so the choice is resolved
 * here rather than rejected. Exported for the suite and a future settings
 * surface.
 *
 * @param directory - a chosen directory, in either slash style.
 * @returns a `bash.exe` path, or an empty string when nothing was chosen.
 */
function gitBashExecutableFromDirectory(directory) {
    let normalized = typeof directory === 'string' ? directory.trim().replace(/\//g, '\\') : '';
    normalized = normalized.replace(/\\+$/, '');
    if (/^[A-Za-z]:$/.test(normalized))
        normalized += '\\';
    if (normalized === '' || /(?:^|\\)bash\.exe$/i.test(normalized))
        return normalized;
    if (/(?:^|\\)bin$/i.test(normalized))
        return appendWindowsPath(normalized, 'bash.exe');
    if (/(?:^|\\)usr$/i.test(normalized))
        return appendWindowsPath(normalized, 'bin\\bash.exe');
    return appendWindowsPath(normalized, 'bin\\bash.exe');
}
/**
 * Plugin entry point.
 *
 * @param ctx - the client context this row was loaded into.
 */
function apply(ctx) {
    ctx.effect(() => installCommandWrapStyle(), 'git-bash-rs: command wrap style');
}
const inject = [];
// The loader contract: `window.__ModuleLoader__` is installed by the shell
// before this file is evaluated, and the factory's return value becomes the
// module's exports. The DOM's `window` type cannot declare it, so the cast goes
// through `unknown` — this is the one unavoidable assertion in this half.
const loader = globalThis.window.__ModuleLoader__;
loader.load({
    id: 'dsh-plugin-git-bash-rs',
    // The parameter is part of the loader contract even though this plugin
    // declares no `dsh.client.inject` entries and so requires nothing; naming it
    // keeps the shape identical to every other client bundle.
    factory: (_require) => {
        const exported = {
            apply,
            inject,
            // Pure helpers, exported so the suite can test them without a browser.
            gitBashExecutableFromDirectory,
            isGitBashExecutablePath,
        };
        return exported;
    },
});


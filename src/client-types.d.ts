// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
/**
 * Ambient types for the browser half's loader contract.
 *
 * DSH's client module system installs `window.__ModuleLoader__` before any
 * plugin bundle is evaluated, then calls each registered factory with a
 * `require` bound to that plugin's declared `dsh.client.inject` entries.
 *
 * These are declared globally, not as a module, so `client.ts` can use them
 * without importing anything: an import would make TypeScript treat that file
 * as a module and emit `export {}`, which the loader — which evaluates the file
 * as a plain script — would reject.
 *
 * @module dsh-plugin-git-bash-rs/client-types
 */

/** A disposer, or a promise of one, as Cordis effects accept. */
type ClientEffectDisposer = () => unknown;

/** The slice of Cordis' client `Context` this plugin actually calls. */
interface ClientContext {
  /**
   * Register a side effect owned by this plugin.
   *
   * @param setup - creates the disposer; runs immediately, synchronously.
   * @param label - a diagnostic name Cordis shows in error reports.
   * @returns the effect's own disposer.
   */
  readonly effect: (setup: () => ClientEffectDisposer, label?: string) => ClientEffectDisposer;
}

/** One module a plugin factory may request. */
type ClientRequire = (specifier: string) => unknown;

/** The registration object a client bundle hands the loader. */
interface ClientModuleRegistration {
  /** Package name; the loader throws when it does not match the installation. */
  readonly id: string;
  /**
   * Builds the module's exports.
   *
   * @param require - resolves the plugin's declared `dsh.client.inject` entries.
   * @returns the module's exports.
   */
  readonly factory: (require: ClientRequire) => unknown;
}

/** The global the shell installs before evaluating any plugin bundle. */
interface ClientModuleLoader {
  /** Register one plugin bundle. */
  readonly load: (registration: ClientModuleRegistration) => void;
}

/** `globalThis` as seen by the browser half. */
interface ClientModuleLoaderGlobal {
  readonly window: {
    readonly __ModuleLoader__: ClientModuleLoader;
  };
}

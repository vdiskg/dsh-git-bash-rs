// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
/**
 * Make the global Git Bash tool win over preset-provided shells.
 *
 * Agent presets contribute their own `bash`/`pwsh` tool rows from an ancestor
 * scope, so replacing the global executor alone is not enough: a preset's
 * PowerShell tool would still shadow the Git Bash one inside that agent. This
 * adapter, for every live and future agent:
 *
 * - registers the global (Git Bash-backed) `bash` tool in the agent's scope,
 *   shadowing whatever the preset contributed under the same name;
 * - restricts `pwsh` out of that scope;
 * - replaces the `tool:bash` system-prompt section with Git Bash-specific
 *   guidance and blanks the `tool:pwsh` section.
 *
 * @module dsh-plugin-git-bash-rs/agents
 */

import type { Context } from '@deepseek-ai/cordis';
import type { Agent } from '@deepseek-ai/dsh-agent';
import type {} from '@deepseek-ai/dsh-system-prompt';
import type {} from '@deepseek-ai/dsh-tools';

/** Plugin name, reported by the Cordis loader. */
export const name = 'git-bash-agent-shell';

/** Services this plugin needs before it can install its adapter. */
export const inject = ['agents', 'tools', 'systemPrompt'];

/**
 * Git Bash / Linux bash differences worth putting in the system prompt.
 *
 * The tool description carries the long form; this is the short reminder the
 * model sees every turn, so it lists only the traps that silently produce
 * wrong commands rather than errors.
 */
export const BASH_SECTION = [
  'Check the [exit code: N] marker on every Git Bash result; investigate failures before moving on.',
  'This is Git Bash (MSYS2) on Windows, not Linux. Windows paths appear as /c/... ; `C:\\foo` works too but avoid mixing.',
  'Do not assume Linux-only facilities: no systemd, no /proc, no apt, no real chmod/symlink semantics, and `ps`/`kill` are emulated.',
  // Under confinement the runner reserves 125 for its own failures, so a
  // command's 125 is reported as 126 to keep the two distinguishable. State
  // only the observed consequence, and scope it to confined runs: bash's own
  // 126 means "found but cannot execute", which is a real and common failure
  // here because chmod is a no-op, and unconfined runs are never remapped.
  'Under sandbox confinement one exit code is remapped: a command that exits 125 is reported as 126, because 125 is reserved for sandbox-runner failures. So in confined mode a 126 does not mean "found but cannot execute" — read stderr for the real cause. Unconfined runs are not remapped.',
  'Prefer forward-slash paths and quote them; CRLF line endings can break tools that parse text output.',
].join(' ');

/**
 * System-prompt section slots for the shell tools.
 *
 * These match `dsh-system-prompt`'s central `SECTION_ORDERS` allocation
 * (`TOOL_BASH: 1000`, `TOOL_PWSH: 1010`); a scoped registration shadows the
 * global section of the same name, so keeping the numbers identical means this
 * adapter replaces the stock guidance in place rather than reordering it.
 */
const TOOL_BASH_ORDER = 1000;
const TOOL_PWSH_ORDER = 1010;

/** Disposer returned by every registration. */
type Disposer = () => unknown;

/**
 * Install the adapter into one agent scope.
 *
 * @param ctx - the plugin context holding the global tool and prompt services.
 * @param agent - the agent whose scope receives the shadowing registrations.
 * @param installed - cleanup handles, keyed by agent, so disposal stays idempotent.
 */
function install(ctx: Context, agent: Agent, installed: Map<Agent, Disposer>): void {
  if (installed.has(agent)) return;
  const cleanup: Disposer = agent.ctx.effect(() => {
    const disposers: Disposer[] = [];

    const globalBash = ctx.tools.get('bash');
    if (!globalBash) {
      throw new Error(
        'git-bash-agent-shell: the global bash tool is unavailable; keep the tool-bash row enabled',
      );
    }
    disposers.push(agent.ctx.tools.register(globalBash));

    // `tools.restrict()` rejects a name that is not a known *global* tool, so
    // the deny is conditional on the global layer having `pwsh` at all. When it
    // does (the shipped PowerShell stack), denying unconditionally here — not
    // merely when the agent already sees it — is what stops a preset's own
    // contribution from reaching the model.
    disposers.push(
      ctx.tools.get('pwsh') === undefined
        ? () => undefined
        : agent.ctx.tools.restrict({ deny: ['pwsh'] }),
    );

    disposers.push(agent.ctx.systemPrompt.section({
      name: 'tool:bash',
      order: TOOL_BASH_ORDER,
      text: BASH_SECTION,
    }));
    // Blank the PowerShell section so the model is not told about a tool it
    // cannot call in this scope.
    disposers.push(agent.ctx.systemPrompt.section({
      name: 'tool:pwsh',
      order: TOOL_PWSH_ORDER,
      text: '',
    }));

    return () => {
      for (const dispose of disposers.reverse()) void dispose();
      if (installed.get(agent) === cleanup) installed.delete(agent);
    };
  }, 'git-bash-agent-shell.install()');
  installed.set(agent, cleanup);
}

/**
 * Plugin entry point.
 *
 * @param ctx - the Cordis context this row was loaded into.
 */
export function apply(ctx: Context): void {
  const installed = new Map<Agent, Disposer>();

  ctx.effect(() => {
    // The `agent/created` listener is typed as an async hook, so it must return
    // `undefined` rather than the `void` that `install` produces.
    const stopCreated = ctx.on('agent/created', ({ agent }) => {
      install(ctx, agent, installed);
      return undefined;
    });
    const stopDisposed = ctx.on('agent/disposed', ({ agent }) => installed.delete(agent));
    for (const agent of ctx.agents.list()) install(ctx, agent, installed);
    return async () => {
      stopCreated();
      stopDisposed();
      const cleanups = [...installed.values()];
      installed.clear();
      await Promise.allSettled(cleanups.map((cleanup) => Promise.resolve(cleanup())));
    };
  }, 'git-bash-agent-shell.lifecycle()');
}

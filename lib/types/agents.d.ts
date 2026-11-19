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
/** Plugin name, reported by the Cordis loader. */
export declare const name = "git-bash-agent-shell";
/** Services this plugin needs before it can install its adapter. */
export declare const inject: string[];
/**
 * Git Bash / Linux bash differences worth putting in the system prompt.
 *
 * The tool description carries the long form; this is the short reminder the
 * model sees every turn, so it lists only the traps that silently produce
 * wrong commands rather than errors.
 */
export declare const BASH_SECTION: string;
/**
 * Plugin entry point.
 *
 * @param ctx - the Cordis context this row was loaded into.
 */
export declare function apply(ctx: Context): void;

# dsh-plugin-git-bash-rs

Use **Git for Windows Bash** as DeepSeek Harness's default Windows shell, while
keeping DSH's `read-only` / `workspace-write` / `danger-full-access` semantics
exactly as shipped.

The reason this needs native code is explained in [DESIGN.md](DESIGN.md): DSH
confines Windows commands with a `WRITE_RESTRICTED` token, and MSYS2 — the
runtime behind every Git for Windows executable — cannot start under it.

## How it works

```text
danger-full-access : bash.exe --login -c <command>
read-only          : sandbox runner -> msys-token-guard.exe -> bash.exe
workspace-write    : sandbox runner -> msys-token-guard.exe -> bash.exe
```

The executor is a `LocalBashExecutor` subclass, so deadlines, output caps,
spill files, background jobs and the terminal environment are inherited from
the shipped implementation unchanged. Only the shell argv differs.

In the two confined modes the command is wrapped by the native guard. The guard
runs **inside** the already-confined token and never widens it: it only makes
the two MSYS2 startup operations that the restricted token rejects succeed,
using the per-logon-session SID instead of a broad group.

## Layout

| Path | Purpose |
|---|---|
| `src/` | plugin sources; `lib/` is the published copy the loader reads |
| `src/index.js` | `GitBashExecutor`, replacing `ctx.shell` on Windows |
| `src/agents.js` | per-agent adapter: Git Bash tool wins, `pwsh` removed |
| `src/discovery.js` | `bash.exe` resolution |
| `native/guard` | `msys-token-guard.exe` — confined launcher |
| `native/hook` | `msys_token_guard_hook.dll` — the MSYS2 detours |
| `native/bin/win32-x64` | committed build output, loaded by the plugin |
| `scripts/` | build and test helpers |

## Install

```
dsh plugin --profile <profile> add dsh-plugin-git-bash-rs
```

The bundle patch disables the shipped PowerShell executor and tool on Windows
and inserts the Git Bash executor. Other platforms are untouched.

## Configuration

| Setting | Meaning |
|---|---|
| `executable` | absolute path to `bash.exe`; blank uses discovery |
| `timeoutMs`, `maxTimeoutMs`, `maxOutputBytes`, `maxSpillBytes`, `graceMs` | the shipped bash budgets |

Discovery order: `executable` → `DSH_GIT_BASH_PATH` → Program Files / per-user
installs / Scoop → a `git` entry on `PATH`. The WSL launcher
(`C:\Windows\System32\bash.exe`) is never considered.

## Build

The plugin layer is TypeScript; the native layer is Rust.

```powershell
pnpm install --frozen-lockfile                     # dev dependencies
pnpm run build                                     # src/*.ts -> lib/ (+ .d.ts)
pnpm run build:native                              # native exe + dll
pnpm run typecheck                                 # tsc --noEmit
```

`.npmrc` carries only explanatory comments: pnpm on this setup resolves its
store from global configuration and does not pick the file up, so nothing here
tries to override it. Reproducibility rests on `pnpm-lock.yaml`, which pins
every dependency to an exact version and integrity hash — install with
`--frozen-lockfile` in CI so a drifted lockfile fails the build instead of being
silently rewritten.

Run the build in a normal shell, not inside a DSH session: pnpm creates its
store-operation lock next to the store, outside the workspace, which DSH's
`workspace-write` sandbox refuses.

Rust needs the `x86_64-pc-windows-msvc` target and the MSVC linker (Visual
Studio Build Tools, C++ workload). No CMake, no vendored C library.

`lib/client.js` is deliberately **not** an ES module: DSH's client loader
evaluates it as a plain script and calls the factory it registers on
`window.__ModuleLoader__`. TypeScript marks module files with an `export {}`
that this script evaluation rejects, so the build strips it and fails if any
`export` survives.

## Test

```powershell
pnpm test                                        # build, then run the suite
```

Runs through DSH's own runtime so the plugin's peer packages resolve from the
installation, and supplies them to the plugin through the documented test seam.

## Type checking

The `@deepseek-ai/*` packages this plugin binds to are installed as **dev
dependencies at the exact runtime version**. They exist twice on purpose:

- **devDependencies** give the compiler the real `.d.ts` files, so `typecheck`
  works on any machine with no reference to a particular DSH install.
- **peerDependencies** declare what the host must supply at runtime, so the
  packages are never bundled into the plugin.

The two lists must stay in step: if a peer's version changes, change both, or
the plugin compiles against types its host does not have.

## Failure behaviour

Any runner-side failure exits `125` with a `msys-token-guard:` line on stderr,
which DSH classifies as `SANDBOX_UNAVAILABLE` — "the command did not run" —
rather than as a command failure. A command that itself exits `125` is remapped
to `126` by the guard so the two cases cannot be confused, and a command is
never executed unconfined.

Before the first confined command the executor asks the guard to repair the
server's own default DACL (`--normalize-server-dacl`). DSH derives every
restricted token from the server token, so a `dsh` started outside MSYS2 can
carry a default DACL with no usable entry for the signed-in user. The repair is
idempotent, touches only the calling process's own token, and is best effort: an
unrepaired DACL still fails closed at the point of use.

## Guard helper subcommands

The committed guard is also useful on its own:

| Command | Purpose |
|---|---|
| `msys-token-guard.exe -- <abs-program> [args…]` | the confined launcher |
| `msys-token-guard.exe --probe-current-token` | print this process's restricting SIDs |
| `msys-token-guard.exe --normalize-server-dacl` | stamp the user's full-access ACE into the server default DACL |

Running `dsh` from Git Bash means the default DACL is already correct, so the
repair normally reports `server-dacl=ok` and changes nothing.

## License

MIT. This port references the source code of two upstream projects and
reimplements them in Rust; [NOTICE](NOTICE) lists both file by file, and
[LICENSE](LICENSE) carries both copyright notices.

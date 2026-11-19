# Design

## Goal

Make Git for Windows Bash the default shell on Windows for DeepSeek Harness (DSH),
while keeping DSH's existing `read-only` / `workspace-write` / `danger-full-access`
semantics byte-for-byte identical to the shipped PowerShell stack.

## The core problem

DSH confines Windows commands with `@deepseek-ai/dsh-sandbox-windows-acl`, which
spawns the child under a `CreateRestrictedToken` **WRITE_RESTRICTED** primary token.
Its restricting SID list is deliberately minimal:

```
read-only        : [logon SID, EVERYONE]
workspace-write  : [logon SID, EVERYONE, workspace SID, temp SID]
```

MSYS2 (the runtime behind every Git for Windows `.exe`, including `bash.exe`, `sh.exe`
and `ssh.exe`) performs at startup:

1. `NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0S5-<hash>)` for its shared memory
   namespace, then sets that object's security so peers can join it; and
2. creates a **signal pipe** for its SIGCHLD/SIGINT emulation.

Under the restricted token both fail:

```
*** fatal error - NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0S5-...): 0xC0000022
*** fatal error - couldn't create signal pipe, Win32 error 5
```

Verified on the target machine in both confined modes. Native Win32 executables
(`cmd.exe`, `where.exe`) run fine under the same token, so the restriction itself
works — MSYS2 simply needs something the restricted token does not provide.

### Why the obvious fixes are rejected

- **Add the missing SIDs to the restricting list.** This is what MSYS2 wants, but it
  widens the sandbox: `Authenticated Users` / `INTERACTIVE` grants let the child create
  objects in directories the policy never granted. That breaks the security contract
  we are required to preserve.
- **Run Git Bash unconfined.** Same objection, more direct.
- **Grant the child `SeSecurityPrivilege` / relaxed token rights.** Broadens the token.

The sandbox restriction must stay exactly as shipped. Only the *MSYS2 runtime's own
startup negotiation* may be adjusted, and only inside the child.

## Approach: native guard + injected hook

```
DSH ACL runner  ->  msys-token-guard.exe  ->  bash.exe  ->  grandchildren
   (unchanged)        (new, Rust)            (unchanged)     (injected too)
```

The guard is spawned **inside** the already-confined token, so everything it does —
and everything its child does — inherits exactly the sandbox the policy produced.
The guard never widens the token; it only changes the two specific MSYS2 startup
operations that the restricted token rejects, and it does so in a way that *reduces*
reach rather than increasing it.

### Injection: rewrite the PE import table, do not spawn a thread

The obvious injection — `CreateRemoteThread(LoadLibraryW)` — **does not work here**,
and the reason is worth recording. MSYS2 does a large amount of work in its static
initializers, which run before any remote thread is scheduled. By the time
`LoadLibraryW` executes, bash has already aborted on the signal pipe. An
experiment confirmed this directly: the injected DLL's `DllMain` never ran.

The working approach, taken from Detours' `UpdateImports64`
(`vendor/detours/uimports.cpp`), rewrites the suspended child's import directory:
a new `IMAGE_IMPORT_DESCRIPTOR` array naming the hook DLL is built next to the
image, and `OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]` is
repointed at it. The Windows loader then maps the DLL during process startup,
before the first instruction of the program itself.

This matters for the "no Detours" goal: the import rewrite is ~350 lines of Rust
over `ReadProcessMemory`/`VirtualAllocEx`/`VirtualProtectEx`, so the plugin keeps a
single dependency chain (`windows-sys` + `detour`) and needs no vendored C library.

### Grandchildren: detour `kernelbase!CreateProcessW`

`bash` implements pipelines, subshells, command substitution and `--login` by
forking itself. Every forked child is a fresh MSYS2 process and needs the same
injection, so the hook detours process creation and injects each child before
resuming it.

Two details proved load-bearing:

- **`kernelbase`, not `kernel32`.** `kernel32!CreateProcessW` is a thin forwarder
  into `kernelbase!CreateProcessW`, and `msys-2.0.dll` imports from kernelbase
  directly. Patching *both* exports makes the kernel32 trampoline re-enter the
  patched kernelbase entry, recursing until the stack overflows (`0xC00000FD`).
  Exactly one export is patched: kernelbase.
- **The DLL's own module handle.** `GetModuleFileNameA(NULL)` returns the path of
  the **hosting executable**, not the calling DLL. Using it wrote an import entry
  telling each grandchild to import `bash.exe` as a DLL; the load failed and the
  child died with the very signal-pipe error the hook exists to prevent.
  `GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, ...)` yields the real
  handle.

### What the hook changes

The guard creates `bash.exe` suspended and injects `msys_target_guard_hook.dll` into it
before the first instruction runs. The hook detours, **only for calls whose return
address lies inside `msys-2.0.dll`**:

1. `NtSetInformationToken(TokenDefaultDacl)` → return `STATUS_SUCCESS` without applying.
   MSYS2 uses this to install a default DACL so its newly created named objects are
   reachable by peers. Under the restricted token this call fails and MSYS2 aborts.
   The desired effect is instead achieved by the guard directly extending the child
   token's default DACL with the **logon SID** (step below) — a narrower grant than
   what MSYS2 would have written.

2. `RtlAddAccessAllowedAce(acl, rev, GENERIC_ALL, AdministratorsSid)` → substitute the
   **logon SID** for `BUILTIN\Administrators`. MSYS2 grants Administrators full control
   on its namespace and pipe objects; that SID is deny-only in the restricted token, so
   the ACL would still exclude the child. Substituting the logon SID keeps the access
   *scoped to the current logon session* instead of granting it to every administrator.

   Two constants here are easy to get wrong and both silently disable the hook:

   - the well-known SID type for Administrators is **26** (`WinBuiltinAdministratorsSid`),
     not `1` (Everyone);
   - `RtlAddAccessAllowedAce` is exported by **ntdll**, not advapi32.

   The detour also checks `is_current_process_token`: only MSYS2 configuring *its own*
   token is intercepted, so unrelated token operations pass through untouched.

3. The signal-pipe failure is a consequence of (1): the pipe is created with a security
   descriptor whose DACL names the default-DACL content. Once the logon-SID default DACL
   is in place, pipe creation succeeds. (Verified empirically — this is the observable
   behaviour, not an assumption about MSYS2 internals.)

### Guard-side token preparation

Before resuming the suspended child the guard:

1. `grant_logon_sid_to_default_dacl` — merges one `FILE_ALL_ACCESS` ACE for the child
   token's own **logon SID** into `TokenDefaultDacl`. This is what makes every object the
   child creates reachable by the child itself, without naming any broad SID.
2. `deny_adjust_default` — adds a `TOKEN_ADJUST_DEFAULT` **deny** ACE on the child token
   object for the user SID, then verifies with an `OpenProcessToken(TOKEN_ADJUST_DEFAULT)`
   probe that it really is denied. This stops a later MSYS2 (or anything else in the
   child) from rewriting the token's default DACL and escaping the hardening.
3. `verify_token_invariants` — re-reads the child token and asserts its restricting SID
   set still equals the guard's own, i.e. the child runs under the *same* confinement.

Then `ResumeThread`, wait for the hook's ready event, and mirror the child exit code.

### Why this preserves the sandbox

- The guard is spawned by the ACL runner, so it holds the restricted token.
- Every child it creates inherits that same restricted token; the guard asserts this.
- No restricting SID is added, and no privilege is enabled.
- The only DACL edits are on objects the child itself owns, and they name the *logon
  SID* (session-scoped) rather than a broad group.

The README documents the residual trust boundary: the injected DLL runs in the bash
process, so a compromised Git Bash could call the hooked functions itself. It gains
nothing beyond what it already has — MSYS2 needs the same accommodation to start at all.

## Rust vs. the C++ reference

The mechanism (guard + injected hook, the specific hooks, the token hardening) was
studied from `inmny/dsh-git-bash` (MIT licensed), and **this port references that
project's source code and reimplements it in Rust** rather than working only from
its documented behaviour. A second source is referenced the same way: the
DLL-injection code translates two algorithms from Microsoft Detours (MIT), and
neither is vendored or linked. `NOTICE` lists both attributions file by file and
`LICENSE` carries both copyright notices.

Two deliberate departures:

- **No Microsoft Detours library.** The C++ version links vendored Detours chiefly
  for `DetourCreateProcessWithDllEx`, which does "create suspended + inject +
  resume". Rust performs the same steps directly — `CreateProcessW` (suspended) →
  rewrite the child's PE import directory to name the hook DLL → `ResumeThread` —
  using algorithms translated from Detours' `UpdateImports64` and
  `FindAndAllocateNearBase` rather than calling into it. See "Why not
  `CreateRemoteThread`" above: the loader must have the DLL before the child's own
  static initializers run, which is earlier than a remote thread can win. This
  drops a vendored C library and the Detours `rundll32` helper export.
- **No ANSI path limitation.** Detours' DLL-path parameter is an ANSI API, so the C++
  version requires the install path to be losslessly representable in the system code
  page and shorter than `MAX_PATH`. The import-table rewrite names the DLL with a wide
  path, so this plugin has no such constraint.

Inline hooking (the two detoured APIs) uses the [`detour`] crate, which supports
transactional patching with thread suspension.

[`detour`]: https://crates.io/crates/detour

## Server default DACL

DSH derives every restricted token from the **server's** own process token, and a
restricted token's DACL begins as a copy of that token's default DACL. A `dsh` started
from an ordinary Windows console can therefore carry a default DACL with no usable
entry for the signed-in user, which blocks the guard's child-token setup even though
nothing about the command is unusual. MSYS2 rewrites the token of its own processes, so
starting `dsh` from Git Bash hides the problem.

The guard's `--normalize-server-dacl` stamps the shape MSYS2 would have applied: one
explicit full-access ACE for the token's user SID. It runs on the unrestricted server
token, changes only that token, is idempotent, and is reachable before the guard's own
confinement assertion so it can be used to repair a server that is not yet confined.
The executor calls it once per instance before the first confined command and ignores
a failure — an unrepaired DACL still fails closed at the point of use, surfacing as
`SANDBOX_UNAVAILABLE` rather than as a wrong answer.

## Verified behaviour

Measured on the target machine, with the guard spawned under DSH's own
`workspace-write` confinement:

| Case | Result |
|---|---|
| `echo hello` | `hello`, exit 0 |
| `false; echo "rc=$?"` | `rc=1`, exit 0 |
| `(echo inner)` (subshell/fork) | `inner`, exit 0 |
| `echo x \| tr x y` (pipeline) | `y`, exit 0 |
| `v=$(echo sub)` (substitution) | `v=sub`, exit 0 |
| heredoc | body read, exit 0 |
| `for i in 1 2 3` (fork per iteration) | three lines, exit 0 |
| `git --version` | `git version 2.56.0.windows.4` |
| `rustc --version` | `rustc 1.100.0` |

The same matrix was re-run through a **complete DSH instance** (an isolated
`0.2.2-rc.3` sandbox with the plugin installed as a bundle), with a real model turn
calling the `bash` tool rather than the guard directly:

| Case | Result |
|---|---|
| `$BASH_VERSION` / `$MSYSTEM` | `5.3.15(2)-release` / `UCRT64` |
| `uname -o` / `pwd` | `Msys` / the session workspace |
| pipeline, subshell, substitution | all pass |
| `for i in 1 2 3` (fork per iteration) | three lines |
| workspace write → read → delete | allowed |
| write to `C:\` | `Permission denied` |
| `pwsh` in the agent's tool catalog | absent |
| plugin activation errors | none |

Confinement is unchanged by the hook:

| Probe | Result |
|---|---|
| write inside the workspace | allowed |
| write to `C:\` | `Permission denied` |

## Fail-closed contract

Every failure mode must prevent an unconfined command from running:

| Situation | Behaviour |
|---|---|
| Not `win32-x64` (restricted mode) | `SandboxUnavailableError` before spawning |
| Guard artifacts missing/unreadable | `SandboxUnavailableError` before spawning |
| Guard rejects its own token (not restricted) | exit `125`, stderr `msys-token-guard: ...` |
| Hook fails to initialize | child terminated, exit `125` |
| Child token SID set differs from guard's | child killed suspended, exit `125` |
| Readiness handshake timeout (30 s) | child terminated, exit `125` |

The executor classifies exit `125` + the `msys-token-guard:` signature via the sandbox
seam's `runnerFailureRules`, so DSH reports `SANDBOX_UNAVAILABLE` instead of
silently treating the guard failure as a command failure.

## Deliberate non-goals

- `danger-full-access` bypasses the guard entirely and spawns `bash.exe` directly;
  no confinement is being emulated there.
- Only `win32-x64` is supported. Other architectures return `SANDBOX_UNAVAILABLE`
  rather than degrading to unconfined execution.

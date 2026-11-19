// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
//! Guard for launching MSYS2 programs under the DeepSeek Harness Windows sandbox.
//!
//! See `DESIGN.md` for the mechanism and the security argument.
//!
//! Usage:
//! ```text
//! msys-token-guard.exe -- <absolute-program> [arguments...]
//! ```
//!
//! Every runner-side failure prints `msys-token-guard: <detail>` to stderr and
//! exits `125`, which the DSH sandbox seam classifies as "the command did not
//! run" rather than as a command failure.

mod imports;
mod launch;
mod normalize;
mod token;
mod win32;

use std::path::Path;

use launch::{GuardedChild, GUARD_FAILURE_EXIT_CODE};
use win32::Win32Error;

/// Exit status for a usage error, distinct from a guard failure.
const USAGE_EXIT_CODE: i32 = 64;

/// Exit status used when a command's own exit code collides with the guard's
/// failure code.
///
/// The guard never produces this code itself, so the plugin's "guard failed"
/// classification (exit `125` plus the `msys-token-guard:` signature) can
/// never match a command that merely chose to exit `125`.
const COLLIDING_EXIT_CODE: i32 = 126;

/// A guard-side failure, reported through the `msys-token-guard:` signature.
enum GuardFailure {
    Usage(String),
    Win32(Win32Error),
    Invariant(&'static str),
}

impl From<Win32Error> for GuardFailure {
    fn from(value: Win32Error) -> Self {
        GuardFailure::Win32(value)
    }
}

impl std::fmt::Display for GuardFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardFailure::Usage(text) => write!(f, "{text}"),
            GuardFailure::Win32(error) => write!(f, "{error}"),
            GuardFailure::Invariant(text) => write!(f, "{text}"),
        }
    }
}

/// The injected DLL, located beside this executable.
fn hook_library_path() -> Result<String, GuardFailure> {
    let exe = std::env::current_exe()
        .map_err(|_| GuardFailure::Invariant("cannot resolve the guard executable path"))?;
    let directory = exe
        .parent()
        .ok_or(GuardFailure::Invariant("guard executable has no parent directory"))?;
    let hook = directory.join("msys_token_guard_hook.dll");
    if !hook.is_file() {
        return Err(GuardFailure::Invariant(
            "hook DLL is missing beside the guard executable",
        ));
    }
    Ok(hook.to_string_lossy().into_owned())
}

/// Prepare the suspended child and run it to completion.
fn run(program: &str, arguments: &[String]) -> Result<u32, GuardFailure> {
    // Refuse to run at all unless the caller actually confined us. A guard in
    // an unrestricted token proves nothing and must not pretend otherwise.
    let expected = token::own_restricted_sid_set()?;
    token::assert_confined(expected.as_ref())?;

    let hook = hook_library_path()?;

    // The ready event is created inheritable so the child can signal it.
    let ready = create_ready_event()?;
    let mut child: GuardedChild = launch::launch_injected(program, arguments, &hook, ready.raw())?;

    // Harden the child while it is still suspended: either step failing means
    // the child never runs.
    let hardened = prepare_child(&mut child, expected.as_ref());
    if let Err(failure) = hardened {
        child.terminate();
        launch::close(ready.raw());
        return Err(failure);
    }

    child.resume()?;
    launch::await_hook_ready(ready.raw(), child.process.raw())?;
    launch::close(ready.raw());

    let exit = child.wait()?;
    Ok(exit)
}

/// Every token step that must succeed before the child is allowed to run.
fn prepare_child(
    child: &mut GuardedChild,
    expected: Option<&Vec<String>>,
) -> Result<(), GuardFailure> {
    let expected = expected.ok_or(GuardFailure::Invariant(
        "guard lost its restricting SID set",
    ))?;
    let debug = std::env::var_os("DSH_MSYS_TOKEN_GUARD_DEBUG").is_some();

    // 1. Prove the child runs under the same confinement as the guard.
    token::verify_same_confinement(child.process.raw(), expected)?;
    if debug {
        eprintln!("msys-token-guard: child confinement verified");
    }
    // 2. Give its created objects a reachable default DACL (logon SID only).
    token::grant_logon_sid_to_default_dacl(child.process.raw())?;
    if debug {
        eprintln!("msys-token-guard: child default DACL extended with logon SID");
    }
    // 3. Make step 2 irreversible from inside the child.
    token::deny_child_token_adjust_default(child.process.raw())?;
    if debug {
        eprintln!("msys-token-guard: child TOKEN_ADJUST_DEFAULT denied");
    }
    // 4. Re-assert confinement after the mutations.
    token::verify_same_confinement(child.process.raw(), expected)?;
    Ok(())
}

/// Create the inheritable manual-reset event the hook signals.
fn create_ready_event() -> Result<win32::OwnedHandle, GuardFailure> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::CreateEventW;

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES asking for inheritance.
    let handle = unsafe { CreateEventW(&attributes, 0, 0, std::ptr::null()) };
    win32::OwnedHandle::expect(handle, "CreateEventW(ready)").map_err(GuardFailure::from)
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();

    // Diagnostic subcommand: report this process's own confinement facts.
    if argv.len() == 2 && argv[1] == "--probe-current-token" {
        match token::own_restricted_sid_set() {
            Ok(Some(sids)) => println!("confined sids={}", sids.join(",")),
            Ok(None) => println!("unconfined"),
            Err(e) => {
                eprintln!("msys-token-guard: probe failed: {e}");
                std::process::exit(GUARD_FAILURE_EXIT_CODE as i32);
            }
        }
        return;
    }

    // Server-token repair: gives the server's own default DACL a full-access
    // entry for the user, which every restricted child derived from it needs.
    // Safe to run once per server process; exits 0 when already correct.
    if argv.len() == 2 && argv[1] == "--normalize-server-dacl" {
        std::process::exit(normalize::run());
    }

    if argv.len() < 3 || argv[1] != "--" {
        eprintln!("usage: msys-token-guard.exe -- <absolute-program> [arguments...]");
        std::process::exit(USAGE_EXIT_CODE);
    }

    let program = &argv[2];
    let arguments: Vec<String> = argv[3..].to_vec();

    if !Path::new(program).is_absolute() {
        eprintln!("msys-token-guard: target program path must be absolute");
        std::process::exit(GUARD_FAILURE_EXIT_CODE as i32);
    }

    match run(program, &arguments) {
        Ok(exit) => std::process::exit(mirror_exit_code(exit)),
        Err(GuardFailure::Usage(text)) => {
            eprintln!("msys-token-guard: {text}");
            std::process::exit(USAGE_EXIT_CODE);
        }
        Err(failure) => {
            eprintln!("msys-token-guard: {failure}");
            std::process::exit(GUARD_FAILURE_EXIT_CODE as i32);
        }
    }
}

/// Map the child's exit code onto the code this guard returns.
///
/// The guard's own failures use [`GUARD_FAILURE_EXIT_CODE`] together with the
/// `msys-token-guard:` stderr signature, which the DSH plugin treats as "the
/// command did not run". A command that exits with that same code must not be
/// mistaken for a guard failure — otherwise a model could write
/// `echo 'msys-token-guard: x' >&2; exit 125` and be told the sandbox broke,
/// and a legitimate command that happens to exit 125 would be misreported.
///
/// Such an exit is therefore remapped to [`COLLIDING_EXIT_CODE`], a code the
/// guard never produces itself. The command's own stdout/stderr are untouched.
fn mirror_exit_code(child_exit: u32) -> i32 {
    if child_exit == GUARD_FAILURE_EXIT_CODE {
        COLLIDING_EXIT_CODE
    } else {
        child_exit as i32
    }
}

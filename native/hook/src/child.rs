// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
//! Intercept `CreateProcessW` so every MSYS2 child gets the same treatment.
//!
//! `bash` implements pipelines, subshells, command substitution and `--login`
//! by forking/exec'ing itself. Each of those grandchildren is a fresh MSYS2
//! process, so each one needs the hook DLL mapped before its own static
//! initializers run — otherwise it dies exactly like an uninjected bash.
//!
//! The detour mirrors the reference implementation: create the child
//! *suspended*, rewrite its import table to include the hook DLL, harden its
//! token, and only then resume it (unless the caller asked for suspension).

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use detour::RawDetour;
use windows_sys::Win32::Foundation::{
    GetLastError, SetLastError, FALSE, HANDLE, TRUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Threading::{
    ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::hook;

/// `CreateProcessW`'s signature.
type CreateProcessWFn = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    i32,
    u32,
    *mut c_void,
    *const u16,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> i32;

/// The next `CreateProcessW` in the chain.
static mut REAL_CREATE_PROCESS_W: Option<CreateProcessWFn> = None;


/// Terminate a half-prepared child and release its handles.
unsafe fn discard_child(info: *mut PROCESS_INFORMATION) {
    if info.is_null() {
        return;
    }
    let process = (*info).hProcess;
    if !process.is_null() {
        windows_sys::Win32::System::Threading::TerminateProcess(process, hook::exit_code());
        windows_sys::Win32::System::Threading::WaitForSingleObject(process, 5_000);
    }
    if !(*info).hThread.is_null() {
        windows_sys::Win32::Foundation::CloseHandle((*info).hThread);
    }
    if !process.is_null() {
        windows_sys::Win32::Foundation::CloseHandle(process);
    }
    *info = core::mem::zeroed();
}

/// Write a diagnostic line to stderr without the Rust runtime.
unsafe fn diagnostic(message: &[u8]) {
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
    let handle = GetStdHandle(STD_ERROR_HANDLE);
    if handle.is_null() || handle as isize == -1 {
        return;
    }
    let mut written = 0u32;
    windows_sys::Win32::Storage::FileSystem::WriteFile(
        handle,
        message.as_ptr(),
        message.len() as u32,
        &mut written,
        ptr::null_mut(),
    );
}

/// Guards against re-entering the detour from its own trampoline.
///
/// `kernel32!CreateProcessW` is a forwarder into `kernelbase!CreateProcessW`.
/// When both exports are detoured, the kernel32 trampoline jumps into the
/// kernelbase implementation — which is itself patched — so a naive chain
/// recurses until the stack overflows. This flag makes the inner invocation
/// fall straight through to the real implementation.
static IN_DETOUR: AtomicBool = AtomicBool::new(false);

/// The `CreateProcessW` detour.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn detour_create_process_w(
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *const SECURITY_ATTRIBUTES,
    thread_attributes: *const SECURITY_ATTRIBUTES,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *mut c_void,
    current_directory: *const u16,
    startup_info: *const STARTUPINFOW,
    process_information: *mut PROCESS_INFORMATION,
) -> i32 {
    let caller_requested_suspension = creation_flags & CREATE_SUSPENDED != 0;

    let Some(real) = REAL_CREATE_PROCESS_W else {
        diagnostic(b"msys-token-guard-hook: CreateProcessW detour has no trampoline\r\n");
        return FALSE;
    };

    // Re-entry from the trampoline chain: call straight through.
    if IN_DETOUR.swap(true, Ordering::AcqRel) {
        return real(
            application_name,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            creation_flags,
            environment,
            current_directory,
            startup_info,
            process_information,
        );
    }
    // Every exit below must clear the flag, so the guard body lives in a
    // closure whose result is returned after the reset.
    let result = run_detour(
        real,
        application_name,
        command_line,
        process_attributes,
        thread_attributes,
        inherit_handles,
        creation_flags,
        caller_requested_suspension,
        environment,
        current_directory,
        startup_info,
        process_information,
    );
    IN_DETOUR.store(false, Ordering::Release);
    result
}

/// The guarded body of the detour.
#[allow(clippy::too_many_arguments)]
unsafe fn run_detour(
    real: CreateProcessWFn,
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *const SECURITY_ATTRIBUTES,
    thread_attributes: *const SECURITY_ATTRIBUTES,
    inherit_handles: i32,
    creation_flags: u32,
    caller_requested_suspension: bool,
    environment: *mut c_void,
    current_directory: *const u16,
    startup_info: *const STARTUPINFOW,
    process_information: *mut PROCESS_INFORMATION,
) -> i32 {
    if std::env::var_os("DSH_MSYS_TOKEN_GUARD_DEBUG").is_some() {
        let name = if application_name.is_null() {
            "<null>".to_string()
        } else {
            let mut len = 0usize;
            while *application_name.add(len) != 0 && len < 512 {
                len += 1;
            }
            String::from_utf16_lossy(core::slice::from_raw_parts(application_name, len))
        };
        eprintln!("msys-token-guard-hook: CreateProcessW application={name}");
    }
    // Always ask for a suspended child so the import table can be rewritten
    // before it runs a single instruction.
    let created = real(
        application_name,
        command_line,
        process_attributes,
        thread_attributes,
        inherit_handles,
        creation_flags | CREATE_SUSPENDED,
        environment,
        current_directory,
        startup_info,
        process_information,
    );
    if created == 0 {
        let code = GetLastError();
        diagnostic(b"msys-token-guard-hook: failed to inject an MSYS child process\r\n");
        SetLastError(code);
        return FALSE;
    }

    if process_information.is_null() {
        discard_child(process_information);
        SetLastError(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED);
        return FALSE;
    }
    let process: HANDLE = (*process_information).hProcess;
    let debug = std::env::var_os("DSH_MSYS_TOKEN_GUARD_DEBUG").is_some();

    // Inject the same hook DLL into the grandchild.
    match hook::inject_into_process(process) {
        Ok(()) => {
            if debug {
                eprintln!("msys-token-guard-hook: grandchild injected");
            }
        }
        Err(error) => {
            if debug {
                eprintln!("msys-token-guard-hook: inject failed: {error}");
            }
            discard_child(process_information);
            diagnostic(b"msys-token-guard-hook: failed to inject an MSYS child process\r\n");
            SetLastError(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }

    // Keep the grandchild from rewriting its own default DACL.
    if let Err(error) = hook::deny_child_adjust_default(process) {
        if debug {
            eprintln!("msys-token-guard-hook: token hardening failed: {error}");
        }
        discard_child(process_information);
        diagnostic(b"msys-token-guard-hook: failed to inject an MSYS child process\r\n");
        SetLastError(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED);
        return FALSE;
    }

    if !caller_requested_suspension {
        let thread = (*process_information).hThread;
        if ResumeThread(thread) == u32::MAX {
            let code = GetLastError();
            discard_child(process_information);
            diagnostic(b"msys-token-guard-hook: failed to inject an MSYS child process\r\n");
            SetLastError(code);
            return FALSE;
        }
    }

    TRUE
}

/// Install the `CreateProcessW` detour.
///
/// `kernel32!CreateProcessW` is a thin forwarder to `kernelbase!CreateProcessW`
/// on modern Windows. Inline-hooking only the kernel32 export works for callers
/// that go through that exact stub, but a module whose import table points at
/// `kernelbase` — as `msys-2.0.dll` does — bypasses it entirely. Both exports
/// are therefore detoured when present.
pub fn install() -> Result<(), String> {
    // `kernel32!CreateProcessW` is a forwarder stub that jumps into
    // `kernelbase!CreateProcessW`. Patching only `kernelbase` detours every
    // caller — whether the module imported from kernel32 (and so lands in the
    // forwarder, which then enters our trampoline) or imported kernelbase
    // directly like `msys-2.0.dll`. The kernel32 export is deliberately left
    // untouched: patching both makes the kernel32 trampoline re-enter the
    // patched kernelbase entry, which recurses until the stack overflows.
    let address = resolve_export("kernelbase.dll", b"CreateProcessW\0")
        .or_else(|| resolve_export("kernel32.dll", b"CreateProcessW\0"))
        .ok_or_else(|| "CreateProcessW is not exported by kernelbase or kernel32".to_string())?;

    // SAFETY: `address` is a live kernel32/kernelbase export and our detour
    // matches CreateProcessW's signature. The detour stays installed for the
    // process lifetime: grandchildren are created at any time.
    unsafe {
        let detour = RawDetour::new(address, detour_create_process_w as *const ())
            .map_err(|e| format!("CreateProcessW: {e}"))?;
        REAL_CREATE_PROCESS_W = Some(core::mem::transmute(detour.trampoline()));
        detour
            .enable()
            .map_err(|e| format!("CreateProcessW enable: {e}"))?;
        DETOURS.push(detour);
    }
    Ok(())
}

/// Resolve `module!symbol`, or `None` when either is absent.
fn resolve_export(module: &str, symbol: &[u8]) -> Option<*const ()> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let name: Vec<u8> = module.bytes().chain(core::iter::once(0)).collect();
    // SAFETY: `name` is NUL-terminated.
    let handle = unsafe { GetModuleHandleA(name.as_ptr()) };
    if handle.is_null() {
        return None;
    }
    // SAFETY: `symbol` is NUL-terminated.
    unsafe { GetProcAddress(handle, symbol.as_ptr()) }.map(|f| f as *const ())
}

/// Detours kept alive for the process lifetime.
static mut DETOURS: Vec<RawDetour> = Vec::new();

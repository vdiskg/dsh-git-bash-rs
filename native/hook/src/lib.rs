// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
//! Injected helper that lets the MSYS2 runtime start under a restricted token.
//!
//! `DllMain` installs two detours, both gated on the *caller* living inside
//! `msys-2.0.dll`:
//!
//! 1. `NtSetInformationToken(TokenDefaultDacl)` is reported as successful
//!    without being applied. MSYS2 uses it to make its named objects reachable
//!    by peers; the guard already widened the child token's default DACL with
//!    the narrow **logon SID**, so the MSYS2 write is redundant *and* would
//!    either fail (aborting startup) or reinstate a broader DACL.
//!
//! 2. `RtlAddAccessAllowedAce(..., GENERIC_ALL, BUILTIN\Administrators)` has its
//!    trustee swapped for the **logon SID**. `Administrators` is deny-only in a
//!    restricted token, so the ACL would exclude the child itself; substituting
//!    the logon SID keeps the grant scoped to this logon session instead of
//!    widening it to every administrator.
//!
//! The signal-pipe failure MSYS2 reports on this sandbox is a consequence of
//! step 1 and disappears once the default DACL is usable.
//!
//! Every failure terminates the process with exit code `125`, so the guard's
//! readiness handshake observes a definite failure rather than a hang.

use core::ffi::c_void;
use core::ptr;

use windows_sys::Win32::Foundation::{HANDLE, HMODULE, TRUE};
use windows_sys::Win32::Security::{CreateWellKnownSid, EqualSid, IsValidSid, PSID};

mod child;
mod hook;
mod imports;

/// Exit code used for every hook-side failure (mirrors the guard's contract).
const HOOK_FAILURE_EXIT_CODE: u32 = 125;

/// Name of the environment variable carrying the ready-event handle.
const READY_HANDLE_ENV: &str = "DSH_MSYS_TOKEN_GUARD_READY_HANDLE";

/// Modules the detours are installed against (loaded by the child itself).
const NTDLL: &str = "ntdll.dll";
const ADVAPI32: &str = "advapi32.dll";
const MSYS_RUNTIME: &str = "msys-2.0.dll";

/// `TokenDefaultDacl`, the information class MSYS2 tries to write.
const TOKEN_DEFAULT_DACL_CLASS: i32 = 6;

/// `GENERIC_ALL`, the access mask MSYS2 grants Administrators on its objects.
const GENERIC_ALL: u32 = 0x1000_0000;

/// `WinBuiltinAdministratorsSid` — the well-known SID type for
/// `BUILTIN\Administrators`. Must stay in sync with the Windows SDK value.
const WIN_BUILTIN_ADMINISTRATORS_SID: i32 = 26;

/// `STATUS_SUCCESS`.
const STATUS_SUCCESS: i32 = 0;

/// State captured once at attach time and read by the detours.
pub struct HookState {
    /// Base address of `msys-2.0.dll`, or null before it is loaded.
    pub msys_base: *mut c_void,
    /// The current logon SID.
    pub logon_sid: [u8; 68],
    /// `BUILTIN\Administrators`.
    pub admin_sid: [u8; 68],
    /// Whether both SIDs were captured successfully.
    pub ready: bool,
}

///
/// The detours are process-wide function pointers, so shared mutable state is
/// unavoidable and is guarded by the fact that only `DllMain` writes it.
static mut STATE: HookState = HookState {
    msys_base: ptr::null_mut(),
    logon_sid: [0; 68],
    admin_sid: [0; 68],
    ready: false,
};

/// Read-only accessor for the detours.
pub fn state() -> &'static HookState {
    // SAFETY: `STATE` is written once during `DllMain` before any detour can
    // call into it, and never mutated afterwards.
    unsafe { &*ptr::addr_of!(STATE) }
}

fn log(message: &str) {
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
    let handle = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if handle.is_null() || handle as isize == -1 {
        return;
    }
    let line = format!("msys-token-guard: {message}\r\n");
    let mut written = 0u32;
    // SAFETY: WriteFile into the inherited stderr handle.
    unsafe {
        windows_sys::Win32::Storage::FileSystem::WriteFile(
            handle,
            line.as_ptr(),
            line.len() as u32,
            &mut written,
            core::ptr::null_mut(),
        );
    }
}

fn fail_closed(message: &str) -> ! {
    log(message);
    std::process::exit(HOOK_FAILURE_EXIT_CODE as i32);
}

/// Copy a well-known SID into `slot`, returning false on failure.
fn capture_well_known(kind: i32, slot: &mut [u8; 68]) -> bool {
    let mut size = slot.len() as u32;
    // SAFETY: `slot` is 68 bytes, the maximum SID size.
    let ok = unsafe {
        CreateWellKnownSid(kind, ptr::null_mut(), slot.as_mut_ptr().cast::<c_void>(), &mut size)
    };
    ok != 0 && unsafe { IsValidSid(slot.as_mut_ptr().cast::<c_void>()) } != 0
}

/// Signal the guard that the hooks are live.
fn signal_ready() {
    let value = match std::env::var(READY_HANDLE_ENV) {
        Ok(v) => v,
        Err(_) => return,
    };
    let raw = match usize::from_str_radix(value.trim(), 16) {
        Ok(v) if v != 0 => v,
        _ => fail_closed("ready handle is not a valid hex value"),
    };
    let handle = raw as HANDLE;
    // SAFETY: the guard created this inheritable event and passed its handle
    // value through the inherited environment; ownership transfers to us.
    let ok = unsafe {
        windows_sys::Win32::System::Threading::SetEvent(handle)
    };
    if ok == 0 {
        fail_closed("SetEvent(ready) failed");
    }
    // SAFETY: as above; we close the inherited handle exactly once.
    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    // Remove the variable so grandchildren do not inherit a stale handle.
    let _ = std::env::remove_var(READY_HANDLE_ENV);
}

/// `DllMain`.
///
/// # Safety
/// Called by the loader with `DLL_PROCESS_ATTACH` and `DLL_PROCESS_DETACH`.
///
/// This runs synchronously inside `DLL_PROCESS_ATTACH`. That is deliberate and
/// mirrors the reference implementation: MSYS2 calls `NtSetInformationToken`
/// from its own static initialization, which happens after this loader
/// callback but *before* any thread we could spawn gets scheduled. Deferring
/// the work to a helper thread loses the race, so the detours are installed
/// here and now.
///
/// The calls made here (`GetModuleHandleW`/`GetProcAddress`/`CreateWellKnownSid`)
/// are loader-safe; we avoid the Rust runtime and any allocation-heavy path.
#[no_mangle]
pub unsafe extern "system" fn DllMain(instance: HMODULE, reason: u32, _reserved: *mut c_void) -> i32 {
    /// `DLL_PROCESS_ATTACH`
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason != DLL_PROCESS_ATTACH {
        return TRUE;
    }
    let _ = instance;

    // 1. Capture the SIDs the detours compare against.
    {
        let state = &mut *ptr::addr_of_mut!(STATE);
        // `WinBuiltinAdministratorsSid` (26), the group MSYS2 grants
        // GENERIC_ALL to on its IPC objects. This must match the reference
        // implementation exactly; using the wrong constant silently disables
        // the substitution.
        let mut ok = capture_well_known(WIN_BUILTIN_ADMINISTRATORS_SID, &mut state.admin_sid);
        if ok {
            ok = hook::capture_logon_sid(&mut state.logon_sid);
        }
        state.ready = ok;
    }
    if !state_ready() {
        fail_closed("failed to capture the logon or Administrators SID");
    }

    // 2. Install the detours before returning, so they are live for the
    //    program's static initializers.
    if let Err(error) = hook::install() {
        fail_closed(&format!("failed to install hooks: {error}"));
    }

    // 3. Tell the guard the hooks are ready.
    signal_ready();
    TRUE
}

fn state_ready() -> bool {
    // SAFETY: written during DllMain before any reader runs.
    unsafe { (*ptr::addr_of!(STATE)).ready }
}

/// Exported so the guard-side tooling can confirm the DLL is the real hook.
#[no_mangle]
pub extern "system" fn msys_token_guard_hook_abi_version() -> u32 {
    1
}

/// Keep the unused constants referenced for documentation value.
#[allow(dead_code)]
const _DOC: (i32, u32, i32, &str, &str, &str) = (
    TOKEN_DEFAULT_DACL_CLASS,
    GENERIC_ALL,
    STATUS_SUCCESS,
    NTDLL,
    ADVAPI32,
    MSYS_RUNTIME,
);

/// Render a SID as SDDL for diagnostics (debug output only).
pub fn sid_debug_string(sid: PSID) -> String {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return "<invalid>".to_string();
    }
    let mut raw: *mut u16 = ptr::null_mut();
    // SAFETY: `raw` is a valid out pointer; freed below.
    let ok = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(sid, &mut raw)
    };
    if ok == 0 || raw.is_null() {
        return "<convert-failed>".to_string();
    }
    let mut len = 0usize;
    // SAFETY: NUL-terminated wide string.
    while unsafe { *raw.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` counts units before the terminator.
    let text = String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(raw, len) });
    // SAFETY: the API handed us this allocation.
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(raw as windows_sys::Win32::Foundation::HLOCAL);
    }
    text
}

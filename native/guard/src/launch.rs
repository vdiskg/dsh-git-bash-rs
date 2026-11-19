// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
//! Create the MSYS2 child suspended, inject the hook DLL, and wait for it.
//!
//! This replaces Detours' `DetourCreateProcessWithDllEx`. The sequence is the
//! documented manual-injection recipe:
//!
//! 1. `CreateProcessW(..., CREATE_SUSPENDED, ...)`
//! 2. `VirtualAllocEx` + `WriteProcessMemory` a wide DLL path
//! 3. `CreateRemoteThread(LoadLibraryW)`
//! 4. wait for the thread, then wait for the hook's own ready event
//!
//! Injecting with `LoadLibraryW` takes a **wide** path, so unlike the Detours
//! path this plugin has no ANSI-code-page or `MAX_PATH` install-location limit.

use core::ffi::c_void;
use core::ptr;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER,
    ERROR_TIMEOUT, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, GetExitCodeProcess, GetExitCodeThread, ResumeThread,
    WaitForMultipleObjects, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::win32::{GuardResult, OwnedHandle, Win32Error};

/// Environment variable carrying the hook's ready-event handle to the DLL.
pub const READY_HANDLE_ENV: &str = "DSH_MSYS_TOKEN_GUARD_READY_HANDLE";

/// Set by the guard so MSYS2 keeps its normal diagnostics path active.
pub const CYGWIN_TESTING_ENV: &str = "CYGWIN_TESTING";

/// Exit code the guard uses for every failure of its own.
pub const GUARD_FAILURE_EXIT_CODE: u32 = 125;

/// Seconds to wait for the injected DLL to signal readiness.
const READY_TIMEOUT_MS: u32 = 30_000;

/// A launched child plus the handles the caller must keep alive.
pub struct GuardedChild {
    pub process: OwnedHandle,
    thread: OwnedHandle,
    resumed: bool,
}

impl GuardedChild {
    /// Whether `ResumeThread` has already succeeded.
    pub fn is_resumed(&self) -> bool {
        self.resumed
    }

    /// Resume the child's primary thread exactly once.
    pub fn resume(&mut self) -> GuardResult<()> {
        if self.resumed {
            return Err(Win32Error::new(
                "ResumeThread called twice",
                ERROR_INVALID_PARAMETER,
            ));
        }
        // SAFETY: the thread handle is valid.
        let previous = unsafe { ResumeThread(self.thread.raw()) };
        if previous == u32::MAX {
            return Err(Win32Error::last("ResumeThread"));
        }
        // A return of 0 means the primary thread is already running: MSYS2's
        // own startup resumed it (its launcher does this before reaching our
        // injected code). That is not an error — hardening already completed
        // while the process was still suspended, and the hook performs its
        // own readiness handshake once it is live.
        self.resumed = true;
        Ok(())
    }

    /// Wait for the child to exit and return its exit code.
    pub fn wait(&self) -> GuardResult<u32> {
        // SAFETY: the process handle is valid.
        let wait = unsafe { WaitForSingleObject(self.process.raw(), u32::MAX) };
        if wait != WAIT_OBJECT_0 {
            return Err(Win32Error::new(
                "WaitForSingleObject(child)",
                if wait == WAIT_FAILED { unsafe { GetLastError() } } else { wait },
            ));
        }
        let mut code: u32 = 0;
        // SAFETY: `code` is a valid out pointer.
        let ok: BOOL = unsafe { GetExitCodeProcess(self.process.raw(), &mut code) };
        if ok == 0 {
            return Err(Win32Error::last("GetExitCodeProcess"));
        }
        Ok(code)
    }

    /// Kill the child while it is still suspended.
    ///
    /// Used on every failure path before resuming, so a half-prepared child can
    /// never run.
    pub fn terminate(&self) {
        if self.resumed {
            return;
        }
        // SAFETY: terminating a valid process handle we own.
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(self.process.raw(), GUARD_FAILURE_EXIT_CODE);
            WaitForSingleObject(self.process.raw(), 5_000);
        }
    }
}

impl Drop for GuardedChild {
    fn drop(&mut self) {
        // Safety net: a child that was never resumed must not outlive the guard.
        self.terminate();
    }
}

/// Validate the target program path before touching the filesystem.
pub fn validate_target(path: &str) -> GuardResult<()> {
    if path.is_empty() {
        return Err(Win32Error::new("target program path is empty", ERROR_INVALID_NAME));
    }
    let bytes = path.as_bytes();
    let absolute = (bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/'))
        || (bytes.len() >= 2 && (bytes[0] == b'\\' && bytes[1] == b'\\'));
    if !absolute {
        return Err(Win32Error::new(
            "target program path must be absolute",
            ERROR_INVALID_NAME,
        ));
    }
    Ok(())
}

/// Quote one argument for a `CreateProcessW` command line.
///
/// Follows the documented parser rules: wrap in quotes only when needed, and
/// double backslashes that precede a quote.
pub fn quote_argument(argument: &str) -> String {
    let needs_quotes =
        argument.is_empty() || argument.chars().any(|c| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '"'));
    if !needs_quotes {
        return argument.to_string();
    }
    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..(backslashes * 2 + 1) {
                    quoted.push('\\');
                }
                quoted.push('"');
                backslashes = 0;
            }
            other => {
                for _ in 0..backslashes {
                    quoted.push('\\');
                }
                backslashes = 0;
                quoted.push(other);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}

/// Join the target and its arguments into a `CreateProcessW` command line.
pub fn command_line(program: &str, arguments: &[String]) -> String {
    let mut line = quote_argument(program);
    for argument in arguments {
        line.push(' ');
        line.push_str(&quote_argument(argument));
    }
    line
}

/// Append a NUL terminator, producing a mutable wide buffer.
fn wide_nul(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Launch `program` suspended, inject `hook_dll`, and wait for its ready event.
///
/// The child is **not** resumed here; the caller hardens its token first and
/// only then calls [`GuardedChild::resume`].
pub fn launch_injected(
    program: &str,
    arguments: &[String],
    hook_dll: &str,
    ready_event: HANDLE,
) -> GuardResult<GuardedChild> {
    validate_target(program)?;

    let mut line = wide_nul(&command_line(program, arguments));
    let mut application = wide_nul(program);

    // The hook reads the ready-event handle from its inherited environment.
    let previous_env = crate::win32::env_var(READY_HANDLE_ENV);
    let ready_text = format!("{:x}", ready_event as usize);
    crate::win32::set_env_var(READY_HANDLE_ENV, Some(&ready_text))?;
    crate::win32::set_env_var(CYGWIN_TESTING_ENV, Some("1"))?;

    let mut startup: STARTUPINFOW = unsafe { core::mem::zeroed() };
    startup.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;
    // SAFETY: these pseudo handles always resolve to the current std handles.
    unsafe {
        startup.hStdInput = windows_sys::Win32::System::Console::GetStdHandle(
            windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
        );
        startup.hStdOutput = windows_sys::Win32::System::Console::GetStdHandle(
            windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE,
        );
        startup.hStdError = windows_sys::Win32::System::Console::GetStdHandle(
            windows_sys::Win32::System::Console::STD_ERROR_HANDLE,
        );
    }

    let mut info: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: all pointers reference live, correctly sized values; both wide
    // buffers are NUL-terminated and outlive the call.
    let created: BOOL = unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut info,
        )
    };
    let create_error = if created == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };

    // Restore the inherited environment either way.
    crate::win32::set_env_var(READY_HANDLE_ENV, previous_env.as_deref())?;
    if let Some(code) = create_error {
        return Err(Win32Error::new("CreateProcessW(target, suspended)", code));
    }

    let process = OwnedHandle::expect(info.hProcess, "CreateProcessW(process handle)")?;
    let thread = OwnedHandle::expect(info.hThread, "CreateProcessW(thread handle)")?;
    let mut child = GuardedChild {
        process,
        thread,
        resumed: false,
    };

    inject_dll(child.process.raw(), hook_dll)?;
    Ok(child)
}

/// Inject `hook_dll` into the suspended `process` by rewriting its import
/// table, so the loader maps the DLL during startup.
fn inject_dll(process: HANDLE, hook_dll: &str) -> GuardResult<()> {
    crate::imports::inject_via_import_table(process, hook_dll)?;
    Ok(())
}

/// Wait for the injected DLL to report that its hooks are installed.
pub fn await_hook_ready(ready_event: HANDLE, process: HANDLE) -> GuardResult<()> {
    let handles = [ready_event, process];
    // SAFETY: both handles are valid; an array of two is passed.
    let wait = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, READY_TIMEOUT_MS) };
    if wait == WAIT_OBJECT_0 {
        return Ok(());
    }
    Err(Win32Error::new(
        "hook readiness handshake",
        if wait == WAIT_FAILED {
            unsafe { GetLastError() }
        } else if wait == WAIT_TIMEOUT {
            ERROR_TIMEOUT
        } else {
            wait
        },
    ))
}

/// Close a handle owned elsewhere (used for the ready event).
pub fn close(handle: HANDLE) {
    if !handle.is_null() {
        // SAFETY: the caller transfers ownership here by contract.
        unsafe {
            CloseHandle(handle);
        }
    }
}

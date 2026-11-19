// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
//! Thin, checked wrappers over the Win32 calls the guard needs.
//!
//! Every function here reports the failing operation name and the exact
//! `GetLastError` code. Nothing in this module silently swallows an error —
//! the guard's fail-closed contract is built on top of it.

use core::ffi::c_void;
use core::ptr;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, HANDLE, HLOCAL};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    CopySid, CreateWellKnownSid, EqualSid, GetLengthSid, GetTokenInformation, IsValidAcl,
    IsValidSid, ACL, PSID, TOKEN_ACCESS_MASK, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::OpenProcessToken;

/// A guard failure: the operation that failed plus its `Win32` code.
#[derive(Debug)]
pub struct Win32Error {
    pub operation: &'static str,
    pub code: u32,
}

impl Win32Error {
    /// Capture the current thread's last error for `operation`.
    pub fn last(operation: &'static str) -> Self {
        Self {
            operation,
            code: unsafe { GetLastError() },
        }
    }

    /// Build an error for a call that returned an explicit `Win32` status.
    pub fn new(operation: &'static str, code: u32) -> Self {
        Self { operation, code }
    }
}

impl core::fmt::Display for Win32Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} failed (Win32 {})",
            self.operation, self.code
        )
    }
}

/// Result alias used throughout the guard.
pub type GuardResult<T> = Result<T, Win32Error>;

/// An owned kernel handle closed on drop.
///
/// `HANDLE` is a pointer-sized integer. The null handle and
/// `INVALID_HANDLE_VALUE` are both treated as "not owned".
#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// The null handle, used as the empty value.
    pub const NULL: OwnedHandle = OwnedHandle(ptr::null_mut());

    /// Take ownership of `handle`, which may be null.
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    /// Take ownership or fail with `operation`'s last error when null.
    pub fn expect(handle: HANDLE, operation: &'static str) -> GuardResult<Self> {
        if handle.is_null() || handle as isize == -1 {
            Err(Win32Error::last(operation))
        } else {
            Ok(Self(handle))
        }
    }

    /// The raw handle, for passing to Win32 calls.
    pub fn raw(&self) -> HANDLE {
        self.0
    }

    /// Whether this holds a usable handle.
    pub fn is_valid(&self) -> bool {
        !self.0.is_null() && self.0 as isize != -1
    }

    /// Release the handle without closing it.
    pub fn into_raw(mut self) -> HANDLE {
        core::mem::replace(&mut self.0, ptr::null_mut())
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            // SAFETY: the handle is valid and owned by this value.
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

/// The current process pseudo-handle.
pub fn current_process() -> HANDLE {
    // SAFETY: always returns the (pseudo) handle of the calling process.
    unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() }
}

/// Open an access token for `process`.
pub fn open_process_token(process: HANDLE, access: TOKEN_ACCESS_MASK) -> GuardResult<OwnedHandle> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `token` is a valid out pointer.
    let ok: BOOL = unsafe { OpenProcessToken(process, access, &mut token) };
    if ok == 0 {
        return Err(Win32Error::last("OpenProcessToken"));
    }
    OwnedHandle::expect(token, "OpenProcessToken")
}

/// Query a token information class into an owned buffer.
///
/// The buffer keeps the class's own C layout (including inline SIDs), so
/// callers reinterpret it; nothing is copied into Rust-owned structures.
pub fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> GuardResult<Vec<u8>> {
    let mut required: u32 = 0;
    // SAFETY: a null buffer with length 0 asks only for the required size.
    let ok: BOOL = unsafe {
        GetTokenInformation(token, class, ptr::null_mut(), 0, &mut required)
    };
    if ok != 0 {
        return Err(Win32Error::new(
            "GetTokenInformation(size) unexpectedly succeeded",
            0,
        ));
    }
    let code = unsafe { GetLastError() };
    if code != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER || required == 0 {
        return Err(Win32Error::new("GetTokenInformation(size)", code));
    }

    let mut buffer = vec![0u8; required as usize];
    let mut written: u32 = 0;
    // SAFETY: the buffer is `required` bytes and we pass that length.
    let ok: BOOL = unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &mut written,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last("GetTokenInformation(data)"));
    }
    Ok(buffer)
}

/// The query-level access mask needed to read token SIDs and DACL.
pub const TOKEN_READ_QUERY: TOKEN_ACCESS_MASK = TOKEN_QUERY;

/// Convert a SID pointer to its SDDL string form.
pub fn sid_to_string(sid: PSID) -> GuardResult<String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(Win32Error::new("IsValidSid(invalid SID)", 0));
    }
    let mut raw: *mut u16 = ptr::null_mut();
    // SAFETY: `raw` is a valid out pointer; the returned string is LocalFree'd.
    let ok: BOOL = unsafe { ConvertSidToStringSidW(sid, &mut raw) };
    if ok == 0 {
        return Err(Win32Error::last("ConvertSidToStringSidW"));
    }
    let mut len = 0usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated wide string.
    while unsafe { *raw.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` counts the UTF-16 units before the terminator.
    let slice = unsafe { core::slice::from_raw_parts(raw, len) };
    let text = String::from_utf16_lossy(slice);
    // SAFETY: the API handed us this allocation; free it exactly once.
    unsafe {
        LocalFree(raw as HLOCAL);
    }
    Ok(text)
}

/// A SID owned by this process, allocated with the system allocator.
pub struct OwnedSid {
    ptr: PSID,
}

impl OwnedSid {
    /// Create any well-known SID by its constant.
    pub fn well_known(kind: i32) -> GuardResult<Self> {
        // SECURITY_MAX_SID_SIZE is 68 on every supported architecture.
        let mut buffer = vec![0u8; 68];
        let mut size = buffer.len() as u32;
        // SAFETY: the buffer is 68 bytes, the documented maximum SID size.
        let ok: BOOL = unsafe {
            CreateWellKnownSid(
                kind,
                ptr::null_mut(),
                buffer.as_mut_ptr().cast::<c_void>(),
                &mut size,
            )
        };
        if ok == 0 {
            return Err(Win32Error::last("CreateWellKnownSid"));
        }
        let ptr = buffer.as_mut_ptr().cast::<c_void>();
        if unsafe { IsValidSid(ptr) } == 0 {
            return Err(Win32Error::last("IsValidSid"));
        }
        // Leak the Vec: the SID lives for the rest of the process, which is
        // exactly what the guard wants for its well-known SIDs.
        core::mem::forget(buffer);
        Ok(Self { ptr })
    }

    /// Parse an SDDL SID string such as `S-1-5-21-...`.
    pub fn from_string(sid: &str) -> GuardResult<Self> {
        let wide: Vec<u16> = sid.encode_utf16().chain(core::iter::once(0)).collect();
        let mut ptr: PSID = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and `ptr` is a valid out pointer.
        let ok: BOOL = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut ptr) };
        if ok == 0 || ptr.is_null() {
            return Err(Win32Error::last("ConvertStringSidToSidW"));
        }
        // The returned SID belongs to a LocalAlloc allocation; copy it into a
        // Rust-owned buffer and release the original.
        let len = unsafe { GetLengthSid(ptr) } as usize;
        let mut copy = vec![0u8; len];
        // SAFETY: `len` is the source SID's exact byte length.
        let ok: BOOL = unsafe {
            CopySid(
                len as u32,
                copy.as_mut_ptr().cast::<c_void>(),
                ptr,
            )
        };
        // SAFETY: `ptr` came from ConvertStringSidToSidW, which LocalAlloc'd it.
        unsafe {
            LocalFree(ptr as HLOCAL);
        }
        if ok == 0 {
            return Err(Win32Error::last("CopySid"));
        }
        let ptr = copy.as_mut_ptr().cast::<c_void>();
        core::mem::forget(copy);
        Ok(Self { ptr })
    }

    /// The raw SID pointer.
    pub fn as_ptr(&self) -> PSID {
        self.ptr
    }

    /// Compare against another SID pointer.
    pub fn equals(&self, other: PSID) -> bool {
        if other.is_null() {
            return false;
        }
        // SAFETY: both are valid SIDs.
        unsafe { EqualSid(self.ptr, other) != 0 }
    }
}

/// Read a UTF-16 environment variable, returning `None` when unset.
pub fn env_var(name: &str) -> Option<String> {
    let wide: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
    let mut buffer = vec![0u16; 64];
    loop {
        // SAFETY: the buffer and its length are consistent.
        let len = unsafe {
            windows_sys::Win32::System::Environment::GetEnvironmentVariableW(
                wide.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        };
        if len == 0 {
            return None;
        }
        if (len as usize) < buffer.len() {
            buffer.truncate(len as usize);
            return Some(String::from_utf16_lossy(&buffer));
        }
        buffer = vec![0u16; len as usize];
    }
}

/// Set or clear (`None`) an environment variable of the current process.
pub fn set_env_var(name: &str, value: Option<&str>) -> GuardResult<()> {
    let wide_name: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
    let wide_value: Option<Vec<u16>> = value.map(|v| v.encode_utf16().chain(core::iter::once(0)).collect());
    // SAFETY: both pointers are NUL-terminated wide strings, or null.
    let ok: BOOL = unsafe {
        windows_sys::Win32::System::Environment::SetEnvironmentVariableW(
            wide_name.as_ptr(),
            wide_value.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
        )
    };
    if ok == 0 {
        return Err(Win32Error::last("SetEnvironmentVariableW"));
    }
    Ok(())
}

/// Borrow an `ACL` from a token-default-DACL buffer.
pub fn acl_from_ptr(ptr: *mut ACL) -> GuardResult<&'static ACL> {
    if ptr.is_null() {
        return Err(Win32Error::new("null ACL pointer", 0));
    }
    if unsafe { IsValidAcl(ptr) } == 0 {
        return Err(Win32Error::new("IsValidAcl", 0));
    }
    // SAFETY: the ACL is valid and outlives the caller's buffer in practice;
    // the guard only borrows it for the duration of a single call.
    Ok(unsafe { &*ptr })
}

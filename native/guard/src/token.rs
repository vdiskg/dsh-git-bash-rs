// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
//! Child-token preparation and verification.
//!
//! Everything here operates on a **suspended** child that the caller created;
//! nothing resumes it. The goal is narrow: make the objects the child creates
//! reachable by the child itself (via its own logon SID), then make sure that
//! arrangement cannot be undone from inside the child, then prove the child is
//! still running under exactly the same confinement as the guard.

use core::ffi::c_void;
use core::ptr;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ACCESS_DENIED, ERROR_INVALID_SECURITY_DESCR, FALSE, HANDLE, HLOCAL,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, DENY_ACCESS,
    GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_KERNEL_OBJECT, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID,
    TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, NO_INHERITANCE, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_QUERY,
    TOKEN_READ_CONTROL, TOKEN_USER, TOKEN_WRITE_DAC,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::win32::{
    open_process_token, sid_to_string, token_information, OwnedHandle, OwnedSid, Win32Error,
};

/// `FILE_ALL_ACCESS`, used for the default-DACL grant on the logon SID.
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

/// Open the child's token for the hardening steps.
///
/// `WRITE_DAC` is needed to add the deny ACE on the token object itself, so the
/// caller asks for `TOKEN_QUERY | READ_CONTROL | WRITE_DAC`.
pub fn child_token_for_hardening(process: HANDLE) -> crate::win32::GuardResult<OwnedHandle> {
    open_process_token(process, TOKEN_QUERY | TOKEN_WRITE_DAC)
}

/// The set of restricting SIDs a token carries, sorted and deduplicated.
pub fn restricted_sid_set(token: HANDLE) -> crate::win32::GuardResult<Vec<String>> {
    let buffer = token_information(token, windows_sys::Win32::Security::TokenRestrictedSids)?;
    if buffer.len() < core::mem::size_of::<TOKEN_GROUPS>() {
        return Err(Win32Error::new(
            "TOKEN_GROUPS buffer shorter than its header",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    // SAFETY: the buffer holds a TOKEN_GROUPS followed by inline SID_AND_ATTRIBUTES.
    let groups = unsafe { &*(buffer.as_ptr().cast::<TOKEN_GROUPS>()) };
    if groups.GroupCount == 0 {
        return Err(Win32Error::new(
            "token carries no restricting SIDs",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    // SAFETY: GroupCount entries are in the buffer by the API contract.
    let entries = unsafe {
        core::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
    };
    let mut sids = Vec::with_capacity(entries.len());
    for entry in entries {
        sids.push(sid_to_string(entry.Sid)?);
    }
    sids.sort();
    let before = sids.len();
    sids.dedup();
    if sids.len() != before {
        return Err(Win32Error::new(
            "token carries duplicate restricting SIDs",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    Ok(sids)
}

/// The token's logon SID (the per-logon-session `S-1-5-5-x-y` identity).
///
/// The restricted token always keeps this SID in its restricting list, which is
/// what makes it usable as a *narrow* substitute for the broad groups MSYS2
/// would otherwise name.
pub fn logon_sid(token: HANDLE) -> crate::win32::GuardResult<OwnedSid> {
    let buffer = token_information(token, windows_sys::Win32::Security::TokenLogonSid)?;
    if buffer.len() < core::mem::size_of::<TOKEN_GROUPS>() {
        return Err(Win32Error::new(
            "TOKEN_GROUPS buffer shorter than its header",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    // SAFETY: as in `restricted_sid_set`.
    let groups = unsafe { &*(buffer.as_ptr().cast::<TOKEN_GROUPS>()) };
    if groups.GroupCount != 1 {
        return Err(Win32Error::new(
            "logon SID query did not return exactly one SID",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    let sid = groups.Groups[0].Sid;
    if sid.is_null() {
        return Err(Win32Error::new(
            "logon SID pointer is null",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    let sddl = sid_to_string(sid)?;
    OwnedSid::from_string(&sddl)
}

/// Build a `TRUSTEE_W` naming `sid`.
fn trustee(sid: *mut c_void, trustee_type: i32) -> TRUSTEE_W {
    TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: trustee_type,
        ptstrName: sid.cast(),
    }
}

/// Merge one `EXPLICIT_ACCESS_W` into `current` and return the new ACL.
///
/// The returned ACL is a `LocalAlloc` allocation the caller must free.
pub(crate) fn merge_entry(
    entry: &EXPLICIT_ACCESS_W,
    current: *const windows_sys::Win32::Security::ACL,
) -> crate::win32::GuardResult<*mut windows_sys::Win32::Security::ACL> {
    let mut merged: *mut windows_sys::Win32::Security::ACL = ptr::null_mut();
    // SAFETY: `entry` points at one initialized EXPLICIT_ACCESS_W.
    let status = unsafe { SetEntriesInAclW(1, entry, current, &mut merged) };
    if status != 0 || merged.is_null() {
        return Err(Win32Error::new(
            "SetEntriesInAclW",
            if status != 0 { status } else { ERROR_INVALID_SECURITY_DESCR },
        ));
    }
    Ok(merged)
}

/// Add a `FILE_ALL_ACCESS` grant for the token's logon SID to its default DACL.
///
/// This is what MSYS2 tries to do for itself (and is refused under a restricted
/// token). Naming the logon SID keeps the grant scoped to this logon session
/// rather than to a broad group.
pub fn grant_logon_sid_to_default_dacl(process: HANDLE) -> crate::win32::GuardResult<()> {
    // The operation string is load-bearing: failing to open the child token here
    // is the signature of a server whose own default DACL grants the user
    // nothing usable, which is the one guard failure with a known remedy. The
    // DSH plugin matches on it (SERVER_DACL_FAILURE_SIGNATURE) to attach that
    // remedy, so do not shorten it to "OpenProcessToken".
    let token = open_process_token(process, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT).map_err(|error| {
        // Rewrite the operation while keeping the captured code; re-reading
        // GetLastError here would be incidental rather than the real cause.
        Win32Error::new("OpenProcessToken(child default dacl)", error.code)
    })?;
    let logon = logon_sid(token.raw())?;

    let buffer = token_information(token.raw(), windows_sys::Win32::Security::TokenDefaultDacl)?;
    if buffer.len() < core::mem::size_of::<TOKEN_DEFAULT_DACL>() {
        return Err(Win32Error::new(
            "TOKEN_DEFAULT_DACL buffer shorter than its header",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    // SAFETY: the buffer holds a TOKEN_DEFAULT_DACL.
    let info = unsafe { &*(buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()) };
    if info.DefaultDacl.is_null() {
        return Err(Win32Error::new(
            "child token default DACL is missing",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: trustee(logon.as_ptr(), TRUSTEE_IS_GROUP),
    };
    let merged = merge_entry(&entry, info.DefaultDacl)?;

    let updated = TOKEN_DEFAULT_DACL {
        DefaultDacl: merged,
    };
    // SAFETY: `updated` carries a valid ACL and the size we declare matches.
    let ok: BOOL = unsafe {
        SetTokenInformation(
            token.raw(),
            windows_sys::Win32::Security::TokenDefaultDacl,
            (&updated as *const TOKEN_DEFAULT_DACL).cast::<c_void>(),
            core::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    };
    let error = if ok == 0 {
        Some(Win32Error::last("SetTokenInformation(default DACL)"))
    } else {
        None
    };
    // SAFETY: `merged` came from SetEntriesInAclW, which LocalAlloc'd it.
    unsafe {
        LocalFree(merged as HLOCAL);
    }
    match error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Whether `OpenProcessToken(process, TOKEN_ADJUST_DEFAULT)` is refused.
///
/// A refusal is the observable proof that the deny ACE below took effect.
fn adjust_default_is_denied(process: HANDLE) -> crate::win32::GuardResult<bool> {
    match open_process_token(process, TOKEN_ADJUST_DEFAULT) {
        Ok(_) => Ok(false),
        Err(e) if e.code == ERROR_ACCESS_DENIED => Ok(true),
        Err(e) => Err(e),
    }
}

/// Deny `TOKEN_ADJUST_DEFAULT` on the child token object for the user SID.
///
/// Without this, anything running inside the child could rewrite the token's
/// default DACL and undo [`grant_logon_sid_to_default_dacl`]. The function
/// verifies the denial with a live probe rather than assuming success.
pub fn deny_child_token_adjust_default(process: HANDLE) -> crate::win32::GuardResult<()> {
    if adjust_default_is_denied(process)? {
        return Ok(());
    }

    let writable = open_process_token(process, TOKEN_QUERY | TOKEN_WRITE_DAC | TOKEN_READ_CONTROL)?;
    let user_buffer = token_information(writable.raw(), windows_sys::Win32::Security::TokenUser)?;
    if user_buffer.len() < core::mem::size_of::<TOKEN_USER>() {
        return Err(Win32Error::new(
            "TOKEN_USER buffer shorter than its header",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    // SAFETY: the buffer holds a TOKEN_USER.
    let user = unsafe { &*(user_buffer.as_ptr().cast::<TOKEN_USER>()) };
    if user.User.Sid.is_null() {
        return Err(Win32Error::new(
            "child token user SID is null",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }

    let mut current_dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: all out pointers are valid; the descriptor is freed below.
    let status = unsafe {
        GetSecurityInfo(
            writable.raw(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut current_dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(Win32Error::new("GetSecurityInfo(child token)", status));
    }
    if current_dacl.is_null() {
        // SAFETY: `descriptor` came from GetSecurityInfo.
        unsafe {
            LocalFree(descriptor as HLOCAL);
        }
        return Err(Win32Error::new(
            "child token object DACL is missing",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: TOKEN_ADJUST_DEFAULT,
        grfAccessMode: DENY_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: trustee(user.User.Sid, TRUSTEE_IS_USER),
    };
    let merged = match merge_entry(&entry, current_dacl) {
        Ok(acl) => {
            // SAFETY: `descriptor` owns `current_dacl`; free it once, now.
            unsafe {
                LocalFree(descriptor as HLOCAL);
            }
            acl
        }
        Err(e) => {
            // SAFETY: as above.
            unsafe {
                LocalFree(descriptor as HLOCAL);
            }
            return Err(e);
        }
    };

    // SAFETY: `merged` is a valid ACL being installed on the token object.
    let status = unsafe {
        SetSecurityInfo(
            writable.raw(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            merged,
            ptr::null_mut(),
        )
    };
    // SAFETY: `merged` came from SetEntriesInAclW.
    unsafe {
        LocalFree(merged as HLOCAL);
    }
    if status != 0 {
        return Err(Win32Error::new("SetSecurityInfo(child token)", status));
    }

    if !adjust_default_is_denied(process)? {
        return Err(Win32Error::new(
            "child token still grants TOKEN_ADJUST_DEFAULT after hardening",
            ERROR_ACCESS_DENIED,
        ));
    }
    Ok(())
}

/// Assert the child token's restricting SIDs equal `expected`.
///
/// This is the check that keeps the guard honest: if the child is not running
/// under the exact same confinement as the guard, the guard kills it rather
/// than continuing.
pub fn verify_same_confinement(
    process: HANDLE,
    expected: &[String],
) -> crate::win32::GuardResult<()> {
    let token = open_process_token(process, TOKEN_QUERY)?;
    let actual = restricted_sid_set(token.raw())?;
    if actual != expected {
        return Err(Win32Error::new(
            "child token restricting SIDs differ from the guard's",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    Ok(())
}

/// Read the guard's own restricting SIDs, or `None` when it is unconfined.
///
/// An unconfined guard carries no restricting SIDs; the launcher refuses to
/// continue in that case, because "confined bash" would be a lie.
pub fn own_restricted_sid_set() -> crate::win32::GuardResult<Option<Vec<String>>> {
    let process = unsafe { GetCurrentProcess() };
    let token = open_process_token(process, TOKEN_QUERY)?;
    match restricted_sid_set(token.raw()) {
        Ok(sids) => Ok(Some(sids)),
        Err(e) if e.operation.contains("no restricting SIDs") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Reject a code path that would run the child unconfined.
pub fn assert_confined(expected: Option<&Vec<String>>) -> crate::win32::GuardResult<()> {
    match expected {
        Some(_) => Ok(()),
        None => Err(Win32Error::new(
            "guard is not running under a restricted token; refusing to launch",
            ERROR_ACCESS_DENIED,
        )),
    }
}

/// Keep `FALSE` referenced so the import is not flagged when features vary.
#[allow(dead_code)]
const _UNUSED: BOOL = FALSE;

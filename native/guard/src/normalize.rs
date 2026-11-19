// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
//! Server-token default-DACL normalization.
//!
//! DSH derives every restricted token from the server's own process token, and
//! a restricted token's DACL starts as a copy of that token's **default** DACL.
//! A server started outside an MSYS2 environment can carry a default DACL with
//! no entry for the signed-in user; the guard's child-token setup then fails,
//! because the restricted DACL it inherits grants the child nothing usable.
//!
//! Starting `dsh` from Git Bash gets this normalization for free, since MSYS2
//! rewrites the token of its own processes. This subcommand applies the same
//! shape on demand: one explicit full-access ACE for the user SID. It runs on
//! the **unrestricted** server token, changes only that token's default DACL,
//! and is idempotent, so calling it once per server process is safe.

use core::ffi::c_void;
use core::ptr;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_INVALID_SECURITY_DESCR, HLOCAL, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAclInformation, GetAce, IsValidAcl, IsValidSid, NO_INHERITANCE,
    SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Security::{ACL_SIZE_INFORMATION, AclSizeInformation};

use crate::token::merge_entry;
use crate::win32::{
    current_process, open_process_token, token_information, Win32Error,
};

/// `FILE_ALL_ACCESS`.
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
/// `ACCESS_ALLOWED_ACE_TYPE`.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// `GENERIC_ALL`.
const GENERIC_ALL: u32 = 0x1000_0000;

/// The header every ACE begins with.
#[repr(C)]
struct AceHeader {
    ace_type: u8,
    ace_flags: u8,
    ace_size: u16,
}

/// An `ACCESS_ALLOWED_ACE`; `sid_start` is the first byte of the trustee SID.
#[repr(C)]
struct AccessAllowedAce {
    header: AceHeader,
    mask: u32,
    sid_start: u32,
}

/// What the normalization did.
enum Outcome {
    AlreadyCovered,
    Normalized,
}

/// Run `--normalize-server-dacl`.
///
/// Returns the process exit code: `0` when the default DACL already covered the
/// user or was normalized, `1` when the token could not be read or written.
pub fn run() -> i32 {
    match normalize() {
        Ok(Outcome::AlreadyCovered) => {
            println!("server-dacl=ok");
            0
        }
        Ok(Outcome::Normalized) => {
            println!("server-dacl=normalized");
            0
        }
        Err(error) => {
            eprintln!("msys-token-guard: {error}");
            1
        }
    }
}

/// Whether the token's default DACL already grants the user full access.
fn default_dacl_covers_user(token: HANDLE) -> Result<bool, Win32Error> {
    let user_buffer = token_information(token, windows_sys::Win32::Security::TokenUser)?;
    if user_buffer.len() < core::mem::size_of::<TOKEN_USER>() {
        return Err(Win32Error::new(
            "TOKEN_USER buffer shorter than its header",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    // SAFETY: the buffer holds a TOKEN_USER.
    let user = unsafe { &*(user_buffer.as_ptr().cast::<TOKEN_USER>()) };
    if user.User.Sid.is_null() || unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Err(Win32Error::new(
            "server token carries an invalid user SID",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }

    let dacl_buffer = token_information(token, windows_sys::Win32::Security::TokenDefaultDacl)?;
    if dacl_buffer.len() < core::mem::size_of::<TOKEN_DEFAULT_DACL>() {
        return Err(Win32Error::new(
            "TOKEN_DEFAULT_DACL buffer shorter than its header",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    // SAFETY: the buffer holds a TOKEN_DEFAULT_DACL.
    let info = unsafe { &*(dacl_buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()) };
    if info.DefaultDacl.is_null() || unsafe { IsValidAcl(info.DefaultDacl) } == 0 {
        return Err(Win32Error::new(
            "server token default DACL is missing or invalid",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }

    let mut size_info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `size_info` is correctly sized for `AclSizeInformation`.
    let ok: BOOL = unsafe {
        GetAclInformation(
            info.DefaultDacl,
            (&mut size_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
            core::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last("GetAclInformation(server default DACL)"));
    }

    for index in 0..size_info.AceCount {
        let mut raw: *mut c_void = ptr::null_mut();
        // SAFETY: `raw` receives an ACE owned by the ACL.
        let ok: BOOL = unsafe { GetAce(info.DefaultDacl, index, &mut raw) };
        if ok == 0 || raw.is_null() {
            return Err(Win32Error::last("GetAce(server default DACL)"));
        }
        // SAFETY: every ACE begins with an ACE header.
        let header = unsafe { &*(raw.cast::<AceHeader>()) };
        if header.ace_type != ACCESS_ALLOWED_ACE_TYPE {
            continue;
        }
        // SAFETY: an allow ACE has the AccessAllowed layout.
        let ace = unsafe { &*(raw.cast::<AccessAllowedAce>()) };
        let grants_full = ace.mask & GENERIC_ALL != 0
            || ace.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS;
        if !grants_full {
            continue;
        }
        // SAFETY: `sid_start` is the trustee SID inside this ACE.
        let sid = unsafe { ptr::addr_of!(ace.sid_start) as *mut c_void };
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(Win32Error::new(
                "invalid SID in the server default DACL",
                ERROR_INVALID_SECURITY_DESCR,
            ));
        }
        // SAFETY: both SIDs were just validated.
        if unsafe { EqualSid(sid, user.User.Sid) } != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn normalize() -> Result<Outcome, Win32Error> {
    let token = open_process_token(current_process(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT)?;

    if default_dacl_covers_user(token.raw())? {
        return Ok(Outcome::AlreadyCovered);
    }

    let user_buffer = token_information(token.raw(), windows_sys::Win32::Security::TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER.
    let user = unsafe { &*(user_buffer.as_ptr().cast::<TOKEN_USER>()) };
    let dacl_buffer = token_information(token.raw(), windows_sys::Win32::Security::TokenDefaultDacl)?;
    // SAFETY: the buffer holds a TOKEN_DEFAULT_DACL.
    let info = unsafe { &*(dacl_buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()) };

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: user.User.Sid.cast(),
        },
    };
    let merged = merge_entry(&entry, info.DefaultDacl)?;

    let updated = TOKEN_DEFAULT_DACL {
        DefaultDacl: merged,
    };
    // SAFETY: `updated` carries a valid ACL and the declared size matches.
    let ok: BOOL = unsafe {
        SetTokenInformation(
            token.raw(),
            windows_sys::Win32::Security::TokenDefaultDacl,
            (&updated as *const TOKEN_DEFAULT_DACL).cast::<c_void>(),
            core::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    };
    let failure = if ok == 0 {
        Some(Win32Error::last("SetTokenInformation(server default DACL)"))
    } else {
        None
    };
    // SAFETY: `merged` came from SetEntriesInAclW, which LocalAlloc'd it.
    unsafe {
        LocalFree(merged as HLOCAL);
    }
    if let Some(error) = failure {
        return Err(error);
    }

    if !default_dacl_covers_user(token.raw())? {
        return Err(Win32Error::new(
            "server default DACL still lacks user coverage after the grant",
            ERROR_INVALID_SECURITY_DESCR,
        ));
    }
    Ok(Outcome::Normalized)
}

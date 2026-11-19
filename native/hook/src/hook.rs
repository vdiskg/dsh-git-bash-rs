// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
//
// Derived from dsh-git-bash (MIT, Copyright (c) 2026); upstream license text
// in licenses/dsh-git-bash-LICENSE. See LICENSE and NOTICE.
//! The detours themselves.
//!
//! Two exported functions are patched:
//!
//! * `ntdll!NtSetInformationToken` — reports success for MSYS2's
//!   `TokenDefaultDacl` write instead of applying it.
//! * `advapi32!RtlAddAccessAllowedAce` — swaps the `Administrators` trustee for
//!   the current logon SID when MSYS2 grants `GENERIC_ALL`.
//!
//! Both are *gated*: they only alter behaviour when the immediate caller is
//! inside `msys-2.0.dll`, so nothing else in the process sees different
//! semantics. `raw-dylib`-free resolution goes through `GetProcAddress` so a
//! missing export is a load-time failure rather than a silent no-op.

use core::ffi::c_void;
use core::ptr;

use detour::RawDetour;
use windows_sys::Win32::Foundation::{HMODULE, TRUE};
use windows_sys::Win32::Security::{ACL, PSID};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

use crate::{state, TOKEN_DEFAULT_DACL_CLASS};

/// `TokenDefaultDacl` information class value.
const TOKEN_DEFAULT_DACL: i32 = TOKEN_DEFAULT_DACL_CLASS;

/// `GENERIC_ALL`.
const GENERIC_ALL: u32 = 0x1000_0000;

/// `STATUS_SUCCESS`.
const STATUS_SUCCESS: i32 = 0;

type NtSetInformationTokenFn =
    unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32) -> i32;
type RtlAddAccessAllowedAceFn =
    unsafe extern "system" fn(*mut ACL, u32, u32, PSID) -> i32;

type HANDLE = *mut c_void;

/// Detour objects must outlive the process; they are never dropped.
static mut SET_TOKEN_DETOUR: Option<RawDetour> = None;
static mut ADD_ACE_DETOUR: Option<RawDetour> = None;

/// Trampolines to the original functions, set once during install.
static mut REAL_SET_INFORMATION_TOKEN: Option<NtSetInformationTokenFn> = None;
static mut REAL_ADD_ACCESS_ALLOWED_ACE: Option<RtlAddAccessAllowedAceFn> = None;

/// Resolve `module!symbol` to an address.
fn resolve(module: &str, symbol: &[u8]) -> Result<*const (), String> {
    let module_c: Vec<u8> = module.bytes().chain(core::iter::once(0)).collect();
    // SAFETY: `module_c` is NUL-terminated.
    let handle: HMODULE = unsafe { GetModuleHandleA(module_c.as_ptr()) };
    if handle.is_null() {
        return Err(format!("{module} is not loaded"));
    }
    // SAFETY: `symbol` is NUL-terminated by the caller.
    match unsafe { GetProcAddress(handle, symbol.as_ptr()) } {
        Some(address) => Ok(address as *const ()),
        None => Err(format!(
            "{module}!{} is missing",
            String::from_utf8_lossy(&symbol[..symbol.len().saturating_sub(1)])
        )),
    }
}

/// Whether `address` lies inside `msys-2.0.dll`.
///
/// MSYS2's runtime base is discovered lazily: the DLL may already be mapped
/// when the first hooked call happens.
fn caller_is_msys(return_address: *mut c_void) -> bool {
    let base = {
        let current = state().msys_base;
        if !current.is_null() {
            current
        } else {
            // `GetModuleHandleA` on a not-yet-loaded module returns null, which
            // simply means "this call is not from MSYS2 yet".
            let handle = unsafe { GetModuleHandleA(b"msys-2.0.dll\0".as_ptr()) };
            handle as *mut c_void
        }
    };
    if base.is_null() || return_address.is_null() {
        return false;
    }
    image_contains(base, return_address)
}

/// Whether `address` lies within the image mapped at `base`.
fn image_contains(base: *mut c_void, address: *mut c_void) -> bool {
    let base = base as usize;
    let address = address as usize;
    if address < base {
        return false;
    }
    let offset = address - base;
    // Read SizeOfImage from the mapped PE headers.
    // SAFETY: the base points at a mapped PE image.
    unsafe {
        let dos = base as *const u8;
        if *dos != b'M' || ptr::read_unaligned(dos.add(1)) != b'Z' {
            return false;
        }
        let e_lfanew = ptr::read_unaligned(dos.add(0x3C).cast::<i32>());
        if e_lfanew <= 0 {
            return false;
        }
        let nt = dos.add(e_lfanew as usize);
        if *nt != b'P' || ptr::read_unaligned(nt.add(1)) != b'E' {
            return false;
        }
        // OptionalHeader.SizeOfImage is at PE+0x18+0x38 for PE32+.
        let optional = nt.add(0x18);
        let size_of_image = ptr::read_unaligned(optional.add(0x38).cast::<u32>());
        (offset as u32) < size_of_image
    }
}

/// Capture a process token's logon SID into `slot`.
///
/// Mirrors the reference implementation: the SID is located by walking
/// `TokenGroups` for the entry carrying `SE_GROUP_LOGON_ID`, rather than
/// relying on the `TokenLogonSid` information class. Both are documented, but
/// only the group walk is guaranteed to find the SID on every token shape.
pub fn capture_logon_sid(slot: &mut [u8; 68]) -> bool {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `token` is a valid out pointer.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return false;
    }
    let guard = TokenHandle(token);
    read_logon_sid(token, slot)
        .inspect_err(|_| drop(guard))
        .is_ok()
}

/// Read the logon SID of `token` into `slot`.
fn read_logon_sid(token: HANDLE, slot: &mut [u8; 68]) -> Result<(), ()> {
    use windows_sys::Win32::Security::{
        CopySid, GetLengthSid, GetTokenInformation, TOKEN_GROUPS, TOKEN_QUERY, TokenGroups,
    };

    /// `SE_GROUP_LOGON_ID`: marks the logon session SID in `TokenGroups`.
    const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

    let mut required: u32 = 0;
    // SAFETY: size query with a null buffer.
    unsafe {
        GetTokenInformation(token, TokenGroups, ptr::null_mut(), 0, &mut required);
    }
    if required < core::mem::size_of::<TOKEN_GROUPS>() as u32 {
        return Err(());
    }
    let mut buffer = vec![0u8; required as usize];
    // SAFETY: the buffer is `required` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    };
    if ok == 0 {
        return Err(());
    }
    // SAFETY: the buffer holds a TOKEN_GROUPS.
    let groups = unsafe { &*(buffer.as_ptr().cast::<TOKEN_GROUPS>()) };
    let entries = unsafe {
        core::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
    };
    let logon = entries
        .iter()
        .find(|entry| entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
        .ok_or(())?;
    let sid = logon.Sid;
    if sid.is_null() {
        return Err(());
    }
    // SAFETY: `sid` is a valid SID inside the buffer.
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length == 0 || length > slot.len() {
        return Err(());
    }
    // SAFETY: both buffers are at least `length` bytes.
    if unsafe { CopySid(length as u32, slot.as_mut_ptr().cast::<c_void>(), sid) } == 0 {
        return Err(());
    }
    Ok(())
}

/// Closes a token handle on drop.
struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: owned token handle.
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

/// Whether `candidate` is the calling process's own primary token.
///
/// The detour must only intercept MSYS2 configuring *its own* token; other
/// tokens (including the child tokens the guard hardens) must pass through
/// untouched.
fn is_current_process_token(candidate: HANDLE) -> bool {
    use windows_sys::Win32::Security::{GetTokenInformation, TokenStatistics, TOKEN_STATISTICS};

    fn statistics(token: HANDLE) -> Option<TOKEN_STATISTICS> {
        let mut value: TOKEN_STATISTICS = unsafe { core::mem::zeroed() };
        let mut returned: u32 = 0;
        // SAFETY: `value` is correctly sized for TokenStatistics.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenStatistics,
                (&mut value as *mut TOKEN_STATISTICS).cast::<c_void>(),
                core::mem::size_of::<TOKEN_STATISTICS>() as u32,
                &mut returned,
            )
        };
        if ok == 0 {
            return None;
        }
        Some(value)
    }

    if candidate.is_null() {
        return false;
    }
    let Some(candidate_stats) = statistics(candidate) else {
        return false;
    };
    let mut current: HANDLE = ptr::null_mut();
    // SAFETY: `current` is a valid out pointer for the current process.
    let ok = unsafe {
        windows_sys::Win32::System::Threading::OpenProcessToken(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            windows_sys::Win32::Security::TOKEN_QUERY,
            &mut current,
        )
    };
    if ok == 0 {
        return false;
    }
    let guard = TokenHandle(current);
    let Some(current_stats) = statistics(guard.0) else {
        return false;
    };
    candidate_stats.TokenId.LowPart == current_stats.TokenId.LowPart
        && candidate_stats.TokenId.HighPart == current_stats.TokenId.HighPart
}

/// The `NtSetInformationToken` detour.
unsafe extern "system" fn detour_set_information_token(
    token: HANDLE,
    class: i32,
    information: *mut c_void,
    length: u32,
) -> i32 {
    let from_msys = caller_is_msys(return_address());
    let own_token = if class == TOKEN_DEFAULT_DACL && from_msys {
        is_current_process_token(token)
    } else {
        false
    };
    if std::env::var_os("DSH_MSYS_TOKEN_GUARD_DEBUG").is_some() {
        eprintln!(
            "msys-token-guard-hook: NtSetInformationToken class={class} from_msys={from_msys} own_token={own_token}"
        );
    }
    if class == TOKEN_DEFAULT_DACL && from_msys && own_token {
        // Report success without applying: the guard already installed the
        // narrow logon-SID default DACL.
        return STATUS_SUCCESS;
    }
    match REAL_SET_INFORMATION_TOKEN {
        Some(real) => real(token, class, information, length),
        None => STATUS_SUCCESS,
    }
}

/// The `RtlAddAccessAllowedAce` detour.
unsafe extern "system" fn detour_add_access_allowed_ace(
    acl: *mut ACL,
    revision: u32,
    mask: u32,
    sid: PSID,
) -> i32 {
    let mut effective = sid;
    let current = state();
    let from_msys = caller_is_msys(return_address());
    let substitute = mask == GENERIC_ALL
        && current.ready
        && !sid.is_null()
        && from_msys
        && sid_equals(sid, current.admin_sid.as_ptr() as PSID);
    if std::env::var_os("DSH_MSYS_TOKEN_GUARD_DEBUG").is_some() {
        let sid_text = crate::sid_debug_string(sid);
        let admin_text = unsafe {
            crate::sid_debug_string(current.admin_sid.as_ptr() as PSID)
        };
        eprintln!(
            "msys-token-guard-hook: RtlAddAccessAllowedAce mask=0x{mask:x} from_msys={from_msys} substitute={substitute} sid={sid_text} admin={admin_text}"
        );
    }
    if substitute {
        // Substitute the logon SID for the deny-only Administrators group.
        effective = current.logon_sid.as_ptr() as PSID;
    }
    match REAL_ADD_ACCESS_ALLOWED_ACE {
        Some(real) => real(acl, revision, mask, effective),
        None => 0,
    }
}

/// The caller's return address.
///
/// `core::intrinsics::return_address` is unstable, so this uses the stable
/// `RtlCaptureStackBackTrace` and skips our own frames. Frame 0 is this
/// helper and frame 1 is the detour, so the *third* entry is the hooked
/// function's caller.
#[inline(always)]
unsafe fn return_address() -> *mut c_void {
    let mut frames = [ptr::null_mut::<c_void>(); 4];
    let captured = windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace(
        2,
        frames.len() as u32,
        frames.as_mut_ptr(),
        ptr::null_mut(),
    );
    if captured == 0 {
        return ptr::null_mut();
    }
    frames[0]
}

/// Compare two SIDs.
fn sid_equals(left: PSID, right: PSID) -> bool {
    // SAFETY: both are non-null valid SIDs.
    unsafe { windows_sys::Win32::Security::EqualSid(left, right as PSID) != 0 }
}

/// Install both detours.
///
/// Called from `DllMain` during process startup, **before** the program's own
/// entry point and static initializers run. That ordering is the whole point:
/// MSYS2 performs its `NtSetInformationToken` call from static initialization,
/// so the detour must already be live by then.
pub fn install() -> Result<(), String> {
    let set_token = resolve("ntdll.dll", b"NtSetInformationToken\0")?;
    // `RtlAddAccessAllowedAce` is exported by ntdll, not advapi32.
    let add_ace = resolve("ntdll.dll", b"RtlAddAccessAllowedAce\0")?;

    // SAFETY: the targets are live exported functions and our detours match
    // their signatures. The detours stay installed for the process lifetime.
    unsafe {
        let set_detour = RawDetour::new(set_token, detour_set_information_token as *const ())
            .map_err(|e| format!("NtSetInformationToken: {e}"))?;
        REAL_SET_INFORMATION_TOKEN = Some(core::mem::transmute(
            set_detour.trampoline(),
        ));
        set_detour
            .enable()
            .map_err(|e| format!("NtSetInformationToken enable: {e}"))?;
        *ptr::addr_of_mut!(SET_TOKEN_DETOUR) = Some(set_detour);

        let ace_detour = RawDetour::new(add_ace, detour_add_access_allowed_ace as *const ())
            .map_err(|e| format!("RtlAddAccessAllowedAce: {e}"))?;
        REAL_ADD_ACCESS_ALLOWED_ACE = Some(core::mem::transmute(ace_detour.trampoline()));
        ace_detour
            .enable()
            .map_err(|e| format!("RtlAddAccessAllowedAce enable: {e}"))?;
        *ptr::addr_of_mut!(ADD_ACE_DETOUR) = Some(ace_detour);
    }

    // `CreateProcessW` is hooked so grandchildren are injected too.
    crate::child::install()?;

    // Keep `TRUE` referenced for the loader contract above.
    let _ = TRUE;
    Ok(())
}

/// The exit code used for every hook-side failure.
pub const fn exit_code() -> u32 {
    crate::HOOK_FAILURE_EXIT_CODE
}

/// The path of this injected DLL, used to inject grandchildren.
///
/// `GetModuleFileNameA` is called with this module's own `HMODULE` — obtained
/// from an address inside the module — because passing null would return the
/// path of the **hosting executable** and write a nonsense import entry.
pub fn self_module_path() -> Result<Vec<u8>, String> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameA, GetModuleHandleExA};

    /// `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS`.
    const FROM_ADDRESS: u32 = 0x0000_0004;
    /// `GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT`.
    const UNCHANGED_REFCOUNT: u32 = 0x0000_0002;

    let mut module: *mut c_void = ptr::null_mut();
    // SAFETY: the address of a function in this module identifies it.
    let ok = unsafe {
        GetModuleHandleExA(
            FROM_ADDRESS | UNCHANGED_REFCOUNT,
            self_module_path as *const u8,
            &mut module,
        )
    };
    if ok == 0 || module.is_null() {
        return Err("GetModuleHandleExA failed for the hook DLL".to_string());
    }

    let mut buffer = vec![0u8; 32 * 1024];
    // SAFETY: `buffer` is writable and correctly sized.
    let len = unsafe {
        GetModuleFileNameA(module, buffer.as_mut_ptr(), buffer.len() as u32)
    };
    if len == 0 || len as usize >= buffer.len() {
        return Err("GetModuleFileNameA failed for the hook DLL".to_string());
    }
    buffer.truncate(len as usize);
    Ok(buffer)
}

/// Rewrite `process`'s import table so this hook DLL loads at startup.
pub fn inject_into_process(process: HANDLE) -> Result<(), String> {
    let path = self_module_path()?;
    // `imports` takes a narrow path, matching Detours' ANSI DLL-path contract.
    let text = String::from_utf8_lossy(&path).into_owned();
    match crate::imports::inject_via_import_table(process, &text) {
        Ok(_) => Ok(()),
        Err(error) => Err(format!("import injection failed: {error:?}")),
    }
}

/// Deny `TOKEN_ADJUST_DEFAULT` on a grandchild token.
///
/// The guard does this for the top-level bash; grandchildren created here need
/// the same hardening so none of them can undo the default-DACL arrangement.
pub fn deny_child_adjust_default(process: HANDLE) -> Result<(), String> {
    // Only the deny ACE is re-applied. The default DACL is inherited from the
    // parent, and the guard already put the logon-SID grant in it; re-merging a
    // second grant here would stack duplicate ACEs on every fork generation.
    deny_adjust_default_ace(process)
}

/// Add the logon-SID full-access ACE to `process`'s token default DACL.
fn grant_logon_sid_to_default_dacl(process: HANDLE) -> Result<(), String> {
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_GROUP,
        TRUSTEE_IS_SID, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        SetTokenInformation, NO_INHERITANCE, TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &mut token) == 0 {
            return Err("OpenProcessToken(child default DACL)".to_string());
        }
        let token = TokenHandle(token);

        // The child's own logon SID, taken from its token groups.
        let mut logon = [0u8; 68];
        if !crate::hook::capture_logon_sid(&mut logon) {
            return Err("child carries no logon SID".to_string());
        }

        let mut dacl_buffer = vec![0u8; core::mem::size_of::<TOKEN_DEFAULT_DACL>()];
        let mut returned = 0u32;
        if windows_sys::Win32::Security::GetTokenInformation(
            token.0,
            TOKEN_DEFAULT_DACL,
            dacl_buffer.as_mut_ptr().cast::<c_void>(),
            dacl_buffer.len() as u32,
            &mut returned,
        ) == 0
        {
            return Err("GetTokenInformation(TokenDefaultDacl)".to_string());
        }
        let info = &*(dacl_buffer.as_ptr() as *const TOKEN_DEFAULT_DACL);
        if info.DefaultDacl.is_null() {
            return Err("child token default DACL is missing".to_string());
        }

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: logon.as_ptr() as *mut u16,
            },
        };
        let mut merged: *mut ACL = ptr::null_mut();
        let status = SetEntriesInAclW(1, &entry, info.DefaultDacl, &mut merged);
        if status != 0 || merged.is_null() {
            return Err(format!("SetEntriesInAclW(default DACL) status={status}"));
        }

        let updated = TOKEN_DEFAULT_DACL { DefaultDacl: merged };
        let ok = SetTokenInformation(
            token.0,
            TOKEN_DEFAULT_DACL,
            (&updated as *const TOKEN_DEFAULT_DACL).cast::<c_void>(),
            core::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
        );
        windows_sys::Win32::Foundation::LocalFree(merged as _);
        if ok == 0 {
            return Err("SetTokenInformation(default DACL)".to_string());
        }
        Ok(())
    }
}

/// Add the `TOKEN_ADJUST_DEFAULT` deny ACE on the token object.
fn deny_adjust_default_ace(process: HANDLE) -> Result<(), String> {
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, DENY_ACCESS, EXPLICIT_ACCESS_W,
        NO_MULTIPLE_TRUSTEE, SE_KERNEL_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, TOKEN_ADJUST_DEFAULT,
        TOKEN_QUERY, TOKEN_READ_CONTROL, TOKEN_WRITE_DAC, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    unsafe {
        // 1. Already denied? Nothing to do.
        let mut probe: HANDLE = ptr::null_mut();
        if OpenProcessToken(process, TOKEN_ADJUST_DEFAULT, &mut probe) != 0 {
            windows_sys::Win32::Foundation::CloseHandle(probe);
        } else {
            return Ok(());
        }

        // 2. Read the token's user SID.
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            process,
            TOKEN_QUERY | TOKEN_READ_CONTROL | TOKEN_WRITE_DAC,
            &mut token,
        ) == 0
        {
            return Err("OpenProcessToken(child WRITE_DAC)".to_string());
        }
        let token = TokenHandle(token);

        let mut user_buffer = vec![0u8; core::mem::size_of::<TOKEN_USER>() + 68];
        let mut returned = 0u32;
        if GetTokenInformation(
            token.0,
            TokenUser,
            user_buffer.as_mut_ptr().cast::<c_void>(),
            user_buffer.len() as u32,
            &mut returned,
        ) == 0
        {
            return Err("GetTokenInformation(TokenUser)".to_string());
        }
        let user = &*(user_buffer.as_ptr() as *const TOKEN_USER);
        if user.User.Sid.is_null() {
            return Err("child token user SID is null".to_string());
        }

        // 3. Merge a deny ACE into the token object's DACL.
        let mut current: *mut ACL = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let status = GetSecurityInfo(
            token.0,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut current,
            ptr::null_mut(),
            &mut descriptor,
        );
        if status != 0 || current.is_null() {
            return Err(format!("GetSecurityInfo(child token) status={status}"));
        }

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: TOKEN_ADJUST_DEFAULT,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: user.User.Sid.cast(),
            },
        };
        let mut merged: *mut ACL = ptr::null_mut();
        let merge_status = SetEntriesInAclW(1, &entry, current, &mut merged);
        windows_sys::Win32::Foundation::LocalFree(descriptor as _
        );
        if merge_status != 0 || merged.is_null() {
            return Err(format!("SetEntriesInAclW status={merge_status}"));
        }

        let apply_status = SetSecurityInfo(
            token.0,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            merged,
            ptr::null_mut(),
        );
        windows_sys::Win32::Foundation::LocalFree(merged as _);
        if apply_status != 0 {
            return Err(format!("SetSecurityInfo(child token) status={apply_status}"));
        }
        Ok(())
    }
}

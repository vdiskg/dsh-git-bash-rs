// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 vdiskg
// SPDX-FileCopyrightText: 2026
// SPDX-FileCopyrightText: Microsoft Corporation
//
// Portions derived from Microsoft Detours v4.0.1 (MIT) and from dsh-git-bash
// (MIT). See the repository's LICENSE and NOTICE for the full text.
//
//! Prepare a child's PE import directory so a DLL loads during process startup.
//!
//! Derived from Microsoft Detours (MIT, Copyright (c) Microsoft Corporation),
//! v4.0.1: `UpdateImports64` (`uimports.cpp`) and `FindAndAllocateNearBase`
//! (`creatwth.cpp`), translated into Rust. See `NOTICE` and `LICENSE` for the
//! full attribution; `native/guard/src/imports.rs` is a sibling variant of the
//! same translation, differing in error plumbing and item visibility.
//!
//! While the target is still suspended, a *new* import directory is built in
//! memory next to the image, the hook DLL is added to it, and the PE optional
//! header's `DataDirectory` is repointed at it. When the process finally
//! starts, the Windows loader — not a helper thread — maps the DLL and runs
//! its `DllMain` before the program's own entry point.
//!
//! Why this design: MSYS2 binaries run substantial startup code from their
//! static initializers. A `CreateRemoteThread(LoadLibraryW)` injection races
//! that sequence and loses — MSYS2 has already failed by the time the thread
//! runs. Repointing the import table removes the race entirely.

use core::ffi::c_void;
use core::mem;
use core::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory,
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    MEM_FREE, MEM_RESERVE, PAGE_READWRITE, PAGE_READWRITE as PAGE_READWRITE_PROTECT,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use windows_sys::Win32::Foundation::GetLastError;

/// Guard/hook-local result alias.
pub(crate) type GuardResult<T> = Result<T, Win32Error>;

/// A Win32 failure: the operation name plus its code.
#[derive(Debug)]
pub(crate) struct Win32Error {
    operation: &'static str,
    code: u32,
}

impl Win32Error {
    fn last(operation: &'static str) -> Self {
        Self { operation, code: unsafe { GetLastError() } }
    }

    fn new(operation: &'static str, code: u32) -> Self {
        Self { operation, code }
    }
}

/// Size of the DOS header (`IMAGE_DOS_HEADER`).
const DOS_HEADER_SIZE: usize = 64;
/// Size of `IMAGE_FILE_HEADER`.
const FILE_HEADER_SIZE: usize = 20;
/// Size of `IMAGE_IMPORT_DESCRIPTOR`.
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
/// Allocation granularity of the Windows allocator.
const ALLOCATION_GRANULARITY: usize = 0x10000;
/// `IMAGE_ORDINAL_FLAG64`.
const IMAGE_ORDINAL_FLAG64: u64 = 1 << 63;

/// `IMAGE_DOS_HEADER`, restricted to the fields we need.
///
/// `e_lfanew` sits at offset `0x3C`; the rest is padding we never read.
#[repr(C)]
#[derive(Clone, Copy)]
struct DosHeader {
    e_magic: u16,
    _pad_to_lfanew: [u8; 0x3C - 2],
    e_lfanew: u32,
}

/// `IMAGE_FILE_HEADER`.
#[repr(C)]
#[derive(Clone, Copy)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

/// `IMAGE_OPTIONAL_HEADER64`, only the fields the import rewrite touches.
#[repr(C)]
#[derive(Clone, Copy)]
struct OptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    /// `DataDirectory[]`; index 1 is the import table, 12 the IAT.
    data_directory: [DataDirectory; 16],
}

/// `IMAGE_DATA_DIRECTORY`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

/// `IMAGE_IMPORT_DESCRIPTOR`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

const IMPORT_DIRECTORY_INDEX: usize = 1;
const IAT_DIRECTORY_INDEX: usize = 12;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

/// Read exactly `size` bytes at `address` in `process`.
fn read_memory<T: Copy>(process: HANDLE, address: usize, value: &mut T) -> GuardResult<()> {
    let size = mem::size_of::<T>();
    let mut read = 0usize;
    // SAFETY: `value` is `size` bytes and `process` is a live handle.
    let ok = unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            (value as *mut T).cast::<c_void>(),
            size,
            &mut read,
        )
    };
    if ok == 0 || read != size {
        return Err(Win32Error::last("ReadProcessMemory"));
    }
    Ok(())
}

/// Write `bytes` at `address` in `process`.
fn write_memory(process: HANDLE, address: usize, bytes: &[u8]) -> GuardResult<()> {
    let mut written = 0usize;
    // SAFETY: `bytes` is a valid slice and `process` is a live handle.
    let ok = unsafe {
        WriteProcessMemory(
            process,
            address as *mut c_void,
            bytes.as_ptr().cast::<c_void>(),
            bytes.len(),
            &mut written,
        )
    };
    if ok == 0 || written != bytes.len() {
        return Err(Win32Error::last("WriteProcessMemory"));
    }
    Ok(())
}

/// Round up to the next 4-byte boundary.
fn pad_to_dword(value: usize) -> usize {
    (value + 3) & !3usize
}

/// Round up to the next pointer-size boundary (8 bytes on x64).
fn pad_to_dword_ptr(value: usize) -> usize {
    (value + 7) & !7usize
}

/// Find free memory within 4 GiB of `base` and reserve `size` bytes there.
///
/// The import directory stores RVAs, so the new block must stay within the
/// image's 32-bit addressable range — exactly the constraint Detours'
/// `FindAndAllocateNearBase` enforces.
fn allocate_near_base(process: HANDLE, base: usize, size: usize) -> GuardResult<usize> {
    let mut cursor = base;
    loop {
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        // SAFETY: `info` is correctly sized and `process` is a live handle.
        let queried = unsafe {
            VirtualQueryEx(
                process,
                cursor as *const c_void,
                &mut info,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            return Err(Win32Error::last("VirtualQueryEx"));
        }

        let region_base = info.BaseAddress as usize;
        let region_size = info.RegionSize;
        if region_size == 0 {
            return Err(Win32Error::new("VirtualQueryEx returned an empty region", 0));
        }
        // An unaligned, all-ones region size marks the end of the address space.
        if region_size & 0xfff == 0xfff {
            return Err(Win32Error::new(
                "reached the end of the address space before finding a free region",
                0,
            ));
        }

        if info.State == MEM_FREE {
            let mut candidate = (region_base + 0xffff) & !0xffffusize;
            let region_end = region_base.saturating_add(region_size);
            while candidate < region_end {
                // RVAs are 32-bit: the block must stay within 4 GiB of the image.
                if candidate.wrapping_sub(base) > u32::MAX as usize {
                    return Err(Win32Error::new(
                        "no free region within 4 GiB of the image base",
                        0,
                    ));
                }
                // SAFETY: reserving and committing at an explicit address.
                let allocated = unsafe {
                    VirtualAllocEx(
                        process,
                        candidate as *const c_void,
                        size,
                        MEM_RESERVE | MEM_COMMIT,
                        PAGE_READWRITE,
                    )
                };
                if !allocated.is_null() {
                    return Ok(allocated as usize);
                }
                candidate += ALLOCATION_GRANULARITY;
            }
        }

        cursor = region_base.saturating_add(region_size);
    }
}

/// Rewrite `process`'s import directory so `dll_path` loads at startup.
///
/// Returns the address of the new import directory in the child.
pub(crate) fn inject_via_import_table(process: HANDLE, dll_path: &str) -> GuardResult<usize> {
    let module_base = image_base(process)?;

    let mut dos: DosHeader = unsafe { mem::zeroed() };
    read_memory(process, module_base, &mut dos)?;
    if dos.e_magic != 0x5a4d {
        return Err(Win32Error::new("target image has no MZ signature", 0));
    }

    let nt_address = module_base + dos.e_lfanew as usize;
    let mut signature: u32 = 0;
    read_memory(process, nt_address, &mut signature)?;
    if signature != 0x0000_4550 {
        return Err(Win32Error::new("target image has no PE signature", 0));
    }

    let file_header_address = nt_address + mem::size_of::<u32>();
    let mut file_header: FileHeader = unsafe { mem::zeroed() };
    read_memory(process, file_header_address, &mut file_header)?;

    let optional_address = file_header_address + FILE_HEADER_SIZE;
    let mut optional: OptionalHeader64 = unsafe { mem::zeroed() };
    read_memory(process, optional_address, &mut optional)?;
    if optional.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return Err(Win32Error::new(
            "only 64-bit PE images are supported by the import rewrite",
            0,
        ));
    }

    let import_directory = optional.data_directory[IMPORT_DIRECTORY_INDEX];
    let old_count = if import_directory.size == 0 {
        0
    } else {
        import_directory.size as usize / IMPORT_DESCRIPTOR_SIZE
    };

    // Layout: new descriptors, then the original descriptors, then the thunk
    // arrays, then the DLL name strings.
    let new_descriptor_bytes = IMPORT_DESCRIPTOR_SIZE;
    let old_descriptor_bytes = IMPORT_DESCRIPTOR_SIZE * old_count;
    let thunk_table_bytes = mem::size_of::<u64>() * 4;
    let name_bytes = pad_to_dword(dll_path.len() + 1);
    let descriptor_region = new_descriptor_bytes + old_descriptor_bytes;
    let thunk_offset = pad_to_dword_ptr(descriptor_region);
    let name_offset = thunk_offset + thunk_table_bytes;
    let total = name_offset + name_bytes;

    // Place the block after the image's mapped sections.
    let image_end = module_base
        .saturating_add(optional.size_of_code as usize)
        .saturating_add(optional.size_of_initialized_data as usize)
        .saturating_add(optional.size_of_uninitialized_data as usize);
    let near_base = image_end.max(module_base);
    let block_address = allocate_near_base(process, near_base, total)?;
    let block_rva = block_address - module_base;

    let mut block = vec![0u8; total];

    // The original import descriptors are preserved verbatim after ours.
    if old_count > 0 {
        let old_descriptors = module_base + import_directory.virtual_address as usize;
        let target = &mut block[new_descriptor_bytes..new_descriptor_bytes + old_descriptor_bytes];
        // SAFETY: `target` is `old_descriptor_bytes` long.
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                process,
                old_descriptors as *const c_void,
                target.as_mut_ptr().cast::<c_void>(),
                old_descriptor_bytes,
                &mut read,
            )
        };
        if ok == 0 || read != old_descriptor_bytes {
            return Err(Win32Error::last("ReadProcessMemory(old imports)"));
        }
    }

    // Our descriptor names the hook DLL by ordinal 1, matching what Detours
    // emits; the loader only needs *a* valid thunk for the module to load.
    let name_rva = block_rva + name_offset;
    let original_thunk_rva = block_rva + thunk_offset;
    let first_thunk_rva = block_rva + thunk_offset + mem::size_of::<u64>() * 2;

    let descriptor = ImportDescriptor {
        original_first_thunk: original_thunk_rva as u32,
        time_date_stamp: 0,
        forwarder_chain: 0,
        name: name_rva as u32,
        first_thunk: first_thunk_rva as u32,
    };
    block[..new_descriptor_bytes].copy_from_slice(as_bytes(&descriptor));

    // Both thunk arrays end in a null entry; `+2` selects the second pair.
    let ordinal_thunk = IMAGE_ORDINAL_FLAG64 | 1;
    block[thunk_offset..thunk_offset + 8].copy_from_slice(&ordinal_thunk.to_le_bytes());
    block[thunk_offset + 16..thunk_offset + 24].copy_from_slice(&ordinal_thunk.to_le_bytes());

    block[name_offset..name_offset + dll_path.len()].copy_from_slice(dll_path.as_bytes());

    write_memory(process, block_address, &block)?;

    // Repoint the optional header at our directory.
    let mut updated = optional;
    if updated.data_directory[IAT_DIRECTORY_INDEX].virtual_address == 0 {
        updated.data_directory[IAT_DIRECTORY_INDEX] = DataDirectory {
            virtual_address: block_rva as u32,
            size: total as u32,
        };
    }
    updated.data_directory[IMPORT_DIRECTORY_INDEX] = DataDirectory {
        virtual_address: block_rva as u32,
        size: total as u32,
    };
    updated.checksum = 0;

    // The headers are read-only in the mapping; make them writable in place.
    let mut previous_protection = 0u32;
    // SAFETY: the region covers the headers we are about to modify.
    let ok = unsafe {
        VirtualProtectEx(
            process,
            module_base as *const c_void,
            updated.size_of_headers as usize,
            PAGE_READWRITE_PROTECT,
            &mut previous_protection,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last("VirtualProtectEx(headers)"));
    }

    let write_result = write_memory(process, optional_address, as_bytes(&updated));

    let mut restored = 0u32;
    // SAFETY: restoring the original protection of the same region.
    unsafe {
        VirtualProtectEx(
            process,
            module_base as *const c_void,
            updated.size_of_headers as usize,
            previous_protection,
            &mut restored,
        );
    }
    write_result?;

    Ok(block_address)
}

/// Treat a `Copy` value as its raw bytes.
fn as_bytes<T: Copy>(value: &T) -> &[u8] {
    // SAFETY: `T` is `Copy` and has no padding-sensitive invariants we rely on.
    unsafe { core::slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>()) }
}

/// The base address of the image `process` is running.
fn image_base(process: HANDLE) -> GuardResult<usize> {
    // The main image is the first PE mapping in the process address space.
    let mut cursor = 0usize;
    loop {
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        // SAFETY: `info` is correctly sized.
        let queried = unsafe {
            VirtualQueryEx(
                process,
                cursor as *const c_void,
                &mut info,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            return Err(Win32Error::last("VirtualQueryEx(image base)"));
        }
        let region_base = info.BaseAddress as usize;
        let region_size = info.RegionSize;
        if region_size & 0xfff == 0xfff {
            return Err(Win32Error::new(
                "could not locate the main image in the child",
                0,
            ));
        }
        if is_pe_image(process, region_base) {
            return Ok(region_base);
        }
        cursor = region_base.saturating_add(region_size);
    }
}

/// Whether `address` begins a mapped PE image.
fn is_pe_image(process: HANDLE, address: usize) -> bool {
    let mut magic: u16 = 0;
    if read_memory(process, address, &mut magic).is_err() || magic != 0x5a4d {
        return false;
    }
    let mut e_lfanew: u32 = 0;
    if read_memory(process, address + 0x3c, &mut e_lfanew).is_err() {
        return false;
    }
    let mut signature: u32 = 0;
    if read_memory(process, address + e_lfanew as usize, &mut signature).is_err() {
        return false;
    }
    signature == 0x0000_4550
}

/// Keep the current-process helper referenced for future diagnostics.
pub fn current_process_image_base() -> GuardResult<usize> {
    // SAFETY: returns the calling process pseudo-handle.
    let process = unsafe { GetCurrentProcess() };
    image_base(process)
}

/// Keep `ptr` referenced where this module needs a raw pointer type.
#[allow(dead_code)]
fn _unused_ptr() -> *mut c_void {
    ptr::null_mut()
}

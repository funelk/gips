use std::{
    ffi, io,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

use windows::{
    core::{HSTRING, PCSTR, PCWSTR},
    Win32::{
        Foundation,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorA, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        System::{Memory, SystemInformation, Threading},
    },
};

use crate::{shm::Header, windows::handle::Handle};

#[derive(Debug, Default)]
pub struct OsShm {
    mapped: AtomicUsize,
    address: AtomicPtr<ffi::c_void>,
    handle: Foundation::HANDLE,
}

impl OsShm {
    #[inline]
    pub fn address(&self) -> *mut ffi::c_void {
        self.address.load(Ordering::Acquire)
    }
    #[inline]
    pub fn set_address(&self, addr: *mut ffi::c_void) {
        self.address.store(addr, Ordering::Release);
    }

    #[inline]
    pub fn mapped(&self) -> usize {
        self.mapped.load(Ordering::Acquire)
    }
    #[inline]
    pub fn set_mapped(&self, size: usize) {
        self.mapped.store(size, Ordering::Release);
    }
}

fn get_page_size() -> usize {
    unsafe {
        let mut system_info: SystemInformation::SYSTEM_INFO = std::mem::zeroed();
        SystemInformation::GetSystemInfo(&mut system_info);
        system_info.dwPageSize as usize
    }
}

fn align_to_page(size: usize) -> usize {
    let page = get_page_size();
    if page == 0 {
        return size.max(std::mem::size_of::<Header>());
    }

    let minimum = std::mem::size_of::<Header>();
    let mut size = size.max(minimum);
    let mask = page - 1;
    if size & mask == 0 {
        size
    } else {
        size = size.saturating_add(page - (size & mask));
        size
    }
}

impl OsShm {
    pub unsafe fn new<S: Into<String>>(name: S, size: usize, total: usize) -> io::Result<OsShm> {
        // let name: String = name.into();
        let raw_name: String = name.into();
        // Try Local namespace first (doesn't require admin privileges)
        // Falls back to Global if needed
        let name = if raw_name.starts_with("Global\\") || raw_name.starts_with("Local\\") {
            raw_name
        } else {
            format!("Local\\{}", raw_name)
        };
        let security_attributes = Self::global_security_attributes().map_err(|err| {
            io::Error::other(
                format!("Failed to get security attributes: {}", err),
            )
        })?;

        crate::debug!(
            "total_physical_memory: {total}, size: {size}, (total-size):{}",
            total - size,
        );
        let handle: Foundation::HANDLE = unsafe {
            Memory::CreateFileMappingW(
                Foundation::INVALID_HANDLE_VALUE,
                Some(&security_attributes),
                Memory::PAGE_READWRITE | Memory::SEC_RESERVE,
                ((total as u64) >> 32) as u32,
                ((total as u64) & 0xFFFFFFFF) as u32,
                PCWSTR::from_raw(HSTRING::from(&name).as_ptr()),
            )
        }
        .map_err(|err| {
            io::Error::other(
                format!("Failed to create file mapping '{}': {}", name, err),
            )
        })?;

        let shm = OsShm {
            handle,
            ..Default::default()
        };
        unsafe { shm.remap(size)? };

        Ok(shm)
    }

    pub unsafe fn open(name: &str, size: usize) -> io::Result<OsShm> {
        // let name: String = name.into();
        // Try Local namespace first (doesn't require admin privileges)
        let name = if name.starts_with("Global\\") || name.starts_with("Local\\") {
            name.to_string()
        } else {
            format!("Local\\{name}")
        };

        let handle: Foundation::HANDLE = unsafe {
            Memory::OpenFileMappingW(
                Memory::FILE_MAP_ALL_ACCESS.0,
                false,
                PCWSTR::from_raw(HSTRING::from(name.clone()).as_ptr()),
            )
        }
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to open file mapping '{}': {}", name, err),
            )
        })?;

        let shm = OsShm {
            handle,
            ..Default::default()
        };
        unsafe { shm.remap(size)? };

        Ok(shm)
    }

    pub unsafe fn new_anonymous(size: usize, total: usize) -> io::Result<OsShm> {
        let security_attributes = Self::global_security_attributes().map_err(|err| {
            io::Error::other(
                format!("Failed to get security attributes: {}", err),
            )
        })?;

        let handle: Foundation::HANDLE = unsafe {
            Memory::CreateFileMappingW(
                Foundation::INVALID_HANDLE_VALUE,
                Some(&security_attributes),
                Memory::PAGE_READWRITE | Memory::SEC_RESERVE,
                ((total as u64) >> 32) as u32,
                ((total as u64) & 0xFFFFFFFF) as u32,
                PCWSTR::null(),
            )
        }
        .map_err(|err| {
            io::Error::other(
                format!("Failed to create anonymous file mapping: {}", err),
            )
        })?;

        let shm = OsShm {
            handle,
            ..Default::default()
        };
        unsafe { shm.remap(size)? };

        Ok(shm)
    }

    /// Remap the memory region to align the range size to the capacity (defined in Header), if not specify the `size` parameter,
    /// that maybe changed by other mapping instance with `resize` method
    pub unsafe fn remap(&self, size: usize) -> io::Result<Memory::MEMORY_MAPPED_VIEW_ADDRESS> {
        let length = align_to_page(size);
        let address = self.address();
        if !address.is_null() {
            let addr = Memory::MEMORY_MAPPED_VIEW_ADDRESS { Value: address };
            unsafe { Memory::UnmapViewOfFile(addr) }.map_err(|err| {
                io::Error::other(
                    format!("Failed to unmap view: {}", err),
                )
            })?;
        }

        let addr = unsafe {
            Memory::MapViewOfFile(
                self.handle, //
                Memory::FILE_MAP_ALL_ACCESS,
                0,
                0,
                length,
            )
        };
        if addr.Value.is_null() {
            unsafe { Foundation::GetLastError() }
                .ok()
                .map_err(|err| {
                    io::Error::other(
                        format!("Failed to map view of file (size {}): {}", length, err),
                    )
                })?;
        }

        let address = unsafe {
            Memory::VirtualAlloc(
                Some(addr.Value),
                length,
                Memory::MEM_COMMIT,
                Memory::PAGE_READWRITE,
            )
        };
        if address.is_null() {
            unsafe { Foundation::GetLastError() }
                .ok()
                .map_err(|err| {
                    io::Error::other(
                        format!("Failed to commit virtual memory (size {}): {}", length, err),
                    )
                })?;
        }
        debug_assert_eq!(address, addr.Value);

        self.set_address(address);
        self.set_mapped(length);

        Ok(addr)
    }

    pub unsafe fn close(&self) -> io::Result<()> {
        let address = self.address();
        #[cfg(feature = "verbose")]
        crate::info!(
            "Try to close shared memory, address: {address:?}/{}, at {:?}",
            address.is_null(),
            std::backtrace::Backtrace::force_capture()
        );
        if !address.is_null() {
            let addr = Memory::MEMORY_MAPPED_VIEW_ADDRESS { Value: address };
            unsafe { Memory::UnmapViewOfFile(addr) }.map_err(|err| {
                io::Error::other(
                    format!("Failed to unmap view on close: {}", err),
                )
            })?;
        }

        if !self.handle.is_invalid() {
            unsafe { Foundation::CloseHandle(self.handle) }.map_err(|err| {
                io::Error::other(
                    format!("Failed to close handle: {}", err),
                )
            })?;
        }
        Ok(())
    }
}

impl OsShm {
    /**
     * `D`: DACL
     * `P`: DACL flags
     * `OICI`: SDDL_OBJECT_INHERIT|SDDL_CONTAINER_INHERIT
     * `GA`: SDDL_GENERIC_ALL
     * `SY`: System
     * `BA`: Administrators
     * `IU`: Interactive Users
     */
    const GLOBAL_SHARE_SSDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GR;;;IU)";

    fn global_security_attributes() -> Result<SECURITY_ATTRIBUTES, ::windows::core::Error> {
        let ssdl = std::ffi::CString::new(Self::GLOBAL_SHARE_SSDL).expect("Invalid SSDL");
        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorA(
                PCSTR(ssdl.as_ptr().cast()),
                SDDL_REVISION_1,
                &mut security_descriptor,
                None,
            )?
        };
        Ok(SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security_descriptor.0,
            bInheritHandle: Foundation::FALSE,
        })
    }
}

impl TryFrom<Handle> for OsShm {
    type Error = io::Error;
    fn try_from(handle: Handle) -> io::Result<Self> {
        let foundation = handle.into_foundation_handle();
        let shm = OsShm {
            handle: foundation,
            mapped: AtomicUsize::new(0),
            address: AtomicPtr::new(std::ptr::null_mut()),
        };
        // Start with just enough space to read the header
        // The actual capacity will be remapped later based on the header content
        let initial = std::mem::size_of::<Header>();
        unsafe { shm.remap(initial)? };
        Ok(shm)
    }
}

impl TryFrom<&OsShm> for Handle {
    type Error = io::Error;
    fn try_from(shm: &OsShm) -> Result<Self, Self::Error> {
        let mut duplicated = Foundation::HANDLE::default();
        unsafe {
            Foundation::DuplicateHandle(
                Threading::GetCurrentProcess(),
                shm.handle,
                Threading::GetCurrentProcess(),
                &mut duplicated,
                0,
                false,
                Foundation::DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(|err| {
            io::Error::other(
                format!("Failed to duplicate handle: {}", err),
            )
        })?;

        Handle::try_from(duplicated).map_err(|err| {
            io::Error::other(
                format!("Failed to convert to Handle: {}", err),
            )
        })
    }
}

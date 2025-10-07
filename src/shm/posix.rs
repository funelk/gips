use std::{
    ffi,
    ffi::CString,
    io, mem,
    os::fd::{IntoRawFd, OwnedFd, RawFd},
    ptr,
    str::FromStr,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

use crate::{errno::Errno, shm::Header};

use super::Result;

#[derive(Debug)]
pub(super) enum Backing {
    Posix {
        fd: RawFd,
        path: Option<CString>,
    },
    #[cfg(target_os = "macos")]
    Mach {
        port: crate::mach::Port,
    },
}

#[derive(Debug)]
pub struct OsShm {
    backing: Backing,
    mapped: AtomicUsize,
    address: AtomicPtr<ffi::c_void>,
}

impl OsShm {
    #[inline]
    pub(super) fn with_backing(backing: Backing) -> Self {
        Self {
            backing,
            mapped: AtomicUsize::new(0),
            address: AtomicPtr::new(ptr::null_mut()),
        }
    }

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

impl OsShm {
    pub unsafe fn new<S: AsRef<str>>(name: S, size: usize, total: usize) -> Result<OsShm> {
        unsafe {
            debug_assert!(name.as_ref().len() < libc::PATH_MAX as usize);
            let path = CString::from_str(name.as_ref())?;
            let name_ptr = path.as_c_str().as_ptr();

            let ret = libc::shm_unlink(name_ptr);
            if let Err(err) = Errno::result(ret)
                && err.ne(&libc::ENOENT)
            {
                return Err(io::Error::other(format!(
                    "unlink shm {:?}: {}",
                    path,
                    io::Error::from(err)
                )));
            }

            let fd = libc::shm_open(name_ptr, libc::O_CREAT | libc::O_RDWR, 0o755);
            if let Err(err) = Errno::result(fd) {
                return Err(io::Error::other(format!(
                    "open shm {:?}: {}",
                    path,
                    io::Error::from(err)
                )));
            }

            let ret = libc::ftruncate(fd, total as _);
            Errno::result(ret).map_err(|err| {
                io::Error::other(format!(
                    "truncate fd with size {}: {}",
                    total,
                    io::Error::from(err)
                ))
            })?;

            let shm = OsShm::with_backing(Backing::Posix {
                fd,
                path: Some(path),
            });
            shm.remap(size)?;

            Ok(shm)
        }
    }

    pub unsafe fn open<S: AsRef<str>>(name: S, size: usize) -> Result<OsShm> {
        unsafe {
            let path = CString::from_str(name.as_ref())?;
            let fd = libc::shm_open(path.as_ptr(), libc::O_RDWR, 0o755);
            if let Err(err) = Errno::result(fd) {
                return Err(io::Error::other(format!(
                    "open shm {:?}: {}",
                    path,
                    io::Error::from(err)
                )));
            }

            let shm = OsShm::with_backing(Backing::Posix {
                fd,
                path: Some(path),
            });
            shm.remap(size)?;

            Ok(shm)
        }
    }

    pub unsafe fn truncate(&self, size: usize) -> Result<()> {
        unsafe {
            match &self.backing {
                Backing::Posix { fd, .. } => {
                    let ret = libc::ftruncate(*fd, size as _);
                    Errno::result(ret).map_err(|err| {
                        io::Error::other(format!(
                            "truncate fd with size {}: {}",
                            size,
                            io::Error::from(err)
                        ))
                    })?;
                    Ok(())
                }
                // Mach memory entries have fixed size set at creation
                #[cfg(target_os = "macos")]
                Backing::Mach { .. } => Ok(()),
            }
        }
    }

    pub unsafe fn remap(&self, size: usize) -> Result<*mut ffi::c_void> {
        match &self.backing {
            Backing::Posix { fd, .. } => {
                // Unmap the old mapping if it exists
                let old_mapped = self.mapped();
                let old_address = self.address();
                if old_mapped != 0 && !old_address.is_null() {
                    let ret = unsafe { libc::munmap(old_address, old_mapped) };
                    if let Err(err) = Errno::result(ret) {
                        return Err(io::Error::other(format!(
                            "memory unmap with fd {} failed: {}",
                            *fd,
                            io::Error::from(err)
                        )));
                    }
                }

                // Create new mapping
                let address = unsafe {
                    libc::mmap(
                        ptr::null_mut(),
                        size,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        *fd,
                        0,
                    )
                };
                if address == libc::MAP_FAILED {
                    return Err(io::Error::other(format!(
                        "memory map with fd {} and size {} failed: {}",
                        *fd,
                        size,
                        io::Error::from(Errno::last())
                    )));
                }
                self.set_address(address);
                self.set_mapped(size);
                Ok(address)
            }
            #[cfg(target_os = "macos")]
            Backing::Mach { port } => self.remap_mach_memory_entry(size, port),
        }
    }

    pub unsafe fn close(&self) -> Result<()> {
        unsafe {
            match &self.backing {
                Backing::Posix { fd, path } => {
                    if self.mapped() != 0 && !self.address().is_null() {
                        let ret = libc::munmap(self.address(), self.mapped());
                        Errno::result(ret).map_err(|err| {
                            io::Error::other(format!(
                                "memory unmap with fd {} failed: {}",
                                *fd,
                                io::Error::from(err)
                            ))
                        })?;
                    }

                    let ret = libc::close(*fd);
                    Errno::result(ret).map_err(|err| {
                        io::Error::other(format!(
                            "close fd {} failed: {}",
                            *fd,
                            io::Error::from(err)
                        ))
                    })?;

                    if let Some(path) = path {
                        let ret = libc::shm_unlink(path.as_ptr());
                        Errno::result(ret).map_err(|err| {
                            io::Error::other(format!(
                                "unlink shm {:?}: {}",
                                path,
                                io::Error::from(err)
                            ))
                        })?;
                    }
                    Ok(())
                }
                #[cfg(target_os = "macos")]
                Backing::Mach { .. } => self.close_mach_memory_entry(),
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub unsafe fn new_anonymous(size: usize, total: usize) -> Result<OsShm> {
        unsafe {
            let path = unique_anonymous_shm_path()?;
            let fd = libc::shm_open(
                path.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
                0o600,
            );
            if let Err(err) = Errno::result(fd) {
                return Err(io::Error::other(
                    format!("open shm {:?}: {}", path, io::Error::from(err)),
                ));
            }

            let ret = libc::ftruncate(fd, total as _);
            Errno::result(ret).map_err(|err| {
                io::Error::other(
                    format!("truncate fd with size {}: {}", total, io::Error::from(err)),
                )
            })?;

            let ret = libc::shm_unlink(path.as_ptr());
            Errno::result(ret).map_err(|err| {
                io::Error::other(
                    format!("unlink shm {:?}: {}", path, io::Error::from(err)),
                )
            })?;

            let shm = OsShm::with_backing(Backing::Posix { fd, path: None });
            shm.remap(size)?;
            Ok(shm)
        }
    }
}

impl TryFrom<OwnedFd> for OsShm {
    type Error = io::Error;
    fn try_from(fd: OwnedFd) -> Result<Self> {
        let raw_fd = fd.into_raw_fd();
        let shm = OsShm::with_backing(Backing::Posix {
            fd: raw_fd,
            path: None,
        });

        let length = file_size(raw_fd)?;
        let map_len = if length <= 0 {
            mem::size_of::<Header>()
        } else {
            length as usize
        };
        unsafe { shm.remap(map_len)? };
        Ok(shm)
    }
}

impl TryFrom<&OsShm> for OwnedFd {
    type Error = io::Error;
    fn try_from(shm: &OsShm) -> Result<Self> {
        use std::os::fd::FromRawFd;

        match &shm.backing {
            Backing::Posix { fd, .. } => unsafe {
                let dup = libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 0);
                match Errno::result(dup) {
                    Ok(raw) => Ok(OwnedFd::from_raw_fd(raw)),
                    Err(err) => Err(io::Error::other(format!(
                        "duplicating fd failed: {}",
                        io::Error::from(err)
                    ))),
                }
            },
            #[cfg(target_os = "macos")]
            Backing::Mach { port: _ } => todo!(),
        }
    }
}

fn file_size(fd: RawFd) -> Result<i64> {
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    let ret = unsafe { libc::fstat(fd, &mut stat) };
    Errno::result(ret).map_err(|err| {
        io::Error::other(format!(
            "querying fd metadata failed: {}",
            io::Error::from(err)
        ))
    })?;
    Ok(stat.st_size)
}

#[cfg(not(target_os = "macos"))]
fn unique_anonymous_shm_path() -> Result<CString> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(1);
    for _ in 0..32 {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = format!("/gips-anonymous-{}-{id}", std::process::id());
        if let Ok(path) = CString::new(candidate) {
            return Ok(path);
        }
    }
    Err(io::Error::other(
        "failed to create unnamed shared memory segment",
    ))
}

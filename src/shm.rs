#[cfg(any(target_os = "linux", target_os = "macos"))]
mod posix;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use posix::*;

#[cfg(target_os = "macos")]
mod mach;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::*;

use std::{
    borrow::Cow,
    ffi, io, mem, ops, ptr, result, slice,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::ipc::Object;

pub type Result<T, E = io::Error> = result::Result<T, E>;

pub struct Shm {
    name: Option<String>,
    inner: OsShm,
}

pub trait IntoOptionalString {
    fn into_optional_string(self) -> Option<String>;
}
impl IntoOptionalString for &str {
    fn into_optional_string(self) -> Option<String> {
        Some(self.to_string())
    }
}
impl IntoOptionalString for &String {
    fn into_optional_string(self) -> Option<String> {
        Some(self.clone())
    }
}
impl IntoOptionalString for String {
    fn into_optional_string(self) -> Option<String> {
        Some(self)
    }
}
impl IntoOptionalString for Option<String> {
    fn into_optional_string(self) -> Option<String> {
        self
    }
}
impl IntoOptionalString for Option<&str> {
    fn into_optional_string(self) -> Option<String> {
        self.map(|s| s.to_string())
    }
}

impl IntoOptionalString for Option<&String> {
    fn into_optional_string(self) -> Option<String> {
        self.cloned()
    }
}
impl IntoOptionalString for Cow<'_, str> {
    fn into_optional_string(self) -> Option<String> {
        Some(self.into_owned())
    }
}
impl IntoOptionalString for Option<Cow<'_, str>> {
    fn into_optional_string(self) -> Option<String> {
        self.map(|s| s.into_owned())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub mapped: usize,
    pub capacity: usize,
}
impl From<usize> for Size {
    fn from(value: usize) -> Self {
        Self {
            mapped: value,
            capacity: value,
        }
    }
}

impl Shm {
    pub fn new<N: IntoOptionalString, S: Into<Size>>(name: N, size: S) -> Result<Shm> {
        let name = name.into_optional_string();
        let Size {
            mapped: size,
            capacity: total,
        } = size.into();
        let inner = unsafe {
            match &name {
                Some(n) => OsShm::new(n, size, total)?,
                None => OsShm::new_anonymous(size, total)?,
            }
        };

        unsafe {
            inner.address().cast::<Header>().write(Header {
                capacity: AtomicUsize::new(size),
                total: AtomicUsize::new(total),
                ..Default::default()
            });
        }

        Ok(Shm { name, inner })
    }

    /**
     * If size parameter is 0 (zero), will open the whole shared memory region
     * (means the mapping extends to the end of the file mapping).
     */
    pub fn open<N: IntoOptionalString>(name: N, size: usize) -> Result<Shm> {
        let should_remap = size == 0;

        let name = name.into_optional_string().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "shared memory name is required for open",
            )
        })?; // Opening requires a name
        let inner = unsafe {
            let size = if should_remap { 0 } else { size };
            OsShm::open(&name, Header::span(size))?
        };

        let header = unsafe { &*(inner.address().cast::<Header>()) };
        if header.invalid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "shared memory is damaged",
            ))?;
        }
        if should_remap {
            unsafe { inner.remap(header.allocated())? };
        }

        Ok(Shm {
            name: Some(name),
            inner,
        })
    }

    pub fn resize(&self, size: usize) -> Result<usize> {
        if size <= self.capacity() {
            return Ok(self.capacity());
        }

        let current_total = self.total();

        // Check if the requested size exceeds the allocated total
        if size > current_total {
            // On some platforms (e.g., macOS with POSIX shm), we cannot grow beyond
            // the initially allocated size. Return error in this case.
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!(
                    "acquired size ({}) exceeds memory limit ({})",
                    size, current_total
                ),
            ));
        }

        // Remap the memory to the new size (within the allocated total)
        unsafe { self.inner.remap(Header::span(size))? };

        // Update the capacity in the header
        self.header().set_capacity(size);

        Ok(size)
    }

    /// Remap the memory region to align the range size to the capacity (defined in Header), if not specify the `size` parameter,
    /// that maybe changed by other mapping instance with `resize` m
    pub fn remap(&self) -> Result<()> {
        let capacity = self.capacity();
        let mapped = self.mapped();
        let aligned_capacity = Header::span(capacity);
        if aligned_capacity == mapped {
            return Ok(());
        }

        let size = aligned_capacity.max(mapped);
        debug_assert!(size <= self.total());
        unsafe { self.inner.remap(size)? };

        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        unsafe { self.inner.close() }
    }
}

impl TryFrom<Object> for Shm {
    type Error = io::Error;

    fn try_from(object: Object) -> Result<Self> {
        #[allow(clippy::infallible_destructuring_match)]
        let inner = OsShm::try_from(match object {
            #[cfg(target_os = "macos")]
            Object::Port(port) => port,
            #[cfg(target_os = "macos")]
            Object::Ool(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OOL not supported",
                ));
            }
            #[cfg(windows)]
            Object::Handle(handle) => handle,
            #[cfg(target_os = "linux")]
            Object::Fd(fd) => fd,
        })?;

        let header = unsafe { &*(inner.address().cast::<Header>()) };
        if header.invalid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "shared memory is damaged",
            ));
        }

        unsafe { inner.remap(header.allocated())? };

        Ok(Shm { name: None, inner })
    }
}

impl TryFrom<&Shm> for Object {
    type Error = io::Error;

    fn try_from(shm: &Shm) -> Result<Self> {
        let Shm { inner, .. } = shm;

        #[cfg(windows)]
        {
            Ok(Object::Handle(inner.try_into()?))
        }
        #[cfg(target_os = "macos")]
        {
            Ok(Object::Port(inner.try_into()?))
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::OwnedFd;
            Ok(Object::Fd(OwnedFd::try_from(inner)?))
        }
    }
}

/**
 * The mapped shared memory regions has the following layout:
 * | Header Region         (header)|
 * | Extension Region   (extension)|
 * | Data Region          (address)|
 */
#[repr(C, align(8))]
#[derive(Debug, Default)]
pub struct Header {
    pub capacity: AtomicUsize,
    pub total: AtomicUsize,
    pub extension: u8, // reserved fields for future extension (default 0)
    barrier: u8,       // should always be 0 (zero)
}
impl Header {
    #[inline]
    pub fn invalid(&self) -> bool {
        self.barrier != 0
    }

    pub fn total(&self) -> usize {
        self.total.load(Ordering::Acquire)
    }
    pub fn set_total(&self, size: usize) {
        self.total.store(size, Ordering::Release);
    }
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
    }
    pub fn set_capacity(&self, size: usize) {
        self.capacity.store(size, Ordering::Release);
    }

    pub fn allocated(&self) -> usize {
        Header::span(self.capacity())
    }

    #[inline]
    pub fn span(size: usize) -> usize {
        mem::size_of::<Header>() + size
    }
}

impl Shm {
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[inline]
    pub fn header(&self) -> &Header {
        unsafe { self.inner.address().cast::<Header>().as_ref().unwrap() }
    }

    #[inline]
    pub fn mapped(&self) -> usize {
        self.inner.mapped()
    }

    /// Returns a raw pointer to the mapping (include Header)
    #[inline]
    pub fn address(&self) -> *mut ffi::c_void {
        cfg_if::cfg_if! {
            if #[cfg(any(unix, windows))] {
                self.inner.address()
            } else {
                compile_error!("Shm isn't supported on the platform but unix or windows yet")
            }
        }
    }
}

impl Shm {
    #[inline]
    fn data(&self) -> *mut u8 {
        unsafe { self.address().cast::<Header>().add(1).cast() }
    }
    #[inline]
    fn len(&self) -> usize {
        self.header().capacity()
    }
}

impl AsRef<[u8]> for Shm {
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.data(), self.len()) }
    }
}
impl AsMut<[u8]> for Shm {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.data(), self.len()) }
    }
}

impl ops::Deref for Shm {
    type Target = Header;
    fn deref(&self) -> &Self::Target {
        self.header()
    }
}
unsafe impl Send for Shm {}
unsafe impl Sync for Shm {}

pub struct OwnedShm(pub Shm);
impl ops::Deref for OwnedShm {
    type Target = Shm;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ops::DerefMut for OwnedShm {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for OwnedShm {
    fn drop(&mut self) {
        if let Err(err) = self.close() {
            crate::warn!("Close Shm {:?} failed: {err:?}", self.name())
        }
    }
}

impl Shm {
    /// Write a buffer into the shared memory, returning how many bytes were successfully written.
    ///
    /// This function will attempt to write the entire contents of buf, but the entire write might not succeed
    /// (typically means the shared memory space is not enough).
    pub fn write(&self, buf: &[u8], offset: usize) -> usize {
        let capacity = self.capacity();
        if offset >= capacity {
            return 0;
        }

        let max_write = capacity - offset;
        let write_len = buf.len().min(max_write);

        unsafe {
            let src_ptr = buf.as_ptr();
            let dst_ptr = self.data().add(offset);
            ptr::copy_nonoverlapping(src_ptr, dst_ptr, write_len);
        }
        write_len
    }
}

impl Shm {
    /// Default read to end, if `size` argument is `None`.
    pub fn read(&self, offset: usize, size: Option<usize>) -> &[u8] {
        let data = unsafe { slice::from_raw_parts(self.data(), self.len()) };
        if offset >= data.len() {
            return &data[0..0];
        }

        let available = data.len() - offset;
        let bytes = size.map_or(available, |requested| requested.min(available));
        &data[offset..offset + bytes]
    }
}

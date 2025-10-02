use std::{
    mem, ops,
    os::windows::{
        io::IntoRawHandle,
        prelude::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
};

use windows::Win32::{
    Foundation,
    Storage::FileSystem,
    System::{IO, Pipes},
};

use super::overlapped::Overlapped;

#[derive(Debug)]
#[repr(transparent)]
pub struct Handle(pub OwnedHandle);

impl Handle {
    /// Duplicates the underlying handle.
    pub fn duplicate(&self) -> std::io::Result<Handle> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Threading::GetCurrentProcess;
        let mut new_handle = HANDLE::default();
        unsafe {
            Foundation::DuplicateHandle(
                GetCurrentProcess(),
                self.as_foundation_handle(),
                GetCurrentProcess(),
                &mut new_handle as *mut HANDLE,
                0,
                false,
                Foundation::DUPLICATE_SAME_ACCESS,
            )?
        };
        Ok(Handle::try_from(new_handle).unwrap())
    }
    #[inline]
    pub fn into_foundation_handle(self) -> Foundation::HANDLE {
        let this = mem::ManuallyDrop::new(self);
        Foundation::HANDLE(this.as_raw_handle() as _)
    }
    #[inline]
    pub fn as_foundation_handle(&self) -> Foundation::HANDLE {
        Foundation::HANDLE(self.as_raw_handle() as _)
    }
}

impl Handle {
    pub fn peek_named_pipe(
        &self,
        buffer: Option<&mut [u8]>,
        bytes_read: Option<&mut u32>,
        total_available: Option<&mut u32>,
        bytes_left_this_message: Option<&mut u32>,
    ) -> Result<(), ::windows::core::Error> {
        let buffer_size = buffer.as_ref().map_or(0, |v| v.len() as u32);
        unsafe {
            Pipes::PeekNamedPipe(
                self.as_foundation_handle(),
                buffer.map(|b| b.as_mut_ptr().cast()),
                buffer_size,
                bytes_read.map(|v| v as *mut _),
                total_available.map(|v| v as *mut _),
                bytes_left_this_message.map(|v| v as *mut _),
            )
        }
    }
}

/// There are some methods for a handle to the device
/// (for example, a file, file stream, physical disk, volume, console buffer, tape drive, socket, communications resource, mailslot, or pipe).
impl Handle {
    /// Calls the `GetOverlappedResult` function to get the result of an
    /// overlapped operation for this handle.
    ///
    /// This function takes the `OVERLAPPED` argument which must have been used
    /// to initiate an overlapped I/O operation, and returns either the
    /// successful number of bytes transferred during the operation or an error
    /// if one occurred.
    ///
    /// # Panics
    ///
    /// This function will panic
    pub fn get_overlapped_result(
        &self,
        overlapped: &Overlapped,
        wait: bool,
    ) -> Result<usize, ::windows::core::Error> {
        let mut transferred = 0;
        let result = unsafe {
            IO::GetOverlappedResult(
                self.as_foundation_handle(),
                overlapped as *const Overlapped as _,
                &mut transferred,
                wait,
            )
        };

        match result {
            Ok(_) => Ok(transferred as usize),
            Err(err) => {
                // For pipe operations, check if we got data before the error
                // ERROR_BROKEN_PIPE and ERROR_MORE_DATA can occur after successful data transfer
                if transferred > 0 {
                    use windows::Win32::Foundation::{
                        ERROR_BROKEN_PIPE, ERROR_MORE_DATA, WIN32_ERROR,
                    };
                    if let Some(code) = WIN32_ERROR::from_error(&err)
                        && (code == ERROR_BROKEN_PIPE || code == ERROR_MORE_DATA)
                    {
                        return Ok(transferred as usize);
                    }
                }
                Err(err)
            }
        }
    }

    /// Flushes the buffers of a specified file and causes all buffered data to be written to a file.
    pub fn flush(&self) -> Result<(), ::windows::core::Error> {
        unsafe { FileSystem::FlushFileBuffers(self.as_foundation_handle()) }
    }

    /// Reads data from the specified file or input/output (I/O) device.
    /// Reads occur at the position specified by the file pointer if supported by the device.
    pub fn read(&self, buffer: &mut [u8]) -> Result<usize, ::windows::core::Error> {
        unsafe { self.read_unchecked(buffer, None) }
    }

    /// Reads data from the specified file or input/output (I/O) device.
    /// Reads occur at the position specified by the file pointer if supported by the device.
    pub fn read_overlapped(
        &self,
        buffer: &mut [u8],
        overlapped: Option<*mut Overlapped>,
    ) -> Result<usize, ::windows::core::Error> {
        unsafe { self.read_unchecked(buffer, overlapped) }
    }

    /// Marks any outstanding I/O operations for the specified file handle. The function only cancels I/O operations in the current process, regardless of which thread created the I/O operation.
    pub fn cancel_io(
        &self,
        overlapped: Option<*const Overlapped>,
    ) -> Result<(), ::windows::core::Error> {
        unsafe { IO::CancelIoEx(self.as_foundation_handle(), mem::transmute(overlapped)) }
    }

    /// Reads data from the specified file or input/output (I/O) device.
    /// Reads occur at the position specified by the file pointer if supported by the device.
    ///
    /// This function is designed for both synchronous and asynchronous operations.
    /// For a similar function designed solely for asynchronous operation, see ReadFileEx.
    ///
    /// # Safety
    ///
    /// This function is unsafe because the kernel requires that the
    /// `overlapped` pointer is valid until the end of the I/O operation. The
    /// kernel also requires that `overlapped` is unique for this I/O operation
    /// and is not in use for any other I/O.
    ///
    /// To safely use this function callers must ensure that this pointer is
    /// valid until the I/O operation is completed, typically via completion
    /// ports and waiting to receive the completion notification on the port.
    pub unsafe fn read_unchecked(
        &self,
        buffer: &mut [u8],
        overlapped: Option<*mut Overlapped>,
    ) -> Result<usize, ::windows::core::Error> {
        let mut bytes = 0;
        unsafe {
            FileSystem::ReadFile(
                self.as_foundation_handle(),
                Some(buffer),
                Some(&mut bytes),
                mem::transmute(overlapped),
            )?
        };
        Ok(bytes as usize)
    }

    /// Writes data to the specified file or input/output (I/O) device.
    ///
    /// This function is designed for both synchronous and asynchronous operation.
    /// For a similar function designed solely for asynchronous operation, see WriteFileEx.
    pub fn write(&self, buffer: &[u8]) -> Result<usize, ::windows::core::Error> {
        unsafe { self.write_unchecked(buffer, None) }
    }

    /// Writes data to the specified file or input/output (I/O) device.
    ///
    /// This function is designed for both synchronous and asynchronous operation.
    /// For a similar function designed solely for asynchronous operation, see WriteFileEx.
    ///
    /// # Safety
    ///
    /// This function is unsafe because the kernel requires that the
    /// `overlapped` pointer is valid until the end of the I/O operation. The
    /// kernel also requires that `overlapped` is unique for this I/O operation
    /// and is not in use for any other I/O.
    ///
    /// To safely use this function callers must ensure that this pointer is
    /// valid until the I/O operation is completed, typically via completion
    /// ports and waiting to receive the completion notification on the port.
    pub unsafe fn write_unchecked(
        &self,
        buffer: &[u8],
        overlapped: Option<*mut Overlapped>,
    ) -> Result<usize, ::windows::core::Error> {
        let mut bytes = 0;
        unsafe {
            FileSystem::WriteFile(
                self.as_foundation_handle(),
                Some(buffer),     // buffer to write from
                Some(&mut bytes), // number of bytes written
                mem::transmute(overlapped),
            )?
        };
        Ok(bytes as usize)
    }

    /// # Safety
    ///
    /// This function is unsafe because the kernel requires that the
    /// `overlapped` pointer is valid until the end of the I/O operation. The
    /// kernel also requires that `overlapped` is unique for this I/O operation
    /// and is not in use for any other I/O.
    ///
    /// To safely use this function callers must ensure that this pointer is
    /// valid until the I/O operation is completed, typically via completion
    /// ports and waiting to receive the completion notification on the port.
    pub fn read_with_overlapped_result(
        &self,
        buffer: &mut [u8],
        overlapped: &mut Overlapped,
        wait: bool,
    ) -> Result<usize, ::windows::core::Error> {
        match unsafe { self.read_unchecked(buffer, Some(overlapped)) } {
            Ok(_) => (),
            Err(ref err)
                if Foundation::WIN32_ERROR::from_error(err)
                    .is_some_and(|e| e == Foundation::ERROR_IO_PENDING) => {}
            Err(e) => return Err(e),
        }

        match self.get_overlapped_result(overlapped, wait) {
            Ok(bytes) => Ok(bytes),
            Err(ref err)
                if Foundation::WIN32_ERROR::from_error(err)
                    .is_some_and(|e| e == Foundation::ERROR_IO_INCOMPLETE) =>
            {
                unreachable!("logic error")
            }
            Err(e) => Err(e),
        }
    }

    /// # Safety
    ///
    /// This function is unsafe because the kernel requires that the
    /// `overlapped` pointer is valid until the end of the I/O operation. The
    /// kernel also requires that `overlapped` is unique for this I/O operation
    /// and is not in use for any other I/O.
    ///
    /// To safely use this function callers must ensure that this pointer is
    /// valid until the I/O operation is completed, typically via completion
    /// ports and waiting to receive the completion notification on the port.
    pub fn write_with_overlapped_result(
        &self,
        buffer: &[u8],
        overlapped: &mut Overlapped,
        wait: bool,
    ) -> Result<usize, ::windows::core::Error> {
        match unsafe { self.write_unchecked(buffer, Some(overlapped)) } {
            Ok(_) => (),
            Err(ref err)
                if Foundation::WIN32_ERROR::from_error(err)
                    .is_some_and(|e| e == Foundation::ERROR_IO_PENDING) => {}
            Err(e) => return Err(e),
        }

        match self.get_overlapped_result(overlapped, wait) {
            Ok(bytes) => Ok(bytes),
            Err(ref err)
                if Foundation::WIN32_ERROR::from_error(err)
                    .is_some_and(|e| e == Foundation::ERROR_IO_INCOMPLETE) =>
            {
                unreachable!("logic error")
            }
            Err(e) => Err(e),
        }
    }
}

impl ops::Deref for Handle {
    type Target = OwnedHandle;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRawHandle for Handle {
    #[inline]
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        unsafe { Handle(OwnedHandle::from_raw_handle(handle)) }
    }
}

impl AsRawHandle for Handle {
    #[inline]
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_handle()
    }
}
impl IntoRawHandle for Handle {
    #[inline]
    fn into_raw_handle(self) -> RawHandle {
        self.0.into_raw_handle()
    }
}

impl TryFrom<Foundation::HANDLE> for Handle {
    type Error = ::windows::core::Error;
    fn try_from(value: Foundation::HANDLE) -> Result<Self, Self::Error> {
        if value.is_invalid() {
            return Err(windows::core::Error::from(std::io::Error::last_os_error()));
        }
        Ok(unsafe { Handle::from_raw_handle(value.0) })
    }
}

impl PartialEq for Handle {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_raw_handle() == other.0.as_raw_handle()
    }
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl std::io::Read for Handle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(Self::read(self, buf)?)
    }
}
impl std::io::Write for Handle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(Self::write(self, buf)?)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(Self::flush(self)?)
    }
}

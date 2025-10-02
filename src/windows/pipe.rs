use std::{ffi::OsStr, io, marker::PhantomData, mem, ops::Deref, os::windows::ffi::OsStrExt, time};
use windows::{
    Win32::{
        Foundation,
        Foundation::WIN32_ERROR,
        Storage::FileSystem,
        System::{Pipes, Threading},
    },
    core::{HSTRING, PCWSTR},
};

use super::{handle::Handle, overlapped::Overlapped};

pub struct AnonymousPipe<Mode = ()> {
    handle: Handle,
    mode: PhantomData<Mode>,
}

impl<T> TryFrom<Foundation::HANDLE> for AnonymousPipe<T> {
    type Error = ::windows::core::Error;
    fn try_from(value: Foundation::HANDLE) -> Result<Self, Self::Error> {
        Ok(AnonymousPipe {
            handle: Handle::try_from(value)?,
            mode: PhantomData,
        })
    }
}

impl<T> Deref for AnonymousPipe<T> {
    type Target = Handle;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

pub struct Readable;
pub struct Writable;

pub type AnonymousPipeReader = AnonymousPipe<Readable>;
pub type AnonymousPipeWriter = AnonymousPipe<Writable>;

impl AnonymousPipe {
    /// Creates a new anonymous in-memory pipe, returning the read/write ends of the
    /// pipe.
    ///
    /// The buffer size for this pipe may also be specified, but the system will
    /// normally use this as a suggestion and it's not guaranteed that the buffer
    /// will be precisely this size.
    pub fn new(
        buffer_size: u32,
    ) -> Result<(AnonymousPipeReader, AnonymousPipeWriter), ::windows::core::Error> {
        let (mut read, mut write) = (Foundation::HANDLE::default(), Foundation::HANDLE::default());
        unsafe { Pipes::CreatePipe(&mut read, &mut write, None, buffer_size)? };
        Ok((
            AnonymousPipe::try_from(read)?,
            AnonymousPipe::try_from(write)?,
        ))
    }
}

#[derive(Debug)]
pub struct NamedPipe {
    name: String,
    handle: Handle,
}

impl NamedPipe {
    /// Duplicates the underlying handle and returns a new NamedPipe with the same name.
    pub fn try_clone_handle(&self) -> io::Result<NamedPipe> {
        let duplicated = self.handle.duplicate()?;
        Ok(NamedPipe {
            name: self.name.clone(),
            handle: duplicated,
        })
    }
}

/// A builder structure for creating a new named pipe.
#[derive(Debug, Default)]
pub struct NamedPipeBuilder {
    name: String,
    open_mode: FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
    pipe_mode: Pipes::NAMED_PIPE_MODE,
    max_instances: u32,
    out_buffer_size: u32,
    in_buffer_size: u32,
    default_time_out: u32,
}

impl NamedPipe {
    /// Creates a new named pipe builder with the default settings.
    ///
    /// The unique pipe name. This string must have the following form:
    ///
    /// \\.\pipe\pipe_name
    ///
    /// The `pipe_name` part of the name can include any character other than a backslash, including numbers and special characters. The entire pipe name string can be up to 256 characters long. Pipe names are not case sensitive.
    pub fn builder<S: Into<String>>(name: S) -> NamedPipeBuilder {
        NamedPipeBuilder {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Constructs a named pipe from an existing handle.
    pub fn from_handle<S: Into<String>>(name: S, handle: Handle) -> Self {
        Self {
            name: name.into(),
            handle,
        }
    }
}

/// Waits until either a time-out interval elapses or an instance of the specified named pipe is available for connection
/// (that is, the pipe's server process has a pending ConnectNamedPipe operation on the pipe).
pub fn wait<A: AsRef<OsStr>>(name: A, timeout: Option<time::Duration>) -> io::Result<()> {
    let name = name
        .as_ref()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let timeout = timeout
        .map(|d| d.as_millis() as u32)
        .unwrap_or(Threading::INFINITE);
    (unsafe { Pipes::WaitNamedPipeW(PCWSTR(name.as_ptr()), timeout) })
        .ok()
        .map_err(io::Error::from)
}

impl NamedPipe {
    /// Waits until either a time-out interval elapses or an instance of the specified named pipe is available for connection
    /// (that is, the pipe's server process has a pending ConnectNamedPipe operation on the pipe).
    pub fn wait(&self, timeout: Option<time::Duration>) -> io::Result<()> {
        wait(self.name.as_str(), timeout)
    }

    /// Copies data from a named or anonymous pipe into a buffer without removing it from the pipe.
    /// It also returns information about data in the pipe.
    pub fn peek(
        &self,
        buffer: Option<&mut [u8]>,
        read: Option<*mut u32>,
        available: Option<*mut u32>,
        left: Option<*mut u32>,
    ) -> io::Result<()> {
        let buffer_size = buffer.as_ref().map(|buf| buf.len()).unwrap_or(0);
        unsafe {
            Pipes::PeekNamedPipe(
                self.handle.as_foundation_handle(),
                buffer.map(|buf| buf.as_mut_ptr() as *mut _),
                buffer_size as _,
                read as _,
                available as _,
                left as _,
            )?
        };
        Ok(())
    }

    /// Enables a named pipe server process to wait for a client process to connect to an instance of a named pipe.
    /// A client process connects by calling either the CreateFile or CallNamedPipe function.
    pub fn connect(&self) -> Result<bool, ::windows::core::Error> {
        self.connect_overlapped_unchecked(None)
    }

    /// Enables a named pipe server process to wait for a client process to connect to an instance of a named pipe.
    /// A client process connects by calling either the CreateFile or CallNamedPipe function.
    pub fn connect_overlapped(
        &self,
        overlapped: &mut Overlapped,
    ) -> Result<bool, ::windows::core::Error> {
        self.connect_overlapped_unchecked(Some(overlapped as *mut Overlapped))
    }

    /// Enables a named pipe server process to wait for a client process to connect to an instance of a named pipe.
    /// A client process connects by calling either the CreateFile or CallNamedPipe function.
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
    fn connect_overlapped_unchecked(
        &self,
        overlapped: Option<*mut Overlapped>,
    ) -> Result<bool, ::windows::core::Error> {
        match unsafe {
            Pipes::ConnectNamedPipe(
                self.handle.as_foundation_handle(),
                mem::transmute::<Option<_>, Option<_>>(overlapped),
            )
        } {
            Ok(_) => Ok(true),
            Err(ref err) => {
                let Some(code) = Foundation::WIN32_ERROR::from_error(err) else {
                    return Err(err.clone());
                };
                match code {
                    Foundation::ERROR_PIPE_CONNECTED => Ok(true),
                    Foundation::ERROR_IO_INCOMPLETE => Ok(false),
                    Foundation::ERROR_IO_PENDING => Ok(false),
                    Foundation::ERROR_NO_DATA => Ok(true),
                    _ => Err(err.clone()),
                }
            }
        }
    }

    /// Disconnects this named pipe from any connected client.
    pub fn disconnect(&self) -> io::Result<()> {
        unsafe { Pipes::DisconnectNamedPipe(self.handle.as_foundation_handle())? };
        Ok(())
    }
}

impl NamedPipe {
    pub fn open_peer_process(&self) -> io::Result<Option<Handle>> {
        if let Ok(opt) = self.get_client_process_handle() {
            return Ok(opt);
        }
        if let Ok(opt) = self.get_server_process_handle() {
            return Ok(opt);
        }
        Ok(None)
    }

    pub fn get_client_process_handle(&self) -> io::Result<Option<Handle>> {
        let mut pid = 0u32;
        unsafe { Pipes::GetNamedPipeClientProcessId(self.handle.as_foundation_handle(), &mut pid)? }
        if pid == 0 {
            return Ok(None);
        }
        Self::open_process(pid)
    }
    pub fn get_server_process_handle(&self) -> io::Result<Option<Handle>> {
        let mut pid = 0u32;
        unsafe { Pipes::GetNamedPipeServerProcessId(self.handle.as_foundation_handle(), &mut pid)? }
        if pid == 0 {
            return Ok(None);
        }
        Self::open_process(pid)
    }

    fn open_process(pid: u32) -> io::Result<Option<Handle>> {
        if pid == 0 {
            return Ok(None);
        }

        match unsafe { Threading::OpenProcess(Threading::PROCESS_DUP_HANDLE, false, pid) } {
            Ok(raw) => Handle::try_from(raw).map(Some).map_err(io::Error::other),
            Err(err) => {
                if let Some(code) = WIN32_ERROR::from_error(&err)
                    && code == Foundation::ERROR_ACCESS_DENIED
                {
                    return Ok(None);
                }

                Err(io::Error::other(err))
            }
        }
    }
}

impl From<NamedPipe> for Handle {
    fn from(pipe: NamedPipe) -> Self {
        pipe.handle
    }
}

impl std::os::windows::io::AsRawHandle for NamedPipe {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.handle.as_raw_handle()
    }
}
impl std::os::windows::io::IntoRawHandle for NamedPipe {
    fn into_raw_handle(self) -> std::os::windows::io::RawHandle {
        self.handle.into_raw_handle()
    }
}

impl Deref for NamedPipe {
    type Target = Handle;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl NamedPipeBuilder {
    /// The open mode.
    ///
    /// The function fails if dwOpenMode specifies anything other than 0 or the flags listed in the following tables.
    ///
    /// This parameter must specify one of the following pipe access modes. The same mode must be specified for each instance of the pipe.
    pub fn open_mode(mut self, mode: FileSystem::FILE_FLAGS_AND_ATTRIBUTES) -> Self {
        self.open_mode |= mode;
        self
    }
    /// The pipe mode.
    ///
    /// The function fails if dwPipeMode specifies anything other than 0 or the flags listed in the following tables.
    ///
    /// One of the following type modes can be specified. The same type mode must be specified for each instance of the pipe.
    pub fn pipe_mode(mut self, mode: Pipes::NAMED_PIPE_MODE) -> Self {
        self.pipe_mode |= mode;
        self
    }

    /// Specifies the maximum number of instances of the server pipe that are
    /// allowed.
    ///
    /// The first instance of a pipe can specify this value. A value of 255
    /// indicates that there is no limit to the number of instances.
    pub fn max_instances(mut self, instances: u32) -> Self {
        self.max_instances = instances;
        self
    }

    /// Specifies the number of bytes to reserver for the output buffer
    pub fn out_buffer_size(mut self, size: u32) -> Self {
        self.out_buffer_size = size;
        self
    }

    /// Specifies the number of bytes to reserver for the input buffer
    pub fn in_buffer_size(mut self, size: u32) -> Self {
        self.in_buffer_size = size;
        self
    }

    /// The default time-out value, in milliseconds, if the WaitNamedPipe function specifies NMPWAIT_USE_DEFAULT_WAIT.
    /// Each instance of a named pipe must specify the same value.
    ///
    /// A value of zero will result in a default time-out of 50 milliseconds.
    pub fn default_time_out(mut self, time_out: u32) -> Self {
        self.default_time_out = time_out;
        self
    }

    /// Using the options in this builder, attempt to create a new named pipe.
    ///
    /// This function will call the `CreateNamedPipe` function and return the
    /// result.
    pub fn build(&self) -> io::Result<NamedPipe> {
        let handle = Handle::try_from(unsafe {
            Pipes::CreateNamedPipeW(
                &HSTRING::from(self.name.as_str()),
                self.open_mode,
                self.pipe_mode,
                self.max_instances,
                self.out_buffer_size,
                self.in_buffer_size,
                self.default_time_out,
                None,
            )
        })?;

        Ok(NamedPipe {
            name: self.name.clone(),
            handle,
        })
    }
}

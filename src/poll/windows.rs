//! Windows-specific polling implementation using IOCP (I/O Completion Ports).

#![allow(clippy::unnecessary_cast)]
#![allow(clippy::io_other_error)]

use std::{
    collections::HashMap,
    io, ops,
    os::windows::io::{AsRawHandle, RawHandle},
    ptr,
    time::Duration,
};

use windows::Win32::{
    Foundation,
    Foundation::{
        CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT, WIN32_ERROR,
    },
    System::{
        Threading,
        IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus},
    },
};

use crate::poll::{Event, Events, Interest, Token};
use crate::windows::{
    handle::Handle,
    overlapped::Overlapped,
    pipe::{NamedPipe, NamedPipeBuilder},
};

pub trait AsSource {
    fn source(&self) -> RawHandle;
}

/// Windows IOCP-based poller.
pub struct Poller {
    iocp: HANDLE,
    sources: HashMap<Token, (RawHandle, Interest)>,
}

unsafe impl Send for Poller {}

impl Poller {
    /// Creates a new IOCP-based poller.
    pub fn new() -> io::Result<Self> {
        let iocp = unsafe {
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                None,
                0,
                0, // Use default number of concurrent threads
            )
        }
        .map_err(|_| io::Error::last_os_error())?;

        Ok(Poller {
            iocp,
            sources: HashMap::new(),
        })
    }

    /// Associates a handle with the IOCP.
    pub fn register(
        &mut self,
        handle: RawHandle,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        unsafe {
            CreateIoCompletionPort(HANDLE(handle), Some(self.iocp), token.into(), 0)
                .map_err(|_| io::Error::last_os_error())?
        };

        self.sources.insert(token, (handle, interest));
        Ok(())
    }

    pub fn deregister(&mut self, token: Token) -> io::Result<()> {
        self.sources.remove(&token);
        // On Windows, we don't need to explicitly deregister from IOCP
        // The association is automatically removed when the handle is closed
        Ok(())
    }

    pub fn update_interest(&mut self, token: Token, interest: Interest) {
        if let Some(entry) = self.sources.get_mut(&token) {
            entry.1 = interest;
        }
    }

    /// Polls for I/O completion events.
    pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();

        let mut wait = timeout
            .map(|d| d.as_millis() as u32)
            .unwrap_or(Threading::INFINITE);

        loop {
            let mut bytes_transferred = 0u32;
            let mut completion_key = 0usize;
            let mut overlapped = ptr::null_mut();

            let result = unsafe {
                GetQueuedCompletionStatus(
                    self.iocp,
                    &mut bytes_transferred,
                    &mut completion_key,
                    &mut overlapped,
                    wait,
                )
            };

            let success = result.is_ok();
            let last_error = if success {
                None
            } else {
                Some(unsafe { GetLastError() })
            };

            if !success {
                match last_error {
                    Some(err) if err.0 == WAIT_TIMEOUT.0 && overlapped.is_null() => break,
                    Some(err) if overlapped.is_null() => {
                        return Err(io::Error::from_raw_os_error(err.0 as i32))
                    }
                    _ => {}
                }
            }

            if overlapped.is_null() && completion_key != Token::WAKER {
                continue;
            }

            let token = Token::new(completion_key);
            let interest = self
                .sources
                .get(&token)
                .map(|(_, interest)| *interest)
                .unwrap_or(Interest::READABLE);

            events.push(Event::new(token, interest));

            // Subsequent iterations should not block
            wait = 0;
        }
        Ok(())
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.iocp);
        }
    }
}

/// A waker that can wake up the poller from another thread.
pub struct Waker {
    iocp: HANDLE,
}

impl Waker {
    /// Creates a new waker associated with the given poller.
    pub fn new(poller: &Poller) -> io::Result<Self> {
        Ok(Waker { iocp: poller.iocp })
    }

    /// Wakes up the associated poller.
    pub fn wake(&self) -> io::Result<()> {
        unsafe {
            PostQueuedCompletionStatus(
                self.iocp,
                0,                   // bytes transferred
                Token::WAKER.into(), // completion key (0 for waker)
                None,                // overlapped
            )
            .map_err(|_| io::Error::last_os_error())
        }
    }
}

unsafe impl Send for Waker {}
unsafe impl Sync for Waker {}

/// Windows Named Pipe source implementation.
pub struct NamedPipeSource {
    builder: NamedPipeBuilder,
    named_pipe: NamedPipe,
    overlapped_connect: Overlapped,
    registered: Option<Token>,
}

impl NamedPipeSource {
    /// Creates a new Named Pipe source.
    pub fn new(builder: NamedPipeBuilder) -> io::Result<Self> {
        let named_pipe = builder.build()?;

        let overlapped_connect = Overlapped::initialize_with_auto_reset_event()
            .map_err(|e| io::Error::other(format!("Failed to create connect overlapped: {e}")))?;

        Ok(NamedPipeSource {
            builder,
            named_pipe,
            overlapped_connect,
            registered: None,
        })
    }

    /// Start an overlapped connection for this pipe instance.
    pub fn try_connect(&mut self) -> io::Result<Option<NamedPipe>> {
        let win32_error = match self
            .named_pipe
            .connect_overlapped(&mut self.overlapped_connect)
        {
            Ok(false) => return Ok(None),
            Ok(true) => {
                let pipe = std::mem::replace(&mut self.named_pipe, self.builder.build()?);
                return Ok(Some(pipe));
            }
            Err(e) => {
                if let Some(err) = WIN32_ERROR::from_error(&e) {
                    err
                } else {
                    return Err(io::Error::other(e));
                }
            }
        };
        match win32_error {
            // Client completed the connection between the call and our check.
            Foundation::ERROR_PIPE_CONNECTED => {
                let pipe = std::mem::replace(&mut self.named_pipe, self.builder.build()?);
                Ok(Some(pipe))
            }
            // No connection yet; keep polling.
            Foundation::ERROR_IO_PENDING
            | Foundation::ERROR_PIPE_LISTENING
            | Foundation::ERROR_PIPE_BUSY => Ok(None),
            other => {
                crate::error!("connect NamedPipe failed: {other:?}");
                Err(io::Error::from_raw_os_error(other.0 as i32))
            }
        }
    }
    /// Start an blocking connection for this pipe instance.
    pub fn connect(&mut self) -> Result<NamedPipe, windows::core::Error> {
        let win32_error = match self.named_pipe.connect() {
            Ok(true) => {
                return Ok(std::mem::replace(
                    &mut self.named_pipe,
                    self.builder.build()?,
                ))
            }
            Ok(false) => Foundation::ERROR_IO_PENDING, // Overlapped connection in progress
            Err(err) => match WIN32_ERROR::from_error(&err) {
                Some(win32_err) => win32_err,
                None => return Err(err),
            },
        };

        match win32_error {
            // Client is already connected, so signal an event.
            Foundation::ERROR_PIPE_CONNECTED => Ok(std::mem::replace(
                &mut self.named_pipe,
                self.builder.build()?,
            )),
            // The overlapped connection in progress.
            // Foundation::ERROR_IO_PENDING | Foundation::ERROR_IO_INCOMPLETE => false,
            // If an error occurs during the connect operation...
            err => {
                crate::error!("connect NamedPipe failed: {err:?}");
                Err(windows::core::Error::from(err))
            }
        }
    }
}

impl AsSource for NamedPipeSource {
    fn source(&self) -> RawHandle {
        self.named_pipe.as_raw_handle()
    }
}

impl PartialEq<Token> for NamedPipeSource {
    fn eq(&self, other: &Token) -> bool {
        self.registered.is_some_and(|t| t.eq(other))
    }
}

impl ops::Deref for NamedPipeSource {
    type Target = NamedPipe;

    fn deref(&self) -> &Self::Target {
        &self.named_pipe
    }
}

/// A generic handle source for Windows.
pub struct IoHandleSource {
    handle: Handle,
    #[allow(dead_code)]
    overlapped_read: Overlapped,
    #[allow(dead_code)]
    overlapped_write: Overlapped,
    #[allow(dead_code)]
    registered: Option<Token>,
    buffer: Vec<u8>,
    reading_state: OverlappedReading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlappedReading {
    Pending,
    Partial,
    Transferred(usize),
    Completed(usize),
}

impl Default for OverlappedReading {
    fn default() -> Self {
        OverlappedReading::Completed(0)
    }
}

impl AsSource for IoHandleSource {
    fn source(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }
}

impl TryFrom<NamedPipe> for IoHandleSource {
    type Error = io::Error;
    fn try_from(pipe: NamedPipe) -> Result<Self, Self::Error> {
        IoHandleSource::new(pipe.into())
    }
}

impl IoHandleSource {
    pub const DEFAULT_BUFFER_SIZE: usize = 64;

    /// Creates a new handle source.
    pub fn new(handle: Handle) -> io::Result<Self> {
        let overlapped_read = Overlapped::initialize_with_auto_reset_event()
            .map_err(|e| io::Error::other(format!("Failed to create read overlapped: {e}")))?;
        let overlapped_write = Overlapped::initialize_with_auto_reset_event()
            .map_err(|e| io::Error::other(format!("Failed to create write overlapped: {e}")))?;
        Ok(IoHandleSource {
            handle,
            overlapped_read,
            overlapped_write,
            registered: None,
            buffer: Vec::new(),
            reading_state: OverlappedReading::Completed(0),
        })
    }

    /// Returns a reference to the underlying handle.
    #[inline]
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Returns a mutable reference to the underlying handle.
    #[inline]
    pub fn handle_mut(&mut self) -> &mut Handle {
        &mut self.handle
    }

    /// Performs a blocking read on the underlying handle.
    pub fn read_blocking(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handle
            .read_with_overlapped_result(buf, &mut self.overlapped_read, true)
            .map_err(io::Error::from)
    }

    /// Performs a blocking write on the underlying handle.
    pub fn write_blocking(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handle
            .write_with_overlapped_result(buf, &mut self.overlapped_write, true)
            .map_err(io::Error::from)
    }

    /// Flushes the underlying handle buffers.
    pub fn flush_blocking(&self) -> io::Result<()> {
        self.handle.flush().map_err(io::Error::from)
    }

    /// Returns last length
    fn try_extend_capacity(&mut self, additional: Option<usize>) -> usize {
        let length = self.buffer.len();
        if length == self.buffer.capacity() {
            let additional =
                additional.unwrap_or_else(|| std::cmp::max(length, Self::DEFAULT_BUFFER_SIZE));
            self.buffer.reserve(additional);
            self.reset_length(self.buffer.capacity());
        }
        length
    }
    fn reset_length(&mut self, length: usize) {
        unsafe { self.buffer.set_len(length) };
    }

    #[inline]
    pub fn take_away(&mut self) -> Vec<u8> {
        #[cfg(feature = "verbose")]
        crate::trace!(
            "take_away {:?}/{}",
            self.buffer.len(),
            self.buffer.capacity()
        );

        let OverlappedReading::Completed(bytes) = self.reading_state else {
            return Vec::new();
        };

        let mut buffer = std::mem::take(&mut self.buffer);
        buffer.truncate(bytes);

        // Reset state and ensure buffer has capacity for next read
        self.reading_state = OverlappedReading::Completed(0);
        // Reserve minimum capacity so next read doesn't start with empty Vec
        self.buffer.reserve(Self::DEFAULT_BUFFER_SIZE);

        buffer
    }

    /// try to read message into buffer
    pub fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            self.reading_state = if self.reading_state == OverlappedReading::Pending {
                self.poll_overlapped_read(false)?
            } else {
                self.start_overlapped_read()?
            };

            match self.reading_state {
                OverlappedReading::Pending => return Ok(None),
                OverlappedReading::Partial => {
                    self.reset_length(self.buffer.capacity());
                }
                OverlappedReading::Transferred(bytes) => {
                    self.reset_length(bytes);
                    // Always transition to Completed after transferring data
                    self.reading_state = OverlappedReading::Completed(bytes);
                }
                OverlappedReading::Completed(bytes) => {
                    self.reset_length(bytes);
                }
            }

            if let OverlappedReading::Completed(bytes) = self.reading_state {
                if bytes == 0 {
                    self.buffer.clear();
                    return Err(io::Error::from_raw_os_error(
                        Foundation::ERROR_BROKEN_PIPE.0 as i32,
                    ));
                }
                return Ok(Some(self.take_away()));
            }
        }
    }

    /// Blocking read that waits for a complete message.
    /// Returns an empty vector if the connection is closed gracefully.
    /// Returns BrokenPipe error only if the connection was closed unexpectedly during transfer.
    pub fn recv_blocking(&mut self) -> io::Result<Vec<u8>> {
        // Use a polling approach with short timeouts to handle the case where
        // the peer closes the connection while we're waiting for data.
        // Pure blocking I/O can miss data that was sent just before closure.
        loop {
            self.reading_state = if self.reading_state == OverlappedReading::Pending {
                // Poll with a short timeout to allow detecting data before pipe closure
                match self.poll_overlapped_read(false)? {
                    OverlappedReading::Pending => {
                        // Still pending, wait a bit and retry
                        std::thread::sleep(std::time::Duration::from_micros(100));
                        OverlappedReading::Pending
                    }
                    other => other,
                }
            } else {
                match self.start_overlapped_read() {
                    Ok(state) => state,
                    Err(err) => {
                        // Check if this is a graceful connection closure
                        if Self::is_connection_closed(&err) {
                            self.buffer.clear();
                            return Err(err);
                        }
                        return Err(err);
                    }
                }
            };

            match self.reading_state {
                OverlappedReading::Pending => {
                    // Continue loop to poll again
                    continue;
                }
                OverlappedReading::Partial => {
                    self.reset_length(self.buffer.capacity());
                }
                OverlappedReading::Transferred(bytes) => {
                    self.reset_length(bytes);
                    if bytes < self.buffer.capacity() {
                        self.reading_state = OverlappedReading::Completed(bytes);
                    }
                }
                OverlappedReading::Completed(bytes) => {
                    self.reset_length(bytes);
                }
            }

            if let OverlappedReading::Completed(bytes) = self.reading_state {
                if bytes == 0 {
                    // Connection closed gracefully - return BrokenPipe to signal this
                    self.buffer.clear();
                    return Err(io::Error::from_raw_os_error(
                        Foundation::ERROR_BROKEN_PIPE.0 as i32,
                    ));
                }
                return Ok(self.take_away());
            }
        }
    }

    fn is_connection_closed(err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
        ) || matches!(
            err.raw_os_error(),
            Some(code)
                if code == Foundation::ERROR_BROKEN_PIPE.0 as i32
                    || code == Foundation::ERROR_NO_DATA.0 as i32
                    || code == Foundation::ERROR_PIPE_NOT_CONNECTED.0 as i32
        )
    }

    fn start_overlapped_read(&mut self) -> io::Result<OverlappedReading> {
        let bytes_left_this_message = self.peek_message_length(None)?;

        #[cfg(feature = "verbose")]
        crate::debug!(
            "[IoHandleSource] start_overlapped_read: peek returned {:?}",
            bytes_left_this_message
        );

        if bytes_left_this_message == Some(0) {
            return Ok(OverlappedReading::Completed(self.buffer.len()));
        }

        // If peek returns None (no data yet), still start a read operation
        // so it will complete when data arrives
        let offset = self.try_extend_capacity(bytes_left_this_message);
        self.reset_length(self.buffer.capacity());

        let result = self
            .handle
            .read_overlapped(&mut self.buffer[offset..], Some(&mut self.overlapped_read));

        #[cfg(feature = "verbose")]
        crate::debug!(
            "[IoHandleSource] start_overlapped_read: read_overlapped returned {:?}",
            result
        );

        match result {
            Ok(bytes) => Ok(OverlappedReading::Transferred(offset + bytes)),
            Err(err) => {
                let Some(win32_error) = WIN32_ERROR::from_error(&err) else {
                    return Err(io::Error::other(err));
                };
                match win32_error {
                    Foundation::ERROR_MORE_DATA => Ok(OverlappedReading::Partial),
                    Foundation::ERROR_IO_PENDING => {
                        self.reset_length(offset);
                        Ok(OverlappedReading::Pending)
                    }
                    code => {
                        self.reset_length(offset);
                        Err(io::Error::from_raw_os_error(code.0 as i32))
                    }
                }
            }
        }
    }

    fn poll_overlapped_read(&mut self, wait: bool) -> io::Result<OverlappedReading> {
        let offset = self.buffer.len();

        let result = self
            .handle
            .get_overlapped_result(&self.overlapped_read, wait);

        #[cfg(feature = "verbose")]
        crate::debug!(
            "[IoHandleSource] poll_overlapped_read: get_overlapped_result(wait={}) returned {:?}",
            wait,
            result
        );

        match result {
            Ok(bytes) => Ok(OverlappedReading::Transferred(offset + bytes)),
            Err(err) => {
                let Some(win32_error) = WIN32_ERROR::from_error(&err) else {
                    return Err(io::Error::other(err));
                };

                #[cfg(feature = "verbose")]
                crate::debug!(
                    "[IoHandleSource] poll_overlapped_read: WIN32_ERROR = {:?}",
                    win32_error
                );

                match win32_error {
                    Foundation::ERROR_MORE_DATA => Ok(OverlappedReading::Partial),
                    Foundation::ERROR_IO_INCOMPLETE => Ok(OverlappedReading::Pending),
                    // Handle pipe closure gracefully when blocking
                    Foundation::ERROR_BROKEN_PIPE
                    | Foundation::ERROR_PIPE_NOT_CONNECTED
                    | Foundation::ERROR_NO_DATA => {
                        self.reset_length(offset);
                        // Return 0 bytes to signal EOF/connection closed
                        Ok(OverlappedReading::Completed(0))
                    }
                    code => {
                        self.reset_length(offset);
                        Err(io::Error::from_raw_os_error(code.0 as i32))
                    }
                }
            }
        }
    }

    fn peek_message_length(&self, total: Option<&mut u32>) -> io::Result<Option<usize>> {
        let mut left = 0u32;
        match self
            .handle
            .peek_named_pipe(None, None, total, Some(&mut left))
        {
            Ok(_) => {
                if left == 0 {
                    return Ok(None);
                }
                Ok(Some(left as usize))
            }
            Err(err) => {
                let Some(code) = WIN32_ERROR::from_error(&err) else {
                    return Err(io::Error::other(err));
                };
                match code {
                    Foundation::ERROR_NO_DATA | Foundation::ERROR_PIPE_LISTENING => Ok(None),
                    // Don't treat BrokenPipe as definitive EOF here - there might still be
                    // buffered data that can be read. Let the actual read operation handle it.
                    Foundation::ERROR_BROKEN_PIPE => Ok(None),
                    _ => Err(io::Error::from(err)),
                }
            }
        }
    }
}

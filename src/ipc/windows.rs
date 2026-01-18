use std::{
    collections::{HashMap, VecDeque},
    convert::TryInto,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, RawHandle},
    ptr,
    sync::{Arc, Mutex},
    time::Duration,
};

use crossbeam::utils::Backoff;
use windows::{
    Win32::{
        Foundation::{self, WIN32_ERROR},
        Security,
        Storage::FileSystem,
        System::{Pipes, Threading},
    },
    core::Owned,
};

use crate::{
    poll::{AsSource, Events, Interest, IoHandleSource, Poller, Token},
    windows::{handle::Handle, overlapped::Overlapped, pipe, pipe::NamedPipe},
};

use super::{Credentials, IntoServiceDescriptor, Message, Object, Policy};

const DEFAULT_BUFFER_SIZE: u32 = 64;
const MIN_PENDING_ACCEPTS: usize = 16; // Maintain at least this many pending accepts
const WIRE_MAGIC: u32 = 0x5350_494C; // 'gips'
const WIRE_VERSION: u16 = 1;
const WIRE_HEADER_LEN: usize = 16;
const WIRE_HANDLE_ENTRY_LEN: usize = 16;
const WIRE_OBJECT_HANDLE: u8 = 1;

pub struct Listener {
    full_name: String,
    poller: Poller,
    events: Events,
    backoff: Backoff,
    accepts: HashMap<Token, Accept>,
    connections: HashMap<Token, Connection>,
    backlog: VecDeque<Pod>,
    acl_policy: Policy,
}

pub struct Endpoint {
    connection: Connection,
}

#[derive(Clone)]
pub struct Connection {
    inner: Arc<Mutex<ConnectionInner>>,
}

struct ConnectionInner {
    io: IoHandleSource,
    peer_process: Option<Handle>,
    pipe: Option<crate::windows::pipe::NamedPipe>,
}

pub struct Pod {
    connection: Connection,
    message: Option<Message>,
    credentials: Credentials,
}

struct Accept {
    pipe: NamedPipe,
    overlapped: Overlapped,
}

enum AcceptOutcome {
    Pending(Accept),
    Connected(NamedPipe),
}

impl Listener {
    pub fn bind<S: IntoServiceDescriptor>(pipe_name: S) -> io::Result<Self> {
        let descriptor = pipe_name.into_service_descriptor();
        let pipe_name = descriptor.name;
        let full_name = format!(r"\\.\\pipe\\{pipe_name}");

        let poller = Poller::new()?;
        let events = Events::with_capacity(64);

        let mut listener = Self {
            full_name,
            poller,
            events,
            backoff: Backoff::new(),
            accepts: HashMap::new(),
            connections: HashMap::new(),
            backlog: VecDeque::new(),
            acl_policy: descriptor.policy,
        };

        // Spawn multiple accepts upfront to handle concurrent connections
        listener.ensure_min_accepts()?;
        Ok(listener)
    }

    pub fn accept(&mut self) -> io::Result<Pod> {
        loop {
            if let Some(pod) = self.backlog.pop_front() {
                self.backoff.reset();
                // Ensure we maintain enough pending accepts
                self.ensure_min_accepts()?;
                return Ok(pod);
            }

            // Always use a short timeout to periodically check for:
            // 1. New accept events (if no connections yet)
            // 2. Existing connections for new messages (they use overlapped I/O, not IOCP events)
            let timeout = Some(Duration::from_millis(10));

            self.poll_once(timeout)?;
            self.backoff.snooze();
        }
    }

    pub fn try_accept(&mut self) -> io::Result<Option<Pod>> {
        if let Some(pod) = self.backlog.pop_front() {
            self.backoff.reset();
            // Ensure we maintain enough pending accepts
            self.ensure_min_accepts()?;
            return Ok(Some(pod));
        }

        self.poll_once(Some(Duration::from_millis(0)))?;
        Ok(self.backlog.pop_front())
    }

    /// Ensure we maintain a minimum number of pending accepts to handle concurrent connections
    fn ensure_min_accepts(&mut self) -> io::Result<()> {
        while self.accepts.len() < MIN_PENDING_ACCEPTS {
            self.spawn_single_accept()?;
        }
        Ok(())
    }

    /// Spawn a single accept, handling immediate connections
    /// This ensures exactly one pending accept is added, handling any immediate connections along the way
    fn spawn_single_accept(&mut self) -> io::Result<()> {
        // Iteratively spawn accepts until we get a pending one; avoid recursive depth.
        let mut pipe = self.build_pipe()?;
        loop {
            let accept = Accept::new(pipe)?;
            // Generate a unique token for this accept
            let token = Token::new(
                self.accepts.keys().map(|t| t.0).max().unwrap_or(0)
                    + self.connections.keys().map(|t| t.0).max().unwrap_or(0)
                    + 1,
            );
            self.poller
                .inner()
                .register(accept.source(), token, Interest::READABLE)?;
            match accept.start()? {
                AcceptOutcome::Pending(state) => {
                    self.accepts.insert(token, state);
                    // Successfully added a pending accept
                    break;
                }
                AcceptOutcome::Connected(conn_pipe) => {
                    // Immediate connection - handle it and create another pipe
                    self.handle_new_connection(token, conn_pipe)?;
                    // Build a new pipe and continue; do NOT recurse.
                    pipe = self.build_pipe()?;
                    // Important: continue the loop to create another accept until we get a pending one
                    continue;
                }
            }
        }
        Ok(())
    }

    fn build_pipe(&self) -> io::Result<NamedPipe> {
        NamedPipe::builder(self.full_name.clone())
            .open_mode(FileSystem::FILE_FLAGS_AND_ATTRIBUTES(
                FileSystem::PIPE_ACCESS_DUPLEX.0 | FileSystem::FILE_FLAG_OVERLAPPED.0,
            ))
            .pipe_mode(Pipes::NAMED_PIPE_MODE(
                Pipes::PIPE_TYPE_MESSAGE.0 | Pipes::PIPE_READMODE_MESSAGE.0 | Pipes::PIPE_WAIT.0,
            ))
            .max_instances(Pipes::PIPE_UNLIMITED_INSTANCES)
            .out_buffer_size(DEFAULT_BUFFER_SIZE)
            .in_buffer_size(DEFAULT_BUFFER_SIZE)
            .default_time_out(Pipes::NMPWAIT_USE_DEFAULT_WAIT)
            .build()
    }

    fn poll_once(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.events.clear();
        self.poller.poll(&mut self.events, timeout)?;

        let tokens: Vec<Token> = self.events.iter().map(|event| event.token()).collect();
        for token in tokens {
            if token == Token::WAKER {
                continue;
            }

            if let Some(accept) = self.accepts.remove(&token) {
                match accept.complete() {
                    Ok(pipe) => self.handle_new_connection(token, pipe)?,
                    Err(err) => {
                        if !is_connection_closed(&err) {
                            return Err(err);
                        }
                        // We can't deregister without the source, so just skip it
                    }
                }

                // Immediately replenish accepts to maintain the minimum
                self.ensure_min_accepts()?;
                continue;
            }

            if let Some(connection) = self.connections.get(&token).cloned() {
                self.drain_connection(token, connection)?;
            }
        }

        // Poll all existing connections for new messages
        // This is necessary because connections use overlapped I/O, not IOCP events
        let connection_tokens: Vec<Token> = self.connections.keys().copied().collect();
        for token in connection_tokens {
            if let Some(connection) = self.connections.get(&token).cloned() {
                self.drain_connection(token, connection)?;
            }
        }

        Ok(())
    }

    fn handle_new_connection(&mut self, token: Token, pipe: NamedPipe) -> io::Result<()> {
        let connection = Connection::from_pipe(pipe)?;
        self.connections.insert(token, connection.clone());
        // Don't try to read immediately - let the normal polling handle it
        // This avoids potential issues with reading from a freshly-connected pipe
        Ok(())
    }

    fn drain_connection(&mut self, token: Token, connection: Connection) -> io::Result<()> {
        loop {
            match connection.try_recv() {
                Ok(Some(message)) => {
                    // Get credentials from the connection and validate ACL
                    let credentials = connection.get_credentials()?;

                    // Check ACL policy if not unrestricted
                    if !self.acl_policy.is_unrestricted()
                        && let Err(err) = self.acl_policy.check(&credentials) {
                            // Forcibly disconnect the pipe on ACL failure
                            let _ = connection.with_inner(|inner| {
                                if let Some(ref pipe) = inner.pipe {
                                    pipe.disconnect()
                                } else {
                                    Ok(())
                                }
                            });
                            self.remove_connection(token)?;
                            return Err(err);
                        }

                    self.backlog.push_back(Pod::from_parts(
                        connection.clone(),
                        message,
                        credentials,
                    ));
                    self.backoff.reset();
                }
                Ok(None) => break,
                Err(err) => {
                    if is_connection_closed(&err) {
                        self.remove_connection(token)?;
                        break;
                    }
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    fn remove_connection(&mut self, token: Token) -> io::Result<()> {
        self.connections.remove(&token);
        // Note: We don't deregister here because we don't have access to the source
        // The IoHandleSource will be dropped which should clean up the registration
        Ok(())
    }
}

/// Explicitly clean up all pending accepts and connections before drop.
/// This avoids potential issues with automatic drop order.
impl Drop for Listener {
    fn drop(&mut self) {
        // Clear all accepts and connections
        // Note: We don't explicitly deregister because we don't have mutable access to sources
        // The IoHandleSource instances will be dropped which should clean up registrations
        self.accepts.clear();
        self.connections.clear();
        self.backlog.clear();
    }
}

impl Endpoint {
    pub fn connect<S: IntoServiceDescriptor>(pipe_name: S) -> io::Result<Self> {
        Self::connect_timeout(pipe_name, None)
    }

    pub fn connect_timeout<S: IntoServiceDescriptor>(
        pipe_name: S,
        mut timeout: Option<Duration>,
    ) -> io::Result<Self> {
        let descriptor = pipe_name.into_service_descriptor();
        let pipe_name = descriptor.name;
        let full_name = format!(r"\\.\\pipe\\{pipe_name}");

        let mut wait_result: Option<io::Result<()>> = None;
        let handle = loop {
            let result = crate::windows::file::Builder::new(&full_name)
                .desired_access(FileSystem::FILE_GENERIC_READ.0 | FileSystem::FILE_GENERIC_WRITE.0)
                .share_mode(FileSystem::FILE_SHARE_READ | FileSystem::FILE_SHARE_WRITE)
                .creation_disposition(FileSystem::OPEN_EXISTING)
                .flags_and_attributes(FileSystem::FILE_FLAGS_AND_ATTRIBUTES(
                    FileSystem::FILE_ATTRIBUTE_NORMAL.0 | FileSystem::FILE_FLAG_OVERLAPPED.0,
                ))
                .build();
            match result {
                Ok(handle) => break Handle::from(handle),
                Err(err) => {
                    let win32_error = WIN32_ERROR::from_error(&err);
                    let should_retry = win32_error.is_some_and(|code| {
                        code == Foundation::ERROR_PIPE_BUSY
                            || code == Foundation::ERROR_FILE_NOT_FOUND
                    });
                    if let Some(ref wait) = wait_result {
                        crate::debug!("wait for named pipe '{}' : {:?}", full_name, wait);
                    } else if should_retry {
                        wait_result = Some(pipe::wait(&full_name, timeout.take()));
                        continue;
                    }

                    return Err(io::Error::other(err));
                }
            }
        };

        let connection = Connection::from_pipe(NamedPipe::from_handle(full_name.clone(), handle))?;
        Ok(Self { connection })
    }
}

impl Accept {
    fn new(pipe: NamedPipe) -> io::Result<Self> {
        let overlapped = Overlapped::initialize_with_auto_reset_event()
            .map_err(|e| io::Error::other(format!("failed to create accept overlapped: {e}")))?;

        Ok(Self { pipe, overlapped })
    }

    fn start(mut self) -> io::Result<AcceptOutcome> {
        match self.pipe.connect_overlapped(&mut self.overlapped) {
            Ok(true) => Ok(AcceptOutcome::Connected(self.pipe)),
            Ok(false) => Ok(AcceptOutcome::Pending(self)),
            Err(err) => {
                if let Some(code) = WIN32_ERROR::from_error(&err) {
                    match code {
                        Foundation::ERROR_PIPE_CONNECTED => Ok(AcceptOutcome::Connected(self.pipe)),
                        Foundation::ERROR_IO_PENDING
                        | Foundation::ERROR_PIPE_LISTENING
                        | Foundation::ERROR_PIPE_BUSY => Ok(AcceptOutcome::Pending(self)),
                        _ => Err(io::Error::from(err)),
                    }
                } else {
                    Err(io::Error::other(err))
                }
            }
        }
    }

    fn complete(self) -> io::Result<NamedPipe> {
        match self.pipe.get_overlapped_result(&self.overlapped, true) {
            Ok(_) => Ok(self.pipe),
            Err(err) => {
                let Some(code) = WIN32_ERROR::from_error(&err) else {
                    return Err(io::Error::other(err));
                };
                match code {
                    Foundation::ERROR_PIPE_CONNECTED => Ok(self.pipe),
                    _ => Err(io::Error::from(err)),
                }
            }
        }
    }
}

impl AsSource for Accept {
    fn source(&self) -> RawHandle {
        self.pipe.as_raw_handle()
    }
}

impl Connection {
    fn from_pipe(pipe: NamedPipe) -> io::Result<Self> {
        let peer_process = pipe.open_peer_process().ok().flatten();
        let pipe_clone = pipe.try_clone_handle()?;
        let io = IoHandleSource::try_from(pipe)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(ConnectionInner {
                io,
                peer_process,
                pipe: Some(pipe_clone),
            })),
        })
    }

    fn with_inner<F, T>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce(&mut ConnectionInner) -> io::Result<T>,
    {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| io::Error::other(err.to_string()))?;
        f(&mut guard)
    }

    fn try_recv(&self) -> io::Result<Option<Message>> {
        self.with_inner(ConnectionInner::recv_message)
    }

    fn recv_blocking(&self) -> io::Result<Message> {
        self.with_inner(ConnectionInner::recv_message_blocking)
    }

    pub fn reply(&self, payload: &[u8], objects: &[Object]) -> io::Result<()> {
        self.with_inner(|inner| inner.send_message(payload, objects))
    }

    fn raw_handle(&self) -> RawHandle {
        match self.inner.lock() {
            Ok(inner) => inner.raw_handle(),
            Err(poisoned) => poisoned.into_inner().raw_handle(),
        }
    }

    /// Get credentials for the peer process connected via this connection
    fn get_credentials(&self) -> io::Result<Credentials> {
        self.with_inner(ConnectionInner::get_credentials)
    }
}

impl ConnectionInner {
    fn get_credentials(&mut self) -> io::Result<Credentials> {
        Credentials::from_pipe(self.io.handle().as_foundation_handle())
    }

    fn recv_message(&mut self) -> io::Result<Option<Message>> {
        match self.io.try_recv() {
            Ok(None) => Ok(None),
            Ok(Some(payload)) => {
                #[cfg(feature = "verbose")]
                crate::info!(
                    "[ipc::windows] recv_message decoded payload of size {}: {payload:?}",
                    payload.len()
                );
                let message = Self::decode_message(payload)?;
                Ok(Some(message))
            }
            Err(err) => {
                #[cfg(feature = "verbose")]
                crate::debug!("[ipc::windows] recv_message error: {:?}", err);
                Err(err)
            }
        }
    }

    fn recv_message_blocking(&mut self) -> io::Result<Message> {
        let payload = self.io.recv_blocking()?;
        #[cfg(feature = "verbose")]
        crate::info!(
            "[ipc::windows] recv_message_blocking decoded payload of size {}: {payload:?}",
            payload.len()
        );
        Self::decode_message(payload)
    }

    fn encode_message(
        &self,
        payload: &[u8],
        objects: &[Object],
    ) -> io::Result<(Vec<u8>, Vec<Foundation::HANDLE>)> {
        let mut handles: Vec<Foundation::HANDLE> = Vec::new();
        for object in objects {
            match object {
                Object::Handle(handle) => {
                    let duplicated = match self.duplicate_handle_for_peer(handle) {
                        Ok(handle) => handle,
                        Err(err) => {
                            self.cleanup_handles(&handles);
                            return Err(err);
                        }
                    };
                    handles.push(duplicated);
                }
            }
        }

        let mut encoded = Vec::with_capacity(
            WIRE_HEADER_LEN + payload.len() + handles.len() * WIRE_HANDLE_ENTRY_LEN,
        );
        encoded.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
        encoded.extend_from_slice(&WIRE_VERSION.to_le_bytes());
        encoded.extend_from_slice(&0u16.to_le_bytes());
        encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        encoded.extend_from_slice(&(handles.len() as u32).to_le_bytes());
        encoded.extend_from_slice(payload);

        for handle in &handles {
            encoded.push(WIRE_OBJECT_HANDLE);
            encoded.extend_from_slice(&[0u8; 7]);
            let raw_value = handle.0 as usize as u64;
            encoded.extend_from_slice(&raw_value.to_le_bytes());
        }

        Ok((encoded, handles))
    }

    fn decode_message(data: Vec<u8>) -> io::Result<Message> {
        if data.len() < WIRE_HEADER_LEN {
            return Ok(Message::new(data));
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != WIRE_MAGIC {
            return Ok(Message::new(data));
        }

        let version = u16::from_le_bytes(data[4..6].try_into().unwrap());
        if version != WIRE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported ipc message version {version}"),
            ));
        }

        let payload_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let object_count = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

        let mut offset = WIRE_HEADER_LEN;
        if data.len() < offset + payload_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "ipc payload truncated, offset {}, data length {}, expected {}: {data:?}",
                    offset,
                    data.len(),
                    offset + payload_len
                ),
            ));
        }

        let payload = data[offset..offset + payload_len].to_vec();
        offset += payload_len;

        let mut objects = Vec::with_capacity(object_count);
        for _ in 0..object_count {
            if data.len() < offset + WIRE_HANDLE_ENTRY_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ipc handle metadata truncated",
                ));
            }

            let kind = data[offset];
            offset += 1;
            offset += 7; // reserved padding
            let handle_value = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;

            if kind != WIRE_OBJECT_HANDLE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported ipc object kind {kind}"),
                ));
            }

            if handle_value == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ipc handle value was zero",
                ));
            }
            let raw = handle_value as usize as RawHandle;
            let handle = unsafe { Handle::from_raw_handle(raw) };
            objects.push(Object::Handle(handle));
        }

        if offset != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ipc message contained trailing bytes",
            ));
        }

        Ok(Message::with_objects(payload, objects))
    }

    fn send_message(&mut self, payload: &[u8], objects: &[Object]) -> io::Result<()> {
        let (encoded, handles) = self.encode_message(payload, objects)?;
        #[cfg(feature = "verbose")]
        tracing::info!(
            "[ipc::windows] send_message sending encoded of size {}: {encoded:?}",
            encoded.len()
        );
        if let Err(err) = self.write_from(&encoded) {
            self.cleanup_handles(&handles);
            return Err(err);
        }

        if let Err(err) = self.flush_pipe() {
            self.cleanup_handles(&handles);
            return Err(err);
        }

        Ok(())
    }

    fn write_from(&mut self, buf: &[u8]) -> io::Result<()> {
        let written = self.io.write_blocking(buf)?;
        if written != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short named pipe write",
            ));
        }
        Ok(())
    }

    fn flush_pipe(&mut self) -> io::Result<()> {
        self.io.flush_blocking()
    }

    fn raw_handle(&self) -> RawHandle {
        self.io.source()
    }

    fn duplicate_handle_for_peer(&self, handle: &Handle) -> io::Result<Foundation::HANDLE> {
        let Some(peer) = self.peer_process.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ipc peer process handle unavailable for duplicating handles",
            ));
        };

        let mut duplicated = Foundation::HANDLE::default();
        unsafe {
            Foundation::DuplicateHandle(
                Threading::GetCurrentProcess(),
                handle.as_foundation_handle(),
                peer.as_foundation_handle(),
                &mut duplicated,
                0,
                false,
                Foundation::DUPLICATE_SAME_ACCESS,
            )
            .map_err(io::Error::from)?;
        }

        if duplicated.is_invalid() {
            return Err(io::Error::other("DuplicateHandle returned invalid handle"));
        }

        Ok(duplicated)
    }

    fn cleanup_handles(&self, handles: &[Foundation::HANDLE]) {
        if handles.is_empty() {
            return;
        }

        let Some(peer) = self.peer_process.as_ref() else {
            return;
        };

        for handle in handles {
            if handle.is_invalid() {
                continue;
            }

            let _ = unsafe {
                Foundation::DuplicateHandle(
                    peer.as_foundation_handle(),
                    *handle,
                    Threading::GetCurrentProcess(),
                    ptr::null_mut(),
                    0,
                    false,
                    Foundation::DUPLICATE_CLOSE_SOURCE,
                )
            };
        }
    }
}

impl Pod {
    fn from_parts(connection: Connection, message: Message, credentials: Credentials) -> Self {
        Self {
            connection,
            message: Some(message),
            credentials,
        }
    }

    pub fn into_parts(mut self) -> (Connection, Vec<u8>, Vec<Object>) {
        match self.message.take() {
            Some(message) => (self.connection, message.payload, message.objects),
            None => (self.connection, Vec::new(), Vec::new()),
        }
    }

    pub fn split(mut self) -> (Connection, Message) {
        let connection = self.connection;
        match self.message.take() {
            Some(message) => (connection, message),
            None => (connection, Message::default()),
        }
    }

    pub fn take(mut self) -> Message {
        self.message
            .take()
            .unwrap_or_else(|| Message::with_objects(Vec::new(), Vec::new()))
    }

    pub fn reply(&self, payload: &[u8], objects: &[Object]) -> io::Result<()> {
        self.connection.reply(payload, objects)
    }

    /// Get the peer process credentials (if available)
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }
}

impl AsSource for Pod {
    fn source(&self) -> RawHandle {
        self.connection.raw_handle()
    }
}

impl AsSource for Endpoint {
    fn source(&self) -> RawHandle {
        self.connection.raw_handle()
    }
}

impl AsSource for Connection {
    fn source(&self) -> RawHandle {
        self.raw_handle()
    }
}

impl Endpoint {
    /// Receives a message from the connection, blocking until a message is available.
    ///
    /// This implementation uses overlapped I/O with a polling strategy to handle Windows
    /// named pipe behavior. On Windows, when a named pipe is closed by the peer while an
    /// overlapped read is pending, `GetOverlappedResult` can return `ERROR_BROKEN_PIPE`
    /// even if data was successfully transferred before closure.
    ///
    /// To work around this, we:
    /// 1. Start an overlapped read operation
    /// 2. Poll with short intervals (100μs) rather than blocking indefinitely
    /// 3. Check for both successful completion and graceful connection closure
    ///
    /// This approach provides:
    /// - Near-zero CPU usage (100μs sleep intervals)
    /// - Reliable message delivery even when peer closes immediately after sending
    /// - Proper handling of connection lifecycle events
    ///
    /// The key insight is that `GetOverlappedResult` was enhanced to return success when
    /// bytes were transferred before `ERROR_BROKEN_PIPE`, allowing us to receive the final
    /// message even if the connection closes during the read.
    pub fn recv(&mut self) -> io::Result<Message> {
        self.connection.recv_blocking()
    }

    pub fn try_recv(&mut self) -> io::Result<Message> {
        match self.connection.try_recv()? {
            Some(message) => Ok(message),
            None => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no data available",
            )),
        }
    }

    pub fn send(&mut self, payload: &[u8], objects: &[Object]) -> io::Result<()> {
        self.connection.reply(payload, objects)
    }
}

fn is_connection_closed(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
    ) || matches!(
        err.raw_os_error(),
        Some(code)
            if code == Foundation::ERROR_BROKEN_PIPE.0 as i32
                || code == Foundation::ERROR_NO_DATA.0 as i32
                || code == Foundation::ERROR_PIPE_NOT_CONNECTED.0 as i32
                || code == Foundation::ERROR_CONNECTION_INVALID.0 as i32
                || code == Foundation::ERROR_NETNAME_DELETED.0 as i32
    )
}

/// Get credentials for the current process (for testing)
impl Credentials {
    pub fn current_process() -> io::Result<Credentials> {
        let process_handle = unsafe { Threading::GetCurrentProcess() };
        Self::from_process(process_handle, std::process::id())
    }

    pub fn from_pipe(pipe_handle: Foundation::HANDLE) -> io::Result<Credentials> {
        // Get the client process ID from the named pipe
        let mut pid = 0u32;
        unsafe {
            Pipes::GetNamedPipeClientProcessId(pipe_handle, &mut pid).map_err(io::Error::from)?
        }

        if pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to get client process ID",
            ));
        }

        // Open the client process with limited access
        let process_handle = unsafe {
            Threading::OpenProcess(
                Threading::PROCESS_QUERY_INFORMATION | Threading::PROCESS_VM_READ,
                false,
                pid,
            )
            .map(|h| Owned::new(h))
            .map_err(io::Error::from)?
        };

        Self::from_process(*process_handle, pid)
    }

    /// Helper function to get credentials from a process handle
    fn from_process(process: Foundation::HANDLE, pid: u32) -> io::Result<Credentials> {
        // Open the process token
        let mut token = Owned::<Foundation::HANDLE>::default();
        unsafe { Threading::OpenProcessToken(process, Security::TOKEN_QUERY, &mut *token)? };

        // Get user SID
        let uid = get_token_user_sid(*token)?;

        // Get group SIDs
        let gid_list = get_token_group_sids(*token)?;

        // Check if the process is elevated (admin)
        let is_privileged = is_token_elevated(*token)?;

        Ok(Credentials {
            pid,
            uid,
            gid_list,
            is_privileged,
        })
    }
}

/// Get the user SID from a token as a string
fn get_token_user_sid(token: Foundation::HANDLE) -> io::Result<String> {
    let mut token_user_buffer = vec![0u8; 256];
    let mut return_length = 0u32;

    unsafe {
        Security::GetTokenInformation(
            token,
            Security::TokenUser,
            Some(token_user_buffer.as_mut_ptr() as _),
            token_user_buffer.len() as u32,
            &mut return_length,
        )
        .map_err(io::Error::from)?;
    }

    let token_user = unsafe { &*(token_user_buffer.as_ptr() as *const Security::TOKEN_USER) };
    sid_to_string(token_user.User.Sid)
}

/// Get the group SIDs from a token as strings
fn get_token_group_sids(token: Foundation::HANDLE) -> io::Result<Vec<String>> {
    let mut token_groups_buffer = vec![0u8; 2048];
    let mut return_length = 0u32;

    unsafe {
        Security::GetTokenInformation(
            token,
            Security::TokenGroups,
            Some(token_groups_buffer.as_mut_ptr() as _),
            token_groups_buffer.len() as u32,
            &mut return_length,
        )
        .map_err(io::Error::from)?;
    }

    let token_groups = unsafe { &*(token_groups_buffer.as_ptr() as *const Security::TOKEN_GROUPS) };
    let groups_slice = unsafe {
        std::slice::from_raw_parts(
            token_groups.Groups.as_ptr(),
            token_groups.GroupCount as usize,
        )
    };

    let mut group_sids = Vec::new();
    for group in groups_slice {
        if let Ok(sid_string) = sid_to_string(group.Sid) {
            group_sids.push(sid_string);
        }
    }

    Ok(group_sids)
}

/// Check if a token is elevated (has admin privileges)
fn is_token_elevated(token: Foundation::HANDLE) -> io::Result<bool> {
    let mut elevation = Security::TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut return_length = 0u32;

    unsafe {
        Security::GetTokenInformation(
            token,
            Security::TokenElevation,
            Some(&mut elevation as *mut _ as _),
            std::mem::size_of::<Security::TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )
        .map_err(io::Error::from)?;
    }

    Ok(elevation.TokenIsElevated != 0)
}

/// Convert a Windows SID to a string representation
fn sid_to_string(sid: Security::PSID) -> io::Result<String> {
    let mut sid_string = windows::core::PWSTR::null();

    let result = unsafe {
        Security::Authorization::ConvertSidToStringSidW(sid, &mut sid_string)
            .map_err(io::Error::from)?;

        // Convert PWSTR to String
        sid_string.to_string().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid SID string: {}", e),
            )
        })
    };

    unsafe { Foundation::LocalFree(Some(Foundation::HLOCAL(sid_string.0 as _))) };

    result
}

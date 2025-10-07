use std::collections::{HashMap, VecDeque};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fs, io};

use crate::poll::{Events, FdSource, Interest, Poller, SeqpacketSource, Token};
use crate::seqpacket::{UCred, UnixSeqpacket, UnixSeqpacketListener};

use super::{
    Message, Object, {Credentials, IntoServiceDescriptor, Policy},
};

const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024 + 4;
const MAX_ANCILLARY_FDS: usize = 253;

pub struct Listener {
    path: PathBuf,
    listener: UnixSeqpacketListener,
    poller: Poller,
    source: FdSource,
    token: Token,
    events: Events,
    connections: HashMap<Token, Connection>,
    backlog: VecDeque<Pod>,
    acl: Policy,
}

pub struct Endpoint {
    source: SeqpacketSource,
}

#[derive(Clone)]
pub struct Connection {
    source: Arc<Mutex<SeqpacketSource>>,
}

pub struct Pod {
    connection: Connection,
    message: Option<Message>,
    credentials: Credentials,
}

impl Listener {
    pub fn bind<P: IntoServiceDescriptor>(path: P) -> io::Result<Self> {
        let descriptor = path.into_service_descriptor();
        let path = resolve_socket_path(&descriptor.name);
        if path.exists()
            && let Err(err) = fs::remove_file(&path)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(err);
        }

        let listener = UnixSeqpacketListener::bind(&path)?;
        listener.set_nonblocking(true)?;

        if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(0o666)) {
            crate::warn!(
                "failed to set socket permissions for {}: {e}",
                path.display(),
            );
        }

        let mut poller = Poller::new()?;
        let mut source = FdSource::new(listener.as_raw_fd());
        let token = poller.register(&mut source, Interest::READABLE)?;

        Ok(Self {
            path: path.to_path_buf(),
            listener,
            poller,
            source,
            token,
            events: Events::with_capacity(64),
            connections: HashMap::new(),
            backlog: VecDeque::new(),
            acl: descriptor.policy,
        })
    }

    pub fn accept(&mut self) -> io::Result<Pod> {
        loop {
            if let Some(pod) = self.backlog.pop_front() {
                return Ok(pod);
            }

            self.poll_once(None)?;
        }
    }

    pub fn try_accept(&mut self) -> io::Result<Option<Pod>> {
        if let Some(pod) = self.backlog.pop_front() {
            return Ok(Some(pod));
        }

        self.poll_once(Some(Duration::from_millis(0)))?;

        Ok(self.backlog.pop_front())
    }

    pub fn local_path(&self) -> &Path {
        &self.path
    }
}

impl Listener {
    fn poll_once(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.events.clear();
        self.poller.poll(&mut self.events, timeout)?;

        let events: Vec<Token> = self.events.iter().map(|event| event.token()).collect();

        for token in events {
            if token == self.token {
                self.accept_connection()?;
                continue;
            }

            if token == Token::WAKER {
                continue;
            }

            self.drain_connection(token)?;
        }

        Ok(())
    }

    fn accept_connection(&mut self) -> io::Result<()> {
        loop {
            match self.listener.accept() {
                Ok((socket, _)) => {
                    let mut connection = Connection::from_socket(socket)?;
                    let token = connection.register(&mut self.poller, Interest::READABLE)?;
                    self.connections.insert(token, connection);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::TimedOut => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }

        self.poller
            .reregister(&mut self.source, self.token, Interest::READABLE)?;

        Ok(())
    }

    fn drain_connection(&mut self, token: Token) -> io::Result<()> {
        let Some(mut connection) = self.connections.get(&token).cloned() else {
            return Ok(());
        };

        loop {
            match connection.recv_message() {
                Ok(Some(message)) => {
                    let credentials = connection.peer_cred().and_then(Credentials::try_from)?;

                    if !self.acl.is_unrestricted()
                        && let Err(err) = self.acl.check(&credentials)
                    {
                        crate::warn!("ACL check failed: {}", err);
                        self.remove_connection(token)?;
                        return Err(err);
                    }

                    self.backlog.push_back(Pod::from_parts(
                        connection.clone(),
                        message,
                        credentials,
                    ));
                }
                Ok(None) => {
                    self.remove_connection(token)?;
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut =>
                {
                    if self.connections.contains_key(&token) {
                        connection.reregister(&mut self.poller, token, Interest::READABLE)?;
                    }
                    break;
                }
                Err(err) => {
                    self.remove_connection(token)?;
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    fn remove_connection(&mut self, token: Token) -> io::Result<()> {
        if let Some(mut connection) = self.connections.remove(&token)
            && let Err(err) = connection.deregister(&mut self.poller, token)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(err);
        }
        Ok(())
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if self.path.exists()
            && let Err(err) = fs::remove_file(&self.path)
        {
            crate::debug!(
                "failed to remove socket file {}: {err}",
                self.path.display(),
            );
        }

        let tokens: Vec<Token> = self.connections.keys().copied().collect();
        for token in tokens {
            let _ = self.remove_connection(token);
        }
        self.backlog.clear();
    }
}

impl Endpoint {
    pub fn connect<P: IntoServiceDescriptor>(path: P) -> io::Result<Self> {
        let descriptor = path.into_service_descriptor();
        let path = resolve_socket_path(&descriptor.name);
        let socket = UnixSeqpacket::connect(&path)?;
        Ok(Self {
            source: SeqpacketSource::new(socket),
        })
    }

    pub fn socket(&self) -> &UnixSeqpacket {
        self.source.socket()
    }

    pub fn socket_mut(&mut self) -> &mut UnixSeqpacket {
        self.source.socket_mut()
    }

    pub fn peer_cred(&self) -> io::Result<UCred> {
        self.socket().peer_cred()
    }

    pub fn send(&mut self, payload: &[u8], objects: &[Object]) -> io::Result<()> {
        Connection::send_datagram(&self.source, payload, objects)
    }

    pub fn recv(&mut self) -> io::Result<Message> {
        self.socket().set_nonblocking(false)?;

        loop {
            match Connection::try_recv(&mut self.source) {
                Ok(Some(message)) => return Ok(message),
                Ok(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    ));
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
    }

    pub fn try_recv(&mut self) -> io::Result<Message> {
        self.socket().set_nonblocking(true)?;

        match Connection::try_recv(&mut self.source)? {
            Some(message) => Ok(message),
            None => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no data available",
            )),
        }
    }
}

impl std::ops::Deref for Endpoint {
    type Target = SeqpacketSource;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

impl std::ops::DerefMut for Endpoint {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.source
    }
}

impl Connection {
    fn from_socket(socket: UnixSeqpacket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            source: Arc::new(Mutex::new(SeqpacketSource::new(socket))),
        })
    }

    fn register(&mut self, poller: &mut Poller, interest: Interest) -> io::Result<Token> {
        self.with_source(|source| poller.register(source, interest))
    }

    fn deregister(&mut self, poller: &mut Poller, token: Token) -> io::Result<()> {
        self.with_source(|source| poller.deregister(source, token))
    }

    fn reregister(
        &mut self,
        poller: &mut Poller,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        self.with_source(|source| poller.reregister(source, token, interest))
    }

    fn with_source<F, T>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce(&mut SeqpacketSource) -> io::Result<T>,
    {
        let mut guard = self
            .source
            .lock()
            .map_err(|err| io::Error::other(err.to_string()))?;
        f(&mut guard)
    }

    fn recv_message(&self) -> io::Result<Option<Message>> {
        self.with_source(Self::try_recv)
    }

    pub fn peer_cred(&self) -> io::Result<UCred> {
        self.with_source(|source| source.socket().peer_cred())
    }

    pub fn reply(&self, payload: &[u8], objects: &[Object]) -> io::Result<()> {
        self.with_source(|source| Self::send_datagram(source, payload, objects))
    }
}

struct Datagram {
    payload: Vec<u8>,
    objects: Vec<Object>,
}

impl Datagram {
    fn into_message(self) -> Message {
        Message::with_objects(self.payload, self.objects)
    }
}

impl Connection {
    fn try_recv_datagram(source: &mut SeqpacketSource) -> io::Result<Option<Datagram>> {
        let length = loop {
            let mut length_uninit_slice = [MaybeUninit::zeroed()];
            let mut buffer_uninit_slices =
                [socket2::MaybeUninitSlice::new(&mut length_uninit_slice)];
            let mut msg_hdr = socket2::MsgHdrMut::new().with_buffers(&mut buffer_uninit_slices);
            match source
                .socket()
                .recvmsg(&mut msg_hdr, libc::MSG_PEEK | libc::MSG_TRUNC)
            {
                Ok(0) => return Ok(None),
                Ok(ret) if ret > MAX_MESSAGE_SIZE => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ipc message exceeds maximum size",
                    ));
                }
                Ok(ret) => break ret,
                Err(err) => match err.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => return Err(err),
                    _ => return Err(err),
                },
            };
        };

        let mut payload = vec![0u8; length];
        let ancillary_capacity = unsafe {
            libc::CMSG_SPACE((MAX_ANCILLARY_FDS * std::mem::size_of::<libc::c_int>()) as u32)
                as usize
        };
        let mut control = if ancillary_capacity == 0 {
            Vec::new()
        } else {
            vec![0u8; ancillary_capacity]
        };

        let payload_uninit =
            unsafe { std::slice::from_raw_parts_mut(payload.as_mut_ptr().cast(), payload.len()) };
        let mut payload_slices = [socket2::MaybeUninitSlice::new(payload_uninit)];
        let mut msg_hdr = socket2::MsgHdrMut::new().with_buffers(&mut payload_slices);

        if !control.is_empty() {
            let control_uninit = unsafe {
                std::slice::from_raw_parts_mut(
                    control.as_mut_ptr() as *mut MaybeUninit<u8>,
                    control.len(),
                )
            };
            msg_hdr = msg_hdr.with_control(control_uninit);
        }

        let ret = loop {
            match source
                .socket()
                .recvmsg(&mut msg_hdr, libc::MSG_CMSG_CLOEXEC | libc::MSG_NOSIGNAL)
            {
                Ok(0) => return Ok(None),
                Ok(n) => break n,
                Err(err) => match err.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => return Err(err),
                    _ => return Err(err),
                },
            }
        };

        if msg_hdr.flags().is_truncated() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ipc message truncated",
            ));
        }

        let raw_flags: libc::c_int = unsafe { std::mem::transmute(msg_hdr.flags()) };
        if raw_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ipc ancillary data truncated",
            ));
        }

        payload.truncate(ret);
        let control_len = msg_hdr.control_len();
        control.truncate(control_len);

        let objects = Self::decode_objects(&mut control)?;
        Ok(Some(Datagram { payload, objects }))
    }

    fn try_recv(source: &mut SeqpacketSource) -> io::Result<Option<Message>> {
        match Self::try_recv_datagram(source)? {
            Some(dg) => Ok(Some(dg.into_message())),
            None => Ok(None),
        }
    }

    fn decode_objects(control: &mut [u8]) -> io::Result<Vec<Object>> {
        if control.is_empty() {
            return Ok(Vec::new());
        }

        let mut objects = Vec::new();

        unsafe {
            let mut msg_hdr: libc::msghdr = std::mem::zeroed();
            msg_hdr.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg_hdr.msg_controllen = control.len();

            let mut header = libc::CMSG_FIRSTHDR(&msg_hdr);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    let data_len = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let fd_count = data_len / std::mem::size_of::<libc::c_int>();
                    let data = libc::CMSG_DATA(header) as *const libc::c_int;
                    for idx in 0..fd_count {
                        let fd = *data.add(idx);
                        if fd >= 0 {
                            objects.push(Object::Fd(OwnedFd::from_raw_fd(fd)));
                        }
                    }
                }

                header = libc::CMSG_NXTHDR(&msg_hdr, header);
            }
        }

        Ok(objects)
    }

    fn send_datagram(
        source: &SeqpacketSource,
        payload: &[u8],
        objects: &[Object],
    ) -> io::Result<()> {
        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ipc message exceeds maximum size",
            ));
        }

        let objects = objects
            .iter()
            .map(|object| match object {
                Object::Fd(fd) => fd.as_raw_fd(),
            })
            .collect::<Vec<_>>();

        let mut control = if objects.is_empty() {
            Vec::new()
        } else {
            let bytes = (objects.len() * std::mem::size_of::<libc::c_int>()) as u32;
            let size = unsafe { libc::CMSG_SPACE(bytes) } as usize;
            vec![0u8; size]
        };

        if !objects.is_empty() {
            unsafe {
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
                msg.msg_controllen = control.len();

                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if cmsg.is_null() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "failed to encode ancillary data",
                    ));
                }

                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len =
                    libc::CMSG_LEN((objects.len() * std::mem::size_of::<libc::c_int>()) as u32)
                        as usize;

                let data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
                std::ptr::copy_nonoverlapping(objects.as_ptr(), data, objects.len());

                let used = (*cmsg).cmsg_len as usize;
                control.truncate(used);
            }
        }

        let mut msg_hdr = socket2::MsgHdr::new();
        let mut buffers = Vec::new();
        if !payload.is_empty() {
            buffers.push(io::IoSlice::new(payload));
            msg_hdr = msg_hdr.with_buffers(&buffers);
        }

        if !control.is_empty() {
            msg_hdr = msg_hdr.with_control(&control);
        }

        let sent = source.socket().sendmsg(&msg_hdr, libc::MSG_NOSIGNAL)?;
        if sent != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short seqpacket write",
            ));
        }

        Ok(())
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

    pub fn peer_cred(&self) -> io::Result<UCred> {
        self.connection.peer_cred()
    }

    pub fn reply(&self, payload: &[u8], objects: &[Object]) -> io::Result<()> {
        self.connection.reply(payload, objects)
    }

    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }
}

impl AsRawFd for Endpoint {
    fn as_raw_fd(&self) -> RawFd {
        self.source.socket().as_raw_fd()
    }
}

impl AsRawFd for Connection {
    fn as_raw_fd(&self) -> RawFd {
        self.source
            .lock()
            .expect("connection poisoned")
            .socket()
            .as_raw_fd()
    }
}

fn resolve_socket_path<P: AsRef<str>>(path: P) -> PathBuf {
    let p = Path::new(path.as_ref());
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new("/tmp").join(p)
    }
}

impl Credentials {
    pub fn current_process() -> io::Result<Credentials> {
        let pid = std::process::id();
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let egid = unsafe { libc::getegid() };

        let mut groups = Vec::with_capacity(16);
        let ngroups = groups.capacity() as libc::c_int;
        unsafe {
            groups.set_len(ngroups as usize);
            let ret = libc::getgroups(ngroups, groups.as_mut_ptr());
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            groups.set_len(ret as usize);
        }

        let mut gid_list = vec![gid.to_string(), egid.to_string()];
        gid_list.extend(groups.into_iter().map(|g| g.to_string()));
        gid_list.sort();
        gid_list.dedup();

        Ok(Credentials {
            pid,
            uid: uid.to_string(),
            gid_list,
            is_privileged: uid == 0,
        })
    }
}

impl TryFrom<UCred> for Credentials {
    type Error = io::Error;

    fn try_from(ucred: UCred) -> Result<Self, Self::Error> {
        let pid = ucred.pid().unwrap_or(0) as u32;
        let uid = ucred.uid();
        let gid = ucred.gid();

        let gid_list = vec![gid.to_string()];

        Ok(Credentials {
            pid,
            uid: uid.to_string(),
            gid_list,
            is_privileged: uid == 0,
        })
    }
}

use std::ops::{Deref, DerefMut};
use std::os::fd::FromRawFd;
use std::os::raw::c_int;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use socket2::SockAddr;

use super::UnixSeqpacket;

pub struct UnixSeqpacketListener(pub(crate) socket2::Socket);

impl std::fmt::Debug for UnixSeqpacketListener {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("UnixSeqpacketListener")
            .field("fd", &self.0.as_raw_fd())
            .finish()
    }
}

impl UnixSeqpacketListener {
    pub fn bind<P: AsRef<Path>>(address: P) -> std::io::Result<Self> {
        Self::bind_with_backlog(address, 128)
    }

    pub fn bind_with_backlog<P: AsRef<Path>>(address: P, backlog: c_int) -> std::io::Result<Self> {
        let socket = socket2::Socket::new(super::SOCKET_DOMAIN, super::SOCKET_TYPE, None)?;
        socket.bind(&SockAddr::unix(address)?)?;
        socket.listen(backlog)?;
        Ok(Self(socket))
    }

    pub fn local_addr(&self) -> std::io::Result<PathBuf> {
        self.0.local_addr().and_then(|sockaddr| {
            sockaddr
                .as_pathname()
                .map(PathBuf::from)
                .ok_or(std::io::Error::other("Local address is not a pathname"))
        })
    }

    pub fn accept(&self) -> std::io::Result<(UnixSeqpacket, Option<PathBuf>)> {
        let (sock, addr) = self.0.accept()?;
        let path = addr.as_pathname().map(PathBuf::from);
        Ok((UnixSeqpacket(sock), path))
    }
}

impl Deref for UnixSeqpacketListener {
    type Target = socket2::Socket;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for UnixSeqpacketListener {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRawFd for UnixSeqpacketListener {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.0.as_raw_fd()
    }
}

impl FromRawFd for UnixSeqpacketListener {
    unsafe fn from_raw_fd(fd: std::os::unix::io::RawFd) -> Self {
        unsafe { Self(socket2::Socket::from_raw_fd(fd)) }
    }
}

impl IntoRawFd for UnixSeqpacketListener {
    fn into_raw_fd(self) -> std::os::unix::io::RawFd {
        self.0.into_raw_fd()
    }
}

impl AsFd for UnixSeqpacketListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl From<UnixSeqpacketListener> for OwnedFd {
    #[inline]
    fn from(listener: UnixSeqpacketListener) -> OwnedFd {
        unsafe { OwnedFd::from_raw_fd(listener.into_raw_fd()) }
    }
}

impl From<OwnedFd> for UnixSeqpacketListener {
    #[inline]
    fn from(owned: OwnedFd) -> Self {
        unsafe { Self::from_raw_fd(owned.into_raw_fd()) }
    }
}

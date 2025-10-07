use std::ops::{Deref, DerefMut};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd};
use std::path::Path;
use std::{
    io,
    io::{IoSlice, IoSliceMut},
};

use socket2::{SockAddr, Socket};

pub struct UnixSeqpacket(pub(crate) socket2::Socket);

impl std::fmt::Debug for UnixSeqpacket {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("UnixSeqpacket")
            .field("fd", &self.0.as_raw_fd())
            .finish()
    }
}

impl UnixSeqpacket {
    pub fn connect<P: AsRef<Path>>(address: P) -> std::io::Result<Self> {
        let socket = Socket::new(super::SOCKET_DOMAIN, super::SOCKET_TYPE, None)?;
        if let Err(e) = socket.connect(&SockAddr::unix(address)?)
            && e.kind() != std::io::ErrorKind::WouldBlock
        {
            return Err(e);
        }
        Ok(Self(socket))
    }

    pub fn pair() -> std::io::Result<(Self, Self)> {
        let (a, b) = Socket::pair(super::SOCKET_DOMAIN, super::SOCKET_TYPE, None)?;
        Ok((Self(a), Self(b)))
    }

    #[cfg(target_os = "linux")]
    pub fn peer_cred(&self) -> std::io::Result<super::UCred> {
        super::UCred::from_socket_peer(&self.0)
    }
}

impl io::Read for UnixSeqpacket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.0, buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        io::Read::read_vectored(&mut self.0, bufs)
    }
}

impl io::Write for UnixSeqpacket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.0, buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        io::Write::write_vectored(&mut self.0, bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.0)
    }
}

impl Deref for UnixSeqpacket {
    type Target = socket2::Socket;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for UnixSeqpacket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRawFd for UnixSeqpacket {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.0.as_raw_fd()
    }
}
impl FromRawFd for UnixSeqpacket {
    #[inline]
    unsafe fn from_raw_fd(fd: std::os::unix::io::RawFd) -> Self {
        unsafe { Self(socket2::Socket::from_raw_fd(fd)) }
    }
}

impl IntoRawFd for UnixSeqpacket {
    fn into_raw_fd(self) -> std::os::unix::io::RawFd {
        self.0.into_raw_fd()
    }
}

impl AsFd for UnixSeqpacket {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl From<UnixSeqpacket> for OwnedFd {
    #[inline]
    fn from(seqpacket: UnixSeqpacket) -> OwnedFd {
        unsafe { OwnedFd::from_raw_fd(seqpacket.into_raw_fd()) }
    }
}

impl From<OwnedFd> for UnixSeqpacket {
    #[inline]
    fn from(owned: OwnedFd) -> Self {
        unsafe { Self::from_raw_fd(owned.into_raw_fd()) }
    }
}

//! Linux-specific polling implementation using epoll.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    time::Duration,
};

use crate::{
    errno::Errno,
    poll::{Event, Events, Interest, Source, Token},
    seqpacket::UnixSeqpacket,
};

/// Linux epoll-based poller.
pub struct Poller {
    epoll: OwnedFd,
    waker: OwnedFd,
}

impl Poller {
    /// Creates a new epoll-based poller.
    pub fn new() -> io::Result<Self> {
        let epoll = unsafe {
            let fd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
            Errno::result(fd)?;
            OwnedFd::from_raw_fd(fd)
        };

        let waker = unsafe {
            let fd = libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK);
            Errno::result(fd)?;
            OwnedFd::from_raw_fd(fd)
        };

        // Register the waker with the epoll
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 0, // Token 0 reserved for waker
        };

        unsafe {
            let ret = libc::epoll_ctl(
                epoll.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                waker.as_raw_fd(),
                &mut ev,
            );
            Errno::result(ret)?;
        }

        Ok(Poller { epoll, waker })
    }

    /// Registers a file descriptor with epoll.
    pub fn register_fd(&self, fd: RawFd, token: Token, interest: Interest) -> io::Result<()> {
        let mut events = 0u32;

        if interest.is_readable() {
            events |= libc::EPOLLIN as u32;
        }

        if interest.is_writable() {
            events |= libc::EPOLLOUT as u32;
        }

        // Always enable edge-triggered mode and error detection
        events |= libc::EPOLLET as u32 | libc::EPOLLERR as u32 | libc::EPOLLHUP as u32;

        let mut ev = libc::epoll_event {
            events,
            u64: token.into_usize() as u64,
        };

        unsafe {
            let ret = libc::epoll_ctl(self.epoll.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &mut ev);
            Errno::result(ret)?;
        }

        Ok(())
    }

    /// Deregisters a file descriptor from epoll.
    pub fn deregister_fd(&self, fd: RawFd) -> io::Result<()> {
        unsafe {
            let ret = libc::epoll_ctl(
                self.epoll.as_raw_fd(),
                libc::EPOLL_CTL_DEL,
                fd,
                std::ptr::null_mut(),
            );
            // Ignore errors during deregistration (fd might already be closed)
            let _ = Errno::result(ret);
        }

        Ok(())
    }

    /// Re-registers a file descriptor with new interest.
    pub fn reregister_fd(&self, fd: RawFd, token: Token, interest: Interest) -> io::Result<()> {
        let mut events = 0u32;

        if interest.is_readable() {
            events |= libc::EPOLLIN as u32;
        }

        if interest.is_writable() {
            events |= libc::EPOLLOUT as u32;
        }

        // Always enable edge-triggered mode and error detection
        events |= libc::EPOLLET as u32 | libc::EPOLLERR as u32 | libc::EPOLLHUP as u32;

        let mut ev = libc::epoll_event {
            events,
            u64: token.into_usize() as u64,
        };

        unsafe {
            let ret = libc::epoll_ctl(self.epoll.as_raw_fd(), libc::EPOLL_CTL_MOD, fd, &mut ev);
            Errno::result(ret)?;
        }

        Ok(())
    }

    /// Polls for events.
    pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();

        let timeout_ms = timeout.map(|d| d.as_millis() as i32).unwrap_or(-1);

        let mut epoll_events = [libc::epoll_event { events: 0, u64: 0 }; 32];

        unsafe {
            let n = libc::epoll_wait(
                self.epoll.as_raw_fd(),
                epoll_events.as_mut_ptr(),
                epoll_events.len() as i32,
                timeout_ms,
            );

            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            for ep_event in &epoll_events[..n as usize] {
                let token_val = ep_event.u64 as usize;

                // Handle waker events
                if token_val == 0 {
                    self.clear_waker();
                    continue;
                }

                let token = Token::new(token_val);
                let ep_events = ep_event.events;

                let mut interest = Interest::READABLE; // Default to readable
                if (ep_events & libc::EPOLLIN as u32) != 0 {
                    interest = Interest::READABLE;
                } else if (ep_events & libc::EPOLLOUT as u32) != 0 {
                    interest = Interest::WRITABLE;
                } else if (ep_events & (libc::EPOLLERR as u32 | libc::EPOLLHUP as u32)) != 0 {
                    // Treat errors as readable events so they can be handled
                    interest = Interest::READABLE;
                }

                events.push(Event::new(token, interest));
            }
        }

        Ok(())
    }

    /// Clears the waker by reading from the eventfd.
    fn clear_waker(&self) {
        unsafe {
            let mut buffer = [0u8; 8];
            let _ = libc::read(
                self.waker.as_raw_fd(),
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                8,
            );
        }
    }
}

/// A waker that can wake up the poller from another thread.
pub struct Waker {
    waker_fd: RawFd,
}

impl Waker {
    /// Creates a new waker associated with the given poller.
    pub fn new(poller: &Poller) -> io::Result<Self> {
        Ok(Waker {
            waker_fd: poller.waker.as_raw_fd(),
        })
    }

    /// Wakes up the associated poller.
    pub fn wake(&self) -> io::Result<()> {
        unsafe {
            let value: u64 = 1;
            let ret = libc::write(
                self.waker_fd,
                &value as *const _ as *const std::ffi::c_void,
                8,
            );
            Errno::result(ret as i32)?;
        }

        Ok(())
    }
}

unsafe impl Send for Waker {}
unsafe impl Sync for Waker {}

/// Unix seqpacket socket source implementation.
pub struct SeqpacketSource {
    socket: UnixSeqpacket,
    registered_interest: Option<Interest>,
}

impl SeqpacketSource {
    /// Creates a new Unix seqpacket socket source.
    pub fn new(socket: UnixSeqpacket) -> Self {
        SeqpacketSource {
            socket,
            registered_interest: None,
        }
    }

    /// Returns a reference to the underlying socket.
    pub fn socket(&self) -> &UnixSeqpacket {
        &self.socket
    }

    /// Returns a mutable reference to the underlying socket.
    pub fn socket_mut(&mut self) -> &mut UnixSeqpacket {
        &mut self.socket
    }
}

impl Source for SeqpacketSource {
    fn register(
        &mut self,
        poller: &mut crate::poll::Poller,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        if self.registered_interest.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Source already registered",
            ));
        }

        let fd = self.socket.as_raw_fd();
        poller.inner().register_fd(fd, token, interest)?;

        self.registered_interest = Some(interest);
        Ok(())
    }

    fn deregister(&mut self, poller: &mut crate::poll::Poller) -> io::Result<()> {
        if self.registered_interest.is_some() {
            let fd = self.socket.as_raw_fd();
            poller.inner().deregister_fd(fd)?;
            self.registered_interest = None;
        }
        Ok(())
    }

    fn reregister(
        &mut self,
        poller: &mut crate::poll::Poller,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        if self.registered_interest.is_some() {
            let fd = self.socket.as_raw_fd();
            poller.inner().reregister_fd(fd, token, interest)?;
            self.registered_interest = Some(interest);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Source not registered",
            ));
        }
        Ok(())
    }
}

/// A generic file descriptor source for Linux.
pub struct FdSource {
    fd: RawFd,
    registered_interest: Option<Interest>,
}

impl FdSource {
    /// Creates a new file descriptor source.
    pub fn new(fd: RawFd) -> Self {
        FdSource {
            fd,
            registered_interest: None,
        }
    }

    /// Returns the raw file descriptor.
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Source for FdSource {
    fn register(
        &mut self,
        poller: &mut crate::poll::Poller,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        if self.registered_interest.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Source already registered",
            ));
        }

        poller.inner().register_fd(self.fd, token, interest)?;

        self.registered_interest = Some(interest);
        Ok(())
    }

    fn deregister(&mut self, poller: &mut crate::poll::Poller) -> io::Result<()> {
        if self.registered_interest.is_some() {
            poller.inner().deregister_fd(self.fd)?;
            self.registered_interest = None;
        }
        Ok(())
    }

    fn reregister(
        &mut self,
        poller: &mut crate::poll::Poller,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        if self.registered_interest.is_some() {
            poller.inner().reregister_fd(self.fd, token, interest)?;
            self.registered_interest = Some(interest);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Source not registered",
            ));
        }
        Ok(())
    }
}

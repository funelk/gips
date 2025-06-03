//! macOS-specific polling implementation using kqueue.
// spell-checker:ignore fflags udata MACHPORT kevents timespec subsec nsec

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr,
    time::Duration,
};

use mach2::message::MACH_RCV_MSG;

use crate::{
    errno::Errno,
    mach::Port,
    poll::{Event, Events, Interest, Source, Token},
};

pub struct Poller {
    kqueue: OwnedFd,
    waker_ident: usize,
}

impl Poller {
    pub fn new() -> io::Result<Self> {
        let kqueue = unsafe {
            let fd = libc::kqueue();
            Errno::result(fd)?;
            OwnedFd::from_raw_fd(fd)
        };

        // Set up a user event for waking up
        let waker_ident = 0xDEADBEEF; // Unique identifier for the waker
        let waker_event = libc::kevent {
            ident: waker_ident,
            filter: libc::EVFILT_USER,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: 0,
            data: 0,
            udata: ptr::null_mut(),
        };

        unsafe {
            let ret = libc::kevent(
                kqueue.as_raw_fd(),
                &waker_event,
                1,
                ptr::null_mut(),
                0,
                ptr::null(),
            );
            Errno::result(ret)?;
        }

        Ok(Poller {
            kqueue,
            waker_ident,
        })
    }

    pub fn register_mach_port(&self, mach_port: &Port, token: Token) -> io::Result<()> {
        let event = libc::kevent {
            ident: mach_port.raw() as usize,
            filter: libc::EVFILT_MACHPORT,
            flags: libc::EV_ADD | libc::EV_ENABLE,
            fflags: MACH_RCV_MSG as _,
            data: 0,
            udata: token.into_usize() as *mut std::ffi::c_void,
        };

        Errno::result(unsafe {
            libc::kevent(
                self.kqueue.as_raw_fd(),
                &event,
                1,
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        })?;

        Ok(())
    }

    pub fn deregister_mach_port(&self, mach_port: &Port) -> io::Result<()> {
        let event = libc::kevent {
            ident: mach_port.raw() as usize,
            filter: libc::EVFILT_MACHPORT,
            flags: libc::EV_DELETE,
            fflags: 0,
            data: 0,
            udata: ptr::null_mut(),
        };

        let ret = unsafe {
            libc::kevent(
                self.kqueue.as_raw_fd(),
                &event,
                1,
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // Ignore attempts to remove ports that were not registered.
            if err.kind() != io::ErrorKind::NotFound {
                return Err(err);
            }
        }

        Ok(())
    }

    pub fn register_fd(&self, fd: RawFd, token: Token, interest: Interest) -> io::Result<()> {
        let mut events = Vec::new();

        if interest.is_readable() {
            events.push(libc::kevent {
                ident: fd as usize,
                filter: libc::EVFILT_READ,
                flags: libc::EV_ADD | libc::EV_RECEIPT,
                fflags: 0,
                data: 0,
                udata: token.into_usize() as *mut std::ffi::c_void,
            });
        }

        if interest.is_writable() {
            events.push(libc::kevent {
                ident: fd as usize,
                filter: libc::EVFILT_WRITE,
                flags: libc::EV_ADD | libc::EV_RECEIPT,
                fflags: 0,
                data: 0,
                udata: token.into_usize() as *mut std::ffi::c_void,
            });
        }

        for event in &events {
            unsafe {
                let ret = libc::kevent(
                    self.kqueue.as_raw_fd(),
                    event,
                    1,
                    ptr::null_mut(),
                    0,
                    ptr::null(),
                );
                Errno::result(ret)?;
            }
        }

        Ok(())
    }

    pub fn deregister_fd(&self, fd: RawFd, interest: Interest) -> io::Result<()> {
        let mut events = Vec::new();

        if interest.is_readable() {
            events.push(libc::kevent {
                ident: fd as usize,
                filter: libc::EVFILT_READ,
                flags: libc::EV_DELETE,
                fflags: 0,
                data: 0,
                udata: ptr::null_mut(),
            });
        }

        if interest.is_writable() {
            events.push(libc::kevent {
                ident: fd as usize,
                filter: libc::EVFILT_WRITE,
                flags: libc::EV_DELETE,
                fflags: 0,
                data: 0,
                udata: ptr::null_mut(),
            });
        }

        for event in &events {
            unsafe {
                let ret = libc::kevent(
                    self.kqueue.as_raw_fd(),
                    event,
                    1,
                    ptr::null_mut(),
                    0,
                    ptr::null(),
                );
                // Ignore errors during deregistration
                let _ = Errno::result(ret);
            }
        }

        Ok(())
    }

    pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();

        let timeout = timeout.map(|t| libc::timespec {
            tv_sec: t.as_secs() as libc::time_t,
            tv_nsec: t.subsec_nanos() as libc::c_long,
        });

        let mut kevents = [libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: ptr::null_mut(),
        }; 32];

        let n = unsafe {
            libc::kevent(
                self.kqueue.as_raw_fd(),
                ptr::null(),
                0,
                kevents.as_mut_ptr(),
                kevents.len() as i32,
                timeout.as_ref().map_or(ptr::null(), |t| t),
            )
        };
        Errno::result(n)?;

        for kevent in &kevents[..n as usize] {
            // Skip waker events
            if kevent.ident == self.waker_ident {
                continue;
            }

            let token = Token::new(kevent.udata as usize);
            let interest = match kevent.filter {
                libc::EVFILT_READ | libc::EVFILT_MACHPORT => Interest::READABLE,
                libc::EVFILT_WRITE => Interest::WRITABLE,
                _ => continue,
            };

            events.push(Event::new(token, interest));
        }

        Ok(())
    }
}

pub struct Waker {
    kqueue: RawFd,
    waker_ident: usize,
}

impl Waker {
    pub fn new(poller: &Poller) -> io::Result<Self> {
        Ok(Waker {
            kqueue: poller.kqueue.as_raw_fd(),
            waker_ident: poller.waker_ident,
        })
    }

    pub fn wake(&self) -> io::Result<()> {
        let event = libc::kevent {
            ident: self.waker_ident,
            filter: libc::EVFILT_USER,
            flags: 0,
            fflags: libc::NOTE_TRIGGER,
            data: 0,
            udata: ptr::null_mut(),
        };

        unsafe {
            let ret = libc::kevent(self.kqueue, &event, 1, ptr::null_mut(), 0, ptr::null());
            Errno::result(ret)?;
        }

        Ok(())
    }
}

unsafe impl Send for Waker {}
unsafe impl Sync for Waker {}

pub struct MachPortSource {
    port: Port,
    registered: bool,
}

impl MachPortSource {
    pub fn new(port: Port) -> Self {
        MachPortSource {
            port,
            registered: false,
        }
    }

    pub fn port(&self) -> &Port {
        &self.port
    }

    pub fn port_mut(&mut self) -> &mut Port {
        &mut self.port
    }
}

impl Source for MachPortSource {
    fn register(
        &mut self,
        poller: &mut crate::poll::Poller,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        if !interest.is_readable() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mach ports only support readable interest",
            ));
        }

        if self.registered {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Source already registered",
            ));
        }

        poller.inner().register_mach_port(&self.port, token)?;

        self.registered = true;
        Ok(())
    }

    fn deregister(&mut self, poller: &mut crate::poll::Poller) -> io::Result<()> {
        if self.registered {
            poller.inner().deregister_mach_port(&self.port)?;
        }
        self.registered = false;
        Ok(())
    }

    fn reregister(
        &mut self,
        poller: &mut crate::poll::Poller,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        self.deregister(poller)?;
        self.register(poller, token, interest)
    }
}

pub struct FdSource {
    fd: RawFd,
    registered_interest: Option<Interest>,
}

impl FdSource {
    pub fn new(fd: RawFd) -> Self {
        FdSource {
            fd,
            registered_interest: None,
        }
    }

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
        if let Some(interest) = self.registered_interest.take() {
            poller.inner().deregister_fd(self.fd, interest)?;
        }
        Ok(())
    }

    fn reregister(
        &mut self,
        poller: &mut crate::poll::Poller,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        if let Some(old_interest) = self.registered_interest {
            let inner = poller.inner();
            inner.deregister_fd(self.fd, old_interest)?;
            inner.register_fd(self.fd, token, interest)?;
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

mod listener;
mod socket;

use libc::{gid_t, pid_t, uid_t};

pub const SOCKET_DOMAIN: socket2::Domain = socket2::Domain::UNIX;
pub const SOCKET_TYPE: socket2::Type = socket2::Type::SEQPACKET;

pub const MAX_BUF_SIZE: usize = 64 << 10;

pub use listener::UnixSeqpacketListener;
pub use socket::UnixSeqpacket;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct UCred {
    uid: uid_t,
    gid: gid_t,
    pid: pid_t,
}

#[cfg(target_os = "linux")]
impl UCred {
    pub fn from_socket_peer<T: AsRawFd>(socket: &T) -> std::io::Result<Self> {
        use libc::{SO_PEERCRED, SOL_SOCKET, c_void, getsockopt, socklen_t, ucred};
        use std::os::unix::io::AsRawFd;

        let mut ucred = ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut ucred_size = std::mem::size_of::<ucred>() as socklen_t;

        let ret = unsafe {
            getsockopt(
                socket.as_raw_fd(),
                SOL_SOCKET,
                SO_PEERCRED,
                &mut ucred as *mut ucred as *mut c_void,
                &mut ucred_size,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(UCred {
            uid: ucred.uid,
            gid: ucred.gid,
            pid: ucred.pid,
        })
    }

    pub fn uid(&self) -> uid_t {
        self.uid
    }

    pub fn gid(&self) -> gid_t {
        self.gid
    }

    pub fn pid(&self) -> Option<pid_t> {
        if self.pid == 0 { None } else { Some(self.pid) }
    }
}

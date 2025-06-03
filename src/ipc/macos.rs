use std::{ffi::CString, io, mem, ops, ptr, slice};

use mach2::{
    bootstrap::{BOOTSTRAP_SUCCESS, bootstrap_check_in, bootstrap_look_up},
    kern_return::{KERN_SUCCESS, kern_return_t},
    message::{
        MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_SUCCESS,
        MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_VIRTUAL_COPY,
        MACH_MSGH_BITS_COMPLEX, MACH_RCV_BODY_ERROR, MACH_RCV_HEADER_ERROR, MACH_RCV_IN_PROGRESS,
        MACH_RCV_IN_PROGRESS_TIMED, MACH_RCV_IN_SET, MACH_RCV_INTERRUPT, MACH_RCV_INTERRUPTED,
        MACH_RCV_INVALID_DATA, MACH_RCV_INVALID_NAME, MACH_RCV_INVALID_NOTIFY,
        MACH_RCV_INVALID_REPLY, MACH_RCV_INVALID_TRAILER, MACH_RCV_INVALID_TYPE, MACH_RCV_LARGE,
        MACH_RCV_MSG, MACH_RCV_NOTIFY, MACH_RCV_PORT_CHANGED, MACH_RCV_PORT_DIED,
        MACH_RCV_SCATTER_SMALL, MACH_RCV_TIMED_OUT, MACH_RCV_TIMEOUT, MACH_RCV_TOO_LARGE,
        MACH_SEND_INTERRUPT, MACH_SEND_INTERRUPTED, MACH_SEND_INVALID_DATA, MACH_SEND_INVALID_DEST,
        MACH_SEND_INVALID_HEADER, MACH_SEND_INVALID_MEMORY, MACH_SEND_INVALID_NOTIFY,
        MACH_SEND_INVALID_REPLY, MACH_SEND_INVALID_RIGHT, MACH_SEND_INVALID_TRAILER,
        MACH_SEND_INVALID_TYPE, MACH_SEND_MSG_TOO_SMALL, MACH_SEND_NO_BUFFER, MACH_SEND_TIMED_OUT,
        audit_token_t, mach_msg, mach_msg_body_t, mach_msg_header_t, mach_msg_id_t,
        mach_msg_ool_descriptor_t, mach_msg_port_descriptor_t, mach_msg_return_t, mach_msg_send,
        mach_msg_timeout_t, mach_msg_trailer_t, mach_msg_type_descriptor_t,
    },
    port::{MACH_PORT_NULL, mach_port_t},
    task::task_info,
    task_info::TASK_AUDIT_TOKEN,
    traps::mach_task_self,
};

use crate::mach::{
    MachMessage, MachMessageDescriptor, Ool, OwnedMachPort, Port, mach_msgh_bits_set,
};
use crate::poll::MachPortSource;

use super::{Credentials, IntoServiceDescriptor, Message, Object, Policy};

pub struct Listener {
    listen: OwnedMachPort,
    source: MachPortSource,
    acl: Policy,
}

impl ops::Deref for Listener {
    type Target = MachPortSource;
    fn deref(&self) -> &Self::Target {
        &self.source
    }
}
impl ops::DerefMut for Listener {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.source
    }
}

pub struct Endpoint {
    source: MachPortSource,
    connection: Connection,
}

impl ops::Deref for Endpoint {
    type Target = MachPortSource;
    fn deref(&self) -> &Self::Target {
        &self.source
    }
}
impl ops::DerefMut for Endpoint {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.source
    }
}

#[derive(Clone)]
pub struct Connection {
    pub remote_port: Port, // Port we send to
    pub local_port: Port,  // Port we receive on
}

impl Connection {
    pub fn reply(&self, payload: &[u8], objects: &[Object]) -> io::Result<()> {
        if payload.is_empty() && objects.is_empty() {
            return Ok(());
        }

        let references = objects
            .iter()
            .map(|o| match o {
                Object::Port(port) => MachMessageDescriptor::Port(*port),
                Object::Ool(ool) => MachMessageDescriptor::Ool(ool.clone()),
            })
            .collect::<Vec<_>>();

        self.send(MachMessage {
            remote: self.remote_port.raw(),
            payload: payload.into(),
            descriptors: references,
        })
    }
}

impl MachMessageReceiver for Connection {
    fn as_mach_port(&self) -> &Port {
        &self.local_port
    }
}
impl MachMessageSender for Connection {}

pub struct Pod {
    connection: Connection,
    message: Option<Message>,
    credentials: Credentials,
}

impl Listener {
    pub fn bind<S: IntoServiceDescriptor>(service: S) -> io::Result<Self> {
        let descriptor = service.into_service_descriptor();
        let name = CString::new(descriptor.name.as_str())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let mut port: mach_port_t = MACH_PORT_NULL;
        let kr =
            unsafe { bootstrap_check_in(Port::bootstrap_root(), name.as_ptr() as _, &mut port) };
        if kr as u32 != BOOTSTRAP_SUCCESS {
            return Err(kernel_error("bootstrap_check_in", kr));
        }

        let listen = Port::from(port);
        let source = MachPortSource::new(listen);

        Ok(Self {
            listen: OwnedMachPort(listen),
            source,
            acl: descriptor.policy,
        })
    }

    pub fn accept(&mut self) -> io::Result<Pod> {
        loop {
            match MachMessageReceiver::recv(self)? {
                None => continue,
                Some(mach_msg) => {
                    // Get credentials from message
                    let credentials = Credentials::from_message(&mach_msg)?;

                    // Check ACL if policy is set
                    if !self.acl.is_unrestricted() {
                        self.acl.check(&credentials)?;
                    }

                    let pod = Pod::from_parts(self.listen.0, mach_msg, credentials);
                    return Ok(pod);
                }
            }
        }
    }

    pub fn try_accept(&mut self) -> io::Result<Option<Pod>> {
        // Non-blocking check for a pending client message
        match MachMessageReceiver::try_recv(self)? {
            None => Ok(None),
            Some(mach_msg) => {
                // Get credentials from message
                let credentials = Credentials::from_message(&mach_msg)?;

                // Check ACL if policy is set
                if !self.acl.is_unrestricted() {
                    self.acl.check(&credentials)?;
                }

                let pod = Pod::from_parts(self.listen.0, mach_msg, credentials);
                Ok(Some(pod))
            }
        }
    }
}

impl MachMessageReceiver for Listener {
    fn as_mach_port(&self) -> &Port {
        &self.listen
    }
}

impl Endpoint {
    pub fn connect<S: IntoServiceDescriptor>(service: S) -> io::Result<Self> {
        let descriptor = service.into_service_descriptor();
        let name = CString::new(descriptor.name.as_str())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let mut remote: mach_port_t = MACH_PORT_NULL;
        let kr =
            unsafe { bootstrap_look_up(Port::bootstrap_root(), name.as_ptr() as _, &mut remote) };
        if kr as u32 != BOOTSTRAP_SUCCESS {
            return Err(kernel_error("bootstrap_look_up", kr));
        }

        let local_port = Port::new();
        local_port.insert_right(MACH_MSG_TYPE_MAKE_SEND);

        let source = MachPortSource::new(local_port);

        Ok(Self {
            source,
            connection: Connection {
                remote_port: Port::from(remote),
                local_port,
            },
        })
    }
}

impl Pod {
    pub fn from_parts(
        local_port: Port,
        mach_msg: MachMessage<'_>,
        credentials: Credentials,
    ) -> Self {
        Self {
            connection: Connection {
                local_port,
                remote_port: Port::from(mach_msg.remote),
            },
            message: Some(Message::from(mach_msg)),
            credentials,
        }
    }

    pub fn into_parts(mut self) -> (Connection, Vec<u8>, Vec<Object>) {
        let connection = self.connection;
        match self.message.take() {
            Some(message) => (connection, message.payload, message.objects),
            None => (connection, Vec::new(), Vec::new()),
        }
    }

    pub fn split(mut self) -> (Connection, Message) {
        let connection = self.connection;
        match self.message.take() {
            Some(message) => (connection, message),
            None => (connection, Message::default()),
        }
    }

    pub fn reply(&self, payload: &[u8], objects: &[Object]) -> io::Result<()> {
        self.connection.reply(payload, objects)
    }

    pub fn take(mut self) -> Message {
        self.message
            .take()
            .unwrap_or_else(|| Message::with_objects(Vec::new(), Vec::new()))
    }

    pub fn take_message(&mut self) -> Option<Message> {
        self.message.take()
    }

    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }
}

impl Endpoint {
    pub fn recv(&mut self) -> io::Result<Message> {
        // Blocking receive
        loop {
            match self.connection.recv()? {
                Some(mach_msg) => return Ok(Message::from(mach_msg)),
                None => continue,
            }
        }
    }

    pub fn try_recv(&mut self) -> io::Result<Message> {
        // Try to receive a new message from the connection
        match self.connection.try_recv()? {
            Some(mach_msg) => Ok(Message::from(mach_msg)),
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

fn kernel_error(context: &str, kr: kern_return_t) -> io::Error {
    io::Error::other(format!("{context} failed with kern_return_t={kr}"))
}

impl Credentials {
    pub fn current_process() -> io::Result<Credentials> {
        let pid = std::process::id();
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let egid = unsafe { libc::getegid() };

        // Get all group IDs
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

    pub fn from_message(message: &MachMessage<'_>) -> io::Result<Credentials> {
        // Extract audit token from message trailer
        // The audit token is in the trailer of Mach messages
        let audit_token = extract_audit_token(message)?;

        // Use audit_token_to_* APIs
        // audit_token_t is a struct with 8 u32 fields
        // The effective UID is in the 1st field (index 0)
        let uid = audit_token.val[1];
        // The effective GID is in the 3rd field (index 2)
        let gid = audit_token.val[3];
        // The real GID is in the 4th field (index 3)
        let rgid = audit_token.val[4];
        // The PID is in the 5th field (index 4)
        let pid = audit_token.val[5];

        let mut gid_list = vec![gid.to_string(), rgid.to_string()];
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

fn extract_audit_token(_message: &MachMessage<'_>) -> io::Result<audit_token_t> {
    // For now, use task_get_audit_token to get our own audit token
    // In a real implementation, this should extract from the message trailer
    let mut token: audit_token_t = unsafe { std::mem::zeroed() };
    let kr = unsafe {
        task_info(
            mach_task_self(),
            TASK_AUDIT_TOKEN,
            &mut token as *mut _ as *mut libc::c_int,
            &mut (std::mem::size_of::<audit_token_t>() as u32 / 4),
        )
    };

    if kr != KERN_SUCCESS {
        return Err(io::Error::other(format!("task_info failed: {}", kr)));
    }

    Ok(token)
}

trait MachMessageReceiver {
    fn as_mach_port(&self) -> &Port;

    // const MACH_MSG_TIMEOUT: mach_msg_timeout_t = 300;
    // Start with a larger buffer to accommodate port descriptors
    const BASE_MSGH_SIZE: usize = mem::size_of::<mach_msg_header_t>()
        + mem::size_of::<mach_msg_body_t>()
        + mem::size_of::<mach_msg_port_descriptor_t>() * 2
        + 64; // Extra space for payload

    fn recv<'bytes>(&self) -> io::Result<Option<MachMessage<'bytes>>> {
        self.recv_timeout(std::time::Duration::MAX)
    }

    fn try_recv<'bytes>(&self) -> io::Result<Option<MachMessage<'bytes>>> {
        self.recv_timeout(std::time::Duration::ZERO)
    }

    fn recv_timeout<'bytes>(
        &self,
        timeout: std::time::Duration,
    ) -> io::Result<Option<MachMessage<'bytes>>> {
        let port = self.as_mach_port();

        let mut msgh_size = Self::BASE_MSGH_SIZE;
        let mut header_ptr: *mut mach_msg_header_t;
        let mut message: Vec<u8>;

        loop {
            message = Vec::with_capacity(msgh_size + mem::size_of::<mach_msg_trailer_t>());
            header_ptr = message.as_mut_ptr().cast();

            let kr = unsafe {
                header_ptr.write(mach_msg_header_t {
                    msgh_size: 0,
                    msgh_bits: 0,
                    msgh_local_port: **port,
                    msgh_remote_port: MACH_PORT_NULL,
                    msgh_voucher_port: MACH_PORT_NULL,
                    msgh_id: 0,
                });

                mach_msg(
                    header_ptr,
                    (MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT | MACH_RCV_NOTIFY) as _,
                    0,
                    message.capacity() as _,
                    **port,
                    timeout.as_micros() as mach_msg_timeout_t,
                    MACH_PORT_NULL,
                )
            };

            // references: https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/mach_msg.html
            match kr as mach_msg_return_t {
                MACH_MSG_SUCCESS => break,
                MACH_RCV_TOO_LARGE => unsafe {
                    msgh_size = (*header_ptr).msgh_size as usize;
                    continue;
                },
                MACH_RCV_IN_PROGRESS | MACH_RCV_IN_PROGRESS_TIMED => {
                    // Thread is waiting for receive. (Internal use only.)
                    continue;
                }
                MACH_RCV_TIMEOUT | MACH_RCV_TIMED_OUT => return Ok(None),
                MACH_RCV_IN_SET | MACH_RCV_PORT_DIED | MACH_RCV_PORT_CHANGED => {
                    return Err(io::Error::last_os_error());
                }
                MACH_RCV_HEADER_ERROR | MACH_RCV_BODY_ERROR | MACH_RCV_SCATTER_SMALL => {
                    return Err(io::Error::last_os_error());
                }
                MACH_RCV_INVALID_DATA
                | MACH_RCV_INVALID_NAME
                | MACH_RCV_INVALID_NOTIFY
                | MACH_RCV_INVALID_REPLY
                | MACH_RCV_INVALID_TRAILER
                | MACH_RCV_INVALID_TYPE => return Err(io::Error::last_os_error()),
                MACH_RCV_INTERRUPT | MACH_RCV_INTERRUPTED => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        format!("mach port recv failed since remote interrupted with code {kr}"),
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("mach port recv failed since remote disconnected with code {kr}"),
                    ));
                }
            }
        }

        let header = unsafe {
            header_ptr.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid header pointer")
            })?
        };
        // After a successful receive, use the actual message size reported by the header
        let msgh_size = header.msgh_size as usize;

        let body_ptr = unsafe { header_ptr.offset(1).cast::<mach_msg_body_t>() };
        let descriptor_count = unsafe { (*body_ptr).msgh_descriptor_count };

        let mut references: Vec<MachMessageDescriptor> = Vec::with_capacity(descriptor_count as _);

        let mut last_descriptor_ptr = unsafe { body_ptr.offset(1).cast::<u8>() };
        for _ in 0..descriptor_count {
            let type_ptr = last_descriptor_ptr.cast::<mach_msg_type_descriptor_t>();
            last_descriptor_ptr = match unsafe { (*type_ptr).type_ as _ } {
                MACH_MSG_OOL_DESCRIPTOR => unsafe {
                    let ool_ptr = last_descriptor_ptr.cast::<mach_msg_ool_descriptor_t>();
                    references.push(MachMessageDescriptor::Ool(Ool::from_raw(
                        (*ool_ptr).address as _,
                        (*ool_ptr).size as _,
                    )));

                    ool_ptr.offset(1).cast()
                },
                MACH_MSG_PORT_DESCRIPTOR => unsafe {
                    let port_ptr = last_descriptor_ptr.cast::<mach_msg_port_descriptor_t>();
                    references.push(MachMessageDescriptor::Port(Port::from((*port_ptr).name)));

                    port_ptr.offset(1).cast()
                },
                _ => unimplemented!(),
            };
        }

        let data_ptr = last_descriptor_ptr.cast::<u8>();
        let data = unsafe {
            let prefix_size = data_ptr.offset_from(header_ptr.cast()) as usize;
            slice::from_raw_parts(data_ptr as *const _, msgh_size - prefix_size)
        };
        let payload = {
            let payload_len = header.msgh_id;
            let data_len = payload_len.max(0).min(data.len() as _) as usize;
            data[..data_len].to_vec()
        };

        Ok(Some(MachMessage {
            remote: header.msgh_remote_port,
            payload: payload.into(),
            descriptors: references,
        }))
    }
}

trait MachMessageSender: MachMessageReceiver {
    fn send(&self, msg: MachMessage<'_>) -> io::Result<()> {
        let MachMessage {
            remote: to,
            payload: data,
            descriptors: refs,
        } = msg;
        #[cfg(feature = "verbose")]
        crate::trace!("send message with data bytes {data:?}");

        let data_length = data.len();
        if data_length > mach_msg_id_t::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("mach message payload too large: {data_length} bytes"),
            ));
        }

        let port = self.as_mach_port();
        unsafe {
            let descriptor_count = refs.len();
            let descriptor_size = refs.iter().fold(0, |sum, reference| {
                sum + match reference {
                    MachMessageDescriptor::Ool(_) => mem::size_of::<mach_msg_ool_descriptor_t>(),
                    MachMessageDescriptor::Port(_) => mem::size_of::<mach_msg_port_descriptor_t>(),
                }
            });

            /* Message Layout:
             * |  header       : mach_msg_header_t;
             * |  body         : mach_msg_body_t;
             * |  descriptor   : body.msgh_descriptor_count;
             * |  data         : u8 * data_len; // aligned by 4
             */
            let size = mem::size_of::<mach_msg_header_t>()
                + mem::size_of::<mach_msg_body_t>()
                + descriptor_size
                + data_length.next_multiple_of(4);

            let mut message: Vec<u8> = Vec::with_capacity(size);

            let header_ptr = message.as_mut_ptr().cast::<mach_msg_header_t>();
            let body_ptr = header_ptr.offset(1).cast::<mach_msg_body_t>();

            header_ptr.write(mach_msg_header_t {
                msgh_bits: mach_msgh_bits_set(
                    MACH_MSG_TYPE_COPY_SEND,
                    MACH_MSG_TYPE_MAKE_SEND,
                    0,
                    MACH_MSGH_BITS_COMPLEX,
                ),
                msgh_size: size as _,
                msgh_local_port: **port,
                msgh_remote_port: to,
                msgh_voucher_port: MACH_PORT_NULL,
                msgh_id: data_length as mach_msg_id_t,
            });
            body_ptr.write(mach_msg_body_t {
                msgh_descriptor_count: descriptor_count as _,
            });

            let mut last_descriptor_ptr = body_ptr.offset(1).cast::<u8>();
            for reference in refs.iter() {
                last_descriptor_ptr = match reference {
                    MachMessageDescriptor::Ool(ool) => {
                        let ool_ptr = last_descriptor_ptr.cast::<mach_msg_ool_descriptor_t>();
                        *ool_ptr = mach_msg_ool_descriptor_t::new(
                            ool.ptr as _,
                            false,
                            MACH_MSG_VIRTUAL_COPY as _,
                            ool.len as _,
                        );
                        ool_ptr.offset(1).cast()
                    }
                    MachMessageDescriptor::Port(port) => {
                        let port_ptr = last_descriptor_ptr.cast::<mach_msg_port_descriptor_t>();
                        *port_ptr = mach_msg_port_descriptor_t::new(
                            port.raw(),
                            MACH_MSG_TYPE_COPY_SEND as _,
                        );
                        port_ptr.offset(1).cast()
                    }
                };
            }

            let data_ptr = last_descriptor_ptr.cast::<u8>();
            ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data_length);

            loop {
                let kr = mach_msg_send(message.as_mut_ptr().cast());
                crate::debug!("sent a message to mach port #{to:?} with result {kr:?}");

                // references: https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/mach_msg.html
                match kr as mach_msg_return_t {
                    MACH_MSG_SUCCESS => return Ok(()),
                    MACH_SEND_NO_BUFFER => continue,
                    MACH_SEND_TIMED_OUT => {
                        return Err(/* Error::SendTimeout */ io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("mach port send failed since timed out with code {kr}"),
                        ));
                    }
                    MACH_SEND_INTERRUPT | MACH_SEND_INTERRUPTED => {
                        return Err(/* Error::Interrupt */ io::Error::new(
                            io::ErrorKind::Interrupted,
                            format!(
                                "mach port send failed since remote interrupted with code {kr}"
                            ),
                        ));
                    }
                    MACH_SEND_INVALID_DEST => {
                        return Err(/* Error::InvalidDestination */ io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            format!(
                                "mach port send failed since destination unavailable with code {kr}"
                            ),
                        ));
                    }
                    MACH_SEND_MSG_TOO_SMALL
                    | MACH_SEND_INVALID_DATA
                    | MACH_SEND_INVALID_HEADER
                    | MACH_SEND_INVALID_NOTIFY
                    | MACH_SEND_INVALID_REPLY
                    | MACH_SEND_INVALID_TRAILER
                    | MACH_SEND_INVALID_MEMORY
                    | MACH_SEND_INVALID_RIGHT
                    | MACH_SEND_INVALID_TYPE => return Err(io::Error::last_os_error()),
                    _ => {
                        return Err(/* Error::Disconnect */ io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!(
                                "mach port send failed since remote disconnected with code {kr}"
                            ),
                        ));
                    }
                };
            }
        }
    }
}

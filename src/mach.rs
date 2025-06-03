use libc::kern_return_t;
use mach2::{
    bootstrap::{BOOTSTRAP_SUCCESS, bootstrap_parent},
    kern_return::{KERN_INVALID_ADDRESS, KERN_INVALID_RIGHT, KERN_SUCCESS},
    mach_port::{mach_port_allocate, mach_port_deallocate, mach_port_insert_right},
    mach_types::ipc_space_t,
    memory_object_types::memory_object_size_t,
    message::mach_msg_type_name_t,
    port::{
        MACH_PORT_NULL, MACH_PORT_RIGHT_DEAD_NAME, MACH_PORT_RIGHT_RECEIVE, mach_port_name_t,
        mach_port_t, mach_port_type_t,
    },
    task::task_get_special_port,
    task_special_ports::TASK_BOOTSTRAP_PORT,
    traps::mach_task_self,
    vm::{mach_make_memory_entry_64, mach_vm_allocate, mach_vm_deallocate},
    vm_prot::vm_prot_t,
    vm_types::mach_vm_offset_t,
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    ffi, io,
    ops::{Deref, DerefMut},
    os::fd::{AsRawFd, RawFd},
    ptr, slice,
    sync::OnceLock,
};

#[macro_export]
macro_rules! MACH_PORT_TYPE {
    ($right: ident) => {
        (1 << ($right + 16)) as mach_port_type_t
    };
}
pub const MACH_PORT_TYPE_NONE: mach_port_type_t = 0;
pub const MACH_PORT_TYPE_RECEIVE: mach_port_type_t = MACH_PORT_TYPE!(MACH_PORT_RIGHT_RECEIVE);
pub const MACH_PORT_TYPE_DEAD_NAME: mach_port_type_t = MACH_PORT_TYPE!(MACH_PORT_RIGHT_DEAD_NAME);

unsafe extern "C" {
    pub fn mach_port_type(
        task: ipc_space_t,
        name: mach_port_name_t,
        port_type: *mut mach_port_type_t,
    ) -> kern_return_t;
}

#[inline]
pub fn mach_msgh_bits_set(remote: u32, local: u32, voucher: u32, other: u32) -> u32 {
    remote | (local << 8) | (voucher << 16) | other
}

#[derive(Debug, Clone)]
pub struct MachMessage<'bytes> {
    pub remote: mach_port_t,
    pub payload: Cow<'bytes, [u8]>,
    pub descriptors: Vec<MachMessageDescriptor>,
}

#[derive(Debug, Clone)]
pub enum MachMessageDescriptor {
    Ool(Ool),   // MACH_MSG_OOL_DESCRIPTOR
    Port(Port), // MACH_MSG_PORT_DESCRIPTOR
}

#[derive(Debug, Clone)]
pub struct Ool {
    pub ptr: *mut u8,
    pub len: usize,
}

impl Ool {
    pub fn new(size: usize) -> Self {
        let mut ptr = 0;

        let kr = unsafe { mach_vm_allocate(mach_task_self(), &mut ptr, size as _, 1) };
        assert_eq!(kr, KERN_SUCCESS);

        Self {
            ptr: ptr as *mut u8,
            len: size,
        }
    }

    pub fn from_raw(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

unsafe impl Send for Ool {}

impl Drop for Ool {
    fn drop(&mut self) {
        let kr = unsafe { mach_vm_deallocate(mach_task_self(), self.ptr as _, self.len as _) };
        assert_eq!(kr, KERN_SUCCESS as kern_return_t);
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OwnedMachPort(pub Port);

impl Deref for OwnedMachPort {
    type Target = Port;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for OwnedMachPort {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for OwnedMachPort {
    fn drop(&mut self) {
        if self.is_null() {
            return;
        }

        crate::trace!("mach port ({:?}) dropped", self.0);
        let kr = self.deallocate();
        match kr as kern_return_t {
            KERN_SUCCESS | KERN_INVALID_RIGHT => {}
            _ => crate::warn!("deallocate {:?} failed with {kr:?}", self.0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Port(mach_port_t);

unsafe impl Send for Port {}
unsafe impl Sync for Port {}

impl Port {
    pub fn new() -> Port {
        let mut local: mach_port_t = MACH_PORT_NULL;
        let kr =
            unsafe { mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut local) };
        assert_eq!(kr, KERN_SUCCESS as kern_return_t);
        assert_ne!(local, MACH_PORT_NULL);
        Port(local)
    }

    pub fn make_memory_entry(address: *mut ffi::c_void, length: usize) -> io::Result<Port> {
        if address.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("mach_make_memory_entry failed: {}", {
                    KERN_INVALID_ADDRESS
                }),
            ));
        }

        let mut size = length as memory_object_size_t;
        let mut entry: mach_port_t = MACH_PORT_NULL;
        let kr = unsafe {
            mach_make_memory_entry_64(
                mach_task_self(),
                &mut size,
                address as mach_vm_offset_t,
                (libc::VM_PROT_READ | libc::VM_PROT_WRITE) as vm_prot_t,
                &mut entry,
                MACH_PORT_NULL,
            )
        };
        if kr != KERN_SUCCESS as kern_return_t {
            return Err(io::Error::other(format!(
                "mach_make_memory_entry failed: {}",
                kr
            )));
        }

        Ok(Port::from(entry))
    }
}

impl Port {
    pub fn raw(&self) -> mach_port_t {
        self.0
    }

    pub fn insert_right(&self, right: mach_msg_type_name_t) {
        let kr = unsafe { mach_port_insert_right(mach_task_self(), self.0, self.0, right) };
        assert_eq!(kr, KERN_SUCCESS as kern_return_t);
    }

    pub fn is_null(&self) -> bool {
        self.0 == MACH_PORT_NULL
    }

    pub fn is_dead(&self) -> bool {
        let mut ty: mach_port_type_t = MACH_PORT_TYPE_NONE;
        unsafe {
            let kr = mach_port_type(mach_task_self(), self.raw(), &mut ty);
            assert_eq!(kr, KERN_SUCCESS as kern_return_t);
        }

        ty & MACH_PORT_TYPE_DEAD_NAME != 0
    }

    pub fn offline(&self) -> bool {
        self.is_null() || self.is_dead()
    }

    pub fn deallocate(&self) -> i32 {
        // mach_port_deallocate and mach_port_mod_refs are very similar, except that
        // mach_port_mod_refs returns an error when there are no receivers for the port,
        // causing the sender port to never be deallocated. mach_port_deallocate handles
        // this case correctly and is therefore important to avoid dangling port leaks.
        unsafe { mach_port_deallocate(mach_task_self(), self.0) }
    }
}

impl Default for Port {
    fn default() -> Self {
        Self(MACH_PORT_NULL)
    }
}

impl From<mach_port_t> for Port {
    fn from(value: mach_port_t) -> Self {
        Port(value)
    }
}

impl Deref for Port {
    type Target = mach_port_t;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl AsRef<mach_port_t> for Port {
    fn as_ref(&self) -> &mach_port_t {
        &self.0
    }
}

impl AsRawFd for Port {
    fn as_raw_fd(&self) -> RawFd {
        self.0 as RawFd
    }
}

impl Port {
    pub fn bootstrap() -> mach_port_t {
        static BOOTSTRAP_PORT: OnceLock<mach_port_t> = OnceLock::new();
        *BOOTSTRAP_PORT.get_or_init(|| {
            let mut bootstrap_port: mach_port_t = 0;
            let kr = unsafe {
                task_get_special_port(
                    mach_task_self(),
                    TASK_BOOTSTRAP_PORT as _,
                    &mut bootstrap_port,
                )
            };
            assert_eq!(kr as u32, BOOTSTRAP_SUCCESS);
            bootstrap_port
        })
    }

    pub fn bootstrap_root() -> mach_port_t {
        static BOOTSTRAP_PORT_ROOT: OnceLock<mach_port_t> = OnceLock::new();
        *BOOTSTRAP_PORT_ROOT.get_or_init(|| {
            let mut root_bootstrap_port = Port::bootstrap();
            let mut parent: mach_port_t = 0;
            unsafe {
                loop {
                    let kr = bootstrap_parent(root_bootstrap_port, ptr::addr_of_mut!(parent));
                    if BOOTSTRAP_SUCCESS != kr as u32 {
                        break;
                    }
                    if root_bootstrap_port == parent {
                        break;
                    }
                    root_bootstrap_port = parent;
                }
            };
            root_bootstrap_port
        })
    }
}

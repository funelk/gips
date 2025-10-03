use std::{ffi, io, mem};

use mach2::{
    kern_return::{KERN_SUCCESS, kern_return_t},
    traps::mach_task_self,
    vm::{mach_vm_allocate, mach_vm_deallocate, mach_vm_map},
    vm_inherit::vm_inherit_t,
    vm_prot::vm_prot_t,
    vm_statistics::VM_FLAGS_ANYWHERE,
    vm_types::{mach_vm_address_t, mach_vm_size_t},
};

use crate::mach::Port;

use super::{
    Header, Result,
    posix::{Backing, OsShm},
};

const MACH_VM_INHERIT_NONE: vm_inherit_t = 2;

impl OsShm {
    pub fn new_anonymous(size: usize, total: usize) -> Result<OsShm> {
        let length = size.max(total);
        let mut addr: mach_vm_address_t = 0;

        let kr = unsafe {
            mach_vm_allocate(
                mach_task_self(),
                &mut addr,
                length as mach_vm_size_t,
                VM_FLAGS_ANYWHERE,
            )
        };
        if kr != KERN_SUCCESS as kern_return_t {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("mach_vm_allocate({}) failed: {}", length, kr),
            ));
        }

        let port = Port::make_memory_entry(addr as *mut ffi::c_void, length)?;
        let shm = OsShm::with_backing(Backing::Mach { port });
        unsafe { shm.remap(size)? };

        Ok(shm)
    }

    pub(super) fn remap_mach_memory_entry(
        &self,
        length: usize,
        port: &Port,
    ) -> Result<*mut ffi::c_void> {
        if self.mapped() != 0 && !self.address().is_null() {
            let ret = unsafe {
                mach_vm_deallocate(
                    mach_task_self(),
                    self.address() as mach_vm_address_t,
                    self.mapped() as mach_vm_size_t,
                )
            };
            if ret != KERN_SUCCESS as kern_return_t {
                return Err(io::Error::other(format!(
                    "mach_vm_deallocate({}) failed: {}",
                    self.mapped(),
                    ret
                )));
            }
        }

        let mut addr: mach_vm_address_t = 0;
        let kr = unsafe {
            mach_vm_map(
                mach_task_self(),
                &mut addr,
                length as mach_vm_size_t,
                0,
                VM_FLAGS_ANYWHERE,
                port.raw(),
                0,
                0,
                (libc::VM_PROT_READ | libc::VM_PROT_WRITE) as vm_prot_t,
                (libc::VM_PROT_READ | libc::VM_PROT_WRITE) as vm_prot_t,
                MACH_VM_INHERIT_NONE,
            )
        };
        if kr != KERN_SUCCESS as kern_return_t {
            return Err(io::Error::other(format!(
                "mach_vm_map({}) for memory entry failed: {}",
                length, kr
            )));
        }

        self.set_address(addr as *mut ffi::c_void);
        self.set_mapped(length);
        Ok(addr as *mut ffi::c_void)
    }

    pub(super) fn close_mach_memory_entry(&self) -> Result<()> {
        if self.mapped() != 0 && !self.address().is_null() {
            let ret = unsafe {
                mach_vm_deallocate(
                    mach_task_self(),
                    self.address() as mach_vm_address_t,
                    self.mapped() as mach_vm_size_t,
                )
            };
            if ret != KERN_SUCCESS as kern_return_t {
                return Err(io::Error::other(format!(
                    "mach_vm_deallocate({}) failed: {ret}",
                    self.mapped(),
                )));
            }
        }
        Ok(())
    }
}

impl TryFrom<Port> for OsShm {
    type Error = io::Error;
    fn try_from(port: Port) -> Result<Self> {
        let shm = OsShm::with_backing(Backing::Mach { port });
        let initial = mem::size_of::<Header>();
        unsafe { shm.remap(initial)? };
        Ok(shm)
    }
}

impl TryFrom<&OsShm> for Port {
    type Error = io::Error;
    fn try_from(shm: &OsShm) -> Result<Self> {
        let length = match shm.mapped() {
            0 => mem::size_of::<Header>(),
            len => len,
        };
        Port::make_memory_entry(shm.address(), length)
    }
}

use std::{fmt, io, mem, ops, thread};

use windows::Win32::{
    Foundation,
    System::{Threading, IO},
};

/// A wrapper around `OVERLAPPED` to provide "rustic" accessors and
/// initializers.
#[repr(transparent)]
pub struct Overlapped(IO::OVERLAPPED);

impl fmt::Debug for Overlapped {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OVERLAPPED")
    }
}

unsafe impl Send for Overlapped {}
unsafe impl Sync for Overlapped {}

impl Drop for Overlapped {
    fn drop(&mut self) {
        if !self.0.hEvent.is_invalid() {
            let result = unsafe { Foundation::CloseHandle(self.0.hEvent) };
            assert!(result.is_ok() || thread::panicking());
        }
    }
}

impl Overlapped {
    pub fn zero() -> Overlapped {
        Overlapped(unsafe { mem::zeroed() })
    }

    pub fn initialize_with_auto_reset_event() -> io::Result<Overlapped> {
        let event = unsafe { Threading::CreateEventW(None, false, false, None)? };
        if event.is_invalid() {
            return Err(io::Error::last_os_error());
        }
        let mut overlapped = Self::zero();
        overlapped.with_event(event);
        Ok(overlapped)
    }

    /// Gain access to the raw underlying data
    pub fn raw(&self) -> *mut IO::OVERLAPPED {
        &self.0 as *const _ as *mut _
    }

    /// Reads the `hEvent` field of this structure, may return null.
    pub fn event(&self) -> Foundation::HANDLE {
        self.0.hEvent
    }

    /// Sets the `hEvent` field of this structure.
    ///
    /// The event specified can be null.
    pub fn with_event(&mut self, event: Foundation::HANDLE) -> &mut Self {
        self.0.hEvent = event;
        self
    }

    /// Sets the specified event object to the signaled state.
    pub fn set_event(&self) -> Result<(), ::windows::core::Error> {
        unsafe { Threading::SetEvent(self.0.hEvent) }
    }

    /// Sets the specified event object to the non-signaled state.
    pub fn reset_event(&self) -> Result<(), ::windows::core::Error> {
        unsafe { Threading::ResetEvent(self.0.hEvent) }
    }

    /// Sets the specified event object to the signaled state and then resets it to the non-signaled state after releasing the appropriate number of waiting threads.
    pub fn pulse_event(&self) -> Result<(), ::windows::core::Error> {
        unsafe { Threading::PulseEvent(self.0.hEvent) }
    }
}

impl Default for Overlapped {
    fn default() -> Self {
        Self::zero()
    }
}

impl From<IO::OVERLAPPED> for Overlapped {
    fn from(value: IO::OVERLAPPED) -> Self {
        Overlapped(value)
    }
}

impl ops::Deref for Overlapped {
    type Target = IO::OVERLAPPED;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for Overlapped {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

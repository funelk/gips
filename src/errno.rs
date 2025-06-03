#[derive(Debug, thiserror::Error)]
pub struct Errno(i32);

impl Errno {
    pub fn last() -> Errno {
        #[cfg(target_os = "macos")]
        let errno = unsafe { *(libc::__error()) };
        #[cfg(target_os = "linux")]
        let errno = unsafe { *(libc::__errno_location()) };
        Errno(errno)
    }

    /// Returns `Ok(value)` if it does not contain the sentinel value. This
    /// should not be used when `-1` is not the errno sentinel value.
    #[inline]
    pub fn result<S: ErrnoSentinel + PartialEq<S>>(value: S) -> Result<S, Errno> {
        if value == S::sentinel() {
            Err(Self::last())
        } else {
            Ok(value)
        }
    }
}
impl std::ops::Deref for Errno {
    type Target = i32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<Errno> for std::io::Error {
    fn from(err: Errno) -> Self {
        std::io::Error::from_raw_os_error(*err)
    }
}
impl TryFrom<std::io::Error> for Errno {
    type Error = std::io::Error;

    fn try_from(err: std::io::Error) -> std::result::Result<Self, std::io::Error> {
        err.raw_os_error().map(Errno).ok_or(err)
    }
}

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let desc = match self.0 {
            libc::EPERM => "Operation not permitted",
            libc::ENOENT => "No such file or directory",
            _ => "Unknown errno",
        };
        write!(f, "{:?}: {}", self, desc)
    }
}

/// The sentinel value indicates that a function failed and more detailed
/// information about the error can be found in `errno`
pub trait ErrnoSentinel: Sized {
    fn sentinel() -> Self;
}

impl ErrnoSentinel for isize {
    fn sentinel() -> Self {
        -1
    }
}
impl ErrnoSentinel for i32 {
    fn sentinel() -> Self {
        -1
    }
}
impl ErrnoSentinel for i64 {
    fn sentinel() -> Self {
        -1
    }
}
impl ErrnoSentinel for *mut libc::c_void {
    fn sentinel() -> Self {
        -1isize as *mut libc::c_void
    }
}
impl ErrnoSentinel for libc::sighandler_t {
    fn sentinel() -> Self {
        libc::SIG_ERR
    }
}

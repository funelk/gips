#[cfg(unix)]
pub mod errno;
#[cfg(target_os = "macos")]
pub mod mach;

pub mod ipc;
pub mod poll;
pub mod shm;

mod sealed {
    /// This trait is sealed to prevent external implementations.
    #[allow(unused)]
    pub trait Sealed {}
}

#[macro_export]
macro_rules! trace {
    ($($body:tt)+) => {{
        #[cfg(feature = "log")]
        { ::log::trace!($($body)+) }
        #[cfg(feature = "tracing")]
        { ::tracing::trace!($($body)+) }
    }};
}

#[macro_export]
macro_rules! debug {
    ($($body:tt)+) => {{
        #[cfg(feature = "log")]
        { ::log::debug!($($body)+) }
        #[cfg(feature = "tracing")]
        { ::tracing::debug!($($body)+) }
    }};
}

#[macro_export]
macro_rules! info {
    ($($body:tt)+) => {{
        #[cfg(feature = "log")]
        { ::log::info!($($body)+) }
        #[cfg(feature = "tracing")]
        { ::tracing::info!($($body)+) }
    }};
}

#[macro_export]
macro_rules! warn {
    ($($body:tt)+) => {{
        #[cfg(feature = "log")]
        { ::log::warn!($($body)+) }
        #[cfg(feature = "tracing")]
        { ::tracing::warn!($($body)+) }
    }};
}

#[macro_export]
macro_rules! error {
    ($($body:tt)+) => {{
        #[cfg(feature = "log")]
        { ::log::error!($($body)+) }
        #[cfg(feature = "tracing")]
        { ::tracing::error!($($body)+) }
    }};
}

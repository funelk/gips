//! # GIPS - General Inter-Process Solution
//!
//! A high-performance, cross-platform inter-process communication (IPC) library for Rust.
//! GIPS provides unified abstractions for IPC primitives across Linux, macOS, and Windows.
//!
//! ## Features
//!
//! - **High Performance**: Zero-copy shared memory and efficient message passing
//! - **Secure by Default**: Built-in credential verification and access control policies
//! - **Cross-Platform**: Unified API across Linux, macOS, and Windows
//! - **Event-Driven**: Efficient polling mechanism for scalable IPC servers
//! - **Type-Safe**: Rust's type system ensures memory safety
//!
//! ## Quick Start
//!
//! ### Basic IPC Example
//!
//! ```no_run
//! use gips::ipc::{Listener, Endpoint};
//!
//! // Server
//! # fn server() -> std::io::Result<()> {
//! let mut listener = Listener::bind("com.example.myservice")?;
//! let pod = listener.accept()?;
//! let (connection, message) = pod.split();
//! connection.reply(b"Hello!", &[])?;
//! # Ok(())
//! # }
//!
//! // Client
//! # fn client() -> std::io::Result<()> {
//! let mut endpoint = Endpoint::connect("com.example.myservice")?;
//! endpoint.send(b"Hello!", &[])?;
//! let response = endpoint.recv()?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Shared Memory Transfer
//!
//! ```no_run
//! use gips::shm::Shm;
//! use gips::ipc::Object;
//! # use gips::ipc::Endpoint;
//! # fn example(mut endpoint: Endpoint) -> std::io::Result<()> {
//!
//! let shm = Shm::new(None::<String>, 4096)?;
//! shm.write(b"Shared data", 0);
//!
//! let shm_handle = Object::try_from(&shm)?;
//! endpoint.send(b"shm", &[shm_handle])?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Event-Driven Server
//!
//! ```no_run
//! use gips::poll::{Poller, Events, Interest};
//! use gips::ipc::Listener;
//! use std::time::Duration;
//!
//! # fn example() -> std::io::Result<()> {
//! let mut poller = Poller::new()?;
//! let mut listener = Listener::bind("com.example.service")?;
//! let token = poller.register(&mut listener, Interest::READABLE)?;
//!
//! let mut events = Events::with_capacity(128);
//! poller.poll(&mut events, Some(Duration::from_secs(1)))?;
//!
//! for event in &events {
//!     if event.token() == token {
//!         let pod = listener.accept()?;
//!         // Handle connection...
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Platform Support
//!
//! | Platform | IPC Backend | Polling | Shared Memory |
//! |----------|-------------|---------|---------------|
//! | **Linux** | Unix Domain Sockets | epoll | POSIX shm |
//! | **macOS** | Mach Ports | kqueue | Mach memory |
//! | **Windows** | Named Pipes | IOCP | File mapping |
//!
//! ## Modules
//!
//! - [`ipc`] - Inter-process communication primitives
//! - [`poll`] - Event-driven I/O multiplexing
//! - [`shm`] - Shared memory regions
//! - [`mach`] - macOS-specific Mach kernel interfaces (macOS only)
//! - [`windows`] - Windows-specific primitives (Windows only)
//! - [`seqpacket`] - SOCK_SEQPACKET sockets (Unix only)
//!
//! ## Security
//!
//! GIPS provides built-in security features:
//!
//! ```no_run
//! use gips::ipc::{ServiceDescriptor, Listener};
//!
//! # fn example() -> std::io::Result<()> {
//! let descriptor = ServiceDescriptor::new("com.example.secure")
//!     .require_privileged()
//!     .with_allowed_uid(["1000"]);
//!
//! let listener = Listener::bind(descriptor)?;
//! # Ok(())
//! # }
//! ```

#[cfg(unix)]
pub mod errno;
#[cfg(unix)]
pub mod seqpacket;
#[cfg(target_os = "macos")]
pub mod mach;
#[cfg(target_os = "windows")]
pub mod windows;

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


//! Event-driven I/O multiplexing for scalable IPC.
//!
//! This module provides a cross-platform polling abstraction for monitoring multiple
//! I/O sources and receiving notifications when they become ready for reading or writing.
//!
//! # Architecture
//!
//! The polling system consists of:
//!
//! - [`Poller`]: The main event loop that monitors registered sources
//! - [`Source`]: Trait for types that can be registered with a poller
//! - [`Events`]: Collection of ready events returned by the poller
//! - [`Event`]: Individual readiness notification with associated token
//! - [`Token`]: Unique identifier for registered sources
//! - [`Interest`]: Flags indicating read/write interests
//!
//! # Platform Implementations
//!
//! | Platform | Backend | Performance |
//! |----------|---------|-------------|
//! | Linux | epoll | Excellent (O(1) ready events) |
//! | macOS | kqueue | Excellent (O(1) ready events) |
//! | Windows | IOCP | Excellent (completion-based) |
//!
//! # Usage Pattern
//!
//! 1. Create a [`Poller`]
//! 2. Register sources with [`Poller::register`]
//! 3. Call [`Poller::poll`] to wait for events
//! 4. Process ready events from [`Events`]
//! 5. Repeat from step 3
//!
//! # Examples
//!
//! ## Basic Event Loop
//!
//! ```no_run
//! use gips::poll::{Poller, Events, Interest};
//! use gips::ipc::Listener;
//! use std::time::Duration;
//!
//! # fn example() -> std::io::Result<()> {
//! let mut poller = Poller::new()?;
//! let mut listener = Listener::bind("com.example.service")?;
//!
//! // Register the listener for read events
//! let token = poller.register(&mut listener, Interest::READABLE)?;
//!
//! let mut events = Events::with_capacity(128);
//!
//! loop {
//!     // Wait for events with 1 second timeout
//!     poller.poll(&mut events, Some(Duration::from_secs(1)))?;
//!
//!     for event in &events {
//!         if event.token() == token && event.is_readable() {
//!             // Accept new connection
//!             let pod = listener.accept()?;
//!             // Handle connection...
//!         }
//!     }
//! }
//! # }
//! ```
//!
//! ## Multiple Sources
//!
//! ```no_run
//! use gips::poll::{Poller, Events, Interest, Token};
//! use gips::ipc::Listener;
//! use std::collections::HashMap;
//! use std::time::Duration;
//!
//! # fn example() -> std::io::Result<()> {
//! let mut poller = Poller::new()?;
//! let mut events = Events::with_capacity(128);
//! let mut listeners = HashMap::new();
//!
//! // Register multiple listeners
//! let mut listener1 = Listener::bind("com.example.service1")?;
//! let token1 = poller.register(&mut listener1, Interest::READABLE)?;
//! listeners.insert(token1, listener1);
//!
//! let mut listener2 = Listener::bind("com.example.service2")?;
//! let token2 = poller.register(&mut listener2, Interest::READABLE)?;
//! listeners.insert(token2, listener2);
//!
//! loop {
//!     poller.poll(&mut events, Some(Duration::from_secs(1)))?;
//!
//!     for event in &events {
//!         if let Some(listener) = listeners.get_mut(&event.token()) {
//!             if event.is_readable() {
//!                 let pod = listener.accept()?;
//!                 // Handle connection...
//!             }
//!         }
//!     }
//! }
//! # }
//! ```
//!
//! ## Waker for External Wake-ups
//!
//! ```no_run
//! use gips::poll::{Poller, Events, Token};
//! use std::thread;
//! use std::time::Duration;
//!
//! # fn example() -> std::io::Result<()> {
//! let mut poller = Poller::new()?;
//! let mut events = Events::with_capacity(128);
//!
//! // Spawn thread that wakes the poller
//! let waker = poller.wake();
//! thread::spawn(move || {
//!     thread::sleep(Duration::from_secs(2));
//!     waker.expect("wake failed");
//! });
//!
//! // This will wake up when the other thread calls wake()
//! poller.poll(&mut events, None)?;
//!
//! for event in &events {
//!     if event.from_waker() {
//!         println!("Poller was woken up!");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Performance Considerations
//!
//! - **Event capacity**: Pre-allocate sufficient capacity in [`Events`] to avoid
//!   reallocations during polling
//! - **Timeout**: Use appropriate timeouts; `None` blocks indefinitely, `Some(Duration::ZERO)`
//!   returns immediately (non-blocking)
//! - **Batch processing**: Process multiple ready events per poll iteration
//! - **Reregister**: Use [`Poller::reregister`] to change interests without
//!   deregistering/registering
//!
//! # Thread Safety
//!
//! - [`Poller`] is NOT thread-safe and should be used from a single thread
//! - Multiple sources can be registered from the same thread
//! - The waker can be used from any thread to wake up the poller

use std::{collections::HashMap, fmt, io, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(pub usize);

impl Token {
    pub const WAKER: Token = Token(0);
    pub const INVALID: Token = Token(usize::MAX);

    pub fn new(val: usize) -> Token {
        Token(val)
    }
    pub fn into_usize(self) -> usize {
        self.0
    }
}

impl From<usize> for Token {
    fn from(val: usize) -> Token {
        Token(val)
    }
}

impl From<Token> for usize {
    fn from(token: Token) -> usize {
        token.0
    }
}

impl PartialEq<usize> for Token {
    fn eq(&self, other: &usize) -> bool {
        &self.0 == other
    }
}
impl PartialEq<Token> for usize {
    fn eq(&self, other: &Token) -> bool {
        self == &other.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interest(u8);

impl Interest {
    pub const READABLE: Interest = Interest(0b0001);

    pub const WRITABLE: Interest = Interest(0b0010);

    pub const BOTH: Interest = Interest(0b0011);

    pub fn is_readable(self) -> bool {
        (self.0 & Self::READABLE.0) != 0
    }

    pub fn is_writable(self) -> bool {
        (self.0 & Self::WRITABLE.0) != 0
    }
}

impl std::ops::BitOr for Interest {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Interest(self.0 | other.0)
    }
}

impl std::ops::BitAnd for Interest {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Interest(self.0 & other.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    token: Token,
    interest: Interest,
}

impl Event {
    pub fn new(token: Token, interest: Interest) -> Event {
        Event { token, interest }
    }

    pub fn token(&self) -> Token {
        self.token
    }

    pub fn interest(&self) -> Interest {
        self.interest
    }

    pub fn is_readable(&self) -> bool {
        self.interest.is_readable()
    }

    pub fn is_writable(&self) -> bool {
        self.interest.is_writable()
    }

    pub fn from_waker(&self) -> bool {
        self.token == Token::WAKER
    }
}

pub struct Events {
    events: Vec<Event>,
}

impl Events {
    pub fn with_capacity(capacity: usize) -> Events {
        Events {
            events: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Event> {
        self.events.iter()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }

    pub(crate) fn push(&mut self, event: Event) {
        self.events.push(event);
    }
}

impl<'a> IntoIterator for &'a Events {
    type Item = &'a Event;
    type IntoIter = std::slice::Iter<'a, Event>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for Events {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Events").field("len", &self.len()).finish()
    }
}

pub trait Source {
    fn register(&mut self, poller: &mut Poller, token: Token, interest: Interest)
    -> io::Result<()>;

    fn deregister(&mut self, poller: &mut Poller) -> io::Result<()>;

    fn reregister(
        &mut self,
        poller: &mut Poller,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        self.deregister(poller)?;
        self.register(poller, token, interest)
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "macos")] {
        mod macos;
        pub use macos::{FdSource, MachPortSource, Poller as OsPoller, Waker as OsWaker };
    } else if #[cfg(target_os = "linux")] {
        mod linux;
        pub use linux::{FdSource, SeqpacketSource, Poller as OsPoller, Waker as OsWaker };
    } else if #[cfg(target_os = "windows")] {
        mod windows;
        pub use windows::{IoHandleSource, NamedPipeSource, AsSource, Poller as OsPoller, Waker as OsWaker };
    }
}

pub struct Poller {
    inner: OsPoller,
    waker: OsWaker,
    registrations: HashMap<Token, Interest>,
    next_token: usize,
}

impl Poller {
    pub fn new() -> io::Result<Poller> {
        let inner = OsPoller::new()?;
        let waker = OsWaker::new(&inner)?;

        Ok(Poller {
            inner,
            waker,
            registrations: HashMap::new(),
            next_token: 1, // Start from 1, reserve 0 for waker
        })
    }

    pub fn register<S>(&mut self, source: &mut S, interest: Interest) -> io::Result<Token>
    where
        S: Source + ?Sized,
    {
        if interest == Interest(0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one interest flag must be set",
            ));
        }

        let token = Token::new(self.next_token);
        source.register(self, token, interest)?;
        self.next_token += 1;
        self.registrations.insert(token, interest);
        Ok(token)
    }

    pub fn deregister<S>(&mut self, source: &mut S, token: Token) -> io::Result<()>
    where
        S: Source + ?Sized,
    {
        source.deregister(self)?;
        self.registrations.remove(&token);
        Ok(())
    }

    pub fn reregister<S>(
        &mut self,
        source: &mut S,
        token: Token,
        interest: Interest,
    ) -> io::Result<()>
    where
        S: Source + ?Sized,
    {
        source.reregister(self, token, interest)?;
        self.registrations.insert(token, interest);
        Ok(())
    }

    pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.poll(events, timeout)
    }

    pub fn wake(&self) -> io::Result<()> {
        self.waker.wake()
    }

    pub fn inner(&mut self) -> &mut OsPoller {
        &mut self.inner
    }
}

impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Poller")
            .field("registrations", &self.registrations.len())
            .finish()
    }
}

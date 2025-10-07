
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

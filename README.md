# GIPS - General Inter-Process Solution

[![Crates.io](https://img.shields.io/crates/v/gips.svg)](https://crates.io/crates/gips)
[![Documentation](https://docs.rs/gips/badge.svg)](https://docs.rs/gips)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE-APACHE-2.0)

A high-performance, cross-platform inter-process solution library for Rust. GIPS currently provides unified abstractions for IPC/SHM/POLL primitives across Linux, macOS, and Windows, with a focus on performance, security, and ease of use.

## Features

- 🚀 **High Performance**: Zero-copy shared memory and efficient message passing
- 🔒 **Secure by Default**: Built-in credential verification and access control policies
- 🌍 **Cross-Platform**: Unified API across Linux, macOS, and Windows
- ⚡ **Event-Driven**: Efficient polling mechanism for scalable IPC servers
- 🛡️ **Type-Safe**: Rust's type system ensures memory safety and prevents common IPC bugs
- 📦 **Flexible**: Support for various data transfer methods including messages and shared memory

## Platform Support

| Platform          | IPC Backend                          | Polling | Shared Memory       |
| ----------------- | ------------------------------------ | ------- | ------------------- |
| **Linux**   | Unix Domain Sockets (SOCK_SEQPACKET) | epoll   | POSIX shm           |
| **macOS**   | Mach Ports                           | kqueue  | Mach memory objects |
| **Windows** | Named Pipes                          | IOCP    | File mapping        |

## Core Components

### IPC (`gips::ipc`)

Provides cross-platform IPC primitives for message passing:

- **Listener**: Server-side endpoint that accepts incoming connections
- **Endpoint**: Client-side connection to a named service
- **Connection**: Bidirectional communication channel
- **Message**: Container for payload data and transferable objects
- **Policy**: Security policies for access control

### Polling (`gips::poll`)

Event-driven I/O multiplexing for scalable IPC servers:

- **Poller**: Cross-platform event loop for monitoring multiple sources
- **Source**: Types that can be registered with a poller
- **Events**: Collection of ready events from the poller
- **Interest**: Read/write interest flags

### Shared Memory (`gips::shm`)

High-performance shared memory regions:

- **Shm**: Memory mapped region that can be shared across processes
- **Header**: Metadata for managing shared memory regions
- Zero-copy data transfer by passing handles via IPC

## Quick Start

Add GIPS to your `Cargo.toml`:

```toml
[dependencies]
gips = "0.1"
```

### Basic IPC Example

```rust
use gips::ipc::{Listener, Endpoint};

// Server
fn server() -> std::io::Result<()> {
    let mut listener = Listener::bind("com.example.myservice")?;
    let pod = listener.accept()?;
    let (connection, message) = pod.split();
  
    println!("Received: {}", String::from_utf8_lossy(&message.payload));
    connection.reply(b"Hello from server!", &[])?;
    Ok(())
}

// Client
fn client() -> std::io::Result<()> {
    let mut endpoint = Endpoint::connect("com.example.myservice")?;
    endpoint.send(b"Hello from client!", &[])?;
  
    let response = endpoint.recv()?;
    println!("Received: {}", String::from_utf8_lossy(&response.payload));
    Ok(())
}
```

### Event-Driven Server

```rust
use gips::ipc::Listener;
use gips::poll::{Poller, Events, Interest};
use std::time::Duration;

let mut poller = Poller::new()?;
let mut listener = Listener::bind("com.example.myservice")?;

let token = poller.register(&mut listener, Interest::READABLE)?;
let mut events = Events::with_capacity(128);

loop {
    poller.poll(&mut events, Some(Duration::from_secs(1)))?;
  
    for event in &events {
        if event.token() == token && event.is_readable() {
            let pod = listener.accept()?;
            // Handle connection...
        }
    }
}
```

### Shared Memory Transfer

```rust
use gips::shm::Shm;
use gips::ipc::{Endpoint, Object};

// Create and share memory
let shm = Shm::new(None::<String>, 4096)?;
shm.write(b"Shared data", 0);

let shm_handle = Object::try_from(&shm)?;
endpoint.send(b"shm", &[shm_handle])?;

// Receive and access shared memory
let message = endpoint.recv()?;
let shm_object = message.objects.into_iter().next().unwrap();
let shm = Shm::try_from(shm_object)?;

let data = shm.read(0, Some(100));
println!("Shared data: {}", String::from_utf8_lossy(data));
```

## Security

GIPS provides built-in security features for IPC:

### Access Control Policies

```rust
use gips::ipc::{ServiceDescriptor, Policy};

// Require elevated privileges
let descriptor = ServiceDescriptor::new("com.example.secure")
    .require_privileged();

// Restrict to specific users
let descriptor = ServiceDescriptor::new("com.example.useronly")
    .with_allowed_uid(["1000", "1001"]);

// Restrict to specific groups
let descriptor = ServiceDescriptor::new("com.example.grouponly")
    .with_allowed_group(["admin", "staff"]);

// Custom validation
let descriptor = ServiceDescriptor::new("com.example.custom")
    .with_credential_validator(|creds| {
        if creds.pid < 1000 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "PID too low"
            ));
        }
        Ok(())
    });

let mut listener = Listener::bind(descriptor)?;
```

### Credential Inspection

```rust
let pod = listener.accept()?;
let credentials = pod.credentials();

println!("Connected process:");
println!("  PID: {}", credentials.pid);
println!("  UID: {}", credentials.uid);
println!("  Groups: {:?}", credentials.gid_list);
println!("  Privileged: {}", credentials.is_privileged);
```

## Examples

The `examples/` directory contains complete working examples:

- **`ipc.rs`**: Simple echo server demonstrating basic IPC
- **`poll.rs`**: Event-driven server handling multiple connections
- **`shm.rs`**: Producer-consumer pattern using shared memory

Run examples with:

```bash
cargo run --example ipc
cargo run --example poll
cargo run --example shm
```

## Architecture

GIPS uses platform-specific backends while providing a unified API:

### Linux Implementation

- **IPC**: Unix domain sockets with `SOCK_SEQPACKET` for message boundaries
- **Polling**: Linux `epoll` for efficient event notification
- **Shared Memory**: POSIX shared memory (`shm_open`/`mmap`)
- **Credentials**: `SO_PEERCRED` socket option for peer authentication

### macOS Implementation

- **IPC**: Mach ports via Bootstrap Server for service registration
- **Polling**: kqueue for event notification
- **Shared Memory**: Mach memory objects transferred via port rights
- **Credentials**: Audit tokens from Mach message trailers

### Windows Implementation

- **IPC**: Named pipes with message mode
- **Polling**: I/O Completion Ports (IOCP)
- **Shared Memory**: File mapping objects transferred via handle duplication
- **Credentials**: Token information from impersonation

## Performance Considerations

- **Zero-Copy**: Shared memory avoids data copying between processes
- **Message Boundaries**: Built-in message framing eliminates custom protocols
- **Efficient Polling**: Platform-native event mechanisms scale to thousands of connections
- **Minimal Allocations**: Reusable event buffers and pre-allocated message space

## Logging

GIPS supports both `log` and `tracing` crates:

```toml
# Use log
gips = { version = "0.1", features = ["log"], default-features = false }

# Use tracing (default)
gips = { version = "0.1", features = ["tracing"], default-features = false }
```

## Platform Notes

### macOS

- Service names should follow reverse-DNS notation: `com.company.service`
- Bootstrap services persist for the user session
- Requires proper entitlements for production apps

### Linux

- Socket paths are created in abstract namespace by default
- Consider using systemd socket activation for services
- File descriptors can be passed through messages

### Windows

- Pipe names follow the format `\\.\pipe\{name}`
- Named pipes support both byte and message modes
- Requires appropriate privileges for global pipes

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE-2.0](LICENSE-APACHE-2.0) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

GIPS builds upon the excellent work of many platform-specific libraries and draws inspiration from various IPC implementations across the Rust ecosystem.

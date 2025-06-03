//! IPC Example: Simple Echo Server and Client
//!
//! This example demonstrates basic inter-process communication using gips.
//! It creates a simple echo server that receives messages and sends them back.
//!
//! Run with: cargo run --example ipc

use std::io;
use std::thread;
use std::time::Duration;

use gips::ipc::{Endpoint, Listener};

const SERVICE_NAME: &str = "com.example.gips.echo";

fn main() -> io::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    println!("=== GIPS IPC Example ===\n");

    // Start the server in a separate thread
    let server_handle = thread::spawn(|| {
        if let Err(e) = run_server() {
            eprintln!("Server error: {}", e);
        }
    });

    // Give the server time to start
    thread::sleep(Duration::from_millis(100));

    // Run the client
    run_client()?;

    // Wait for server to finish
    server_handle.join().unwrap();

    Ok(())
}

fn run_server() -> io::Result<()> {
    println!("[Server] Starting echo server on service: {}", SERVICE_NAME);
    
    let mut listener = Listener::bind(SERVICE_NAME)?;
    println!("[Server] Listening for connections...");

    // Accept one connection
    let pod = listener.accept()?;
    println!("[Server] Client connected!");

    // Split into connection and initial message
    let (connection, message) = pod.split();
    
    println!(
        "[Server] Received: '{}'",
        String::from_utf8_lossy(&message.payload)
    );

    // Echo the message back
    let response = format!("Echo: {}", String::from_utf8_lossy(&message.payload));
    connection.reply(response.as_bytes(), &[])?;
    
    println!("[Server] Sent echo response");
    println!("[Server] Shutting down");

    Ok(())
}

fn run_client() -> io::Result<()> {
    println!("[Client] Connecting to service: {}", SERVICE_NAME);
    
    let mut endpoint = Endpoint::connect(SERVICE_NAME)?;
    println!("[Client] Connected!");

    // Send a message
    let message = "Hello from client!";
    println!("[Client] Sending: '{}'", message);
    endpoint.send(message.as_bytes(), &[])?;

    // Receive the echo response
    let response = endpoint.recv()?;
    println!(
        "[Client] Received: '{}'",
        String::from_utf8_lossy(&response.payload)
    );

    println!("[Client] Done");

    Ok(())
}

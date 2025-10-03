//! Shared Memory Example: Producer-Consumer Pattern
//!
//! This example demonstrates using shared memory for efficient data sharing
//! between processes. It simulates a producer writing data and a consumer
//! reading it through shared memory transferred via IPC.
//!
//! Run with: cargo run --example shm

use std::io;
use std::thread;
use std::time::Duration;

use gips::ipc::{Endpoint, Listener, Object};
use gips::shm::Shm;

const SERVICE_NAME: &str = "com.example.gips.shm";
const SHM_SIZE: usize = 4096; // 4KB

fn main() -> io::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    println!("=== GIPS Shared Memory Example ===\n");

    // Start the consumer (server) in a separate thread
    let consumer_handle = thread::spawn(|| {
        if let Err(e) = run_consumer() {
            eprintln!("Consumer error: {}", e);
        }
    });

    // Give the consumer time to start
    thread::sleep(Duration::from_millis(100));

    // Run the producer (client)
    run_producer()?;

    // Wait for consumer to finish
    consumer_handle.join().unwrap();

    Ok(())
}

fn run_producer() -> io::Result<()> {
    println!("[Producer] Creating shared memory region...");
    
    // Create an anonymous shared memory region
    let shm = Shm::new(None::<String>, SHM_SIZE)?;
    println!("[Producer] Created shared memory: {} bytes", shm.capacity());

    // Write some data to the shared memory
    let data = "Hello from shared memory! This data is directly accessible by both processes.";
    let written = shm.write(data.as_bytes(), 0);
    println!("[Producer] Wrote {} bytes: '{}'", written, data);

    // Add some additional data
    let more_data = "\nShared memory is fast and efficient!";
    let offset = written;
    let written2 = shm.write(more_data.as_bytes(), offset);
    println!("[Producer] Wrote {} more bytes at offset {}", written2, offset);

    // Connect to the consumer
    println!("[Producer] Connecting to consumer...");
    let mut endpoint = Endpoint::connect(SERVICE_NAME)?;

    // Export the shared memory handle
    let shm_handle = Object::try_from(&shm)
        .map_err(|e| io::Error::other(format!("Failed to export handle: {}", e)))?;

    println!("[Producer] Sending shared memory handle to consumer...");
    endpoint.send(b"shm_transfer", &[shm_handle])?;

    // Wait for acknowledgment
    let response = endpoint.recv()?;
    println!(
        "[Producer] Consumer acknowledged: '{}'",
        String::from_utf8_lossy(&response.payload)
    );

    // Check if consumer wrote back
    let consumer_response_offset = 200;
    let consumer_data = shm.read(consumer_response_offset, Some(50));
    if !consumer_data.is_empty() && consumer_data[0] != 0 {
        println!(
            "[Producer] Consumer wrote back: '{}'",
            String::from_utf8_lossy(consumer_data)
        );
    }

    println!("[Producer] Done");

    Ok(())
}

fn run_consumer() -> io::Result<()> {
    println!("[Consumer] Starting and waiting for shared memory...");
    
    let mut listener = Listener::bind(SERVICE_NAME)?;
    println!("[Consumer] Listening on service: {}", SERVICE_NAME);

    // Accept connection
    let pod = listener.accept()?;
    println!("[Consumer] Producer connected!");

    let (connection, mut message) = pod.split();

    // Extract the shared memory handle
    if message.objects.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No shared memory handle received",
        ));
    }

    let shm_object = message.objects.pop().unwrap();
    println!("[Consumer] Received shared memory handle");

    // Create Shm from the received handle
    let shm = Shm::try_from(shm_object)
        .map_err(|e| io::Error::other(format!("Failed to import handle: {}", e)))?;

    println!("[Consumer] Mapped shared memory: {} bytes", shm.capacity());

    // Read the data written by producer
    let data = shm.read(0, Some(200));
    let text = String::from_utf8_lossy(data);
    println!("[Consumer] Read from shared memory:");
    println!("  {}", text.trim_end_matches('\0'));

    // Write a response back to shared memory
    let response = "Consumer was here!";
    let response_offset = 200;
    shm.write(response.as_bytes(), response_offset);
    println!("[Consumer] Wrote response at offset {}", response_offset);

    // Send acknowledgment
    connection.reply(b"Shared memory received and processed!", &[])?;
    println!("[Consumer] Sent acknowledgment");

    println!("[Consumer] Done");

    Ok(())
}

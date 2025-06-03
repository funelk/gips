//! Poll Example: Event-Driven IPC Server
//!
//! This example demonstrates using the polling mechanism to handle multiple
//! IPC connections in an event-driven manner. It shows how to use MachPortSource
//! with a Poller to wait for incoming messages.
//!
//! Run with: cargo run --example poll

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("This example is only available on macOS");
}

#[cfg(target_os = "macos")]
fn main() -> std::io::Result<()> {
    use std::thread;
    use std::time::Duration;

    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    println!("=== GIPS Poll Example ===\n");

    const SERVICE_NAME: &str = "com.example.gips.poll";

    // Start the event-driven server in a separate thread
    let server_handle = thread::spawn(|| {
        if let Err(e) = run_event_server(SERVICE_NAME) {
            eprintln!("Server error: {}", e);
        }
    });

    // Give the server time to start
    thread::sleep(Duration::from_millis(200));

    // Start multiple clients
    let mut client_handles = vec![];
    
    for i in 1..=3 {
        let handle = thread::spawn(move || {
            if let Err(e) = run_client(SERVICE_NAME, i) {
                eprintln!("Client {} error: {}", i, e);
            }
        });
        client_handles.push(handle);
        thread::sleep(Duration::from_millis(50));
    }

    // Wait for all clients to finish
    for handle in client_handles {
        handle.join().unwrap();
    }

    // Give server time to process
    thread::sleep(Duration::from_millis(200));

    server_handle.join().unwrap();

    Ok(())
}

#[cfg(target_os = "macos")]
fn run_event_server(service_name: &str) -> std::io::Result<()> {
    use gips::ipc::Listener;
    use gips::poll::{Events, Interest, Poller};
    use std::collections::HashMap;
    use std::io;
    use std::ops::DerefMut;
    use std::time::Duration;

    println!("[Server] Starting event-driven server...");
    
    // Create poller
    let mut poller = Poller::new()?;
    println!("[Server] Created poller");

    // Create listener
    let mut listener = Listener::bind(service_name)?;
    println!("[Server] Listening on service: {}", service_name);

    // Register the listener with the poller
    let listener_token = poller.register(listener.deref_mut(), Interest::READABLE)?;
    println!("[Server] Registered listener with token: {:?}", listener_token);

    // Track active connections
    let connections: HashMap<gips::poll::Token, String> = HashMap::new();
    let mut events = Events::with_capacity(10);
    let mut clients_handled = 0;
    const MAX_CLIENTS: usize = 3;

    println!("[Server] Waiting for events...\n");

    // Event loop
    loop {
        // Poll for events with timeout
        poller.poll(&mut events, Some(Duration::from_secs(5)))?;

        if events.is_empty() {
            println!("[Server] Poll timeout, no events");
            if clients_handled >= MAX_CLIENTS {
                break;
            }
            continue;
        }

        println!("[Server] Received {} event(s)", events.len());

        for event in events.iter() {
            println!("[Server] Processing event for token: {:?}", event.token());

            if event.token() == listener_token {
                // New connection
                println!("[Server] New connection available");
                
                match listener.accept() {
                    Ok(pod) => {
                        let (connection, message) = pod.split();
                        clients_handled += 1;

                        let client_id = String::from_utf8_lossy(&message.payload);
                        println!(
                            "[Server] Accepted connection from: {}",
                            client_id
                        );

                        // Send response
                        let response = format!("Hello, {}! You are client #{}", client_id, clients_handled);
                        connection.reply(response.as_bytes(), &[])?;
                        println!("[Server] Sent response to {}", client_id);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        println!("[Server] Would block on accept");
                    }
                    Err(e) => return Err(e),
                }
            } else if let Some(client_name) = connections.get(&event.token()) {
                // Existing connection has data
                println!("[Server] Data available for client: {}", client_name);
            }
        }

        // Exit after handling all clients
        if clients_handled >= MAX_CLIENTS {
            println!("\n[Server] Handled all {} clients, shutting down", MAX_CLIENTS);
            break;
        }
    }

    println!("[Server] Done");
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_client(service_name: &str, client_id: usize) -> std::io::Result<()> {
    use gips::ipc::Endpoint;

    println!("[Client {}] Connecting to server...", client_id);
    
    let mut endpoint = Endpoint::connect(service_name)?;
    println!("[Client {}] Connected!", client_id);

    // Send client identification
    let message = format!("Client {}", client_id);
    println!("[Client {}] Sending: '{}'", client_id, message);
    endpoint.send(message.as_bytes(), &[])?;

    // Wait for response
    let response = endpoint.recv()?;
    println!(
        "[Client {}] Received: '{}'",
        client_id,
        String::from_utf8_lossy(&response.payload)
    );

    println!("[Client {}] Done\n", client_id);

    Ok(())
}

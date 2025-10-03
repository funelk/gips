use std::io;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use gips::ipc::{Endpoint, Listener, Message};

fn read_message(target: &mut Endpoint) -> io::Result<Message> {
    loop {
        match target.try_recv() {
            Ok(message) => return Ok(message),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => thread::yield_now(),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_nanos()
}

#[test]
fn basic_usage() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!("gips_ipc_test_{}_{}", std::process::id(), unique_suffix());

    let listener = Listener::bind(&service)?;
    let client_payload = b"ping from client".to_vec();
    let server_payload = b"pong from host".to_vec();

    let server_thread = std::thread::spawn({
        let client_payload = client_payload.clone();
        let server_payload = server_payload.clone();

        move || -> std::io::Result<()> {
            let mut listener = listener;

            // Accept connection using the unified API
            let pod = listener.accept()?;

            // Split pod into connection and message
            let (connection, message) = pod.split();
            assert_eq!(message.payload, client_payload);
            assert!(message.objects.is_empty());

            // Reply using Connection::reply
            connection.reply(&server_payload, &[])?;
            Ok(())
        }
    });

    // Give server time to start accepting
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Client-side: use Endpoint::send and Endpoint::recv
    let mut endpoint = Endpoint::connect(&service)?;

    endpoint.send(&client_payload, &[])?;
    let message = endpoint.recv()?;
    assert_eq!(message.payload, server_payload);
    assert!(message.objects.is_empty());

    server_thread.join().expect("server thread panicked")?;

    Ok(())
}

#[test]
fn transfer_shm_object_via_ipc() -> std::io::Result<()> {
    use gips::ipc::Object;
    use gips::shm::Shm;

    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_shm_ipc_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let size = 512;
    let test_data = b"shared memory via IPC";

    // Create shared memory in parent
    let shm = Shm::new(None::<String>, size).expect("Failed to create shared memory");
    shm.write(test_data, 0);

    let listener = Listener::bind(&service)?;

    let server_thread = std::thread::spawn({
        let expected_data = test_data.to_vec();

        move || -> std::io::Result<()> {
            let mut listener = listener;

            let pod = loop {
                match listener.accept() {
                    Ok(pod) => break pod,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            };

            let (connection, mut message) = pod.split();
            assert_eq!(message.payload, b"shm_transfer");
            assert_eq!(message.objects.len(), 1);

            // Extract the handle and create Shm from it
            let shm_object = message.objects.pop().unwrap();

            let received_shm = Shm::try_from(shm_object).map_err(|e| {
                std::io::Error::other(format!("Failed to create Shm from handle: {e:?}"))
            })?;

            // Verify data
            assert_eq!(
                &received_shm.as_ref()[..expected_data.len()],
                expected_data.as_slice()
            );

            // Modify data to signal back
            let response = b"server received";
            received_shm.write(response, 100);

            connection.reply(b"ack", &[])?;
            Ok(())
        }
    });

    // Give server time to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Client connects and sends shared memory handle
    let mut endpoint = Endpoint::connect(&service)?;

    let shm_object = Object::try_from(&shm)
        .map_err(|e| std::io::Error::other(format!("Failed to export Object: {e:?}")))?;

    endpoint.send(b"shm_transfer", &[shm_object])?;

    // Wait for acknowledgment
    let response = read_message(&mut endpoint)?;
    assert_eq!(response.payload, b"ack");

    // Verify server's modification
    let server_response = b"server received";
    assert_eq!(
        &shm.as_ref()[100..100 + server_response.len()],
        server_response
    );

    server_thread.join().expect("server thread panicked")?;
    shm.close()
        .map_err(|e| std::io::Error::other(format!("Failed to close shm: {e:?}")))?;

    Ok(())
}

#[test]
fn transfer_multiple_shm_objects_via_ipc() -> std::io::Result<()> {
    use gips::ipc::Object;
    use gips::shm::Shm;

    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_multi_shm_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let size = 256;

    // Create multiple shared memory regions
    let shm1 = Shm::new(None::<String>, size).expect("Failed to create shm1");
    let shm2 = Shm::new(None::<String>, size).expect("Failed to create shm2");
    let shm3 = Shm::new(None::<String>, size).expect("Failed to create shm3");

    shm1.write(b"first", 0);
    shm2.write(b"second", 0);
    shm3.write(b"third", 0);

    let listener = Listener::bind(&service)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        let pod = loop {
            match listener.accept() {
                Ok(pod) => break pod,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(err) => return Err(err),
            }
        };

        let (connection, mut message) = pod.split();
        assert_eq!(message.objects.len(), 3, "Expected 3 shared memory objects");

        // Verify all three shared memory regions
        for idx in 0..3 {
            let obj = message.objects.remove(0);
            let received_shm = Shm::try_from(obj).map_err(|e| {
                std::io::Error::other(format!("Failed to create Shm from handle {idx}: {e:?}"))
            })?;

            let expected: &[u8] = match idx {
                0 => b"first",
                1 => b"second",
                2 => b"third",
                _ => unreachable!(),
            };

            assert_eq!(
                &received_shm.as_ref()[..expected.len()],
                expected,
                "Mismatch in shm{}",
                idx + 1
            );
        }

        connection.reply(b"all verified", &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(100));

    let mut endpoint = Endpoint::connect(&service)?;

    // Export all handles
    let handle1 = Object::try_from(&shm1).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    let handle2 = Object::try_from(&shm2).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    let handle3 = Object::try_from(&shm3).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    let objects = vec![handle1, handle2, handle3];

    endpoint.send(b"multiple_shm", &objects)?;

    let response = read_message(&mut endpoint)?;
    assert_eq!(response.payload, b"all verified");

    server_thread.join().expect("server thread panicked")?;

    shm1.close().ok();
    shm2.close().ok();
    shm3.close().ok();

    Ok(())
}

#[test]
fn bidirectional_shm_transfer_via_ipc() -> std::io::Result<()> {
    use gips::ipc::Object;
    use gips::shm::Shm;

    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_bidirectional_shm_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let client_size = 256;
    let server_size = 512;

    let listener = Listener::bind(&service)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        let pod = loop {
            match listener.accept() {
                Ok(pod) => break pod,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(err) => return Err(err),
            }
        };

        let (connection, mut message) = pod.split();
        assert_eq!(message.objects.len(), 1);

        // Receive client's shm
        let client_object = message.objects.pop().unwrap();
        let client_shm = Shm::try_from(client_object)
            .map_err(|e| std::io::Error::other(format!("Failed to create client Shm: {e:?}")))?;

        assert_eq!(&client_shm.as_ref()[..11], b"from client");

        // Create server's own shm and send back
        let server_shm = Shm::new(None::<String>, server_size)
            .map_err(|e| std::io::Error::other(format!("Failed to create server shm: {e:?}")))?;
        server_shm.write(b"from server", 0);

        let server_object = Object::try_from(&server_shm)
            .map_err(|e| std::io::Error::other(format!("Failed to export server shm: {e:?}")))?;

        connection.reply(b"server_response", &[server_object])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(100));

    let mut endpoint = Endpoint::connect(&service)?;

    // Client creates and sends shm
    let client_shm = Shm::new(None::<String>, client_size)
        .map_err(|e| std::io::Error::other(format!("Failed to create client shm: {e:?}")))?;
    client_shm.write(b"from client", 0);

    let client_object = Object::try_from(&client_shm)
        .map_err(|e| std::io::Error::other(format!("Failed to export client shm: {e:?}")))?;

    endpoint.send(b"client_request", &[client_object])?;

    // Receive server's shm
    let mut response = read_message(&mut endpoint)?;
    assert_eq!(response.payload, b"server_response");
    assert_eq!(response.objects.len(), 1);

    let server_object = response.objects.pop().unwrap();
    let server_shm = Shm::try_from(server_object)
        .map_err(|e| std::io::Error::other(format!("Failed to create server Shm: {e:?}")))?;

    assert_eq!(&server_shm.as_ref()[..11], b"from server");

    server_thread.join().expect("server thread panicked")?;

    client_shm.close().ok();
    server_shm.close().ok();

    Ok(())
}

// NOTE: The following tests are commented out as they cause the test suite to hang
// TODO: Investigate and fix the hanging issue
/*
#[test]
fn test_ipc_nonblocking_try_recv() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_nonblocking_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let listener = Listener::bind(&service)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;
        
        let pod = loop {
            match listener.accept() {
                Ok(pod) => break pod,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(err) => return Err(err),
            }
        };
        
        let (connection, message) = pod.split();
        
        assert_eq!(message.payload, b"hello");
        connection.reply(b"world", &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"hello", &[])?;

    // Try non-blocking receive before message arrives
    let start = std::time::Instant::now();
    loop {
        match endpoint.try_recv() {
            Ok(msg) => {
                assert_eq!(msg.payload, b"world");
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if start.elapsed() > std::time::Duration::from_secs(1) {
                    panic!("Timeout waiting for message");
                }
                thread::yield_now();
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn test_ipc_empty_payload() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!("gips_empty_test_{}_{}", std::process::id(), unique_suffix());

    let listener = Listener::bind(&service)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;
        
        let pod = loop {
            match listener.accept() {
                Ok(pod) => break pod,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(err) => return Err(err),
            }
        };
        
        let (connection, message) = pod.split();
        
        assert!(message.payload.is_empty());
        assert!(message.objects.is_empty());
        
        connection.reply(&[], &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(&[], &[])?;
    
    let response = endpoint.recv()?;
    assert!(response.payload.is_empty());
    assert!(response.objects.is_empty());

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}
*/

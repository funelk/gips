use std::io;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use gips::ipc::{Endpoint, Listener, Message, Policy, ServiceDescriptor};

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

    // Use blocking recv to ensure we get the response before connection closes
    let response = endpoint.recv()?;
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

// ACL Policy Tests

#[test]
fn acl_policy_allow_current_uid() -> std::io::Result<()> {
    use gips::ipc::Credentials;

    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_acl_uid_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    // Get current process UID
    let current_credentials = Credentials::current_process()?;

    // Create policy that allows only current UID
    let policy = Policy::new().with_allowed_uid([current_credentials.uid.clone()]);
    let descriptor = ServiceDescriptor::new(service.clone()).with_policy(policy);

    let listener = Listener::bind(descriptor)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        let pod = listener.accept()?;
        let (connection, message) = pod.split();

        assert_eq!(message.payload, b"allowed");
        connection.reply(b"accepted", &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"allowed", &[])?;
    let message = endpoint.recv()?;
    assert_eq!(message.payload, b"accepted");

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn acl_policy_deny_wrong_uid() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_acl_deny_uid_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    // Create policy that allows a non-existent UID
    let policy = Policy::new().with_allowed_uid(["99999"]);
    let descriptor = ServiceDescriptor::new(service.clone()).with_policy(policy);

    let listener = Listener::bind(descriptor)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        // Server should reject the connection in try_accept
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > std::time::Duration::from_secs(2) {
                break;
            }

            match listener.try_accept() {
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    // Expected: connection rejected due to ACL
                    return Ok(());
                }
                Ok(None) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Ok(Some(_)) => panic!("Expected permission denied, but connection was accepted"),
                Err(e) => return Err(e),
            }
        }

        panic!("Timeout waiting for rejected connection");
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"should_fail", &[])?;

    // Wait for server to process and reject
    std::thread::sleep(std::time::Duration::from_millis(200));

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn acl_policy_allow_current_gid() -> std::io::Result<()> {
    use gips::ipc::Credentials;

    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_acl_gid_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    // Get current process GIDs
    let current_credentials = Credentials::current_process()?;

    // Create policy that allows current GIDs
    let policy = Policy::new().with_allowed_gid(current_credentials.gid_list.clone());
    let descriptor = ServiceDescriptor::new(service.clone()).with_policy(policy);

    let listener = Listener::bind(descriptor)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        let pod = listener.accept()?;
        let (connection, message) = pod.split();

        assert_eq!(message.payload, b"gid_allowed");
        connection.reply(b"gid_accepted", &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"gid_allowed", &[])?;
    let message = endpoint.recv()?;
    assert_eq!(message.payload, b"gid_accepted");

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn acl_policy_deny_wrong_gid() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_acl_deny_gid_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    // Create policy that allows a non-existent GID
    let policy = Policy::new().with_allowed_gid(["99999"]);
    let descriptor = ServiceDescriptor::new(service.clone()).with_policy(policy);

    let listener = Listener::bind(descriptor)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        // Server should reject the connection in try_accept
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > std::time::Duration::from_secs(2) {
                break;
            }

            match listener.try_accept() {
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    // Expected: connection rejected due to ACL
                    return Ok(());
                }
                Ok(None) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Ok(Some(_)) => panic!("Expected permission denied, but connection was accepted"),
                Err(e) => return Err(e),
            }
        }

        panic!("Timeout waiting for rejected connection");
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"should_fail_gid", &[])?;

    // Wait for server to process and reject
    std::thread::sleep(std::time::Duration::from_millis(200));

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn acl_policy_custom_validator() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_acl_validator_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let current_pid = std::process::id();

    // Create policy with custom validator that checks PID
    let policy = Policy::new().with_credential_validator(move |creds| {
        if creds.pid == current_pid {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PID mismatch in validator",
            ))
        }
    });

    let descriptor = ServiceDescriptor::new(service.clone()).with_policy(policy);

    let listener = Listener::bind(descriptor)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        let pod = listener.accept()?;
        let (connection, message) = pod.split();

        assert_eq!(message.payload, b"custom_validator");
        connection.reply(b"validator_passed", &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"custom_validator", &[])?;
    let message = endpoint.recv()?;
    assert_eq!(message.payload, b"validator_passed");

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn acl_policy_combined_constraints() -> std::io::Result<()> {
    use gips::ipc::Credentials;

    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_acl_combined_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let current_credentials = Credentials::current_process()?;

    // Create policy with multiple constraints
    let policy = Policy::new()
        .with_allowed_uid([current_credentials.uid.clone()])
        .with_allowed_gid(current_credentials.gid_list.clone())
        .with_credential_validator(|creds| {
            if creds.pid > 0 {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Invalid PID",
                ))
            }
        });

    let descriptor = ServiceDescriptor::new(service.clone()).with_policy(policy);

    let listener = Listener::bind(descriptor)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        let pod = listener.accept()?;
        let (connection, message) = pod.split();

        assert_eq!(message.payload, b"all_checks");
        connection.reply(b"all_passed", &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"all_checks", &[])?;
    let message = endpoint.recv()?;
    assert_eq!(message.payload, b"all_passed");

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn acl_policy_unrestricted() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_acl_unrestricted_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    // Default policy is unrestricted
    let listener = Listener::bind(&service)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        let pod = listener.accept()?;
        let (connection, message) = pod.split();

        assert_eq!(message.payload, b"unrestricted");
        connection.reply(b"accepted_unrestricted", &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"unrestricted", &[])?;
    let message = endpoint.recv()?;
    assert_eq!(message.payload, b"accepted_unrestricted");

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn acl_policy_credentials_available() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_acl_creds_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let listener = Listener::bind(&service)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        let pod = listener.accept()?;
        let credentials = pod.credentials();

        // Verify credentials are populated
        assert!(credentials.pid > 0, "PID should be positive");
        assert!(!credentials.uid.is_empty(), "UID should not be empty");
        assert!(
            !credentials.gid_list.is_empty(),
            "GID list should not be empty"
        );

        let (connection, message) = pod.split();
        assert_eq!(message.payload, b"check_creds");
        connection.reply(b"creds_verified", &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"check_creds", &[])?;
    let message = endpoint.recv()?;
    assert_eq!(message.payload, b"creds_verified");

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn acl_policy_try_accept_with_policy() -> std::io::Result<()> {
    use gips::ipc::Credentials;

    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_acl_try_accept_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let current_credentials = Credentials::current_process()?;
    let policy = Policy::new().with_allowed_uid([current_credentials.uid.clone()]);
    let descriptor = ServiceDescriptor::new(service.clone()).with_policy(policy);

    let listener = Listener::bind(descriptor)?;

    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        // Use try_accept (non-blocking)
        let pod = loop {
            match listener.try_accept()? {
                Some(pod) => break pod,
                None => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
            }
        };

        let (connection, message) = pod.split();
        assert_eq!(message.payload, b"try_accept");
        connection.reply(b"try_accept_ok", &[])?;
        Ok(())
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut endpoint = Endpoint::connect(&service)?;
    endpoint.send(b"try_accept", &[])?;
    let message = endpoint.recv()?;
    assert_eq!(message.payload, b"try_accept_ok");

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn multiple_concurrent_clients() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_multi_client_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let num_clients = 10;
    let listener = Listener::bind(&service)?;

    // Server thread: accept connections from all clients
    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        for _ in 0..num_clients {
            let pod = listener.accept()?;
            let (connection, message) = pod.split();

            // Parse the client ID from the message and echo it back
            let msg_str = String::from_utf8_lossy(&message.payload);
            assert!(msg_str.starts_with("client_"));

            let response = format!("response_{}", &msg_str[7..]);
            connection.reply(response.as_bytes(), &[])?;
        }

        Ok(())
    });

    // Give server time to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Spawn multiple client threads simultaneously
    let mut client_threads = Vec::new();
    for i in 0..num_clients {
        let service = service.clone();
        let client_thread = std::thread::spawn(move || -> std::io::Result<()> {
            let mut endpoint = Endpoint::connect(&service)?;

            let request = format!("client_{}", i);
            endpoint.send(request.as_bytes(), &[])?;

            let message = endpoint.recv()?;
            let expected = format!("response_{}", i);
            assert_eq!(message.payload, expected.as_bytes());

            Ok(())
        });
        client_threads.push(client_thread);
    }

    // Wait for all clients to complete
    for (i, thread) in client_threads.into_iter().enumerate() {
        thread
            .join()
            .unwrap_or_else(|_| panic!("client thread {} panicked", i))?;
    }

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn rapid_connection_burst() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!("gips_burst_test_{}_{}", std::process::id(), unique_suffix());

    let num_clients = 20;
    let listener = Listener::bind(&service)?;

    // Server thread
    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        for i in 0..num_clients {
            let pod = listener.accept()?;
            let (connection, message) = pod.split();

            assert_eq!(message.payload, b"burst");
            connection.reply(format!("ack_{}", i).as_bytes(), &[])?;
        }

        Ok(())
    });

    // Wait a bit shorter to test race conditions
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Spawn all clients with minimal delay between them
    let mut client_threads = Vec::new();
    for _ in 0..num_clients {
        let service = service.clone();
        let client_thread = std::thread::spawn(move || -> std::io::Result<()> {
            let mut endpoint = Endpoint::connect(&service)?;
            endpoint.send(b"burst", &[])?;
            let _message = endpoint.recv()?;
            Ok(())
        });
        client_threads.push(client_thread);
        // Minimal delay to create burst
        std::thread::sleep(std::time::Duration::from_micros(100));
    }

    // Wait for all clients
    for (i, thread) in client_threads.into_iter().enumerate() {
        thread
            .join()
            .unwrap_or_else(|_| panic!("client thread {} panicked", i))?;
    }

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn sequential_connections() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_sequential_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let num_rounds = 5;
    let listener = Listener::bind(&service)?;

    // Server thread
    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;

        for round in 0..num_rounds {
            let pod = listener.accept()?;
            let (connection, message) = pod.split();

            let expected = format!("round_{}", round);
            assert_eq!(message.payload, expected.as_bytes());

            let response = format!("done_{}", round);
            connection.reply(response.as_bytes(), &[])?;
        }

        Ok(())
    });

    // Give server time to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Connect sequentially (one completes before next starts)
    for round in 0..num_rounds {
        let mut endpoint = Endpoint::connect(&service)?;

        let request = format!("round_{}", round);
        endpoint.send(request.as_bytes(), &[])?;

        let message = endpoint.recv()?;
        let expected = format!("done_{}", round);
        assert_eq!(message.payload, expected.as_bytes());

        // Explicitly drop to close connection
        drop(endpoint);

        // Small delay between rounds
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

#[test]
fn multiple_clients_multiple_messages() -> std::io::Result<()> {
    // This test simulates the RPC scenario where multiple clients
    // connect and send multiple messages each
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let service = format!(
        "gips_multi_msg_test_{}_{}",
        std::process::id(),
        unique_suffix()
    );

    let num_clients = 5;
    let messages_per_client = 10;
    let total_messages = num_clients * messages_per_client;

    let listener = Listener::bind(&service)?;

    // Server thread: accept connections and process messages
    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut listener = listener;
        let mut message_count = 0;

        while message_count < total_messages {
            let pod = listener.accept()?;
            let (connection, message) = pod.split();

            // Echo back the message
            connection.reply(&message.payload, &[])?;
            message_count += 1;
        }

        Ok(())
    });

    // Give server time to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Spawn multiple client threads
    let mut client_threads = Vec::new();
    for client_id in 0..num_clients {
        let service = service.clone();
        let client_thread = std::thread::spawn(move || -> std::io::Result<()> {
            let mut endpoint = Endpoint::connect(&service)?;

            for msg_id in 0..messages_per_client {
                let message = format!("client_{}_msg_{}", client_id, msg_id);
                endpoint.send(message.as_bytes(), &[])?;

                let response = endpoint.recv()?;
                assert_eq!(response.payload, message.as_bytes());
            }

            Ok(())
        });
        client_threads.push(client_thread);
    }

    // Wait for all clients
    for (i, thread) in client_threads.into_iter().enumerate() {
        thread
            .join()
            .unwrap_or_else(|_| panic!("client thread {} panicked", i))?;
    }

    server_thread.join().expect("server thread panicked")?;
    Ok(())
}

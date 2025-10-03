use std::io;
use std::thread;
use std::time::Duration;

#[cfg(target_os = "macos")]
#[test]
fn test_poll_mach_port() -> io::Result<()> {
    use gips::poll::{Events, Interest, MachPortSource, Poller};
    use gips::mach::Port;

    tracing_subscriber::fmt().with_target(false).try_init().ok();

    // Create a Mach port pair
    let receiver_port = Port::new();
    let send_port = receiver_port.raw();

    // Insert send right for the receiver port
    receiver_port.insert_right(mach2::message::MACH_MSG_TYPE_MAKE_SEND);

    // Create poller and register the receiver port
    let mut poller = Poller::new()?;
    let mut source = MachPortSource::new(receiver_port);
    let token = poller.register(&mut source, Interest::READABLE)?;

    // Poll with short timeout - should return nothing since no message sent yet
    let mut events = Events::with_capacity(10);
    poller.poll(&mut events, Some(Duration::from_millis(50)))?;
    assert_eq!(events.len(), 0, "Should not receive any events yet");

    // Send a message to the port from another thread
    let sender_thread = thread::spawn(move || -> io::Result<()> {
        thread::sleep(Duration::from_millis(100));

        use mach2::message::{
            mach_msg, mach_msg_header_t, MACH_MSG_TYPE_COPY_SEND, MACH_SEND_MSG,
        };

        let mut msg = mach_msg_header_t {
            msgh_bits: gips::mach::mach_msgh_bits_set(
                MACH_MSG_TYPE_COPY_SEND,
                0,
                0,
                0,
            ),
            msgh_size: std::mem::size_of::<mach_msg_header_t>() as u32,
            msgh_remote_port: send_port,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: 1234,
        };

        let kr = unsafe {
            mach_msg(
                &mut msg as *mut _ as *mut _,
                MACH_SEND_MSG,
                msg.msgh_size,
                0,
                0,
                0,
                0,
            )
        };

        assert_eq!(
            kr,
            mach2::kern_return::KERN_SUCCESS,
            "Failed to send mach message"
        );

        Ok(())
    });

    // Poll with longer timeout - should receive the event
    events.clear();
    poller.poll(&mut events, Some(Duration::from_millis(500)))?;

    assert_eq!(events.len(), 1, "Should receive exactly one event");

    let event = events.iter().next().unwrap();
    assert_eq!(event.token(), token, "Token should match");
    assert!(event.is_readable(), "Event should be readable");

    // Clean up
    sender_thread.join().expect("sender thread panicked")?;
    poller.deregister(&mut source, token)?;

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn test_poll_mach_port_multiple_messages() -> io::Result<()> {
    use gips::poll::{Events, Interest, MachPortSource, Poller};
    use gips::mach::Port;

    tracing_subscriber::fmt().with_target(false).try_init().ok();

    let receiver_port = Port::new();
    let send_port = receiver_port.raw();
    receiver_port.insert_right(mach2::message::MACH_MSG_TYPE_MAKE_SEND);

    let mut poller = Poller::new()?;
    let mut source = MachPortSource::new(receiver_port);
    let token = poller.register(&mut source, Interest::READABLE)?;

    // Send multiple messages
    let num_messages = 3;
    for i in 0..num_messages {
        use mach2::message::{
            mach_msg, mach_msg_header_t, MACH_MSG_TYPE_COPY_SEND, MACH_SEND_MSG,
        };

        let mut msg = mach_msg_header_t {
            msgh_bits: gips::mach::mach_msgh_bits_set(
                MACH_MSG_TYPE_COPY_SEND,
                0,
                0,
                0,
            ),
            msgh_size: std::mem::size_of::<mach_msg_header_t>() as u32,
            msgh_remote_port: send_port,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: 1000 + i,
        };

        let kr = unsafe {
            mach_msg(
                &mut msg as *mut _ as *mut _,
                MACH_SEND_MSG,
                msg.msgh_size,
                0,
                0,
                0,
                0,
            )
        };

        assert_eq!(
            kr,
            mach2::kern_return::KERN_SUCCESS,
            "Failed to send message {i}"
        );
    }

    // Poll should indicate port is readable
    let mut events = Events::with_capacity(10);
    poller.poll(&mut events, Some(Duration::from_millis(100)))?;

    assert!(!events.is_empty(), "Should receive at least one event");

    let event = events.iter().next().unwrap();
    assert_eq!(event.token(), token);
    assert!(event.is_readable());

    poller.deregister(&mut source, token)?;

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn test_poll_mach_port_timeout() -> io::Result<()> {
    use gips::poll::{Events, Interest, MachPortSource, Poller};
    use gips::mach::Port;

    tracing_subscriber::fmt().with_target(false).try_init().ok();

    let receiver_port = Port::new();
    receiver_port.insert_right(mach2::message::MACH_MSG_TYPE_MAKE_SEND);

    let mut poller = Poller::new()?;
    let mut source = MachPortSource::new(receiver_port);
    let _token = poller.register(&mut source, Interest::READABLE)?;

    // Poll with a short timeout and no messages - should timeout
    let mut events = Events::with_capacity(10);
    let start = std::time::Instant::now();
    poller.poll(&mut events, Some(Duration::from_millis(100)))?;
    let elapsed = start.elapsed();

    assert!(
        elapsed >= Duration::from_millis(100),
        "Poll should respect the timeout"
    );
    assert!(
        elapsed < Duration::from_millis(200),
        "Poll shouldn't take much longer than timeout"
    );
    assert_eq!(events.len(), 0, "No events should be received");

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn test_poll_mach_port_reregister() -> io::Result<()> {
    use gips::poll::{Events, Interest, MachPortSource, Poller};
    use gips::mach::Port;

    tracing_subscriber::fmt().with_target(false).try_init().ok();

    let receiver_port = Port::new();
    let send_port = receiver_port.raw();
    receiver_port.insert_right(mach2::message::MACH_MSG_TYPE_MAKE_SEND);

    let mut poller = Poller::new()?;
    let mut source = MachPortSource::new(receiver_port);
    let token1 = poller.register(&mut source, Interest::READABLE)?;

    // Deregister
    poller.deregister(&mut source, token1)?;

    // Re-register with a new token
    let token2 = poller.register(&mut source, Interest::READABLE)?;
    assert_ne!(token1, token2, "Tokens should be different");

    // Send a message
    use mach2::message::{
        mach_msg, mach_msg_header_t, MACH_MSG_TYPE_COPY_SEND, MACH_SEND_MSG,
    };

    let mut msg = mach_msg_header_t {
        msgh_bits: gips::mach::mach_msgh_bits_set(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0),
        msgh_size: std::mem::size_of::<mach_msg_header_t>() as u32,
        msgh_remote_port: send_port,
        msgh_local_port: 0,
        msgh_voucher_port: 0,
        msgh_id: 5678,
    };

    let kr = unsafe {
        mach_msg(
            &mut msg as *mut _ as *mut _,
            MACH_SEND_MSG,
            msg.msgh_size,
            0,
            0,
            0,
            0,
        )
    };

    assert_eq!(kr, mach2::kern_return::KERN_SUCCESS);

    // Poll should receive event with new token
    let mut events = Events::with_capacity(10);
    poller.poll(&mut events, Some(Duration::from_millis(100)))?;

    assert_eq!(events.len(), 1);
    let event = events.iter().next().unwrap();
    assert_eq!(event.token(), token2, "Should use the new token");
    assert!(event.is_readable());

    poller.deregister(&mut source, token2)?;

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn test_poll_mach_port_only_readable_interest() -> io::Result<()> {
    use gips::poll::{Interest, MachPortSource, Poller};
    use gips::mach::Port;

    tracing_subscriber::fmt().with_target(false).try_init().ok();

    let receiver_port = Port::new();
    let mut poller = Poller::new()?;
    let mut source = MachPortSource::new(receiver_port);

    // Try to register with writable interest - should fail
    let result = poller.register(&mut source, Interest::WRITABLE);
    assert!(
        result.is_err(),
        "Should not be able to register Mach port with writable interest"
    );

    // Readable interest should work
    let token = poller.register(&mut source, Interest::READABLE)?;
    assert!(token.into_usize() > 0);

    poller.deregister(&mut source, token)?;

    Ok(())
}

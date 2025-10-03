use gips::ipc::Object;
use gips::shm::{Header, Result, Shm};
use std::sync::atomic::{AtomicU64, Ordering};

fn unique_identifier(prefix: &str) -> String {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let base = format!("gips-test-{prefix}-{}-{id}", std::process::id());
    if cfg!(unix) {
        format!("/{base}")
    } else {
        base
    }
}

#[test]
fn named_shared_memory_initializes_header() -> Result<()> {
    let name = unique_identifier("named");
    let size = 256;
    let shm = Shm::new(name.clone(), size)?;

    assert_eq!(shm.name(), Some(name.as_str()));
    assert_eq!(shm.capacity(), size);
    assert!(shm.mapped() >= std::mem::size_of::<Header>());

    let payload = b"shared memory payload";
    let written = shm.write(payload, 0);
    assert_eq!(written, payload.len());
    assert_eq!(&shm.as_ref()[..written], payload);

    shm.close()?;
    Ok(())
}

#[test]
fn anonymous_shared_memory_can_round_trip_handles() -> Result<()> {
    let size = 128;
    let original = Shm::new(None::<String>, size)?;

    let initial = b"initial contents";
    let written = original.write(initial, 0);
    assert_eq!(written, initial.len());
    assert_eq!(&original.as_ref()[..written], initial);

    let handle = Object::try_from(&original)?;
    let follower = Shm::try_from(handle)?;

    assert_eq!(follower.capacity(), original.capacity());
    assert_eq!(&follower.as_ref()[..written], initial);

    let update = b"updated contents";
    let update_written = follower.write(update, 0);
    assert_eq!(update_written, update.len());
    assert_eq!(&original.as_ref()[..update_written], update);

    follower.close()?;
    original.close()?;
    Ok(())
}

#[test]
fn resize_increases_capacity_and_preserves_data() -> Result<()> {
    let name = unique_identifier("resize");
    let size = 64;

    use gips::shm::Size;
    let shm = Shm::new(
        name,
        Size {
            mapped: size,
            capacity: size * 4, // Allocate more capacity upfront to allow resizing
        },
    )?;

    let payload: Vec<u8> = (0u8..size as u8).collect();
    let written = shm.write(&payload, 0);
    assert_eq!(written, payload.len());

    let new_size = size * 2;
    let resized = shm.resize(new_size)?;
    assert_eq!(resized, new_size);
    assert_eq!(shm.capacity(), new_size);
    assert_eq!(&shm.as_ref()[..payload.len()], payload.as_slice());

    shm.close()?;
    Ok(())
}

#[test]
fn handle_transfer_preserves_data_integrity() -> Result<()> {
    let size = 512;
    let parent = Shm::new(None::<String>, size)?;

    // Parent writes initial data
    let data: Vec<u8> = (0..255).cycle().take(size).collect();
    let written = parent.write(&data, 0);
    assert_eq!(written, size);

    // Export handle (simulating IPC transfer)
    let handle = Object::try_from(&parent)?;

    // Import in "child process" (simulated by creating new Shm from handle)
    let child = Shm::try_from(handle)?;

    // Verify child sees parent's data
    assert_eq!(child.capacity(), parent.capacity());
    assert_eq!(child.as_ref(), parent.as_ref());

    // Child modifies data
    let update = b"child was here!";
    let update_pos = 100;
    let updated = child.write(update, update_pos);
    assert_eq!(updated, update.len());

    // Parent sees child's modifications
    assert_eq!(
        &parent.as_ref()[update_pos..update_pos + update.len()],
        update
    );

    child.close()?;
    parent.close()?;
    Ok(())
}

#[test]
fn multiple_handles_share_same_memory() -> Result<()> {
    let size = 256;
    let original = Shm::new(None::<String>, size)?;

    // Create multiple handles from the same shared memory
    let handle1 = Object::try_from(&original)?;
    let handle2 = Object::try_from(&original)?;
    let handle3 = Object::try_from(&original)?;

    let shm1 = Shm::try_from(handle1)?;
    let shm2 = Shm::try_from(handle2)?;
    let shm3 = Shm::try_from(handle3)?;

    // Write from first instance
    let msg1 = b"message from shm1";
    shm1.write(msg1, 0);

    // All instances see the same data
    assert_eq!(&shm2.as_ref()[..msg1.len()], msg1);
    assert_eq!(&shm3.as_ref()[..msg1.len()], msg1);
    assert_eq!(&original.as_ref()[..msg1.len()], msg1);

    // Write from second instance
    let msg2 = b"message from shm2";
    shm2.write(msg2, 50);

    // All instances see the update
    assert_eq!(&shm1.as_ref()[50..50 + msg2.len()], msg2);
    assert_eq!(&shm3.as_ref()[50..50 + msg2.len()], msg2);
    assert_eq!(&original.as_ref()[50..50 + msg2.len()], msg2);

    shm3.close()?;
    shm2.close()?;
    shm1.close()?;
    original.close()?;
    Ok(())
}

#[test]
fn handle_survives_original_drop() -> Result<()> {
    let size = 128;
    let data = b"persistent data";

    // Create handle in inner scope
    let handle = {
        let temp_shm = Shm::new(None::<String>, size)?;
        temp_shm.write(data, 0);
        Object::try_from(&temp_shm)?
        // temp_shm is dropped here, but handle should remain valid
    };

    // Create new Shm from handle after original is dropped
    let recovered = Shm::try_from(handle)?;

    // Data should still be accessible
    assert_eq!(&recovered.as_ref()[..data.len()], data);

    recovered.close()?;
    Ok(())
}

#[test]
fn handle_transfer_with_large_data() -> Result<()> {
    let size = 2048; // 2KB
    let parent = Shm::new(None::<String>, size)?;

    // Write pattern data
    let pattern: Vec<u8> = (0..=255).cycle().take(size).collect();
    let written = parent.write(&pattern, 0);
    assert_eq!(written, size);

    // Export and transfer handle
    let handle = Object::try_from(&parent)?;
    let child = Shm::try_from(handle)?;

    // Verify all data transferred correctly
    assert_eq!(child.capacity(), size);
    assert_eq!(child.as_ref(), pattern.as_slice());

    child.close()?;
    parent.close()?;
    Ok(())
}

#[test]
fn handle_transfer_with_concurrent_writes() -> Result<()> {
    let size = 512;
    let shm = Shm::new(None::<String>, size)?;

    // Initialize with zeros
    let zeros = vec![0u8; size];
    shm.write(&zeros, 0);

    // Create two "processes" via handles
    let handle1 = Object::try_from(&shm)?;
    let handle2 = Object::try_from(&shm)?;

    let proc1 = Shm::try_from(handle1)?;
    let proc2 = Shm::try_from(handle2)?;

    // Process 1 writes to first half
    let data1: Vec<u8> = (1..=255).collect();
    proc1.write(&data1, 0);

    // Process 2 writes to second half
    let data2: Vec<u8> = (100..=200).cycle().take(256).collect();
    proc2.write(&data2, 256);

    // Verify both writes are visible in original
    assert_eq!(&shm.as_ref()[..data1.len()], data1.as_slice());
    assert_eq!(&shm.as_ref()[256..256 + data2.len()], data2.as_slice());

    // Verify both writes are visible to each process
    assert_eq!(&proc1.as_ref()[256..256 + data2.len()], data2.as_slice());
    assert_eq!(&proc2.as_ref()[..data1.len()], data1.as_slice());

    proc2.close()?;
    proc1.close()?;
    shm.close()?;
    Ok(())
}

#[test]
fn handle_transfer_zero_capacity() -> Result<()> {
    // Edge case: transfer handle of minimal shared memory
    let size = 1;
    let shm = Shm::new(None::<String>, size)?;

    let byte = 0x42;
    shm.write(&[byte], 0);

    let handle = Object::try_from(&shm)?;
    let other = Shm::try_from(handle)?;

    assert_eq!(other.capacity(), size);
    assert_eq!(other.as_ref()[0], byte);

    other.close()?;
    shm.close()?;
    Ok(())
}

#[test]
fn handle_can_be_converted_multiple_times() -> Result<()> {
    let size = 256;
    let shm = Shm::new(None::<String>, size)?;

    let test_data = b"test data for multiple conversions";
    shm.write(test_data, 0);

    // Convert to handle and back multiple times
    for iteration in 0..5 {
        let handle = Object::try_from(&shm)?;
        let recovered = Shm::try_from(handle)?;

        // Data should still be intact
        assert_eq!(
            &recovered.as_ref()[..test_data.len()],
            test_data,
            "Data corrupted in iteration {iteration}"
        );

        // Write iteration marker
        let marker = format!("iteration:{iteration}");
        recovered.write(marker.as_bytes(), 50);

        // Original should see the marker
        assert_eq!(&shm.as_ref()[50..50 + marker.len()], marker.as_bytes());

        recovered.close()?;
    }

    shm.close()?;
    Ok(())
}

#[test]
fn test_read_with_offset_and_size() -> Result<()> {
    let size = 256;
    let shm = Shm::new(None::<String>, size)?;

    let data = b"Hello, World! This is a test message.";
    shm.write(data, 10);

    // Read with offset and specific size
    let read_data = shm.read(10, Some(13));
    assert_eq!(read_data, b"Hello, World!");

    // Read to end without size
    let read_all = shm.read(10, None);
    assert_eq!(&read_all[..data.len()], data);

    // Read beyond bounds
    let empty = shm.read(1000, Some(10));
    assert!(empty.is_empty());

    shm.close()?;
    Ok(())
}

#[test]
fn test_write_boundary_conditions() -> Result<()> {
    let size = 100;
    let shm = Shm::new(None::<String>, size)?;

    // Write at the very end
    let last_byte = b"X";
    let written = shm.write(last_byte, size - 1);
    assert_eq!(written, 1);
    assert_eq!(shm.as_ref()[size - 1], b'X');

    // Try to write beyond capacity
    let written_overflow = shm.write(b"overflow", size);
    assert_eq!(written_overflow, 0);

    // Write with partial overflow
    let partial = b"partial";
    let written_partial = shm.write(partial, size - 3);
    assert_eq!(written_partial, 3);

    shm.close()?;
    Ok(())
}

#[test]
fn test_header_capacity_tracking() -> Result<()> {
    let size = 128;
    let shm = Shm::new(None::<String>, size)?;

    assert_eq!(shm.header().capacity(), size);
    assert_eq!(shm.capacity(), size);

    // The header's capacity should match
    let header = shm.header();
    assert_eq!(header.capacity(), size);
    assert!(!header.invalid());

    shm.close()?;
    Ok(())
}

use super::PacketPool;
use crate::Error;

#[test]
fn packet_references_share_immutable_bytes_until_all_owners_release() {
    let mut pool = PacketPool::<32, 1>::new();
    let first = pool.reserve().unwrap();
    pool.write(&first, b"serialized").unwrap();
    let second = pool.retain(&first).unwrap();

    assert_eq!(pool.get(&first), Some(&b"serialized"[..]));
    assert_eq!(pool.get(&second), Some(&b"serialized"[..]));
    assert_eq!(pool.write(&first, b"changed"), Err(Error::Capacity));
    assert_eq!(pool.get(&second), Some(&b"serialized"[..]));

    pool.release(first);
    assert_eq!(pool.available(), 0);
    assert_eq!(pool.get(&second), Some(&b"serialized"[..]));
    pool.release(second);
    assert_eq!(pool.available(), 1);
}

#[test]
fn write_rejects_oversize_without_changing_existing_bytes() {
    let mut pool = PacketPool::<4, 1>::new();
    let packet = pool.reserve().unwrap();
    pool.write(&packet, b"ok").unwrap();
    assert_eq!(pool.write(&packet, b"oversize"), Err(Error::Capacity));
    assert_eq!(pool.get(&packet), Some(&b"ok"[..]));
}

#[test]
fn pool_exhaustion_and_zero_capacity_are_explicit() {
    let mut pool = PacketPool::<8, 1>::new();
    let held = pool.reserve().unwrap();
    assert_eq!(pool.available(), 0);
    assert_eq!(pool.reserve(), Err(Error::Capacity));
    pool.release(held);

    let mut empty = PacketPool::<8, 0>::new();
    assert_eq!(empty.available(), 0);
    assert_eq!(empty.reserve(), Err(Error::Capacity));
}

#[test]
fn encoding_commits_the_same_storage_without_copying() {
    let mut pool = PacketPool::<16, 1>::new();
    let packet = pool.reserve().unwrap();
    let output = pool
        .encode(&packet, |bytes| {
            assert_eq!(bytes.len(), 16);
            bytes[..4].copy_from_slice(b"wire");
            Ok((4, bytes.as_ptr()))
        })
        .unwrap();
    assert_eq!(pool.get(&packet).unwrap().as_ptr(), output);
    assert_eq!(pool.get(&packet), Some(&b"wire"[..]));
    pool.release(packet);
}

#[test]
fn encoding_requires_unique_live_ownership_and_clears_failed_output() {
    let mut pool = PacketPool::<8, 1>::new();
    let packet = pool.reserve().unwrap();
    pool.write(&packet, b"original").unwrap();
    let shared = pool.retain(&packet).unwrap();
    assert_eq!(
        pool.encode(&packet, |_| -> Result<(usize, ()), Error> {
            panic!("shared storage must not be passed to an encoder")
        }),
        Err(Error::Capacity)
    );
    assert_eq!(pool.get(&packet), Some(&b"original"[..]));
    pool.release(shared);
    assert_eq!(
        pool.encode(&packet, |bytes| {
            bytes.fill(0x55);
            Err::<(usize, ()), _>(Error::Malformed)
        }),
        Err(Error::Malformed)
    );
    assert_eq!(pool.get(&packet), Some(&b""[..]));
    assert_eq!(pool.encode(&packet, |_| Ok((9, ()))), Err(Error::Capacity));
    assert_eq!(pool.get(&packet), Some(&b""[..]));
    pool.release(packet);
}

#[cfg(feature = "_xarxa")]
mod owned {
    use super::*;
    use crate::packet_pool::XarxaStorage;
    use xarxa::{Pool, StaticPool};

    #[test]
    fn network_buffer_is_direct_and_only_unique_owners_can_transfer_it() {
        static NETWORK: StaticPool<128, 1> = StaticPool::new();
        let storage = XarxaStorage::<_, 1>::new(|| {
            let mut buffer = NETWORK.alloc()?;
            buffer.reserve(32);
            Some(buffer)
        });
        let mut pool = PacketPool::<64, 1, _>::with_storage(storage);
        let packet = pool.reserve().unwrap();
        assert!(NETWORK.alloc().is_none());
        let output = pool
            .encode(&packet, |bytes| {
                bytes[..4].copy_from_slice(b"wire");
                Ok((4, bytes.as_ptr()))
            })
            .unwrap();
        assert_eq!(pool.get(&packet).unwrap().as_ptr(), output);
        let shared = pool.retain(&packet).unwrap();
        assert!(pool.owned_buffer(&packet).is_none());
        pool.release(shared);
        let buffer = pool.owned_buffer(&packet).unwrap().take().unwrap();
        assert_eq!(buffer.as_ptr(), output);
        assert_eq!(&*buffer, b"wire");
        assert_eq!(buffer.headroom(), 32);
        assert!(pool.get(&packet).is_none());
        *pool.owned_buffer(&packet).unwrap() = Some(buffer);
        assert_eq!(pool.get(&packet), Some(&b"wire"[..]));
        pool.release(packet);
        assert!(NETWORK.alloc().is_some());
    }

    #[test]
    fn exhaustion_and_undersized_buffers_preserve_logical_capacity() {
        static NETWORK: StaticPool<128, 1> = StaticPool::new();
        let held = NETWORK.alloc().unwrap();
        let mut pool = PacketPool::<64, 1, _>::with_storage(XarxaStorage::new(|| NETWORK.alloc()));
        assert_eq!(pool.reserve(), Err(Error::Capacity));
        assert_eq!(pool.available(), 1);
        drop(held);
        let packet = pool.reserve().unwrap();
        pool.release(packet);
        drop(pool);
        let mut undersized =
            PacketPool::<129, 1, _>::with_storage(XarxaStorage::new(|| NETWORK.alloc()));
        assert_eq!(undersized.reserve(), Err(Error::InvalidStorage));
        assert_eq!(undersized.available(), 1);
        assert!(NETWORK.alloc().is_some());
    }

    #[test]
    fn failed_encoding_empties_payload_and_pool_drop_releases_buffers() {
        static NETWORK: StaticPool<128, 1> = StaticPool::new();
        let mut pool = PacketPool::<64, 1, _>::with_storage(XarxaStorage::new(|| NETWORK.alloc()));
        let packet = pool.reserve().unwrap();
        assert_eq!(
            pool.encode(&packet, |bytes| {
                bytes.fill(0x55);
                Err::<(usize, ()), _>(Error::Malformed)
            }),
            Err(Error::Malformed)
        );
        assert_eq!(pool.get(&packet), Some(&b""[..]));
        assert_eq!(pool.encode(&packet, |_| Ok((65, ()))), Err(Error::Capacity));
        assert_eq!(pool.get(&packet), Some(&b""[..]));
        drop(pool);
        let mut recovered = NETWORK.alloc().unwrap();
        assert!(recovered.storage_mut()[..64].iter().all(|byte| *byte == 0));
    }
}

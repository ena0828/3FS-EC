use hf3fs_ec::wire::{encoded_len, Frame, FrameKind, SessionId, HEADER_LEN};

// Independent CRC oracle: normal polynomial and MSB-first division, with
// explicit input/output reflection, rather than the production reflected loop.
fn checksum(bytes: &[u8]) -> u32 {
    let mut remainder = u32::MAX;
    for &byte in bytes {
        remainder ^= u32::from(byte.reverse_bits()) << 24;
        for _ in 0..8 {
            let high = remainder & 0x8000_0000 != 0;
            remainder <<= 1;
            if high {
                remainder ^= 0x1edc_6f41;
            }
        }
    }
    !remainder.reverse_bits()
}

fn refresh_header(bytes: &mut [u8]) {
    let crc = checksum(&bytes[..124]);
    bytes[124..128].copy_from_slice(&crc.to_le_bytes());
}

fn refresh_body_and_header(bytes: &mut [u8]) {
    let crc = checksum(&bytes[HEADER_LEN..]);
    bytes[120..124].copy_from_slice(&crc.to_le_bytes());
    refresh_header(bytes);
}

fn sample() -> Frame {
    Frame {
        kind: FrameKind::Slice,
        session: SessionId {
            job: 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
            plan: std::array::from_fn(|i| 0x80 + i as u8),
            stripe: 0x1f1e_1d1c_1b1a_1918_1716_1514_1312_1110,
            generation: 0x2726_2524_2322_2120,
            epoch: 0x2f2e_2d2c_2b2a_2928,
        },
        sequence: 0x3736_3534_3332_3130,
        offset: 0x4746_4544_4342_4140,
        valid_len: 3,
        hop: 0x1234,
        targets: vec![0x0302, 0x0100],
        payload: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    }
}

#[test]
fn exact_little_endian_layout_matches_independent_crc() {
    assert_eq!(HEADER_LEN, 128);
    assert_eq!(checksum(b"123456789"), 0xe306_9283);
    assert_eq!(checksum(&[]), 0);
    let frame = sample();
    let bytes = frame.encode(10).unwrap();
    let body = [2, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let mut expected = vec![
        b'3', b'F', b'S', b'E', b'C', b'W', 0, 0, // magic
        1, 0, 1, 0, // version, Slice, reserved
        10, 0, 0, 0, 2, 0, 0x34, 0x12, // body length, count, hop
        3, 0, 0, 0, // valid length
    ];
    expected.extend(0x30..=0x37); // sequence
    expected.extend(0x40..=0x47); // offset
    expected.extend(0..=15); // job
    expected.extend(0x80..=0x9f); // plan
    expected.extend(0x10..=0x1f); // stripe
    expected.extend(0x20..=0x27); // generation
    expected.extend(0x28..=0x2f); // epoch
    expected.extend_from_slice(&checksum(&body).to_le_bytes());
    assert_eq!(expected.len(), 124);
    expected.extend_from_slice(&checksum(&expected).to_le_bytes());
    expected.extend_from_slice(&body);
    assert_eq!(bytes, expected);
    assert_eq!(encoded_len(&bytes[..HEADER_LEN], 10).unwrap(), 138);
    assert_eq!(Frame::decode(&bytes, 10).unwrap(), frame);
}

#[test]
fn all_kinds_and_tail_lengths_round_trip_with_exact_limits() {
    for kind in [
        FrameKind::Slice,
        FrameKind::Finish,
        FrameKind::Ack,
        FrameKind::Failure,
    ] {
        for length in (0..=193).chain([257, 4099]) {
            if kind == FrameKind::Slice && length == 0 {
                continue;
            }
            let mut frame = sample();
            frame.kind = kind;
            frame.valid_len = if kind == FrameKind::Slice {
                length as u32
            } else {
                u32::MAX
            };
            frame.payload = (0..length * 2).map(|i| (i * 113) as u8).collect();
            let before = frame.clone();
            let limit = 4 + frame.payload.len();
            let bytes = frame.encode(limit).unwrap();
            assert_eq!(
                encoded_len(&bytes[..HEADER_LEN], limit).unwrap(),
                bytes.len()
            );
            assert_eq!(Frame::decode(&bytes, limit).unwrap(), frame);
            assert!(frame.encode(limit - 1).is_err());
            assert!(encoded_len(&bytes[..HEADER_LEN], limit - 1).is_err());
            assert!(Frame::decode(&bytes, limit - 1).is_err());
            assert_eq!(frame, before);
        }
    }
    for kind in [FrameKind::Finish, FrameKind::Ack, FrameKind::Failure] {
        let mut frame = sample();
        frame.kind = kind;
        frame.targets.clear();
        frame.payload.clear();
        let bytes = frame.encode(0).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(Frame::decode(&bytes, 0).unwrap(), frame);
    }
}

#[test]
fn truncation_extra_bytes_and_each_single_bit_corruption_are_rejected() {
    let bytes = sample().encode(10).unwrap();
    for end in 0..bytes.len() {
        assert!(
            Frame::decode(&bytes[..end], 10).is_err(),
            "truncated at {end}"
        );
    }
    for end in 0..HEADER_LEN {
        assert!(encoded_len(&bytes[..end], 10).is_err());
    }
    assert!(encoded_len(&bytes[..HEADER_LEN + 1], 10).is_err());
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Frame::decode(&extra, 10).is_err());
    extra.extend_from_slice(&bytes);
    assert!(Frame::decode(&extra, 10).is_err());
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut damaged = bytes.clone();
            damaged[index] ^= 1 << bit;
            assert!(
                Frame::decode(&damaged, 10).is_err(),
                "bit {bit} at byte {index}"
            );
        }
    }
}

#[test]
fn unknown_header_fields_are_rejected_even_with_valid_checksums() {
    let bytes = sample().encode(10).unwrap();
    for kind in [0, 5, 255] {
        let mut changed = bytes.clone();
        changed[10] = kind;
        refresh_header(&mut changed);
        assert!(encoded_len(&changed[..HEADER_LEN], 10).is_err());
        assert!(Frame::decode(&changed, 10).is_err());
    }
    for version in [0u16, 2, u16::MAX] {
        let mut changed = bytes.clone();
        changed[8..10].copy_from_slice(&version.to_le_bytes());
        refresh_header(&mut changed);
        assert!(encoded_len(&changed[..HEADER_LEN], 10).is_err());
    }
    for reserved in [1, 128, 255] {
        let mut changed = bytes.clone();
        changed[11] = reserved;
        refresh_header(&mut changed);
        assert!(encoded_len(&changed[..HEADER_LEN], 10).is_err());
    }
    let mut changed = bytes;
    changed[0] = b'X';
    refresh_header(&mut changed);
    assert!(encoded_len(&changed[..HEADER_LEN], 10).is_err());
}

#[test]
fn malicious_lengths_and_counts_fail_at_header_precheck() {
    let bytes = sample().encode(10).unwrap();
    // No body is supplied: limits must be enforced before a network reader
    // could reserve an attacker-controlled amount of memory.
    for count in [257u16, u16::MAX] {
        let mut header = bytes[..HEADER_LEN].to_vec();
        header[16..18].copy_from_slice(&count.to_le_bytes());
        refresh_header(&mut header);
        assert!(encoded_len(&header, usize::MAX).is_err());
    }
    let mut header = bytes[..HEADER_LEN].to_vec();
    header[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    refresh_header(&mut header);
    assert!(encoded_len(&header, 4096).is_err());
    assert!(Frame::decode(&header, 4096).is_err());

    header[10] = FrameKind::Finish as u8;
    refresh_header(&mut header);
    if let Some(expected) = HEADER_LEN.checked_add(u32::MAX as usize) {
        assert_eq!(encoded_len(&header, usize::MAX).unwrap(), expected);
    } else {
        assert!(encoded_len(&header, usize::MAX).is_err());
    }
    // Even if the caller deliberately permits a huge control body, an absent
    // body is rejected before its advertised payload can be allocated.
    assert!(Frame::decode(&header, usize::MAX).is_err());

    header[12..16].copy_from_slice(&3u32.to_le_bytes());
    refresh_header(&mut header);
    assert!(encoded_len(&header, 4096).is_err()); // 2 IDs need 4 bytes

    header[10] = FrameKind::Slice as u8;
    header[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    header[16..18].copy_from_slice(&256u16.to_le_bytes());
    header[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    refresh_header(&mut header);
    assert!(encoded_len(&header, usize::MAX).is_err()); // cannot wrap length * count
}

#[test]
fn target_limit_uniqueness_and_slice_shape_are_enforced() {
    let mut frame = sample();
    frame.valid_len = 1;
    frame.targets = (0..256).collect();
    frame.payload = vec![19; 256];
    let bytes = frame.encode(768).unwrap();
    assert_eq!(Frame::decode(&bytes, 768).unwrap(), frame);
    frame.targets.push(u16::MAX);
    frame.payload.push(19);
    assert!(frame.encode(usize::MAX).is_err());

    let frame = sample();
    let mut duplicate = frame.clone();
    duplicate.targets[1] = duplicate.targets[0];
    assert!(duplicate.encode(10).is_err());
    let mut bytes = frame.encode(10).unwrap();
    bytes[HEADER_LEN + 2..HEADER_LEN + 4].copy_from_slice(&frame.targets[0].to_le_bytes());
    refresh_body_and_header(&mut bytes);
    assert!(encoded_len(&bytes[..HEADER_LEN], 10).is_ok());
    assert!(Frame::decode(&bytes, 10).is_err());

    for (valid_len, targets, payload) in [
        (0, vec![1], vec![]),
        (1, vec![], vec![]),
        (5, vec![1, 2], vec![0; 9]),
        (5, vec![1, 2], vec![0; 11]),
    ] {
        let mut invalid = frame.clone();
        invalid.valid_len = valid_len;
        invalid.targets = targets;
        invalid.payload = payload;
        assert!(invalid.encode(4096).is_err());
    }
    for (valid_len, target_count, body_len) in
        [(0u32, 2u16, 4u32), (1, 0, 0), (3, 2, 9), (3, 2, 11)]
    {
        let mut header = frame.encode(10).unwrap()[..HEADER_LEN].to_vec();
        header[12..16].copy_from_slice(&body_len.to_le_bytes());
        header[16..18].copy_from_slice(&target_count.to_le_bytes());
        header[20..24].copy_from_slice(&valid_len.to_le_bytes());
        refresh_header(&mut header);
        assert!(encoded_len(&header, 4096).is_err());
    }
}

#[test]
fn valid_checksum_does_not_authenticate_session_or_payload() {
    let mut bytes = sample().encode(10).unwrap();
    bytes[40] ^= 0x80;
    bytes[HEADER_LEN + 4] ^= 1;
    refresh_body_and_header(&mut bytes);
    let changed = Frame::decode(&bytes, 10).unwrap();
    assert_ne!(changed.session, sample().session);
    assert_ne!(changed.payload, sample().payload);
    // This is intentional: only the executor can reject a validly checksummed
    // but unauthorized session or compare data against trusted content digests.
}

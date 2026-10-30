use hf3fs_ec::read::{crc32c, CancellationToken};
use hf3fs_ec::transport::{self, TransportControl};
use hf3fs_ec::wire::{Frame, FrameKind, SessionId, HEADER_LEN};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn control(milliseconds: u64) -> TransportControl {
    TransportControl {
        cancellation: CancellationToken::default(),
        deadline: Instant::now() + Duration::from_millis(milliseconds),
    }
}

fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

fn pair() -> (TcpStream, TcpStream) {
    let listener = listener();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.set_nodelay(true).unwrap();
    }
    (client, server)
}

fn frame(length: usize) -> Frame {
    Frame {
        kind: FrameKind::Slice,
        session: SessionId {
            job: 23,
            plan: [7; 32],
            stripe: 91,
            generation: 3,
            epoch: 8,
        },
        sequence: 19,
        offset: 4097,
        valid_len: length as u32,
        hop: 2,
        targets: vec![0, 11],
        payload: (0..length * 2).map(|i| (i * 71 + i / 251) as u8).collect(),
    }
}

#[test]
fn connects_and_exchanges_frames_with_fragmented_raw_peer_io() {
    let listener = listener();
    let address = listener.local_addr().unwrap();
    let incoming = frame(97);
    let reply = frame(70_003); // Requires multiple <=64 KiB transport writes.
    let incoming_bytes = incoming.encode(198).unwrap();
    let expected_reply = reply.encode(140_010).unwrap();
    let budget = control(5000);
    // Establish the queued connection before spawning a blocking raw accept;
    // a connect failure therefore cannot strand the test's peer thread.
    let mut stream = transport::connect(address, &budget).unwrap();
    std::thread::scope(|scope| {
        let peer = scope.spawn(|| {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.set_nodelay(true).unwrap();
            for chunk in incoming_bytes.chunks(3) {
                stream.write_all(chunk).unwrap();
                std::thread::sleep(Duration::from_millis(1));
            }
            let mut actual = vec![0; expected_reply.len()];
            for chunk in actual.chunks_mut(13) {
                stream.read_exact(chunk).unwrap();
            }
            assert_eq!(actual, expected_reply);
        });
        assert!(stream.nodelay().unwrap());
        assert_eq!(
            transport::receive(&mut stream, 198, &budget).unwrap(),
            incoming
        );
        transport::send(&mut stream, &reply, 140_010, &budget).unwrap();
        peer.join().unwrap();
    });
}

#[test]
fn accept_sets_nonblocking_and_receive_preserves_next_frame() {
    let listener = listener();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let budget = control(1000);
    let mut stream = transport::accept(&listener, &budget).unwrap();
    assert!(stream.nodelay().unwrap());
    let mut byte = [0];
    assert_eq!(
        stream.read(&mut byte).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    let first = frame(3);
    let mut second = frame(1);
    second.kind = FrameKind::Ack;
    second.targets.clear();
    second.payload.clear();
    let mut bytes = first.encode(10).unwrap();
    bytes.extend(second.encode(0).unwrap());
    peer.write_all(&bytes).unwrap();
    assert_eq!(transport::receive(&mut stream, 10, &budget).unwrap(), first);
    assert_eq!(transport::receive(&mut stream, 0, &budget).unwrap(), second);
}

#[test]
fn eof_at_each_frame_stage_is_reported_without_waiting_for_deadline() {
    let bytes = frame(3).encode(10).unwrap();
    for length in [0, 1, HEADER_LEN - 1, HEADER_LEN, bytes.len() - 1] {
        let (mut stream, mut peer) = pair();
        peer.write_all(&bytes[..length]).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let failure = transport::receive(&mut stream, 10, &control(1000)).unwrap_err();
        assert!(failure.0.contains("EOF"), "length={length}: {failure}");
    }
}

#[test]
fn bad_header_and_oversize_are_rejected_before_waiting_for_a_body() {
    let encoded = frame(3).encode(10).unwrap();
    for oversized in [false, true] {
        let (mut stream, mut peer) = pair();
        let mut header = encoded[..HEADER_LEN].to_vec();
        if oversized {
            header[10] = FrameKind::Failure as u8;
            header[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
            let checksum = crc32c(&header[..124]);
            header[124..128].copy_from_slice(&checksum.to_le_bytes());
        } else {
            header[0] ^= 1;
        }
        peer.write_all(&header).unwrap();
        // Keep the peer open and send no body: a body read would time out.
        let failure = transport::receive(&mut stream, 1024, &control(500)).unwrap_err();
        assert!(failure.0.contains(if oversized {
            "configured limit"
        } else {
            "magic"
        }));
    }
    let (mut stream, mut peer) = pair();
    let mut damaged = encoded;
    damaged[HEADER_LEN + 4] ^= 1;
    peer.write_all(&damaged).unwrap();
    let failure = transport::receive(&mut stream, 10, &control(500)).unwrap_err();
    assert!(failure.0.contains("CRC32C"));

    let (mut stream, mut peer) = pair();
    let failure = transport::send(&mut stream, &frame(3), 9, &control(500)).unwrap_err();
    assert!(failure.0.contains("configured limit"));
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn cancellation_interrupts_idle_receive_accept_and_failed_connect_retries() {
    std::thread::scope(|scope| {
        let (mut stream, _peer) = pair();
        let budget = control(2000);
        let cancellation = budget.cancellation.clone();
        let cancel = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            cancellation.cancel();
        });
        let failure = transport::receive(&mut stream, 1024, &budget).unwrap_err();
        assert!(failure.0.contains("cancelled"));
        cancel.join().unwrap();
    });
    std::thread::scope(|scope| {
        let listener = listener();
        let budget = control(2000);
        let cancellation = budget.cancellation.clone();
        let cancel = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            cancellation.cancel();
        });
        assert!(transport::accept(&listener, &budget)
            .unwrap_err()
            .0
            .contains("cancelled"));
        cancel.join().unwrap();
    });
    std::thread::scope(|scope| {
        let listener = listener();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let budget = control(2000);
        let cancellation = budget.cancellation.clone();
        let cancel = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            cancellation.cancel();
        });
        assert!(transport::connect(address, &budget)
            .unwrap_err()
            .0
            .contains("cancelled"));
        cancel.join().unwrap();
    });
}

#[test]
fn idle_operations_and_closed_listener_obey_absolute_deadlines() {
    let (mut stream, _peer) = pair();
    assert!(transport::receive(&mut stream, 1024, &control(25))
        .unwrap_err()
        .0
        .contains("deadline"));
    let listener = listener();
    assert!(transport::accept(&listener, &control(25))
        .unwrap_err()
        .0
        .contains("deadline"));
    let address = listener.local_addr().unwrap();
    drop(listener);
    assert!(transport::connect(address, &control(25))
        .unwrap_err()
        .0
        .contains("deadline"));
    let budget = control(0);
    assert!(budget.check().is_err());
    assert!(transport::send(&mut stream, &frame(3), 10, &budget)
        .unwrap_err()
        .0
        .contains("deadline"));
}

#[test]
fn arriving_body_bytes_do_not_reset_the_total_deadline() {
    let (mut stream, mut peer) = pair();
    let bytes = frame(193).encode(390).unwrap();
    let stop = CancellationToken::default();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
    std::thread::scope(|scope| {
        let stop_peer = stop.clone();
        let writer = scope.spawn(move || {
            peer.write_all(&bytes[..HEADER_LEN + 1]).unwrap();
            ready_tx.send(()).unwrap();
            for byte in &bytes[HEADER_LEN + 1..] {
                if stop_peer.is_cancelled() {
                    break;
                }
                if peer.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(4));
            }
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let budget = control(45);
        let failure = transport::receive(&mut stream, 390, &budget).unwrap_err();
        stop.cancel();
        assert!(failure.0.contains("deadline"));
        writer.join().unwrap();
    });
}

#[test]
fn cancellation_stops_a_send_when_the_peer_does_not_drain_its_socket() {
    let (mut stream, _peer) = pair();
    stream.set_nonblocking(true).unwrap();
    // Fill the real socket with a reusable buffer. Wait for stable backpressure
    // so the frame cannot simply fit into an otherwise empty kernel send queue.
    let filler = [0; 64 * 1024];
    let fill_deadline = Instant::now() + Duration::from_secs(3);
    let mut blocked = 0;
    while blocked < 10 {
        assert!(
            Instant::now() < fill_deadline,
            "socket did not reach backpressure"
        );
        match stream.write(&filler) {
            Ok(0) => panic!("unexpected closed socket while filling queue"),
            Ok(_) => blocked = 0,
            Err(failure) if failure.kind() == ErrorKind::WouldBlock => {
                blocked += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(failure) if failure.kind() == ErrorKind::Interrupted => {}
            Err(failure) => panic!("unexpected fill error: {failure}"),
        }
    }
    std::thread::scope(|scope| {
        let budget = control(2000);
        let cancellation = budget.cancellation.clone();
        let cancel = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            cancellation.cancel();
        });
        let failure = transport::send(&mut stream, &frame(3), 10, &budget).unwrap_err();
        assert!(failure.0.contains("cancelled"));
        cancel.join().unwrap();
    });
}

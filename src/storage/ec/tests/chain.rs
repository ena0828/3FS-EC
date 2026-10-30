use hf3fs_ec::chain::*;
use hf3fs_ec::read::CancellationToken;
use hf3fs_ec::transport::{self, TransportControl};
use hf3fs_ec::wire::{Frame, FrameKind, SessionId};
use hf3fs_ec::{Codec, Error, Result};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn session() -> SessionId {
    SessionId {
        job: 19,
        plan: [33; 32],
        stripe: 81,
        generation: 8,
        epoch: 3,
    }
}

fn control() -> TransportControl {
    TransportControl {
        cancellation: CancellationToken::default(),
        deadline: Instant::now() + Duration::from_secs(5),
    }
}

struct Source(Vec<u8>);
impl SliceSource for Source {
    fn read_slice(
        &mut self,
        _: usize,
        offset: u64,
        length: usize,
        control: &TransportControl,
    ) -> Result<Vec<u8>> {
        control.check()?;
        self.0
            .get(offset as usize..offset as usize + length)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| Error("short source".into()))
    }
}

#[derive(Default)]
struct State {
    bytes: Vec<Vec<u8>>,
    sealed: bool,
    aborted: bool,
}
struct Sink {
    targets: Vec<usize>,
    expected: Vec<Vec<u8>>,
    state: Arc<Mutex<State>>,
    fail_write: bool,
    fail_after_seal: bool,
}
impl RepairSink for Sink {
    fn write_slice(
        &mut self,
        target: usize,
        offset: u64,
        bytes: &[u8],
        control: &TransportControl,
    ) -> Result<()> {
        control.check()?;
        if self.fail_write {
            return Err(Error("injected write failure".into()));
        }
        let row = self.targets.iter().position(|&id| id == target).unwrap();
        let mut state = self.state.lock().unwrap();
        if state.bytes[row].len() as u64 != offset {
            return Err(Error("out of order write".into()));
        }
        state.bytes[row].extend_from_slice(bytes);
        Ok(())
    }
    fn seal(&mut self, control: &TransportControl) -> Result<()> {
        control.check()?;
        let mut state = self.state.lock().unwrap();
        if state.bytes != self.expected {
            return Err(Error("terminal integrity mismatch".into()));
        }
        state.sealed = true;
        if self.fail_after_seal {
            return Err(Error("injected unknown seal result".into()));
        }
        Ok(())
    }
    fn abort(&mut self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        assert!(!state.sealed, "must not abort sealed data");
        state.aborted = true;
        state.bytes.iter_mut().for_each(Vec::clear);
        Ok(())
    }
}

fn run(length: usize, fail_write: bool, fail_after_seal: bool) {
    let codec = Codec::new(3, 2).unwrap();
    let data: Vec<Vec<_>> = (0..3)
        .map(|i| (0..length).map(|j| (i * 71 + j) as u8).collect())
        .collect();
    let shards = codec.encode(&data).unwrap();
    let healthy = [1, 3, 4];
    let targets = [2, 0];
    let plan = ChainPlan::new(
        session(),
        codec.repair_plan(&healthy, &targets).unwrap(),
        length as u64,
        4096,
    )
    .unwrap();
    let listeners: Vec<_> = (0..3)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<_> = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect();
    let state = Arc::new(Mutex::new(State {
        bytes: vec![Vec::new(); 2],
        ..State::default()
    }));
    let mut sink = Sink {
        targets: targets.to_vec(),
        expected: targets.iter().map(|&id| shards[id].clone()).collect(),
        state: state.clone(),
        fail_write,
        fail_after_seal,
    };
    let control = control();
    std::thread::scope(|scope| {
        let sink_handle = scope.spawn(|| run_sink(&plan, &listeners[2], &mut sink, &control));
        let mut helpers = Vec::new();
        for position in 0..3 {
            let mut source = Source(shards[healthy[position]].clone());
            let plan = &plan;
            let listener = (position > 0).then(|| &listeners[position - 1]);
            let address = addresses[position];
            let control = &control;
            helpers.push(scope.spawn(move || {
                run_helper(plan, position, &mut source, listener, address, control)
            }));
        }
        let result = sink_handle.join().unwrap();
        if fail_write || fail_after_seal {
            assert!(result.is_err());
            for helper in helpers {
                assert!(helper.join().unwrap().is_err());
            }
        } else {
            let stats = result.unwrap();
            assert!(stats.sealed);
            assert_eq!(stats.written_bytes, (length * 2) as u64);
            let mut total_sent = stats.sent_wire_bytes;
            let mut total_received = stats.received_wire_bytes;
            for helper in helpers {
                let stats = helper.join().unwrap().unwrap();
                assert!(stats.sealed);
                assert_eq!(stats.source_bytes, length as u64);
                total_sent += stats.sent_wire_bytes;
                total_received += stats.received_wire_bytes;
            }
            assert_eq!(total_sent, total_received);
        }
    });
    let state = state.lock().unwrap();
    assert_eq!(state.sealed, !fail_write);
    assert_eq!(state.aborted, fail_write);
}

#[test]
fn helper_chain_recovers_both_targets_and_waits_for_terminal_seal() {
    for length in [0, 1, 4095, 4096, 4097, 16391] {
        run(length, false, false);
    }
}

#[test]
fn pre_seal_failures_abort_but_uncertain_seal_results_preserve_output() {
    run(4097, true, false);
    run(4097, false, true);
}

fn frame(kind: FrameKind, sequence: u64, offset: u64, length: u32) -> Frame {
    Frame {
        kind,
        session: session(),
        sequence,
        offset,
        valid_len: length,
        hop: 2,
        targets: vec![0],
        payload: vec![7; length as usize],
    }
}

#[test]
fn valid_crc_does_not_allow_stale_replayed_or_malformed_control_frames() {
    for case in 0..8 {
        let codec = Codec::new(2, 1).unwrap();
        let plan =
            ChainPlan::new(session(), codec.repair_plan(&[1, 2], &[0]).unwrap(), 2, 1).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            bytes: vec![vec![]],
            ..State::default()
        }));
        let mut sink = Sink {
            targets: vec![0],
            expected: vec![vec![7; 2]],
            state: state.clone(),
            fail_write: false,
            fail_after_seal: false,
        };
        let control = control();
        std::thread::scope(|scope| {
            let job = scope.spawn(|| run_sink(&plan, &listener, &mut sink, &control));
            let mut socket = transport::connect(address, &control).unwrap();
            let mut bad = frame(FrameKind::Slice, 0, 0, 1);
            match case {
                0 => bad.session.epoch += 1,
                1 => bad.session.plan[0] ^= 1,
                2 => bad.hop -= 1,
                3 => bad.targets[0] = 1,
                4 => bad.offset = 1,
                5 => bad.sequence = 1,
                6 => {
                    transport::send(&mut socket, &bad, plan.max_payload(), &control).unwrap();
                }
                _ => {
                    transport::send(&mut socket, &bad, plan.max_payload(), &control).unwrap();
                    transport::send(
                        &mut socket,
                        &frame(FrameKind::Slice, 1, 1, 1),
                        plan.max_payload(),
                        &control,
                    )
                    .unwrap();
                    bad = frame(FrameKind::Finish, 2, 2, 1);
                }
            }
            transport::send(&mut socket, &bad, plan.max_payload(), &control).unwrap();
            drop(socket);
            assert!(job.join().unwrap().is_err());
        });
        let state = state.lock().unwrap();
        assert!(state.aborted);
        assert!(!state.sealed);
    }
}

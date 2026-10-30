use hf3fs_ec::chain::{run_helper, run_sink, ChainPlan, RepairSink, SliceSource};
use hf3fs_ec::read::CancellationToken;
use hf3fs_ec::transport::TransportControl;
use hf3fs_ec::wire::{SessionId, HEADER_LEN};
use hf3fs_ec::{Codec, Error, Result};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn session() -> SessionId {
    SessionId {
        job: 37,
        plan: [91; 32],
        stripe: 12,
        generation: 5,
        epoch: 8,
    }
}

fn control() -> TransportControl {
    TransportControl {
        cancellation: CancellationToken::default(),
        deadline: Instant::now() + Duration::from_secs(3),
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
            .ok_or_else(|| Error("test source range mismatch".into()))
    }
}

#[derive(Default)]
struct State {
    bytes: Vec<Vec<u8>>,
    sealed: bool,
    abort_calls: usize,
}

struct Sink {
    expected: Vec<Vec<u8>>,
    targets: Vec<usize>,
    state: Arc<Mutex<State>>,
    cancel_after_seal: bool,
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
        let row = self.targets.iter().position(|&id| id == target).unwrap();
        let mut state = self.state.lock().unwrap();
        if state.bytes[row].len() as u64 != offset {
            return Err(Error("test sink range mismatch".into()));
        }
        state.bytes[row].extend_from_slice(bytes);
        Ok(())
    }

    fn seal(&mut self, control: &TransportControl) -> Result<()> {
        control.check()?;
        let mut state = self.state.lock().unwrap();
        if state.bytes != self.expected {
            return Err(Error("test target mismatch".into()));
        }
        state.sealed = true;
        if self.cancel_after_seal {
            control.cancellation.cancel();
        }
        // The storage operation completed successfully; only sending its ACK
        // will fail. This differs from a storage callback returning Err.
        Ok(())
    }

    fn abort(&mut self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.abort_calls += 1;
        if state.sealed {
            return Err(Error("attempted to abort sealed test output".into()));
        }
        state.bytes.iter_mut().for_each(Vec::clear);
        Ok(())
    }
}

#[test]
fn empty_and_tail_shards_have_exact_per_hop_application_wire_counts() {
    for length in [0usize, 13] {
        let codec = Codec::new(2, 2).unwrap();
        let data: Vec<Vec<u8>> = (0..2)
            .map(|row| (0..length).map(|i| (row * 101 + i * 7) as u8).collect())
            .collect();
        let shards = codec.encode(&data).unwrap();
        let helpers = [3, 2];
        let targets = [1, 0];
        let plan = ChainPlan::new(
            session(),
            codec.repair_plan(&helpers, &targets).unwrap(),
            length as u64,
            5,
        )
        .unwrap();
        let listeners: Vec<_> = (0..2)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let addresses: Vec<_> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
        let state = Arc::new(Mutex::new(State {
            bytes: vec![Vec::new(); 2],
            ..State::default()
        }));
        let mut sink = Sink {
            expected: targets
                .iter()
                .map(|&target| shards[target].clone())
                .collect(),
            targets: targets.to_vec(),
            state: state.clone(),
            cancel_after_seal: false,
        };
        let control = control();
        let (sink_stats, helper_stats) = std::thread::scope(|scope| {
            let sink_job = scope.spawn(|| run_sink(&plan, &listeners[1], &mut sink, &control));
            let jobs: Vec<_> = (0..2)
                .map(|position| {
                    let mut source = Source(shards[helpers[position]].clone());
                    let upstream = (position != 0).then(|| &listeners[0]);
                    let address = addresses[position];
                    let plan = &plan;
                    let control = &control;
                    scope.spawn(move || {
                        run_helper(plan, position, &mut source, upstream, address, control)
                    })
                })
                .collect();
            let sink_stats = sink_job.join().unwrap().unwrap();
            let helper_stats: Vec<_> = jobs
                .into_iter()
                .map(|job| job.join().unwrap().unwrap())
                .collect();
            (sink_stats, helper_stats)
        });
        let slices = (length as u64).div_ceil(5);
        let control_bytes = HEADER_LEN as u64 + 2 * targets.len() as u64;
        let slice_bytes = slices * control_bytes + length as u64 * targets.len() as u64;
        let forward_bytes = slice_bytes + control_bytes; // Slice frames + Finish.
        assert_eq!(sink_stats.received_wire_bytes, forward_bytes);
        assert_eq!(sink_stats.sent_wire_bytes, control_bytes); // One terminal ACK.
        assert_eq!(sink_stats.source_bytes, 0);
        assert_eq!(sink_stats.written_bytes, length as u64 * 2);
        assert_eq!(sink_stats.slices, slices);
        assert!(sink_stats.sealed);
        for (position, stats) in helper_stats.iter().enumerate() {
            assert_eq!(stats.slices, slices);
            assert_eq!(stats.source_bytes, length as u64);
            assert_eq!(stats.written_bytes, 0);
            assert!(stats.sealed);
            assert_eq!(
                stats.sent_wire_bytes,
                forward_bytes + if position == 0 { 0 } else { control_bytes }
            );
            assert_eq!(
                stats.received_wire_bytes,
                control_bytes + if position == 0 { 0 } else { forward_bytes }
            );
        }
        let state = state.lock().unwrap();
        assert!(state.sealed);
        assert_eq!(state.abort_calls, 0);
    }
}

#[test]
fn successful_seal_followed_by_ack_cancellation_preserves_output_and_reports_reconciliation() {
    let codec = Codec::new(1, 1).unwrap();
    let plan = ChainPlan::new(session(), codec.repair_plan(&[1], &[0]).unwrap(), 3, 3).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let expected = vec![vec![6, 7, 8]];
    let state = Arc::new(Mutex::new(State {
        bytes: vec![Vec::new()],
        ..State::default()
    }));
    let mut sink = Sink {
        expected: expected.clone(),
        targets: vec![0],
        state: state.clone(),
        cancel_after_seal: true,
    };
    let sink_control = control();
    // Separate tokens keep the deliberate sink cancellation local. The helper
    // must observe the missing ACK through its own transport and report the
    // possible terminal seal, without relying on a shared cancellation token.
    let helper_control = control();
    std::thread::scope(|scope| {
        let sink_job = scope.spawn(|| run_sink(&plan, &listener, &mut sink, &sink_control));
        // For k=1,m=1 the systematic Cauchy parity is the unchanged data.
        let mut source = Source(expected[0].clone());
        let failure =
            run_helper(&plan, 0, &mut source, None, address, &helper_control).unwrap_err();
        assert!(
            failure.0.starts_with("TCP "),
            "original transport error was lost: {failure}"
        );
        assert!(failure.0.contains("Finish attempted"));
        assert!(failure.0.contains("terminal seal may have completed"));
        assert!(failure.0.contains("reconcile"));
        let failure = sink_job.join().unwrap().unwrap_err();
        assert!(failure.0.contains("cancelled"));
        assert!(failure.0.contains("seal started"));
        assert!(failure.0.contains("retain output"));
        assert!(failure.0.contains("reconcile"));
    });
    let state = state.lock().unwrap();
    assert!(state.sealed);
    assert_eq!(state.abort_calls, 0);
    assert_eq!(state.bytes, expected);
}

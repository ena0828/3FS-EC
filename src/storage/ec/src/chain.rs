//! Fixed, preinstalled helper chains over bounded framed transport.
//!
//! Every helper computes only its own contribution; distinct slices can be at
//! different hops concurrently. A terminal acknowledgement means the sink's
//! seal contract completed, NOT that a 3FS metadata transaction was published.
//! The caller must authenticate/configure endpoints and install matching plans.
//! Session.plan is an externally supplied binding, not a digest computed here.
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use crate::transport::{self, TransportControl};
use crate::wire::{Frame, FrameKind, SessionId, HEADER_LEN};
use crate::{error, RepairPlan, Result};

/// A trusted local plan. Addresses are supplied out of band, never by frames.
pub struct ChainPlan {
    session: SessionId,
    repair: RepairPlan,
    shard_len: u64,
    slice_len: usize,
    targets: Vec<u16>,
    max_payload: usize,
}

impl ChainPlan {
    pub fn new(
        session: SessionId,
        repair: RepairPlan,
        shard_len: u64,
        slice_len: usize,
    ) -> Result<Self> {
        if slice_len == 0 || slice_len > 1024 * 1024 {
            return Err(error("chain slice length must be in 1..=1048576"));
        }
        let targets: Vec<_> = repair.targets().iter().map(|&id| id as u16).collect();
        let max_payload = targets
            .len()
            .checked_mul(slice_len + 2)
            .filter(|&length| length <= 8 * 1024 * 1024)
            .ok_or_else(|| error("chain frame budget exceeds 8 MiB"))?;
        shard_len
            .checked_mul(targets.len() as u64)
            .ok_or_else(|| error("chain output byte count overflow"))?;
        // Payload per edge plus the Slice/Finish/Ack header overhead.
        let slices = shard_len / slice_len as u64 + u64::from(shard_len % slice_len as u64 != 0);
        slices
            .checked_add(2)
            .and_then(|count| count.checked_mul((HEADER_LEN + targets.len() * 2) as u64))
            .and_then(|overhead| {
                shard_len
                    .checked_mul(targets.len() as u64)?
                    .checked_add(overhead)
            })
            .ok_or_else(|| error("chain wire byte accounting overflow"))?;
        Ok(Self {
            session,
            repair,
            shard_len,
            slice_len,
            targets,
            max_payload,
        })
    }

    pub fn shard_len(&self) -> u64 {
        self.shard_len
    }
    pub fn slice_len(&self) -> usize {
        self.slice_len
    }
    pub fn helper_count(&self) -> usize {
        self.repair.healthy().len()
    }
    pub fn targets(&self) -> &[usize] {
        self.repair.targets()
    }
    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    fn frame(&self, kind: FrameKind, sequence: u64, offset: u64, hop: usize) -> Frame {
        Frame {
            kind,
            session: self.session,
            sequence,
            offset,
            valid_len: 0,
            hop: hop as u16,
            targets: self.targets.clone(),
            payload: Vec::new(),
        }
    }

    fn check(
        &self,
        frame: &Frame,
        kind: FrameKind,
        sequence: u64,
        offset: u64,
        hop: usize,
        length: usize,
    ) -> Result<()> {
        if frame.kind != kind
            || frame.session != self.session
            || frame.sequence != sequence
            || frame.offset != offset
            || usize::from(frame.hop) != hop
            || frame.targets != self.targets
            || frame.valid_len as usize != length
            || frame.payload.len() != length * self.targets.len()
        {
            return Err(error(
                "chain frame violates installed plan, slice order or control state",
            ));
        }
        Ok(())
    }
}

pub trait SliceSource {
    /// Validate source identity, generation and integrity against pinned metadata.
    /// A checksum generated only after reading is not independent validation.
    fn read_slice(
        &mut self,
        shard: usize,
        offset: u64,
        length: usize,
        control: &TransportControl,
    ) -> Result<Vec<u8>>;
}

pub trait RepairSink {
    fn write_slice(
        &mut self,
        target: usize,
        offset: u64,
        bytes: &[u8],
        control: &TransportControl,
    ) -> Result<()>;
    /// Verify all targets and seal them according to the selected storage policy.
    /// An error/panic is ambiguous: caller preserves data for reconciliation.
    fn seal(&mut self, control: &TransportControl) -> Result<()>;
    /// Called only before seal starts; must not erase previously published data.
    fn abort(&mut self) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct ChainStats {
    pub slices: u64,
    pub source_bytes: u64,
    pub written_bytes: u64,
    pub received_wire_bytes: u64,
    pub sent_wire_bytes: u64,
    pub sealed: bool,
    pub elapsed: Duration,
}

fn invoke<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    catch_unwind(AssertUnwindSafe(operation))
        .map_err(|_| error("chain storage callback panicked"))?
}

fn wire_size(frame: &Frame) -> u64 {
    (HEADER_LEN + frame.targets.len() * 2 + frame.payload.len()) as u64
}

fn receive(
    stream: &mut TcpStream,
    plan: &ChainPlan,
    control: &TransportControl,
    stats: &mut ChainStats,
) -> Result<Frame> {
    let frame = transport::receive(stream, plan.max_payload, control)?;
    // Malicious/unexpected frames are not counted as completed application work.
    stats.received_wire_bytes = stats
        .received_wire_bytes
        .checked_add(wire_size(&frame))
        .ok_or_else(|| error("received wire byte counter overflow"))?;
    Ok(frame)
}

fn send(
    stream: &mut TcpStream,
    frame: &Frame,
    plan: &ChainPlan,
    control: &TransportControl,
    stats: &mut ChainStats,
) -> Result<()> {
    transport::send(stream, frame, plan.max_payload, control)?;
    stats.sent_wire_bytes = stats
        .sent_wire_bytes
        .checked_add(wire_size(frame))
        .ok_or_else(|| error("sent wire byte counter overflow"))?;
    Ok(())
}

/// Execute one hop. Bind/listen before calling; start the sink and tail first.
/// No per-slice round trip is required. TCP and one-frame-at-a-time processing
/// bound the user-space buffers; socket buffers are an additional OS budget.
pub fn run_helper(
    plan: &ChainPlan,
    position: usize,
    source: &mut dyn SliceSource,
    upstream: Option<&TcpListener>,
    downstream: SocketAddr,
    control: &TransportControl,
) -> Result<ChainStats> {
    if position >= plan.helper_count() || upstream.is_some() != (position != 0) {
        return Err(error("helper position and upstream listener disagree"));
    }
    control.check()?;
    let started = Instant::now();
    let helper = plan.repair.healthy()[position];
    let contribution = plan.repair.contribution(helper)?;
    let mut stats = ChainStats::default();
    let mut output = transport::connect(downstream, control)?;
    let mut input = upstream
        .map(|listener| transport::accept(listener, control))
        .transpose()?;
    let (mut sequence, mut offset) = (0u64, 0u64);
    while offset < plan.shard_len {
        control.check()?;
        let length = (plan.shard_len - offset).min(plan.slice_len as u64) as usize;
        let mut frame = if let Some(input) = &mut input {
            let frame = receive(input, plan, control, &mut stats)?;
            plan.check(&frame, FrameKind::Slice, sequence, offset, position, length)?;
            frame
        } else {
            let mut frame = plan.frame(FrameKind::Slice, sequence, offset, 0);
            frame.valid_len = length as u32;
            frame.payload = vec![0; length * plan.targets.len()];
            frame
        };
        let bytes = invoke(|| source.read_slice(helper, offset, length, control))?;
        if bytes.len() != length {
            return Err(error("source returned a short or oversized slice"));
        }
        control.check()?;
        let terms = contribution.apply(&bytes)?;
        for (target, term) in frame.payload.chunks_exact_mut(length).zip(terms) {
            for (destination, byte) in target.iter_mut().zip(term) {
                *destination ^= byte;
            }
        }
        control.check()?;
        frame.hop = (position + 1) as u16;
        send(&mut output, &frame, plan, control, &mut stats)?;
        offset += length as u64;
        sequence += 1;
        stats.source_bytes += length as u64;
        stats.slices += 1;
    }
    if let Some(input) = &mut input {
        let finish = receive(input, plan, control, &mut stats)?;
        plan.check(&finish, FrameKind::Finish, sequence, offset, position, 0)?;
    }
    let finish = plan.frame(FrameKind::Finish, sequence, offset, position + 1);
    // Once Finish is attempted, even a failed send can have delivered it.
    // The terminal may seal before this helper sees an ACK, and forwarding a
    // valid ACK can fail after the terminal has definitely completed its seal.
    // Preserve the original error and expose that ambiguity to the caller.
    let terminal = (|| {
        send(&mut output, &finish, plan, control, &mut stats)?;
        let ack = receive(&mut output, plan, control, &mut stats)?;
        plan.check(
            &ack,
            FrameKind::Ack,
            sequence,
            offset,
            plan.helper_count(),
            0,
        )?;
        if let Some(input) = &mut input {
            send(input, &ack, plan, control, &mut stats)?;
        }
        stats.sealed = true;
        stats.elapsed = started.elapsed();
        Ok(stats)
    })();
    terminal.map_err(|primary: crate::Error| {
        error(format!(
            "{primary}; Finish attempted; terminal seal may have completed; retain output and reconcile outcome"
        ))
    })
}

/// Receive complete repaired targets. The sink is aborted on pre-seal failures.
/// Seal errors and lost final ACKs preserve output, since publication is unknown.
pub fn run_sink(
    plan: &ChainPlan,
    listener: &TcpListener,
    sink: &mut dyn RepairSink,
    control: &TransportControl,
) -> Result<ChainStats> {
    let started = Instant::now();
    let mut stats = ChainStats::default();
    let mut seal_started = false;
    let result = (|| {
        control.check()?;
        let mut input = transport::accept(listener, control)?;
        let (mut sequence, mut offset) = (0u64, 0u64);
        while offset < plan.shard_len {
            let length = (plan.shard_len - offset).min(plan.slice_len as u64) as usize;
            let frame = receive(&mut input, plan, control, &mut stats)?;
            plan.check(
                &frame,
                FrameKind::Slice,
                sequence,
                offset,
                plan.helper_count(),
                length,
            )?;
            for (&target, bytes) in plan
                .repair
                .targets()
                .iter()
                .zip(frame.payload.chunks_exact(length))
            {
                control.check()?;
                invoke(|| sink.write_slice(target, offset, bytes, control))?;
                stats.written_bytes += bytes.len() as u64;
            }
            sequence += 1;
            offset += length as u64;
            stats.slices += 1;
        }
        let finish = receive(&mut input, plan, control, &mut stats)?;
        plan.check(
            &finish,
            FrameKind::Finish,
            sequence,
            offset,
            plan.helper_count(),
            0,
        )?;
        control.check()?;
        seal_started = true;
        invoke(|| sink.seal(control))?;
        stats.sealed = true;
        let ack = plan.frame(FrameKind::Ack, sequence, offset, plan.helper_count());
        send(&mut input, &ack, plan, control, &mut stats)?;
        stats.elapsed = started.elapsed();
        Ok(stats)
    })();
    match result {
        Ok(stats) => Ok(stats),
        Err(primary) if !seal_started => match invoke(|| sink.abort()) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(error(format!("{primary}; abort failed: {cleanup}"))),
        },
        Err(primary) => Err(error(format!(
            "{primary}; seal started, retain output and reconcile outcome"
        ))),
    }
}

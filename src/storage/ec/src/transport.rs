//! Deadline-bounded, nonblocking TCP frame I/O without background workers.
//!
//! One caller must own each direction of a stream. These functions change its
//! nonblocking flag, which may also affect cloned handles. A send/receive error
//! can leave a partial frame on the connection: discard that connection rather
//! than retrying the whole frame on the same byte stream. An error never proves
//! that the peer received or applied nothing. Authentication, session binding,
//! replay handling and acknowledgments remain the executor's responsibility.
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::read::CancellationToken;
use crate::wire::{encoded_len, Frame, HEADER_LEN};
use crate::{error, Result};

const MAX_IO: usize = 64 * 1024;
const RETRY_WAIT: Duration = Duration::from_millis(2);
const CONNECT_ATTEMPT: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct TransportControl {
    pub cancellation: CancellationToken,
    pub deadline: Instant,
}

impl TransportControl {
    pub fn check(&self) -> Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(error("TCP operation cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(error("TCP operation deadline exceeded"));
        }
        Ok(())
    }

    fn remaining(&self) -> Result<Duration> {
        self.check()?;
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| error("TCP operation deadline exceeded"))
    }
}

fn wait_without_progress(control: &TransportControl) -> Result<()> {
    std::thread::sleep(RETRY_WAIT.min(control.remaining()?));
    control.check()
}

fn configure(stream: &TcpStream) -> Result<()> {
    stream
        .set_nonblocking(true)
        .map_err(|failure| error(format!("TCP set_nonblocking: {failure}")))?;
    stream
        .set_nodelay(true)
        .map_err(|failure| error(format!("TCP set_nodelay: {failure}")))
}

/// Retries failed connections until the fixed deadline or cancellation.
/// Each connect_timeout call uses at most 50 ms of the remaining budget.
pub fn connect(address: SocketAddr, control: &TransportControl) -> Result<TcpStream> {
    loop {
        let attempt = CONNECT_ATTEMPT.min(control.remaining()?);
        match TcpStream::connect_timeout(&address, attempt) {
            Ok(stream) => {
                configure(&stream)?;
                control.check()?;
                return Ok(stream);
            }
            Err(_) => wait_without_progress(control)?,
        }
    }
}

/// Makes the listener nonblocking and waits cooperatively for one connection.
pub fn accept(listener: &TcpListener, control: &TransportControl) -> Result<TcpStream> {
    control.check()?;
    listener
        .set_nonblocking(true)
        .map_err(|failure| error(format!("TCP listener set_nonblocking: {failure}")))?;
    loop {
        control.check()?;
        match listener.accept() {
            Ok((stream, _)) => {
                configure(&stream)?;
                control.check()?;
                return Ok(stream);
            }
            Err(failure)
                if matches!(
                    failure.kind(),
                    ErrorKind::Interrupted | ErrorKind::WouldBlock
                ) =>
            {
                wait_without_progress(control)?;
            }
            Err(failure) => return Err(error(format!("TCP accept: {failure}"))),
        }
    }
}

fn write_complete(stream: &mut TcpStream, bytes: &[u8], control: &TransportControl) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        control.check()?;
        let count = MAX_IO.min(bytes.len() - offset);
        match stream.write(&bytes[offset..offset + count]) {
            Ok(0) => return Err(error("TCP write returned zero before complete frame")),
            Ok(written) => offset += written,
            Err(failure)
                if matches!(
                    failure.kind(),
                    ErrorKind::Interrupted | ErrorKind::WouldBlock
                ) =>
            {
                wait_without_progress(control)?;
            }
            Err(failure) => return Err(error(format!("TCP write: {failure}"))),
        }
    }
    control.check()
}

fn read_complete(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    control: &TransportControl,
) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        control.check()?;
        let count = MAX_IO.min(bytes.len() - offset);
        match stream.read(&mut bytes[offset..offset + count]) {
            Ok(0) => return Err(error("TCP EOF before complete frame")),
            Ok(read) => offset += read,
            Err(failure)
                if matches!(
                    failure.kind(),
                    ErrorKind::Interrupted | ErrorKind::WouldBlock
                ) =>
            {
                wait_without_progress(control)?;
            }
            Err(failure) => return Err(error(format!("TCP read: {failure}"))),
        }
    }
    control.check()
}

/// Encodes a bounded frame before writing any bytes. Checks the same absolute
/// deadline between I/O attempts and before/after codec work; progress never
/// extends that deadline. Individual nonblocking writes are at most 64 KiB.
pub fn send(
    stream: &mut TcpStream,
    frame: &Frame,
    max_payload: usize,
    control: &TransportControl,
) -> Result<()> {
    control.check()?;
    let bytes = frame.encode(max_payload)?;
    control.check()?;
    configure(stream)?;
    write_complete(stream, &bytes, control)
}

/// Receives one frame, leaving later frames unread. The fixed header is read on
/// the stack and validated before reserving the variable region. Decoding owns
/// a separate payload buffer, so peak memory includes both encoded and decoded
/// bodies. A configured byte limit must account for that bounded overlap.
pub fn receive(
    stream: &mut TcpStream,
    max_payload: usize,
    control: &TransportControl,
) -> Result<Frame> {
    control.check()?;
    configure(stream)?;
    let mut header = [0; HEADER_LEN];
    read_complete(stream, &mut header, control)?;
    let length = encoded_len(&header, max_payload)?;
    control.check()?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| error("cannot allocate bounded TCP frame buffer"))?;
    bytes.extend_from_slice(&header);
    bytes.resize(length, 0);
    read_complete(stream, &mut bytes[HEADER_LEN..], control)?;
    let frame = Frame::decode(&bytes, max_payload)?;
    control.check()?;
    Ok(frame)
}

//! Isolated TCP helper-chain experiment on ordinary files, not native 3FS.
//! Trusted preinstalled plans and CRCs are not peer authentication or Meta CAS.
//! Run with --help for the per-process CLI and preinstalled-file formats.
use hf3fs_ec::{
    chain::{self, ChainPlan, RepairSink, SliceSource},
    read::{crc32c, CancellationToken},
    transport::TransportControl,
    wire::SessionId,
    Codec, Error, Result,
};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

fn err(s: impl Into<String>) -> Error {
    Error(s.into())
}
fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|e| err(e.to_string()))
}
fn context<T>(r: std::io::Result<T>, action: &str) -> Result<T> {
    r.map_err(|e| err(format!("{action}: {e}")))
}
fn known_keys(map: &BTreeMap<String, String>, allowed: &[&str], kind: &str) -> Result<()> {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(err(format!("unknown {kind} key: {key}")));
        }
    }
    Ok(())
}
fn check(c: &TransportControl) -> Result<()> {
    if c.cancellation.is_cancelled() {
        return Err(err("cancelled"));
    }
    if Instant::now() >= c.deadline {
        return Err(err("deadline exceeded"));
    }
    Ok(())
}
fn json(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn emit(s: &str) -> Result<()> {
    println!("{s}");
    io(std::io::stdout().flush())
}
fn required<'a>(map: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    map.get(key)
        .map(String::as_str)
        .ok_or_else(|| err(format!("missing {key}")))
}
fn number<T: std::str::FromStr>(s: &str) -> Result<T> {
    s.parse().map_err(|_| err(format!("invalid number: {s}")))
}
fn list(s: &str) -> Result<Vec<usize>> {
    s.split(',').map(number).collect()
}
fn text_file(path: &Path, cap: u64) -> Result<String> {
    let file = io(File::open(path))?;
    if io(file.metadata())?.len() > cap {
        return Err(err("configuration exceeds limit"));
    }
    let mut out = String::new();
    io(file.take(cap + 1).read_to_string(&mut out))?;
    if out.len() as u64 > cap {
        return Err(err("configuration exceeds limit"));
    }
    Ok(out)
}
fn pairs(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for line in text_file(path, 65536)?
        .lines()
        .filter(|s| !s.trim().is_empty())
    {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| err("expected key=value"))?;
        if out.insert(key.trim().into(), value.trim().into()).is_some() {
            return Err(err("duplicate configuration key"));
        }
    }
    Ok(out)
}
fn parse_crc(s: &str) -> Result<u32> {
    if s.len() != 8 {
        return Err(err("CRC32C requires 8 hex digits"));
    }
    u32::from_str_radix(s, 16).map_err(|_| err("invalid CRC32C"))
}
fn digest(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return Err(err("plan digest requires 64 hex digits"));
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b =
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| err("invalid plan digest"))?;
    }
    Ok(out)
}
fn delay(ms: u64, control: &TransportControl) -> Result<()> {
    let until = Instant::now()
        .checked_add(Duration::from_millis(ms))
        .ok_or_else(|| err("delay overflow"))?;
    while Instant::now() < until {
        check(control)?;
        thread::sleep(
            Duration::from_millis(5).min(until.saturating_duration_since(Instant::now())),
        );
    }
    check(control)
}

struct FileSource {
    file: File,
    shard: usize,
    length: u64,
    slice: usize,
    crcs: Vec<u32>,
    next: u64,
    reads: u64,
}
impl SliceSource for FileSource {
    fn read_slice(
        &mut self,
        shard: usize,
        offset: u64,
        length: usize,
        c: &TransportControl,
    ) -> Result<Vec<u8>> {
        check(c)?;
        let expected = (self.length.saturating_sub(self.next)).min(self.slice as u64) as usize;
        if shard != self.shard || offset != self.next || length != expected || length == 0 {
            return Err(err("source identity, range or sequence mismatch"));
        }
        let mut bytes = vec![0; length];
        io(self.file.read_exact(&mut bytes))?;
        let index = (offset / self.slice as u64) as usize;
        if self.crcs.get(index).copied() != Some(crc32c(&bytes)) {
            return Err(err("source slice CRC32C mismatch"));
        }
        self.next += length as u64;
        self.reads += 1;
        emit(&format!(
            "{{\"event\":\"source\",\"pid\":{},\"shard\":{},\"slices\":{},\"bytes\":{}}}",
            std::process::id(),
            shard,
            self.reads,
            self.next
        ))?;
        check(c)?;
        Ok(bytes)
    }
}
struct Output {
    target: usize,
    file: File,
    written: u64,
    expected: u32,
}
struct FileSink {
    stage: PathBuf,
    output: PathBuf,
    entries: Vec<Output>,
    length: u64,
    delay_ms: u64,
    sealing: bool,
}
impl FileSink {
    fn new(
        output: PathBuf,
        targets: &[usize],
        length: u64,
        expected: &BTreeMap<String, String>,
        delay_ms: u64,
    ) -> Result<Self> {
        if fs::symlink_metadata(&output).is_ok() {
            return Err(err("output must not exist"));
        }
        if expected.len() != targets.len() {
            return Err(err("expected checksum count differs from targets"));
        }
        let name = output
            .file_name()
            .ok_or_else(|| err("output requires a directory name"))?
            .to_string_lossy();
        let stage = output.with_file_name(format!(".{name}.stage-{}", std::process::id()));
        io(fs::create_dir(&stage))?;
        let mut sink = Self {
            stage,
            output,
            entries: Vec::new(),
            length,
            delay_ms,
            sealing: false,
        };
        let setup = (|| {
            for &target in targets {
                let crc = parse_crc(required(expected, &target.to_string())?)?;
                let file = io(OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(sink.stage.join(format!("shard-{target}"))))?;
                sink.entries.push(Output {
                    target,
                    file,
                    written: 0,
                    expected: crc,
                });
            }
            Ok(())
        })();
        if let Err(e) = setup {
            let _ = sink.abort();
            return Err(e);
        }
        Ok(sink)
    }
}
fn update_crc(mut crc: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}
impl RepairSink for FileSink {
    fn write_slice(
        &mut self,
        target: usize,
        offset: u64,
        bytes: &[u8],
        c: &TransportControl,
    ) -> Result<()> {
        check(c)?;
        delay(self.delay_ms, c)?;
        let e = self
            .entries
            .iter_mut()
            .find(|x| x.target == target)
            .ok_or_else(|| err("unknown target"))?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| err("output range overflow"))?;
        if self.sealing || offset != e.written || end > self.length {
            return Err(err("output range or publication state mismatch"));
        }
        io(e.file.write_all(bytes))?;
        e.written = end;
        emit(&format!(
            "{{\"event\":\"write\",\"pid\":{},\"target\":{},\"bytes\":{end}}}",
            std::process::id(),
            target
        ))?;
        check(c)
    }
    fn seal(&mut self, c: &TransportControl) -> Result<()> {
        self.sealing = true;
        for e in &mut self.entries {
            check(c)?;
            if e.written != self.length || io(e.file.metadata())?.len() != self.length {
                return Err(err("incomplete target"));
            }
            io(e.file.seek(SeekFrom::Start(0)))?;
            let mut crc = !0u32;
            let mut buffer = [0u8; 65536];
            loop {
                check(c)?;
                let count = io(e.file.read(&mut buffer))?;
                if count == 0 {
                    break;
                }
                crc = update_crc(crc, &buffer[..count]);
            }
            if !crc != e.expected {
                return Err(err("target full CRC32C mismatch"));
            }
            context(e.file.sync_all(), "fsync target file")?;
        }
        check(c)?;
        context(
            File::open(&self.stage).and_then(|f| f.sync_all()),
            "fsync stage directory",
        )?;
        // Exclusive experiment directory; this is not a multi-writer CAS.
        if fs::symlink_metadata(&self.output).is_ok() {
            return Err(err("output appeared before publication"));
        }
        context(
            fs::rename(&self.stage, &self.output),
            "rename sealed stage directory",
        )?;
        let parent = self
            .output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        context(
            File::open(parent).and_then(|f| f.sync_all()),
            "fsync output parent directory",
        )?;
        emit(&format!(
            "{{\"event\":\"sealed\",\"pid\":{}}}",
            std::process::id()
        ))?;
        check(c)
    }
    fn abort(&mut self) -> Result<()> {
        if self.sealing {
            return Err(err(
                "seal attempted; preserve data for outcome reconciliation",
            ));
        }
        for e in &self.entries {
            io(fs::remove_file(
                self.stage.join(format!("shard-{}", e.target)),
            ))?;
        }
        io(fs::remove_dir(&self.stage))
    }
}

fn run() -> Result<()> {
    let mut args = BTreeMap::new();
    let mut input = env::args().skip(1);
    while let Some(key) = input.next() {
        if !key.starts_with("--") {
            return Err(err("arguments must be --key value pairs"));
        }
        let value = input.next().ok_or_else(|| err("argument has no value"))?;
        if args.insert(key[2..].into(), value).is_some() {
            return Err(err("duplicate argument"));
        }
    }
    known_keys(
        &args,
        &[
            "role",
            "plan",
            "timeout-ms",
            "listen",
            "position",
            "source",
            "crc",
            "next",
            "output",
            "expected",
            "delay-ms",
        ],
        "CLI",
    )?;
    let role = required(&args, "role")?;
    match role {
        "helper" => known_keys(
            &args,
            &[
                "role",
                "plan",
                "timeout-ms",
                "listen",
                "position",
                "source",
                "crc",
                "next",
            ],
            "helper CLI",
        )?,
        "sink" => known_keys(
            &args,
            &[
                "role",
                "plan",
                "timeout-ms",
                "listen",
                "output",
                "expected",
                "delay-ms",
            ],
            "sink CLI",
        )?,
        _ => return Err(err("role must be helper or sink")),
    }
    let conf = pairs(Path::new(required(&args, "plan")?))?;
    known_keys(
        &conf,
        &[
            "k",
            "m",
            "shard_len",
            "slice_len",
            "healthy",
            "targets",
            "job",
            "plan",
            "stripe",
            "generation",
            "epoch",
        ],
        "plan",
    )?;
    let healthy = list(required(&conf, "healthy")?)?;
    let targets = list(required(&conf, "targets")?)?;
    let length: u64 = number(required(&conf, "shard_len")?)?;
    let slice: usize = number(required(&conf, "slice_len")?)?;
    if slice == 0 || slice > 1024 * 1024 {
        return Err(err("slice length must be 1..=1048576 bytes (1 MiB)"));
    }
    let count = length / slice as u64 + u64::from(length % slice as u64 != 0);
    if count > 1_000_000 {
        return Err(err("example supports at most one million slices"));
    }
    let repair = Codec::new(
        number(required(&conf, "k")?)?,
        number(required(&conf, "m")?)?,
    )?
    .repair_plan(&healthy, &targets)?;
    let session = SessionId {
        job: number(required(&conf, "job")?)?,
        plan: digest(required(&conf, "plan")?)?,
        stripe: number(required(&conf, "stripe")?)?,
        generation: number(required(&conf, "generation")?)?,
        epoch: number(required(&conf, "epoch")?)?,
    };
    let plan = ChainPlan::new(session, repair, length, slice)?;
    let timeout: u64 = number(required(&args, "timeout-ms")?)?;
    let control = TransportControl {
        cancellation: CancellationToken::default(),
        deadline: Instant::now()
            .checked_add(Duration::from_millis(timeout))
            .ok_or_else(|| err("deadline overflow"))?,
    };
    let role = required(&args, "role")?;
    let listener = if let Some(address) = args.get("listen") {
        let address: SocketAddr = number(address)?;
        if !address.ip().is_loopback() {
            return Err(err("example listens only on loopback"));
        }
        Some(io(TcpListener::bind(address))?)
    } else {
        None
    };
    let listen = match &listener {
        Some(l) => json(&io(l.local_addr())?.to_string()),
        None => "null".into(),
    };
    let ready = format!(
        "{{\"event\":\"ready\",\"role\":{},\"listen\":{listen},\"pid\":{}}}",
        json(role),
        std::process::id()
    );
    let stats = match role {
        "helper" => {
            let position: usize = number(required(&args, "position")?)?;
            let shard = *healthy
                .get(position)
                .ok_or_else(|| err("helper position out of range"))?;
            if (position == 0) != listener.is_none() {
                return Err(err("only the first helper must omit listen"));
            }
            let crcs = text_file(Path::new(required(&args, "crc")?), 9_000_001)?
                .lines()
                .map(parse_crc)
                .collect::<Result<Vec<_>>>()?;
            if crcs.len() as u64 != count {
                return Err(err("source checksum count differs from slice count"));
            }
            let mut source = FileSource {
                file: io(File::open(required(&args, "source")?))?,
                shard,
                length,
                slice,
                crcs,
                next: 0,
                reads: 0,
            };
            let next: SocketAddr = number(required(&args, "next")?)?;
            if !next.ip().is_loopback() {
                return Err(err("example connects only to loopback"));
            }
            emit(&ready)?;
            chain::run_helper(
                &plan,
                position,
                &mut source,
                listener.as_ref(),
                next,
                &control,
            )?
        }
        "sink" => {
            let expected = pairs(Path::new(required(&args, "expected")?))?;
            let pause = number(args.get("delay-ms").map(String::as_str).unwrap_or("0"))?;
            let mut sink = FileSink::new(
                PathBuf::from(required(&args, "output")?),
                &targets,
                length,
                &expected,
                pause,
            )?;
            emit(&ready)?;
            chain::run_sink(
                &plan,
                listener
                    .as_ref()
                    .ok_or_else(|| err("sink requires listen"))?,
                &mut sink,
                &control,
            )?
        }
        _ => return Err(err("role must be helper or sink")),
    };
    emit(&format!(
        "{{\"event\":\"result\",\"ok\":true,\"pid\":{},\"stats\":{}}}",
        std::process::id(),
        json(&format!("{stats:?}"))
    ))
}
fn main() {
    if env::args().skip(1).eq(["--help"]) {
        println!("{}", USAGE);
        return;
    }
    if let Err(e) = run() {
        let _ = emit(&format!(
            "{{\"event\":\"result\",\"ok\":false,\"pid\":{},\"error\":{}}}",
            std::process::id(),
            json(&e.to_string())
        ));
        eprintln!("{e}");
        std::process::exit(1);
    }
}

const USAGE: &str = r#"network_chain: trusted-plan TCP experiment on ordinary Linux files

Start sink first, then helpers in descending position order:
  network_chain --role sink --plan PLAN --listen 127.0.0.1:0 \
    --output NEW_DIRECTORY --expected EXPECTED --timeout-ms 30000
  network_chain --role helper --plan PLAN --position I \
    --source SOURCE --crc SLICE_CRCS --next 127.0.0.1:PORT \
    --listen 127.0.0.1:0 --timeout-ms 30000
Helper position 0 must omit --listen. READY JSON reports PID and actual address.
All listeners and destinations must be loopback. --delay-ms N is sink-only and
delays each target slice, for fault/flow-control experiments. Unknown keys fail.

PLAN is one key=value per line; all keys are required:
  k, m                  data and parity shard counts (decimal)
  shard_len, slice_len  bytes; slice_len is 1..1048576
  healthy, targets      comma-separated ordered shard IDs
  job, stripe           unsigned 128-bit decimal IDs
  generation, epoch     unsigned 64-bit decimal IDs
  plan                  64 hex digits of a trusted preinstalled plan fingerprint
The CLI does not recompute this fingerprint or authenticate its origin.

SLICE_CRCS contains one eight-digit hex CRC32C per consecutive source slice;
the final short slice has its own CRC, and an empty source uses an empty list.
EXPECTED contains target_id=CRC32C lines for complete original target shards.
These checksums must be generated independently before a fault is injected.

Each helper opens only its named read-only source. The sink requires a new
output directory and creates shard-ID files in an adjacent new stage directory.
After full length/CRC checks it fsyncs files and the stage, renames the directory,
then fsyncs its parent. Any failure after seal begins preserves the data.
Use a native Linux filesystem for strict directory publication semantics;
Windows-mounted filesystems may reject operations (errors are not ignored).
This is exclusive-directory publication, not Meta CAS, native 3FS, authenticated
networking, independent physical disks, or proof of power-loss durability.
"#;

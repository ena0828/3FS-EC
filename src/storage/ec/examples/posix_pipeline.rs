//! Local EC integration through POSIX files, optionally on a mounted 3FS volume.
//! Linux only; this does not add native EC to StorageClient or independent nodes.
use hf3fs_ec::{
    repair_pipeline, repair_sequential, Backend, Codec, Error, PipelineConfig, Result, ShardStore,
};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

const K: usize = 10;
const N: usize = 12;
const MAGIC: &[u8] = b"3fs-ec-posix-v1\0cauchy-systematic-gf256-11d-k10-m2-inv-row-xor-col\0";
const MANIFEST: &str = "manifest";
const NEXT: &str = "manifest.next";

fn err(s: impl Into<String>) -> Error {
    Error(s.into())
}
fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|e| err(e.to_string()))
}
fn new_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| err(format!("create {}: {e}", path.display())))
}
fn sync_dir(path: &Path) -> Result<()> {
    io(File::open(path).and_then(|f| f.sync_all()))
}
fn backend_name(backend: Backend) -> &'static str {
    match backend {
        Backend::Scalar => "scalar",
        #[cfg(feature = "isal-backend")]
        Backend::Isal => "isal",
    }
}
fn parse_backend(name: &str) -> Result<Backend> {
    match name {
        "scalar" => Ok(Backend::Scalar),
        #[cfg(feature = "isal-backend")]
        "isal" => Ok(Backend::Isal),
        #[cfg(not(feature = "isal-backend"))]
        "isal" => Err(err("ISA-L requires building with feature isal-backend")),
        _ => Err(err("backend must be scalar or isal")),
    }
}
fn shard_path(root: &Path, shard: usize, staged: bool) -> PathBuf {
    root.join(format!(
        "{}-{shard:02}",
        if staged { "repair" } else { "initial" }
    ))
}
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
fn bytes(length: usize, mut state: u64) -> Vec<u8> {
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Manifest {
    logical: usize,
    shard_len: usize,
    seed: u64,
    logical_crc: u32,
    repaired: u16,
    checksums: [u32; N],
}
impl Manifest {
    fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for value in [self.logical as u64, self.shard_len as u64, self.seed] {
            out.extend(value.to_le_bytes());
        }
        out.extend(self.logical_crc.to_le_bytes());
        out.extend(self.repaired.to_le_bytes());
        for value in self.checksums {
            out.extend(value.to_le_bytes());
        }
        out
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MAGIC.len() + 30 + 4 * N || !bytes.starts_with(MAGIC) {
            return Err(err("invalid manifest length or codec identifier"));
        }
        fn take<const L: usize>(b: &[u8], offset: &mut usize) -> [u8; L] {
            let mut out = [0; L];
            out.copy_from_slice(&b[*offset..*offset + L]);
            *offset += L;
            out
        }
        let mut p = MAGIC.len();
        let logical = usize::try_from(u64::from_le_bytes(take(bytes, &mut p)))
            .map_err(|_| err("manifest logical length overflows usize"))?;
        let shard_len = usize::try_from(u64::from_le_bytes(take(bytes, &mut p)))
            .map_err(|_| err("manifest shard length overflows usize"))?;
        let seed = u64::from_le_bytes(take(bytes, &mut p));
        let logical_crc = u32::from_le_bytes(take(bytes, &mut p));
        let repaired = u16::from_le_bytes(take(bytes, &mut p));
        let checksums = std::array::from_fn(|_| u32::from_le_bytes(take(bytes, &mut p)));
        if shard_len == 0
            || shard_len > 64 * 1024 * 1024 / K + 1
            || logical > 64 * 1024 * 1024
            || logical.div_ceil(K).max(1) != shard_len
            || repaired >= 1 << N
            || seed == 0
        {
            return Err(err("manifest parameters exceed experiment limits"));
        }
        Ok(Self {
            logical,
            shard_len,
            seed,
            logical_crc,
            repaired,
            checksums,
        })
    }
}
fn read_manifest(root: &Path) -> Result<Manifest> {
    let mut bytes = Vec::new();
    io(File::open(root.join(MANIFEST)))?
        .take(4096)
        .read_to_end(&mut bytes)
        .map_err(|e| err(format!("read manifest: {e}")))?;
    Manifest::decode(&bytes)
}
fn read_file(file: &File, length: usize) -> Result<Vec<u8>> {
    if io(file.metadata())?.len() != length as u64 {
        return Err(err("shard length changed"));
    }
    let mut out = vec![0; length];
    io(file.read_exact_at(&mut out, 0))?;
    Ok(out)
}
fn unlink_owned(path: &Path, file: &File) -> Result<()> {
    let held = io(file.metadata())?;
    let current = io(fs::symlink_metadata(path))?;
    if !current.is_file() || current.dev() != held.dev() || current.ino() != held.ino() {
        return Err(err(format!(
            "refusing to remove replaced path {}",
            path.display()
        )));
    }
    io(fs::remove_file(path))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    WriteAfter(usize),
    AfterRename,
    AfterSync,
}
struct State {
    offsets: [usize; N],
    writes: usize,
    attempted: bool,
    published: bool,
}
struct Store<'a> {
    root: &'a Path,
    expected: &'a [Vec<u8>],
    base: &'a Manifest,
    targets: &'a [usize],
    inputs: Vec<Option<File>>,
    staged: Vec<Option<File>>,
    next: File,
    state: Mutex<State>,
    fault: Fault,
}
impl<'a> Store<'a> {
    fn open(
        root: &'a Path,
        expected: &'a [Vec<u8>],
        base: &'a Manifest,
        targets: &'a [usize],
        fault: Fault,
    ) -> Result<Self> {
        if expected.len() != N
            || expected.iter().any(|bytes| bytes.len() != base.shard_len)
            || targets.is_empty()
            || targets.len() > N - K
            || targets.iter().any(|&shard| shard >= N)
            || (targets.len() == 2 && targets[0] == targets[1])
            || base.repaired != 0
        {
            return Err(err("inconsistent initial codeword or target set"));
        }
        if read_manifest(root)? != *base {
            return Err(err("initial manifest changed"));
        }
        let mut inputs = Vec::new();
        let mut staged = Vec::new();
        for (shard, wanted) in expected.iter().enumerate() {
            if targets.contains(&shard) {
                match fs::symlink_metadata(shard_path(root, shard, false)) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(err("target initial shard was not verifiably removed")),
                }
                inputs.push(None);
                staged.push(Some(new_file(&shard_path(root, shard, true))?));
            } else {
                let file = io(File::open(shard_path(root, shard, false)))?;
                if read_file(&file, base.shard_len)? != *wanted {
                    return Err(err("source verification failed"));
                }
                inputs.push(Some(file));
                staged.push(None);
            }
        }
        Ok(Self {
            root,
            expected,
            base,
            targets,
            inputs,
            staged,
            next: new_file(&root.join(NEXT))?,
            state: Mutex::new(State {
                offsets: [0; N],
                writes: 0,
                attempted: false,
                published: false,
            }),
            fault,
        })
    }
    fn check_targets(&self, supplied: &[usize]) -> Result<()> {
        if supplied != self.targets {
            return Err(err("target set/order changed"));
        }
        Ok(())
    }
}
impl ShardStore for Store<'_> {
    fn read_shard(&self, shard: usize, offset: usize, length: usize) -> Result<Vec<u8>> {
        let file = self
            .inputs
            .get(shard)
            .and_then(Option::as_ref)
            .ok_or_else(|| err("invalid source"))?;
        let expected = self.expected[shard]
            .get(
                offset
                    ..offset
                        .checked_add(length)
                        .ok_or_else(|| err("offset overflow"))?,
            )
            .ok_or_else(|| err("source range exceeds shard"))?;
        let mut out = vec![0; length];
        io(file.read_exact_at(&mut out, offset as u64))?;
        if out != expected {
            return Err(err("source slice differs from fixture oracle"));
        }
        Ok(out)
    }
    fn write_shard(&self, shard: usize, offset: usize, data: &[u8]) -> Result<()> {
        let file = self
            .staged
            .get(shard)
            .and_then(Option::as_ref)
            .ok_or_else(|| err("invalid target"))?;
        let mut state = self.state.lock().map_err(|_| err("store state poisoned"))?;
        if state.attempted
            || state.offsets[shard] != offset
            || data.is_empty()
            || offset
                .checked_add(data.len())
                .is_none_or(|end| end > self.base.shard_len)
        {
            return Err(err("invalid or out-of-order target slice"));
        }
        if matches!(self.fault, Fault::WriteAfter(n) if state.writes >= n) {
            return Err(err("injected write failure"));
        }
        io(file.write_all_at(data, offset as u64))?;
        state.offsets[shard] += data.len();
        state.writes += 1;
        Ok(())
    }
    fn commit(&self, targets: &[usize]) -> Result<()> {
        self.check_targets(targets)?;
        let mut state = self.state.lock().map_err(|_| err("store state poisoned"))?;
        if state.attempted {
            return Err(err("publication already attempted"));
        }
        if read_manifest(self.root)? != *self.base {
            return Err(err("manifest changed before publication"));
        }
        let mut published = self.base.clone();
        for &shard in targets {
            let file = self.staged[shard]
                .as_ref()
                .ok_or_else(|| err("missing staged file"))?;
            if state.offsets[shard] != self.base.shard_len
                || read_file(file, self.base.shard_len)? != self.expected[shard]
            {
                return Err(err("incomplete or incorrect repair"));
            }
            io(file.sync_all())?;
            published.repaired |= 1 << shard;
        }
        io(self.next.write_all_at(&published.encode(), 0))?;
        io(self.next.sync_all())?;
        state.attempted = true;
        io(fs::rename(self.root.join(NEXT), self.root.join(MANIFEST)))?;
        if self.fault == Fault::AfterRename {
            return Err(err("injected error after rename"));
        }
        sync_dir(self.root)?;
        if self.fault == Fault::AfterSync {
            return Err(err("injected acknowledgement loss after sync"));
        }
        state.published = true;
        Ok(())
    }
    fn abort(&self, targets: &[usize]) -> Result<()> {
        self.check_targets(targets)?;
        let state = self
            .state
            .lock()
            .map_err(|_| err("state poisoned; staging retained"))?;
        if state.attempted {
            return Err(err(
                "publication attempted; staging retained pending recovery verification",
            ));
        }
        if read_manifest(self.root)
            .map_err(|e| err(format!("manifest unverified; staging retained: {e}")))?
            != *self.base
            || targets
                .iter()
                .any(|&shard| self.base.repaired & (1 << shard) != 0)
        {
            return Err(err("manifest changed; staging retained"));
        }
        // Never recurse or remove arbitrary directory entries. Every deletion
        // requires the dev/ino of the exact file opened by this repair owner.
        for &shard in targets {
            unlink_owned(
                &shard_path(self.root, shard, true),
                self.staged[shard].as_ref().unwrap(),
            )?;
        }
        unlink_owned(&self.root.join(NEXT), &self.next)?;
        sync_dir(self.root)
    }
}

#[derive(Clone)]
struct Args {
    root: PathBuf,
    mode: String,
    backend: Backend,
    length: usize,
    seed: u64,
    missing: Vec<usize>,
    slice: usize,
    queue: usize,
    require_3fs: bool,
    verify_abort: bool,
    verify_existing: bool,
}
impl Args {
    fn parse() -> Result<Self> {
        let mut out = Self {
            root: PathBuf::new(),
            mode: "both".into(),
            backend: Backend::Scalar,
            length: 112 * 1024,
            seed: 20261029,
            missing: vec![0, 11],
            slice: 4096,
            queue: 2,
            require_3fs: false,
            verify_abort: false,
            verify_existing: false,
        };
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--require-3fs" => out.require_3fs = true, "--verify-abort" => out.verify_abort = true,
                "--verify-existing" => out.verify_existing = true,
                "--help" => return Err(err("usage: posix_pipeline --root DIRECTORY [--verify-existing] [--mode sequential|pipeline|both] [--backend scalar|isal] [--bytes N] [--seed N] [--missing 0,11] [--slice-bytes N] [--queue-depth N] [--require-3fs] [--verify-abort]")),
                _ => {
                    let value = args.next().ok_or_else(|| err(format!("missing value for {flag}")))?;
                    match flag.as_str() {
                        "--root" => out.root = value.into(), "--mode" => out.mode = value,
                        "--backend" => out.backend = parse_backend(&value)?,
                        "--bytes" => out.length = value.parse().map_err(|_| err("invalid bytes"))?,
                        "--seed" => out.seed = value.parse().map_err(|_| err("invalid seed"))?,
                        "--missing" => out.missing = value.split(',').map(|v| v.parse().map_err(|_| err("invalid missing index"))).collect::<Result<_>>()?,
                        "--slice-bytes" => out.slice = value.parse().map_err(|_| err("invalid slice length"))?,
                        "--queue-depth" => out.queue = value.parse().map_err(|_| err("invalid queue depth"))?,
                        _ => return Err(err(format!("unknown argument {flag}"))),
                    }
                }
            }
        }
        if out.root.as_os_str().is_empty()
            || !matches!(out.mode.as_str(), "sequential" | "pipeline" | "both")
            || (out.verify_existing && out.verify_abort)
            || (!out.verify_existing
                && (out.length > 64 * 1024 * 1024
                    || out.seed == 0
                    || out.missing.is_empty()
                    || out.missing.len() > 2
                    || out.missing.iter().any(|&s| s >= N)
                    || (out.missing.len() == 2 && out.missing[0] == out.missing[1])))
        {
            return Err(err(
                "invalid arguments; verify-existing and verify-abort are mutually exclusive",
            ));
        }
        Ok(out)
    }
}

fn mount_unescape(field: &str) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut out = Vec::new();
    let mut i = 0;
    let b = field.as_bytes();
    while i < b.len() {
        if b[i] == b'\\' {
            let digits = b
                .get(i + 1..i + 4)
                .ok_or_else(|| err("truncated mountinfo escape"))?;
            if !digits.iter().all(|d| (b'0'..=b'7').contains(d)) {
                return Err(err("invalid mountinfo escape"));
            }
            let value = u16::from(digits[0] - b'0') * 64
                + u16::from(digits[1] - b'0') * 8
                + u16::from(digits[2] - b'0');
            out.push(u8::try_from(value).map_err(|_| err("mountinfo escape overflow"))?);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(std::ffi::OsString::from_vec(out).into())
}
fn mount_type(path: &Path, mountinfo: &str) -> Result<String> {
    let mut best = None;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            return Err(err("malformed mountinfo"));
        };
        let field = left
            .split_whitespace()
            .nth(4)
            .ok_or_else(|| err("mountinfo missing mountpoint"))?;
        let mount = mount_unescape(field)?;
        if path.starts_with(&mount) {
            let depth = mount.components().count();
            if best.as_ref().is_none_or(|(old, _)| depth >= *old) {
                best = Some((
                    depth,
                    right
                        .split_whitespace()
                        .next()
                        .ok_or_else(|| err("mountinfo missing fs type"))?
                        .to_owned(),
                ));
            }
        }
    }
    best.map(|(_, fs)| fs)
        .ok_or_else(|| err("no covering mount found"))
}
fn verify(root: &Path, expected: &[Vec<u8>], manifest: &Manifest) -> Result<()> {
    if read_manifest(root)? != *manifest {
        return Err(err("reopened manifest mismatch"));
    }
    let mut logical = Vec::new();
    for (shard, wanted) in expected.iter().enumerate() {
        let file = io(File::open(shard_path(
            root,
            shard,
            manifest.repaired & (1 << shard) != 0,
        )))?;
        let actual = read_file(&file, manifest.shard_len)?;
        if actual != *wanted || crc32c(&actual) != manifest.checksums[shard] {
            return Err(err("reopened codeword mismatch"));
        }
        if shard < K {
            logical.extend_from_slice(&actual);
        }
    }
    logical.truncate(manifest.logical);
    if logical != bytes(manifest.logical, manifest.seed) || crc32c(&logical) != manifest.logical_crc
    {
        return Err(err("reopened logical object mismatch"));
    }
    Ok(())
}
fn verify_existing(root: &Path, mode: &str, require_3fs: bool) -> Result<()> {
    let root = io(root.canonicalize())?;
    let filesystem = mount_type(&root, &io(fs::read_to_string("/proc/self/mountinfo"))?)?;
    if require_3fs && filesystem != "fuse.hf3fs" {
        return Err(err(format!("expected fuse.hf3fs, found {filesystem}")));
    }
    let manifest = read_manifest(&root)?;
    if !(1..=(N - K) as u32).contains(&manifest.repaired.count_ones()) {
        return Err(err(
            "existing experiment must publish one or two repaired targets",
        ));
    }
    // Recreate only the in-memory oracle. No data is generated on the filesystem.
    let original = bytes(manifest.logical, manifest.seed);
    let mut data = vec![vec![0; manifest.shard_len]; K];
    for (index, byte) in original.into_iter().enumerate() {
        data[index / manifest.shard_len][index % manifest.shard_len] = byte;
    }
    let expected = Codec::new(K, N - K)?.encode(&data)?;
    verify(&root, &expected, &manifest)?;
    let targets: Vec<_> = (0..N)
        .filter(|&shard| manifest.repaired & (1 << shard) != 0)
        .collect();
    println!("{{\"schema\":\"3fs-ec-posix-v1\",\"operation\":\"verify-existing\",\"scope\":\"read-only-existing-experiment\",\"filesystem\":\"{}\",\"mode\":\"{}\",\"object_bytes\":{},\"shard_bytes\":{},\"seed\":{},\"published_targets\":{:?},\"object_crc32c\":{},\"read_only\":true,\"files_verified\":12,\"service_restart_inferred\":false,\"power_loss_tested\":false,\"performance_claim\":false}}",
        filesystem, mode, manifest.logical, manifest.shard_len, manifest.seed, targets, manifest.logical_crc);
    Ok(())
}
fn run_case(root: &Path, args: &Args, pipeline: bool, fault: Fault) -> Result<()> {
    let codec = Codec::with_backend(K, N - K, args.backend)?;
    let original = bytes(args.length, args.seed);
    let shard_len = args.length.div_ceil(K).max(1);
    let mut data = vec![vec![0; shard_len]; K];
    for (i, byte) in original.iter().copied().enumerate() {
        data[i / shard_len][i % shard_len] = byte;
    }
    let encoded = codec.encode(&data)?;
    let manifest = Manifest {
        logical: original.len(),
        shard_len,
        seed: args.seed,
        logical_crc: crc32c(&original),
        repaired: 0,
        checksums: std::array::from_fn(|s| crc32c(&encoded[s])),
    };
    let healthy: Vec<_> = (0..N)
        .filter(|s| !args.missing.contains(s))
        .take(K)
        .collect();
    let plan = codec.repair_plan(&healthy, &args.missing)?;
    let config = PipelineConfig {
        shard_len,
        slice_len: args.slice,
        queue_depth: args.queue,
    };
    config.validate(&plan)?;
    io(DirBuilder::new().mode(0o700).create(root))?;
    for (shard, content) in encoded.iter().enumerate() {
        let mut file = new_file(&shard_path(root, shard, false))?;
        io(file.write_all(content))?;
        io(file.sync_all())?;
    }
    let mut file = new_file(&root.join(MANIFEST))?;
    io(file.write_all(&manifest.encode()))?;
    io(file.sync_all())?;
    drop(file);
    sync_dir(root)?;
    verify(root, &encoded, &manifest)?;
    for &shard in &args.missing {
        let path = shard_path(root, shard, false);
        let file = io(File::open(&path))?;
        unlink_owned(&path, &file)?;
    }
    sync_dir(root)?;
    let repair = |store: &Store<'_>| {
        if pipeline {
            repair_pipeline(store, &plan, config)
        } else {
            repair_sequential(store, &plan, config)
        }
    };
    if args.verify_abort {
        let store = Store::open(
            root,
            &encoded,
            &manifest,
            &args.missing,
            Fault::WriteAfter(1),
        )?;
        // A one-slice, one-target case must fail before its first write.
        let store = if shard_len.div_ceil(args.slice) * args.missing.len() == 1 {
            Store {
                fault: Fault::WriteAfter(0),
                ..store
            }
        } else {
            store
        };
        let failure = repair(&store).expect_err("injected write failure must fail");
        if !failure.0.contains("injected write failure")
            || failure.0.contains("abort failed")
            || read_manifest(root)? != manifest
        {
            return Err(err(format!("abort verification failed: {failure}")));
        }
        for &shard in &args.missing {
            if shard_path(root, shard, true).exists() {
                return Err(err("staging was not cleaned"));
            }
        }
    }
    let start = Instant::now();
    let result = {
        let store = Store::open(root, &encoded, &manifest, &args.missing, fault)?;
        repair(&store)
    };
    let elapsed = start.elapsed().as_micros();
    let mut published = manifest.clone();
    for &shard in &args.missing {
        published.repaired |= 1 << shard;
    }
    if fault != Fault::None {
        let failure = result.expect_err("injected publication failure must fail");
        if !failure
            .0
            .contains("staging retained pending recovery verification")
        {
            return Err(failure);
        }
        verify(root, &encoded, &published)?;
        return Ok(());
    }
    let stats = result?;
    verify(root, &encoded, &published)?;
    let filesystem = mount_type(
        &io(root.canonicalize())?,
        &io(fs::read_to_string("/proc/self/mountinfo"))?,
    )?;
    println!("{{\"schema\":\"3fs-ec-posix-v1\",\"scope\":\"single-mount-logical-shard-loss\",\"filesystem\":\"{}\",\"mode\":\"{}\",\"selected_backend\":\"{}\",\"object_bytes\":{},\"shard_bytes\":{},\"seed\":{},\"missing\":{:?},\"slice_bytes\":{},\"queue_depth\":{},\"slices\":{},\"read_bytes\":{},\"written_bytes\":{},\"object_crc32c\":{},\"elapsed_us\":{},\"abort_verified\":{},\"reopen_verified\":true,\"directory_sync_syscall_succeeded\":true,\"retained\":true,\"power_loss_tested\":false,\"performance_claim\":false}}",
        filesystem, if pipeline { "pipeline" } else { "sequential" }, backend_name(args.backend), args.length, shard_len, args.seed, args.missing, args.slice, args.queue,
        stats.slices, stats.read_bytes, stats.written_bytes, manifest.logical_crc, elapsed, args.verify_abort);
    Ok(())
}
fn execute(args: &Args) -> Result<()> {
    if args.verify_existing {
        for mode in ["sequential", "pipeline"] {
            if args.mode == "both" || args.mode == mode {
                verify_existing(&args.root.join(mode), mode, args.require_3fs)?;
            }
        }
        return Ok(());
    }
    let parent = args
        .root
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = io(parent.canonicalize())?;
    let fs_type = mount_type(&parent, &io(fs::read_to_string("/proc/self/mountinfo"))?)?;
    if args.require_3fs && fs_type != "fuse.hf3fs" {
        return Err(err(format!("expected fuse.hf3fs, found {fs_type}")));
    }
    let name = args
        .root
        .file_name()
        .ok_or_else(|| err("root must name a new directory"))?;
    let root = parent.join(name);
    io(DirBuilder::new().mode(0o700).create(&root))?;
    sync_dir(&parent)?;
    eprintln!(
        "retained experiment root: {}; filesystem: {fs_type}",
        root.display()
    );
    for pipeline in [false, true] {
        let mode = if pipeline { "pipeline" } else { "sequential" };
        if args.mode == "both" || args.mode == mode {
            run_case(&root.join(mode), args, pipeline, Fault::None)?;
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = Args::parse().and_then(|args| execute(&args)) {
        eprintln!("posix_pipeline: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    fn scratch() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "3fs-ec-posix-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }
    fn args(root: PathBuf) -> Args {
        Args {
            root,
            mode: "both".into(),
            backend: Backend::Scalar,
            length: 1031,
            seed: 42,
            missing: vec![0, 11],
            slice: 31,
            queue: 1,
            require_3fs: false,
            verify_abort: true,
            verify_existing: false,
        }
    }
    fn clear_test_case(path: &Path) {
        // Test-owned fresh directories only; no recursive removal API is used.
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            fs::remove_file(entry.path()).unwrap();
        }
        fs::remove_dir(path).unwrap();
    }
    #[test]
    fn posix_repairs_boundaries_and_all_missing_pairs() {
        let root = scratch();
        let mut config = args(root.clone());
        for (case, length) in [0, 1, 9, 10, 11, 1031, 112 * 1024].into_iter().enumerate() {
            config.length = length;
            for pipeline in [false, true] {
                let path = root.join(format!("boundary-{case}-{pipeline}"));
                run_case(&path, &config, pipeline, Fault::None).unwrap();
                clear_test_case(&path);
            }
        }
        config.length = 1031;
        for a in 0..N {
            for b in a + 1..N {
                config.missing = vec![a, b];
                let path = root.join(format!("pair-{a}-{b}"));
                run_case(&path, &config, true, Fault::None).unwrap();
                clear_test_case(&path);
            }
        }
        config.length = 1;
        config.missing = vec![0];
        let path = root.join("single");
        run_case(&path, &config, true, Fault::None).unwrap();
        clear_test_case(&path);
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn posix_published_output_survives_uncertain_return() {
        let root = scratch();
        let config = args(root.clone());
        for (case, fault) in [Fault::AfterRename, Fault::AfterSync]
            .into_iter()
            .enumerate()
        {
            for pipeline in [false, true] {
                let path = root.join(format!("fault-{case}-{pipeline}"));
                run_case(&path, &config, pipeline, fault).unwrap();
                assert!(shard_path(&path, 0, true).is_file());
                assert!(shard_path(&path, 11, true).is_file());
                assert!(!path.join(NEXT).exists());
                clear_test_case(&path);
            }
        }
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn readonly_verification_rejects_damage_without_writing() {
        let root = scratch();
        let case = root.join("pipeline");
        let mut config = args(root.clone());
        run_case(&case, &config, true, Fault::None).unwrap();
        config.mode = "pipeline".into();
        config.verify_existing = true;
        config.verify_abort = false;
        config.length = 1;
        config.seed = 9;
        config.missing = vec![2];
        let snapshot = || {
            let mut files: Vec<_> = fs::read_dir(&case)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    let metadata = entry.metadata().unwrap();
                    (
                        entry.file_name(),
                        fs::read(entry.path()).unwrap(),
                        metadata.ino(),
                        metadata.modified().unwrap(),
                    )
                })
                .collect();
            files.sort_by(|a, b| a.0.cmp(&b.0));
            files
        };
        let before = snapshot();
        execute(&config).unwrap();
        assert_eq!(snapshot(), before);
        let original_manifest = fs::read(case.join(MANIFEST)).unwrap();
        for mask in [0, 7] {
            let mut invalid = Manifest::decode(&original_manifest).unwrap();
            invalid.repaired = mask;
            fs::write(case.join(MANIFEST), invalid.encode()).unwrap();
            let before = snapshot();
            assert!(execute(&config).is_err());
            assert_eq!(snapshot(), before);
        }
        fs::write(case.join(MANIFEST), b"damaged manifest").unwrap();
        let before = snapshot();
        assert!(execute(&config).is_err());
        assert_eq!(snapshot(), before);
        fs::write(case.join(MANIFEST), original_manifest).unwrap();
        let source = shard_path(&case, 1, false);
        let mut damaged = fs::read(&source).unwrap();
        damaged[0] ^= 1;
        fs::write(source, damaged).unwrap();
        let before = snapshot();
        assert!(execute(&config).is_err());
        assert_eq!(snapshot(), before);
        clear_test_case(&case);
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn posix_abort_preserves_unknown_manifest_and_replaced_files() {
        let root = scratch();
        let data = vec![vec![7; 8]; K];
        let encoded = Codec::new(K, 2).unwrap().encode(&data).unwrap();
        let manifest = Manifest {
            logical: 80,
            shard_len: 8,
            seed: 42,
            logical_crc: crc32c(&[7; 80]),
            repaired: 0,
            checksums: std::array::from_fn(|s| crc32c(&encoded[s])),
        };
        for (s, content) in encoded.iter().enumerate().skip(1) {
            io(new_file(&shard_path(&root, s, false))
                .unwrap()
                .write_all_at(content, 0))
            .unwrap();
        }
        fs::write(root.join(MANIFEST), manifest.encode()).unwrap();
        let store = Store::open(&root, &encoded, &manifest, &[0], Fault::None).unwrap();
        store.write_shard(0, 0, &[7; 4]).unwrap();
        fs::write(root.join(MANIFEST), b"broken").unwrap();
        assert!(store
            .abort(&[0])
            .unwrap_err()
            .0
            .contains("manifest unverified"));
        assert_eq!(fs::read(shard_path(&root, 0, true)).unwrap(), [7; 4]);
        fs::write(root.join(MANIFEST), manifest.encode()).unwrap();
        fs::rename(shard_path(&root, 0, true), root.join("owned-staging-moved")).unwrap();
        fs::write(shard_path(&root, 0, true), b"unrelated replacement").unwrap();
        assert!(store
            .abort(&[0])
            .unwrap_err()
            .0
            .contains("refusing to remove replaced path"));
        assert_eq!(
            fs::read(shard_path(&root, 0, true)).unwrap(),
            b"unrelated replacement"
        );
        drop(store);
        clear_test_case(&root);
    }
    #[test]
    fn mount_check_and_manifest_reject_ambiguous_inputs() {
        let info = "1 0 0:1 / / rw - ext4 /dev/root rw\n2 1 0:2 / /mnt/three\\040fs rw - fuse.hf3fs hf3fs.test rw\n3 2 0:3 / /mnt/three\\040fs/nested rw - tmpfs tmpfs rw\n";
        assert_eq!(
            mount_type(Path::new("/mnt/three fs/data"), info).unwrap(),
            "fuse.hf3fs"
        );
        assert_eq!(
            mount_type(Path::new("/mnt/three fs/nested/data"), info).unwrap(),
            "tmpfs"
        );
        assert_eq!(
            mount_type(Path::new("/mnt/three fs-other"), info).unwrap(),
            "ext4"
        );
        assert!(mount_unescape("/bad\\777").is_err());
        assert!(Manifest::decode(b"bad").is_err());
        assert_eq!(crc32c(b"123456789"), 0xe3069283);
        let root = scratch();
        let config = args(root.clone());
        fs::write(root.join("unrelated"), b"preserve").unwrap();
        assert!(execute(&config).is_err());
        assert_eq!(fs::read(root.join("unrelated")).unwrap(), b"preserve");
        clear_test_case(&root);
    }
}

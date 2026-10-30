//! Local EC repair over the real 3FS ChunkEngine. Shards share one failure domain.
//! This example does not implement the distributed CRAQ protocol or a FUSE mount.

use chunk_engine::{Engine, EngineConfig, FsType, UpdateReq};
use clap::{Parser, ValueEnum};
use hf3fs_ec::{
    repair_pipeline, repair_sequential, Codec, Error, PipelineConfig, RepairStats, ShardStore,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

type Result<T> = std::result::Result<T, Error>;
const DATA_SHARDS: usize = 10;
const PARITY_SHARDS: usize = 2;
const SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;
const MAX_SHARD_BYTES: usize = 64 * 1024;
const MANIFEST_KEY: &[u8] = b"ec-local/v1/manifest";
const CODEC_ID: &str = "cauchy-systematic-gf256-11d-inv-global-row-xor-column-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Mode {
    Sequential,
    Pipeline,
    Both,
}

impl Mode {
    fn cases(self) -> &'static [bool] {
        match self {
            Self::Sequential => &[false],
            Self::Pipeline => &[true],
            Self::Both => &[false, true],
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "Verify 10+2 EC repair using real, local 3FS ChunkEngine storage")]
struct Args {
    /// Existing Linux ext4/XFS directory for isolated temporary stores.
    #[arg(long)]
    root: PathBuf,
    /// Select one strategy for externally randomized runs, or both for a smoke test.
    #[arg(long, value_enum, default_value = "both")]
    mode: Mode,
    /// Logical object size, bounded to keep each shard within 64 KiB.
    #[arg(long, default_value_t = 112 * 1024)]
    bytes: usize,
    #[arg(long, default_value_t = 20261029)]
    seed: u64,
    #[arg(long, value_delimiter = ',', default_value = "0,11")]
    missing: Vec<usize>,
    #[arg(long, default_value_t = 4096)]
    slice_bytes: usize,
    #[arg(long, default_value_t = 2)]
    queue_depth: usize,
    /// First inject a write failure, verify staging cleanup, then retry repair.
    #[arg(long)]
    verify_abort: bool,
    /// Preserve only this run's generated directory for later inspection.
    #[arg(long)]
    keep: bool,
}

fn err(context: impl Into<String>) -> Error {
    Error(context.into())
}

fn native<T>(result: chunk_engine::Result<T>) -> Result<T> {
    result.map_err(|e| err(format!("ChunkEngine: {e}")))
}

fn key(shard: usize, staged: bool) -> Vec<u8> {
    format!(
        "ec-local/v1/object-generation-1/{}/{shard:02}",
        if staged { "repair" } else { "initial" }
    )
    .into_bytes()
}

fn put(engine: &Engine, key: &[u8], offset: usize, data: &[u8]) -> Result<()> {
    let mut request = UpdateReq {
        checksum: crc32c::crc32c(data),
        length: u32::try_from(data.len()).map_err(|_| err("write length exceeds u32"))?,
        offset: u32::try_from(offset).map_err(|_| err("write offset exceeds u32"))?,
        data: data.as_ptr() as u64,
        ..Default::default()
    };
    // update_chunk consumes the borrowed input synchronously before returning.
    let pending = native(engine.update_chunk(key, &mut request))?;
    native(engine.commit_chunk(pending, true))?;
    Ok(())
}

fn read_full(engine: &Engine, key: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    let chunk = native(engine.get(key))?.ok_or_else(|| err("requested chunk is missing"))?;
    if chunk.meta().len as usize != expected_len {
        return Err(err("stored chunk length differs from manifest"));
    }
    let mut bytes = vec![0; expected_len];
    native(chunk.pread(&mut bytes, 0))?;
    if crc32c::crc32c(&bytes) != chunk.meta().checksum {
        return Err(err("stored chunk checksum mismatch"));
    }
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Manifest {
    logical_len: usize,
    shard_len: usize,
    seed: u64,
    logical_crc: u32,
    repaired: [bool; SHARDS],
    checksums: [u32; SHARDS],
}

impl Manifest {
    fn encode(&self) -> Vec<u8> {
        let mut text = format!(
            "3fs-ec-local-v1 {} 10 2 {} {} {} {}\n",
            CODEC_ID, self.logical_len, self.shard_len, self.seed, self.logical_crc
        );
        for shard in 0..SHARDS {
            text.push_str(&format!(
                "{} {} {}\n",
                shard,
                u8::from(self.repaired[shard]),
                self.checksums[shard]
            ));
        }
        text.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let text =
            std::str::from_utf8(bytes).map_err(|e| err(format!("invalid manifest UTF-8: {e}")))?;
        let mut fields = text.split_whitespace();
        if fields.next() != Some("3fs-ec-local-v1")
            || fields.next() != Some(CODEC_ID)
            || fields.next() != Some("10")
            || fields.next() != Some("2")
        {
            return Err(err("unsupported manifest schema or code parameters"));
        }
        fn number<T: std::str::FromStr>(fields: &mut std::str::SplitWhitespace<'_>) -> Result<T> {
            fields
                .next()
                .ok_or_else(|| err("truncated manifest"))?
                .parse()
                .map_err(|_| err("invalid numeric manifest field"))
        }
        let mut manifest = Self {
            logical_len: number(&mut fields)?,
            shard_len: number(&mut fields)?,
            seed: number(&mut fields)?,
            logical_crc: number(&mut fields)?,
            repaired: [false; SHARDS],
            checksums: [0; SHARDS],
        };
        if manifest.shard_len == 0
            || manifest.shard_len > MAX_SHARD_BYTES
            || manifest.logical_len > DATA_SHARDS * manifest.shard_len
        {
            return Err(err("manifest length exceeds local experiment limits"));
        }
        for shard in 0..SHARDS {
            if number::<usize>(&mut fields)? != shard {
                return Err(err("manifest shard order is invalid"));
            }
            manifest.repaired[shard] = match number::<u8>(&mut fields)? {
                0 => false,
                1 => true,
                _ => return Err(err("invalid manifest repaired flag")),
            };
            manifest.checksums[shard] = number(&mut fields)?;
        }
        if fields.next().is_some() {
            return Err(err("unexpected trailing manifest fields"));
        }
        Ok(manifest)
    }
}

struct EngineShardStore<'a> {
    engine: &'a Engine,
    expected: &'a [Vec<u8>],
    versions: [Option<u32>; SHARDS],
    targets: BTreeSet<usize>,
    next_offsets: Mutex<[usize; SHARDS]>,
    manifest: Manifest,
    publication_attempted: AtomicBool,
    published: AtomicBool,
    #[cfg(test)]
    fail_after_manifest_put: bool,
    fail_after_writes: Option<usize>,
    successful_writes: AtomicUsize,
}

impl ShardStore for EngineShardStore<'_> {
    fn read_shard(&self, shard: usize, offset: usize, length: usize) -> Result<Vec<u8>> {
        if shard >= SHARDS
            || self.targets.contains(&shard)
            || length == 0
            || offset
                .checked_add(length)
                .map_or(true, |end| end > self.manifest.shard_len)
        {
            return Err(err("invalid source shard slice"));
        }
        let chunk = native(self.engine.get(&key(shard, false)))?
            .ok_or_else(|| err("source shard disappeared"))?;
        if Some(chunk.meta().chunk_ver) != self.versions[shard]
            || chunk.meta().len as usize != self.manifest.shard_len
            || chunk.meta().checksum != self.manifest.checksums[shard]
        {
            return Err(err("source shard changed after validation"));
        }
        let mut bytes = vec![0; length];
        native(chunk.pread(&mut bytes, offset as u32))?;
        Ok(bytes)
    }

    fn write_shard(&self, shard: usize, offset: usize, data: &[u8]) -> Result<()> {
        if !self.targets.contains(&shard)
            || data.is_empty()
            || offset
                .checked_add(data.len())
                .map_or(true, |end| end > self.manifest.shard_len)
        {
            return Err(err("invalid repair output slice"));
        }
        let mut offsets = self
            .next_offsets
            .lock()
            .map_err(|_| err("repair output lock poisoned"))?;
        if offsets[shard] != offset {
            return Err(err("repair slices are out of order or duplicated"));
        }
        if self
            .fail_after_writes
            .is_some_and(|limit| self.successful_writes.load(Ordering::Acquire) >= limit)
        {
            return Err(err("injected repair write failure"));
        }
        put(self.engine, &key(shard, true), offset, data)?;
        offsets[shard] += data.len();
        self.successful_writes.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn commit(&self, targets: &[usize]) -> Result<()> {
        if self.publication_attempted.load(Ordering::Acquire) {
            return Err(err("manifest publication was already attempted"));
        }
        let supplied: BTreeSet<_> = targets.iter().copied().collect();
        if supplied != self.targets || supplied.len() != targets.len() {
            return Err(err("commit target set differs from repair plan"));
        }
        let offsets = self
            .next_offsets
            .lock()
            .map_err(|_| err("repair output lock poisoned"))?;
        for &shard in targets {
            if offsets[shard] != self.manifest.shard_len {
                return Err(err("cannot publish incomplete shard"));
            }
            let actual = read_full(self.engine, &key(shard, true), self.manifest.shard_len)?;
            if actual != self.expected[shard]
                || crc32c::crc32c(&actual) != self.manifest.checksums[shard]
            {
                return Err(err("reconstructed shard differs from original"));
            }
        }
        // Only one local manifest is replaced, after all staged output verifies.
        // This is not a distributed transaction or a power-loss recovery proof.
        let mut published = self.manifest.clone();
        for &shard in targets {
            published.repaired[shard] = true;
        }
        // A failed acknowledgement does not prove the manifest was not written.
        // Engine::get may still serve its old cache after a metadata write error.
        self.publication_attempted.store(true, Ordering::Release);
        put(self.engine, MANIFEST_KEY, 0, &published.encode())?;
        #[cfg(test)]
        if self.fail_after_manifest_put {
            return Err(err("injected manifest acknowledgement loss"));
        }
        self.published.store(true, Ordering::Release);
        Ok(())
    }

    fn abort(&self, targets: &[usize]) -> Result<()> {
        let supplied: BTreeSet<_> = targets.iter().copied().collect();
        if supplied != self.targets || supplied.len() != targets.len() {
            return Err(err("abort target set differs from repair plan"));
        }
        let _offsets = self
            .next_offsets
            .lock()
            .map_err(|_| err("repair output lock poisoned; staged output retained"))?;
        if self.published.load(Ordering::Acquire) {
            return Err(err("refusing to delete already published repair output"));
        }
        if self.publication_attempted.load(Ordering::Acquire) {
            return Err(err(
                "manifest publication was attempted; staged output retained pending recovery verification",
            ));
        }
        // This example has one exclusive repair owner. Even before publication,
        // require a verified, unchanged manifest before deleting staged keys.
        let current = read_full(self.engine, MANIFEST_KEY, self.manifest.encode().len())
            .and_then(|bytes| Manifest::decode(&bytes))
            .map_err(|failure| {
                err(format!(
                    "cannot verify manifest before abort: {failure}; staged output retained"
                ))
            })?;
        if current != self.manifest || targets.iter().any(|&shard| current.repaired[shard]) {
            return Err(err(
                "manifest changed or references repair output; staged output retained",
            ));
        }
        let mut first_error = None;
        for &shard in targets {
            if let Err(e) = native(self.engine.remove(&key(shard, true))) {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn deterministic_data(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn validate(args: &Args) -> Result<()> {
    if args.bytes > DATA_SHARDS * MAX_SHARD_BYTES || args.seed == 0 {
        return Err(err(
            "object must be <=640 KiB and xorshift64 seed must be nonzero",
        ));
    }
    let missing: BTreeSet<_> = args.missing.iter().copied().collect();
    if missing.is_empty()
        || missing.len() > PARITY_SHARDS
        || missing.len() != args.missing.len()
        || missing.iter().any(|&shard| shard >= SHARDS)
    {
        return Err(err(
            "missing must contain one or two distinct shard indices in 0..12",
        ));
    }
    if args.slice_bytes == 0
        || args.slice_bytes > MAX_SHARD_BYTES
        || args.queue_depth == 0
        || args.queue_depth > 64
    {
        return Err(err(
            "slice-bytes must be 1..65536 and queue-depth must be 1..64",
        ));
    }
    if !args.root.is_dir() || !matches!(FsType::check(&args.root), FsType::EXT4 | FsType::XFS) {
        return Err(err("root must be an existing Linux ext4/XFS directory"));
    }
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // getrlimit writes exactly one initialized rlimit into the provided pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 || limit.rlim_cur < 8192 {
        return Err(err(
            "ChunkEngine needs >5632 descriptors; run ulimit -n 65536 first",
        ));
    }
    Ok(())
}

struct Outcome {
    stats: RepairStats,
    elapsed_us: u128,
    shard_len: usize,
    object_crc: u32,
}

fn run_case(path: &Path, args: &Args, pipeline: bool) -> Result<Outcome> {
    std::fs::create_dir(path).map_err(|e| err(format!("create fresh store: {e}")))?;
    let codec = Codec::new(DATA_SHARDS, PARITY_SHARDS)?;
    let original = deterministic_data(args.bytes, args.seed);
    let shard_len = original.len().div_ceil(DATA_SHARDS).max(1);
    let mut data = vec![vec![0; shard_len]; DATA_SHARDS];
    for (index, byte) in original.iter().copied().enumerate() {
        data[index / shard_len][index % shard_len] = byte;
    }
    let encoded = codec.encode(&data)?;
    let checksums = std::array::from_fn(|shard| crc32c::crc32c(&encoded[shard]));
    let manifest = Manifest {
        logical_len: original.len(),
        shard_len,
        seed: args.seed,
        logical_crc: crc32c::crc32c(&original),
        repaired: [false; SHARDS],
        checksums,
    };
    let targets: BTreeSet<_> = args.missing.iter().copied().collect();
    let healthy: Vec<_> = (0..SHARDS)
        .filter(|shard| !targets.contains(shard))
        .take(DATA_SHARDS)
        .collect();
    let plan = codec.repair_plan(&healthy, &args.missing)?;
    let stats;
    let elapsed_us;
    {
        let engine = native(Engine::open(&EngineConfig {
            path: path.to_owned(),
            create: true,
            prefix_len: 0,
        }))?;
        for (shard, bytes) in encoded.iter().enumerate() {
            put(&engine, &key(shard, false), 0, bytes)?;
            if read_full(&engine, &key(shard, false), shard_len)? != *bytes {
                return Err(err("initial shard round-trip differs from input"));
            }
        }
        put(&engine, MANIFEST_KEY, 0, &manifest.encode())?;
        for &shard in &args.missing {
            native(engine.remove(&key(shard, false)))?;
            if native(engine.get(&key(shard, false)))?.is_some() {
                return Err(err("logical shard removal failed"));
            }
        }
        let mut versions = [None; SHARDS];
        for &shard in &healthy {
            let chunk = native(engine.get(&key(shard, false)))?
                .ok_or_else(|| err("source missing before repair"))?;
            versions[shard] = Some(chunk.meta().chunk_ver);
        }
        let mut store = EngineShardStore {
            engine: &engine,
            expected: &encoded,
            versions,
            targets,
            next_offsets: Mutex::new([0; SHARDS]),
            manifest: manifest.clone(),
            publication_attempted: AtomicBool::new(false),
            published: AtomicBool::new(false),
            #[cfg(test)]
            fail_after_manifest_put: false,
            fail_after_writes: None,
            successful_writes: AtomicUsize::new(0),
        };
        let config = PipelineConfig {
            shard_len,
            slice_len: args.slice_bytes,
            queue_depth: args.queue_depth,
        };
        if args.verify_abort {
            let total_writes = shard_len.div_ceil(args.slice_bytes) * args.missing.len();
            store.fail_after_writes = Some(usize::from(total_writes > 1));
            let result = if pipeline {
                repair_pipeline(&store, &plan, config)
            } else {
                repair_sequential(&store, &plan, config)
            };
            match result {
                Err(e) if e.0.contains("injected repair write failure") => {}
                other => {
                    return Err(err(format!(
                        "injected failure did not propagate: {other:?}"
                    )))
                }
            }
            if store.published.load(Ordering::Acquire)
                || read_full(&engine, MANIFEST_KEY, manifest.encode().len())? != manifest.encode()
            {
                return Err(err("failed repair changed the published manifest"));
            }
            for &shard in &args.missing {
                if native(engine.get(&key(shard, true)))?.is_some() {
                    return Err(err("failed repair left staged output"));
                }
            }
            store.fail_after_writes = None;
            store.successful_writes.store(0, Ordering::Release);
            *store
                .next_offsets
                .lock()
                .map_err(|_| err("repair output lock poisoned"))? = [0; SHARDS];
        }
        let start = Instant::now();
        stats = if pipeline {
            repair_pipeline(&store, &plan, config)?
        } else {
            repair_sequential(&store, &plan, config)?
        };
        elapsed_us = start.elapsed().as_micros();
        if !store.published.load(Ordering::Acquire) {
            return Err(err("repair returned without manifest publication"));
        }
    }
    {
        let engine = native(Engine::open(&EngineConfig {
            path: path.to_owned(),
            create: false,
            prefix_len: 0,
        }))?;
        let manifest_chunk = native(engine.get(MANIFEST_KEY))?
            .ok_or_else(|| err("manifest missing after reopen"))?;
        let persisted = Manifest::decode(&read_full(
            &engine,
            MANIFEST_KEY,
            manifest_chunk.meta().len as usize,
        )?)?;
        let mut expected_manifest = manifest.clone();
        for &shard in &args.missing {
            expected_manifest.repaired[shard] = true;
        }
        if persisted != expected_manifest {
            return Err(err("manifest changed after reopen"));
        }
        let mut restored = Vec::with_capacity(DATA_SHARDS * shard_len);
        for shard in 0..SHARDS {
            let actual = read_full(
                &engine,
                &key(shard, persisted.repaired[shard]),
                persisted.shard_len,
            )?;
            if actual != encoded[shard] || crc32c::crc32c(&actual) != persisted.checksums[shard] {
                return Err(err("reopened shard differs from original codeword"));
            }
            if shard < DATA_SHARDS {
                restored.extend_from_slice(&actual);
            }
        }
        restored.truncate(persisted.logical_len);
        if restored != original || crc32c::crc32c(&restored) != persisted.logical_crc {
            return Err(err("reopened logical object differs from original"));
        }
    }
    Ok(Outcome {
        stats,
        elapsed_us,
        shard_len,
        object_crc: manifest.logical_crc,
    })
}

fn json_string(value: &str) -> String {
    let mut escaped = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

fn execute(args: Args) -> Result<()> {
    validate(&args)?;
    let scratch = tempfile::Builder::new()
        .prefix("3fs-ec-")
        .tempdir_in(&args.root)
        .map_err(|e| err(format!("create experiment directory: {e}")))?;
    for &pipeline in args.mode.cases() {
        let mode = if pipeline { "pipeline" } else { "sequential" };
        let path = scratch.path().join(mode);
        let outcome = run_case(&path, &args, pipeline)?;
        println!(
            "{{\"schema\":\"3fs-ec-native-v1\",\"scope\":\"single-engine-logical-shard-loss\",\"mode\":{},\"path\":{},\"k\":10,\"m\":2,\"object_bytes\":{},\"shard_bytes\":{},\"seed\":{},\"missing\":{:?},\"slice_bytes\":{},\"queue_depth\":{},\"slices\":{},\"read_bytes\":{},\"written_bytes\":{},\"elapsed_us\":{},\"object_crc32c\":{},\"abort_verified\":{},\"reopen_verified\":true,\"power_loss_tested\":false,\"performance_claim\":false,\"retained\":{}}}",
            json_string(mode), json_string(&path.to_string_lossy()), args.bytes, outcome.shard_len,
            args.seed, args.missing, args.slice_bytes, args.queue_depth, outcome.stats.slices,
            outcome.stats.read_bytes, outcome.stats.written_bytes, outcome.elapsed_us, outcome.object_crc, args.verify_abort, args.keep
        );
    }
    if args.keep {
        let _ = scratch.into_path();
    }
    Ok(())
}

fn main() {
    if let Err(error) = execute(Args::parse()) {
        eprintln!(
            "{{\"schema\":\"3fs-ec-native-v1\",\"error\":{}}}",
            json_string(&error.to_string())
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_codeword() -> (Vec<Vec<u8>>, Manifest) {
        let shard_len = 104;
        let original = deterministic_data(DATA_SHARDS * shard_len, 42);
        let data: Vec<_> = original.chunks(shard_len).map(<[u8]>::to_vec).collect();
        let encoded = Codec::new(DATA_SHARDS, PARITY_SHARDS)
            .unwrap()
            .encode(&data)
            .unwrap();
        let manifest = Manifest {
            logical_len: original.len(),
            shard_len,
            seed: 42,
            logical_crc: crc32c::crc32c(&original),
            repaired: [false; SHARDS],
            checksums: std::array::from_fn(|shard| crc32c::crc32c(&encoded[shard])),
        };
        (encoded, manifest)
    }

    fn initial_store<'a>(
        engine: &'a Engine,
        encoded: &'a [Vec<u8>],
        manifest: &Manifest,
    ) -> EngineShardStore<'a> {
        let mut versions = [None; SHARDS];
        for (shard, bytes) in encoded.iter().enumerate() {
            put(engine, &key(shard, false), 0, bytes).unwrap();
            versions[shard] = Some(
                engine
                    .get(&key(shard, false))
                    .unwrap()
                    .unwrap()
                    .meta()
                    .chunk_ver,
            );
        }
        put(engine, MANIFEST_KEY, 0, &manifest.encode()).unwrap();
        for shard in [0, 11] {
            engine.remove(&key(shard, false)).unwrap();
            versions[shard] = None;
        }
        EngineShardStore {
            engine,
            expected: encoded,
            versions,
            targets: BTreeSet::from([0, 11]),
            next_offsets: Mutex::new([0; SHARDS]),
            manifest: manifest.clone(),
            publication_attempted: AtomicBool::new(false),
            published: AtomicBool::new(false),
            fail_after_manifest_put: false,
            fail_after_writes: None,
            successful_writes: AtomicUsize::new(0),
        }
    }

    fn assert_published_codeword(engine: &Engine, encoded: &[Vec<u8>], expected: &Manifest) {
        let current =
            Manifest::decode(&read_full(engine, MANIFEST_KEY, expected.encode().len()).unwrap())
                .unwrap();
        assert_eq!(&current, expected);
        let mut logical = Vec::new();
        for (shard, bytes) in encoded.iter().enumerate() {
            let actual = read_full(
                engine,
                &key(shard, current.repaired[shard]),
                current.shard_len,
            )
            .unwrap();
            assert_eq!(&actual, bytes);
            assert_eq!(crc32c::crc32c(&actual), current.checksums[shard]);
            if shard < DATA_SHARDS {
                logical.extend_from_slice(&actual);
            }
        }
        logical.truncate(current.logical_len);
        assert_eq!(crc32c::crc32c(&logical), current.logical_crc);
    }

    #[test]
    fn native_manifest_acknowledgement_loss_preserves_published_shards() {
        let root = tempfile::tempdir().unwrap();
        let (encoded, manifest) = test_codeword();
        let mut published = manifest.clone();
        for shard in [0, 11] {
            published.repaired[shard] = true;
        }
        {
            let engine = Engine::open(&EngineConfig {
                path: root.path().to_owned(),
                create: true,
                prefix_len: 0,
            })
            .unwrap();
            let mut store = initial_store(&engine, &encoded, &manifest);
            store.fail_after_manifest_put = true;
            let healthy: Vec<_> = (1..11).collect();
            let plan = Codec::new(DATA_SHARDS, PARITY_SHARDS)
                .unwrap()
                .repair_plan(&healthy, &[0, 11])
                .unwrap();
            let failure = repair_pipeline(
                &store,
                &plan,
                PipelineConfig {
                    shard_len: manifest.shard_len,
                    slice_len: 31,
                    queue_depth: 1,
                },
            )
            .unwrap_err();
            assert!(failure.0.contains("injected manifest acknowledgement loss"));
            assert!(failure.0.contains("abort failed"));
            assert!(failure
                .0
                .contains("staged output retained pending recovery verification"));
            assert!(store.publication_attempted.load(Ordering::Acquire));
            assert!(!store.published.load(Ordering::Acquire));
            assert_published_codeword(&engine, &encoded, &published);
        }
        // Normal close and reopen verifies the adapter's lost-acknowledgement
        // path. It does not simulate a sync error, crash, or power loss.
        let reopened = Engine::open(&EngineConfig {
            path: root.path().to_owned(),
            create: false,
            prefix_len: 0,
        })
        .unwrap();
        assert_published_codeword(&reopened, &encoded, &published);
    }

    #[test]
    fn native_abort_preserves_staging_when_manifest_is_uncertain() {
        let root = tempfile::tempdir().unwrap();
        let (encoded, manifest) = test_codeword();
        let engine = Engine::open(&EngineConfig {
            path: root.path().to_owned(),
            create: true,
            prefix_len: 0,
        })
        .unwrap();
        let store = initial_store(&engine, &encoded, &manifest);
        for shard in [0, 11] {
            store.write_shard(shard, 0, &encoded[shard][..17]).unwrap();
        }
        let assert_staging_retained = || {
            for shard in [0, 11] {
                assert_eq!(
                    read_full(&engine, &key(shard, true), 17).unwrap(),
                    encoded[shard][..17]
                );
            }
        };
        assert!(store.abort(&[0, 9]).is_err());
        assert_staging_retained();

        put(
            &engine,
            MANIFEST_KEY,
            0,
            &vec![b'?'; manifest.encode().len()],
        )
        .unwrap();
        assert!(store
            .abort(&[0, 11])
            .unwrap_err()
            .0
            .contains("cannot verify manifest"));
        assert_staging_retained();

        let mut changed = manifest.clone();
        changed.seed += 1;
        put(&engine, MANIFEST_KEY, 0, &changed.encode()).unwrap();
        assert!(store
            .abort(&[0, 11])
            .unwrap_err()
            .0
            .contains("manifest changed"));
        assert_staging_retained();

        engine.remove(MANIFEST_KEY).unwrap();
        assert!(store
            .abort(&[0, 11])
            .unwrap_err()
            .0
            .contains("cannot verify manifest"));
        assert_staging_retained();

        put(&engine, MANIFEST_KEY, 0, &manifest.encode()).unwrap();
        // Even a valid old manifest is not negative proof after publication
        // was attempted: Engine::get can return a cached old value.
        store.publication_attempted.store(true, Ordering::Release);
        assert!(store
            .abort(&[0, 11])
            .unwrap_err()
            .0
            .contains("pending recovery verification"));
        assert_staging_retained();
    }

    #[test]
    fn manifest_round_trip_rejects_invalid_lengths() {
        let manifest = Manifest {
            logical_len: 13,
            shard_len: 2,
            seed: 42,
            logical_crc: 7,
            repaired: [false; SHARDS],
            checksums: [0; SHARDS],
        };
        assert_eq!(Manifest::decode(&manifest.encode()).unwrap(), manifest);
        let mut invalid = manifest;
        invalid.shard_len = 0;
        assert!(Manifest::decode(&invalid.encode()).is_err());
        assert!(Manifest::decode(b"3fs-ec-local-v1 10 2").is_err());
    }

    #[test]
    fn native_repair_reopen_data_and_parity() {
        let root = tempfile::tempdir().unwrap();
        let mut args = Args {
            root: root.path().to_owned(),
            mode: Mode::Pipeline,
            bytes: 1031,
            seed: 42,
            missing: vec![0, 11],
            slice_bytes: 31,
            queue_depth: 1,
            verify_abort: true,
            keep: false,
        };
        validate(&args).unwrap();
        for (index, missing) in [vec![0, 1], vec![0, 11], vec![10, 11]]
            .into_iter()
            .enumerate()
        {
            args.missing = missing;
            run_case(&root.path().join(format!("case-{index}")), &args, true).unwrap();
        }
    }
}

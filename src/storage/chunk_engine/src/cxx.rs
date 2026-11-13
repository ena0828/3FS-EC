use std::collections::BTreeSet;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::ec_codec::{
    ec_codec_backend, ec_codec_contribute, ec_codec_encode, ec_codec_recover, ec_codec_verify,
};
use crate::ec_scope_bridge::*;
use crate::ec_stage_bridge::*;
use crate::*;
pub use ::cxx::CxxString;

pub(crate) fn storage_error_code(error: &Error) -> u16 {
    match error {
        Error::IoError(_) => 4011,              // ChunkWriteFailed
        Error::RocksDBError(_) => 4003,         // ChunkMetadataSetError
        Error::MetaError(_) => 4002,            // ChunkMetadataGetError
        Error::InvalidArg(_) => 3,              // InvalidArg
        Error::SerializationError(_) => 4002,   // ChunkMetadataGetError
        Error::ChecksumMismatch(_) => 4080,     // ChecksumMismatch
        Error::ChainVersionMismatch(_) => 4081, // ChainVersionMismatch
        Error::ChunkETagMismatch(_) => 4083,    // ChunkETagMismatch
        Error::ChunkAlreadyExists => 4084,      // ChunkAlreadyExists
        Error::ChunkCommittedUpdate(_) => 4008, // ChunkCommittedUpdate
        Error::ChunkMissingUpdate(_) => 4007,   // ChunkMissingUpdate
        Error::NoSpace => 7021,                 // NoSpace
    }
}

pub(crate) fn raw_meta_value(meta: &ChunkMeta) -> ffi::RawMeta {
    ffi::RawMeta {
        pos: meta.pos.0,
        chain_ver: meta.chain_ver,
        chunk_ver: meta.chunk_ver,
        len: meta.len,
        checksum: meta.checksum,
        timestamp: meta.timestamp,
        last_request_id: meta.last_request_id,
        last_client_low: meta.last_client_low,
        last_client_high: meta.last_client_high,
    }
}

fn immutable_read_error(code: u16, error: impl Into<String>) -> ffi::ImmutableReadResult {
    ffi::ImmutableReadResult {
        error_code: code,
        error: error.into(),
        meta: ffi::RawMeta::default(),
        data: Vec::new(),
    }
}

fn create(path: &str, create: bool, prefix_len: usize, error: Pin<&mut CxxString>) -> *mut Engine {
    let config = EngineConfig {
        path: PathBuf::from(path),
        create,
        prefix_len,
    };
    match Engine::open(&config) {
        Ok(engine) => Box::into_raw(Box::new(engine)),
        Err(e) => {
            error.push_str(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

fn release(_engine: Box<Engine>) {}

#[allow(dead_code)]
struct LogGuard(tracing_appender::non_blocking::WorkerGuard);

fn init_log(path: &str, error: Pin<&mut CxxString>) -> *mut LogGuard {
    match rolling_file::BasicRollingFileAppender::new(
        path,
        rolling_file::RollingConditionBasic::new().max_size(Size::mebibyte(500).into()),
        20,
    ) {
        Ok(file_appender) => {
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .with_writer(non_blocking)
                .with_ansi(false)
                .init();
            Box::into_raw(Box::new(LogGuard(guard)))
        }
        Err(e) => {
            error.push_str(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

impl Chunk {
    fn raw_meta(&self) -> &ffi::RawMeta {
        unsafe { std::mem::transmute(self.meta()) }
    }

    fn raw_etag(&self) -> &[u8] {
        &self.meta().etag
    }

    fn uncommitted(&self) -> bool {
        self.meta().uncommitted
    }
}

impl WritingChunk {
    fn raw_meta(&self) -> &ffi::RawMeta {
        self.chunk.raw_meta()
    }

    fn raw_etag(&self) -> &[u8] {
        self.chunk.raw_etag()
    }

    fn uncommitted(&self) -> bool {
        self.chunk.uncommitted()
    }

    fn raw_chunk(&self) -> *const Chunk {
        &self.chunk
    }

    fn set_chain_ver(&mut self, chain_ver: u32) {
        self.chunk.set_chain_ver(chain_ver);
    }
}

pub(crate) fn sample_metrics(metrics: &crate::Metrics) -> ffi::Metrics {
    let copy_on_write_times = metrics.copy_on_write_times.swap(0, Ordering::AcqRel);
    let copy_on_write_latency = metrics.copy_on_write_latency.swap(0, Ordering::AcqRel);
    let copy_on_write_read_times = metrics.copy_on_write_read_times.swap(0, Ordering::AcqRel);
    let copy_on_write_read_latency = metrics.copy_on_write_read_latency.swap(0, Ordering::AcqRel);
    let allocate_total_latency = metrics.allocate_latency.swap(0, Ordering::AcqRel);
    let allocate_total_times = metrics.allocate_times.swap(0, Ordering::AcqRel);
    let pwrite_total_latency = metrics.pwrite_latency.swap(0, Ordering::AcqRel);
    let pwrite_total_times = metrics.pwrite_times.swap(0, Ordering::AcqRel);
    ffi::Metrics {
        copy_on_write_times,
        copy_on_write_latency: copy_on_write_latency / std::cmp::max(1, copy_on_write_times),
        copy_on_write_read_bytes: metrics.copy_on_write_read_bytes.swap(0, Ordering::AcqRel),
        copy_on_write_read_times,
        copy_on_write_read_latency: copy_on_write_read_latency
            / std::cmp::max(1, copy_on_write_read_times),
        checksum_reuse: metrics.checksum_reuse.swap(0, Ordering::AcqRel),
        checksum_combine: metrics.checksum_combine.swap(0, Ordering::AcqRel),
        checksum_recalculate: metrics.checksum_recalculate.swap(0, Ordering::AcqRel),
        safe_write_direct_append: metrics.safe_write_direct_append.swap(0, Ordering::AcqRel),
        safe_write_indirect_append: metrics.safe_write_indirect_append.swap(0, Ordering::AcqRel),
        safe_write_truncate_shorten: metrics
            .safe_write_truncate_shorten
            .swap(0, Ordering::AcqRel),
        safe_write_truncate_extend: metrics.safe_write_truncate_extend.swap(0, Ordering::AcqRel),
        safe_write_read_tail_times: metrics.safe_write_read_tail_times.swap(0, Ordering::AcqRel),
        safe_write_read_tail_bytes: metrics.safe_write_read_tail_bytes.swap(0, Ordering::AcqRel),
        allocate_latency: allocate_total_latency / std::cmp::max(1, allocate_total_times),
        allocate_times: allocate_total_times,
        pwrite_latency: pwrite_total_latency / std::cmp::max(1, pwrite_total_times),
        pwrite_times: pwrite_total_times,
    }
}

impl Engine {
    fn raw_used_size(&self) -> ffi::RawUsedSize {
        unsafe { std::mem::transmute(self.used_size()) }
    }

    fn get_raw_chunk(&self, chunk_id: &[u8], error: Pin<&mut CxxString>) -> *const Chunk {
        match self.get(chunk_id) {
            Ok(None) => {
                error.clear();
                std::ptr::null()
            }
            Ok(Some(c)) => {
                error.clear();
                Arc::into_raw(c)
            }
            Err(e) => {
                error.push_str(&e.to_string());
                std::ptr::null()
            }
        }
    }

    fn get_raw_chunks(&self, reqs: &mut [GetReq], error: Pin<&mut CxxString>) {
        let chunk_ids = reqs
            .iter()
            .map(|r| Bytes::from(r.chunk_id))
            .collect::<BTreeSet<_>>();
        match self.batch_get(&chunk_ids) {
            Ok(chunks) => {
                for req in reqs {
                    match chunks.get(req.chunk_id) {
                        Some(c) => req.chunk_ptr = Arc::into_raw(c.clone()),
                        None => req.chunk_ptr = std::ptr::null_mut(),
                    }
                }
                error.clear();
            }
            Err(e) => {
                error.push_str(&e.to_string());
            }
        }
    }

    unsafe fn release_raw_chunk(&self, chunk: *const Chunk) {
        if !chunk.is_null() {
            Arc::from_raw(chunk);
        }
    }

    unsafe fn release_writing_chunk(&self, chunk: *mut WritingChunk) {
        if !chunk.is_null() {
            let _ = Box::from_raw(chunk);
        }
    }

    fn create_immutable_raw_chunk(
        &self,
        chunk_id: &[u8],
        data: &[u8],
        checksum: u32,
        sync: bool,
        context: &ffi::RawImmutableContext,
        desired_etag: &[u8],
    ) -> ffi::ImmutableCreateResult {
        let context = ImmutableCreateContext {
            chain_ver: context.chain_ver,
            last_request_id: context.last_request_id,
            last_client_low: context.last_client_low,
            last_client_high: context.last_client_high,
            desired_etag,
        };
        match self.create_immutable_with_context(chunk_id, data, checksum, sync, &context) {
            Ok(chunk) => {
                let meta = chunk.meta();
                ffi::ImmutableCreateResult {
                    error_code: 0,
                    error: String::new(),
                    meta: raw_meta_value(meta),
                    etag: meta.etag.to_vec(),
                }
            }
            Err(error) => ffi::ImmutableCreateResult {
                error_code: storage_error_code(&error),
                error: error.to_string(),
                meta: ffi::RawMeta::default(),
                etag: Vec::new(),
            },
        }
    }

    fn read_immutable_raw_chunk(
        &self,
        chunk_id: &[u8],
        expected_length: u32,
        expected_checksum: u32,
        expected_etag: &[u8],
    ) -> ffi::ImmutableReadResult {
        // This validates current contents only. It does not re-establish a
        // durable seal acknowledgement after an earlier synchronization error.
        // Bound all caller-controlled lengths before fetching metadata or
        // allocating the payload. ETag is an identity token, not a digest.
        if chunk_id.is_empty() || chunk_id.len() < self.prefix_len {
            return immutable_read_error(3, "immutable chunk id is empty or shorter than prefix");
        }
        if Size::from(expected_length) > CHUNK_SIZE_ULTRA {
            return immutable_read_error(3, "immutable read length exceeds chunk limit");
        }
        if expected_etag.is_empty() || expected_etag.len() > MAX_IMMUTABLE_ETAG_LEN {
            return immutable_read_error(3, "immutable read etag must contain 1..=64 bytes");
        }

        // Keep this exact allocation referenced until the complete read and
        // checksum validation finish, even if the key's cache entry changes.
        let chunk = match self.get_immutable(chunk_id) {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return immutable_read_error(4001, "immutable chunk not found"),
            Err(error) => return immutable_read_error(4002, error.to_string()),
        };
        let meta = chunk.meta();
        if meta.uncommitted {
            return immutable_read_error(4086, "immutable fragment is not sealed");
        }
        if meta.len != expected_length {
            return immutable_read_error(4015, "immutable fragment length mismatch");
        }
        if meta.etag.as_slice() != expected_etag {
            return immutable_read_error(4083, "immutable fragment etag mismatch");
        }
        if meta.checksum != expected_checksum {
            return immutable_read_error(4080, "immutable fragment metadata checksum mismatch");
        }

        let mut data = Vec::new();
        if let Err(error) = data.try_reserve_exact(expected_length as usize) {
            return immutable_read_error(26, format!("allocate immutable read buffer: {error}"));
        }
        data.resize(expected_length as usize, 0);
        if let Err(error) = chunk.pread(&mut data, 0) {
            return immutable_read_error(4010, error.to_string());
        }
        if crc32c::crc32c(&data) != expected_checksum {
            return immutable_read_error(4080, "immutable fragment data checksum mismatch");
        }
        ffi::ImmutableReadResult {
            error_code: 0,
            error: String::new(),
            meta: raw_meta_value(meta),
            data,
        }
    }

    fn reconcile_immutable_raw_chunk(
        &self,
        chunk_id: &[u8],
        expected_length: u32,
        expected_checksum: u32,
        expected_etag: &[u8],
    ) -> ffi::ImmutableReconcileResult {
        // Only malformed inputs are a definite request rejection. A failure
        // to establish a new durable confirmation never proves absence.
        if chunk_id.is_empty()
            || chunk_id.len() < self.prefix_len
            || Size::from(expected_length) > CHUNK_SIZE_ULTRA
            || expected_etag.is_empty()
            || expected_etag.len() > MAX_IMMUTABLE_ETAG_LEN
        {
            return ffi::ImmutableReconcileResult {
                error_code: 3,
                error: "invalid immutable reconciliation key, length or etag".into(),
                meta: ffi::RawMeta::default(),
                etag: Vec::new(),
            };
        }
        match self.reconcile_immutable(chunk_id, expected_length, expected_checksum, expected_etag)
        {
            Ok(chunk) => ffi::ImmutableReconcileResult {
                error_code: 0,
                error: String::new(),
                meta: raw_meta_value(chunk.meta()),
                etag: chunk.meta().etag.to_vec(),
            },
            Err(error) => ffi::ImmutableReconcileResult {
                error_code: 4085,
                error: format!(
                    "immutable seal outcome remains unknown; retain allocation: {error}"
                ),
                meta: ffi::RawMeta::default(),
                etag: Vec::new(),
            },
        }
    }

    fn update_raw_chunk(
        &self,
        chunk_id: &[u8],
        mut req: Pin<&mut ffi::UpdateReq>,
        error: Pin<&mut CxxString>,
    ) -> *mut WritingChunk {
        match self.update_chunk(chunk_id, &mut req) {
            Ok(chunk) => Box::into_raw(Box::new(chunk)),
            Err(e) => {
                error.push_str(&e.to_string());
                req.out_error_code = storage_error_code(&e);
                std::ptr::null_mut()
            }
        }
    }

    unsafe fn commit_raw_chunk(
        &self,
        new_chunk: *mut WritingChunk,
        sync: bool,
        error: Pin<&mut CxxString>,
    ) {
        let new_chunk = Box::from_raw(new_chunk);
        match self.commit_chunk(*new_chunk, sync) {
            Ok(_) => (),
            Err(e) => error.push_str(&e.to_string()),
        }
    }

    unsafe fn commit_raw_chunks(
        &self,
        reqs: &[*mut WritingChunk],
        sync: bool,
        error: Pin<&mut CxxString>,
    ) {
        let chunks = reqs.iter().map(|c| *Box::from_raw(*c)).collect::<Vec<_>>();
        match self.commit_chunks(chunks, sync) {
            Ok(_) => (),
            Err(e) => error.push_str(&e.to_string()),
        }
    }

    fn query_raw_chunks(
        &self,
        begin: &[u8],
        end: &[u8],
        max_count: u64,
        error: Pin<&mut CxxString>,
    ) -> Box<RawChunks> {
        match self.query_chunks(begin, end, max_count) {
            Ok(vec) => Box::new(RawChunks { vec }),
            Err(e) => {
                error.push_str(&e.to_string());
                Default::default()
            }
        }
    }

    fn query_all_raw_chunks(&self, prefix: &[u8], error: Pin<&mut CxxString>) -> Box<RawChunks> {
        match self.query_all_chunks(prefix) {
            Ok(vec) => Box::new(RawChunks { vec }),
            Err(e) => {
                error.push_str(&e.to_string());
                Default::default()
            }
        }
    }

    fn query_raw_chunks_by_timestamp(
        &self,
        prefix: &[u8],
        begin: u64,
        end: u64,
        max_count: u64,
        error: Pin<&mut CxxString>,
    ) -> Box<RawChunks> {
        match self.query_chunks_by_timestamp(prefix, begin, end, max_count) {
            Ok(vec) => Box::new(RawChunks { vec }),
            Err(e) => {
                error.push_str(&e.to_string());
                Default::default()
            }
        }
    }

    fn raw_batch_remove(
        &self,
        begin: &[u8],
        end: &[u8],
        max_count: u64,
        error: Pin<&mut CxxString>,
    ) -> u64 {
        match self.batch_remove(begin, end, max_count) {
            Ok(cnt) => cnt,
            Err(e) => {
                error.push_str(&e.to_string());
                0
            }
        }
    }

    fn query_raw_used_size(&self, prefix: &[u8], error: Pin<&mut CxxString>) -> u64 {
        match self.meta_store.query_used_size(prefix) {
            Ok(size) => size,
            Err(e) => {
                error.push_str(&e.to_string());
                0
            }
        }
    }

    fn get_metrics(&self) -> ffi::Metrics {
        sample_metrics(self.metrics.as_ref())
    }

    fn query_uncommitted_raw_chunks(
        &self,
        prefix: &[u8],
        error: Pin<&mut CxxString>,
    ) -> Box<RawChunks> {
        match self.query_uncommitted_chunks(prefix) {
            Ok(chunks) => Box::new(RawChunks { vec: chunks }),
            Err(e) => {
                error.push_str(&e.to_string());
                Default::default()
            }
        }
    }

    fn handle_uncommitted_raw_chunks(
        &self,
        prefix: &[u8],
        chain_ver: u32,
        error: Pin<&mut CxxString>,
    ) -> Box<RawChunks> {
        match self.handle_uncommitted_chunks(prefix, chain_ver) {
            Ok(chunks) => Box::new(RawChunks { vec: chunks }),
            Err(e) => {
                error.push_str(&e.to_string());
                Box::default()
            }
        }
    }
}

#[derive(Default)]
struct RawChunks {
    vec: Vec<(Bytes, ChunkMeta)>,
}

impl RawChunks {
    fn len(&self) -> usize {
        self.vec.len()
    }

    fn chunk_id(&self, pos: usize) -> &[u8] {
        self.vec[pos].0.as_ref()
    }

    fn chunk_meta(&self, pos: usize) -> &ffi::RawMeta {
        unsafe { std::mem::transmute(&self.vec[pos].1) }
    }

    fn chunk_etag(&self, pos: usize) -> &[u8] {
        &self.vec[pos].1.etag
    }

    fn chunk_uncommitted(&self, pos: usize) -> bool {
        self.vec[pos].1.uncommitted
    }
}

#[::cxx::bridge(namespace = "hf3fs::chunk_engine")]
pub mod ffi {
    // Process-local scope ABI, deliberately unrelated to capability v1 wire.
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawEcScopeTarget {
        engine: [u8; 16],
        incarnation: [u8; 16],
        chain: u32,
        target: u64,
    }
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawEcScopeBinding {
        target: RawEcScopeTarget,
        object: [u8; 16],
        kind: u8,
        scope: [u8; 16],
        owner_uid: u32,
        client_namespace: [u8; 16],
    }
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawEcScopeRevocation {
        binding: RawEcScopeBinding,
        id: [u8; 16],
        endpoint_set_digest: [u8; 32],
    }
    struct RawEcScopeStatus {
        error_code: u16,
        error: String,
    }
    struct RawEcScopeOpenResult {
        status: RawEcScopeStatus,
        handle: Box<EcScopeHandle>,
    }
    struct RawEcTargetResult {
        status: RawEcScopeStatus,
        target: RawEcScopeTarget,
    }
    struct RawEcTicketResult {
        status: RawEcScopeStatus,
        ticket: Box<EcScopeTicketHandle>,
    }
    struct RawEcDrainResult {
        status: RawEcScopeStatus,
        durable: bool,
        inflight: u64,
        drained: bool,
    }
    extern "Rust" {
        type EcScopeHandle;
        type EcScopeTicketHandle;
        fn ec_scope_open(engine: &Engine) -> RawEcScopeOpenResult;
        fn ec_scope_register_target(
            handle: &EcScopeHandle,
            chain: u32,
            target: u64,
        ) -> RawEcTargetResult;
        fn ec_scope_load_target(
            handle: &EcScopeHandle,
            chain: u32,
            target: u64,
        ) -> RawEcTargetResult;
        fn ec_scope_prepare(
            handle: &EcScopeHandle,
            binding: &RawEcScopeBinding,
        ) -> RawEcScopeStatus;
        fn ec_scope_prepare_wait(
            handle: &EcScopeHandle,
            binding: &RawEcScopeBinding,
            wait_millis: u32,
        ) -> RawEcScopeStatus;
        fn ec_scope_try_admit(
            handle: &EcScopeHandle,
            binding: &RawEcScopeBinding,
        ) -> RawEcTicketResult;
        fn ec_scope_ticket_check(ticket: &EcScopeTicketHandle) -> RawEcScopeStatus;
        fn ec_scope_revoke(
            handle: &EcScopeHandle,
            revocation: &RawEcScopeRevocation,
        ) -> RawEcDrainResult;
        fn ec_scope_drain_status(
            handle: &EcScopeHandle,
            revocation: &RawEcScopeRevocation,
        ) -> RawEcDrainResult;
    }

    #[derive(Clone, Copy, Debug)]
    struct EcCodecFormat {
        codec_id: u16,
        matrix_version: u16,
        data_shards: u16,
        parity_shards: u16,
        field_polynomial: u16,
    }

    #[derive(Clone, Copy)]
    struct EcCodecInput<'a> {
        index: u16,
        data: &'a [u8],
    }

    struct EcCodecShard {
        index: u16,
        data: Vec<u8>,
    }

    // Failure always has an empty output. These arithmetic results are neither
    // authenticated fragment identities nor durable seal acknowledgements.
    struct EcCodecResult {
        error_code: u16,
        error: String,
        shards: Vec<EcCodecShard>,
    }

    extern "Rust" {
        fn ec_codec_backend() -> &'static str;
        fn ec_codec_encode(format: &EcCodecFormat, data: &[u8], shard_bytes: u32) -> EcCodecResult;
        fn ec_codec_verify(
            format: &EcCodecFormat,
            shards: &[EcCodecInput],
            logical_length: u64,
            shard_bytes: u32,
        ) -> EcCodecResult;
        fn ec_codec_recover(
            format: &EcCodecFormat,
            shards: &[EcCodecInput],
            logical_length: u64,
            shard_bytes: u32,
        ) -> EcCodecResult;
        fn ec_codec_contribute(
            format: &EcCodecFormat,
            healthy: &[u16],
            targets: &[u16],
            helper: u16,
            data: &[u8],
        ) -> EcCodecResult;
    }

    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct UpdateReq {
        without_checksum: bool,
        is_truncate: bool,
        is_remove: bool,
        is_syncing: bool,
        update_ver: u32,
        chain_ver: u32,
        checksum: u32,
        length: u32,
        offset: u32,
        // SAFETY: This u64 field represents a raw pointer to data of size `length`.
        // The pointer must remain valid for the entire duration of update_chunk().
        // Currently safe because data is consumed synchronously within the function.
        data: u64,
        last_request_id: u64,
        last_client_low: u64,
        last_client_high: u64,
        expected_tag: &'static [u8],
        desired_tag: &'static [u8],
        create_new: bool,

        out_non_existent: bool,
        out_error_code: u16,
        out_commit_ver: u32,
        out_chain_ver: u32,
        out_checksum: u32,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct GetReq<'a> {
        chunk_id: &'a [u8],
        chunk_ptr: *const Chunk,
    }

    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawEcStageBinding {
        operation: [u8; 16],
        length: u32,
        checksum: u32,
    }
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawEcStageLimits {
        max_cached_records: u32,
        max_active: u32,
        max_concurrent_io: u32,
    }
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawEcStageState {
        operation: [u8; 16],
        state: u8,
        prefix_bytes: u32,
        pending_block: bool,
        revision: u64,
        needs_reconcile: bool,
    }
    // Process-local exact-GC ABI; these fields do not grant authorization.
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawEcStageGcClaim {
        claim_id: [u8; 16],
        claim_digest: [u8; 32],
        eligibility_digest: [u8; 32],
        target: RawEcScopeTarget,
        binding: RawEcStageBinding,
        writer: [u8; 16],
    }
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawEcStageGcReceipt {
        claim_id: [u8; 16],
        ledger_sha256: [u8; 32],
        terminal_revision: u64,
    }
    struct RawEcStageGcResult {
        status: RawEcScopeStatus,
        receipt: RawEcStageGcReceipt,
    }
    struct RawEcStageFormatResult {
        status: RawEcScopeStatus,
        disk_format: u16,
    }
    struct RawEcStageOpenResult {
        status: RawEcScopeStatus,
        handle: Box<EcStageHandle>,
    }
    struct RawEcStageResult {
        status: RawEcScopeStatus,
        state: RawEcStageState,
    }
    struct RawEcStageReadResult {
        status: RawEcScopeStatus,
        data: Vec<u8>,
    }
    struct RawEcStageUsedResult {
        status: RawEcScopeStatus,
        committed: u64,
    }
    struct RawEcStagePhysicalSizeResult {
        status: RawEcScopeStatus,
        value: RawUsedSize,
    }
    #[derive(Default, Clone, Copy)]
    struct RawEcStageTrimLimits {
        max_groups: u32,
        max_bytes: u64,
        keep_empty_groups: u32,
    }
    // Counts are per-call, never a statfs result. An error retains all known
    // progress; complete=false means an unexpected boundary failure occurred.
    #[derive(Default, Clone, Copy)]
    struct RawEcStageTrimReport {
        attempted_groups: u32,
        charged_bytes: u64,
        punch_confirmed_groups: u32,
        punch_confirmed_bytes: u64,
        withdrawn_preallocation_bytes: u64,
        unconfirmed_extent_bytes: u64,
        reconciled_groups: u32,
        quarantined_groups: u32,
        busy_classes: u32,
        oversized_classes: u32,
        unsupported_groups: u32,
        os_errno: i32,
        complete: bool,
    }
    struct RawEcStageTrimResult {
        status: RawEcScopeStatus,
        report: RawEcStageTrimReport,
    }
    struct RawEcStageMetricsResult {
        status: RawEcScopeStatus,
        value: Metrics,
    }
    extern "Rust" {
        type EcStageHandle;
        fn stage_open(
            path: &str,
            create: bool,
            prefix_len: u32,
            limits: &RawEcStageLimits,
        ) -> RawEcStageOpenResult;
        // Reuse the existing EcStageHandle type; do not declare it again.
        fn stage_open_gc(
            path: &str,
            create: bool,
            prefix_len: u32,
            limits: &RawEcStageLimits,
        ) -> RawEcStageOpenResult;
        fn stage_gc_collect(
            handle: &EcStageHandle,
            key: &[u8],
            claim: &RawEcStageGcClaim,
        ) -> RawEcStageGcResult;
        fn stage_gc_query(
            handle: &EcStageHandle,
            key: &[u8],
            claim: &RawEcStageGcClaim,
        ) -> RawEcStageGcResult;
        fn stage_actual_disk_format(handle: &EcStageHandle) -> RawEcStageFormatResult;
        fn stage_scope_open(handle: &EcStageHandle) -> RawEcScopeOpenResult;
        fn stage_begin(
            handle: &EcStageHandle,
            key: &[u8],
            binding: &RawEcStageBinding,
            writer: &[u8; 16],
        ) -> RawEcStageResult;
        fn stage_append(
            handle: &EcStageHandle,
            key: &[u8],
            binding: &RawEcStageBinding,
            index: u8,
            bytes: &[u8],
        ) -> RawEcStageResult;
        fn stage_query(
            handle: &EcStageHandle,
            key: &[u8],
            binding: &RawEcStageBinding,
        ) -> RawEcStageResult;
        fn stage_reconcile(
            handle: &EcStageHandle,
            key: &[u8],
            binding: &RawEcStageBinding,
        ) -> RawEcStageResult;
        fn stage_seal(
            handle: &EcStageHandle,
            key: &[u8],
            binding: &RawEcStageBinding,
        ) -> ImmutableReconcileResult;
        fn stage_read_block(
            handle: &EcStageHandle,
            key: &[u8],
            binding: &RawEcStageBinding,
            index: u8,
        ) -> RawEcStageReadResult;
        fn stage_used_size(handle: &EcStageHandle, prefix: &[u8]) -> RawEcStageUsedResult;
        fn stage_physical_used_size(handle: &EcStageHandle) -> RawEcStagePhysicalSizeResult;
        fn stage_trim_empty_groups(handle: &EcStageHandle,
                                   limits: &RawEcStageTrimLimits) -> RawEcStageTrimResult;
        fn stage_sample_metrics(handle: &EcStageHandle) -> RawEcStageMetricsResult;
        fn stage_set_allow_to_allocate(handle: &EcStageHandle, allow: bool) -> RawEcScopeStatus;
    }

    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawMeta {
        pos: u64,
        chain_ver: u32,
        chunk_ver: u32,
        len: u32,
        checksum: u32,
        timestamp: u64,
        last_request_id: u64,
        last_client_low: u64,
        last_client_high: u64,
    }

    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawImmutableContext {
        chain_ver: u32,
        last_request_id: u64,
        last_client_low: u64,
        last_client_high: u64,
    }

    // Metadata and tag are meaningful only when error_code is zero. An error
    // does not establish absence or that no data/metadata reached storage.
    struct ImmutableCreateResult {
        error_code: u16,
        error: String,
        meta: RawMeta,
        etag: Vec<u8>,
    }

    // Failed reads never return partial data or usable metadata.
    struct ImmutableReadResult {
        error_code: u16,
        error: String,
        meta: RawMeta,
        data: Vec<u8>,
    }

    // Success confirms explicit data and metadata barriers for the existing
    // immutable identity. Failure does not yield a publishable seal receipt.
    struct ImmutableReconcileResult {
        error_code: u16,
        error: String,
        meta: RawMeta,
        etag: Vec<u8>,
    }

    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct RawUsedSize {
        allocated_size: u64,
        reserved_size: u64,
        position_count: u64,
        position_rc: u64,
    }

    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    struct FdAndOffset {
        fd: i32,
        offset: u64,
    }

    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Metrics {
        pub copy_on_write_times: u64,
        pub copy_on_write_latency: u64,
        pub copy_on_write_read_bytes: u64,
        pub copy_on_write_read_times: u64,
        pub copy_on_write_read_latency: u64,

        pub checksum_reuse: u64,
        pub checksum_combine: u64,
        pub checksum_recalculate: u64,

        pub safe_write_direct_append: u64,
        pub safe_write_indirect_append: u64,
        pub safe_write_truncate_shorten: u64,
        pub safe_write_truncate_extend: u64,
        pub safe_write_read_tail_times: u64,
        pub safe_write_read_tail_bytes: u64,

        pub allocate_times: u64,
        pub allocate_latency: u64,
        pub pwrite_times: u64,
        pub pwrite_latency: u64,
    }

    extern "Rust" {
        type Engine;
        fn create(
            path: &str,
            create: bool,
            prefix_len: usize,
            error: Pin<&mut CxxString>,
        ) -> *mut Engine;
        fn release(engine: Box<Engine>);

        fn raw_used_size(&self) -> RawUsedSize;
        fn allocate_groups(&self, min_remain: usize, max_remain: usize, batch_size: usize)
            -> usize;
        fn allocate_ultra_groups(
            &self,
            min_remain: usize,
            max_remain: usize,
            batch_size: usize,
        ) -> usize;
        fn compact_groups(&self, max_reserved: u64) -> usize;

        fn set_allow_to_allocate(&self, val: bool);
        unsafe fn speed_up_quit(&self);

        fn get_raw_chunk(&self, chunk_id: &[u8], error: Pin<&mut CxxString>) -> *const Chunk;
        fn get_raw_chunks(&self, reqs: &mut [GetReq], error: Pin<&mut CxxString>);
        unsafe fn release_raw_chunk(&self, chunk: *const Chunk);
        unsafe fn release_writing_chunk(&self, chunk: *mut WritingChunk);

        fn create_immutable_raw_chunk(
            &self,
            chunk_id: &[u8],
            data: &[u8],
            checksum: u32,
            sync: bool,
            context: &RawImmutableContext,
            desired_etag: &[u8],
        ) -> ImmutableCreateResult;

        fn read_immutable_raw_chunk(
            &self,
            chunk_id: &[u8],
            expected_length: u32,
            expected_checksum: u32,
            expected_etag: &[u8],
        ) -> ImmutableReadResult;

        fn reconcile_immutable_raw_chunk(
            &self,
            chunk_id: &[u8],
            expected_length: u32,
            expected_checksum: u32,
            expected_etag: &[u8],
        ) -> ImmutableReconcileResult;

        fn update_raw_chunk(
            &self,
            chunk_id: &[u8],
            req: Pin<&mut UpdateReq>,
            error: Pin<&mut CxxString>,
        ) -> *mut WritingChunk;

        unsafe fn commit_raw_chunk(
            &self,
            new_chunk: *mut WritingChunk,
            sync: bool,
            error: Pin<&mut CxxString>,
        );

        unsafe fn commit_raw_chunks(
            &self,
            reqs: &[*mut WritingChunk],
            sync: bool,
            error: Pin<&mut CxxString>,
        );

        fn query_raw_chunks(
            &self,
            begin: &[u8],
            end: &[u8],
            max_count: u64,
            error: Pin<&mut CxxString>,
        ) -> Box<RawChunks>;

        fn query_all_raw_chunks(&self, prefix: &[u8], error: Pin<&mut CxxString>)
            -> Box<RawChunks>;

        fn query_raw_chunks_by_timestamp(
            &self,
            prefix: &[u8],
            begin: u64,
            end: u64,
            max_count: u64,
            error: Pin<&mut CxxString>,
        ) -> Box<RawChunks>;

        fn raw_batch_remove(
            &self,
            begin: &[u8],
            end: &[u8],
            max_count: u64,
            error: Pin<&mut CxxString>,
        ) -> u64;

        fn query_raw_used_size(&self, prefix: &[u8], error: Pin<&mut CxxString>) -> u64;

        fn get_metrics(&self) -> Metrics;

        fn query_uncommitted_raw_chunks(
            &self,
            prefix: &[u8],
            error: Pin<&mut CxxString>,
        ) -> Box<RawChunks>;

        fn handle_uncommitted_raw_chunks(
            &self,
            prefix: &[u8],
            chain_ver: u32,
            error: Pin<&mut CxxString>,
        ) -> Box<RawChunks>;
    }

    extern "Rust" {
        type LogGuard;
        fn init_log(path: &str, error: Pin<&mut CxxString>) -> *mut LogGuard;
    }

    extern "Rust" {
        type Chunk;
        fn raw_meta(&self) -> &RawMeta;
        fn raw_etag(&self) -> &[u8];
        fn uncommitted(&self) -> bool;
        fn fd_and_offset(&self) -> FdAndOffset;
    }

    extern "Rust" {
        type WritingChunk;
        fn raw_meta(&self) -> &RawMeta;
        fn raw_etag(&self) -> &[u8];
        fn uncommitted(&self) -> bool;
        fn raw_chunk(&self) -> *const Chunk;
        fn set_chain_ver(&mut self, chain_ver: u32);
    }

    extern "Rust" {
        type RawChunks;
        fn len(&self) -> usize;
        fn chunk_id(&self, pos: usize) -> &[u8];
        fn chunk_meta(&self, pos: usize) -> &RawMeta;
        fn chunk_etag(&self, pos: usize) -> &[u8];
        fn chunk_uncommitted(&self, pos: usize) -> bool;
    }
}

static_assertions::const_assert_eq!(
    std::mem::align_of::<ChunkMeta>(),
    std::mem::align_of::<ffi::RawMeta>()
);
static_assertions::const_assert_eq!(
    std::mem::size_of::<UsedSize>(),
    std::mem::size_of::<ffi::RawUsedSize>()
);
static_assertions::const_assert_eq!(
    std::mem::align_of::<UsedSize>(),
    std::mem::align_of::<ffi::RawUsedSize>()
);
static_assertions::const_assert_eq!(
    std::mem::size_of::<Metrics>(),
    std::mem::size_of::<ffi::Metrics>()
);
static_assertions::const_assert_eq!(
    std::mem::align_of::<Metrics>(),
    std::mem::align_of::<ffi::Metrics>()
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_immutable_raw_owned_result() {
        let dir = tempfile::tempdir().unwrap();
        let result = {
            let engine = Engine::open(&EngineConfig {
                path: dir.path().into(),
                create: true,
                prefix_len: 2,
            })
            .unwrap();
            let data = b"value returned across the CXX boundary";
            let tag = vec![0, 255, 1, 254, 2];
            let context = ffi::RawImmutableContext {
                chain_ver: 23,
                last_request_id: 0x1234_5678_9abc_def0,
                last_client_low: 0x0123_4567_89ab_cdef,
                last_client_high: 0xfedc_ba98_7654_3210,
            };
            let result = engine.create_immutable_raw_chunk(
                b"ec-raw",
                data,
                crc32c::crc32c(data),
                true,
                &context,
                &tag,
            );
            assert_eq!(result.error_code, 0);
            assert!(result.error.is_empty());
            let chunk = engine.get(b"ec-raw").unwrap().unwrap();
            assert_eq!(result.meta, *chunk.raw_meta());
            assert_eq!(result.meta.chain_ver, context.chain_ver);
            assert_eq!(result.meta.last_request_id, context.last_request_id);
            assert_eq!(result.meta.last_client_low, context.last_client_low);
            assert_eq!(result.meta.last_client_high, context.last_client_high);
            assert_eq!(result.meta.chunk_ver, 1);
            assert_eq!(result.meta.len, data.len() as u32);
            assert_eq!(result.meta.checksum, crc32c::crc32c(data));
            assert_eq!(result.etag, tag);
            result
        };
        // The result owns all its fields and outlives both Engine and inputs.
        assert_eq!(result.meta.chain_ver, 23);
        assert_eq!(result.etag, [0, 255, 1, 254, 2]);
        assert_eq!(result.error_code, 0);
    }

    #[test]
    fn test_create_immutable_raw_error_results() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let context = ffi::RawImmutableContext::default();
        let key = b"ec-raw-errors";
        let first = engine.create_immutable_raw_chunk(key, b"", 0, true, &context, b"first");
        assert_eq!(first.error_code, 0);
        let oversized = vec![0; MAX_IMMUTABLE_ETAG_LEN + 1];
        let errors = [
            (
                engine.create_immutable_raw_chunk(b"", b"", 0, true, &context, b""),
                3,
            ),
            (
                engine.create_immutable_raw_chunk(b"ec-tag", b"", 0, true, &context, &oversized),
                3,
            ),
            (
                engine.create_immutable_raw_chunk(b"ec-crc", b"", 1, true, &context, b""),
                4080,
            ),
            (
                engine.create_immutable_raw_chunk(key, b"", 0, true, &context, b"second"),
                4084,
            ),
        ];
        for (result, code) in errors {
            assert_eq!(result.error_code, code);
            assert!(!result.error.is_empty());
            assert_eq!(result.meta, ffi::RawMeta::default());
            assert!(result.etag.is_empty());
        }
        let chunk = engine.get(key).unwrap().unwrap();
        assert_eq!(chunk.meta().etag.as_slice(), b"first");
        assert_eq!(engine.query_all_chunks(b"ec").unwrap().len(), 1);
    }

    fn assert_read_error(result: ffi::ImmutableReadResult, code: u16) {
        assert_eq!(result.error_code, code);
        assert!(!result.error.is_empty());
        assert_eq!(result.meta, ffi::RawMeta::default());
        assert!(result.data.is_empty());
    }

    #[test]
    fn test_read_immutable_raw_committed_metadata_without_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        };
        let key = b"ec-committed-without-confirmation";
        let tag = b"same-allocation-and-operation";
        let data: Vec<_> = (0..4097).map(|i| (i * 29 + 7) as u8).collect();
        let checksum = crc32c::crc32c(&data);
        let (owned, accounted) = {
            let engine = Engine::open(&config).unwrap();
            let mut request = UpdateReq {
                data: data.as_ptr() as u64,
                length: data.len() as u32,
                checksum,
                create_new: true,
                desired_tag: tag,
                ..Default::default()
            };
            let pending = engine.update_chunk(key, &mut request).unwrap();
            let mut committed = pending.chunk.clone();
            committed.set_committed();
            let meta = committed.meta().clone();
            let clusters = &engine.allocators.select_by_pos(meta.pos).unwrap().clusters;
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(clusters.path.join(format!("{:02X}", meta.pos.cluster())))
                .unwrap()
                .sync_data()
                .unwrap();
            // Real final metadata commit, followed by the exact caller state
            // left when its confirmation is lost: no cache insertion and no
            // WritingChunk::commit_succ. This constructs that post-state; it
            // does not inject an actual RocksDB error or simulate power loss.
            engine.meta_store.add_chunk(key, &meta, true).unwrap();
            drop(committed);
            drop(pending);
            assert!(engine
                .meta_cache
                .entry_by_ref(key.as_slice())
                .get()
                .is_none());
            assert_eq!(engine.meta_store.get_chunk_meta(key).unwrap(), Some(meta));
            let pending = engine.query_uncommitted_chunks(b"ec").unwrap();
            assert_eq!(pending.len(), 1);
            let before = engine.used_size();
            assert_eq!(before.position_count, 1);
            assert_eq!(before.position_rc, 1);
            let accounted = engine.meta_store.query_used_size(b"ec").unwrap();

            // Exercise the actual owned CXX implementation before reconcile.
            // The old lookup asserts first_ref with an already held position.
            // Do not catch this panic: the pre-fix run belongs in its own process.
            let read = engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag);
            assert_eq!(read.error_code, 0, "{}", read.error);
            assert_eq!(read.data, data);
            let after = engine.used_size();
            assert_eq!(after.allocated_size, before.allocated_size);
            assert_eq!(after.reserved_size, before.reserved_size);
            assert_eq!(after.position_count, before.position_count);
            assert_eq!(after.position_rc, before.position_rc + 1);
            for _ in 0..3 {
                let confirmed =
                    engine.reconcile_immutable_raw_chunk(key, data.len() as u32, checksum, tag);
                assert_eq!(confirmed.error_code, 0, "{}", confirmed.error);
                assert_eq!(confirmed.meta, read.meta);
                assert_eq!(confirmed.etag, tag);
                let repeated =
                    engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag);
                assert_eq!(repeated.error_code, 0, "{}", repeated.error);
                assert_eq!(repeated.data, data);
                assert_eq!(engine.used_size(), after);
                assert_eq!(engine.meta_store.query_used_size(b"ec").unwrap(), accounted);
                assert_eq!(engine.query_uncommitted_chunks(b"ec").unwrap(), pending);
            }
            (read, accounted)
        };
        config.create = false;
        let reopened = Engine::open(&config).unwrap();
        assert!(reopened.query_uncommitted_chunks(b"ec").unwrap().is_empty());
        let read = reopened.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag);
        assert_eq!(read.error_code, 0, "{}", read.error);
        assert_eq!(read.meta, owned.meta);
        assert_eq!(read.data, owned.data);
        assert_eq!(
            reopened.meta_store.query_used_size(b"ec").unwrap(),
            accounted
        );
    }

    #[test]
    fn test_read_immutable_raw_cache_cannot_override_actual_metadata() {
        use derse::Serialize;
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let key = b"ec-actual-read-metadata";
        let data = b"cache visibility is not committed metadata";
        let tag = b"actual-metadata-operation";
        let checksum = crc32c::crc32c(data);
        let original = engine
            .create_immutable_with_context(
                key,
                data,
                checksum,
                true,
                &ImmutableCreateContext {
                    desired_etag: tag,
                    ..Default::default()
                },
            )
            .unwrap();
        let write_meta = |meta: &ChunkMeta| {
            let bytes: derse::DownwardBytes = meta.serialize().unwrap();
            let mut batch = RocksDB::new_write_batch();
            batch.put(MetaKey::chunk_meta_key(key), bytes.as_slice());
            engine.meta_store.write(batch, true).unwrap();
        };

        let mut absent = RocksDB::new_write_batch();
        absent.delete(MetaKey::chunk_meta_key(key));
        engine.meta_store.write(absent, true).unwrap();
        assert_read_error(
            engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag),
            4001,
        );
        let mut corrupt = RocksDB::new_write_batch();
        corrupt.put(MetaKey::chunk_meta_key(key), [0xff]);
        engine.meta_store.write(corrupt, true).unwrap();
        assert_read_error(
            engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag),
            4002,
        );
        let mut different = original.meta().clone();
        different.chain_ver += 1;
        write_meta(&different);
        assert_read_error(
            engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag),
            4002,
        );
        assert_eq!(
            engine
                .meta_cache
                .entry_by_ref(key.as_slice())
                .get()
                .as_ref()
                .unwrap()
                .meta(),
            original.meta()
        );
        write_meta(original.meta());
        let read = engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag);
        assert_eq!(read.error_code, 0, "{}", read.error);
        assert_eq!(read.data, data);
    }

    #[test]
    fn test_read_immutable_raw_roundtrip_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        };
        let mut records = Vec::new();
        {
            let engine = Engine::open(&config).unwrap();
            for length in [0, 1, 4095, 4096, 4097] {
                let key = format!("ec-read-{length}").into_bytes();
                let data: Vec<u8> = (0..length).map(|i| (i * 17 + length) as u8).collect();
                let checksum = crc32c::crc32c(&data);
                let tag = vec![0, 255, (length % 251) as u8];
                let created = engine.create_immutable_raw_chunk(
                    &key,
                    &data,
                    checksum,
                    true,
                    &ffi::RawImmutableContext {
                        chain_ver: 7,
                        last_request_id: length as u64 + 1,
                        last_client_low: 11,
                        last_client_high: 13,
                    },
                    &tag,
                );
                assert_eq!(created.error_code, 0);
                let read = engine.read_immutable_raw_chunk(&key, length as u32, checksum, &tag);
                assert_eq!(read.error_code, 0);
                assert!(read.error.is_empty());
                assert_eq!(read.meta, created.meta);
                assert_eq!(read.data, data);
                records.push((key, tag, read));
            }
        }

        config.create = false;
        let engine = Engine::open(&config).unwrap();
        for (key, tag, original) in records {
            // The first owned result is still valid after its Engine closes.
            let read = engine.read_immutable_raw_chunk(
                &key,
                original.meta.len,
                original.meta.checksum,
                &tag,
            );
            assert_eq!(read.error_code, 0);
            assert!(read.error.is_empty());
            assert_eq!(read.meta, original.meta);
            assert_eq!(read.data, original.data);
        }
    }

    #[test]
    fn test_read_immutable_raw_validation() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let key = b"ec-read-validation";
        let data = b"expected sealed bytes";
        let tag = b"opaque identity";
        let length = data.len() as u32;
        let checksum = crc32c::crc32c(data);
        let created = engine.create_immutable_raw_chunk(
            key,
            data,
            checksum,
            true,
            &ffi::RawImmutableContext::default(),
            tag,
        );
        assert_eq!(created.error_code, 0);
        for invalid_key in [&b""[..], &b"e"[..]] {
            assert_read_error(
                engine.read_immutable_raw_chunk(invalid_key, length, checksum, tag),
                3,
            );
        }
        assert_read_error(
            engine.read_immutable_raw_chunk(key, CHUNK_SIZE_ULTRA.0 as u32 + 1, checksum, tag),
            3,
        );
        for invalid_tag in [Vec::new(), vec![0; MAX_IMMUTABLE_ETAG_LEN + 1]] {
            assert_read_error(
                engine.read_immutable_raw_chunk(key, length, checksum, &invalid_tag),
                3,
            );
        }
        assert_read_error(
            engine.read_immutable_raw_chunk(b"ec-missing", length, checksum, tag),
            4001,
        );
        assert_read_error(
            engine.read_immutable_raw_chunk(key, length + 1, checksum, tag),
            4015,
        );
        assert_read_error(
            engine.read_immutable_raw_chunk(key, length, checksum ^ 1, tag),
            4080,
        );
        assert_read_error(
            engine.read_immutable_raw_chunk(key, length, checksum, b"different identity"),
            4083,
        );
        let read = engine.read_immutable_raw_chunk(key, length, checksum, tag);
        assert_eq!(read.error_code, 0);
        assert_eq!(read.data, data);
    }

    #[test]
    fn test_read_immutable_raw_disk_corruption_and_short_read() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let key = b"ec-read-corruption";
        let data: Vec<u8> = (0..4097).map(|i| (i * 31 + 5) as u8).collect();
        let checksum = crc32c::crc32c(&data);
        let tag = b"corruption-test";
        let created = engine.create_immutable_raw_chunk(
            key,
            &data,
            checksum,
            true,
            &ffi::RawImmutableContext::default(),
            tag,
        );
        assert_eq!(created.error_code, 0);
        let chunk = engine.get(key).unwrap().unwrap();
        let pos = chunk.meta().pos;
        let clusters = &engine.allocators.select_by_pos(pos).unwrap().clusters;

        // Change a real on-disk byte without changing the stored CRC or tag.
        clusters.pwrite(pos, &[data[17] ^ 0x80], 17).unwrap();
        assert_eq!(engine.get(key).unwrap().unwrap().meta().checksum, checksum);
        assert_read_error(
            engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag),
            4080,
        );

        clusters.pwrite(pos, &[data[17]], 17).unwrap();
        let restored = engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag);
        assert_eq!(restored.error_code, 0);
        assert_eq!(restored.data, data);

        // This temporary Engine holds only this object. Truncate its cluster
        // to force a partial pread followed by EOF; no partial bytes may escape.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(clusters.path.join(format!("{:02X}", pos.cluster())))
            .unwrap();
        file.set_len(pos.offset().0 + 1024).unwrap();
        file.sync_data().unwrap();
        assert_read_error(
            engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag),
            4010,
        );
    }

    #[test]
    fn test_read_immutable_raw_rejects_uncommitted_metadata() {
        use derse::Serialize;
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let key = b"ec-read-uncommitted";
        let data = b"uncommitted metadata must not yield a sealed read";
        let checksum = crc32c::crc32c(data);
        let tag = b"uncommitted-test";
        let created = engine.create_immutable_raw_chunk(
            key,
            data,
            checksum,
            true,
            &ffi::RawImmutableContext::default(),
            tag,
        );
        assert_eq!(created.error_code, 0);
        let original = engine.get(key).unwrap().unwrap();
        let mut unsealed = original.as_ref().clone();
        unsealed.update_meta(&UpdateReq {
            desired_tag: tag,
            ..Default::default()
        });
        assert!(unsealed.meta().uncommitted);
        // Persist the same uncommitted record as the cache entry. A cache-only
        // discrepancy is rejected by lookup before the explicit sealed guard.
        let bytes: derse::DownwardBytes = unsealed.meta().serialize().unwrap();
        let mut batch = RocksDB::new_write_batch();
        batch.put(MetaKey::chunk_meta_key(key), bytes.as_slice());
        engine.meta_store.write(batch, true).unwrap();
        engine
            .meta_cache
            .entry_by_ref(key.as_slice())
            .insert(Arc::new(unsealed));
        assert_read_error(
            engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag),
            4086,
        );
    }

    #[test]
    fn test_reconcile_immutable_raw_owned_result_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        };
        let key = b"ec-reconcile-owned";
        let data: Vec<_> = (0..4097).map(|i| (i * 29 + 11) as u8).collect();
        let checksum = crc32c::crc32c(&data);
        let tag = b"owned-reconciliation-operation";
        let context = ffi::RawImmutableContext {
            chain_ver: 0,
            last_request_id: 41,
            last_client_low: 51,
            last_client_high: 61,
        };
        let result = {
            let engine = Engine::open(&config).unwrap();
            let created =
                engine.create_immutable_raw_chunk(key, &data, checksum, false, &context, tag);
            assert_eq!(created.error_code, 0);
            let reconciled =
                engine.reconcile_immutable_raw_chunk(key, data.len() as u32, checksum, tag);
            assert_eq!(reconciled.error_code, 0);
            assert_eq!(reconciled.meta, created.meta);
            reconciled
        };
        assert!(result.error.is_empty());
        assert_eq!(result.etag, tag);
        assert_eq!(result.meta.last_request_id, context.last_request_id);
        assert_eq!(result.meta.last_client_low, context.last_client_low);
        assert_eq!(result.meta.last_client_high, context.last_client_high);
        config.create = false;
        let engine = Engine::open(&config).unwrap();
        let reopened = engine.reconcile_immutable_raw_chunk(key, data.len() as u32, checksum, tag);
        assert_eq!(reopened.error_code, 0);
        assert_eq!(reopened.meta, result.meta);
        let read = engine.read_immutable_raw_chunk(key, data.len() as u32, checksum, tag);
        assert_eq!(read.error_code, 0);
        assert_eq!(read.data, data);
    }

    #[test]
    fn test_reconcile_immutable_raw_rejections_and_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let key = b"ec-reconcile-errors";
        let data: Vec<_> = (0..65553).map(|i| (i * 23 + 13) as u8).collect();
        let length = data.len() as u32;
        let checksum = crc32c::crc32c(&data);
        let tag = b"reconciliation-errors";
        assert_eq!(
            engine
                .create_immutable_raw_chunk(
                    key,
                    &data,
                    checksum,
                    true,
                    &ffi::RawImmutableContext::default(),
                    tag,
                )
                .error_code,
            0
        );
        let accounted = engine.meta_store.query_used_size(b"ec").unwrap();
        let assert_failure = |result: ffi::ImmutableReconcileResult, expected_code| {
            assert_eq!(result.error_code, expected_code);
            assert!(!result.error.is_empty());
            assert_eq!(result.meta, ffi::RawMeta::default());
            assert!(result.etag.is_empty());
            assert_eq!(engine.meta_store.query_used_size(b"ec").unwrap(), accounted);
        };
        for bad_key in [b"".as_slice(), b"e".as_slice()] {
            assert_failure(
                engine.reconcile_immutable_raw_chunk(bad_key, length, checksum, tag),
                3,
            );
        }
        assert_failure(
            engine.reconcile_immutable_raw_chunk(key, CHUNK_SIZE_ULTRA.0 as u32 + 1, checksum, tag),
            3,
        );
        for bad_tag in [Vec::new(), vec![0; 65]] {
            assert_failure(
                engine.reconcile_immutable_raw_chunk(key, length, checksum, &bad_tag),
                3,
            );
        }
        assert_failure(
            engine.reconcile_immutable_raw_chunk(b"ec-absent", length, checksum, tag),
            4085,
        );
        assert_failure(
            engine.reconcile_immutable_raw_chunk(key, length + 1, checksum, tag),
            4085,
        );
        assert_failure(
            engine.reconcile_immutable_raw_chunk(key, length, checksum ^ 1, tag),
            4085,
        );
        assert_failure(
            engine.reconcile_immutable_raw_chunk(key, length, checksum, b"other-operation"),
            4085,
        );
        let chunk = engine.get(key).unwrap().unwrap();
        let pos = chunk.meta().pos;
        let clusters = &engine.allocators.select_by_pos(pos).unwrap().clusters;
        // Corruption in the second verification slice must be detected.
        let offset = 65540usize;
        clusters
            .pwrite(pos, &[data[offset] ^ 0x40], offset as u32)
            .unwrap();
        assert_failure(
            engine.reconcile_immutable_raw_chunk(key, length, checksum, tag),
            4085,
        );
        clusters
            .pwrite(pos, &[data[offset]], offset as u32)
            .unwrap();
        let valid = engine.reconcile_immutable_raw_chunk(key, length, checksum, tag);
        assert_eq!(valid.error_code, 0);
        assert_eq!(valid.etag, tag);
        assert_eq!(engine.meta_store.query_used_size(b"ec").unwrap(), accounted);
    }
}

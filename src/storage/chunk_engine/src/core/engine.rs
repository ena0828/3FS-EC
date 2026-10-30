use super::super::*;
use lockmap::{EntryByRef, LockMap};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Deref;
use std::path::PathBuf;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default, Deserialize)]
pub struct EngineConfig {
    pub path: PathBuf,
    pub create: bool,
    pub prefix_len: usize,
}

/// Bound for explicitly supplied tags on the immutable-create API only.
pub const MAX_IMMUTABLE_ETAG_LEN: usize = 64;

const MAX_RETAINED_WRITING_PER_KEY: usize = 8;
const MAX_RETAINED_WRITING_CHUNKS: usize = 64;

/// Metadata persisted together with a newly created immutable chunk.
///
/// The caller validates the routing version and request identity. Zero values
/// remain valid for local callers. A nonempty tag is an opaque identifier, not
/// a verified content digest; an empty tag retains the engine's random tag.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImmutableCreateContext<'a> {
    pub chain_ver: u32,
    pub last_request_id: u64,
    pub last_client_low: u64,
    pub last_client_high: u64,
    pub desired_etag: &'a [u8],
}

#[derive(Clone)]
pub struct Engine {
    pub meta_store: Arc<MetaStore>,
    pub allocators: Allocators,
    pub meta_cache: Arc<LockMap<Bytes, ChunkArc>>,
    pub workers: Arc<Mutex<Vec<Worker>>>,
    pub allow_to_allocate: Arc<AtomicBool>,
    pub metrics: Arc<Metrics>,
    pub prefix_len: usize,
    pub writing_list: Arc<WritingList>,
    // Failed log replacements may leave any earlier candidate on disk. Keep
    // their positions referenced until a later synchronous replacement wins.
    retained_writing: Arc<Mutex<HashMap<Bytes, Vec<Chunk>>>>,
    immutable_namespace: Arc<ImmutableNamespace>,
}

struct ImmutableNamespace {
    // All paths are established by Engine::open; allocation only fallocates
    // existing cluster files. External namespace mutation is unsupported.
    engine_path: PathBuf,
    parents_to_sync: Vec<PathBuf>,
    synced: Mutex<bool>,
}

impl Engine {
    pub fn open(config: &EngineConfig) -> Result<Self> {
        // Capture the pre-existing ancestor before RocksDB's create_dir_all
        // creates missing engine/metadata parents. Do not recursively walk
        // arbitrary directories: only this explicitly configured path chain.
        let engine_path = std::path::absolute(&config.path)
            .map_err(|error| Error::IoError(format!("resolve engine path: {error}")))?;
        let mut parents_to_sync = Vec::new();
        let mut parent = engine_path.parent();
        while let Some(path) = parent {
            parents_to_sync.push(path.to_path_buf());
            match std::fs::metadata(path) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    parent = path.parent();
                }
                Err(error) => {
                    return Err(Error::IoError(format!(
                        "inspect engine ancestor {path:?}: {error}"
                    )));
                }
            }
        }
        let meta_config = MetaStoreConfig {
            rocksdb: RocksDBConfig {
                path: config.path.join("meta"),
                create: config.create,
                ..Default::default()
            },
            prefix_len: config.prefix_len,
        };

        let mut meta_store = MetaStore::open(&meta_config)?;
        let uncommitted_chunks = meta_store.occupy_uncommitted_positions()?;
        let meta_store = Arc::new(meta_store);
        let allocators = Allocators::new(&config.path, config.create, meta_store.clone())?;
        let meta_cache = Arc::new(LockMap::with_capacity_and_shard_amount(1 << 20, 256));

        let engine = Self {
            meta_store: meta_store.clone(),
            allocators,
            meta_cache,
            workers: Default::default(),
            allow_to_allocate: Arc::new(AtomicBool::new(true)),
            metrics: Default::default(),
            prefix_len: config.prefix_len,
            writing_list: Default::default(),
            retained_writing: Default::default(),
            immutable_namespace: Arc::new(ImmutableNamespace {
                engine_path,
                parents_to_sync,
                synced: Mutex::new(false),
            }),
        };

        if !uncommitted_chunks.is_empty() {
            // resume writing chunks in memory.
            for (chunk_id, meta, _) in &uncommitted_chunks {
                let old_chunk = engine.get(chunk_id)?;

                let prefix: Bytes = chunk_id[..engine.prefix_len].into();
                let mut writing_list = engine.writing_list.entry(prefix).or_default();
                let allocator = engine.allocators.select_by_pos(meta.pos)?;
                let chunk = allocator.reference(meta.clone(), old_chunk.is_none());
                writing_list.insert(chunk_id.clone(), WritingHolder { chunk, abort: true });
            }
            meta_store.vacate_uncommitted_positions(uncommitted_chunks)?;
        }

        engine.upgrade_version()?;

        Ok(engine)
    }

    pub fn used_size(&self) -> UsedSize {
        self.allocators.used_size()
    }

    pub fn allocate_groups(
        &self,
        min_remain: usize,
        max_remain: usize,
        batch_size: usize,
    ) -> usize {
        self.allocators.allocate_groups(
            if self.allow_to_allocate.load(Ordering::Acquire) {
                min_remain
            } else {
                0
            },
            max_remain,
            batch_size,
            false,
        )
    }

    pub fn allocate_ultra_groups(
        &self,
        min_remain: usize,
        max_remain: usize,
        batch_size: usize,
    ) -> usize {
        self.allocators.allocate_groups(
            if self.allow_to_allocate.load(Ordering::Acquire) {
                min_remain
            } else {
                0
            },
            max_remain,
            batch_size,
            true,
        )
    }

    pub fn compact_groups(&self, max_reserved: u64) -> usize {
        let group_ids = self.allocators.get_allocate_tasks(max_reserved);
        if group_ids.is_empty() {
            return 0;
        }

        let mut finish = 0usize;
        for group_id in group_ids {
            let mut it = self.meta_store.iterator();
            let result = it.iterate(
                MetaKey::group_to_chunks_key_prefix(group_id),
                |_, chunk_id| self.move_chunk(chunk_id).map(|_| ()),
            );
            match result {
                Ok(_) => finish += 1,
                Err(e) => tracing::error!("compact group {:?} failed: {:?}", group_id, e),
            }
            self.allocators.finish_compact_task(group_id);
        }

        finish
    }

    pub fn start_allocate_workers(&self, num: usize) {
        let workers = (0..num)
            .map(|i| {
                let allocators = self.allocators.clone();
                WorkerBuilder::default()
                    .name(format!("Allocate{}", i))
                    .spawn(move || {
                        let finish = allocators.allocate_groups(1, 2, 2, false);
                        if finish != 0 {
                            WorkerState::Continue
                        } else {
                            WorkerState::Wait(std::time::Duration::from_millis(100))
                        }
                    })
            })
            .collect::<Vec<_>>();

        self.workers.lock().unwrap().extend(workers);
    }

    pub fn stop_and_join(&self) {
        let mut workers = self.workers.lock().unwrap();
        for mut worker in workers.drain(..) {
            worker.stop_and_join();
        }
    }

    pub fn set_allow_to_allocate(&self, val: bool) {
        self.allow_to_allocate.store(val, Ordering::Release)
    }

    /// Intentionally leaks Arc pointers to avoid shutdown overhead.
    ///
    /// # Safety
    ///
    /// This function **must only be called** when the process is guaranteed to exit immediately afterwards.
    /// Calling it in any other context (e.g., during a restart, in a test) will cause permanent memory leaks
    /// of the Arc-managed data. This is an internal method intended to be used exactly once in the process exit path.
    pub unsafe fn speed_up_quit(&self) {
        // There is a memory leak and should only be called when the process exits.
        let _ = Arc::into_raw(self.meta_cache.clone());
        let _ = Arc::into_raw(self.writing_list.clone());
    }

    pub fn get(&self, chunk_id: &[u8]) -> Result<Option<ChunkArc>> {
        let mut entry = self.meta_cache.entry_by_ref(chunk_id);
        self.get_with_entry(chunk_id, &mut entry)
    }

    fn get_with_entry(
        &self,
        chunk_id: &[u8],
        entry: &mut EntryByRef<Bytes, [u8], ChunkArc>,
    ) -> Result<Option<ChunkArc>> {
        match entry.get() {
            Some(chunk) => Ok(Some(chunk.clone())),
            None => {
                let meta = self.meta_store.get_chunk_meta(chunk_id)?;
                if let Some(mut meta) = meta {
                    meta.set_default_etag_if_need();
                    let allocator = self.allocators.select_by_pos(meta.pos)?;
                    let chunk = Arc::new(allocator.reference(meta, true));
                    entry.insert(chunk.clone());
                    Ok(Some(chunk))
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub fn batch_get(&self, chunk_ids: &BTreeSet<Bytes>) -> Result<BTreeMap<Bytes, ChunkArc>> {
        let mut chunks = BTreeMap::<Bytes, ChunkArc>::new();

        let mut entries = Vec::with_capacity(chunk_ids.len());
        for chunk_id in chunk_ids {
            let mut entry = self.meta_cache.entry_by_ref(chunk_id);
            if let Some(chunk) = self.get_with_entry(chunk_id, &mut entry)? {
                chunks.insert(chunk_id.clone(), chunk);
            }
            entries.push(entry);
        }

        Ok(chunks)
    }

    pub fn move_chunk(&self, chunk_id: &[u8]) -> Result<Option<ChunkArc>> {
        // 1. get chunk and keep reference.
        let old_chunk = match self.get(chunk_id)? {
            Some(chunk) => chunk,
            None => return Ok(None),
        };

        // 2. allocate new chunk.
        let new_chunk = old_chunk.copy_chunk()?;

        // 3. replace chunk.
        let mut entry = self.meta_cache.entry_by_ref(chunk_id);
        match entry.get() {
            Some(chunk) if Arc::ptr_eq(chunk, &old_chunk) => {
                self.meta_store
                    .move_chunk(chunk_id, old_chunk.meta(), new_chunk.meta(), true)?;
                let new_chunk = Arc::new(new_chunk);
                entry.insert(new_chunk.clone());
                Ok(Some(new_chunk))
            }
            _ => Ok(None), // chunk is updated or deleted by other thread.
        }
    }

    pub fn write(
        &self,
        chunk_id: &[u8],
        data: &[u8],
        offset: u32,
        checksum: u32,
    ) -> Result<ChunkArc> {
        self.update(
            chunk_id,
            &mut UpdateReq {
                checksum,
                length: data.len() as _,
                offset,
                data: data.as_ptr() as u64,
                ..Default::default()
            },
        )
    }

    /// Create a complete chunk only if no committed chunk has this key.
    ///
    /// The key lock spans the existence check, preparation and publication, so
    /// concurrent calls cannot replace each other's result. Existing bytes,
    /// even identical bytes, return `ChunkAlreadyExists`; idempotence belongs
    /// to the caller. Other mutation APIs remain able to change this key, so
    /// callers must reserve their immutable namespace for this API.
    ///
    /// With `sync`, data is explicitly synchronized before the synchronous
    /// metadata commit. Errors retain the engine's existing writing-list
    /// recovery semantics and do not establish that nothing reached storage.
    pub fn create_immutable(
        &self,
        chunk_id: &[u8],
        data: &[u8],
        checksum: u32,
        sync: bool,
    ) -> Result<ChunkArc> {
        self.create_immutable_with_context(
            chunk_id,
            data,
            checksum,
            sync,
            &ImmutableCreateContext::default(),
        )
    }

    /// Create with routing/request metadata and an optional bounded opaque tag.
    ///
    /// The context is applied before the writing log and final metadata commit;
    /// no committed metadata is subsequently modified. The first chunk version
    /// is still one and is independent of an upper-layer EC generation.
    pub fn create_immutable_with_context(
        &self,
        chunk_id: &[u8],
        data: &[u8],
        checksum: u32,
        sync: bool,
        context: &ImmutableCreateContext<'_>,
    ) -> Result<ChunkArc> {
        if chunk_id.is_empty() || chunk_id.len() < self.prefix_len {
            return Err(Error::InvalidArg(format!(
                "immutable chunk id must be nonempty and cover prefix {}",
                self.prefix_len
            )));
        }
        if context.desired_etag.len() > MAX_IMMUTABLE_ETAG_LEN {
            return Err(Error::InvalidArg(format!(
                "immutable etag length {} exceeds {}",
                context.desired_etag.len(),
                MAX_IMMUTABLE_ETAG_LEN
            )));
        }
        let length = u32::try_from(data.len())
            .map_err(|_| Error::InvalidArg("immutable chunk length exceeds u32".into()))?;
        if Size::from(length) > CHUNK_SIZE_ULTRA {
            return Err(Error::InvalidArg(format!(
                "immutable chunk length {} exceeds {}",
                length, CHUNK_SIZE_ULTRA
            )));
        }
        let actual_checksum = crc32c::crc32c(data);
        if actual_checksum != checksum {
            return Err(Error::ChecksumMismatch(format!(
                "invalid checksum local {:08x} != remote {:08x}",
                actual_checksum, checksum
            )));
        }

        // Do not call get/update_chunk/commit_chunk while this lock is held:
        // those public entry points acquire the same non-reentrant key lock.
        let mut entry = self.meta_cache.entry_by_ref(chunk_id);
        if self.get_with_entry(chunk_id, &mut entry)?.is_some() {
            return Err(Error::ChunkAlreadyExists);
        }
        let mut req = UpdateReq {
            checksum,
            length,
            create_new: true,
            chain_ver: context.chain_ver,
            last_request_id: context.last_request_id,
            last_client_low: context.last_client_low,
            last_client_high: context.last_client_high,
            ..Default::default()
        };
        // Pass the borrowed slice directly; no raw pointer is reconstructed.
        let mut chunk =
            self.prepare_update_chunk(chunk_id, &mut req, data, None, Some(context.desired_etag))?;
        let result = (|| {
            if sync {
                Self::sync_immutable_data(&chunk.chunk)?;
                self.sync_immutable_namespace()?;
            }
            self.commit_chunk_with_entry(&mut chunk, sync, &mut entry)
        })();
        // WritingChunk::drop takes writing_list; release the key guard first.
        drop(entry);
        result
    }

    fn sync_immutable_data(chunk: &Chunk) -> Result<()> {
        let fd = chunk.fd_and_offset().fd;
        loop {
            // SAFETY: chunk keeps the owning Cluster alive; this call borrows
            // its fd and does not close it.
            if unsafe { libc::fdatasync(fd) } == 0 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(Error::IoError(format!(
                    "sync immutable chunk data failed: {err}"
                )));
            }
        }
    }

    fn sync_immutable_directory(path: &std::path::Path) -> Result<()> {
        let directory = std::fs::File::open(path).map_err(|error| {
            Error::IoError(format!("open immutable directory {path:?}: {error}"))
        })?;
        let metadata = directory.metadata().map_err(|error| {
            Error::IoError(format!("stat immutable directory {path:?}: {error}"))
        })?;
        if !metadata.is_dir() {
            return Err(Error::IoError(format!(
                "immutable path is not a directory: {path:?}"
            )));
        }
        directory
            .sync_all()
            .map_err(|error| Error::IoError(format!("sync immutable directory {path:?}: {error}")))
    }

    fn sync_immutable_namespace(&self) -> Result<()> {
        self.sync_immutable_namespace_with(Self::sync_immutable_directory)
    }

    // The private callback allows path-order and error-retry assertions while
    // keeping real filesystem operations in the test's synchronization path.
    fn sync_immutable_namespace_with(
        &self,
        mut sync_directory: impl FnMut(&std::path::Path) -> Result<()>,
    ) -> Result<()> {
        let namespace = &self.immutable_namespace;
        let mut synced = namespace.synced.lock().unwrap();
        if *synced {
            return Ok(());
        }
        // Each class has 256 files created at open. Later allocations, moves
        // and hole punching do not add or rename filesystem entries.
        for allocator in &self.allocators.vec {
            sync_directory(
                &namespace
                    .engine_path
                    .join(allocator.clusters.chunk_size.to_string()),
            )?;
        }
        // RocksDB synchronizes its own log/manifest entries, but does not
        // establish the reachability of the newly created meta directory.
        sync_directory(&namespace.engine_path.join("meta"))?;
        sync_directory(&namespace.engine_path)?;
        for parent in &namespace.parents_to_sync {
            sync_directory(parent)?;
        }
        *synced = true;
        Ok(())
    }

    /// Reconfirm an existing immutable committed object after an unknown result.
    ///
    /// Requires an isolated immutable namespace: legacy in-place updates must
    /// not run on these keys. The key and opaque tag bind the caller's object
    /// and allocation/operation identity; neither is a cryptographic digest.
    /// This is separate from ordinary reads: success requires full-byte CRC,
    /// data fdatasync, namespace synchronization, then a successful metadata WAL
    /// synchronization. Directory success is cached for this Engine instance.
    /// These explicit barriers are not a substitute for power-loss testing. An error,
    /// including missing metadata, never authorizes reclamation. A preparation
    /// log alone is insufficient and is never promoted or removed here.
    pub fn reconcile_immutable(
        &self,
        chunk_id: &[u8],
        expected_length: u32,
        expected_checksum: u32,
        expected_etag: &[u8],
    ) -> Result<ChunkArc> {
        self.reconcile_immutable_with_barriers(
            chunk_id,
            expected_length,
            expected_checksum,
            expected_etag,
            Self::sync_immutable_data,
            || self.meta_store.sync_wal(),
        )
    }

    // Private barrier parameters permit deterministic failure/order tests
    // without a global failpoint or changes to ordinary reads and writes.
    fn reconcile_immutable_with_barriers(
        &self,
        chunk_id: &[u8],
        expected_length: u32,
        expected_checksum: u32,
        expected_etag: &[u8],
        sync_data: impl FnOnce(&Chunk) -> Result<()>,
        sync_wal: impl FnOnce() -> Result<()>,
    ) -> Result<ChunkArc> {
        if chunk_id.is_empty() || chunk_id.len() < self.prefix_len {
            return Err(Error::InvalidArg(
                "invalid immutable reconciliation key".into(),
            ));
        }
        if Size::from(expected_length) > CHUNK_SIZE_ULTRA {
            return Err(Error::InvalidArg(
                "immutable reconciliation length exceeds limit".into(),
            ));
        }
        if expected_etag.is_empty() || expected_etag.len() > MAX_IMMUTABLE_ETAG_LEN {
            return Err(Error::InvalidArg(
                "immutable reconciliation etag must contain 1..=64 bytes".into(),
            ));
        }

        let mut entry = self.meta_cache.entry_by_ref(chunk_id);
        // Read the actual committed record, even when a cache entry exists.
        // Cache visibility after an unsuccessful sync is not a durable ACK.
        let meta = self.meta_store.get_chunk_meta(chunk_id)?.ok_or_else(|| {
            Error::MetaError(
                "immutable committed metadata not found; outcome remains unknown".into(),
            )
        })?;
        if meta.uncommitted {
            return Err(Error::MetaError(
                "immutable metadata is not committed".into(),
            ));
        }
        if meta.len != expected_length {
            return Err(Error::MetaError(
                "immutable reconciliation length mismatch".into(),
            ));
        }
        if meta.etag.as_slice() != expected_etag {
            return Err(Error::ChunkETagMismatch(
                "immutable reconciliation identity mismatch".into(),
            ));
        }
        if meta.checksum != expected_checksum {
            return Err(Error::ChecksumMismatch(
                "immutable reconciliation metadata checksum mismatch".into(),
            ));
        }
        let chunk = match entry.get() {
            Some(chunk) if chunk.meta() == &meta => chunk.clone(),
            Some(_) => {
                return Err(Error::MetaError(
                    "immutable cache and committed metadata differ; outcome remains unknown".into(),
                ))
            }
            None => {
                let allocator = self.allocators.select_by_pos(meta.pos)?;
                // A failed commit may already retain this position in the
                // writing list. This is not necessarily its first reference.
                let chunk = Arc::new(allocator.reference(meta, false));
                // Keep a persistent reference even when validation/sync fails;
                // dropping the last temporary reference would free the position.
                entry.insert(chunk.clone());
                chunk
            }
        };

        const VERIFY_SLICE: usize = 64 * 1024;
        let buffer_length = (expected_length as usize).min(VERIFY_SLICE);
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(buffer_length).map_err(|error| {
            Error::MetaError(format!("allocate immutable reconciliation buffer: {error}"))
        })?;
        buffer.resize(buffer_length, 0);
        let mut checksum = 0;
        let mut offset = 0;
        while offset < expected_length {
            let length = ((expected_length - offset) as usize).min(buffer.len());
            chunk.pread(&mut buffer[..length], offset)?;
            checksum = crc32c::crc32c_append(checksum, &buffer[..length]);
            offset += length as u32;
        }
        if checksum != expected_checksum {
            return Err(Error::ChecksumMismatch(
                "immutable reconciliation data checksum mismatch".into(),
            ));
        }
        sync_data(&chunk)?;
        self.sync_immutable_namespace()?;
        sync_wal()?;
        // Do not repeat add_chunk/move_chunk or change preparation state: those
        // mutations carry non-idempotent accounting and recovery semantics.
        drop(entry);
        Ok(chunk)
    }

    pub fn remove(&self, chunk_id: &[u8]) -> Result<ChunkArc> {
        self.update(
            chunk_id,
            &mut UpdateReq {
                is_remove: true,
                ..Default::default()
            },
        )
    }

    pub fn truncate(&self, chunk_id: &[u8], length: u32) -> Result<ChunkArc> {
        self.update(
            chunk_id,
            &mut UpdateReq {
                is_truncate: true,
                offset: length,
                ..Default::default()
            },
        )
    }

    fn update(&self, chunk_id: &[u8], req: &mut UpdateReq) -> Result<ChunkArc> {
        let chunk = self.update_chunk(chunk_id, req)?;
        self.commit_chunk(chunk, false)
    }

    pub fn update_chunk(&self, chunk_id: &[u8], req: &mut UpdateReq) -> Result<WritingChunk> {
        if chunk_id.len() < self.prefix_len {
            return Err(Error::InvalidArg(format!(
                "chunk id {:?} is too short for prefix {}",
                chunk_id, self.prefix_len
            )));
        }

        // 1. prepare update info.
        let data = if req.length != 0 {
            // SAFETY: req.data pointer must be valid and remain live for the duration of this function.
            // The slice is consumed synchronously and immediately within safe_write/copy_on_write calls
            // (lines 386-394, 398-404, 418-424). If writes become asynchronous in the future,
            // this would require refactoring to take ownership of the data (e.g., via Vec<u8>).
            let data =
                unsafe { std::slice::from_raw_parts(req.data as *const _, req.length as usize) };
            let checksum = crc32c::crc32c(data);
            if req.without_checksum {
                req.checksum = checksum;
            } else if checksum != req.checksum {
                return Err(Error::ChecksumMismatch(format!(
                    "invalid checksum local {:08x} != remote {:08x}",
                    checksum, req.checksum
                )));
            }
            data
        } else {
            &[]
        };

        // 2. get old chunk.
        let old_chunk = self.get(chunk_id)?;
        self.prepare_update_chunk(chunk_id, req, data, old_chunk, None)
    }

    // The caller validates data and supplies the previously loaded chunk.
    // This helper never acquires meta_cache, allowing create_immutable to
    // retain the key lock across preparation and metadata publication.
    fn prepare_update_chunk(
        &self,
        chunk_id: &[u8],
        req: &mut UpdateReq,
        data: &[u8],
        old_chunk: Option<ChunkArc>,
        desired_etag: Option<&[u8]>,
    ) -> Result<WritingChunk> {
        // Refuse additional candidates before data allocation when previous
        // log outcomes have exhausted the conservative retention budget.
        Self::check_retained_writing_capacity(&self.retained_writing.lock().unwrap(), chunk_id)?;
        let etag = match &old_chunk {
            Some(chunk) => {
                if req.create_new {
                    return Err(Error::ChunkAlreadyExists);
                }
                let meta = chunk.meta();
                req.out_commit_ver = meta.chunk_ver;
                req.out_chain_ver = meta.chain_ver;
                req.out_checksum = meta.checksum;
                meta.etag.as_slice()
            }
            None => {
                if req.is_remove && req.update_ver > 0 {
                    req.out_commit_ver = req.update_ver - 1;
                } else {
                    req.out_commit_ver = 0;
                }
                req.out_chain_ver = req.chain_ver;
                req.out_checksum = 0;
                req.out_non_existent = true;
                &[]
            }
        };

        // 3. check version.
        if req.chain_ver < req.out_chain_ver {
            return Err(Error::ChainVersionMismatch(format!(
                "req.chain_ver {} < meta.chain_ver {}",
                req.chain_ver, req.out_chain_ver
            )));
        }

        let new_chunk_ver = if req.is_syncing {
            req.update_ver
        } else if req.update_ver > 0 {
            if req.update_ver <= req.out_commit_ver {
                return Err(Error::ChunkCommittedUpdate(format!(
                    "committed update {} <= {}",
                    req.update_ver, req.out_commit_ver
                )));
            } else if req.update_ver > req.out_commit_ver + 1 {
                return Err(Error::ChunkMissingUpdate(format!(
                    "missing update {} > {} + 1",
                    req.update_ver, req.out_commit_ver
                )));
            }
            req.update_ver
        } else {
            req.out_commit_ver + 1
        };

        if !req.expected_tag.is_empty() && req.expected_tag != etag {
            return Err(Error::ChunkETagMismatch(format!(
                "expected {:?} != real {:?}",
                req.expected_tag, etag
            )));
        }

        // 4. do update.
        let mut new_chunk = match old_chunk {
            Some(old_chunk) if req.is_remove => old_chunk.as_ref().clone(),
            Some(old_chunk)
                if req.is_syncing
                    || (req.length > 0 && req.offset < old_chunk.meta().len)
                    || req.offset + req.length > old_chunk.capacity() =>
            {
                old_chunk.copy_on_write(
                    data,
                    req.offset,
                    req.checksum,
                    req.is_syncing,
                    self.allow_to_allocate.load(Ordering::Acquire),
                    &self.allocators,
                    &self.metrics,
                )?
            }
            Some(old_chunk) => {
                let mut new_chunk = old_chunk.as_ref().clone();
                new_chunk.safe_write(
                    data,
                    req.offset,
                    req.checksum,
                    req.is_truncate,
                    &self.metrics,
                )?;
                new_chunk
            }
            None => {
                let begin = std::time::Instant::now();
                let mut new_chunk = self.allocators.allocate(
                    Size::from(req.offset + req.length),
                    self.allow_to_allocate.load(Ordering::Acquire),
                )?;
                let latency = std::time::Instant::now().duration_since(begin).as_micros() as _;
                self.metrics.allocate_times.fetch_add(1, Ordering::AcqRel);
                self.metrics
                    .allocate_latency
                    .fetch_add(latency, Ordering::AcqRel);
                new_chunk.safe_write(
                    data,
                    req.offset,
                    req.checksum,
                    req.is_truncate,
                    &self.metrics,
                )?;
                new_chunk
            }
        };

        req.out_commit_ver = new_chunk_ver;
        req.out_chain_ver = req.chain_ver;
        req.out_checksum = new_chunk.meta().checksum;
        new_chunk.update_meta(req.deref());
        if let Some(etag) = desired_etag.filter(|etag| !etag.is_empty()) {
            new_chunk.set_etag(etag);
        }

        let prefix: Bytes = chunk_id[..self.prefix_len].into();
        let mut writing_list = self.writing_list.entry(prefix).or_default();
        match writing_list.entry(chunk_id.into()) {
            std::collections::hash_map::Entry::Occupied(mut occupied_entry)
                if occupied_entry.get().abort =>
            {
                // Lock order is writing_list -> retained_writing. No code
                // holding retained_writing acquires writing_list. Recheck
                // under both locks so concurrent retries cannot exceed caps.
                let mut retained = self.retained_writing.lock().unwrap();
                Self::check_retained_writing_capacity(&retained, chunk_id)?;
                let replaced = occupied_entry
                    .insert(WritingHolder {
                        chunk: new_chunk.clone(),
                        abort: false,
                    })
                    .chunk;
                retained.entry(chunk_id.into()).or_default().push(replaced);
            }
            std::collections::hash_map::Entry::Occupied(occupied_entry) => {
                return Err(Error::InvalidArg(format!(
                    "chunk {:?} is in writing ({:?})",
                    chunk_id,
                    occupied_entry.get().chunk.meta(),
                )));
            }
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(WritingHolder {
                    chunk: new_chunk.clone(),
                    abort: false,
                });
            }
        }
        drop(writing_list);

        // Establish the owner before persistence can fail. Its Drop marks the
        // holder aborted without discarding a possibly persisted writing log.
        let writing = WritingChunk {
            chunk_id: chunk_id.into(),
            chunk: new_chunk,
            list: self.writing_list.clone(),
            prefix_len: self.prefix_len as _,
            is_remove: req.is_remove,
            commit_succ: false,
        };
        self.meta_store
            .persist_writing_chunk(chunk_id, writing.meta())?;
        // Only a successful synchronous put proves that the log no longer
        // references any old candidate. Release positions outside the lock.
        self.release_retained_writing(chunk_id);
        Ok(writing)
    }

    fn release_retained_writing(&self, chunk_id: &[u8]) {
        let replaced = self.retained_writing.lock().unwrap().remove(chunk_id);
        drop(replaced);
    }

    fn check_retained_writing_capacity(
        retained: &HashMap<Bytes, Vec<Chunk>>,
        chunk_id: &[u8],
    ) -> Result<()> {
        if retained.get(chunk_id).map_or(0, Vec::len) >= MAX_RETAINED_WRITING_PER_KEY
            || retained.values().map(Vec::len).sum::<usize>() >= MAX_RETAINED_WRITING_CHUNKS
        {
            return Err(Error::InvalidArg(
                "unresolved writing-log replacements reached retention limit; recovery required"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn commit_chunk(&self, mut chunk: WritingChunk, sync: bool) -> Result<ChunkArc> {
        let chunk_id = chunk.chunk_id.clone();
        let mut entry = self.meta_cache.entry_by_ref(&chunk_id);
        let result = self.commit_chunk_with_entry(&mut chunk, sync, &mut entry);
        drop(entry);
        result
    }

    fn commit_chunk_with_entry(
        &self,
        chunk: &mut WritingChunk,
        sync: bool,
        entry: &mut EntryByRef<Bytes, [u8], ChunkArc>,
    ) -> Result<ChunkArc> {
        chunk.set_committed();
        let chunk_id = &chunk.chunk_id;
        let new_chunk: ChunkArc = (&*chunk).into();

        if chunk.is_remove {
            match self.get_with_entry(chunk_id, entry)? {
                Some(old_chunk) => {
                    self.meta_store
                        .remove(&chunk.chunk_id, old_chunk.meta(), sync)?
                }
                None => self.meta_store.remove_writing_chunk(chunk_id, sync)?,
            }
            entry.remove();
            if sync {
                self.release_retained_writing(chunk_id);
            }
            chunk.commit_succ();
            return Ok(new_chunk);
        }

        // update rocksdb under lock protection.
        match self.get_with_entry(chunk_id, entry)? {
            Some(old_chunk) => {
                self.meta_store
                    .move_chunk(chunk_id, old_chunk.meta(), new_chunk.meta(), sync)?;
            }
            None => {
                self.meta_store
                    .add_chunk(chunk_id, new_chunk.meta(), sync)?;
            }
        }
        entry.insert(new_chunk.clone());

        if sync {
            self.release_retained_writing(chunk_id);
        }
        chunk.commit_succ();
        Ok(new_chunk)
    }

    pub fn commit_chunks(&self, mut chunks: Vec<WritingChunk>, sync: bool) -> Result<()> {
        let chunk_ids = chunks
            .iter()
            .map(|c| c.chunk_id.clone())
            .collect::<BTreeSet<_>>();
        if chunk_ids.len() != chunks.len() {
            return Err(Error::InvalidArg("same chunk id in the batch!".into()));
        }

        // lock it.
        let mut entries = HashMap::with_capacity(chunk_ids.len());
        for chunk_id in &chunk_ids {
            let mut entry = self.meta_cache.entry_by_ref(chunk_id);
            self.get_with_entry(chunk_id, &mut entry)?;
            entries.insert(chunk_id.clone(), entry);
        }

        let mut write_batch = RocksDB::new_write_batch();
        for chunk in &mut chunks {
            chunk.set_committed();
            if chunk.is_remove {
                match entries.get_mut(&chunk.chunk_id).unwrap().get() {
                    Some(old_chunk) => self.meta_store.remove_mut(
                        &chunk.chunk_id,
                        old_chunk.meta(),
                        &mut write_batch,
                    )?,
                    None => self
                        .meta_store
                        .remove_writing_chunk(&chunk.chunk_id, sync)?,
                }
            } else {
                match entries.get_mut(&chunk.chunk_id).unwrap().get() {
                    Some(old_chunk) => self.meta_store.move_chunk_mut(
                        &chunk.chunk_id,
                        old_chunk.meta(),
                        chunk.meta(),
                        &mut write_batch,
                    )?,
                    None => self.meta_store.add_chunk_mut(
                        &chunk.chunk_id,
                        chunk.meta(),
                        &mut write_batch,
                    )?,
                }
            }
        }
        self.meta_store.write(write_batch, sync)?;

        for chunk in &mut chunks {
            if sync {
                self.release_retained_writing(&chunk.chunk_id);
            }
            chunk.commit_succ();
            if chunk.is_remove {
                entries.get_mut(&chunk.chunk_id).unwrap().remove();
            } else {
                entries
                    .get_mut(&chunk.chunk_id)
                    .unwrap()
                    .insert(chunk.deref().into());
            }
        }
        Ok(())
    }

    pub fn query_uncommitted_chunks(&self, prefix: &[u8]) -> Result<Vec<(Bytes, ChunkMeta)>> {
        let writing_list = self.writing_list.entry(prefix.into()).or_default();
        let mut uncommitted_chunks = Vec::with_capacity(writing_list.len());
        for (chunk_id, holder) in writing_list.iter() {
            uncommitted_chunks.push((chunk_id.clone(), holder.chunk.meta().clone()));
        }
        Ok(uncommitted_chunks)
    }

    pub fn handle_uncommitted_chunks(
        &self,
        prefix: &[u8],
        chain_ver: u32,
    ) -> Result<Vec<(Bytes, ChunkMeta)>> {
        let mut writing_list = self.writing_list.entry(prefix.into()).or_default();

        let mut chunks = Vec::with_capacity(writing_list.len());
        let mut uncommitted_chunks = Vec::with_capacity(writing_list.len());
        // commit it!
        for (chunk_id, holder) in writing_list.iter_mut() {
            holder.chunk.set_chain_ver(chain_ver);
            let chunk = holder.chunk.clone();
            chunks.push(WritingChunk {
                chunk_id: chunk_id.clone(),
                chunk,
                list: self.writing_list.clone(),
                prefix_len: self.prefix_len as _,
                is_remove: false,
                commit_succ: false,
            });
            uncommitted_chunks.push((chunk_id.clone(), holder.chunk.meta().clone()));
        }
        drop(writing_list);
        self.commit_chunks(chunks, true)?;
        Ok(uncommitted_chunks)
    }

    pub fn query_chunks(
        &self,
        begin: impl AsRef<[u8]>,
        end: impl AsRef<[u8]>,
        max_count: u64,
    ) -> Result<Vec<(Bytes, ChunkMeta)>> {
        let mut chunks = self.meta_store.query_chunks(begin, end, max_count)?;
        for (_, meta) in &mut chunks {
            meta.set_default_etag_if_need();
        }
        Ok(chunks)
    }

    // returns an unordered list of chunks (including chunks being written).
    pub fn query_all_chunks(&self, prefix: &[u8]) -> Result<Vec<(Bytes, ChunkMeta)>> {
        let (mut writing_list, it) = match self.writing_list.entry(prefix.into()) {
            dashmap::Entry::Occupied(occupied_entry) => {
                let mut map = HashMap::new();
                for (chunk_id, holder) in occupied_entry.get() {
                    map.insert(chunk_id.clone(), holder.chunk.meta().clone());
                }
                (map, self.meta_store.iterator())
            }
            dashmap::Entry::Vacant(_) => (Default::default(), self.meta_store.iterator()),
        };

        let mut chunks =
            self.meta_store
                .query_chunks_from_iterator(it, prefix, prefix, u64::MAX)?;
        for (chunk_id, meta) in &mut chunks {
            meta.set_default_etag_if_need();
            if let Some(writing) = writing_list.remove(chunk_id) {
                *meta = writing;
            }
        }
        chunks.extend(writing_list);
        Ok(chunks)
    }

    pub fn query_chunks_by_timestamp(
        &self,
        prefix: &[u8],
        begin: u64,
        end: u64,
        max_count: u64,
    ) -> Result<Vec<(Bytes, ChunkMeta)>> {
        let chunk_ids = self
            .meta_store
            .query_chunks_by_timestamp(prefix, begin, end, max_count)?;
        let mut chunks = Vec::with_capacity(chunk_ids.len());
        for chunk_id in chunk_ids {
            if let Some(chunk) = self.get(&chunk_id)? {
                let mut meta = chunk.meta().clone();
                meta.set_default_etag_if_need();
                chunks.push((chunk_id, meta));
            }
        }
        Ok(chunks)
    }

    pub fn batch_remove(
        &self,
        begin: impl AsRef<[u8]>,
        end: impl AsRef<[u8]>,
        max_count: u64,
    ) -> Result<u64> {
        let mut chunk_ids = self
            .meta_store
            .query_chunks(begin, end, max_count)?
            .into_iter()
            .map(|(chunk_id, _)| chunk_id)
            .collect::<Vec<Bytes>>();

        const BATCH_SIZE: usize = 4096;
        for batch in chunk_ids.chunks_mut(BATCH_SIZE) {
            batch.sort(); // acquire locks in sequence to avoid deadlocks.

            let mut write_batch = RocksDB::new_write_batch();
            let mut entries = Vec::with_capacity(batch.len());
            for chunk_id in batch.iter() {
                let mut entry = self.meta_cache.entry_by_ref(chunk_id);
                match self.get_with_entry(chunk_id, &mut entry)? {
                    Some(chunk) => {
                        self.meta_store
                            .remove_mut(chunk_id, chunk.meta(), &mut write_batch)?;
                    }
                    None => {
                        // The chunk has been deleted by another thread. Still count it as a successfully deleted one.
                    }
                }
                entries.push(entry);
            }

            self.meta_store.write(write_batch, true)?;

            for mut entry in entries {
                entry.remove();
            }
        }

        Ok(chunk_ids.len() as _)
    }

    pub fn upgrade_version(&self) -> Result<()> {
        let version = self.meta_store.get_version()?;
        let mut new_version = version;

        if new_version < MetaStore::V1_FIX_TIMESTAMP {
            // fix timestamp format.
            tracing::info!(
                "upgrade version: {} -> {}",
                new_version,
                MetaStore::V1_FIX_TIMESTAMP
            );
            let mut write_batch = RocksDB::new_write_batch();
            self.meta_store
                .remove_range_mut(MetaKey::TIMESTAMP_KEY_PREFIX, &mut write_batch)?;
            self.meta_store.write(write_batch, true)?;
            new_version = MetaStore::V1_FIX_TIMESTAMP;
        }

        if version < new_version {
            self.meta_store.set_version(new_version)?;
            tracing::info!("upgrade version {} -> {} successful!", version, new_version);
        }
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_engine_immutable_namespace_order_and_shared_cache() {
        let dir = tempfile::tempdir().unwrap();
        let outer = dir.path().join("new-parent");
        let inner = outer.join("new-inner");
        let engine_path = inner.join("engine");
        let engine = Engine::open(&EngineConfig {
            path: engine_path.clone(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let mut expected: Vec<_> = engine
            .allocators
            .vec
            .iter()
            .map(|allocator| allocator.clusters.path.clone())
            .collect();
        expected.extend([
            engine_path.join("meta"),
            engine_path.clone(),
            inner,
            outer,
            dir.path().to_path_buf(),
        ]);
        let mut actual = Vec::new();
        engine
            .sync_immutable_namespace_with(|path| {
                actual.push(path.to_path_buf());
                Engine::sync_immutable_directory(path)
            })
            .unwrap();
        assert_eq!(actual, expected);
        assert!(*engine.immutable_namespace.synced.lock().unwrap());
        engine
            .clone()
            .sync_immutable_namespace_with(|_| {
                panic!("successful namespace synchronization must be shared by Engine clones")
            })
            .unwrap();
    }

    #[test]
    fn test_engine_immutable_namespace_failure_blocks_seal_and_retries() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let class_path = engine.allocators.vec[3].clusters.path.clone();
        let displaced = dir.path().join("temporarily-displaced-class");
        // All file descriptors remain open, so data I/O can succeed while the
        // required directory binding is absent. This is a real filesystem
        // failure, scoped to the temporary Engine, not a global failpoint.
        std::fs::rename(&class_path, &displaced).unwrap();
        let mut attempted = Vec::new();
        assert!(matches!(
            engine.sync_immutable_namespace_with(|path| {
                attempted.push(path.to_path_buf());
                Engine::sync_immutable_directory(path)
            }),
            Err(Error::IoError(_))
        ));
        assert_eq!(
            attempted,
            engine.allocators.vec[..4]
                .iter()
                .map(|allocator| allocator.clusters.path.clone())
                .collect::<Vec<_>>()
        );
        assert!(!*engine.immutable_namespace.synced.lock().unwrap());

        let key = b"ec-namespace-failure";
        let data = b"successful data I/O is not enough when directory sync fails";
        let checksum = crc32c::crc32c(data);
        let tag = b"namespace-operation";
        let context = ImmutableCreateContext {
            desired_etag: tag,
            ..Default::default()
        };
        assert!(matches!(
            engine.create_immutable_with_context(key, data, checksum, true, &context,),
            Err(Error::IoError(_))
        ));
        assert!(engine.meta_store.get_chunk_meta(key).unwrap().is_none());
        assert_eq!(engine.query_uncommitted_chunks(b"ec").unwrap().len(), 1);
        assert!(!*engine.immutable_namespace.synced.lock().unwrap());
        // A preparation record cannot use the new barrier to promote itself.
        assert!(engine
            .reconcile_immutable(key, data.len() as u32, checksum, tag)
            .is_err());
        assert!(!*engine.immutable_namespace.synced.lock().unwrap());

        // A committed-but-unsynchronized object must also refuse a new seal
        // confirmation while this directory prerequisite remains unresolved.
        let async_key = b"ec-namespace-async";
        let asynchronous = engine
            .create_immutable_with_context(async_key, data, checksum, false, &context)
            .unwrap();
        assert!(matches!(
            engine.reconcile_immutable(async_key, data.len() as u32, checksum, tag),
            Err(Error::IoError(_))
        ));
        assert_eq!(
            engine.meta_store.get_chunk_meta(async_key).unwrap(),
            Some(asynchronous.meta().clone())
        );
        assert!(!*engine.immutable_namespace.synced.lock().unwrap());
        std::fs::rename(&displaced, &class_path).unwrap();
        assert_eq!(
            engine
                .reconcile_immutable(async_key, data.len() as u32, checksum, tag)
                .unwrap()
                .meta(),
            asynchronous.meta()
        );
        assert!(*engine.immutable_namespace.synced.lock().unwrap());
        let created = engine
            .create_immutable_with_context(key, data, checksum, true, &context)
            .unwrap();
        assert!(*engine.immutable_namespace.synced.lock().unwrap());
        let mut actual = vec![0; data.len()];
        created.pread(&mut actual, 0).unwrap();
        assert_eq!(actual, data);
        assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
        let accounted = engine.meta_store.query_used_size(b"ec").unwrap();
        let confirmed = engine
            .reconcile_immutable(key, data.len() as u32, checksum, tag)
            .unwrap();
        assert_eq!(confirmed.meta(), created.meta());
        assert_eq!(engine.meta_store.query_used_size(b"ec").unwrap(), accounted);
    }

    #[test]
    fn test_engine_reconcile_immutable_no_accounting_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        };
        let objects: Vec<_> = [0usize, 4097, 65553]
            .into_iter()
            .map(|length| {
                let data: Vec<_> = (0..length).map(|i| (i * 19 + 7) as u8).collect();
                (format!("ec-reconfirm-{length}").into_bytes(), data)
            })
            .collect();
        let tag = b"same-operation-after-lost-ack";
        {
            let engine = Engine::open(&config).unwrap();
            for (key, data) in &objects {
                // Discard the original return as a lost-ACK model. The initial
                // final metadata commit is deliberately asynchronous; this is
                // not an injected RocksDB sync error or a power-loss test.
                drop(
                    engine
                        .create_immutable_with_context(
                            key,
                            data,
                            crc32c::crc32c(data),
                            false,
                            &ImmutableCreateContext {
                                desired_etag: tag,
                                ..Default::default()
                            },
                        )
                        .unwrap(),
                );
            }
            let accounted = engine.meta_store.query_used_size(b"ec").unwrap();
            let allocated = engine.used_size();
            for _ in 0..3 {
                for (key, data) in &objects {
                    let before = engine.meta_store.get_chunk_meta(key).unwrap().unwrap();
                    let reconciled = engine
                        .reconcile_immutable(key, data.len() as u32, crc32c::crc32c(data), tag)
                        .unwrap();
                    assert_eq!(reconciled.meta(), &before);
                    let mut actual = vec![0; data.len()];
                    reconciled.pread(&mut actual, 0).unwrap();
                    assert_eq!(&actual, data);
                }
                assert_eq!(engine.meta_store.query_used_size(b"ec").unwrap(), accounted);
                assert_eq!(engine.used_size(), allocated);
            }
        }
        config.create = false;
        let engine = Engine::open(&config).unwrap();
        for (key, data) in &objects {
            let chunk = engine
                .reconcile_immutable(key, data.len() as u32, crc32c::crc32c(data), tag)
                .unwrap();
            let mut actual = vec![0; data.len()];
            chunk.pread(&mut actual, 0).unwrap();
            assert_eq!(&actual, data);
        }
    }

    #[test]
    fn test_engine_reconcile_immutable_barrier_failures() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let key = b"ec-barrier-errors";
        let data = b"data must precede the metadata WAL barrier";
        let checksum = crc32c::crc32c(data);
        let tag = b"barrier-operation";
        let original = engine
            .create_immutable_with_context(
                key,
                data,
                checksum,
                false,
                &ImmutableCreateContext {
                    desired_etag: tag,
                    ..Default::default()
                },
            )
            .unwrap();
        let before = original.meta().clone();
        let accounted = engine.meta_store.query_used_size(b"ec").unwrap();
        let allocated = engine.used_size();
        let wal_called = AtomicBool::new(false);
        let result = engine.reconcile_immutable_with_barriers(
            key,
            data.len() as u32,
            checksum,
            tag,
            |_| Err(Error::IoError("injected data barrier refusal".into())),
            || {
                wal_called.store(true, Ordering::SeqCst);
                engine.meta_store.sync_wal()
            },
        );
        assert!(matches!(result, Err(Error::IoError(_))));
        assert!(!wal_called.load(Ordering::SeqCst));

        // Remove only the cache entry while original keeps the allocation
        // referenced. The failing path must install a new persistent reference.
        engine.meta_cache.entry_by_ref(key.as_slice()).remove();
        let data_synced = AtomicBool::new(false);
        for _ in 0..2 {
            let result = engine.reconcile_immutable_with_barriers(
                key,
                data.len() as u32,
                checksum,
                tag,
                |chunk| {
                    Engine::sync_immutable_data(chunk)?;
                    data_synced.store(true, Ordering::SeqCst);
                    Ok(())
                },
                || {
                    assert!(data_synced.load(Ordering::SeqCst));
                    Err(Error::RocksDBError("injected WAL barrier refusal".into()))
                },
            );
            assert!(matches!(result, Err(Error::RocksDBError(_))));
            assert_eq!(engine.get(key).unwrap().unwrap().meta(), &before);
            assert_eq!(
                engine.meta_store.get_chunk_meta(key).unwrap(),
                Some(before.clone())
            );
            assert_eq!(engine.meta_store.query_used_size(b"ec").unwrap(), accounted);
        }
        drop(original);
        assert_eq!(engine.used_size(), allocated);
        let chunk = engine
            .reconcile_immutable(key, data.len() as u32, checksum, tag)
            .unwrap();
        assert_eq!(chunk.meta(), &before);
        assert_eq!(engine.used_size(), allocated);
        assert_eq!(engine.meta_store.query_used_size(b"ec").unwrap(), accounted);
    }

    #[test]
    fn test_engine_reconcile_immutable_rejects_prepare_and_cache_only() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let key = b"ec-prepared-only";
        let data = b"a prepared record must not become a seal receipt";
        let tag = b"prepared-operation";
        let checksum = crc32c::crc32c(data);
        let mut request = UpdateReq {
            data: data.as_ptr() as u64,
            length: data.len() as u32,
            checksum,
            desired_tag: tag,
            ..Default::default()
        };
        let pending = engine.update_chunk(key, &mut request).unwrap();
        let staged = engine.query_uncommitted_chunks(b"ec").unwrap();
        assert_eq!(staged.len(), 1);
        let barrier_called = AtomicBool::new(false);
        let assert_not_confirmed = || {
            let result = engine.reconcile_immutable_with_barriers(
                key,
                data.len() as u32,
                checksum,
                tag,
                |_| {
                    barrier_called.store(true, Ordering::SeqCst);
                    Ok(())
                },
                || {
                    barrier_called.store(true, Ordering::SeqCst);
                    Ok(())
                },
            );
            assert!(matches!(result, Err(Error::MetaError(_))));
            assert!(!barrier_called.load(Ordering::SeqCst));
            assert_eq!(engine.query_uncommitted_chunks(b"ec").unwrap(), staged);
            assert!(engine.meta_store.get_chunk_meta(key).unwrap().is_none());
        };
        assert_not_confirmed();
        let mut cache_only = pending.chunk.clone();
        cache_only.set_committed();
        engine
            .meta_cache
            .entry_by_ref(key.as_slice())
            .insert(Arc::new(cache_only));
        assert_not_confirmed();
        engine.meta_cache.entry_by_ref(key.as_slice()).remove();
        drop(pending);
    }

    #[test]
    fn test_engine_reconcile_immutable_checks_actual_metadata() {
        use derse::Serialize;
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let key = b"ec-metadata-identity";
        let data = b"check the real committed record and the fixed allocation";
        let checksum = crc32c::crc32c(data);
        let tag = b"metadata-operation";
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
        let mut different = original.as_ref().clone();
        different.set_chain_ver(original.meta().chain_ver + 1);
        engine
            .meta_cache
            .entry_by_ref(key.as_slice())
            .insert(Arc::new(different));
        assert!(matches!(
            engine.reconcile_immutable(key, data.len() as u32, checksum, tag),
            Err(Error::MetaError(_))
        ));
        engine
            .meta_cache
            .entry_by_ref(key.as_slice())
            .insert(original.clone());
        let write_meta = |meta: &ChunkMeta| {
            let mut batch = RocksDB::new_write_batch();
            let bytes: derse::DownwardBytes = meta.serialize().unwrap();
            batch.put(MetaKey::chunk_meta_key(key), bytes.as_slice());
            engine.meta_store.write(batch, true).unwrap();
        };
        let mut uncommitted = original.meta().clone();
        uncommitted.uncommitted = true;
        write_meta(&uncommitted);
        assert!(matches!(
            engine.reconcile_immutable(key, data.len() as u32, checksum, tag),
            Err(Error::MetaError(_))
        ));
        write_meta(original.meta());
        assert_eq!(
            engine
                .reconcile_immutable(key, data.len() as u32, checksum, tag,)
                .unwrap()
                .meta(),
            original.meta()
        );
    }

    #[test]
    fn test_engine_create_immutable_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        };
        let key = b"ec-fragment";
        let data: Vec<u8> = (0..4097).map(|i| (i * 37 + 11) as u8).collect();
        let checksum = crc32c::crc32c(&data);
        {
            let engine = Engine::open(&config).unwrap();
            let chunk = engine.create_immutable(key, &data, checksum, true).unwrap();
            assert_eq!(chunk.meta().len, data.len() as u32);
            assert_eq!(chunk.meta().checksum, checksum);
            assert_eq!(chunk.meta().chunk_ver, 1);
            assert!(!chunk.meta().uncommitted);
            let position = chunk.meta().pos;
            for replacement in [&data[..], &b"different bytes"[..]] {
                assert_eq!(
                    engine
                        .create_immutable(key, replacement, crc32c::crc32c(replacement), true)
                        .unwrap_err(),
                    Error::ChunkAlreadyExists
                );
            }
            let existing = engine.get(key).unwrap().unwrap();
            assert_eq!(existing.meta().pos, position);
            let mut actual = vec![0; data.len()];
            existing.pread(&mut actual, 0).unwrap();
            assert_eq!(actual, data);
            assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
        }

        // Clean reopen checks durable metadata/data visibility, not power loss.
        config.create = false;
        let engine = Engine::open(&config).unwrap();
        let existing = engine.get(key).unwrap().unwrap();
        let mut actual = vec![0; data.len()];
        existing.pread(&mut actual, 0).unwrap();
        assert_eq!(actual, data);
        assert_eq!(existing.meta().checksum, checksum);
        assert_eq!(
            engine
                .create_immutable(key, &data, checksum, true)
                .unwrap_err(),
            Error::ChunkAlreadyExists
        );
        assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
    }

    #[test]
    fn test_engine_create_immutable_context_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        };
        let key = b"ec-context";
        let data: Vec<u8> = (0..4097).map(|i| (i * 29 + 7) as u8).collect();
        let checksum = crc32c::crc32c(&data);
        let expected;
        {
            let engine = Engine::open(&config).unwrap();
            // Include NUL and non-UTF-8 bytes: tags are opaque, bounded bytes.
            let tag: Vec<u8> = (0..MAX_IMMUTABLE_ETAG_LEN)
                .map(|i| (i * 13) as u8)
                .collect();
            let context = ImmutableCreateContext {
                chain_ver: 17,
                last_request_id: u64::MAX - 3,
                last_client_low: 0x0123_4567_89ab_cdef,
                last_client_high: 0xfedc_ba98_7654_3210,
                desired_etag: &tag,
            };
            let chunk = engine
                .create_immutable_with_context(key, &data, checksum, true, &context)
                .unwrap();
            expected = chunk.meta().clone();
            assert_eq!(expected.chain_ver, context.chain_ver);
            assert_eq!(expected.chunk_ver, 1);
            assert_eq!(expected.last_request_id, context.last_request_id);
            assert_eq!(expected.last_client_low, context.last_client_low);
            assert_eq!(expected.last_client_high, context.last_client_high);
            assert_eq!(expected.etag.as_slice(), tag);
            assert!(!expected.uncommitted);
            // Reusing a key cannot overwrite its already committed context.
            assert_eq!(
                engine
                    .create_immutable_with_context(
                        key,
                        &data,
                        checksum,
                        true,
                        &ImmutableCreateContext::default(),
                    )
                    .unwrap_err(),
                Error::ChunkAlreadyExists
            );
            assert_eq!(engine.get(key).unwrap().unwrap().meta(), &expected);
        }

        // The tag input and original Engine are gone; all context fields must
        // survive a clean reopen through the same metadata commit as the data.
        config.create = false;
        let engine = Engine::open(&config).unwrap();
        let chunk = engine.get(key).unwrap().unwrap();
        assert_eq!(chunk.meta(), &expected);
        let mut actual = vec![0; data.len()];
        chunk.pread(&mut actual, 0).unwrap();
        assert_eq!(actual, data);
        assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
    }

    #[test]
    fn test_engine_create_immutable_context_validation() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let tag = vec![0x5a; MAX_IMMUTABLE_ETAG_LEN + 1];
        let invalid = ImmutableCreateContext {
            desired_etag: &tag,
            ..Default::default()
        };
        assert!(matches!(
            engine.create_immutable_with_context(b"ec-invalid-tag", b"", 0, true, &invalid),
            Err(Error::InvalidArg(_))
        ));
        assert_eq!(engine.metrics.allocate_times.load(Ordering::Acquire), 0);
        assert_eq!(engine.used_size(), UsedSize::default());
        assert!(engine.writing_list.is_empty());
        assert!(engine.get(b"ec-invalid-tag").unwrap().is_none());

        let chunk = engine
            .create_immutable_with_context(
                b"ec-zero-context",
                b"",
                0,
                true,
                &ImmutableCreateContext::default(),
            )
            .unwrap();
        assert_eq!(chunk.meta().chain_ver, 0);
        assert_eq!(chunk.meta().last_request_id, 0);
        assert_eq!(chunk.meta().last_client_low, 0);
        assert_eq!(chunk.meta().last_client_high, 0);
        assert!(!chunk.meta().etag.is_empty());
        assert!(chunk.meta().etag.len() <= 16);
    }

    #[test]
    fn test_engine_create_immutable_validation() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        for key in [&b""[..], &b"e"[..]] {
            assert!(matches!(
                engine.create_immutable(key, b"", 0, true),
                Err(Error::InvalidArg(_))
            ));
        }
        for data in [&b""[..], &b"bad checksum"[..]] {
            assert!(matches!(
                engine.create_immutable(b"ec-invalid", data, crc32c::crc32c(data) ^ 1, true),
                Err(Error::ChecksumMismatch(_))
            ));
        }
        // Only allocate this input in RAM; rejection precedes disk allocation
        // and checksum traversal, avoiding a 64 MiB allocator group on disk.
        let oversized = vec![0; CHUNK_SIZE_ULTRA.0 as usize + 1];
        assert!(matches!(
            engine.create_immutable(b"ec-oversized", &oversized, 0, true),
            Err(Error::InvalidArg(_))
        ));
        drop(oversized);
        assert_eq!(engine.used_size(), UsedSize::default());
        assert!(engine.get(b"ec-invalid").unwrap().is_none());
        assert!(engine.get(b"ec-oversized").unwrap().is_none());
        assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());

        engine.set_allow_to_allocate(false);
        assert_eq!(
            engine
                .create_immutable(b"ec-empty", b"", 0, true)
                .unwrap_err(),
            Error::NoSpace
        );
        assert!(engine.get(b"ec-empty").unwrap().is_none());
        engine.set_allow_to_allocate(true);
        let empty = engine.create_immutable(b"ec-empty", b"", 0, false).unwrap();
        assert_eq!(empty.meta().len, 0);
        assert_eq!(empty.meta().checksum, 0);
        assert!(!empty.meta().uncommitted);
        assert_eq!(
            engine
                .create_immutable(b"ec-empty", b"", 0, false)
                .unwrap_err(),
            Error::ChunkAlreadyExists
        );
    }

    #[test]
    fn test_engine_create_immutable_concurrent() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let gate = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for writer in 0..8u8 {
                let engine = &engine;
                let gate = &gate;
                handles.push(scope.spawn(move || {
                    let data = vec![writer; 4097];
                    let checksum = crc32c::crc32c(&data);
                    gate.wait();
                    (
                        writer,
                        engine.create_immutable(b"ec-race", &data, checksum, true),
                    )
                }));
            }
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        let mut winner = None;
        for (writer, result) in results {
            match result {
                Ok(chunk) => {
                    assert!(
                        winner.replace(writer).is_none(),
                        "multiple creates succeeded"
                    );
                    assert_eq!(chunk.meta().chunk_ver, 1);
                }
                Err(error) => assert_eq!(error, Error::ChunkAlreadyExists),
            }
        }
        let data = vec![winner.expect("no create succeeded"); 4097];
        let chunk = engine.get(b"ec-race").unwrap().unwrap();
        let mut actual = vec![0; data.len()];
        chunk.pread(&mut actual, 0).unwrap();
        assert_eq!(actual, data);
        assert_eq!(chunk.meta().checksum, crc32c::crc32c(&data));
        assert_eq!(engine.query_all_chunks(b"ec").unwrap().len(), 1);
        assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
    }

    #[test]
    fn test_engine_create_immutable_preserves_pending_update() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 2,
        })
        .unwrap();
        let data = b"existing pending update";
        let mut req = UpdateReq {
            length: data.len() as u32,
            checksum: crc32c::crc32c(data),
            data: data.as_ptr() as u64,
            ..Default::default()
        };
        let pending = engine.update_chunk(b"ec-pending", &mut req).unwrap();
        assert!(matches!(
            engine.create_immutable(b"ec-pending", b"", 0, true),
            Err(Error::InvalidArg(_))
        ));
        assert!(engine.get(b"ec-pending").unwrap().is_none());
        assert_eq!(engine.query_uncommitted_chunks(b"ec").unwrap().len(), 1);
        let chunk = engine.commit_chunk(pending, true).unwrap();
        let mut actual = vec![0; data.len()];
        chunk.pread(&mut actual, 0).unwrap();
        assert_eq!(actual, data);
        assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
    }

    #[test]
    fn test_engine_create_immutable_persist_failure_then_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = EngineConfig {
            path: dir.path().join("engine"),
            create: true,
            prefix_len: 2,
        };
        let key = b"ec-persist-failure";
        let rejected = vec![0x29; 4097];
        let replacement: Vec<u8> = (0..4097).map(|i| (i * 17 + 3) as u8).collect();
        std::fs::create_dir(&config.path).unwrap();

        {
            let mut engine = Engine::open(&config).unwrap();
            // A separately initialized read-only RocksDB rejects the actual
            // writing-log put after allocation, data I/O and holder insertion.
            // The allocator retains the original writable store; no production
            // fault hook or shared process-wide state is needed.
            let mut readonly_config = MetaStoreConfig {
                rocksdb: RocksDBConfig {
                    path: dir.path().join("readonly-meta"),
                    create: true,
                    ..Default::default()
                },
                prefix_len: config.prefix_len,
            };
            drop(MetaStore::open(&readonly_config).unwrap());
            readonly_config.rocksdb.create = false;
            readonly_config.rocksdb.read_only = true;
            let readonly_store = Arc::new(MetaStore::open(&readonly_config).unwrap());
            let writable_store = std::mem::replace(&mut engine.meta_store, readonly_store);

            for _ in 0..3 {
                assert!(matches!(
                    engine.create_immutable(key, &rejected, crc32c::crc32c(&rejected), true),
                    Err(Error::RocksDBError(_))
                ));
                assert!(engine.get(key).unwrap().is_none());
                let pending = engine.writing_list.get(b"ec".as_slice()).unwrap();
                assert_eq!(pending.len(), 1);
                assert!(pending.get(key.as_slice()).unwrap().abort);
            }

            engine.meta_store = writable_store;
            assert!(engine.get(key).unwrap().is_none());
            let chunk = engine
                .create_immutable(key, &replacement, crc32c::crc32c(&replacement), true)
                .unwrap();
            let mut actual = vec![0; replacement.len()];
            chunk.pread(&mut actual, 0).unwrap();
            assert_eq!(actual, replacement);
            assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
            assert!(engine.retained_writing.lock().unwrap().is_empty());
        }

        // This is a deterministic refused write and clean reopen, not an
        // ambiguous acknowledgement or power-loss test.
        config.create = false;
        let engine = Engine::open(&config).unwrap();
        let chunk = engine.get(key).unwrap().unwrap();
        let mut actual = vec![0; replacement.len()];
        chunk.pread(&mut actual, 0).unwrap();
        assert_eq!(actual, replacement);
        assert_eq!(chunk.meta().checksum, crc32c::crc32c(&replacement));
        assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
    }

    #[test]
    fn test_engine_immutable_failed_log_replacement_retains_positions() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = EngineConfig {
            path: dir.path().join("engine"),
            create: true,
            prefix_len: 2,
        };
        std::fs::create_dir(&config.path).unwrap();
        let stage_key = b"ec-retained-stage";
        let live_key = b"ok-committed";
        let initial_data = vec![0x19; 4097];
        let stage_data = vec![0x35; 4097];
        let live_data = vec![0xc7; 4097];
        let old_position;
        let live_position;
        {
            let mut engine = Engine::open(&config).unwrap();
            // This real preparation leaves a synchronous writing log pointing
            // to old_position. Dropping its owner aborts only the memory state.
            let mut initial_request = UpdateReq {
                length: initial_data.len() as u32,
                checksum: crc32c::crc32c(&initial_data),
                data: initial_data.as_ptr() as u64,
                ..Default::default()
            };
            let pending = engine
                .update_chunk(stage_key, &mut initial_request)
                .unwrap();
            old_position = pending.meta().pos;
            assert_eq!(old_position.chunk_size(), CHUNK_SIZE_SMALL);
            drop(pending);

            let mut readonly_config = MetaStoreConfig {
                rocksdb: RocksDBConfig {
                    path: dir.path().join("readonly-meta"),
                    create: true,
                    ..Default::default()
                },
                prefix_len: config.prefix_len,
            };
            drop(MetaStore::open(&readonly_config).unwrap());
            readonly_config.rocksdb.create = false;
            readonly_config.rocksdb.read_only = true;
            let writable = std::mem::replace(
                &mut engine.meta_store,
                Arc::new(MetaStore::open(&readonly_config).unwrap()),
            );

            // Each replacement gets a new allocation, but its actual log put
            // fails. The original on-disk log must retain exclusive use of its
            // position regardless of how many replacements were attempted.
            for attempt in 1..=MAX_RETAINED_WRITING_PER_KEY {
                assert!(matches!(
                    engine.create_immutable(
                        stage_key,
                        &stage_data,
                        crc32c::crc32c(&stage_data),
                        true,
                    ),
                    Err(Error::RocksDBError(_))
                ));
                let retained = engine.retained_writing.lock().unwrap();
                let candidates = retained.get(stage_key.as_slice()).unwrap();
                assert_eq!(candidates.len(), attempt);
                assert_eq!(candidates[0].meta().pos, old_position);
                assert!(candidates.iter().all(
                    |candidate| candidate.meta().pos.chunk_size() == old_position.chunk_size()
                ));
            }
            let allocations = engine.metrics.allocate_times.load(Ordering::Acquire);
            assert!(matches!(
                engine.create_immutable(
                    stage_key,
                    &stage_data,
                    crc32c::crc32c(&stage_data),
                    true,
                ),
                Err(Error::InvalidArg(message)) if message.contains("retention limit")
            ));
            assert_eq!(
                engine.metrics.allocate_times.load(Ordering::Acquire),
                allocations
            );

            engine.meta_store = writable;
            let live = engine
                .create_immutable(live_key, &live_data, crc32c::crc32c(&live_data), true)
                .unwrap();
            live_position = live.meta().pos;
            assert_eq!(live_position.chunk_size(), old_position.chunk_size());
            let retained = engine.retained_writing.lock().unwrap();
            for candidate in retained.get(stage_key.as_slice()).unwrap() {
                assert_ne!(live_position, candidate.meta().pos);
            }
        }

        // Clean reopen deterministically exercises the old durable log and
        // allocator recovery. This is not a physical power-loss experiment.
        config.create = false;
        {
            let engine = Engine::open(&config).unwrap();
            assert!(engine.retained_writing.lock().unwrap().is_empty());
            let staged = engine.query_uncommitted_chunks(b"ec").unwrap();
            assert_eq!(staged.len(), 1);
            assert_eq!(staged[0].1.pos, old_position);
            assert!(engine.get(stage_key).unwrap().is_none());
            let live = engine.get(live_key).unwrap().unwrap();
            assert_eq!(live.meta().pos, live_position);
            let mut actual = vec![0; live_data.len()];
            live.pread(&mut actual, 0).unwrap();
            assert_eq!(actual, live_data);

            engine
                .create_immutable(stage_key, &stage_data, crc32c::crc32c(&stage_data), true)
                .unwrap();
            assert!(engine.retained_writing.lock().unwrap().is_empty());
            assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
        }
        let engine = Engine::open(&config).unwrap();
        for (key, expected) in [
            (stage_key.as_slice(), &stage_data),
            (live_key.as_slice(), &live_data),
        ] {
            let chunk = engine.get(key).unwrap().unwrap();
            let mut actual = vec![0; expected.len()];
            chunk.pread(&mut actual, 0).unwrap();
            assert_eq!(&actual, expected);
        }
        assert!(engine.query_uncommitted_chunks(b"ec").unwrap().is_empty());
    }

    #[test]
    fn test_engine_normal() {
        let dir = tempfile::tempdir().unwrap();

        let chunk_id = "chunk01".as_bytes();
        let bytes = "hello world!".as_bytes();

        let mut config: EngineConfig = toml::from_str(&format!(
            r#"
                path = {:?}
                create = true
                prefix_len = 0
            "#,
            dir.path()
        ))
        .unwrap();

        {
            let engine = Engine::open(&config).unwrap();
            let _ = format!("{:?}", engine);
            assert!(engine.get(chunk_id).unwrap().is_none());
            assert_eq!(engine.used_size(), UsedSize::default());
            assert!(engine.move_chunk(chunk_id).is_ok());

            let allocator = engine.allocators.select_by_size(CHUNK_SIZE_NORMAL).unwrap();
            for _ in 0..1000 {
                let chunk = allocator.allocate(true).unwrap();
                assert_eq!(chunk.meta().pos, Position::default());
            }

            let s = CHUNK_SIZE_NORMAL * GroupId::COUNT;
            assert_eq!(engine.used_size().allocated_size, s);
            assert_eq!(engine.used_size().reserved_size, s);

            // SAFETY: This is an exceptional case for testing the function itself.
            // In normal usage, speed_up_quit() should ONLY be called immediately before process exit.
            // This test intentionally violates that contract to verify the function's behavior,
            // but this will cause memory leaks that persist for the remainder of the test process.
            unsafe {
                engine.speed_up_quit();
            }
        }

        {
            let engine = Engine::open(&config).unwrap();
            assert!(engine.get(chunk_id).unwrap().is_none());
            assert_eq!(engine.used_size(), UsedSize::default());
            assert!(engine.write(chunk_id, bytes, 0, 0).is_err());

            let checksum = crc32c::crc32c(bytes);
            let chunk = engine.write(chunk_id, bytes, 0, checksum).unwrap();
            assert_eq!(chunk.meta().pos.chunk_size(), CHUNK_SIZE_SMALL);
            assert_eq!(chunk.meta().pos.group(), 0);
            assert_eq!(chunk.meta().pos.cluster(), 0);
            assert_eq!(chunk.meta().chunk_ver, 1);

            let s = CHUNK_SIZE_SMALL * GroupId::COUNT;
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL);

            let chunk = engine.get(chunk_id).unwrap().unwrap();
            assert_eq!(chunk.meta().chunk_ver, 1);
            assert_eq!(chunk.meta().len, 12);

            let mut buf = [0u8; 12];
            assert!(chunk.pread(&mut buf, 0).is_ok());
            assert_eq!(buf, bytes);
            assert_eq!(chunk.meta().checksum, crc32c::crc32c(&buf));

            let fd_and_offset = chunk.fd_and_offset();
            assert_ne!(fd_and_offset.fd, 0);
            assert_eq!(fd_and_offset.offset, chunk.meta().pos.offset());
        }

        {
            config.create = false;
            let engine = Engine::open(&config).unwrap();
            let chunk0 = engine.get(chunk_id).unwrap().unwrap();

            let s = CHUNK_SIZE_SMALL * GroupId::COUNT;
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL);

            let mut buf = [0u8; 12];
            assert!(chunk0.pread(&mut buf, 0).is_ok());
            assert_eq!(buf, bytes);
            assert_eq!(chunk0.meta().pos.chunk_size(), CHUNK_SIZE_SMALL);
            assert_eq!(chunk0.meta().pos.group(), 0);
            assert_eq!(chunk0.meta().pos.cluster(), 0);
            assert_eq!(chunk0.meta().checksum, crc32c::crc32c(&buf));

            let chunk1 = engine.move_chunk(chunk_id).unwrap().unwrap();
            let mut buf = [0u8; 12];
            assert!(chunk1.pread(&mut buf, 0).is_ok());
            assert_eq!(buf, bytes);
            assert_eq!(chunk1.meta().pos.chunk_size(), CHUNK_SIZE_SMALL);
            assert_eq!(chunk1.meta().pos.index(), 1);
            assert_eq!(chunk1.meta().checksum, crc32c::crc32c(&buf));
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL * 2);

            let allocator = engine.allocators.select_by_size(CHUNK_SIZE_SMALL).unwrap();
            assert_eq!(
                allocator.allocate(true).unwrap().meta().pos,
                Position::new(GroupId::new(CHUNK_SIZE_SMALL, 0, 0), 2)
            );
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL * 2);

            drop(chunk0);
            assert_eq!(
                allocator.allocate(true).unwrap().meta().pos,
                Position::new(GroupId::new(CHUNK_SIZE_SMALL, 0, 0), 0)
            );
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL);

            drop(chunk1); // still in cache.
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL);

            let chunk2 = engine
                .write(chunk_id, bytes, 12, crc32c::crc32c(bytes))
                .unwrap();
            assert_eq!(chunk2.meta().len, 24);
            assert_eq!(chunk2.meta().pos.index(), 1);
            assert_eq!(chunk2.meta().chunk_ver, 2);
            let mut buf = [0u8; 12];
            chunk2.pread(&mut buf, 12).unwrap();
            assert_eq!(buf, bytes);
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL);

            let empty = [0u8; 12];
            let chunk3 = engine
                .write(chunk_id, &empty, 0, crc32c::crc32c(&empty))
                .unwrap();
            assert_eq!(chunk3.meta().len, 24);
            assert_eq!(chunk3.meta().pos.index(), 0);
            assert_eq!(chunk3.meta().chunk_ver, 3);
            let mut buf = [0u8; 12];
            chunk3.pread(&mut buf, 0).unwrap();
            assert_eq!(buf, [0u8; 12]);
            chunk3.pread(&mut buf, 12).unwrap();
            assert_eq!(buf, bytes);
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL * 2);

            engine.remove(chunk_id).unwrap();
            engine.remove(chunk_id).unwrap();
            assert!(engine.get(chunk_id).unwrap().is_none());
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL * 2);

            let mut buf = [0u8; 12];
            chunk3.pread(&mut buf, 0).unwrap();
            assert_eq!(buf, [0u8; 12]);
            chunk3.pread(&mut buf, 12).unwrap();
            assert_eq!(buf, bytes);

            drop(chunk3);
            assert_eq!(engine.used_size().reserved_size, s - CHUNK_SIZE_SMALL);

            drop(chunk2);
            assert_eq!(engine.used_size().reserved_size, s);
        }

        {
            let engine = Engine::open(&config).unwrap();
            let s = CHUNK_SIZE_SMALL * GroupId::COUNT;
            assert_eq!(engine.used_size().reserved_size, s);

            engine.start_allocate_workers(2);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[test]
    fn test_engine_list_chunks() {
        let dir = tempfile::tempdir().unwrap();

        // 1. prepare.
        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };

        // 2. write chunks.
        let engine = Engine::open(&config).unwrap();
        const N: usize = 512;
        for i in 1..=N {
            let data = vec![i as u8; i * 1024];
            let checksum = crc32c::crc32c(&data);
            let chunk = engine
                .write(&i.to_be_bytes(), &data, i as u32 * 512, checksum)
                .unwrap();
            assert_eq!(chunk.meta().chunk_ver, 1);
        }

        // 3. list all chunks.
        drop(engine);
        let engine = Engine::open(&config).unwrap();
        let chunks = engine.query_chunks([], [], u64::MAX).unwrap();
        assert_eq!(chunks.len(), N);
        let mut buffer = create_aligned_buf(CHUNK_SIZE_LARGE);
        for (i, (chunk_id, chunk_meta)) in chunks.iter().enumerate() {
            let i = N - i; // reversed order.
            assert_eq!(&i.to_be_bytes(), &chunk_id[..]);
            let offset = i * 512;
            let data_len = i * 1024;
            let total = Size::from(offset + data_len);
            assert_eq!(chunk_meta.len, total);
            assert_eq!(
                chunk_meta.pos.chunk_size(),
                std::cmp::max(total.next_power_of_two(), CHUNK_SIZE_SMALL)
            );

            let chunk = engine.get(chunk_id).unwrap().unwrap();
            assert_eq!(chunk.meta(), chunk_meta);

            chunk.pread(&mut buffer[..total.into()], 0).unwrap();
            assert!(buffer[..offset].iter().all(|v| *v == 0));
            assert!(buffer[offset..total.into()].iter().all(|v| *v == i as u8));
        }

        let key = vec![1u8; 1 << 20];
        engine.write(&key, &[], 0, 0).unwrap();

        let count = engine.batch_remove([], [], u64::MAX).unwrap();
        assert_eq!(count, 1 + N as u64);
        for i in 1..=N {
            assert!(engine.get(&i.to_be_bytes()).unwrap().is_none());
        }
        let count = engine.batch_remove([], [], u64::MAX).unwrap();
        assert_eq!(count, 0);

        let chunks = engine.query_chunks([], [], u64::MAX).unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_engine_load() {
        let dir = tempfile::tempdir().unwrap();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();

        // 1. prepare.
        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };

        // 2. write chunks.
        let engine = Engine::open(&config).unwrap();

        let mut data = create_aligned_buf(CHUNK_SIZE_SMALL);
        for i in 0..512u32 {
            data.fill(i as u8);
            let checksum = crc32c::crc32c(&data);
            let chunk = engine.write(&i.to_le_bytes(), &data, 0, checksum).unwrap();
            assert_eq!(chunk.meta().chunk_ver, 1);
        }

        let vec = engine.query_chunks([], [], 10000).unwrap();
        assert_eq!(vec.len(), 512);

        for i in 0..256u32 {
            engine.remove(&i.to_le_bytes()).unwrap();
        }

        let vec = engine.query_chunks([], [], 10000).unwrap();
        assert_eq!(vec.len(), 256);

        assert_eq!(engine.allocate_groups(0, 0, 8), 1);

        drop(engine);
        let engine = Engine::open(&config).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut buf = create_aligned_buf(CHUNK_SIZE_SMALL);
        for i in 0..512u32 {
            let chunk = engine.get(&i.to_le_bytes()).unwrap();
            if i < 256 {
                assert!(chunk.is_none());
            } else {
                let chunk = chunk.unwrap();
                chunk.pread(&mut buf, 0).unwrap();
                assert!(buf.iter().all(|&v| v == i as u8));
                assert_eq!(
                    chunk.meta().checksum,
                    crc32c::crc32c(&[i as u8; CHUNK_SIZE_SMALL.0 as _])
                );

                data.fill(!i as u8);
                let checksum = crc32c::crc32c(&data);
                let chunk = engine.write(&i.to_le_bytes(), &data, 0, checksum).unwrap();
                assert_eq!(chunk.meta().chunk_ver, 2);
            }
        }

        drop(engine);
        let engine = Engine::open(&config).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        for i in 0..512u32 {
            let chunk = engine.get(&i.to_le_bytes()).unwrap();
            if i < 256 {
                assert!(chunk.is_none());
            } else {
                let chunk = chunk.unwrap();
                chunk.pread(&mut buf, 0).unwrap();
                assert!(buf.iter().all(|&v| v == !i as u8));
                assert_eq!(
                    chunk.meta().checksum,
                    crc32c::crc32c(&[!i as u8; CHUNK_SIZE_SMALL.0 as _])
                );
            }
        }

        let vec = engine.query_chunks([], [], 10000).unwrap();
        assert_eq!(vec.len(), 256);

        let vec = engine
            .query_chunks_by_timestamp(&[], 0, u64::MAX, 10000)
            .unwrap();
        assert_eq!(vec.len(), 256);
    }

    #[test]
    fn test_engine_compact() {
        let dir = tempfile::tempdir().unwrap();

        // 1. prepare.
        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };

        // 2. write chunks.
        let engine = Engine::open(&config).unwrap();

        let mut data = create_aligned_buf(CHUNK_SIZE_SMALL);
        for i in 0..512u32 {
            data.fill(i as u8);
            let checksum = crc32c::crc32c(&data);
            let chunk = engine.write(&i.to_le_bytes(), &data, 0, checksum).unwrap();
            assert_eq!(chunk.meta().chunk_ver, 1);
        }

        engine.remove(&255u32.to_le_bytes()).unwrap();
        let chunk1 = engine.allocators.allocate(CHUNK_SIZE_SMALL, true);
        engine.remove(&511u32.to_le_bytes()).unwrap();
        let chunk2 = engine.allocators.allocate(CHUNK_SIZE_SMALL, true);

        // 3. remove some chunks.
        for i in 0..512u32 {
            if i % 2 == 0 {
                engine.remove(&i.to_le_bytes()).unwrap();
            }
        }
        assert_eq!(engine.used_size().allocated_size, CHUNK_SIZE_SMALL * 512);
        assert_eq!(engine.used_size().reserved_size, CHUNK_SIZE_SMALL * 256);
        assert_eq!(engine.allocate_groups(0, 0, 16), 0);

        // 4. start a bg read thread.
        let stop = Arc::new(AtomicBool::default());
        let stop_clone = stop.clone();
        let engine_clone = engine.clone();
        let thread = std::thread::spawn(move || {
            let engine = engine_clone;
            let stop = stop_clone;
            while !stop.load(Ordering::Acquire) {
                let mut buf = create_aligned_buf(CHUNK_SIZE_SMALL);
                for i in 0..512u32 {
                    let chunk = engine.get(&i.to_le_bytes()).unwrap();
                    if i % 2 == 0 || i == 255 || i == 511 {
                        assert!(chunk.is_none());
                    } else {
                        let chunk = chunk.unwrap();
                        chunk.pread(&mut buf, 0).unwrap();
                        assert!(buf.iter().all(|&v| v == i as u8));
                        assert_eq!(
                            chunk.meta().checksum,
                            crc32c::crc32c(&[i as u8; CHUNK_SIZE_SMALL.0 as _])
                        );
                    }
                }
            }
        });

        // 5. compact.
        assert_eq!(engine.compact_groups(10000), 0);
        assert_eq!(engine.compact_groups(0), 1);
        assert_eq!(engine.used_size().allocated_size, CHUNK_SIZE_SMALL * 512);
        assert_eq!(engine.used_size().reserved_size, CHUNK_SIZE_SMALL * 256);

        // 6. deallocate previous group.
        drop(chunk1);
        drop(chunk2);
        assert_eq!(engine.compact_groups(0), 1);
        assert_eq!(engine.allocate_groups(0, 0, 16), 1);
        assert_eq!(engine.used_size().allocated_size, CHUNK_SIZE_SMALL * 256);
        assert_eq!(engine.used_size().reserved_size, CHUNK_SIZE_SMALL * 2);
        assert_eq!(engine.compact_groups(1), 1);

        // 7. stop read chunks.
        stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
    }

    #[test]
    fn test_engine_truncate() {
        let dir = tempfile::tempdir().unwrap();

        // 1. prepare.
        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };

        // 2. write chunks.
        let engine = Engine::open(&config).unwrap();
        let mut data = create_aligned_buf(CHUNK_SIZE_SMALL);
        for i in 0..512u32 {
            data.fill(i as u8);
            let checksum = crc32c::crc32c(&data);
            let chunk = engine.write(&i.to_le_bytes(), &data, 0, checksum).unwrap();
            assert_eq!(chunk.meta().chunk_ver, 1);
        }

        // 3. extend chunks.
        for i in 0..512u32 {
            let length = i * 131;
            let chunk = engine.write(&i.to_le_bytes(), &[], length, 0).unwrap();
            assert_eq!(chunk.meta().chunk_ver, 2);
            assert_eq!(
                chunk.meta().len,
                std::cmp::max(length, CHUNK_SIZE_SMALL.into())
            );
        }

        // 4. truncate and check.
        let mut buf = create_aligned_buf(CHUNK_SIZE_NORMAL);
        for i in 0..512u32 {
            let length = i * 137;
            let chunk = engine.truncate(&i.to_le_bytes(), length).unwrap();
            assert_eq!(chunk.meta().chunk_ver, 3);
            assert_eq!(chunk.meta().len, length);
            chunk
                .pread(
                    &mut buf[..length.next_multiple_of(ALIGN_SIZE.into()) as usize],
                    0,
                )
                .unwrap();

            let bound = std::cmp::min(length, CHUNK_SIZE_SMALL.into()) as usize;
            assert!(buf[..bound].iter().all(|v| *v == i as u8));
            assert!(buf[bound..length as usize].iter().all(|v| *v == 0));
            assert_eq!(
                chunk.meta().checksum,
                crc32c::crc32c(&buf[..length as usize])
            );
        }

        // 4. check version.
        let chunk_id = &511u32.to_le_bytes();
        let mut req = UpdateReq {
            update_ver: 4,
            ..Default::default()
        };
        let chunk = engine.update(chunk_id, &mut req).unwrap();
        assert_eq!(req.out_chain_ver, 0);
        assert_eq!(req.out_commit_ver, 4);
        assert_eq!(req.out_checksum, chunk.meta().checksum);

        engine.update(chunk_id, &mut req).unwrap_err();
        assert_eq!(req.out_chain_ver, 0);
        assert_eq!(req.out_commit_ver, 4);
        assert_eq!(req.out_checksum, chunk.meta().checksum);

        req.update_ver = 6;
        engine.update(chunk_id, &mut req).unwrap_err();
        assert_eq!(req.out_chain_ver, 0);
        assert_eq!(req.out_commit_ver, 4);
        assert_eq!(req.out_checksum, chunk.meta().checksum);

        req.is_syncing = true;
        engine.update(chunk_id, &mut req).unwrap();
        req.is_syncing = false;
        assert_eq!(req.out_chain_ver, 0);
        assert_eq!(req.out_commit_ver, 6);
        assert_eq!(req.out_checksum, 0);
        assert_eq!(req.length, 0);

        req.chain_ver = 1;
        req.update_ver = 7;
        let chunk = engine.update(chunk_id, &mut req).unwrap();
        assert_eq!(req.out_chain_ver, 1);
        assert_eq!(req.out_commit_ver, 7);
        assert_eq!(req.out_checksum, chunk.meta().checksum);

        req.chain_ver = 0;
        req.update_ver = 8;
        engine.update(chunk_id, &mut req).unwrap_err();
        assert_eq!(req.out_chain_ver, 1);
        assert_eq!(req.out_commit_ver, 7);
        assert_eq!(req.out_checksum, chunk.meta().checksum);

        assert_eq!(
            format!("{:?}", chunk.as_ref()),
            format!("{:?}", chunk.meta())
        );
    }

    #[test]
    fn test_engine_checksum() {
        let dir = tempfile::tempdir().unwrap();

        // 1. prepare.
        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };

        // 2. write chunks.
        let engine = Engine::open(&config).unwrap();

        let data = b"etc";
        let checksum = crc32c::crc32c(data);
        engine.write(b"chunk", data, 0, checksum).unwrap();

        let data = b"zzz";
        let checksum = crc32c::crc32c(data);
        let chunk = engine.write(b"chunk", data, 3, checksum).unwrap();

        let mut buf = [0u8; 6];
        chunk.pread(&mut buf, 0).unwrap();
        assert_eq!(crc32c::crc32c(&buf), chunk.meta().checksum);

        // 3. write without checksum
        engine
            .update(
                b"chunk",
                &mut UpdateReq {
                    without_checksum: true,
                    length: data.len() as _,
                    offset: 6,
                    data: data.as_ptr() as u64,
                    expected_tag: unsafe {
                        std::mem::transmute::<&[u8], &[u8]>(chunk.meta().etag.as_slice())
                    },
                    desired_tag: b"desired_tag",
                    ..Default::default()
                },
            )
            .unwrap();

        let err = engine
            .update(
                b"chunk",
                &mut UpdateReq {
                    without_checksum: true,
                    length: data.len() as _,
                    offset: 6,
                    data: data.as_ptr() as u64,
                    expected_tag: b"mismatch",
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::ChunkETagMismatch(_)));

        let err = engine
            .update(
                b"chunk",
                &mut UpdateReq {
                    without_checksum: true,
                    length: data.len() as _,
                    offset: 6,
                    data: data.as_ptr() as u64,
                    create_new: true,
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::ChunkAlreadyExists));
    }

    #[test]
    fn test_set_allow_to_allocate() {
        let dir = tempfile::tempdir().unwrap();

        // 1. prepare.
        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };

        // 2. write chunks.
        let engine = Engine::open(&config).unwrap();
        assert_eq!(engine.allocate_ultra_groups(0, 1, 1), 0);

        engine.set_allow_to_allocate(false);
        assert_eq!(engine.allocate_groups(1, 1, 1), 0);
        assert_eq!(engine.allocate_ultra_groups(0, 1, 1), 0);

        let data = b"etc";
        let checksum = crc32c::crc32c(data);
        let err = engine.write(b"chunk", data, 0, checksum).unwrap_err();
        assert!(matches!(err, Error::NoSpace));
    }

    #[test]
    fn test_remove_update() {
        let dir = tempfile::tempdir().unwrap();

        // 1. prepare.
        let data = b"etc";
        let checksum = crc32c::crc32c(data);
        {
            let config = EngineConfig {
                path: dir.path().into(),
                create: true,
                ..Default::default()
            };
            let engine = Engine::open(&config).unwrap();

            engine.write(b"chunk", data, 0, checksum).unwrap();
        }

        // 2. remove.
        {
            let config = EngineConfig {
                path: dir.path().into(),
                create: false,
                ..Default::default()
            };
            let engine = Engine::open(&config).unwrap();
            let mut req = UpdateReq {
                is_remove: true,
                is_syncing: true,
                ..Default::default()
            };
            engine.update(b"chunk", &mut req).unwrap();
            assert!(!req.out_non_existent);
            assert_eq!(req.out_checksum, checksum);
        }
    }

    #[test]
    fn test_engine_writing_list() {
        let dir = tempfile::tempdir().unwrap();

        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };
        let engine = Engine::open(&config).unwrap();

        let chunks = engine.query_all_chunks(&[]).unwrap();
        assert!(chunks.is_empty());

        let chunk_id = "chunk01".as_bytes();
        let bytes = "hello world!".as_bytes();
        let mut req = UpdateReq {
            length: bytes.len() as _,
            data: bytes.as_ptr() as _,
            without_checksum: true,
            ..Default::default()
        };
        let mut chunk = engine.update_chunk(chunk_id, &mut req).unwrap();
        assert!(!engine
            .writing_list
            .entry(Default::default())
            .or_default()
            .is_empty());

        let err = engine.update_chunk(chunk_id, &mut req).unwrap_err();
        assert!(matches!(err, Error::InvalidArg(_)));

        let chunks = engine.query_chunks([], [], u64::MAX).unwrap();
        assert!(chunks.is_empty());

        let chunks = engine.query_all_chunks(&[]).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(&chunks[0].1, chunk.meta());

        chunk.chunk.set_chain_ver(3);
        let mut meta = chunk.meta().clone();
        engine.commit_chunks(vec![chunk], false).unwrap();
        assert!(engine
            .writing_list
            .entry(Default::default())
            .or_default()
            .is_empty());

        let chunks = engine.query_chunks([], [], u64::MAX).unwrap();
        assert_eq!(chunks.len(), 1);
        meta.uncommitted = false;
        assert_eq!(chunks[0].1, meta);

        let mut writing_chunks = vec![];
        let remove = engine
            .update_chunk(
                b"remove",
                &mut UpdateReq {
                    is_remove: true,
                    ..Default::default()
                },
            )
            .unwrap();
        writing_chunks.push(remove);

        let new_chunk = engine
            .update_chunk(
                b"new_chunk",
                &mut UpdateReq {
                    length: bytes.len() as _,
                    data: bytes.as_ptr() as _,
                    without_checksum: true,
                    ..Default::default()
                },
            )
            .unwrap();
        writing_chunks.push(new_chunk);

        let update = engine
            .update_chunk(
                chunk_id,
                &mut UpdateReq {
                    offset: bytes.len() as _,
                    length: bytes.len() as _,
                    data: bytes.as_ptr() as _,
                    without_checksum: true,
                    chain_ver: 3,
                    ..Default::default()
                },
            )
            .unwrap();
        writing_chunks.push(update);
        assert_eq!(
            engine
                .writing_list
                .entry(Default::default())
                .or_default()
                .len(),
            3
        );

        assert_eq!(engine.query_chunks([], [], u64::MAX).unwrap().len(), 1);
        let chunks = engine.query_all_chunks(&[]).unwrap();
        assert_eq!(chunks.len(), 3);
        for (id, meta) in chunks {
            if id == chunk_id {
                assert_eq!(meta.len as usize, bytes.len() * 2);
            } else if id.as_slice() == b"new_chunk" {
                assert_eq!(meta.len as usize, bytes.len());
            } else {
                assert_eq!(id.as_slice(), b"remove");
            }
        }

        engine.commit_chunks(writing_chunks, false).unwrap();
        assert!(engine
            .writing_list
            .entry(Default::default())
            .or_default()
            .is_empty());
    }

    #[test]
    fn test_engine_persist_writing_list() {
        let dir = tempfile::tempdir().unwrap();

        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };
        let engine = Engine::open(&config).unwrap();

        let chunk_id = "chunk01".as_bytes();
        let bytes = "hello world!".as_bytes();
        let mut req = UpdateReq {
            length: bytes.len() as _,
            data: bytes.as_ptr() as _,
            without_checksum: true,
            ..Default::default()
        };
        let chunk = engine.update_chunk(chunk_id, &mut req).unwrap();
        assert!(!engine
            .writing_list
            .entry(Default::default())
            .or_default()
            .is_empty());

        let mut chunks = engine.query_all_chunks(&[]).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(&chunks[0].1, chunk.meta());
        assert!(chunk.meta().uncommitted);

        let uncommitted_chunks = engine.query_uncommitted_chunks(&[]).unwrap();
        assert_eq!(uncommitted_chunks.len(), 1);
        assert_eq!(chunks, uncommitted_chunks);

        drop(chunk);
        drop(engine);

        let engine = Engine::open(&config).unwrap();
        let uncommitted_chunks = engine.query_uncommitted_chunks(&[]).unwrap();
        assert_eq!(uncommitted_chunks.len(), 1);
        assert_eq!(chunks, uncommitted_chunks);

        assert!(engine.get(chunk_id).unwrap().is_none());
        let chain_ver = 233;
        let uncommitted_chunks = engine.handle_uncommitted_chunks(&[], chain_ver).unwrap();
        assert_eq!(uncommitted_chunks.len(), 1);
        for chunk in &mut chunks {
            chunk.1.chain_ver = chain_ver;
        }
        assert_eq!(chunks, uncommitted_chunks);

        let chunk = engine.get(chunk_id).unwrap().unwrap();
        assert!(!chunk.meta().uncommitted);
        assert_eq!(chunk.meta().chain_ver, chain_ver);
    }

    #[test]
    fn test_engine_persist_writing_list_2() {
        let dir = tempfile::tempdir().unwrap();

        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };
        let engine = Engine::open(&config).unwrap();

        let chunk_id = "chunk01".as_bytes();
        let bytes = "hello world!".as_bytes();
        let mut req = UpdateReq {
            length: bytes.len() as _,
            data: bytes.as_ptr() as _,
            without_checksum: true,
            ..Default::default()
        };
        let _ = engine.update(chunk_id, &mut req).unwrap();
        assert!(engine
            .writing_list
            .entry(Default::default())
            .or_default()
            .is_empty());

        let mut req = UpdateReq {
            length: bytes.len() as _,
            data: bytes.as_ptr() as _,
            offset: bytes.len() as _,
            without_checksum: true,
            ..Default::default()
        };
        let chunk = engine.update_chunk(chunk_id, &mut req).unwrap();
        assert!(!engine
            .writing_list
            .entry(Default::default())
            .or_default()
            .is_empty());

        let chunks = engine.query_all_chunks(&[]).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(&chunks[0].1, chunk.meta());
        assert!(chunk.meta().uncommitted);

        let uncommitted_chunks = engine.query_uncommitted_chunks(&[]).unwrap();
        assert_eq!(uncommitted_chunks.len(), 1);
        assert_eq!(chunks, uncommitted_chunks);

        drop(chunk);

        let mut req = UpdateReq {
            length: bytes.len() as _,
            data: bytes.as_ptr() as _,
            offset: bytes.len() as _,
            without_checksum: true,
            ..Default::default()
        };
        let chunk = engine.update_chunk(chunk_id, &mut req).unwrap();
        drop(chunk);

        let mut req = UpdateReq {
            length: bytes.len() as _,
            data: bytes.as_ptr() as _,
            offset: bytes.len() as _,
            without_checksum: true,
            ..Default::default()
        };
        let chunk = engine.update_chunk(chunk_id, &mut req).unwrap();
        drop(chunk);

        drop(engine);

        let engine = Engine::open(&config).unwrap();
        let chunks = engine.query_uncommitted_chunks(&[]).unwrap();
        assert_eq!(chunks.len(), 1);

        engine.handle_uncommitted_chunks(&[], 2).unwrap();
        let chunk = engine.get(chunk_id).unwrap().unwrap();
        assert_eq!(chunk.meta().len as usize, bytes.len() * 2);
    }

    #[test]
    fn test_engine_concurrent_update_and_get() {
        let dir = tempfile::tempdir().unwrap();

        let config = EngineConfig {
            path: dir.path().into(),
            create: true,
            ..Default::default()
        };
        let engine = Engine::open(&config).unwrap();

        let chunk_id = "chunk01".as_bytes();
        let bytes = "hello world!".as_bytes();
        let checksum = crc32c::crc32c(bytes);

        let start = std::time::Instant::now();
        let duration = std::time::Duration::from_secs(2);
        let engine_clone = engine.clone();
        let commit_thread = std::thread::spawn(move || {
            while std::time::Instant::now().duration_since(start) < duration {
                engine.write(chunk_id, bytes, 0, checksum).unwrap();
                engine.remove(chunk_id).unwrap();
            }
        });

        let get_thread = std::thread::spawn(move || {
            while std::time::Instant::now().duration_since(start) < duration {
                let _ = engine_clone.get(chunk_id).unwrap();
            }
        });

        let _ = get_thread.join().unwrap();
        let _ = commit_thread.join().unwrap();
    }
}

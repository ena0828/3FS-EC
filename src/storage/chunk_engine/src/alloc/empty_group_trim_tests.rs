use super::*;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture {
    allocator: Arc<Allocator>,
    meta: Arc<MetaStore>,
    dir: tempfile::TempDir,
    group: GroupId,
}
fn configs(path: &std::path::Path) -> (ClustersConfig, MetaStoreConfig) {
    (ClustersConfig { path: path.join("clusters"), chunk_size: CHUNK_SIZE_SMALL, create: true },
     MetaStoreConfig { rocksdb: RocksDBConfig { path: path.join("meta"), create: true,
                         ..Default::default() }, ..Default::default() })
}
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (clusters, db) = configs(dir.path());
    let meta = Arc::new(MetaStore::open(&db).unwrap());
    let allocator = Allocator::load(Clusters::open(&clusters).unwrap(), meta.iterator()).unwrap();
    let task = allocator.do_allocate_task(1, 1, &meta).unwrap();
    let group = match task { AllocateTask::Allocate(group) => group, _ => panic!("expected preallocation") };
    Fixture { allocator, meta, dir, group }
}
fn limits() -> EmptyGroupTrimLimits {
    EmptyGroupTrimLimits { max_groups: 1, max_bytes: CHUNK_SIZE_SMALL.0 * 256, keep_empty_groups: 0 }
}
#[derive(Clone, Copy, PartialEq)]
enum Fault { None, BeforeDelete, AfterDelete, Wal, Punch, Unsupported, Sync }
struct FaultIo<'a> { actual: ActualTrimIo<'a>, fault: Fault, punches: AtomicUsize }
impl<'a> FaultIo<'a> {
    fn new(f: &'a Fixture, fault: Fault) -> Self {
        Self { actual: ActualTrimIo { meta: &f.meta, clusters: &f.allocator.clusters }, fault,
               punches: AtomicUsize::new(0) }
    }
}
fn injected() -> Error { Error::RocksDBError("injected trim persistence result".into()) }
impl TrimIo for FaultIo<'_> {
    fn remove_group(&self, group: GroupId) -> Result<()> {
        if self.fault == Fault::BeforeDelete { return Err(injected()); }
        self.actual.remove_group(group)?;
        if self.fault == Fault::AfterDelete { return Err(injected()); }
        Ok(())
    }
    fn sync_wal(&self) -> Result<()> {
        if self.fault == Fault::Wal { Err(injected()) } else { self.actual.sync_wal() }
    }
    fn punch(&self, group: GroupId) -> std::io::Result<()> {
        self.punches.fetch_add(1, Ordering::SeqCst);
        if self.fault == Fault::Punch { return Err(std::io::Error::from_raw_os_error(libc::EIO)); }
        if self.fault == Fault::Unsupported { return Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP)); }
        self.actual.punch(group)
    }
    fn sync_data(&self, group: GroupId) -> std::io::Result<()> {
        if self.fault == Fault::Sync { Err(std::io::Error::from_raw_os_error(libc::EIO)) }
        else { self.actual.sync_data(group) }
    }
}

#[test]
fn trim_budget_keep_and_real_chunk_owner_prevent_punch() {
    let f = fixture();
    let mut report = EmptyGroupTrimReport::default();
    let mut budget = limits();
    budget.max_bytes -= 1;
    f.allocator.trim_empty_group(&f.meta, budget, &mut report).unwrap();
    assert_eq!(report.attempted_groups, 0);
    assert_eq!(report.oversized_classes, 1);
    budget = limits(); budget.keep_empty_groups = 1;
    f.allocator.trim_empty_group(&f.meta, budget, &mut report).unwrap();
    assert_eq!(report.attempted_groups, 0);
    let chunk = f.allocator.allocate(false).unwrap();
    let retained = Arc::new(chunk);
    let another_owner = retained.clone();
    let bytes = vec![0x65; CHUNK_SIZE_SMALL.0 as usize];
    retained.pwrite(&bytes, 0).unwrap();
    drop(retained);
    f.allocator.trim_empty_group(&f.meta, limits(), &mut report).unwrap();
    assert_eq!(report.attempted_groups, 0);
    let mut got = vec![0; bytes.len()]; another_owner.pread(&mut got, 0).unwrap();
    assert_eq!(got, bytes);
    drop(another_owner);
    let path = f.allocator.clusters.path.join(format!("{:02X}", f.group.cluster()));
    let before = std::fs::metadata(&path).unwrap();
    f.allocator.trim_empty_group(&f.meta, limits(), &mut report).unwrap();
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(report.punch_confirmed_groups, 1);
    assert_eq!(report.punch_confirmed_bytes, f.group.size().0);
    assert_eq!(report.withdrawn_preallocation_bytes, f.group.size().0);
    assert_eq!(report.unconfirmed_extent_bytes, 0);
    assert_eq!(before.len(), after.len()); // KEEP_SIZE, not a file truncation.
    assert!(after.blocks() < before.blocks(), "real ext4 punch must release allocated blocks");
    assert_eq!(f.allocator.counter.used_size().allocated_size, Size::new(0));
    assert!(f.allocator.allocate(false).is_err()); // No preallocated shortcut.
    let replacement = f.allocator.allocate(true).unwrap();
    assert_eq!(replacement.meta().pos.group_id(), f.group);
    replacement.pwrite(&bytes, 0).unwrap();
    replacement.pread(&mut got, 0).unwrap(); assert_eq!(got, bytes);
    let mut replay = EmptyGroupTrimReport::default();
    f.allocator.trim_empty_group(&f.meta, limits(), &mut replay).unwrap();
    assert_eq!(replay.attempted_groups, 0); // No old physical task exists.
}

#[test]
fn trim_delete_and_wal_unknown_quarantine_without_punch_and_reconcile_only() {
    for fault in [Fault::BeforeDelete, Fault::AfterDelete, Fault::Wal] {
        let f = fixture(); let io = FaultIo::new(&f, fault);
        let mut first = EmptyGroupTrimReport::default();
        assert!(f.allocator.trim_empty_group_with(&f.meta, limits(), &mut first, &io).is_err());
        assert_eq!(io.punches.load(Ordering::SeqCst), 0);
        assert_eq!(first.quarantined_groups, 1);
        assert_eq!(first.withdrawn_preallocation_bytes, 0);
        assert!(f.allocator.allocate(false).is_err());
        assert_eq!(*f.allocator.trim_pending.lock().unwrap(), Some(f.group));
        let still_uncertain = FaultIo::new(&f, Fault::Wal);
        let mut failed_reconcile = EmptyGroupTrimReport::default();
        assert!(f.allocator.trim_empty_group_with(&f.meta, limits(), &mut failed_reconcile, &still_uncertain).is_err());
        assert_eq!(failed_reconcile.quarantined_groups, 1);
        assert_eq!(still_uncertain.punches.load(Ordering::SeqCst), 0);
        assert!(f.allocator.allocate(false).is_err());
        let resumed = FaultIo::new(&f, Fault::None);
        let mut recovered = EmptyGroupTrimReport::default();
        f.allocator.trim_empty_group_with(&f.meta, limits(), &mut recovered, &resumed).unwrap();
        assert_eq!(resumed.punches.load(Ordering::SeqCst), 0);
        assert_eq!(recovered.reconciled_groups, 1);
        assert_eq!(recovered.punch_confirmed_groups, 0);
        if fault == Fault::BeforeDelete {
            assert_eq!(recovered.unconfirmed_extent_bytes, 0);
            assert!(f.allocator.allocate(false).is_ok());
        } else {
            assert_eq!(recovered.unconfirmed_extent_bytes, f.group.size().0);
            assert!(f.allocator.allocate(false).is_err());
        }
    }
}

#[test]
fn trim_empty_group_leaves_another_live_group_byte_identical() {
    let f = fixture();
    let first: Vec<_> = (0..256).map(|_| f.allocator.allocate(false).unwrap()).collect();
    let live = f.allocator.allocate(true).unwrap();
    assert_ne!(live.meta().pos.group_id(), f.group);
    let bytes: Vec<u8> = (0..CHUNK_SIZE_SMALL.0).map(|i| (i.wrapping_mul(73) & 255) as u8).collect();
    live.pwrite(&bytes, 0).unwrap();
    drop(first);
    let mut report = EmptyGroupTrimReport::default();
    f.allocator.trim_empty_group(&f.meta, limits(), &mut report).unwrap();
    assert_eq!(report.punch_confirmed_groups, 1);
    assert_eq!(report.withdrawn_preallocation_bytes, f.group.size().0);
    assert_eq!(f.allocator.counter.used_size().allocated_size, live.meta().pos.group_id().size());
    let mut got = vec![0; bytes.len()]; live.pread(&mut got, 0).unwrap(); assert_eq!(got, bytes);
    let mut repeated = EmptyGroupTrimReport::default();
    f.allocator.trim_empty_group(&f.meta, limits(), &mut repeated).unwrap();
    assert_eq!(repeated.attempted_groups, 0);
}

#[test]
fn trim_failed_punch_and_sync_withdraw_once_and_never_retry_old_extent() {
    for fault in [Fault::Punch, Fault::Unsupported, Fault::Sync] {
        let f = fixture(); let io = FaultIo::new(&f, fault);
        let mut first = EmptyGroupTrimReport::default();
        assert!(f.allocator.trim_empty_group_with(&f.meta, limits(), &mut first, &io).is_err());
        assert_eq!(io.punches.load(Ordering::SeqCst), 1);
        assert_eq!(first.punch_confirmed_groups, 0);
        assert_eq!(first.unconfirmed_extent_bytes, f.group.size().0);
        assert_eq!(first.withdrawn_preallocation_bytes, f.group.size().0);
        assert_eq!(first.quarantined_groups, 0);
        assert_eq!(first.unsupported_groups, u32::from(fault == Fault::Unsupported));
        assert!(f.allocator.allocate(false).is_err());
        let mut repeated = EmptyGroupTrimReport::default();
        f.allocator.trim_empty_group_with(&f.meta, limits(), &mut repeated, &io).unwrap();
        assert_eq!(repeated.attempted_groups, 0);
        assert_eq!(io.punches.load(Ordering::SeqCst), 1);
        assert_eq!(f.allocator.counter.used_size().allocated_size, Size::new(0));
    }
}

#[test]
fn trim_rejects_bitmap_and_both_durable_position_indexes() {
    for kind in 0..3 {
        let f = fixture();
        let mut batch = RocksDB::new_write_batch();
        match kind {
            0 => batch.put(MetaKey::group_bits_key(f.group), GroupState::full().as_bytes()),
            1 => batch.put(MetaKey::pos_to_chunk_key(Position::new(f.group, 7)), b"unexpected"),
            _ => batch.put(stage_position_key(Position::new(f.group, 9)), b"unexpected"),
        }
        f.meta.write(batch, true).unwrap();
        let io = FaultIo::new(&f, Fault::None); let mut report = EmptyGroupTrimReport::default();
        assert!(f.allocator.trim_empty_group_with(&f.meta, limits(), &mut report, &io).is_err());
        assert_eq!(io.punches.load(Ordering::SeqCst), 0);
        assert_eq!(report.quarantined_groups, 1);
        assert!(f.allocator.allocate(false).is_err());
    }
}

#[test]
fn trim_unrecorded_slow_allocation_is_not_corruption_or_permission_to_punch() {
    let dir = tempfile::tempdir().unwrap();
    let (clusters, db) = configs(dir.path());
    let meta = Arc::new(MetaStore::open(&db).unwrap());
    let allocator = Allocator::load(Clusters::open(&clusters).unwrap(), meta.iterator()).unwrap();
    let chunk = allocator.allocate(true).unwrap();
    let group = chunk.meta().pos.group_id();
    assert!(meta.stage_get_exact(MetaKey::group_bits_key(group).as_ref()).unwrap().is_none());
    drop(chunk); // No stage/meta batch was ever submitted for this allocation.
    let f = Fixture { allocator, meta, dir, group };
    let io = FaultIo::new(&f, Fault::None);
    let mut report = EmptyGroupTrimReport::default();
    f.allocator.trim_empty_group_with(&f.meta, limits(), &mut report, &io).unwrap();
    assert_eq!(io.punches.load(Ordering::SeqCst), 0);
    assert_eq!(report.reconciled_groups, 1);
    assert_eq!(report.quarantined_groups, 0);
    assert_eq!(report.unconfirmed_extent_bytes, group.size().0);
    assert_eq!(report.withdrawn_preallocation_bytes, group.size().0);
    assert!(f.allocator.allocate(false).is_err());
    let replacement = f.allocator.allocate(true).unwrap();
    assert_eq!(replacement.meta().pos.group_id(), group);
}

#[test]
fn trim_holds_ticket_through_sync_and_allows_no_concurrent_reuse() {
    let f = fixture();
    struct Pause<'a> { actual: ActualTrimIo<'a>, entered: std::sync::mpsc::Sender<()>,
                      resume: std::sync::mpsc::Receiver<()> }
    impl TrimIo for Pause<'_> {
        fn remove_group(&self, group: GroupId) -> Result<()> { self.actual.remove_group(group) }
        fn sync_wal(&self) -> Result<()> { self.actual.sync_wal() }
        fn punch(&self, group: GroupId) -> std::io::Result<()> { self.actual.punch(group) }
        fn sync_data(&self, group: GroupId) -> std::io::Result<()> {
            self.entered.send(()).unwrap();
            self.resume.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            self.actual.sync_data(group)
        }
    }
    std::thread::scope(|scope| {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let allocator = &f.allocator; let meta = &f.meta;
        let worker = scope.spawn(move || {
            let io = Pause { actual: ActualTrimIo { meta, clusters: &allocator.clusters },
                             entered: entered_tx, resume: resume_rx };
            let mut report = EmptyGroupTrimReport::default();
            let result = allocator.trim_empty_group_with(meta, limits(), &mut report, &io);
            (result, report)
        });
        entered_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        assert!(f.allocator.allocator.try_lock().is_err());
        let mut competing = EmptyGroupTrimReport::default();
        f.allocator.trim_empty_group(&f.meta, limits(), &mut competing).unwrap();
        assert_eq!(competing.attempted_groups, 0);
        assert_eq!(competing.busy_classes, 1);
        resume_tx.send(()).unwrap();
        let (result, report) = worker.join().unwrap(); result.unwrap();
        assert_eq!(report.punch_confirmed_groups, 1);
    });
}

#[test]
fn trim_process_kill_after_delete_never_replays_punch_on_reused_group() {
    const CHILD: &str = "HF3FS_TRIM_KILL_CHILD";
    const AFTER_PUNCH: &str = "HF3FS_TRIM_KILL_AFTER_PUNCH";
    const FILTER: &str = "alloc::allocator::empty_group_trim::tests::trim_process_kill_after_delete_never_replays_punch_on_reused_group";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = std::path::PathBuf::from(path);
        let (clusters, db) = configs(&path);
        let meta = MetaStore::open(&db).unwrap();
        let allocator = Allocator::load(Clusters::open(&clusters).unwrap(), meta.iterator()).unwrap();
        struct KillPoint<'a> { actual: ActualTrimIo<'a>, ready: std::path::PathBuf, after_punch: bool }
        impl TrimIo for KillPoint<'_> {
            fn remove_group(&self, g: GroupId) -> Result<()> { self.actual.remove_group(g) }
            fn sync_wal(&self) -> Result<()> { self.actual.sync_wal() }
            fn punch(&self, group: GroupId) -> std::io::Result<()> {
                use std::io::Write;
                if self.after_punch { self.actual.punch(group)?; self.actual.sync_data(group)?; }
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&self.ready)?;
                file.write_all(if self.after_punch { b"punch synchronized; accounting not finalized\n" }
                               else { b"bitmap delete synchronized; punch not executed\n" })?;
                file.sync_all()?;
                loop { std::thread::park(); }
            }
            fn sync_data(&self, _g: GroupId) -> std::io::Result<()> { panic!("child must be killed before punch") }
        }
        let io = KillPoint { actual: ActualTrimIo { meta: &meta, clusters: &allocator.clusters }, ready: path.join("ready"),
                            after_punch: std::env::var_os(AFTER_PUNCH).is_some() };
        allocator.trim_empty_group_with(&meta, limits(), &mut EmptyGroupTrimReport::default(), &io).unwrap();
        panic!("child unexpectedly returned");
    }
    for after_punch in [false, true] {
    let f = fixture();
    let Fixture { allocator, meta, dir, group } = f;
    drop(allocator); drop(meta); // Release both DB ownership and cluster fds.
    struct Owned(std::process::Child);
    impl Drop for Owned { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", FILTER, "--nocapture"]).env(CHILD, dir.path()).env_remove(AFTER_PUNCH)
        .stdout(std::fs::File::create(dir.path().join("child.stdout")).unwrap())
        .stderr(std::fs::File::create(dir.path().join("child.stderr")).unwrap());
    if after_punch { command.env(AFTER_PUNCH, "1"); }
    let mut child = Owned(command.spawn().unwrap());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !dir.path().join("ready").exists() {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("child exited {status} before trim barrier: {}",
                   std::fs::read_to_string(dir.path().join("child.stderr")).unwrap_or_default());
        }
        assert!(std::time::Instant::now() < deadline, "child trim barrier timeout; stderr: {}",
                std::fs::read_to_string(dir.path().join("child.stderr")).unwrap_or_default());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child.0.kill().unwrap(); let status = child.0.wait().unwrap(); assert!(!status.success());
    let (clusters, db) = configs(dir.path());
    let meta = MetaStore::open(&db).unwrap();
    assert!(meta.stage_get_exact(MetaKey::group_bits_key(group).as_ref()).unwrap().is_none());
    let allocator = Allocator::load(Clusters::open(&clusters).unwrap(), meta.iterator()).unwrap();
    assert!(allocator.allocate(false).is_err());
    let chunk = allocator.allocate(true).unwrap(); assert_eq!(chunk.meta().pos.group_id(), group);
    let bytes = vec![0xC3; CHUNK_SIZE_SMALL.0 as usize]; chunk.pwrite(&bytes, 0).unwrap();
    let mut report = EmptyGroupTrimReport::default(); allocator.trim_empty_group(&meta, limits(), &mut report).unwrap();
    assert_eq!(report.attempted_groups, 0);
    let mut got = vec![0; bytes.len()]; chunk.pread(&mut got, 0).unwrap(); assert_eq!(got, bytes);
    }
}

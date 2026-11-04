use super::*;
use std::io::Write;
use std::sync::Mutex;

static ENGINE_TEST: Mutex<()> = Mutex::new(());

fn setup() -> (tempfile::TempDir, String, ffi::RawEcStageLimits) {
    let root = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("engine", IMMUTABLE_STAGE_ROOT_MARKER),
        ("engine-ec-v1", IMMUTABLE_STAGE_V1_BLOCKER),
    ] {
        let mut file = std::fs::File::create(root.path().join(name)).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    std::fs::File::open(root.path())
        .unwrap()
        .sync_all()
        .unwrap();
    let path = root
        .path()
        .join(IMMUTABLE_STAGE_ENGINE_DIRECTORY)
        .to_str()
        .unwrap()
        .to_owned();
    (
        root,
        path,
        ffi::RawEcStageLimits {
            max_cached_records: 8,
            max_active: 4,
            max_concurrent_io: 2,
        },
    )
}

#[test]
fn stage_bridge_owned_boundary_reopen_identity_and_accounting() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_root, path, limits) = setup();
    let data: Vec<_> = (0..65543).map(|i| (i * 37 + 11) as u8).collect();
    let binding = ffi::RawEcStageBinding {
        operation: [7; 16],
        length: data.len() as u32,
        checksum: crc32c::crc32c(&data),
    };
    let opened = stage_open(&path, true, 2, &limits);
    assert_eq!(opened.status.error_code, 0, "{}", opened.status.error);
    let handle = opened.handle;
    let begun = stage_begin(&handle, b"ec-key", &binding, &[9; 16]);
    assert_eq!(begun.status.error_code, 0);
    assert_eq!(begun.state.state, 1);
    assert_eq!(
        stage_begin(&handle, b"ec-key", &binding, &[10; 16])
            .status
            .error_code,
        64
    );
    assert_eq!(
        stage_read_block(&handle, b"ec-key", &binding, 0)
            .status
            .error_code,
        4086
    );
    for (index, block) in data.chunks(65536).enumerate() {
        let result = stage_append(&handle, b"ec-key", &binding, index as u8, block);
        assert_eq!(result.status.error_code, 0, "{}", result.status.error);
    }
    let sealed = stage_seal(&handle, b"ec-key", &binding);
    assert_eq!(sealed.error_code, 0, "{}", sealed.error);
    assert_eq!(sealed.meta.chain_ver, 0);
    assert_eq!(sealed.meta.last_client_low, u64::from_be_bytes([9; 8]));
    assert_eq!(sealed.etag, [7; 16]);
    let accounted = stage_used_size(&handle, b"ec");
    assert_eq!(accounted.status.error_code, 0);
    assert!(accounted.committed >= data.len() as u64);
    let owned = stage_read_block(&handle, b"ec-key", &binding, 1);
    assert_eq!(owned.status.error_code, 0);
    drop(handle);
    assert_eq!(owned.data, data[65536..]);
    let reopened = stage_open(&path, false, 2, &limits);
    assert_eq!(reopened.status.error_code, 0, "{}", reopened.status.error);
    let handle = reopened.handle;
    assert!(
        stage_query(&handle, b"ec-key", &binding)
            .state
            .needs_reconcile
    );
    assert_eq!(
        stage_reconcile(&handle, b"ec-key", &binding)
            .status
            .error_code,
        0
    );
    assert_eq!(stage_seal(&handle, b"ec-key", &binding).error_code, 0);
    assert_eq!(
        stage_used_size(&handle, b"ec").committed,
        accounted.committed
    );
    assert_eq!(
        stage_read_block(&handle, b"ec-key", &binding, 0).data,
        data[..65536]
    );
}

#[test]
fn stage_bridge_rejects_wrong_binding_and_oversized_slice_without_partial_output() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_root, path, limits) = setup();
    let opened = stage_open(&path, true, 2, &limits);
    assert_eq!(opened.status.error_code, 0);
    let handle = opened.handle;
    let binding = ffi::RawEcStageBinding {
        operation: [1; 16],
        length: 1,
        checksum: crc32c::crc32c(b"a"),
    };
    assert_eq!(
        stage_begin(&handle, b"ec-k", &binding, &[2; 16])
            .status
            .error_code,
        0
    );
    let wrong = ffi::RawEcStageBinding {
        checksum: binding.checksum ^ 1,
        ..binding
    };
    assert_eq!(
        stage_append(&handle, b"ec-k", &wrong, 0, b"a")
            .status
            .error_code,
        64
    );
    assert_eq!(
        stage_append(&handle, b"ec-k", &binding, 0, &[0; 65537])
            .status
            .error_code,
        3
    );
    assert_eq!(
        stage_append(&handle, b"ec-k", &binding, 16, b"a")
            .status
            .error_code,
        3
    );
    assert_eq!(
        stage_query(&handle, b"ec-k", &binding).state.prefix_bytes,
        0
    );
    let missing = stage_read_block(&handle, b"ec-missing", &binding, 0);
    assert_eq!(missing.status.error_code, 4001);
    assert!(missing.data.is_empty());
    let failed = stage_seal(&handle, b"ec-k", &wrong);
    assert_eq!(failed.error_code, 64);
    assert_eq!(failed.meta, ffi::RawMeta::default());
    assert!(failed.etag.is_empty());
    assert_eq!(stage_used_size(&handle, b"bad-prefix").status.error_code, 3);
}

#[test]
fn stage_bridge_empty_fragment_and_invalid_open_remain_owned() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_root, path, limits) = setup();
    let invalid = stage_open(&path, true, 2, &ffi::RawEcStageLimits::default());
    assert_ne!(invalid.status.error_code, 0);
    assert_ne!(stage_scope_open(&invalid.handle).status.error_code, 0);
    let opened = stage_open(&path, true, 2, &limits);
    assert_eq!(opened.status.error_code, 0);
    let binding = ffi::RawEcStageBinding {
        operation: [3; 16],
        length: 0,
        checksum: 0,
    };
    assert_eq!(
        stage_begin(&opened.handle, b"ec-empty", &binding, &[4; 16])
            .status
            .error_code,
        0
    );
    assert_eq!(
        stage_seal(&opened.handle, b"ec-empty", &binding).error_code,
        0
    );
    let read = stage_read_block(&opened.handle, b"ec-empty", &binding, 0);
    assert_ne!(read.status.error_code, 0);
    assert!(read.data.is_empty());
}

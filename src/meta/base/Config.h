#pragma once

#include "analytics/StructuredTraceLog.h"
#include "client/storage/StorageClient.h"
#include "common/kv/TransactionRetry.h"
#include "common/utils/ConfigBase.h"
#include "common/utils/CoroutinesPool.h"
#include "common/utils/Duration.h"
#include "common/utils/PriorityCoroutinePool.h"
#include "common/utils/Size.h"
#include "core/user/UserCache.h"
#include "fbs/meta/Ec.h"
#include "meta/components/Distributor.h"
#include "meta/components/Forward.h"
#include "meta/components/SessionManager.h"
#include "meta/event/Event.h"
#include "meta/store/Utils.h"

namespace hf3fs::meta::server {

using kv::TransactionRetry;

struct GcConfig : ConfigBase<GcConfig> {
  CONFIG_HOT_UPDATED_ITEM(enable, true);
  CONFIG_HOT_UPDATED_ITEM(scan_interval, 200_ms);
  CONFIG_HOT_UPDATED_ITEM(scan_batch, 4096);
  CONFIG_HOT_UPDATED_ITEM(remove_chunks_batch_size, 32);
  CONFIG_HOT_UPDATED_ITEM(gc_file_delay, 5_min);
  CONFIG_HOT_UPDATED_ITEM(gc_file_concurrent, 32ul);
  CONFIG_HOT_UPDATED_ITEM(gc_directory_delay, 0_s);
  CONFIG_HOT_UPDATED_ITEM(gc_directory_concurrent, 4ul);
  CONFIG_HOT_UPDATED_ITEM(gc_directory_entry_batch, 32ul);
  CONFIG_HOT_UPDATED_ITEM(gc_directory_entry_concurrent, 4ul);
  CONFIG_HOT_UPDATED_ITEM(retry_delay, 10_min);
  // disable gc delay if free space is below 5%
  CONFIG_HOT_UPDATED_ITEM(gc_delay_free_space_threshold, 5);
  CONFIG_HOT_UPDATED_ITEM(check_session, true);
  CONFIG_HOT_UPDATED_ITEM(distributed_gc, true);  // random select a GC directory
  CONFIG_HOT_UPDATED_ITEM(txn_low_priority, false);

  // small file or large file
  CONFIG_HOT_UPDATED_ITEM(small_file_chunks, (uint64_t)32);
  CONFIG_HOT_UPDATED_ITEM(large_file_chunks, (uint64_t)128);

  CONFIG_HOT_UPDATED_ITEM(recursive_perm_check, true);

  CONFIG_OBJ(workers, PriorityCoroutinePoolConfig, [](auto &c) {
    c.set_coroutines_num(8);
    c.set_queue_size(1024);
  });
  CONFIG_OBJ(retry_remove_chunks, storage::client::RetryOptions, [](auto &c) {
    c.set_init_wait_time(10_s);
    c.set_max_wait_time(10_s);
    c.set_max_retry_time(30_s);
  });
};

struct EcTargetConfig : ConfigBase<EcTargetConfig> {
  CONFIG_ITEM(chain, uint32_t{});
  CONFIG_ITEM(target, uint64_t{});
  CONFIG_ITEM(node, uint32_t{});
  CONFIG_ITEM(engine_uuid, std::string{});
  CONFIG_ITEM(target_incarnation, std::string{});

 public:
  EcPlacement placement() const {
    EcPlacement p;
    p.chain = storage::ChainId(chain());
    p.target = storage::TargetId(target());
    p.node = flat::NodeId(node());
    return p;
  }
};

struct Config : ConfigBase<Config> {
  // Native EC remains opt-in while storage capability enforcement is integrated.
  CONFIG_ITEM(enable_ec_catalog, false);
  CONFIG_ITEM(enable_ec_v2, false);
  // Explicit root-only, exact-allocation GC. No scan, TTL or automatic retire.
  CONFIG_ITEM(enable_ec_exact_gc, false);
  CONFIG_ITEM(enable_ec_revision_retirement, false);
  CONFIG_ITEM(ec_gc_key_file, Path{});
  CONFIG_ITEM(ec_gc_key_id, std::string{});
  CONFIG_ITEM(ec_gc_authority, std::string{});
  CONFIG_ITEM(ec_gc_request_ttl_seconds, uint64_t{60});
  CONFIG_ITEM(ec_gc_timeout, 60_s);
  CONFIG_ITEM(ec_gc_max_concurrent, uint32_t{8});
  CONFIG_ITEM(ec_v2_helper_key_file, Path{});
  CONFIG_ITEM(ec_v2_helper_grant_ttl_seconds, uint64_t{300});
  CONFIG_ITEM(ec_v2_control_key_file, Path{});
  CONFIG_ITEM(ec_v2_control_authority, std::string{});
  CONFIG_ITEM(ec_v2_drain_timeout, 60_s);
  CONFIG_ITEM(ec_v2_drain_poll_interval, 20_ms);
  CONFIG_ITEM(ec_allow_colocated_test_targets, false);
  CONFIG_ITEM(ec_allow_unauthorized_storage_for_tests, false);
  CONFIG_ITEM(ec_capability_key_file, Path{});
  CONFIG_ITEM(ec_grant_ttl_seconds, uint64_t{300});
  CONFIG_OBJ_ARRAY(ec_targets, EcTargetConfig, 13, [](auto &) { return 0ul; });
  CONFIG_ITEM(ec_max_verifying_stripes, 1u, ConfigCheckers::checkPositive);
  CONFIG_ITEM(ec_verify_timeout, 60_s);
  CONFIG_HOT_UPDATED_ITEM(readonly, false);
  CONFIG_HOT_UPDATED_ITEM(authenticate, false);
  CONFIG_HOT_UPDATED_ITEM(grv_cache, false);

  CONFIG_OBJ(gc, GcConfig);
  CONFIG_OBJ(session_manager, SessionManager::Config);
  CONFIG_OBJ(distributor, Distributor::Config);
  CONFIG_OBJ(forward, Forward::Config);
  CONFIG_OBJ(event_trace_log, analytics::StructuredTraceLog<MetaEventTrace>::Config);

  CONFIG_HOT_UPDATED_ITEM(max_symlink_depth, 4L, ConfigCheckers::checkPositive);
  CONFIG_HOT_UPDATED_ITEM(max_symlink_count, 10L, ConfigCheckers::checkPositive);
  CONFIG_HOT_UPDATED_ITEM(max_directory_depth, 64L, ConfigCheckers::checkPositive);
  CONFIG_HOT_UPDATED_ITEM(acl_cache_time, 15_s);
  CONFIG_HOT_UPDATED_ITEM(list_default_limit, 128);
  CONFIG_HOT_UPDATED_ITEM(sync_on_prune_session, false);
  CONFIG_HOT_UPDATED_ITEM(max_remove_chunks_per_request, 32u, ConfigCheckers::checkPositive);
  CONFIG_HOT_UPDATED_ITEM(allow_stat_deleted_inodes, true);
  CONFIG_HOT_UPDATED_ITEM(ignore_length_hint, false);
  CONFIG_HOT_UPDATED_ITEM(time_granularity, 1_s);
  CONFIG_HOT_UPDATED_ITEM(dynamic_stripe, false);
  CONFIG_HOT_UPDATED_ITEM(dynamic_stripe_initial, 16u, ConfigCheckers::checkPositive);
  CONFIG_HOT_UPDATED_ITEM(dynamic_stripe_growth, 2u);
  CONFIG_HOT_UPDATED_ITEM(batch_stat_concurrent, 8u);
  CONFIG_HOT_UPDATED_ITEM(batch_stat_by_path_concurrent, 4u);
  CONFIG_HOT_UPDATED_ITEM(max_batch_operations, 4096u);
  CONFIG_HOT_UPDATED_ITEM(enable_new_chunk_engine, false);
  CONFIG_HOT_UPDATED_ITEM(allow_owner_change_immutable, false);

  // deperated
  CONFIG_HOT_UPDATED_ITEM(check_file_hole, false);
  CONFIG_OBJ(background_hole_checker, CoroutinesPoolBase::Config, [](CoroutinesPoolBase::Config &c) {
    c.set_coroutines_num(16);
    c.set_queue_size(4096);
  });

  CONFIG_HOT_UPDATED_ITEM(inodeId_check_unique, true);
  CONFIG_HOT_UPDATED_ITEM(inodeId_abort_on_duplicate, false);

  // replace file with new inode on O_TRUNC
  CONFIG_HOT_UPDATED_ITEM(otrunc_replace_file, true);
  CONFIG_HOT_UPDATED_ITEM(otrunc_replace_file_threshold, 1_GB);

  // statfs
  CONFIG_HOT_UPDATED_ITEM(statfs_cache_time, 60_s);
  CONFIG_HOT_UPDATED_ITEM(statfs_update_interval, 5_s);
  CONFIG_HOT_UPDATED_ITEM(statfs_space_imbalance_threshold, 5);

  // iflags
  CONFIG_HOT_UPDATED_ITEM(iflags_chain_allocation, false);
  CONFIG_HOT_UPDATED_ITEM(iflags_chunk_engine, true);

  // recursive remove
  CONFIG_HOT_UPDATED_ITEM(recursive_remove_check_owner, true);
  CONFIG_HOT_UPDATED_ITEM(recursive_remove_perm_check, (size_t)1024);
  CONFIG_HOT_UPDATED_ITEM(allow_directly_move_to_trash, false);

  // idempotent operation
  CONFIG_HOT_UPDATED_ITEM(idempotent_record_expire, 30_min);
  CONFIG_HOT_UPDATED_ITEM(idempotent_record_clean, 1_min);
  CONFIG_HOT_UPDATED_ITEM(idempotent_remove, true);
  CONFIG_HOT_UPDATED_ITEM(idempotent_rename, false);

  CONFIG_HOT_UPDATED_ITEM(operation_timeout, 5_s);

  CONFIG_OBJ(retry_transaction, TransactionRetry);
  CONFIG_OBJ(retry_remove_chunks, storage::client::RetryOptions, [](auto &c) {
    c.set_init_wait_time(10_s);
    c.set_max_wait_time(10_s);
    c.set_max_retry_time(30_s);
  });

  CONFIG_OBJ(user_cache, core::UserCache::Config);
};

}  // namespace hf3fs::meta::server

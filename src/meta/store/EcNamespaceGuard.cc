#include "meta/store/EcNamespaceGuard.h"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <vector>

#include "common/kv/KeyPrefix.h"

namespace hf3fs::meta::server {
namespace {

struct SubtreeCount {
  SERDE_STRUCT_FIELD(version, uint16_t(1));
  SERDE_STRUCT_FIELD(files, uint64_t(0));
};

struct RegisteredFile {
  SERDE_STRUCT_FIELD(version, uint16_t(1));
  SERDE_STRUCT_FIELD(incarnation, Uuid::zero());
  SERDE_STRUCT_FIELD(parent, InodeId());
};

std::string key(kv::KeyPrefix prefix, InodeId inode) {
  std::string out(kv::toStr(prefix));
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<char>(inode.u64() >> shift));
  }
  return out;
}

template <typename T>
CoTryTask<std::optional<T>> load(IReadWriteTransaction &txn, kv::KeyPrefix prefix, InodeId inode) {
  auto bytes = co_await txn.get(key(prefix, inode));
  CO_RETURN_ON_ERROR(bytes);
  if (!*bytes) co_return std::nullopt;
  T record;
  if (!serde::deserialize(record, **bytes) || record.version != 1) {
    co_return makeError(StatusCode::kDataCorruption, "invalid EC namespace index record");
  }
  co_return record;
}

CoTryTask<std::vector<InodeId>> liveAncestors(IReadWriteTransaction &txn, InodeId parent) {
  std::vector<InodeId> ancestors;
  std::set<InodeId> seen;
  while (ancestors.size() < 4096) {
    if (parent == InodeId::gcRoot()) {
      co_return makeError(MetaCode::kNotFound, "EC namespace cannot enter the GC tree");
    }
    if (!seen.insert(parent).second) {
      co_return makeError(StatusCode::kDataCorruption, "EC namespace ancestor cycle");
    }
    auto inode = co_await Inode::load(txn, parent);
    CO_RETURN_ON_ERROR(inode);
    if (!*inode || !(**inode).nlink) {
      co_return makeError(MetaCode::kNotFound, "EC namespace ancestor has been removed");
    }
    if (!(**inode).isDirectory()) {
      co_return makeError(MetaCode::kNotDirectory, "EC namespace ancestor is not a directory");
    }
    ancestors.push_back(parent);
    auto next = (**inode).asDirectory().parent;
    if (parent == InodeId::root()) {
      if (next != parent) co_return makeError(StatusCode::kDataCorruption, "invalid namespace root parent");
      co_return ancestors;
    }
    parent = next;
  }
  co_return makeError(StatusCode::kNotImplemented, "EC namespace ancestor depth exceeds 4096");
}

CoTryTask<void> storeCount(IReadWriteTransaction &txn, InodeId directory, uint64_t count) {
  auto packed = key(kv::KeyPrefix::EcNamespaceCount, directory);
  if (!count) co_return co_await txn.clear(packed);
  co_return co_await txn.set(packed, serde::serialize(SubtreeCount{1, count}));
}

}  // namespace

CoTryTask<uint64_t> EcNamespaceGuard::subtreeCount(IReadWriteTransaction &txn, InodeId directory) {
  auto record = co_await load<SubtreeCount>(txn, kv::KeyPrefix::EcNamespaceCount, directory);
  CO_RETURN_ON_ERROR(record);
  co_return *record ? (**record).files : 0;
}

CoTryTask<void> EcNamespaceGuard::checkRemove(IReadWriteTransaction &txn, InodeId directory) {
  auto count = co_await subtreeCount(txn, directory);
  CO_RETURN_ON_ERROR(count);
  if (*count) {
    co_return makeError(StatusCode::kNotImplemented, "removing a directory containing EC files is not implemented");
  }
  co_return Void{};
}

CoTryTask<void> EcNamespaceGuard::registerFile(IReadWriteTransaction &txn, const Inode &file, InodeId parent) {
  if (!file.isFile() || !file.asFile().layout.isErasureCoded() || file.id.isTreeRoot() ||
      file.id > InodeId::normalMax() || file.nlink != 1) {
    co_return makeError(StatusCode::kInvalidArg, "EC namespace registration requires a singly linked EC file");
  }
  auto descriptor = file.asFile().layout.ecLayout();
  CO_RETURN_ON_ERROR(descriptor->valid());
  auto ancestors = co_await liveAncestors(txn, parent);
  CO_RETURN_ON_ERROR(ancestors);
  auto previous = co_await load<RegisteredFile>(txn, kv::KeyPrefix::EcNamespaceFile, file.id);
  CO_RETURN_ON_ERROR(previous);
  if (*previous && ((**previous).incarnation != descriptor->incarnation || (**previous).parent != parent)) {
    co_return makeError(StatusCode::kTokenMismatch, "EC inode has a different namespace registration");
  }
  std::vector<std::pair<InodeId, uint64_t>> updates;
  for (auto directory : *ancestors) {
    auto count = co_await subtreeCount(txn, directory);
    CO_RETURN_ON_ERROR(count);
    if (*previous) {
      if (!*count) co_return makeError(StatusCode::kDataCorruption, "registered EC file has no ancestor count");
    } else {
      if (*count == std::numeric_limits<uint64_t>::max()) {
        co_return makeError(StatusCode::kDataCorruption, "EC namespace count overflow");
      }
      updates.emplace_back(directory, *count + 1);
    }
  }
  if (*previous) co_return Void{};
  for (auto [directory, count] : updates) {
    CO_RETURN_ON_ERROR(co_await storeCount(txn, directory, count));
  }
  co_return co_await txn.set(key(kv::KeyPrefix::EcNamespaceFile, file.id),
                             serde::serialize(RegisteredFile{1, descriptor->incarnation, parent}));
}

CoTryTask<void> EcNamespaceGuard::moveDirectory(IReadWriteTransaction &txn, const Inode &directory, InodeId newParent) {
  if (!directory.isDirectory() || directory.id.isTreeRoot()) {
    co_return makeError(StatusCode::kInvalidArg, "EC namespace move requires a non-root directory");
  }
  // Even an absent key is a conflict read: first EC creation must race with this move.
  auto count = co_await subtreeCount(txn, directory.id);
  CO_RETURN_ON_ERROR(count);
  if (!*count) co_return Void{};
  auto source = co_await liveAncestors(txn, directory.id);
  CO_RETURN_ON_ERROR(source);
  if (source->size() < 2 || (*source)[1] != directory.asDirectory().parent) {
    co_return makeError(StatusCode::kDataCorruption, "EC namespace source parent is inconsistent");
  }
  auto destination = co_await liveAncestors(txn, newParent);
  CO_RETURN_ON_ERROR(destination);
  if (std::find(destination->begin(), destination->end(), directory.id) != destination->end()) {
    co_return makeError(StatusCode::kInvalidArg, "EC namespace move would introduce a directory cycle");
  }
  std::map<InodeId, int> deltas;
  for (size_t i = 1; i != source->size(); ++i) --deltas[(*source)[i]];
  for (auto ancestor : *destination) ++deltas[ancestor];
  std::vector<std::pair<InodeId, uint64_t>> updates;
  for (auto [ancestor, delta] : deltas) {
    // Common ancestors receive no net change, avoiding transient underflow/overflow.
    auto value = co_await subtreeCount(txn, ancestor);
    CO_RETURN_ON_ERROR(value);
    if (delta <= 0 && *value < *count) {
      co_return makeError(StatusCode::kDataCorruption, "EC namespace count underflow");
    }
    if (delta > 0 && *value > std::numeric_limits<uint64_t>::max() - *count) {
      co_return makeError(StatusCode::kDataCorruption, "EC namespace count overflow");
    }
    if (delta) updates.emplace_back(ancestor, delta > 0 ? *value + *count : *value - *count);
  }
  for (auto [ancestor, value] : updates) {
    CO_RETURN_ON_ERROR(co_await storeCount(txn, ancestor, value));
  }
  co_return Void{};
}

CoTryTask<Void> EcNamespaceGuard::checkTreeFile(IReadWriteTransaction &txn, const Inode &file) {
  if (!file.isFile() || !file.asFile().layout.ecLayout()) co_return makeError(StatusCode::kInvalidArg);
  const auto *layout = file.asFile().layout.ecLayout();
  CO_RETURN_ON_ERROR(layout->valid());
  auto r = co_await load<RegisteredFile>(txn, kv::KeyPrefix::EcNamespaceFile, file.id);
  CO_RETURN_ON_ERROR(r);
  if (!*r || (**r).incarnation != layout->incarnation)
    co_return makeError(StatusCode::kDataCorruption, "EC file lost namespace birth registration");
  co_return Void{};
}
CoTryTask<Void> EcNamespaceGuard::adjustTreeLink(IReadWriteTransaction &txn,
                                                 const Inode &file,
                                                 InodeId parent,
                                                 bool increment) {
  CO_RETURN_ON_ERROR(co_await checkTreeFile(txn, file));
  auto ancestors = co_await liveAncestors(txn, parent);
  CO_RETURN_ON_ERROR(ancestors);
  std::vector<std::pair<InodeId, uint64_t>> changes;
  for (auto id : *ancestors) {
    auto n = co_await subtreeCount(txn, id);
    CO_RETURN_ON_ERROR(n);
    if ((increment && *n == std::numeric_limits<uint64_t>::max()) || (!increment && !*n))
      co_return makeError(StatusCode::kDataCorruption, "EC namespace link count overflow/underflow");
    changes.emplace_back(id, increment ? *n + 1 : *n - 1);
  }
  for (auto [id, n] : changes) CO_RETURN_ON_ERROR(co_await storeCount(txn, id, n));
  // Permanent original registration is retained; later links are accounted by
  // the typed lifecycle ledger, not by rewriting the creation parent.
  co_return Void{};
}
}  // namespace hf3fs::meta::server

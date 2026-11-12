// Included inside EcFileTreeCatalog.cc so the existing checked node/reference
// primitives remain the single implementation of their ownership contract.
CoTryTask<EcTreeRoot> EcFileTreeCatalog::cut(EcTreeContext &context, const EcTreeCut &cut) {
  auto root = co_await validateContext(context);
  CO_RETURN_ON_ERROR(root);
  auto &txn = *context.txn_;
  const auto &birth = context.birth_;
  if (cut.object != birth.object || cut.operation.is_nil() || !same(cut.expected, *root) ||
      root->sequence == std::numeric_limits<uint64_t>::max())
    co_return makeError(StatusCode::kTokenStale, "truncate root CAS changed");
  if (cut.length >= root->visibleLength) {
    // A prior shrink removed every right-hand edge and rewrote any shortened
    // Data tail; extension therefore exposes holes, never hidden old bytes.
    if (cut.tail) co_return makeError(StatusCode::kInvalidArg, "extension cannot install a tail");
  } else {
    const uint64_t width = uint64_t(birth.shardBytes) * 10;
    const uint64_t stripe = cut.length / width, remainder = cut.length % width;
    CO_RETURN_ON_ERROR(stripeStart(stripe, birth.shardBytes));
    std::set<Uuid> unique;
    for (const auto &id : cut.nodeIds)
      if (id.is_nil() || !unique.insert(id).second) co_return makeError(StatusCode::kInvalidArg);
    auto oldTail = co_await lookup(context, stripe);
    CO_RETURN_ON_ERROR(oldTail);
    const bool needsTail = remainder && oldTail->kind == EcTreeSlotKind::Data && oldTail->logicalLength > remainder;
    if (needsTail != cut.tail.has_value())
      co_return makeError(StatusCode::kInvalidArg, "partial Data truncate requires a verified new tail");
    EcTreeSlot replacement;
    if (remainder) replacement = *oldTail;
    if (cut.tail) {
      replacement = *cut.tail;
      CO_RETURN_ON_ERROR(validSlot(replacement, birth, stripe));
      if (replacement.kind != EcTreeSlotKind::Data || replacement.logicalLength != remainder ||
          replacement.revision == oldTail->revision || replacement.generation == oldTail->generation)
        co_return makeError(StatusCode::kTokenMismatch, "truncate tail must be a new exact-length allocation set");
      // A fresh tail is fully validated by its first manifestHold() below.
      // Existing positive-hold tails still require the explicit full check:
      // their later COW increment intentionally uses only compact accounting.
      auto tailHolds = co_await require<EcTreeManifestHolds>(
          txn,
          manifestKey(KeyPrefix::EcTreeManifest, birth.object, replacement.stripe, replacement.revision));
      CO_RETURN_ON_ERROR(tailHolds);
      if (tailHolds->treeHolds) {
        auto installedTail = co_await installed(context, replacement, true);
        CO_RETURN_ON_ERROR(installedTail);
      }
    }
    std::array<EcTreeNode, 16> next;
    auto id = root->root;
    for (int level = 15; level >= 0; --level) {
      EcTreeNode body;
      if (!id.is_nil()) {
        auto previous = co_await node(txn, birth, id);
        CO_RETURN_ON_ERROR(previous);
        if (previous->first.level != level || previous->first.prefix != prefix(stripe, level) ||
            previous->second.state != EcTreeRefState::Live)
          co_return makeError(StatusCode::kDataCorruption);
        body = std::move(previous->first);
      } else {
        body.object = birth.object;
        body.level = level;
        body.prefix = prefix(stripe, level);
        if (!level) body.slots.emplace();
      }
      const auto at = index(stripe, level);
      id = level ? body.children[at] : Uuid::zero();
      body.id = cut.nodeIds[level];
      body.operation = cut.operation;
      if (level) {
        body.children[at] = cut.nodeIds[level - 1];
        for (size_t i = at + 1; i < 16; ++i) body.children[i] = Uuid::zero();
      } else {
        (*body.slots)[at] = replacement;
        for (size_t i = at + 1; i < 16; ++i) (*body.slots)[i] = EcTreeSlot{};
      }
      CO_RETURN_ON_ERROR(validNode(body, birth));
      next[level] = std::move(body);
    }
    for (const auto &newId : cut.nodeIds)
      for (auto kind : {KeyPrefix::EcTreeNode, KeyPrefix::EcTreeNodeRefs, KeyPrefix::EcTreeReclaim}) {
        auto old = co_await txn.get(idKey(kind, birth.object, newId));
        CO_RETURN_ON_ERROR(old);
        if (*old) co_return makeError(StatusCode::kTokenDuplicated, "truncate cannot reuse a permanent node ID");
      }
    for (uint8_t level = 0; level < 16; ++level) {
      const auto &body = next[level];
      if (!level) {
        for (const auto &slot : *body.slots)
          if (slot.kind == EcTreeSlotKind::Data) CO_RETURN_ON_ERROR(co_await manifestHold(context, slot, true));
      } else {
        for (size_t i = 0; i < 16; ++i) {
          const auto &child = body.children[i];
          if (child.is_nil() || i == index(stripe, level)) continue;
          CO_RETURN_ON_ERROR(
              co_await childRef(txn, birth, child, level - 1, body.prefix | (uint64_t(i) << (4 * level)), true));
        }
      }
      EcTreeNodeRefs refs;
      refs.object = birth.object;
      refs.node = body.id;
      refs.references = 1;
      refs.level = body.level;
      refs.prefix = body.prefix;
      CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcTreeNode, birth.object, body.id), body));
      CO_RETURN_ON_ERROR(co_await store(txn, idKey(KeyPrefix::EcTreeNodeRefs, birth.object, body.id), refs));
    }
    if (!root->root.is_nil()) CO_RETURN_ON_ERROR(co_await childRef(txn, birth, root->root, 15, 0, false));
    root->root = cut.nodeIds[15];
  }
  root->visibleLength = cut.length;
  ++root->sequence;
  auto object = co_await EcCatalog::getObject(txn, birth.object);
  CO_RETURN_ON_ERROR(object);
  object->length = root->visibleLength;
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcObject, birth.object), *object));
  CO_RETURN_ON_ERROR(co_await store(txn, objectKey(KeyPrefix::EcTreeRoot, birth.object), *root));
  co_return *root;
}

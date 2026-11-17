add_executable(test_ec_shard_store TestECShardStore.cc)
target_link_libraries(test_ec_shard_store PRIVATE ec_shard_store GTest::gtest_main)
set_target_properties(test_ec_shard_store PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
add_test(NAME test_ec_shard_store COMMAND test_ec_shard_store)

add_executable(test_storage_target_ec TestStorageTargetEC.cc)
target_link_libraries(test_storage_target_ec PRIVATE storage GTest::gtest_main)
set_target_properties(test_storage_target_ec PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
add_test(NAME test_storage_target_ec COMMAND test_storage_target_ec)

add_executable(test_ec_shard_worker TestECShardWorker.cc)
target_link_libraries(test_ec_shard_worker PRIVATE ec_shard_worker GTest::gtest_main)
set_target_properties(test_ec_shard_worker PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
add_test(NAME test_ec_shard_worker COMMAND test_ec_shard_worker)

# Protocol-only executable: no worker/service implementation is linked.
add_executable(test_ec_shard_serde TestECShardSerde.cc)
target_link_libraries(test_ec_shard_serde PRIVATE storage-fbs GTest::gtest_main)
set_target_properties(test_ec_shard_serde PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
add_test(NAME test_ec_shard_serde COMMAND test_ec_shard_serde)

# TCP Messenger test peer only; no production StorageService/Worker is linked.
add_executable(test_ec_shard_messenger TestECShardMessenger.cc)
target_link_libraries(test_ec_shard_messenger PRIVATE storage-client test_main)
set_target_properties(test_ec_shard_messenger PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
add_test(NAME test_ec_shard_messenger COMMAND test_ec_shard_messenger)

add_executable(test_storage_targets_ec TestStorageTargetsEC.cc)
target_link_libraries(test_storage_targets_ec PRIVATE storage test_main)
set_target_properties(test_storage_targets_ec PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
add_test(NAME test_storage_targets_ec COMMAND test_storage_targets_ec)

add_executable(test_ec_worker_service_lifecycle TestECWorkerServiceLifecycle.cc)
target_link_libraries(test_ec_worker_service_lifecycle PRIVATE test-fabric-lib test_main)
set_target_properties(test_ec_worker_service_lifecycle PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
add_test(NAME test_ec_worker_service_lifecycle COMMAND test_ec_worker_service_lifecycle)

add_executable(test_ec_real_rpc TestECRealRPC.cc)
target_link_libraries(test_ec_real_rpc PRIVATE test-fabric-lib test_main)
set_target_properties(test_ec_real_rpc PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
add_test(NAME test_ec_real_rpc COMMAND test_ec_real_rpc)

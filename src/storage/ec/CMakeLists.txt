add_library(ec_shard_store STATIC ECShardStore.cc ECShardStore.h)
target_include_directories(ec_shard_store PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ec_shard_store PUBLIC ec_layout kv)

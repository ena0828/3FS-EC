add_crate(chunk_engine)

target_add_lib(storage core-app core-service memory-common storage-fbs mgmtd-client storage-client kv analytics aio chunk_engine profiler)
# Keep the standalone EC store out of the legacy storage archive.
get_target_property(_storage_sources storage SOURCES)
list(FILTER _storage_sources EXCLUDE REGEX "^ec/")
set_property(TARGET storage PROPERTY SOURCES "${_storage_sources}")
target_include_directories(storage PUBLIC ${CMAKE_SOURCE_DIR}/third_party/leveldb)
target_add_bin(storage_main "storage.cpp" storage jemalloc)

add_subdirectory(ec)
target_link_libraries(storage ec_shard_store)

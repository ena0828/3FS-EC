add_crate(chunk_engine)
add_subdirectory(ec_codec)

target_add_lib(storage core-app core-service memory-common storage-fbs mgmtd-client storage-client kv analytics aio chunk_engine profiler ec-codec)

# target_add_lib recursively discovers sources; the arithmetic wrapper belongs
# only to ec-codec so Meta can link it without linking the storage server.
get_target_property(STORAGE_SOURCES storage SOURCES)
list(REMOVE_ITEM STORAGE_SOURCES "ec_codec/EcCodec.cc" "ec_codec/EcCodec.h")
set_property(TARGET storage PROPERTY SOURCES ${STORAGE_SOURCES})
target_include_directories(storage PUBLIC ${CMAKE_SOURCE_DIR}/third_party/leveldb)
target_add_bin(storage_main "storage.cpp" storage jemalloc)

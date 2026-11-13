add_crate(chunk_engine)
add_subdirectory(ec_codec)
add_subdirectory(ec_repair)
add_subdirectory(ec_rmw)

target_add_lib(storage core-app core-service memory-common storage-fbs mgmtd-client storage-client kv analytics aio chunk_engine profiler ec-codec ec-repair ec-rmw-core)

# target_add_lib recursively discovers sources; the arithmetic wrapper belongs
# only to ec-codec so Meta can link it without linking the storage server.
get_target_property(STORAGE_SOURCES storage SOURCES)
list(REMOVE_ITEM STORAGE_SOURCES "ec_codec/EcCodec.cc" "ec_codec/EcCodec.h")
list(REMOVE_ITEM STORAGE_SOURCES "ec_repair/EcRepairPlan.cc" "ec_repair/EcRepairPlan.h"
     "ec_repair/EcHelperAuthorization.cc" "ec_repair/EcHelperAuthorization.h"
     "ec_repair/EcHelperDirectAuthorization.cc" "ec_repair/EcHelperDirectAuthorization.h")
list(REMOVE_ITEM STORAGE_SOURCES
  "ec_rmw/EcRmwPlan.cc" "ec_rmw/EcRmwPlan.h"
  "ec_rmw/EcRmwAuthorization.cc" "ec_rmw/EcRmwAuthorization.h"
  "ec_rmw/EcRmwComputation.cc" "ec_rmw/EcRmwComputation.h"
  "ec_rmw/EcRmwExecution.cc" "ec_rmw/EcRmwExecution.h"
  "ec_rmw/EcRmwPatchBuffer.cc" "ec_rmw/EcRmwPatchBuffer.h"
  "ec_rmw/EcRmwWire.cc" "ec_rmw/EcRmwWire.h"
)
set_property(TARGET storage PROPERTY SOURCES ${STORAGE_SOURCES})
target_include_directories(storage PUBLIC ${CMAKE_SOURCE_DIR}/third_party/leveldb)
target_add_bin(storage_main "storage.cpp" storage jemalloc)

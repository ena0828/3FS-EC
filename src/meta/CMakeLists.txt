target_add_lib(meta core-app core-user core-service fdb meta-fbs mgmtd-client storage-client memory-common analytics ec-codec ec-repair ec-rmw-core)
target_add_bin(meta_main "meta.cpp" meta jemalloc)

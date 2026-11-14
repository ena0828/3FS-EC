target_add_test(test_storage_service test-fabric-lib ec-client ec-codec ec-rmw-core)
# Share the exact on-disk pending-write seam with the native Meta tests.
target_sources(test_storage_service PRIVATE ${CMAKE_SOURCE_DIR}/tests/meta/EcPendingWriteFault.cc)
target_link_options(test_storage_service PRIVATE "LINKER:--wrap=pwrite" "LINKER:--wrap=pwrite64")

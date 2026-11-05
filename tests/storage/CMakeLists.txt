add_subdirectory(client)
add_subdirectory(service)
add_subdirectory(store)
add_subdirectory(sync)
target_add_test(test_storage test-fabric-lib)
# The standalone EC test has its own executable and CTest registration.
get_target_property(_test_storage_sources test_storage SOURCES)
list(FILTER _test_storage_sources EXCLUDE REGEX "^ec/")
set_property(TARGET test_storage PROPERTY SOURCES "${_test_storage_sources}")

add_subdirectory(ec)

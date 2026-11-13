target_add_test(test_meta meta fdb mgmtd test-fabric-lib ec-client)
# Exact pending-write fault injection belongs only to this test executable.
target_link_options(test_meta PRIVATE "LINKER:--wrap=pwrite" "LINKER:--wrap=pwrite64")

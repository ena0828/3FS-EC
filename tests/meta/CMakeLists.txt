target_add_test(test_meta meta fdb mgmtd test-fabric-lib ec-client)
# Only test executables opt in to exact pending-write fault injection.
target_link_options(test_meta PRIVATE "LINKER:--wrap=pwrite" "LINKER:--wrap=pwrite64")

target_add_bin(admin_cli "admin_cli.cc" admin-cli)

target_add_bin(ec_stripe_cli "ec_stripe_cli.cc" ec-client meta-client mgmtd-client)

target_add_bin(ec_file_cli "ec_file_cli.cc" ec-client meta-client mgmtd-client)
target_add_bin(ec_read_spool_cli "ec_read_spool_cli.cc" ec-client meta-client mgmtd-client)
target_add_bin(ec_mount_read_probe ec_mount_read_probe.cc hf3fs_api)

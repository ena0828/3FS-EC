find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)
target_add_lib(storage-fbs meta-fbs mgmtd-fbs OpenSSL::Crypto)

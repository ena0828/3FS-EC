fn main() {
    let _ = cxx_build::bridge("src/cxx.rs");
    println!("cargo:rerun-if-changed=src/cxx.rs");
    println!("cargo:rerun-if-env-changed=HF3FS_EC_ISAL_LIBDIR");

    #[cfg(feature = "isal-backend")]
    if let Some(directory) = std::env::var_os("HF3FS_EC_ISAL_LIBDIR") {
        let directory = std::path::PathBuf::from(directory);
        assert!(directory.is_absolute(), "HF3FS_EC_ISAL_LIBDIR must be absolute");
        let directory = directory
            .canonicalize()
            .expect("HF3FS_EC_ISAL_LIBDIR must be an existing directory");
        assert!(directory.is_dir(), "HF3FS_EC_ISAL_LIBDIR is not a directory");
        assert!(
            directory.join("libisal.so").is_file(),
            "HF3FS_EC_ISAL_LIBDIR must contain the dynamic libisal.so linker name"
        );
        let directory = directory.to_str().expect("ISA-L library path must be UTF-8");
        assert!(
            !directory.chars().any(char::is_control),
            "ISA-L library path must not contain control characters"
        );
        println!("cargo:rustc-link-search=native={directory}");
    } else {
        // Direct Cargo users explicitly enabling the feature may use their
        // system linker search. Missing ISA-L remains a link error, not fallback.
        println!(concat!(
            "cargo:warning=ISA-L backend uses the system linker search ",
            "(HF3FS_EC_ISAL_LIBDIR is unset)"
        ));
    }
}

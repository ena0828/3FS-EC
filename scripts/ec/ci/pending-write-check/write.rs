use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileExt;

// Borrow the caller's fd; exercise the same std FileExt path as ChunkEngine.
// This small test does not instantiate an Engine or provide a fake stage ACK.
#[no_mangle]
pub unsafe extern "C" fn checked_rust_write(fd: i32, bytes: *const u8, len: usize, offset: u64) -> i64 {
    let file = ManuallyDrop::new(File::from_raw_fd(fd));
    match file.write_at(std::slice::from_raw_parts(bytes, len), offset) {
        Ok(written) => written as i64,
        Err(error) => -(error.raw_os_error().unwrap_or(5) as i64),
    }
}

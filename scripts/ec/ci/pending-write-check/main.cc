#include <cerrno>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "tests/meta/EcPendingWriteFault.h"

extern "C" int64_t checked_rust_write(int, const void *, size_t, uint64_t);
namespace {
namespace fs = std::filesystem;
namespace fault = hf3fs::test::ec_pending;
constexpr size_t blockBytes = 65536;
void require(bool value, const char *message) {
  if (!value) throw std::runtime_error(message);
}
struct File {
  int fd;
  explicit File(const fs::path &path) : fd(::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) {
    require(fd >= 0, "create fresh data file");
  }
  explicit File(int descriptor) : fd(descriptor) { require(fd >= 0, "open owned data file"); }
  ~File() { if (fd >= 0) ::close(fd); }
  bool close() {
    const auto owned = fd;
    fd = -1;
    return ::close(owned) == 0;
  }
  File(const File &) = delete;
  File &operator=(const File &) = delete;
};
void written(int fd, const std::string &bytes, uint64_t offset) {
  require(checked_rust_write(fd, bytes.data(), bytes.size(), offset) == int64_t(bytes.size()), "Rust write failed");
}
void verify(int fd, const std::string &bytes, off_t offset) {
  std::string actual(bytes.size(), '\0');
  require(::pread(fd, actual.data(), actual.size(), offset) == ssize_t(actual.size()), "readback failed");
  require(actual == bytes, "readback differs");
}
}  // namespace

int main(int argc, char **argv) {
  try {
    require(argc == 2, "one fresh absolute directory required");
    const fs::path root(argv[1]);
    require(root.is_absolute() && fs::create_directory(root), "fresh directory required");
    fs::permissions(root, fs::perms::owner_all);
    require(fs::create_directory(root / "128KiB"), "fresh data class required");
    const auto directory = fs::canonical(root / "128KiB");
    constexpr char hex[] = "0123456789ABCDEF";
    for (unsigned i = 0; i != 256; ++i) {
      const std::string name{hex[i >> 4], hex[i & 15]};
      File file(directory / name);
    }
    File dataFile(::open((directory / "00").c_str(), O_RDWR | O_CLOEXEC));
    File otherFile(::open((directory / "01").c_str(), O_RDWR | O_CLOEXEC));
    const int data = dataFile.fd, other = otherFile.fd;
    const std::string first(blockBytes, 'A'), pending(blockBytes, 'B'), different(blockBytes, 'C');
    fault::captureNext(directory, first);
    errno = EDOM;
    written(data, first, 0);
    require(errno == EDOM, "successful delegated write changed incoming errno");
    verify(data, first, 0);
    const auto captured = fault::observation();
    struct stat info {};
    require(::fstat(data, &info) == 0, "fstat exact data file");
    require(captured.captures == 1 && captured.failures == 0 && captured.interceptionErrors == 0 &&
                captured.device == uint64_t(info.st_dev) && captured.inode == uint64_t(info.st_ino) &&
                captured.offset == 0,
            "actual Rust syscall was not captured exactly once");
    fault::failNext(captured, blockBytes, pending);
    // Different inode, payload and offset must still reach the real syscall.
    written(other, pending, blockBytes);
    written(data, different, blockBytes);
    written(data, pending, 2 * blockBytes);
    require(fault::observation().failures == 0, "nonmatching write consumed the fault");
    require(checked_rust_write(data, pending.data(), pending.size(), blockBytes) == -EIO,
            "exact Rust write did not see the injected EIO");
    const auto failed = fault::observation();
    require(failed.captures == 1 && failed.failures == 1 && failed.interceptionErrors == 0 &&
                failed.device == captured.device && failed.inode == captured.inode && failed.offset == blockBytes,
            "fault identity or count differs");
    verify(data, different, blockBytes);  // Refused call did not write its bytes.
    written(data, pending, blockBytes);   // One-shot failure; same fd/offset replay is real.
    verify(data, first, 0);
    verify(data, pending, blockBytes);
    verify(other, pending, blockBytes);
    verify(data, pending, 2 * blockBytes);
    require(fault::observation().failures == 1, "fault repeated");
    fault::reset();
    const bool otherClosed = otherFile.close();
    const bool dataClosed = dataFile.close();
    require(otherClosed && dataClosed, "owned descriptor close failed");
    std::cout << "Rust FileExt/pwrite wrapper: actual capture, one EIO, nonmatching delegation and byte replay passed\n";
    return 0;
  } catch (const std::exception &error) {
    fault::reset();
    std::cerr << error.what() << '\n';
    return 1;
  }
}

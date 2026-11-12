#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#include "lib/api/hf3fs_usrbio.h"

// A small application-level probe of the unchanged public C ABI. It never
// modifies the tested file. Unconfirmed accepted I/O is a process failure,
// never a reason to destroy shared buffers while the daemon may still use them.
namespace {
[[noreturn]] void unconfirmed() noexcept {
  constexpr char text[] = "USRBIO probe has unconfirmed accepted I/O; fail-stop before buffer cleanup.\n";
  (void)::write(STDERR_FILENO, text, sizeof(text) - 1);
  ::_Exit(EXIT_FAILURE);
}
struct Resources {
  hf3fs_iov data{};
  hf3fs_ior ring{};
  int fd = -1;
  bool dataReady = false, ringReady = false, registered = false;
  unsigned accepted = 0, completed = 0;
  ~Resources() {
    if (accepted != completed) unconfirmed();
    if (registered) hf3fs_dereg_fd(fd);
    if (ringReady) hf3fs_iordestroy(&ring);
    if (dataReady) hf3fs_iovdestroy(&data);
    if (fd >= 0) ::close(fd);
  }
};
void require(bool ok, const char *text) {
  if (!ok) throw std::runtime_error(text);
}
int run(int argc, char **argv) {
  if (argc != 5) {
    std::cerr << "ec_mount_read_probe MOUNTPOINT EC_FILE EXPECTED_FILE SHARD_BYTES\n";
    return 2;
  }
  uint64_t shard = 0;
  const std::string text(argv[4]);
  auto parsed = std::from_chars(text.data(), text.data() + text.size(), shard);
  require(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && shard && shard <= (1u << 20),
          "invalid fixed shard size");
  std::ifstream input(argv[3], std::ios::binary | std::ios::ate);
  require(bool(input), "cannot open expected data");
  const auto length = input.tellg();
  require(length > 0 && length <= std::streamoff(32u << 20), "expected data must be nonempty and <=32MiB");
  std::vector<uint8_t> expected(static_cast<size_t>(length));
  input.seekg(0);
  input.read(reinterpret_cast<char *>(expected.data()), expected.size());
  require(bool(input), "cannot read complete expected data");
  require(expected.size() >= 20 * shard, "cross-stripe probe requires at least two complete stripes");
  Resources resources;
  resources.fd = ::open(argv[2], O_RDONLY | O_CLOEXEC);
  require(resources.fd >= 0 && hf3fs_is_hf3fs(resources.fd), "not an open 3FS file");
  struct stat file {};
  require(::fstat(resources.fd, &file) == 0 && uint64_t(file.st_size) == expected.size(), "EOF mismatch");
  require(hf3fs_iovcreate(&resources.data, argv[1], 4u << 16, 1u << 16, -1) == 0, "cannot create data IOV");
  resources.dataReady = true;
  require(hf3fs_iorcreate(&resources.ring, argv[1], 8, true, 0, -1) == 0, "cannot create read IOR");
  resources.ringReady = true;
  require(hf3fs_reg_fd(resources.fd, 0) <= 0, "cannot register read-only descriptor");
  resources.registered = true;
  constexpr unsigned count = 3;
  const std::array<uint64_t, count> offsets{0, 10 * shard - 1, uint64_t(expected.size()) - 1};
  const std::array<uint64_t, count> lengths{std::min<uint64_t>(65536, 10 * shard), 2, 2};
  std::array<int, count> indices{};
  for (unsigned i = 0; i != count; ++i) {
    indices[i] = hf3fs_prep_io(&resources.ring,
                               &resources.data,
                               true,
                               resources.data.base + (i << 16),
                               resources.fd,
                               offsets[i],
                               lengths[i],
                               reinterpret_cast<void *>(uintptr_t(i + 1)));
    require(indices[i] >= 0, "cannot prepare bounded read");
    ++resources.accepted;  // SQE is visible before the optional submit hint.
  }
  if (hf3fs_submit_ios(&resources.ring) != 0) unconfirmed();
  std::array<bool, count> seen{};
  while (resources.completed != resources.accepted) {
    hf3fs_cqe completion[8]{};
    timespec deadline{};
    require(::clock_gettime(CLOCK_REALTIME, &deadline) == 0, "clock error");
    deadline.tv_sec += 300;
    const int received = hf3fs_wait_for_ios(&resources.ring, completion, 8, 1, &deadline);
    if (received <= 0) unconfirmed();
    for (int c = 0; c != received; ++c) {
      const auto id = reinterpret_cast<uintptr_t>(completion[c].userdata);
      if (id < 1 || id > count || seen[id - 1] || completion[c].index != indices[id - 1]) unconfirmed();
      const unsigned i = unsigned(id - 1);
      seen[i] = true;
      ++resources.completed;
      const auto expectedLength = std::min<uint64_t>(lengths[i], expected.size() - offsets[i]);
      require(completion[c].result == static_cast<int64_t>(expectedLength), "actual CQE length/error mismatch");
      require(std::memcmp(resources.data.base + (i << 16), expected.data() + offsets[i], expectedLength) == 0,
              "actual shared-memory readback differs");
    }
  }
  std::cout << "{\"actual_abi\":true,\"completed_reads\":3,\"cross_stripe\":true,\"eof_clipped\":true,\"bytes_equal\":"
               "true}\n";
  return 0;
}
}  // namespace
int main(int argc, char **argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}

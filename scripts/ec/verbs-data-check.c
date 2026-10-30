#define _POSIX_C_SOURCE 200809L
#include <infiniband/verbs.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Functional self-loop test: two real RC QPs, registered memory and CQ checks.
 * No throughput result is produced. Run in the isolated Soft-RoCE guest. */
static void fail(const char *message) {
  perror(message);
  exit(EXIT_FAILURE);
}

static void checked(int result, const char *message) {
  if (result) {
    errno = result;
    fail(message);
  }
}

static double now(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts)) fail("clock_gettime");
  return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void complete(struct ibv_cq *cq, uint64_t id, enum ibv_wc_opcode opcode) {
  const double deadline = now() + 10;
  const struct timespec pause = {.tv_nsec = 100000};
  while (now() < deadline) {
    struct ibv_wc wc;
    int count = ibv_poll_cq(cq, 1, &wc);
    if (count < 0) fail("ibv_poll_cq");
    if (!count) { nanosleep(&pause, NULL); continue; }
    if (wc.status != IBV_WC_SUCCESS || wc.wr_id != id || wc.opcode != opcode) {
      fprintf(stderr, "CQ failure: status=%s id=%llu opcode=%d vendor=%u\n",
              ibv_wc_status_str(wc.status), (unsigned long long)wc.wr_id,
              wc.opcode, wc.vendor_err);
      exit(EXIT_FAILURE);
    }
    return;
  }
  fprintf(stderr, "CQ timeout after 10 seconds\n");
  exit(EXIT_FAILURE);
}

static uint8_t next_byte(uint64_t *state) {
  *state ^= *state << 13;
  *state ^= *state >> 7;
  *state ^= *state << 17;
  return (uint8_t)*state;
}

static void verify(const uint8_t *buffer, size_t bytes, uint64_t seed) {
  for (size_t i = 0; i < bytes; ++i) {
    uint8_t expected = next_byte(&seed);
    if (buffer[i] != expected) {
      fprintf(stderr, "Byte mismatch at %zu: expected=%u actual=%u\n",
              i, expected, buffer[i]);
      exit(EXIT_FAILURE);
    }
  }
}

static void connect_qp(struct ibv_qp *qp, struct ibv_qp *peer, union ibv_gid gid,
                       int gid_index, enum ibv_mtu mtu) {
  struct ibv_qp_attr attr = {
      .qp_state = IBV_QPS_INIT, .port_num = 1, .pkey_index = 0,
      .qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE};
  checked(ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
                       IBV_QP_PORT | IBV_QP_ACCESS_FLAGS), "QP INIT");
  memset(&attr, 0, sizeof(attr));
  attr.qp_state = IBV_QPS_RTR;
  attr.path_mtu = mtu;
  attr.dest_qp_num = peer->qp_num;
  attr.rq_psn = 0;
  attr.max_dest_rd_atomic = 1;
  attr.min_rnr_timer = 12;
  attr.ah_attr.is_global = 1;
  attr.ah_attr.port_num = 1;
  attr.ah_attr.grh.dgid = gid;
  attr.ah_attr.grh.sgid_index = (uint8_t)gid_index;
  attr.ah_attr.grh.hop_limit = 1;
  checked(ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                       IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                       IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER), "QP RTR");
  memset(&attr, 0, sizeof(attr));
  attr.qp_state = IBV_QPS_RTS;
  attr.sq_psn = 0;
  attr.timeout = 14;
  attr.retry_cnt = 7;
  attr.rnr_retry = 7;
  attr.max_rd_atomic = 1;
  checked(ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_TIMEOUT |
                       IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
                       IBV_QP_MAX_QP_RD_ATOMIC), "QP RTS");
}

static void transfer(struct ibv_qp *qp, struct ibv_cq *cq, struct ibv_mr *local,
                     struct ibv_mr *remote, size_t bytes, uint64_t id,
                     enum ibv_wr_opcode opcode) {
  struct ibv_sge sge = {.addr = (uintptr_t)local->addr,
                       .length = (uint32_t)bytes, .lkey = local->lkey};
  struct ibv_send_wr wr = {.wr_id = id, .sg_list = &sge, .num_sge = 1,
                          .opcode = opcode, .send_flags = IBV_SEND_SIGNALED};
  struct ibv_send_wr *bad = NULL;
  wr.wr.rdma.remote_addr = (uintptr_t)remote->addr;
  wr.wr.rdma.rkey = remote->rkey;
  checked(ibv_post_send(qp, &wr, &bad), "ibv_post_send");
  complete(cq, id, opcode == IBV_WR_RDMA_WRITE ? IBV_WC_RDMA_WRITE : IBV_WC_RDMA_READ);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s DEVICE GID_INDEX\n", argv[0]);
    return EXIT_FAILURE;
  }
  char *end = NULL;
  long gid_index = strtol(argv[2], &end, 10);
  if (!*argv[2] || *end || gid_index < 0 || gid_index > 255) {
    fprintf(stderr, "Invalid GID index\n");
    return EXIT_FAILURE;
  }
  int count = 0;
  struct ibv_device **devices = ibv_get_device_list(&count);
  if (!devices) fail("ibv_get_device_list");
  struct ibv_context *context = NULL;
  for (int i = 0; i < count; ++i)
    if (!strcmp(ibv_get_device_name(devices[i]), argv[1])) {
      context = ibv_open_device(devices[i]);
      break;
    }
  if (!context) fail("ibv_open_device or device not found");
  struct ibv_port_attr port;
  checked(ibv_query_port(context, 1, &port), "ibv_query_port");
  if (port.state != IBV_PORT_ACTIVE) {
    fprintf(stderr, "Port is not ACTIVE\n");
    return EXIT_FAILURE;
  }
  union ibv_gid gid;
  checked(ibv_query_gid(context, 1, (int)gid_index, &gid), "ibv_query_gid");
  const uint8_t zero[16] = {0};
  if (!memcmp(gid.raw, zero, sizeof(zero))) {
    fprintf(stderr, "Selected GID is zero\n");
    return EXIT_FAILURE;
  }
  struct ibv_pd *pd = ibv_alloc_pd(context);
  struct ibv_cq *cq = ibv_create_cq(context, 16, NULL, NULL, 0);
  if (!pd || !cq) fail("PD/CQ allocation");
  struct ibv_qp_init_attr init = {
      .send_cq = cq, .recv_cq = cq, .qp_type = IBV_QPT_RC,
      .cap = {.max_send_wr = 8, .max_recv_wr = 8,
              .max_send_sge = 1, .max_recv_sge = 1}};
  struct ibv_qp *qp_a = ibv_create_qp(pd, &init);
  struct ibv_qp *qp_b = ibv_create_qp(pd, &init);
  if (!qp_a || !qp_b) fail("QP allocation");
  const enum ibv_mtu mtu = port.active_mtu < IBV_MTU_1024 ? port.active_mtu : IBV_MTU_1024;
  connect_qp(qp_a, qp_b, gid, (int)gid_index, mtu);
  connect_qp(qp_b, qp_a, gid, (int)gid_index, mtu);
  const size_t capacity = 114688;
  uint8_t *local = NULL, *remote = NULL;
  checked(posix_memalign((void **)&local, 4096, capacity), "local allocation");
  checked(posix_memalign((void **)&remote, 4096, capacity), "remote allocation");
  const int access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
  struct ibv_mr *local_mr = ibv_reg_mr(pd, local, capacity, access);
  struct ibv_mr *remote_mr = ibv_reg_mr(pd, remote, capacity, access);
  if (!local_mr || !remote_mr) fail("ibv_reg_mr");
  printf("device=%s gid_index=%ld mtu_enum=%d registered_bytes=%zu\n",
         argv[1], gid_index, mtu, 2 * capacity);
  const size_t sizes[] = {1, 4096, 114688};
  uint64_t id = 0;
  for (unsigned round = 0; round < 3; ++round) {
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
      const size_t bytes = sizes[s];
      uint64_t seed = UINT64_C(0x123456789abcdef) + round * 17 + s;
      uint64_t state = seed;
      for (size_t i = 0; i < bytes; ++i) local[i] = next_byte(&state);
      memset(remote, 0xcc, capacity);
      transfer(qp_a, cq, local_mr, remote_mr, bytes, ++id, IBV_WR_RDMA_WRITE);
      verify(remote, bytes, seed);
      for (size_t i = bytes; i < capacity; ++i)
        if (remote[i] != 0xcc) { fprintf(stderr, "Write changed tail at %zu\n", i); return 1; }
      memset(local, 0x3c, capacity);
      transfer(qp_a, cq, local_mr, remote_mr, bytes, ++id, IBV_WR_RDMA_READ);
      verify(local, bytes, seed);
      for (size_t i = bytes; i < capacity; ++i)
        if (local[i] != 0x3c) { fprintf(stderr, "Read changed tail at %zu\n", i); return 1; }
      printf("PASS round=%u bytes=%zu RDMA_WRITE+RDMA_READ content+tail verified\n", round, bytes);
    }
  }
  checked(ibv_destroy_qp(qp_a), "destroy QP A");
  checked(ibv_destroy_qp(qp_b), "destroy QP B");
  checked(ibv_dereg_mr(local_mr), "deregister local");
  checked(ibv_dereg_mr(remote_mr), "deregister remote");
  checked(ibv_destroy_cq(cq), "destroy CQ");
  checked(ibv_dealloc_pd(pd), "deallocate PD");
  checked(ibv_close_device(context), "close device");
  ibv_free_device_list(devices);
  free(local);
  free(remote);
  puts("PASS all real verbs transfers and byte checks");
  return EXIT_SUCCESS;
}

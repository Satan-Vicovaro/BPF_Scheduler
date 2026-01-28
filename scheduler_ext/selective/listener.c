// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include "selective.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

typedef unsigned long long u64;
typedef unsigned int u32;

typedef struct task_stats_ext {
  int call_function_counter;
  int last_used_index;

  u64 slice;
  int pid;
  int recent_used_cpu;
  long unsigned int last_switch_count;
  long unsigned int last_switch_time;

  // u64 voluntary_switch_count;
  // u64 involuntary_switch_count;

  u64 exec_max;

  u64 total_wait_ns;
  u64 max_wait_ns;
  u64 start_wait_ns;
  u64 wait_count;
} task_stats_ext;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {

  struct selective_bpf *skel;
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Open BPF application */
  skel = selective_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* ensure BPF program only handles write() syscalls from our process */
  // skel->bss->my_pid = getpid();
  /* Load & verify BPF programs */
  err = selective_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  printf("attaching sched");
  struct bpf_link *link = bpf_map__attach_struct_ops(skel->maps.sched_ops);
  if (!link) {
    fprintf(stderr, "Failed to register scheduler: %d\n", -errno);
    goto cleanup;
  }
  skel->links.sched_ops = link;

  // int map_fd = bpf_map__fd(skel->maps.task_storage);

  /* Attach tracepoint handler */
  err = selective_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  printf("Successfully started! The selective scheduler \n");

  struct bpf_link *iter_link =
      bpf_program__attach_iter(skel->progs.dump_task_stats, NULL);

  if (!iter_link) {
    fprintf(stderr, "Failed to attach iter_link\n");
    goto cleanup;
  }

  fprintf(stderr, ".");
  while (true) {

    int iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
    if (iter_fd < 0) {
      fprintf(stderr, "Failed to create iterator File Descriptor\n");
      break;
    }

    char buf[8192];
    int n = 0;
    fprintf(stderr, ".");
    while ((n = read(iter_fd, buf, sizeof(buf))) > 0) {
      write(STDOUT_FILENO, buf, n);
    }
    close(iter_fd);
    sleep(2);
  }

cleanup:
  selective_bpf__destroy(skel);
  return -err;
}

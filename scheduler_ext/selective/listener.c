// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include "selective.skel.h"
#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <stdbool.h>

typedef unsigned long long u64;
typedef unsigned int u32;

typedef struct task_statistics {
    int call_function_counter;
    int last_used_index;
    u64 slice;
    int pid;
} task_statistics;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{

    struct selective_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);


    printf("opening");
    /* Open BPF application */
    skel = selective_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* ensure BPF program only handles write() syscalls from our process */
    // skel->bss->my_pid = getpid();
    printf("loading");
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

    
    int map_fd = bpf_map__fd(skel->maps.array_map);

    /* Attach tracepoint handler */
    err = selective_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! The selective scheduler"
           " `/sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    while(true) {
        sleep(1);
        fprintf(stderr, ".");
        task_statistics stats;
        for(u32 i = 0; i < 10; i++) {
            // if (bpf_map__lookup_elem(&map_fd, &i, sizeof(u32), &stats, sizeof(task_statistics), 0) == 0) {
            //     printf("slice: %lld", stats.slice);
            // }

            if (bpf_map_lookup_elem(map_fd, &i, &stats) == 0) {
                printf("%d: enque_counter: %d pid: %d slice: %lld \n",i,stats.call_function_counter,stats.pid, stats.slice);
            }
        }
    }

cleanup:
    selective_bpf__destroy(skel);
    return -err;
}

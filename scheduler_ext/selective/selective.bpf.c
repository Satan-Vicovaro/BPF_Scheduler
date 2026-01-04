#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// there is some problem with headers:
// vmlinux.h is kinda weird with that
extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node_id) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern void scx_bpf_consume(u64 dsq_id) __ksym;
extern s32 scx_bpf_dsq_nr_queued(u64 dsq_id) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;

// Define a shared Dispatch Queue (DSQ) ID
#define SHARED_DSQ_ID 2

#define BPF_STRUCT_OPS(name, args...)	\
    SEC("struct_ops/"#name)	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...)	\
    SEC("struct_ops.s/"#name)							      \
    BPF_PROG(name, ##args)


typedef struct sched_data{
    int call_function_counter;
    int last_used_index;
} sched_data;

typedef struct task_statistics {
    int call_function_counter;
    int last_used_index;
    u64 slice;
    int pid;
} task_statistics;

// Array map definition
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, task_statistics);
} array_map SEC(".maps");

// Initialize the scheduler by creating a shared dispatch queue (DSQ)
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init) {
    // All scx_ functions come from vmlinux.h
    return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
}

// Enqueue a task to the shared DSQ that wants to run, 
// dispatching it with a time slice
int BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags) {
    static u32 last_used_index = 0;
    last_used_index = (last_used_index + 1) % 10;
    // reference to map
    struct task_statistics *stats = bpf_map_lookup_elem(&array_map, &last_used_index); 

    if(!stats) return -1;

    // Calculate the time slice for the task based on the number of tasks in the queue
    u64 slice = 10u;  // scx_bpf_dsq_nr_queued(SHARED_DSQ_ID); 
    stats->call_function_counter ++;
    stats->slice = slice;
    stats->pid = p->pid;

    scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, enq_flags);
    return 0;
}

// Dispatch a task from the shared DSQ to a CPU,
int BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev) {
    bpf_printk("Dispatching task\n");
    scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
    return 0;
}

// Define the main scheduler operations structure (sched_ops)
SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {
    .enqueue   = (void *)sched_enqueue,
    .dispatch  = (void *)sched_dispatch,
    .init      = (void *)sched_init,
    .flags     = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE,
    .name      = "selective"
};


// All schedulers have to be GPLv2 licensed
char _license[] SEC("license") = "GPL";

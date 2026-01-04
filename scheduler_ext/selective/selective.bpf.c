#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// there is some problem with headers:
// vmlinux.h is kinda weird with that
extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node_id) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice,
                               u64 enq_flags) __ksym;
extern void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice,
                             u64 enq_flags) __ksym;
extern void scx_bpf_consume(u64 dsq_id) __ksym;
extern s32 scx_bpf_dsq_nr_queued(u64 dsq_id) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;
extern void scx_bpf_kick_cpu(s32 cpu, u64 flags) __ksym;
// extern __u64 (*const bpf_ktime_get_boot_ns)(void) = (void *)125;

// Define a shared Dispatch Queue (DSQ) ID
#define SHARED_DSQ_ID 2  // normal
#define PARKING_DSQ_ID 3 // for tasks we hate and don't want to run
#define DELAY_NS 5000000000ULL
char forbidden_name[5] = "hello";
int time_to_unpark = 0;

#define BPF_STRUCT_OPS(name, args...)                                          \
    SEC("struct_ops/" #name) BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...)                                \
    SEC("struct_ops.s/" #name)                                                 \
    BPF_PROG(name, ##args)

typedef struct global_sched_data {
    int call_function_counter;
    unsigned int last_used_index;
} global_sched_data;

typedef struct task_stats_ext {
    int call_function_counter;
    int last_used_index;

    u64 slice;
    int pid;
    int recent_used_cpu;
    long unsigned int last_switch_count;
    long unsigned int last_switch_time;

    char comm[16];
    u64 total_wait_ns;
    u64 max_wait_ns;
    u64 start_wait_ns;
    u64 wait_count;
} task_stats_ext;

// Array map definition
struct {
    __uint(type, 29);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, task_stats_ext);
} task_storage SEC(".maps");

struct parking_lot {
    struct bpf_timer timer;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct parking_lot);

} timer_map SEC(".maps");

static int timer_cb(void *map, int *key, struct bpf_timer *timer)
{
    time_to_unpark = 1;
    scx_bpf_kick_cpu(0, 0);
    return 0;
}

// Initialize the scheduler by creating a shared dispatch queue (DSQ)
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init)
{
    // All scx_ functions come from vmlinux.h
    scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    scx_bpf_create_dsq(PARKING_DSQ_ID, -1); // second queue

    return 0;
}

// Enqueue a task to the shared DSQ that wants to run,
// dispatching it with a time slice
int BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags)
{

    u64 slice = 0u / scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);

    if (p->pid == 2137 || __builtin_memcmp(p->comm, forbidden_name,
                                           sizeof(forbidden_name)) == 0) {
        slice = 67;
        // scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, enq_flags);
        bpf_printk("Parking %s for %d seconds...\n", forbidden_name,
                   DELAY_NS / 1000000000);

        int key = 0;
        struct parking_lot *val = bpf_map_lookup_elem(&timer_map, &key);
        if (val) {
            bpf_timer_init(&val->timer, &timer_map, 1);
            bpf_timer_set_callback(&val->timer, timer_cb);
            bpf_timer_start(&val->timer, DELAY_NS, 0);
        }
        scx_bpf_dsq_insert(p, PARKING_DSQ_ID, slice, enq_flags);

    } else if (__builtin_memcmp(p->comm, forbidden_name,
                                sizeof(forbidden_name)) == 0) {
    } else {
        // Calculate the time slice for the task based on the number of tasks in
        // the queue
        slice = 50000000u / scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, enq_flags);
    }

    // ------------- stats for listener ---------------

    // global sched data
    static global_sched_data g_sched_data = {0, 0};

    // reference to  task map
    task_stats_ext *stats = bpf_task_storage_get(
        &task_storage, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);

    // stats
    if (stats) {
        stats->call_function_counter = g_sched_data.call_function_counter;
        stats->slice = slice;
        stats->pid = p->pid;
        stats->recent_used_cpu = p->recent_used_cpu;
        stats->last_switch_count = p->last_switch_count;
        stats->last_switch_time = p->last_switch_time;
        stats->start_wait_ns = bpf_ktime_get_boot_ns(); // now
        bpf_probe_read_kernel_str(stats->comm, sizeof(stats->comm), p->comm);
    }
    return 0;
}

// Dispatch a task from the shared DSQ to a CPU,
int BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev)
{
    if (time_to_unpark == 1) {
        bpf_printk("Dispaching from Parking");

        if (scx_bpf_dsq_move_to_local(PARKING_DSQ_ID)) {
            time_to_unpark = 0;
            return 0;
        }
    }
    scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
    return 0;
}

int BPF_STRUCT_OPS(sched_running, struct task_struct *p)
{
    // reference to task map
    task_stats_ext *stats = bpf_task_storage_get(
        &task_storage, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);

    if (!stats) {
        return 0;
    }

    if (stats->start_wait_ns == 0) {
        return 0;
    }

    u64 now = bpf_ktime_get_boot_ns();
    u64 wait_duration = now - stats->start_wait_ns;

    stats->total_wait_ns += wait_duration;
    stats->wait_count++;
    stats->start_wait_ns = 0;

    if (wait_duration > stats->max_wait_ns) {
        stats->max_wait_ns = wait_duration;
    }

    return 0;
}

// Define the main scheduler operations structure (sched_ops)
SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {.enqueue = (void *)sched_enqueue,
                                  .dispatch = (void *)sched_dispatch,
                                  .init = (void *)sched_init,
                                  .running = (void *)sched_running,
                                  .flags = SCX_OPS_ENQ_LAST |
                                           SCX_OPS_KEEP_BUILTIN_IDLE,
                                  .name = "selective"};

// helper for getting task_storage
SEC("iter/task")
int dump_task_stats(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (!task)
        return 0;

    task_stats_ext *stats = bpf_task_storage_get(&task_storage, task, 0, 0);
    if (!stats)
        return 0;

    if (stats->pid == 2137 || __builtin_memcmp(stats->comm, forbidden_name,
                                               sizeof(forbidden_name)) == 0) {

        BPF_SEQ_PRINTF(seq,
                       "------- Name: %-16s Pid: %-8d slice: %-10lld "
                       "max_wait(ms): %-10lld "
                       "total_wait(ms): %-10lld"
                       "wait_count: %-10lld\n",
                       stats->comm, stats->pid, stats->slice,
                       (stats->max_wait_ns) / 1000000,
                       stats->total_wait_ns / 1000000, stats->wait_count);
        return 0;
    }

    BPF_SEQ_PRINTF(seq,
                   "Name: %-16s Pid: %-8d slice: %-10lld max_wait(ms): %-10lld "
                   "total_wait(ms): %-10lld"
                   "wait_count: %-10lld\n",
                   stats->comm, stats->pid, stats->slice,
                   (stats->max_wait_ns) / 1000000,
                   stats->total_wait_ns / 1000000, stats->wait_count);
    return 0;
};

// All schedulers have to be GPLv2 licensed
char _license[] SEC("license") = "GPL";

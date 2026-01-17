#include <linux/sched.h>

// typedef struct sched_info {
// 	/* Cumulative counters: */
//
//   /* # of times we have run on this CPU: */
// 	unsigned long			pcount;
//
// 	/* Time spent waiting on a runqueue: */
// 	unsigned long long		run_delay;
//
// 	/* Timestamps: */
//
// 	/* When did we last run on a CPU? */
// 	unsigned long long		last_arrival;
//
// 	/* When were we last queued to run? */
// 	unsigned long long		last_queued;
// }sched_info;

// typedef struct sched_statistics {
// 	u64				wait_start;
// 	u64				wait_max;
// 	u64				wait_count;
// 	u64				wait_sum;
// 	u64				iowait_count;
// 	u64				iowait_sum;
//
// 	u64				sleep_start;
// 	u64				sleep_max;
// 	s64				sum_sleep_runtime;
//
// 	u64				block_start;
// 	u64				block_max;
// 	s64				sum_block_runtime;
//
// 	s64				exec_max;
// 	u64				slice_max;
//
// 	u64				nr_migrations_cold;
// 	u64				nr_failed_migrations_affine;
// 	u64				nr_failed_migrations_running;
// 	u64				nr_failed_migrations_hot;
// 	u64				nr_forced_migrations;
//
// 	u64				nr_wakeups;
// 	u64				nr_wakeups_sync;
// 	u64				nr_wakeups_migrate;
// 	u64				nr_wakeups_local;
// 	u64				nr_wakeups_remote;
// 	u64				nr_wakeups_affine;
// 	u64				nr_wakeups_affine_attempts;
// 	u64				nr_wakeups_passive;
// 	u64				nr_wakeups_idle;
//
// } sched_statistics;

// typedef struct thread_info {
//   unsigned long flags;
//   unsigned long syscall_work;
//   u32 status;
//   u32 cpu;
// } thread_info;

typedef struct TaskData {

  void *stack; // pointer to stack?

  int on_cpu;
  int recent_used_cpu;
  int wake_cpu;

  // On runqueue. Is task runnable
  // 0 - Blocked (not runnable)
  // 1 - Runnable
  // 2 - Migrating (moving from one CPU runqueue to other)?
  int on_rq;

  int prio;
  int static_prio;
  int normal_prio;

  int nr_wakeups;

  unsigned int policy;
  unsigned long max_allowed_capacity;

  int nr_cpus_allowed;

  int pid;  // pid_t type is an int type ig
  int tgid; // pid_t type is an int type ig
  unsigned long long run_delay;
  
  // too havy structs for ebpf  
  // struct thread_info thread_info;
  // struct sched_info sched_info;
  // struct sched_statistics sched_stats;
  //
} TaskData;

BPF_ARRAY(task_array, TaskData, 1);

int task_sniffer(void *ctx) {
  struct task_struct *task = (void *)bpf_get_current_task();
  int array_index = 0;
  TaskData task_data;
  task_data.stack = task->stack;
  task_data.on_cpu = task->on_cpu;
  task_data.wake_cpu = task->wake_cpu;
  task_data.on_rq = task->on_rq;
  task_data.prio = task->prio;
  task_data.static_prio = task->static_prio;
  task_data.normal_prio = task->normal_prio;
  task_data.policy = task->policy;
  task_data.pid = task->pid;
  task_data.tgid = task->tgid;

  // task_data.thread_info = task->thread_info;
  // task_data.sched_stats = task->stats;
  bpf_probe_read_kernel(&task_data.nr_wakeups,sizeof(u64), &task->stats.nr_wakeups);
  bpf_probe_read_kernel(&task_data.run_delay,sizeof(unsigned long long), &task->sched_info.run_delay);
  // task_data.max_allowed_capacity = task->max_allowed_capacity;
  // task_data.sched_info = task->sched_info;

  task_array.update(&array_index, &task_data);

  return 0;
}

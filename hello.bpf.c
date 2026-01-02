#include <linux/sched.h>

BPF_HASH(counter_table);

typedef struct TaskData {
  int prio;
  int static_prio;
  int normal_prio;
  int nr_cpus_allowed;
}TaskData;

BPF_ARRAY(task_array, TaskData, 4);

int hello_world(void *ctx) {
  u64 uid;
  u64 counter = 0;
  u64 *p;
  int task_struct_id = 4;
  struct TaskData task_data;
  struct task_struct *task = (void *)bpf_get_current_task();

  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  p = counter_table.lookup(&uid);
  if (p != 0) {
    counter = *p;
  }
  counter++;
  counter_table.update(&uid, &counter);
  

  task_data.prio = task->prio;
  task_data.static_prio = task->static_prio;
  task_data.normal_prio = task->normal_prio;
  task_data.nr_cpus_allowed = task->nr_cpus_allowed;

  bpf_trace_printk("prio: %d\nnr_cpus_allowed: %d\n", task_data.prio,task_data.nr_cpus_allowed);
  task_array.update(&task_struct_id, &task_data);

  return 0;
}

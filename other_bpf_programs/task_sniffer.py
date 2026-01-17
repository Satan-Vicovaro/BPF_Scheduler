from time import sleep
from bcc import BPF


b = BPF(src_file=b"task_sniffer.bpf.c")
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name=b"task_sniffer")

while True:
    sleep(2)
    for k, v in b["task_array"].items():
        print(f"--- Task Index {k.value} ---")
        print(f"PID: {v.pid}")
        print(f"TGID: {v.tgid}")
        print(f"On CPU: {v.on_cpu}")
        print(f"Priority: {v.prio}")
        print(f"State (on_rq): {v.on_rq}")
        print(f"Policy: {v.policy}")
        print(f"Stack pointer: {v.stack}")
        print(f"Wake cpu: {v.wake_cpu}")
        print(f"Nr wakeups: {v.nr_wakeups}")
        print(f"Time spent in queue: {v.run_delay}")
        print(f"Sched info:")
        # print(f"pcount: {v.sched_info.pcount}")
        # print(f"run delay: {v.sched_info.run_delay}")
        # print(f"last arrival: {v.sched_info.last_arrival}")
        # print(f"last queued: {v.sched_info.last_queued}")
        print("-" * 20)

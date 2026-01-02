#!/usr/bin/python3
from time import sleep
from bcc import BPF

b = BPF(src_file=b"hello.bpf.c")
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name=b"hello_world")


# b.trace_print()

while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        print(f"ID {k.value}: {v.value}")

    for k, v in b["task_array"].items():
        print(f"ID {k.value}: nr_cpus_allowed: {v.nr_cpus_allowed}\t")

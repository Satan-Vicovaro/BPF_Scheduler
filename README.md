# BPF_Scheduler
Simple scheduler made using eBPF with sched_ext. Made as a project for course System Software at Gdańsk University of Technology.

This repository contains selective scheduler, which try to starve specified task. Scheduler is using most basic shared dispatch queue, with round robin as a policy. User space program show data about all processes which were scheduled.

# Requirements
- kernel version 6.14 (versions 16.13 and 16.12 need minor changes in the code, names of functions have changed)
- clang with bpf compiler
- bpf tools
``` 
sudo apt install clang llvm libelf-dev libz-dev
```
- newest libbpf library
```
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src && make
```
Build & Run:
1) Place libbpf in root of this repository
2) Generate linux headers:
   ```
   cd scheduler_ext/selective/
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
   ```
3) Compile kernel code:
   ```
   clang -target bpf -g -O2 -c selective.bpf.c -o selective.bpf.o -I.
   ```
4) Generate skeleton header for user space program part:
   ```
   bpftool gen skeleton selective.bpf.o > selective.skel.h
   ```
5) Compile user space program:
   ```
    clang -g -O2 -Wall listener.c -o listener ./../../libbpf/src/libbpf.a -lelf -lz
   ```
6) Run scheduler:
   ```
   sudo ./listener
   ```

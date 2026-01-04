#!/bin/bash

set -e

clang -target bpf -g -O2 -c selective.bpf.c -o selective.bpf.o -I.

bpftool gen skeleton selective.bpf.o > selective.skel.h

clang -g -O2 -Wall listener.c -o listener ./../../libbpf/src/libbpf.a -lelf -lz

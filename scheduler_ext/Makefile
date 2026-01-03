CLANG := clang
BPFTOOL := bpftool
ARCH := x86

all: scheduler

# Compile Kernel side (.bpf.c -> .bpf.o)
%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

# Generate Skeleton (.bpf.o -> .skel.h)
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile User side (.c + .skel.h -> binary)
scheduler: minimal.c minimal.skel.h
	$(CC) -g -O2 -Wall minimal.c -o minimal -lbpf -lelf

clean:
	rm -f *.o *.skel.h minimal

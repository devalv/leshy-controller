BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip

CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
         -I/usr/include/$(shell uname -r) \
         -I/usr/include/x86_64-linux-gnu

all: l4_filter.o

l4_filter.o: l4_filter.c
	$(BPF_CLANG) $(CFLAGS) -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

clean:
	rm -f l4_filter.o

.PHONY: all clean

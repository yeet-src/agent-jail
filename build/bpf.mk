# Reusable BPF build rules, included by the project Makefile.
#
# The BPF program is modular: each src/bpf/*.bpf.c is a unit, compiled on
# its own, and all units are statically linked into ONE loadable object,
# bin/probe.bpf.o, with `bpftool gen object` — the same linker libbpf uses
# internally. Split the program across as many .bpf.c files as you like;
# share structs, maps and helpers through headers in src/bpf/include/ and
# the linker merges the duplicates. vmlinux.h (CO-RE) is generated there.
#
# To add another independent object, give it its own link target alongside
# bin/probe.bpf.o below — there is intentionally no per-object magic here.

CLANG   ?= clang
# bpftool frequently lives in /usr/sbin, which isn't always on a
# non-root user's PATH; fall back to it before giving up.
BPFTOOL ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)

# Map the host machine to the __TARGET_ARCH_* clang expects.
UNAME_M := $(shell uname -m)
ARCH    := $(UNAME_M:x86_64=x86)
ARCH    := $(ARCH:aarch64=arm64)

VMLINUX  := src/bpf/include/vmlinux.h
BPF_SRCS := $(wildcard src/bpf/*.bpf.c)
# One intermediate object per unit. They live under .build/ so they are
# never mistaken for the loadable object in bin/.
BPF_OBJS := $(patsubst src/bpf/%.bpf.c,.build/bpf/%.bpf.o,$(BPF_SRCS))
# The single linked object. Its `.bpf.o` suffix is what the JS side loads
# with `import probe from "../bin/probe.bpf.o"` (the loader's
# BpfObjectRule matches on that suffix).
BPF_OUT  := bin/probe.bpf.o

BPF_CFLAGS ?= -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -mcpu=v3 -I src/bpf/include

bpf: $(BPF_OUT)

$(VMLINUX):
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo "error: bpftool not found — install bpftool / linux-tools"; exit 1; }
	sh build/gen-vmlinux.sh $(BPFTOOL) $@

# Compile each unit to an intermediate object.
.build/bpf/%.bpf.o: src/bpf/%.bpf.c $(VMLINUX)
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "error: clang not found — install clang"; exit 1; }
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Statically link every unit into the single loadable object.
$(BPF_OUT): $(BPF_OBJS) | bin
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo "error: bpftool not found — install bpftool / linux-tools"; exit 1; }
	$(BPFTOOL) gen object $@ $(BPF_OBJS)

bin:
	mkdir -p bin

clean-bpf:
	rm -rf $(BPF_OUT) .build $(VMLINUX)

.PHONY: bpf clean-bpf

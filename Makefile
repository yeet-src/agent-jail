# Build the yeet script project.
#
#   make          — build everything (BPF object + JS bundle)
#   make bpf      — compile bpf/*.bpf.c into bin/probe.bpf.o only
#   make bundle   — bundle the JS entry with the vendored esbuild
#   make veristat — load the built object with veristat (verifier check on this kernel)
#   make adversary— build, then run the LSM jail-breakout self-test (0 leaks)
#   make clangd   — write a local .clangd pointing at the resolved toolchain
#   make clean    — remove build artifacts
#
# This is the build *frontend*: it orchestrates two independent compilers — clang
# for the BPF object, esbuild for the JS bundle. The JS references the compiled
# BPF object in bin/ only by path, resolved at runtime. `yeet run` invokes `make`
# automatically when running this project from a trusted remote source, so the
# default goal must leave the project runnable.
#
# This branch enforces with an eBPF LSM program (jail.bpf.c) — no Landlock C
# launcher. clang, bpftool and esbuild come from the static toolchain resolved by
# build/toolchain.mk (a shared per-machine cache, or host tools on PATH) — so the
# build needs no system C/BPF toolchain.

.DEFAULT_GOAL := all

include build/toolchain.mk
include build/bpf.mk

all: bpf bundle

# Bundle the entry with the vendored esbuild. esbuild honors tsconfig `paths`
# (so `@/` resolves at bundle time), while `yeet:*` builtins and `*.bpf.o`
# objects stay external. The bundle is written to src/index.jsx, which the entry
# ladder prefers over src/main.jsx — so once built, that is what runs.
#
# The build needs no npm/node: the script imports only `yeet:*` builtins and
# local `@/` modules, which esbuild resolves on its own. If you add third-party
# packages to package.json, install them into node_modules and esbuild inlines
# whatever it finds there.
ESBUILD_FLAGS := --bundle --format=esm --platform=neutral \
	--main-fields=module,main --conditions=import,module \
	--outfile=src/index.jsx --jsx=automatic --jsx-import-source=yeet:tui

bundle: | toolchain
	$(ESBUILD) src/main.jsx $(ESBUILD_FLAGS) '--external:yeet:*' '--external:*.bpf.o'

# Adversary self-test: prove the eBPF jail withstands escape attempts. Loads the
# LSM program, runs the breakout suite as an omp-comm process confined to a temp
# dir, and checks the jailed leak count is 0. Needs root for the BPF load.
adversary: bpf bundle
	@sudo sh scripts/adversary-lsm.sh

# Post-generation finalize: git init with the vendored git. Idempotent.
postgen: | vendored-git
	@g="$(GIT)"; [ -x "$$g" ] || g="$$(command -v git 2>/dev/null || true)"; \
	if [ -e .git ]; then \
		echo "postgen: already a git repository"; \
	elif [ -n "$$g" ]; then \
		echo "postgen: git init"; \
		"$$g" -c init.templateDir= init -q . || echo "warning: 'git init' failed" >&2; \
	else \
		echo "warning: no git available (vendored or host); skipping 'git init'" >&2; \
	fi

clean: clean-bpf
	rm -rf node_modules dist src/index.jsx

.PHONY: all bpf bundle adversary postgen clean

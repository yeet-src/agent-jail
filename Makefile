# Build the yeet script project.
#
#   make          — build everything (BPF object + Landlock launcher + JS bundle)
#   make bpf      — compile bpf/*.bpf.c into bin/probe.bpf.o only
#   make jail     — build the Landlock launcher (bin/agent-jail-bin) only
#   make bundle   — bundle the JS entry with the vendored esbuild
#   make veristat — load the built object with veristat (verifier check on this kernel)
#   make adversary— build, then run the jail-breakout self-test (must report 0 leaks)
#   make clangd   — write a local .clangd pointing at the resolved toolchain
#   make clean    — remove build artifacts
#
# This is the build *frontend*: it orchestrates two independent compilers — clang
# for the BPF object, esbuild for the JS bundle — plus the host C compiler for
# the small Landlock launcher. The JS references the compiled BPF object in bin/
# only by path, resolved at runtime. `yeet run` invokes `make` automatically when
# running this project from a trusted remote source, so the default goal must
# leave the project runnable.
#
# clang, bpftool and esbuild come from the static toolchain resolved by
# build/toolchain.mk (a shared per-machine cache, or host tools on PATH) — so the
# build needs no system C/BPF toolchain for the eBPF + bundle steps.

.DEFAULT_GOAL := all

include build/toolchain.mk
include build/bpf.mk

CC ?= cc

all: bpf jail bundle

# The Landlock launcher — a tiny dependency-free C binary that confines a process
# to one directory tree, then execs it. Built with the host C compiler (not the
# bpf-target clang) into bin/agent-jail-bin. The user-facing `agent-jail` command
# is the shell wrapper in scripts/. `bin` target comes from build/bpf.mk.
jail: bin/agent-jail-bin

bin/agent-jail-bin: src/jail/agent-jail.c | bin
	@command -v $(CC) >/dev/null 2>&1 || { echo "error: C compiler ($(CC)) not found — install clang or gcc"; exit 1; }
	$(CC) -O2 -Wall -o $@ $<

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

# Adversary self-test: prove the jail withstands escape attempts. Runs the
# breakout suite unconfined (baseline — attacks succeed) then jailed (all
# blocked). Needs root for the jailed run. The jailed leak count must be 0.
adversary: jail
	@echo "── baseline (unconfined): attacks should SUCCEED ──"
	-@sh scripts/adversary.sh; echo "  unconfined leaks: $$?"
	@echo "── jailed: every attack should be BLOCKED ──"
	@mkdir -p /tmp/agent-jail-selftest && cp scripts/adversary.sh /tmp/agent-jail-selftest/
	@sudo bin/agent-jail-bin /tmp/agent-jail-selftest -- /bin/sh /tmp/agent-jail-selftest/adversary.sh; \
		rc=$$?; echo "  jailed leaks: $$rc"; \
		[ "$$rc" -eq 0 ] && echo "PASS: jail held" || { echo "FAIL: $$rc leak(s)"; exit 1; }

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
	rm -rf node_modules dist src/index.jsx bin/agent-jail-bin

.PHONY: all jail bundle adversary postgen clean

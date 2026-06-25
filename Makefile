# Build the yeet script project.
#
#   make        — build everything (BPF objects + JS bundle)
#   make bpf    — compile bpf/*.bpf.c into bin/* only
#   make bundle — resolve npm/jsr deps and bundle the JS entry
#   make clean  — remove build artifacts
#
# This is the build *frontend*: it orchestrates two independent
# compilers — clang for the BPF objects, esbuild for the JS bundle.
# Neither understands the other; the JS references compiled objects in
# bin/ only by path, resolved at runtime. `yeet run` invokes `make`
# automatically when running this project from a trusted remote source,
# so the default goal must leave the project runnable.

.DEFAULT_GOAL := all

include build/bpf.mk

NPM ?= npm
CC  ?= cc

all: bpf jail bundle

# The Landlock launcher — a tiny dependency-free C binary that confines a
# process to one directory tree, then execs it. Built with the host C compiler
# (not the bpf-target clang) into bin/omp-jail-bin. The user-facing `omp-jail`
# command is the shell wrapper in scripts/, which backgrounds the watcher and
# runs this locked exec in the foreground. `bin` target comes from build/bpf.mk.
jail: bin/omp-jail-bin

bin/omp-jail-bin: src/jail/omp-jail.c | bin
	@command -v $(CC) >/dev/null 2>&1 || { echo "error: C compiler ($(CC)) not found — install clang or gcc"; exit 1; }
	$(CC) -O2 -Wall -o $@ $<

# Resolve npm/jsr dependencies and bundle the entry. esbuild inlines
# node_modules and honors tsconfig `paths` (so `@/` resolves at bundle
# time), while `yeet:*` builtins stay external. The bundle is written
# to src/index.jsx, which the entry ladder prefers over src/main.jsx —
# so once built, that is what runs. The .jsx extension keeps the bundle
# eligible for component auto-mount. Compiled BPF objects in bin/ are
# loaded by path at runtime, never imported, so they are not bundled.
bundle: node_modules
	$(NPM) run build

node_modules: package.json
	$(NPM) install
	@touch node_modules

# Adversary self-test: prove the jail withstands escape attempts. Runs the
# breakout suite unconfined (baseline — attacks succeed) then jailed (all
# blocked). Needs root for the jailed run. The jailed leak count must be 0.
adversary: jail
	@echo "── baseline (unconfined): attacks should SUCCEED ──"
	-@sh scripts/adversary.sh; echo "  unconfined leaks: $$?"
	@echo "── jailed: every attack should be BLOCKED ──"
	@mkdir -p /tmp/omp-jail-selftest && cp scripts/adversary.sh /tmp/omp-jail-selftest/
	@sudo bin/omp-jail-bin /tmp/omp-jail-selftest -- /bin/sh /tmp/omp-jail-selftest/adversary.sh; \
		rc=$$?; echo "  jailed leaks: $$rc"; \
		[ "$$rc" -eq 0 ] && echo "PASS: jail held" || { echo "FAIL: $$rc leak(s)"; exit 1; }

clean: clean-bpf
	rm -rf node_modules dist src/index.jsx bin/omp-jail-bin

.PHONY: all jail bundle adversary clean

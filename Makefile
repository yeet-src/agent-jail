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

all: bpf bundle

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

# Adversary self-test: prove the eBPF jail withstands escape attempts. Loads the
# LSM program, runs the breakout suite as an omp-comm process confined to a temp
# dir, and checks the jailed leak count is 0. Needs root for the BPF load.
adversary: bpf bundle
	@sudo sh scripts/adversary-lsm.sh

clean: clean-bpf
	rm -rf node_modules dist src/index.jsx

.PHONY: all bpf bundle adversary clean

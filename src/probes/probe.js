// Shared BPF object. The single jail.bpf.c unit is linked into bin/probe.bpf.o
// and loaded once here; the feature module (fileaccess.js) imports this
// `control` and reads/patches its maps. All binds happen before the single
// start(), so they live together here.
//
// jail.bpf.c is BOTH the enforcer and the observer: the lsm/file_open program
// blocks out-of-bounds opens (-EPERM) and emits each decision to `events`; the
// sched_process_fork/exit tracepoints maintain the jailed-subtree membership.
// All three auto-attach on start().
import { BpfObject } from "yeet:bpf";

// `base: import.meta.dirname` resolves the object path against the running bundle.
const probe = new BpfObject({ exe: "../bin/probe.bpf.o", base: import.meta.dirname });

export const control = await probe
  .bind("events", { kind: "ring_buf", btf_struct: "file_event" }) // open decisions
  .bind("jailed", { kind: "hash" }) // tgid -> jail_cfg (root + fork-propagated children)
  .bind("probe.data", { kind: "data" }) // target_prefix / _len / target_comm knobs
  .start(); // lsm/file_open + fork/exit tracepoints auto-attach

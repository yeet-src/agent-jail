// Shared BPF object. The single fileaccess.bpf.c unit is linked into
// bin/probe.bpf.o and loaded once here; the feature module (fileaccess.js)
// imports this `control` and reads/patches its maps. All binds happen before
// the single start(), so they live together here.
import { BpfObject } from "yeet:bpf";

// `base: import.meta.dirname` resolves the object path against the running bundle.
const probe = new BpfObject({ exe: "../bin/probe.bpf.o", base: import.meta.dirname });

export const control = await probe
  .bind("events", { kind: "ring_buf", btf_struct: "file_event" }) // open-attempt stream
  .bind("probe.data", { kind: "data" }) // target_prefix / _len / target_comm knobs
  .start(); // the openat/openat2 tracepoints auto-attach

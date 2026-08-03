---
title: "Linux Kernel Rootkits (LKM / ftrace-hooking)"
type: technique
tags: [linux, rootkit, lkm, kernel, evasion, persistence, anti-forensics, edr-evasion, post-exploitation]
phase: post-exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [gh-singularity-rootkit]
---

# Linux Kernel Rootkits (LKM / ftrace-hooking)

## What it is

A kernel-mode rootkit is code that runs at ring 0 to hide an attacker's presence and
maintain access after a host is already compromised as root. The dominant modern form on
Linux is a Loadable Kernel Module (LKM) that installs itself into a running kernel and
hooks system calls via the ftrace infrastructure to filter what userland tooling can see.
Reference implementation studied here: the Singularity rootkit (MatheuZSecurity), built for
kernel 6.x. Rootkits are post-exploitation: they require existing root, they do not grant it.
Related lineage: Diamorphine, KoviD, Basilisk, Reptile.

Distinguish this from [[kernel-exploitation]] (how you get to ring 0). A rootkit is what you
install once you are already there, to stay hidden.

## How it works

### Loading mechanism (LKM via ftrace)

The module is compiled against the running kernel's headers and inserted with `insmod`. It
resolves un-exported kernel symbols through a kprobe on `kallsyms_lookup_name` (the standard
post-5.7 workaround, since that symbol is no longer exported):

```c
struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
register_kprobe(&kp);
lookup = (void *)kp.addr;
unregister_kprobe(&kp);
```

Each hook is installed with ftrace by setting a filter on the target function entry and
registering an ftrace callback that rewrites the instruction pointer to the rootkit handler;
a `within_module()` guard on the caller stops the hook recursing into itself:

```c
hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
register_ftrace_function(&hook->ops);
```

This is the "ftrace_helper" pattern (fh_install_hook / fh_remove_hook) shared across most
modern educational rootkits. It hooks syscall entry functions by name (`__x64_sys_*` on
x86_64, `__ia32_sys_*` / `__ia32_compat_sys_*` for 32-bit compat), so it is architecture
aware and does not patch the syscall table directly.

Prerequisite kernel state the operator needs (and a defender can deny): module loading still
allowed (`kernel.modules_disabled = 0`), kernel headers / build tree present
(`/lib/modules/$(uname -r)/build`), and root.

### Persistence

Boot persistence without touching userland service files:

```bash
cp rootkit.ko /usr/lib/modules/$(uname -r)/kernel/rootkit.ko
depmod
echo rootkit > /etc/modules-load.d/rootkit.conf   # loaded by systemd-modules-load on boot
```

The module self-hides on load (removes itself from the module lists) and ships no unload
path by design, so removal requires a reboot into a clean kernel. An anti-tamper loader will
shred its own source tree if it detects `kernel.modules_disabled = 1`.

### Stealth techniques (what gets hooked and why)

| Goal | Hooked functions | Effect |
|---|---|---|
| Hide files/dirs | `getdents`/`getdents64`, `stat`/`lstat`/`statx`/`newfstatat`, `openat`, `readlinkat`, `chdir` | Directory entries matching a name pattern are filtered out; metadata and access to hidden paths blocked |
| Hide processes | `getdents` on /proc, `kill(sig 0)`, `getsid`/`getpgid`, `sched_get*`, `getpriority`, `pidfd_open`, `sysinfo`, taskstats netlink | PID vanishes from /proc, returns ESRCH; children auto-hidden via a `sched_process_fork` tracepoint |
| Hide network | `tcp4/6_seq_show`, `udp4/6_seq_show`, `tpacket_rcv`, netlink `recvmsg`/`recvfrom` (SOCK_DIAG, conntrack) | Connections on a chosen port/IP disappear from /proc/net, ss, netstat, lsof, conntrack; raw packets dropped (defeats tcpdump) |
| Privesc backdoor | `kill` with signal 59 | `kill -59 $$` calls `commit_creds(prepare_kernel_cred(NULL))` on the caller for instant uid 0; the same signal marks a PID hidden |
| Remote access | `icmp_rcv` | A crafted ICMP packet triggers a hidden root reverse shell to a hardcoded IP:port, with automatic SELinux enforcing to permissive downgrade |
| Log/forensics evasion | `read`/`preadv` on /proc/kmsg, /proc/kcore, /proc/kallsyms, nf_conntrack, kern.log; `do_syslog`; `write`/`writev`/`splice`/`sendfile`/`copy_file_range` | Sensitive keywords scrubbed in-place from dmesg, journalctl -k, debugfs raw-disk output; kernel taint flags reset; `ftrace_enabled` writes silently no-op'd |
| Anti-audit | `netlink_unicast`, `audit_log_start`, `recvmsg` | auditd/netlink messages for hidden PIDs dropped |
| Anti-eBPF (Falco/Tracee) | `bpf_iter_run_prog`, `bpf_ringbuf_*`, `bpf_map_lookup/update_elem`, `perf_event_output`, `__bpf_prog_run` | Filters the data eBPF programs collect rather than blocking the `bpf` syscall (blocking is itself a signature), so agents run but never see hidden resources |
| Anti-LKRG | LKRG internal symbols (`p_cmp_creds`, `p_cmp_tasks`, integrity/UMH checks) | Hooks the runtime-guard's own checks so hidden process trees pass validation |

The architectural idea behind the anti-EDR layer: intercept the kernel functions the
telemetry pipeline reads from, not the collection syscall itself, so the monitoring tool
keeps working and emits zero events for hidden objects.

### Operator usage (indicators to know as a defender)

```bash
kill -59 $$                 # become root + hide current shell (signal trigger)
kill -59 <PID>             # hide an arbitrary process
nc -lvnp 8081              # a listener on the magic port is hidden from ss/netstat/lsof
python3 trigger.py <ip>    # ICMP magic packet -> hidden root reverse shell, SELinux bypassed
```

## Attack phases

Post-exploitation only: persistence, defense evasion, anti-forensics. Assumes prior root.

## Prerequisites

Root; module loading enabled (`kernel.modules_disabled=0`); matching kernel headers to
compile the `.ko`.

## Detection and defence

Prevention (kills the whole class):
- Lock module loading after boot: `sysctl kernel.modules_disabled=1` (irreversible until
  reboot) and enable kernel lockdown (integrity/confidentiality mode).
- Enforce module signing (`CONFIG_MODULE_SIG_FORCE`) and Secure Boot so an unsigned `.ko`
  cannot load.
- Remove kernel headers / build toolchain from production hosts.

Detection (artifacts a ftrace rootkit cannot fully suppress):
- Kernel taint: read `/proc/sys/kernel/tainted` from a trusted context; a mismatch between a
  live read and an offline/collected value is itself the signal (rootkits reset it).
- Enumerate active ftrace hooks: unexpected callbacks on syscall entry points (`__x64_sys_*`)
  are the core IOC. Inspect `/sys/kernel/debug/tracing/enabled_functions` against a baseline.
- Cross-view analysis: a process or port visible from a memory image (Volatility) or a raw
  `/proc` walk but absent from `ps`/`ss` is a hidden object.
- On-disk persistence IOCs: unexpected `/etc/modules-load.d/*.conf`, stray `.ko` under
  `/usr/lib/modules/$(uname -r)/kernel/`, recent `depmod` timestamps.
- Signal/trigger IOCs: the kernel handling non-standard real-time signals (59/64) as a
  privilege trigger; anomalous inbound ICMP followed by a hidden outbound connection.
- Prefer out-of-band forensics (VM snapshot, cold image), since every in-host tool is on the
  rootkit filter path.
- Volatility 3 Linux plugins (`check_syscall`, `check_modules`, `check_ftrace`) are the
  canonical hunt for exactly this hook style.

## Tools

`insmod`/`rmmod`/`lsmod`, `depmod`; ftrace via `/sys/kernel/debug/tracing`; Volatility 3
Linux plugins; LKRG (both a target and a partial defense); auditd. Related: [[linux-persistence]],
[[linux-evasion]], [[kernel-exploitation]].

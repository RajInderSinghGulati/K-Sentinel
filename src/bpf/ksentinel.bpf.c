// SPDX-License-Identifier: GPL-2.0
/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * ksentinel.bpf.c — eBPF kernel-space program
 *
 * This program attaches to Linux kernel tracepoints on critical filesystem
 * system calls to provide real-time behavioral monitoring. It implements:
 *
 *   1. Honeyfile detection — immediate SIGKILL on unauthorized access
 *   2. Frequency tracking — per-PID operation counting in a sliding window
 *   3. Event telemetry — rich event data pushed to user-space via ring buffer
 *
 * Compilation requires: clang, llvm, libbpf, vmlinux.h (generated via bpftool)
 * This file is written on macOS but must be compiled on a Linux system.
 *
 * Copyright (c) 2026 K-Sentinel Project
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Include shared definitions (event structs, constants, enums) */
#include "../include/ksentinel_common.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Character classification (license)
 * eBPF programs loaded into the kernel must declare a GPL-compatible license
 * to access certain BPF helper functions (e.g., bpf_send_signal).
 * ───────────────────────────────────────────────────────────────────────────── */

char LICENSE[] SEC("license") = "GPL";

/* ─────────────────────────────────────────────────────────────────────────────
 * BPF Maps
 *
 * These maps are the shared data structures between the eBPF programs
 * and the user-space agent. They persist for the lifetime of the loaded
 * BPF program.
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * Ring Buffer — high-performance, variable-length event channel.
 * Events are pushed here by tracepoint handlers and consumed by
 * the user-space agent via ring_buffer__poll().
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, KSENTINEL_RINGBUF_SIZE);
} events SEC(".maps");

/*
 * Honeyfile Path Map — hash map of monitored canary file paths.
 * Key: honeyfile_key (canonicalized absolute path)
 * Value: u8 (non-zero = active honeyfile)
 *
 * The user-space agent populates this map at startup with all
 * deployed honeyfile paths. The eBPF program checks every openat()
 * target against this map for O(1) lookup.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KSENTINEL_MAX_HONEYFILES);
    __type(key, struct honeyfile_key);
    __type(value, __u8);
} honeyfile_map SEC(".maps");

/*
 * PID Frequency Map — per-PID sliding window operation counter.
 * Key: u32 (PID)
 * Value: pid_freq_entry (window start + operation count)
 *
 * Updated on every monitored syscall. If op_count exceeds
 * KSENTINEL_FREQ_THRESHOLD within the window, the event is flagged.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KSENTINEL_MAX_TRACKED_PIDS);
    __type(key, __u32);
    __type(value, struct pid_freq_entry);
} pid_freq_map SEC(".maps");

/*
 * Agent Configuration Map — runtime-tunable parameters.
 * Key: u32 (config key index)
 * Value: u64 (config value)
 *
 * Allows the user-space agent to dynamically adjust thresholds
 * without reloading the eBPF program.
 * Config keys:
 *   0 = frequency threshold
 *   1 = enable/disable auto-kill
 *   2 = frequency window (ns)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

/*
 * Allowlist — PIDs (TGIDs) that must never be killed by the sentinel
 * (e.g. the agent itself, the canary manager, trusted backup tools).
 * Key: u32 (PID), Value: u8 (non-zero = exempt). Populated by user space.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} allowlist_map SEC(".maps");

/* Returns 1 if the current process may be killed, 0 if allowlisted. */
static __always_inline int kill_allowed(void)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&allowlist_map, &pid) ? 0 : 1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: Populate common event fields
 *
 * Fills in process metadata (PID, TGID, UID, comm) from the current
 * task context. Called by every tracepoint handler.
 * ───────────────────────────────────────────────────────────────────────────── */

static __always_inline void populate_event_metadata(struct ksentinel_event *evt)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    evt->pid  = pid_tgid >> 32;        /* Upper 32 bits = TGID (userspace PID) */
    evt->tgid = pid_tgid & 0xFFFFFFFF; /* Lower 32 bits = TID */
    evt->uid  = uid_gid & 0xFFFFFFFF;  /* Lower 32 bits = UID */
    evt->gid  = uid_gid >> 32;         /* Upper 32 bits = GID */

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->flags = KSENTINEL_FLAG_NONE;
    evt->sample_len = 0;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* Read parent PID from current task_struct */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: Update per-PID frequency counter
 *
 * Implements a sliding window counter. If the current timestamp falls
 * within the existing window, the counter is incremented. If the window
 * has expired, a new window is started.
 *
 * Returns: 1 if the frequency threshold is exceeded, 0 otherwise.
 * ───────────────────────────────────────────────────────────────────────────── */

static __always_inline int update_pid_frequency(__u32 pid, __u64 now_ns)
{
    struct pid_freq_entry *entry;
    struct pid_freq_entry new_entry = {};
    int threshold_exceeded = 0;

    /* Runtime-tunable limits (config_map keys 0 and 2), with defaults */
    __u32 thr_key = 0, win_key = 2;
    __u64 threshold = KSENTINEL_FREQ_THRESHOLD;
    __u64 window_ns = KSENTINEL_FREQ_WINDOW_NS;
    __u64 *cfg;

    cfg = bpf_map_lookup_elem(&config_map, &thr_key);
    if (cfg && *cfg)
        threshold = *cfg;
    cfg = bpf_map_lookup_elem(&config_map, &win_key);
    if (cfg && *cfg)
        window_ns = *cfg;

    entry = bpf_map_lookup_elem(&pid_freq_map, &pid);

    if (entry) {
        /* Check if we're still within the sliding window */
        if ((now_ns - entry->window_start_ns) < window_ns) {
            /* Same window — increment counter */
            __sync_fetch_and_add(&entry->op_count, 1);
            if (entry->op_count > threshold) {
                threshold_exceeded = 1;
            }
        } else {
            /* Window expired — reset */
            new_entry.window_start_ns = now_ns;
            new_entry.op_count = 1;
            new_entry.flags = 0;
            bpf_map_update_elem(&pid_freq_map, &pid, &new_entry, BPF_ANY);
        }
    } else {
        /* First time seeing this PID — create new entry */
        new_entry.window_start_ns = now_ns;
        new_entry.op_count = 1;
        new_entry.flags = 0;
        bpf_map_update_elem(&pid_freq_map, &pid, &new_entry, BPF_ANY);
    }

    return threshold_exceeded;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: Check if a path is a honeyfile
 *
 * Performs an O(1) hash map lookup against the honeyfile_map.
 * Returns: 1 if the path matches a known honeyfile, 0 otherwise.
 * ───────────────────────────────────────────────────────────────────────────── */

static __always_inline int check_honeyfile(const char *path)
{
    struct honeyfile_key key = {};

    bpf_probe_read_user_str(&key.path, sizeof(key.path), path);

    __u8 *val = bpf_map_lookup_elem(&honeyfile_map, &key);
    return val ? 1 : 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Tracepoint: sys_enter_openat
 *
 * Intercepts every openat(2) system call. This is the primary detection
 * point for honeyfile access. When a process opens a file:
 *   1. The filename is extracted from the syscall arguments
 *   2. It is checked against the honeyfile hash map
 *   3. If it's a honeyfile → SIGKILL is sent immediately
 *   4. The PID frequency counter is updated
 *   5. An event is pushed to the ring buffer
 *
 * Tracepoint format (from /sys/kernel/debug/tracing/events/syscalls):
 *   field:int __syscall_nr;        offset:8;  size:4; signed:1;
 *   field:int dfd;                 offset:16; size:8; signed:0;
 *   field:const char * filename;   offset:24; size:8; signed:0;
 *   field:int flags;               offset:32; size:8; signed:0;
 *   field:umode_t mode;            offset:40; size:8; signed:0;
 * ───────────────────────────────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct ksentinel_event *evt;

    /* Reserve space in the ring buffer */
    if (!kill_allowed())
        return 0;   /* allowlisted process (e.g. the agent itself) */

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    /* Populate common metadata */
    populate_event_metadata(evt);
    evt->event_type = KSENTINEL_EVENT_OPEN;

    /* Extract filename from syscall args:
     * args[0] = dfd (directory file descriptor)
     * args[1] = filename pointer
     * args[2] = flags
     * args[3] = mode
     */
    const char *fname_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), fname_ptr);

    /* Extract open flags for write detection */
    int open_flags = (int)ctx->args[2];
    if (open_flags & 0x40)  /* O_CREAT = 0x40 */
        evt->flags |= KSENTINEL_FLAG_WRITE_NEW;
    if (open_flags & 0x200) /* O_TRUNC = 0x200 */
        evt->flags |= KSENTINEL_FLAG_WRITE_TRUNC;

    /* ── Honeyfile Detection ──────────────────────────────────────────────
     * CRITICAL PATH: If the opened file is a honeyfile, this is an
     * immediate indicator of unauthorized filesystem traversal.
     * Action: Send SIGKILL to the calling process immediately.
     */
    if (check_honeyfile(fname_ptr)) {
        evt->flags |= KSENTINEL_FLAG_HONEYFILE;

        /* Check if auto-kill is enabled via config map */
        __u32 config_key = 1;  /* Key 1 = auto-kill enable/disable */
        __u64 *auto_kill = bpf_map_lookup_elem(&config_map, &config_key);

        if ((!auto_kill || *auto_kill != 0) && kill_allowed()) {
            /* Auto-kill is enabled (default) — terminate the process */
            bpf_send_signal(9);  /* SIGKILL = 9 */
            evt->flags |= KSENTINEL_FLAG_KILLED;
        }
    }

    /* ── Frequency Analysis ───────────────────────────────────────────────
     * Update the per-PID operation counter and flag if threshold exceeded
     */
    if (update_pid_frequency(evt->pid, evt->timestamp_ns)) {
        evt->flags |= KSENTINEL_FLAG_HIGH_FREQ;
    }

    /* Submit event to ring buffer */
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Tracepoint: sys_enter_write
 *
 * Intercepts write(2) system calls. Monitors for high-frequency write
 * patterns which are characteristic of ransomware encryption operations.
 *
 * Tracepoint args:
 *   args[0] = unsigned int fd
 *   args[1] = const char __user *buf
 *   args[2] = size_t count
 * ───────────────────────────────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    struct ksentinel_event *evt;

    if (!kill_allowed())
        return 0;   /* allowlisted process (e.g. the agent itself) */

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    populate_event_metadata(evt);
    evt->event_type = KSENTINEL_EVENT_WRITE;

    /* Extract write arguments */
    evt->fd = (int)ctx->args[0];
    evt->write_size = (__u64)ctx->args[2];

    /* In-kernel entropy sampling: copy the head of the write buffer so the
     * user-space engine can estimate Shannon entropy (encrypted/compressed
     * data is near-uniform; documents and logs are not). */
    const void *wbuf = (const void *)ctx->args[1];
    __u64 wsz = evt->write_size;
    if (wsz >= KSENTINEL_SAMPLE_MIN) {
        __u32 n = wsz > KSENTINEL_SAMPLE_BYTES ? KSENTINEL_SAMPLE_BYTES : (__u32)wsz;
        if (bpf_probe_read_user(evt->sample, n, wbuf) == 0)
            evt->sample_len = n;
    }

    /* We don't have the filename for write() — the user-space agent
     * will correlate fd → filename via /proc/<pid>/fd/<fd> if needed */
    evt->filename[0] = '\0';

    /* Update frequency counter */
    if (update_pid_frequency(evt->pid, evt->timestamp_ns)) {
        evt->flags |= KSENTINEL_FLAG_HIGH_FREQ;

        /* High-frequency writes are dangerous — check auto-kill config */
        __u32 config_key = 1;
        __u64 *auto_kill = bpf_map_lookup_elem(&config_map, &config_key);
        if (auto_kill && *auto_kill == 2 && kill_allowed()) {
            /* Mode 2 = aggressive: kill on high-freq writes too */
            bpf_send_signal(9);
            evt->flags |= KSENTINEL_FLAG_KILLED;
        }
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Tracepoint: sys_enter_renameat2
 *
 * Intercepts rename operations. Ransomware often renames files after
 * encryption (e.g., adding .encrypted, .locked, .cry extensions).
 * Mass renaming is a strong behavioral signal.
 *
 * Tracepoint args:
 *   args[0] = int olddfd
 *   args[1] = const char __user *oldname
 *   args[2] = int newdfd
 *   args[3] = const char __user *newname
 *   args[4] = unsigned int flags
 * ───────────────────────────────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct ksentinel_event *evt;

    if (!kill_allowed())
        return 0;   /* allowlisted process (e.g. the agent itself) */

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    populate_event_metadata(evt);
    evt->event_type = KSENTINEL_EVENT_RENAME;

    /* Read the old filename (source of rename) */
    const char *oldname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), oldname);

    /* Check if the source file is a honeyfile */
    if (check_honeyfile(oldname)) {
        evt->flags |= KSENTINEL_FLAG_HONEYFILE;

        __u32 config_key = 1;
        __u64 *auto_kill = bpf_map_lookup_elem(&config_map, &config_key);
        if ((!auto_kill || *auto_kill != 0) && kill_allowed()) {
            bpf_send_signal(9);
            evt->flags |= KSENTINEL_FLAG_KILLED;
        }
    }

    /* Update frequency counter — mass renames are suspicious */
    if (update_pid_frequency(evt->pid, evt->timestamp_ns)) {
        evt->flags |= KSENTINEL_FLAG_HIGH_FREQ;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Tracepoint: sys_enter_unlinkat
 *
 * Intercepts file deletion. Some ransomware variants delete original
 * files after creating encrypted copies. Mass deletion is alarming.
 *
 * Tracepoint args:
 *   args[0] = int dfd
 *   args[1] = const char __user *pathname
 *   args[2] = int flag
 * ───────────────────────────────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct ksentinel_event *evt;

    if (!kill_allowed())
        return 0;   /* allowlisted process (e.g. the agent itself) */

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    populate_event_metadata(evt);
    evt->event_type = KSENTINEL_EVENT_UNLINK;

    /* Extract pathname */
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), pathname);

    /* Check if the deleted file is a honeyfile */
    if (check_honeyfile(pathname)) {
        evt->flags |= KSENTINEL_FLAG_HONEYFILE;

        __u32 config_key = 1;
        __u64 *auto_kill = bpf_map_lookup_elem(&config_map, &config_key);
        if ((!auto_kill || *auto_kill != 0) && kill_allowed()) {
            bpf_send_signal(9);
            evt->flags |= KSENTINEL_FLAG_KILLED;
        }
    }

    /* Update frequency counter */
    if (update_pid_frequency(evt->pid, evt->timestamp_ns)) {
        evt->flags |= KSENTINEL_FLAG_HIGH_FREQ;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

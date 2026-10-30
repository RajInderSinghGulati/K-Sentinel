/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * ksentinel_common.h — Shared definitions between kernel and user space
 *
 * This header defines the data structures, constants, and enumerations
 * shared between the eBPF kernel-space programs and the user-space agent.
 * It must remain compatible with both the BPF verifier constraints and
 * standard C compilation.
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

#ifndef __KSENTINEL_COMMON_H
#define __KSENTINEL_COMMON_H

/* ─────────────────────────────────────────────────────────────────────────────
 * Portable Type Definitions
 *
 * The BPF kernel programs use Linux kernel types (__u64, __u32, etc.).
 * When compiling user-space code on macOS (for testing), we provide
 * stdint-based equivalents.
 * ───────────────────────────────────────────────────────────────────────────── */

#ifndef __BPF__   /* Not compiling as eBPF — provide portable types */
#ifdef __linux__
#include <linux/types.h>
#else
#include <stdint.h>

typedef uint64_t __u64;
typedef uint32_t __u32;
typedef int64_t  __s64;
typedef int32_t  __s32;
typedef uint8_t  __u8;
#endif
#endif /* __BPF__ */

/* ─────────────────────────────────────────────────────────────────────────────
 * Constants
 * ───────────────────────────────────────────────────────────────────────────── */

/* Maximum length of a filename captured from syscall arguments */
#define KSENTINEL_MAX_FILENAME_LEN  256

/* Maximum length of process comm name (TASK_COMM_LEN in kernel) */
#define KSENTINEL_MAX_COMM_LEN      16

/* Bytes of each write() buffer sampled in-kernel for entropy analysis */
#define KSENTINEL_SAMPLE_BYTES      256
/* Writes smaller than this are not sampled (too few bytes for a stable estimate) */
#define KSENTINEL_SAMPLE_MIN        128

/* Maximum number of honeyfile paths tracked in the BPF hash map */
#define KSENTINEL_MAX_HONEYFILES    128

/* Maximum number of PIDs concurrently tracked for frequency analysis */
#define KSENTINEL_MAX_TRACKED_PIDS  4096

/* Ring buffer size in bytes (must be power of 2). 256 KB default. */
#define KSENTINEL_RINGBUF_SIZE      (256 * 1024)

/* Sliding window duration for frequency analysis (nanoseconds).
 * Default: 5 seconds = 5,000,000,000 ns */
#define KSENTINEL_FREQ_WINDOW_NS    5000000000ULL

/* Threshold: max file operations per PID within the sliding window
 * before triggering a high-frequency alert */
#define KSENTINEL_FREQ_THRESHOLD    50

/* Entropy threshold (Shannon entropy of write buffer).
 * Encrypted data typically has entropy > 7.5 (on a 0-8 scale) */
#define KSENTINEL_ENTROPY_THRESHOLD 7.5

/* ─────────────────────────────────────────────────────────────────────────────
 * Event Types — classifies the syscall that triggered the event
 * ───────────────────────────────────────────────────────────────────────────── */

enum ksentinel_event_type {
    KSENTINEL_EVENT_OPEN    = 0,  /* sys_enter_openat */
    KSENTINEL_EVENT_WRITE   = 1,  /* sys_enter_write  */
    KSENTINEL_EVENT_RENAME  = 2,  /* sys_enter_rename / renameat2 */
    KSENTINEL_EVENT_UNLINK  = 3,  /* sys_enter_unlinkat */
    KSENTINEL_EVENT_EXECVE  = 4,  /* sys_enter_execve */
    KSENTINEL_EVENT_CLOSE   = 5,  /* sys_enter_close  */
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Flags — bitmask of additional context carried with each event
 * ───────────────────────────────────────────────────────────────────────────── */

enum ksentinel_event_flags {
    KSENTINEL_FLAG_NONE         = 0,
    KSENTINEL_FLAG_HONEYFILE    = (1 << 0),  /* Target path is a honeyfile */
    KSENTINEL_FLAG_HIGH_FREQ    = (1 << 1),  /* PID exceeds frequency threshold */
    KSENTINEL_FLAG_WRITE_NEW    = (1 << 2),  /* File opened with O_CREAT */
    KSENTINEL_FLAG_WRITE_TRUNC  = (1 << 3),  /* File opened with O_TRUNC */
    KSENTINEL_FLAG_KILLED       = (1 << 4),  /* Process was terminated by agent */
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Core Event Structure — passed from kernel to user space via ring buffer
 *
 * This struct is the primary telemetry payload. Each syscall interception
 * produces one event that is pushed to the BPF ring buffer for the
 * user-space agent to consume.
 * ───────────────────────────────────────────────────────────────────────────── */

struct ksentinel_event {
    /* Monotonic kernel timestamp in nanoseconds (bpf_ktime_get_ns) */
    __u64 timestamp_ns;

    /* Process identification */
    __u32 pid;              /* Thread group leader PID (userspace PID) */
    __u32 tgid;             /* NOTE: holds the thread ID (TID); 'pid' is the TGID */
    __u32 uid;              /* Real user ID of the process */
    __u32 gid;              /* Real group ID of the process */
    __u32 ppid;             /* Parent process ID */

    /* Syscall context */
    enum ksentinel_event_type event_type;
    __u32 flags;            /* Bitmask of ksentinel_event_flags */
    __s64 syscall_ret;      /* Return value (populated on sys_exit hooks) */

    /* File descriptor / argument context */
    __s32 fd;               /* File descriptor (for write/close events) */
    __u64 write_size;       /* Number of bytes in the write call */

    /* Process metadata */
    char comm[KSENTINEL_MAX_COMM_LEN];       /* Process command name */
    char filename[KSENTINEL_MAX_FILENAME_LEN]; /* Target file path */

    /* In-kernel write-buffer sample (WRITE events only; 0 if not sampled) */
    __u32 sample_len;
    __u8  sample[KSENTINEL_SAMPLE_BYTES];
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-PID Frequency Tracking — stored in BPF hash map
 *
 * Tracks the number of file operations performed by each PID within
 * a sliding time window. Used for high-frequency file modification
 * detection (a key ransomware behavioral indicator).
 * ───────────────────────────────────────────────────────────────────────────── */

struct pid_freq_entry {
    __u64 window_start_ns;  /* Start of the current sliding window */
    __u32 op_count;         /* Number of operations in this window */
    __u32 flags;            /* Accumulated event flags for this window */
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Honeyfile Map Key — used in the honeyfile path hash map
 *
 * The key is a fixed-size buffer containing the canonicalized absolute
 * path of the honeyfile. The BPF program performs a hash map lookup
 * on every openat() call to check if the target is a honeyfile.
 * ───────────────────────────────────────────────────────────────────────────── */

struct honeyfile_key {
    char path[KSENTINEL_MAX_FILENAME_LEN];
};

#endif /* __KSENTINEL_COMMON_H */

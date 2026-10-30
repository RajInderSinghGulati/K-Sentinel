/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * ksentinel_events.h — Alert and response type definitions
 *
 * This header defines the structures and enumerations used by the
 * user-space detection and response engines. These types are NOT
 * shared with kernel space — they exist only in user-space logic.
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

#ifndef __KSENTINEL_EVENTS_H
#define __KSENTINEL_EVENTS_H

#include "ksentinel_common.h"
#include <time.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Alert Severity Levels
 *
 * Maps to the graduated response model:
 *   INFO     → Logged, no action
 *   LOW      → Logged, monitoring intensified
 *   MEDIUM   → Logged, process flagged for observation
 *   HIGH     → Logged, immediate SIGKILL candidate
 *   CRITICAL → Logged, SIGKILL executed, full incident report
 * ───────────────────────────────────────────────────────────────────────────── */

enum ksentinel_severity {
    KSENTINEL_SEV_INFO      = 0,
    KSENTINEL_SEV_LOW       = 1,
    KSENTINEL_SEV_MEDIUM    = 2,
    KSENTINEL_SEV_HIGH      = 3,
    KSENTINEL_SEV_CRITICAL  = 4,
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Detection Trigger Reason — explains why the alert was raised
 * ───────────────────────────────────────────────────────────────────────────── */

enum ksentinel_trigger_reason {
    KSENTINEL_TRIGGER_HONEYFILE_ACCESS   = 0,  /* Process touched a honeyfile */
    KSENTINEL_TRIGGER_HIGH_FREQUENCY     = 1,  /* Excessive file ops in window */
    KSENTINEL_TRIGGER_HIGH_ENTROPY       = 2,  /* Write buffer entropy > threshold */
    KSENTINEL_TRIGGER_MASS_RENAME        = 3,  /* Rapid file renaming pattern */
    KSENTINEL_TRIGGER_MASS_DELETE        = 4,  /* Rapid file deletion pattern */
    KSENTINEL_TRIGGER_COMBINED_SCORE     = 5,  /* Weighted behavioral score exceeded */
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Response Action — what mitigation was taken
 * ───────────────────────────────────────────────────────────────────────────── */

enum ksentinel_response_action {
    KSENTINEL_ACTION_NONE       = 0,  /* No action (info/low severity) */
    KSENTINEL_ACTION_LOG        = 1,  /* Alert logged to JSON file */
    KSENTINEL_ACTION_ALERT      = 2,  /* Alert pushed to dashboard */
    KSENTINEL_ACTION_THROTTLE   = 3,  /* Process I/O throttled (future) */
    KSENTINEL_ACTION_SIGKILL    = 4,  /* SIGKILL sent to process */
    KSENTINEL_ACTION_SIGSTOP    = 5,  /* SIGSTOP sent (pause for analysis) */
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Detection Result — output of the behavioral analysis engine
 *
 * Produced by detection_engine_analyze() for each incoming event.
 * Contains the threat assessment, scoring breakdown, and recommended
 * response action.
 * ───────────────────────────────────────────────────────────────────────────── */

struct ksentinel_detection_result {
    /* Overall threat assessment */
    enum ksentinel_severity         severity;
    enum ksentinel_trigger_reason   trigger;
    enum ksentinel_response_action  recommended_action;

    /* Behavioral scoring breakdown (0.0 – 1.0 each) */
    double score_honeyfile;      /* 1.0 if honeyfile was accessed */
    double score_frequency;      /* Normalized frequency score */
    double score_entropy;        /* Normalized entropy score */
    double score_rename;         /* Rename pattern score */
    double score_delete;         /* Deletion pattern score */
    double score_total;          /* Weighted composite score */

    /* Metadata */
    __u32  target_pid;           /* PID under analysis */
    char   target_comm[KSENTINEL_MAX_COMM_LEN]; /* Process name */
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Alert Record — serializable alert for logging and dashboard
 *
 * This is the final enriched alert that gets written to the JSON log
 * and pushed to the monitoring dashboard.
 * ───────────────────────────────────────────────────────────────────────────── */

struct ksentinel_alert {
    /* Unique alert ID (monotonically increasing) */
    __u64 alert_id;

    /* Timestamps */
    struct timespec wall_time;    /* Real wall-clock time */
    __u64 kernel_time_ns;         /* Kernel monotonic timestamp */

    /* Source event data */
    struct ksentinel_event event;

    /* Detection analysis result */
    struct ksentinel_detection_result detection;

    /* Response action actually taken */
    enum ksentinel_response_action action_taken;

    /* Whether the process was successfully killed */
    int kill_success;
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Agent Statistics — runtime counters for monitoring
 * ───────────────────────────────────────────────────────────────────────────── */

struct ksentinel_stats {
    __u64 events_received;       /* Total events from ring buffer */
    __u64 events_processed;      /* Events that passed filtering */
    __u64 alerts_generated;      /* Total alerts produced */
    __u64 processes_killed;      /* SIGKILL signals sent */
    __u64 honeyfile_hits;        /* Honeyfile access detections */
    __u64 freq_violations;       /* Frequency threshold violations */
    __u64 entropy_violations;    /* High entropy write detections */
    __u64 false_positives;       /* Manually marked false positives */
    __u64 uptime_seconds;        /* Agent uptime */
};

#endif /* __KSENTINEL_EVENTS_H */

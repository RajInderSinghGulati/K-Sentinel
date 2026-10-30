/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * detection_engine.h — Behavioral analysis engine interface
 *
 * The detection engine evaluates incoming eBPF events against multiple
 * behavioral heuristics to produce a threat score and severity level.
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

#ifndef __KSENTINEL_DETECTION_ENGINE_H
#define __KSENTINEL_DETECTION_ENGINE_H

#include "../include/ksentinel_common.h"
#include "../include/ksentinel_events.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Detection Engine Configuration
 * ───────────────────────────────────────────────────────────────────────────── */

struct detection_config {
    /* Scoring weights (must sum to 1.0) */
    double weight_honeyfile;    /* Weight for honeyfile access (default: 0.40) */
    double weight_frequency;    /* Weight for frequency score    (default: 0.25) */
    double weight_entropy;      /* Weight for entropy score      (default: 0.20) */
    double weight_rename;       /* Weight for rename patterns    (default: 0.10) */
    double weight_delete;       /* Weight for deletion patterns  (default: 0.05) */

    /* Thresholds */
    double entropy_threshold;   /* Shannon entropy threshold (default: 7.5) */
    unsigned int freq_threshold;       /* Ops per window threshold (default: 50) */
    double score_threshold_medium;     /* Score for MEDIUM severity (default: 0.3) */
    double score_threshold_high;       /* Score for HIGH severity   (default: 0.6) */
    double score_threshold_critical;   /* Score for CRITICAL        (default: 0.8) */

    /* Sliding window parameters */
    unsigned long long freq_window_ns; /* Window duration in nanoseconds */
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-PID Behavioral State — maintained in user-space for richer analysis
 * ───────────────────────────────────────────────────────────────────────────── */

#define PID_STATE_HASH_SIZE 4096

struct pid_behavior_state {
    unsigned int pid;
    char comm[KSENTINEL_MAX_COMM_LEN];

    /* Counters within current analysis window */
    unsigned int open_count;
    unsigned int write_count;
    unsigned int rename_count;
    unsigned int delete_count;
    unsigned int total_ops;

    /* Timing */
    unsigned long long window_start_ns;
    unsigned long long last_event_ns;

    /* Entropy accumulator */
    unsigned long long total_bytes_written;
    double accumulated_entropy;
    unsigned int entropy_samples;

    /* Honeyfile access flag */
    int honeyfile_accessed;

    /* Hash table linkage */
    struct pid_behavior_state *next;
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * Initialize the detection engine with the given configuration.
 * Must be called before any calls to detection_engine_analyze().
 * Returns 0 on success, -1 on failure.
 */
int detection_engine_init(const struct detection_config *config);

/*
 * Analyze an incoming eBPF event and produce a detection result.
 *
 * This is the main analysis entry point. It:
 *   1. Updates the per-PID behavioral state
 *   2. Computes individual scores (frequency, entropy, etc.)
 *   3. Calculates the weighted composite threat score
 *   4. Determines severity level and recommended action
 *
 * Parameters:
 *   event  — the raw event from the eBPF ring buffer
 *   result — output struct to be populated with the analysis result
 *
 * Returns 0 on success, -1 on error.
 */
int detection_engine_analyze(const struct ksentinel_event *event,
                             struct ksentinel_detection_result *result);

/*
 * Calculate the Shannon entropy of a byte buffer.
 *
 * Shannon entropy measures the randomness/information density of data.
 * Encrypted data (ransomware output) typically has entropy > 7.5 bits/byte,
 * while normal text/code has entropy < 5.0 bits/byte.
 *
 * Parameters:
 *   data — pointer to the byte buffer
 *   len  — length of the buffer
 *
 * Returns: entropy value in range [0.0, 8.0]
 */
double detection_engine_calculate_entropy(const unsigned char *data, size_t len);

/*
 * Get the current behavioral state for a specific PID.
 * Returns NULL if the PID is not currently tracked.
 */
const struct pid_behavior_state *detection_engine_get_pid_state(unsigned int pid);

/*
 * Reset the behavioral state for a specific PID.
 * Called when a process exits or is killed.
 */
void detection_engine_reset_pid(unsigned int pid);

/*
 * Clean up stale PID entries (processes that haven't been active
 * within 2x the sliding window duration).
 */
void detection_engine_cleanup_stale(void);

/*
 * Shut down the detection engine and free resources.
 */
void detection_engine_destroy(void);

#endif /* __KSENTINEL_DETECTION_ENGINE_H */

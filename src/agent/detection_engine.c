/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * detection_engine.c — Behavioral analysis engine implementation
 *
 * This module implements the core ransomware detection logic:
 *   1. Per-PID behavioral state tracking (sliding window)
 *   2. Shannon entropy calculation for write buffer analysis
 *   3. Frequency-based anomaly detection
 *   4. Weighted composite threat scoring
 *   5. Severity classification and action recommendation
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include "detection_engine.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal State
 * ───────────────────────────────────────────────────────────────────────────── */

static struct detection_config g_config;
static struct pid_behavior_state *g_pid_hash[PID_STATE_HASH_SIZE];
static int g_initialized = 0;

/* ─────────────────────────────────────────────────────────────────────────────
 * Hash Table Helpers — simple chained hash for PID → state mapping
 * ───────────────────────────────────────────────────────────────────────────── */

static unsigned int pid_hash(unsigned int pid)
{
    return pid % PID_STATE_HASH_SIZE;
}

static struct pid_behavior_state *find_pid_state(unsigned int pid)
{
    unsigned int h = pid_hash(pid);
    struct pid_behavior_state *s = g_pid_hash[h];
    while (s) {
        if (s->pid == pid)
            return s;
        s = s->next;
    }
    return NULL;
}

static struct pid_behavior_state *get_or_create_pid_state(unsigned int pid,
                                                           const char *comm)
{
    struct pid_behavior_state *s = find_pid_state(pid);
    if (s)
        return s;

    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    s->pid = pid;
    if (comm)
        strncpy(s->comm, comm, KSENTINEL_MAX_COMM_LEN - 1);

    unsigned int h = pid_hash(pid);
    s->next = g_pid_hash[h];
    g_pid_hash[h] = s;

    return s;
}

static void remove_pid_state(unsigned int pid)
{
    unsigned int h = pid_hash(pid);
    struct pid_behavior_state **pp = &g_pid_hash[h];
    while (*pp) {
        if ((*pp)->pid == pid) {
            struct pid_behavior_state *tmp = *pp;
            *pp = tmp->next;
            free(tmp);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Shannon Entropy Calculation
 *
 * Computes the information-theoretic entropy of a byte buffer.
 *
 * Formula: H(X) = -Σ p(x) * log2(p(x))
 *
 * Where p(x) is the probability of byte value x appearing in the buffer.
 *
 * Interpretation:
 *   0.0       — perfectly uniform (e.g., all zeros)
 *   < 4.0     — structured data (code, ASCII text)
 *   4.0 - 6.0 — mixed data (compressed/binary with headers)
 *   6.0 - 7.5 — moderately random (some compressed formats)
 *   > 7.5     — highly random (encrypted data, ransomware output)
 *   8.0       — theoretical maximum (perfect randomness)
 * ───────────────────────────────────────────────────────────────────────────── */

double detection_engine_calculate_entropy(const unsigned char *data, size_t len)
{
    if (!data || len == 0)
        return 0.0;

    /* Count byte value frequencies */
    unsigned int freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    /* Calculate Shannon entropy */
    double entropy = 0.0;
    double log2_val = log(2.0);

    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0)
            continue;

        double p = (double)freq[i] / (double)len;
        entropy -= p * (log(p) / log2_val);
    }

    return entropy;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Frequency Score Calculation
 *
 * Normalizes the operation count within the sliding window to a 0.0-1.0
 * score. Uses a sigmoid-like function to provide smooth scaling:
 *
 *   score = min(1.0, ops / (threshold * 2.0))
 *
 * This gives a linear increase up to 2x the threshold, capping at 1.0.
 * ───────────────────────────────────────────────────────────────────────────── */

static double calculate_frequency_score(const struct pid_behavior_state *state)
{
    if (g_config.freq_threshold == 0)
        return 0.0;

    double ratio = (double)state->total_ops / (double)(g_config.freq_threshold * 2);
    return ratio > 1.0 ? 1.0 : ratio;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Rename Pattern Score
 *
 * Calculates a normalized score based on the ratio of rename operations
 * to total operations. Ransomware typically shows a high rename ratio
 * (renaming files after encryption).
 * ───────────────────────────────────────────────────────────────────────────── */

static double calculate_rename_score(const struct pid_behavior_state *state)
{
    if (state->total_ops == 0)
        return 0.0;

    double rename_ratio = (double)state->rename_count / (double)state->total_ops;

    /* Boost score if rename count is high in absolute terms */
    double absolute_factor = 1.0;
    if (state->rename_count > 10)
        absolute_factor = 1.5;
    if (state->rename_count > 30)
        absolute_factor = 2.0;

    double score = rename_ratio * absolute_factor;
    return score > 1.0 ? 1.0 : score;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Deletion Pattern Score
 *
 * Similar to rename scoring but for unlink operations.
 * ───────────────────────────────────────────────────────────────────────────── */

static double calculate_delete_score(const struct pid_behavior_state *state)
{
    if (state->total_ops == 0)
        return 0.0;

    double delete_ratio = (double)state->delete_count / (double)state->total_ops;

    double absolute_factor = 1.0;
    if (state->delete_count > 10)
        absolute_factor = 1.5;
    if (state->delete_count > 30)
        absolute_factor = 2.0;

    double score = delete_ratio * absolute_factor;
    return score > 1.0 ? 1.0 : score;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Entropy Score Normalization
 *
 * Converts raw Shannon entropy (0-8) to a 0.0-1.0 threat score.
 * Uses a threshold-based curve:
 *   - Below threshold: score = 0
 *   - At threshold: score = 0.5
 *   - At maximum (8.0): score = 1.0
 * ───────────────────────────────────────────────────────────────────────────── */

static double calculate_entropy_score(const struct pid_behavior_state *state)
{
    if (state->entropy_samples == 0)
        return 0.0;

    double avg_entropy = state->accumulated_entropy / (double)state->entropy_samples;

    if (avg_entropy < g_config.entropy_threshold)
        return 0.0;

    /* Linear scale from threshold to 8.0 → 0.5 to 1.0 */
    double range = 8.0 - g_config.entropy_threshold;
    if (range <= 0.0)
        return 1.0;

    double normalized = (avg_entropy - g_config.entropy_threshold) / range;
    return 0.5 + (normalized * 0.5);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Severity Classification
 *
 * Maps the composite threat score to a severity level using configured
 * thresholds.
 * ───────────────────────────────────────────────────────────────────────────── */

static enum ksentinel_severity classify_severity(double score, int honeyfile_hit)
{
    /* Honeyfile access is always CRITICAL — no ambiguity */
    if (honeyfile_hit)
        return KSENTINEL_SEV_CRITICAL;

    if (score >= g_config.score_threshold_critical)
        return KSENTINEL_SEV_CRITICAL;
    if (score >= g_config.score_threshold_high)
        return KSENTINEL_SEV_HIGH;
    if (score >= g_config.score_threshold_medium)
        return KSENTINEL_SEV_MEDIUM;
    if (score > 0.0)
        return KSENTINEL_SEV_LOW;

    return KSENTINEL_SEV_INFO;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Action Recommendation
 *
 * Maps severity to a recommended response action.
 * ───────────────────────────────────────────────────────────────────────────── */

static enum ksentinel_response_action recommend_action(enum ksentinel_severity sev)
{
    switch (sev) {
    case KSENTINEL_SEV_CRITICAL:
        return KSENTINEL_ACTION_SIGKILL;
    case KSENTINEL_SEV_HIGH:
        return KSENTINEL_ACTION_SIGKILL;
    case KSENTINEL_SEV_MEDIUM:
        return KSENTINEL_ACTION_ALERT;
    case KSENTINEL_SEV_LOW:
        return KSENTINEL_ACTION_LOG;
    case KSENTINEL_SEV_INFO:
    default:
        return KSENTINEL_ACTION_NONE;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Determine Trigger Reason
 *
 * Identifies the primary reason an alert was triggered based on which
 * score component contributed the most.
 * ───────────────────────────────────────────────────────────────────────────── */

static enum ksentinel_trigger_reason determine_trigger(
    const struct ksentinel_detection_result *r)
{
    if (r->score_honeyfile > 0.0)
        return KSENTINEL_TRIGGER_HONEYFILE_ACCESS;

    /* Find the dominant score component */
    double max_score = r->score_frequency;
    enum ksentinel_trigger_reason reason = KSENTINEL_TRIGGER_HIGH_FREQUENCY;

    if (r->score_entropy > max_score) {
        max_score = r->score_entropy;
        reason = KSENTINEL_TRIGGER_HIGH_ENTROPY;
    }
    if (r->score_rename > max_score) {
        max_score = r->score_rename;
        reason = KSENTINEL_TRIGGER_MASS_RENAME;
    }
    if (r->score_delete > max_score) {
        max_score = r->score_delete;
        reason = KSENTINEL_TRIGGER_MASS_DELETE;
    }

    /* If no single component dominates, it's a combined score trigger */
    if (max_score < 0.3 && r->score_total >= g_config.score_threshold_medium)
        return KSENTINEL_TRIGGER_COMBINED_SCORE;

    return reason;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API Implementation
 * ───────────────────────────────────────────────────────────────────────────── */

int detection_engine_init(const struct detection_config *config)
{
    if (!config) {
        /* Apply sensible defaults */
        g_config.weight_honeyfile = 0.40;
        g_config.weight_frequency = 0.25;
        g_config.weight_entropy   = 0.25;
        g_config.weight_rename    = 0.10;
        g_config.weight_delete    = 0.05;

        g_config.entropy_threshold       = KSENTINEL_ENTROPY_THRESHOLD;
        g_config.freq_threshold          = KSENTINEL_FREQ_THRESHOLD;
        g_config.score_threshold_medium  = 0.3;
        g_config.score_threshold_high    = 0.45;
        g_config.score_threshold_critical = 0.7;
        g_config.freq_window_ns          = KSENTINEL_FREQ_WINDOW_NS;
    } else {
        memcpy(&g_config, config, sizeof(g_config));
    }

    memset(g_pid_hash, 0, sizeof(g_pid_hash));
    g_initialized = 1;

    fprintf(stderr, "[K-Sentinel] Detection engine initialized\n");
    fprintf(stderr, "  Weights: honeyfile=%.2f freq=%.2f entropy=%.2f "
                    "rename=%.2f delete=%.2f\n",
            g_config.weight_honeyfile, g_config.weight_frequency,
            g_config.weight_entropy, g_config.weight_rename,
            g_config.weight_delete);
    fprintf(stderr, "  Thresholds: entropy=%.1f freq=%u\n",
            g_config.entropy_threshold, g_config.freq_threshold);

    return 0;
}

int detection_engine_analyze(const struct ksentinel_event *event,
                             struct ksentinel_detection_result *result)
{
    if (!g_initialized || !event || !result)
        return -1;

    memset(result, 0, sizeof(*result));
    result->target_pid = event->pid;
    strncpy(result->target_comm, event->comm, KSENTINEL_MAX_COMM_LEN - 1);

    /* Get or create per-PID behavioral state */
    struct pid_behavior_state *state = get_or_create_pid_state(
        event->pid, event->comm);
    if (!state)
        return -1;

    /* ── Update behavioral state with this event ─────────────────────── */

    /* Check if we need to reset the sliding window */
    if (state->window_start_ns == 0 ||
        (event->timestamp_ns - state->window_start_ns) > g_config.freq_window_ns) {
        /* Window expired — reset counters but preserve some history */
        state->window_start_ns = event->timestamp_ns;
        state->open_count = 0;
        state->write_count = 0;
        state->rename_count = 0;
        state->delete_count = 0;
        state->total_ops = 0;
        state->accumulated_entropy = 0.0;
        state->entropy_samples = 0;
        state->honeyfile_accessed = 0;
    }

    state->last_event_ns = event->timestamp_ns;
    state->total_ops++;

    /* Update per-type counters */
    switch (event->event_type) {
    case KSENTINEL_EVENT_OPEN:
        state->open_count++;
        break;
    case KSENTINEL_EVENT_WRITE:
        state->write_count++;
        state->total_bytes_written += event->write_size;
        if (event->sample_len >= KSENTINEL_SAMPLE_MIN &&
            event->sample_len <= KSENTINEL_SAMPLE_BYTES) {
            double n = (double)event->sample_len;
            double h = detection_engine_calculate_entropy(event->sample,
                                                          event->sample_len);
            /* Expected entropy of a uniformly random n-byte sample (Miller-Madow):
             * E(n) ~= 8 - 255 / (2 n ln 2). Rescale so random data maps to ~8. */
            double expected = 8.0 - 255.0 / (2.0 * n * 0.693147);
            double scaled = h * 8.0 / expected;
            if (scaled > 8.0)
                scaled = 8.0;
            state->accumulated_entropy += scaled;
            state->entropy_samples++;
        }
        break;
    case KSENTINEL_EVENT_RENAME:
        state->rename_count++;
        break;
    case KSENTINEL_EVENT_UNLINK:
        state->delete_count++;
        break;
    default:
        break;
    }

    /* Check honeyfile flag from eBPF */
    if (event->flags & KSENTINEL_FLAG_HONEYFILE) {
        state->honeyfile_accessed = 1;
    }

    /* ── Calculate individual scores ─────────────────────────────────── */

    result->score_honeyfile = state->honeyfile_accessed ? 1.0 : 0.0;
    result->score_frequency = calculate_frequency_score(state);
    result->score_entropy   = calculate_entropy_score(state);
    result->score_rename    = calculate_rename_score(state);
    result->score_delete    = calculate_delete_score(state);

    /* ── Calculate weighted composite score ──────────────────────────── */

    result->score_total =
        (result->score_honeyfile * g_config.weight_honeyfile) +
        (result->score_frequency * g_config.weight_frequency) +
        (result->score_entropy   * g_config.weight_entropy) +
        (result->score_rename    * g_config.weight_rename) +
        (result->score_delete    * g_config.weight_delete);

    /* Clamp to [0.0, 1.0] */
    if (result->score_total > 1.0)
        result->score_total = 1.0;

    /* ── Classify and recommend ──────────────────────────────────────── */

    result->severity = classify_severity(result->score_total,
                                          state->honeyfile_accessed);
    result->trigger = determine_trigger(result);
    result->recommended_action = recommend_action(result->severity);

    return 0;
}

const struct pid_behavior_state *detection_engine_get_pid_state(unsigned int pid)
{
    return find_pid_state(pid);
}

void detection_engine_reset_pid(unsigned int pid)
{
    remove_pid_state(pid);
}

void detection_engine_cleanup_stale(void)
{
    unsigned long long now_ns;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    now_ns = (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    unsigned long long stale_threshold = g_config.freq_window_ns * 2;

    for (int i = 0; i < PID_STATE_HASH_SIZE; i++) {
        struct pid_behavior_state **pp = &g_pid_hash[i];
        while (*pp) {
            if ((now_ns - (*pp)->last_event_ns) > stale_threshold) {
                struct pid_behavior_state *tmp = *pp;
                *pp = tmp->next;
                free(tmp);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}

void detection_engine_destroy(void)
{
    for (int i = 0; i < PID_STATE_HASH_SIZE; i++) {
        struct pid_behavior_state *s = g_pid_hash[i];
        while (s) {
            struct pid_behavior_state *tmp = s;
            s = s->next;
            free(tmp);
        }
        g_pid_hash[i] = NULL;
    }
    g_initialized = 0;
    fprintf(stderr, "[K-Sentinel] Detection engine destroyed\n");
}

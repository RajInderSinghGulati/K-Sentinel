/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * event_handler.c — Ring buffer event processing implementation
 *
 * Receives raw events from the eBPF ring buffer, routes them through
 * the detection engine, and dispatches results to the response engine.
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "event_handler.h"
#include "detection_engine.h"
#include "response_engine.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal State
 * ───────────────────────────────────────────────────────────────────────────── */

static struct event_handler_config g_config;
static struct ksentinel_stats g_stats = {0};
static int g_initialized = 0;
static unsigned long long g_next_alert_id = 1;

/* Alert callback chain */
#define MAX_ALERT_CALLBACKS 8
static struct {
    alert_callback_fn fn;
    void *ctx;
    enum ksentinel_severity min_severity;
} g_alert_callbacks[MAX_ALERT_CALLBACKS];
static int g_num_callbacks = 0;

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: Get event type name for display
 * ───────────────────────────────────────────────────────────────────────────── */

static const char *event_type_name(enum ksentinel_event_type type)
{
    switch (type) {
    case KSENTINEL_EVENT_OPEN:   return "OPEN";
    case KSENTINEL_EVENT_WRITE:  return "WRITE";
    case KSENTINEL_EVENT_RENAME: return "RENAME";
    case KSENTINEL_EVENT_UNLINK: return "UNLINK";
    case KSENTINEL_EVENT_EXECVE: return "EXECVE";
    case KSENTINEL_EVENT_CLOSE:  return "CLOSE";
    default:                     return "UNKNOWN";
    }
}

static const char *severity_name(enum ksentinel_severity sev)
{
    switch (sev) {
    case KSENTINEL_SEV_INFO:     return "INFO";
    case KSENTINEL_SEV_LOW:      return "LOW";
    case KSENTINEL_SEV_MEDIUM:   return "MEDIUM";
    case KSENTINEL_SEV_HIGH:     return "HIGH";
    case KSENTINEL_SEV_CRITICAL: return "CRITICAL";
    default:                     return "UNKNOWN";
    }
}

static const char *severity_color(enum ksentinel_severity sev)
{
    switch (sev) {
    case KSENTINEL_SEV_INFO:     return "\033[37m";      /* White */
    case KSENTINEL_SEV_LOW:      return "\033[36m";      /* Cyan */
    case KSENTINEL_SEV_MEDIUM:   return "\033[33m";      /* Yellow */
    case KSENTINEL_SEV_HIGH:     return "\033[31m";      /* Red */
    case KSENTINEL_SEV_CRITICAL: return "\033[1;31m";    /* Bold Red */
    default:                     return "\033[0m";
    }
}

static const char *flags_description(unsigned int flags)
{
    static char buf[256];
    buf[0] = '\0';

    if (flags & KSENTINEL_FLAG_HONEYFILE)
        strcat(buf, "HONEYFILE ");
    if (flags & KSENTINEL_FLAG_HIGH_FREQ)
        strcat(buf, "HIGH_FREQ ");
    if (flags & KSENTINEL_FLAG_WRITE_NEW)
        strcat(buf, "CREAT ");
    if (flags & KSENTINEL_FLAG_WRITE_TRUNC)
        strcat(buf, "TRUNC ");
    if (flags & KSENTINEL_FLAG_KILLED)
        strcat(buf, "KILLED ");

    if (buf[0] == '\0')
        strcpy(buf, "NONE");

    return buf;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: Print event to console (verbose mode)
 * ───────────────────────────────────────────────────────────────────────────── */

static void print_event(const struct ksentinel_event *evt,
                        const struct ksentinel_detection_result *det)
{
    const char *color = severity_color(det->severity);
    const char *reset = "\033[0m";

    fprintf(stderr,
            "%s[%s]%s %-6s pid=%-6u comm=%-16s file=%-40s "
            "score=%.3f [%s]\n",
            color, severity_name(det->severity), reset,
            event_type_name(evt->event_type),
            evt->pid, evt->comm,
            evt->filename[0] ? evt->filename : "(n/a)",
            det->score_total,
            flags_description(evt->flags));
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: Fire alert callbacks
 * ───────────────────────────────────────────────────────────────────────────── */

static void fire_alert_callbacks(const struct ksentinel_alert *alert)
{
    for (int i = 0; i < g_num_callbacks; i++) {
        if (alert->detection.severity >= g_alert_callbacks[i].min_severity) {
            g_alert_callbacks[i].fn(alert, g_alert_callbacks[i].ctx);
        }
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API Implementation
 * ───────────────────────────────────────────────────────────────────────────── */

int event_handler_init(const struct event_handler_config *config)
{
    if (!config) {
        g_config.alert_log_path = "/var/log/ksentinel/alerts.json";
        g_config.verbose = 1;
        g_config.min_log_severity = KSENTINEL_SEV_LOW;
        g_config.min_console_severity = KSENTINEL_SEV_INFO;
    } else {
        memcpy(&g_config, config, sizeof(g_config));
    }

    memset(&g_stats, 0, sizeof(g_stats));
    g_next_alert_id = 1;
    g_num_callbacks = 0;
    g_initialized = 1;

    fprintf(stderr, "[K-Sentinel] Event handler initialized\n");
    return 0;
}

int event_handler_ringbuf_callback(void *ctx, void *data, size_t sz)
{
    (void)ctx;

    if (sz < sizeof(struct ksentinel_event)) {
        fprintf(stderr, "[K-Sentinel] WARNING: Received truncated event "
                        "(got %zu, expected %zu)\n",
                sz, sizeof(struct ksentinel_event));
        return 0;
    }

    const struct ksentinel_event *evt = (const struct ksentinel_event *)data;
    g_stats.events_received++;

    /* Ignore benign writes from essential system services (e.g. sshd sending encrypted network packets) */
    if (!(evt->flags & KSENTINEL_FLAG_HONEYFILE)) {
        if (strcmp(evt->comm, "sshd") == 0 ||
            strcmp(evt->comm, "systemd") == 0 ||
            strcmp(evt->comm, "systemd-journal") == 0 ||
            strcmp(evt->comm, "systemd-resolve") == 0 ||
            strcmp(evt->comm, "lima-guestagent") == 0 ||
            strcmp(evt->comm, "dbus-daemon") == 0) {
            return 0;
        }
    }

    /* ── Detection Analysis ──────────────────────────────────────────── */

    struct ksentinel_detection_result detection;
    int rc = detection_engine_analyze(evt, &detection);
    if (rc != 0) {
        fprintf(stderr, "[K-Sentinel] Detection engine error for PID %u\n",
                evt->pid);
        return 0;
    }

    g_stats.events_processed++;

    /* ── Console Output (verbose mode) ───────────────────────────────── */

    if (g_config.verbose &&
        detection.severity >= g_config.min_console_severity) {
        print_event(evt, &detection);
    }

    /* ── Update statistics ───────────────────────────────────────────── */

    if (evt->flags & KSENTINEL_FLAG_HONEYFILE)
        g_stats.honeyfile_hits++;
    if (evt->flags & KSENTINEL_FLAG_HIGH_FREQ)
        g_stats.freq_violations++;

    /* ── Response Execution ──────────────────────────────────────────── */

    if (detection.severity >= g_config.min_log_severity) {
        struct ksentinel_alert alert = {0};
        alert.alert_id = g_next_alert_id++;
        clock_gettime(CLOCK_REALTIME, &alert.wall_time);
        alert.kernel_time_ns = evt->timestamp_ns;
        memcpy(&alert.event, evt, sizeof(*evt));
        memcpy(&alert.detection, &detection, sizeof(detection));

        /* Execute response action */
        response_engine_execute(evt, &detection, &alert);

        g_stats.alerts_generated++;

        if (alert.kill_success)
            g_stats.processes_killed++;

        /* Fire registered callbacks */
        fire_alert_callbacks(&alert);
    }

    return 0;
}

void event_handler_register_alert_callback(alert_callback_fn callback,
                                           void *ctx,
                                           enum ksentinel_severity min_severity)
{
    if (g_num_callbacks >= MAX_ALERT_CALLBACKS) {
        fprintf(stderr, "[K-Sentinel] WARNING: Max alert callbacks reached\n");
        return;
    }

    g_alert_callbacks[g_num_callbacks].fn = callback;
    g_alert_callbacks[g_num_callbacks].ctx = ctx;
    g_alert_callbacks[g_num_callbacks].min_severity = min_severity;
    g_num_callbacks++;
}

const struct ksentinel_stats *event_handler_get_stats(void)
{
    return &g_stats;
}

void event_handler_destroy(void)
{
    g_initialized = 0;
    fprintf(stderr, "[K-Sentinel] Event handler destroyed\n");
    fprintf(stderr, "  Events received:   %llu\n", g_stats.events_received);
    fprintf(stderr, "  Events processed:  %llu\n", g_stats.events_processed);
    fprintf(stderr, "  Alerts generated:  %llu\n", g_stats.alerts_generated);
    fprintf(stderr, "  Processes killed:  %llu\n", g_stats.processes_killed);
    fprintf(stderr, "  Honeyfile hits:    %llu\n", g_stats.honeyfile_hits);
}

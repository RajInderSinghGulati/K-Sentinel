/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * response_engine.h — Mitigation and response action interface
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

#ifndef __KSENTINEL_RESPONSE_ENGINE_H
#define __KSENTINEL_RESPONSE_ENGINE_H

#include "../include/ksentinel_common.h"
#include "../include/ksentinel_events.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Response Engine Configuration
 * ───────────────────────────────────────────────────────────────────────────── */

struct response_config {
    /* Enable autonomous process killing (without user confirmation) */
    int auto_kill_enabled;

    /* Minimum severity required to issue SIGKILL */
    enum ksentinel_severity min_kill_severity;

    /* Path to the JSON incident log */
    const char *incident_log_path;

    /* Dashboard endpoint for push notifications (NULL to disable) */
    const char *dashboard_endpoint;

    /* Dry-run mode: log actions but don't actually kill processes */
    int dry_run;
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Incident Record — full forensic capture of a mitigation event
 * ───────────────────────────────────────────────────────────────────────────── */

struct ksentinel_incident {
    /* Alert that triggered the response */
    struct ksentinel_alert alert;

    /* Process forensic info */
    char exe_path[512];         /* Full path of the executable */
    char cmdline[1024];         /* Full command line */
    unsigned int parent_pid;    /* Parent PID */
    char parent_comm[KSENTINEL_MAX_COMM_LEN]; /* Parent command name */

    /* Response details */
    enum ksentinel_response_action action;
    int action_success;         /* 1 = success, 0 = failure */
    int kill_errno;             /* errno if kill() failed */

    /* Timestamp of the response action */
    struct timespec response_time;
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * Initialize the response engine.
 * Returns 0 on success, -1 on failure.
 */
int response_engine_init(const struct response_config *config);

/*
 * Execute the appropriate response action based on a detection result.
 *
 * This is the main mitigation entry point. Depending on the severity:
 *   - INFO/LOW:   Log only
 *   - MEDIUM:     Log + alert dashboard
 *   - HIGH:       Log + alert + SIGKILL candidate
 *   - CRITICAL:   Log + alert + immediate SIGKILL + incident report
 *
 * Note: For honeyfile access events, the eBPF program has already sent
 * SIGKILL in kernel space. This user-space response is a secondary
 * confirmation and logging mechanism.
 *
 * Parameters:
 *   event     — the original eBPF event
 *   detection — the detection engine's analysis result
 *   alert_out — populated with the final alert record (can be NULL)
 *
 * Returns 0 on success, -1 on error.
 */
int response_engine_execute(const struct ksentinel_event *event,
                            const struct ksentinel_detection_result *detection,
                            struct ksentinel_alert *alert_out);

/*
 * Attempt to kill a process by PID.
 *
 * Performs pre-kill safety checks:
 *   - Won't kill PID 1 (init) or PID 2 (kthreadd)
 *   - Won't kill the agent's own PID
 *   - Logs full forensic details before killing
 *
 * Parameters:
 *   pid  — target process ID
 *   sig  — signal to send (typically SIGKILL=9 or SIGSTOP=19)
 *
 * Returns 0 on success, -1 on failure (with errno set).
 */
int response_engine_kill_process(unsigned int pid, int sig);

/*
 * Log an alert to the JSON alert log file.
 */
int response_engine_log_alert(const struct ksentinel_alert *alert);

/*
 * Serialize an alert to a JSON string.
 * Caller must free the returned string.
 */
char *response_engine_alert_to_json(const struct ksentinel_alert *alert);

/*
 * Push an alert to the dashboard endpoint.
 * Returns 0 on success, -1 on failure.
 */
int response_engine_push_to_dashboard(const struct ksentinel_alert *alert);

/*
 * Shut down the response engine.
 */
void response_engine_destroy(void);

#endif /* __KSENTINEL_RESPONSE_ENGINE_H */

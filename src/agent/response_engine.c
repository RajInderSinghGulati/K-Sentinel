/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * response_engine.c — Mitigation and response action implementation
 *
 * Executes response actions based on detection results:
 *   - Process termination (SIGKILL/SIGSTOP)
 *   - JSON alert logging with full forensic context
 *   - Dashboard event push notifications
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>

#include "response_engine.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal State
 * ───────────────────────────────────────────────────────────────────────────── */

static struct response_config g_config;
static FILE *g_incident_log = NULL;
static int g_initialized = 0;
static pid_t g_own_pid = 0;

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: Severity to string
 * ───────────────────────────────────────────────────────────────────────────── */

static const char *severity_str(enum ksentinel_severity sev)
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

static const char *action_str(enum ksentinel_response_action action)
{
    switch (action) {
    case KSENTINEL_ACTION_NONE:     return "NONE";
    case KSENTINEL_ACTION_LOG:      return "LOG";
    case KSENTINEL_ACTION_ALERT:    return "ALERT";
    case KSENTINEL_ACTION_THROTTLE: return "THROTTLE";
    case KSENTINEL_ACTION_SIGKILL:  return "SIGKILL";
    case KSENTINEL_ACTION_SIGSTOP:  return "SIGSTOP";
    default:                        return "UNKNOWN";
    }
}

static const char *trigger_str(enum ksentinel_trigger_reason trigger)
{
    switch (trigger) {
    case KSENTINEL_TRIGGER_HONEYFILE_ACCESS: return "HONEYFILE_ACCESS";
    case KSENTINEL_TRIGGER_HIGH_FREQUENCY:   return "HIGH_FREQUENCY";
    case KSENTINEL_TRIGGER_HIGH_ENTROPY:     return "HIGH_ENTROPY";
    case KSENTINEL_TRIGGER_MASS_RENAME:      return "MASS_RENAME";
    case KSENTINEL_TRIGGER_MASS_DELETE:      return "MASS_DELETE";
    case KSENTINEL_TRIGGER_COMBINED_SCORE:   return "COMBINED_SCORE";
    default:                                 return "UNKNOWN";
    }
}

static const char *event_type_str(enum ksentinel_event_type type)
{
    switch (type) {
    case KSENTINEL_EVENT_OPEN:   return "openat";
    case KSENTINEL_EVENT_WRITE:  return "write";
    case KSENTINEL_EVENT_RENAME: return "renameat2";
    case KSENTINEL_EVENT_UNLINK: return "unlinkat";
    case KSENTINEL_EVENT_EXECVE: return "execve";
    case KSENTINEL_EVENT_CLOSE:  return "close";
    default:                     return "unknown";
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: Read /proc/<pid>/exe to get binary path
 * ───────────────────────────────────────────────────────────────────────────── */

static int read_proc_exe(unsigned int pid, char *buf, size_t buflen)
{
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/exe", pid);

    ssize_t len = readlink(proc_path, buf, buflen - 1);
    if (len < 0) {
        buf[0] = '\0';
        return -1;
    }
    buf[len] = '\0';
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: Read /proc/<pid>/cmdline
 * ───────────────────────────────────────────────────────────────────────────── */

static int read_proc_cmdline(unsigned int pid, char *buf, size_t buflen)
{
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/cmdline", pid);

    FILE *f = fopen(proc_path, "r");
    if (!f) {
        buf[0] = '\0';
        return -1;
    }

    size_t n = fread(buf, 1, buflen - 1, f);
    fclose(f);

    /* cmdline uses NUL as separator — replace with spaces */
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == '\0')
            buf[i] = ' ';
    }
    if (n > 0)
        buf[n - 1] = '\0';
    else
        buf[0] = '\0';

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API Implementation
 * ───────────────────────────────────────────────────────────────────────────── */

int response_engine_init(const struct response_config *config)
{
    if (!config) {
        g_config.auto_kill_enabled = 1;
        g_config.min_kill_severity = KSENTINEL_SEV_HIGH;
        g_config.incident_log_path = "/var/log/ksentinel/incidents.json";
        g_config.dashboard_endpoint = NULL;
        g_config.dry_run = 0;
    } else {
        memcpy(&g_config, config, sizeof(g_config));
    }

    g_own_pid = getpid();

    /* Open incident log file (append mode) */
    if (g_config.incident_log_path) {
        g_incident_log = fopen(g_config.incident_log_path, "a");
        if (!g_incident_log) {
            fprintf(stderr, "[K-Sentinel] WARNING: Cannot open incident log: %s\n",
                    g_config.incident_log_path);
            /* Non-fatal — continue without file logging */
        }
    }

    g_initialized = 1;

    fprintf(stderr, "[K-Sentinel] Response engine initialized\n");
    fprintf(stderr, "  Auto-kill: %s | Min kill severity: %s | Dry-run: %s\n",
            g_config.auto_kill_enabled ? "ENABLED" : "DISABLED",
            severity_str(g_config.min_kill_severity),
            g_config.dry_run ? "YES" : "NO");

    return 0;
}

int response_engine_kill_process(unsigned int pid, int sig)
{
    /* Safety checks — never kill critical system processes or ourselves */
    if (pid <= 2) {
        fprintf(stderr, "[K-Sentinel] REFUSED: Will not kill PID %u "
                        "(system critical)\n", pid);
        return -1;
    }

    if ((pid_t)pid == g_own_pid) {
        fprintf(stderr, "[K-Sentinel] REFUSED: Will not kill own PID %u\n", pid);
        return -1;
    }

    /* Log forensic info before killing */
    char exe_path[512] = {0};
    char cmdline[1024] = {0};
    read_proc_exe(pid, exe_path, sizeof(exe_path));
    read_proc_cmdline(pid, cmdline, sizeof(cmdline));

    /* Safety check: Never kill essential system daemons (sshd, systemd, lima-guestagent, shells) */
    if (strstr(exe_path, "sshd") || strstr(cmdline, "sshd") ||
        strstr(exe_path, "systemd") || strstr(cmdline, "systemd") ||
        strstr(exe_path, "lima-guestagent") || strstr(cmdline, "lima-guestagent") ||
        strstr(exe_path, "dbus-daemon") || strstr(cmdline, "dbus-daemon") ||
        strstr(cmdline, "dashboard_bridge.py")) {
        fprintf(stderr, "[K-Sentinel] REFUSED: Will not kill protected system service PID %u (%s)\n",
                pid, exe_path[0] ? exe_path : cmdline);
        return -1;
    }

    fprintf(stderr, "\033[1;31m[K-Sentinel] KILLING PID %u\033[0m\n", pid);
    fprintf(stderr, "  Executable: %s\n", exe_path[0] ? exe_path : "(unknown)");
    fprintf(stderr, "  Cmdline:    %s\n", cmdline[0] ? cmdline : "(unknown)");
    fprintf(stderr, "  Signal:     %d (%s)\n", sig,
            sig == SIGKILL ? "SIGKILL" : sig == SIGSTOP ? "SIGSTOP" : "OTHER");

    if (g_config.dry_run) {
        fprintf(stderr, "  Mode:       DRY-RUN (not actually killing)\n");
        return 0;
    }

    /* Send the signal */
    int ret = kill((pid_t)pid, sig);
    if (ret != 0) {
        fprintf(stderr, "  Result:     FAILED (errno=%d: %s)\n",
                errno, strerror(errno));
        return -1;
    }

    fprintf(stderr, "  Result:     SUCCESS — process terminated\n");
    return 0;
}

char *response_engine_alert_to_json(const struct ksentinel_alert *alert)
{
    if (!alert)
        return NULL;

    /* Allocate a generous buffer for the JSON output */
    size_t buflen = 4096;
    char *buf = malloc(buflen);
    if (!buf)
        return NULL;

    /* Format wall clock time */
    char time_str[64];
    struct tm tm_info;
    localtime_r(&alert->wall_time.tv_sec, &tm_info);
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", &tm_info);

    int written = snprintf(buf, buflen,
        "{"
        "\"alert_id\":%llu,"
        "\"timestamp\":\"%s.%03ld\","
        "\"kernel_time_ns\":%llu,"
        "\"severity\":\"%s\","
        "\"trigger\":\"%s\","
        "\"action_taken\":\"%s\","
        "\"kill_success\":%s,"
        "\"event\":{"
            "\"type\":\"%s\","
            "\"pid\":%u,"
            "\"tgid\":%u,"
            "\"uid\":%u,"
            "\"ppid\":%u,"
            "\"comm\":\"%s\","
            "\"filename\":\"%s\","
            "\"write_size\":%llu,"
            "\"flags\":%u"
        "},"
        "\"scores\":{"
            "\"honeyfile\":%.4f,"
            "\"frequency\":%.4f,"
            "\"entropy\":%.4f,"
            "\"rename\":%.4f,"
            "\"delete\":%.4f,"
            "\"total\":%.4f"
        "}"
        "}\n",
        (unsigned long long)alert->alert_id,
        time_str, alert->wall_time.tv_nsec / 1000000,
        (unsigned long long)alert->kernel_time_ns,
        severity_str(alert->detection.severity),
        trigger_str(alert->detection.trigger),
        action_str(alert->action_taken),
        alert->kill_success ? "true" : "false",
        event_type_str(alert->event.event_type),
        alert->event.pid,
        alert->event.tgid,
        alert->event.uid,
        alert->event.ppid,
        alert->event.comm,
        alert->event.filename,
        (unsigned long long)alert->event.write_size,
        alert->event.flags,
        alert->detection.score_honeyfile,
        alert->detection.score_frequency,
        alert->detection.score_entropy,
        alert->detection.score_rename,
        alert->detection.score_delete,
        alert->detection.score_total
    );

    if (written < 0 || (size_t)written >= buflen) {
        free(buf);
        return NULL;
    }

    return buf;
}

int response_engine_log_alert(const struct ksentinel_alert *alert)
{
    if (!g_incident_log || !alert)
        return -1;

    char *json = response_engine_alert_to_json(alert);
    if (!json)
        return -1;

    fputs(json, g_incident_log);
    fflush(g_incident_log);
    free(json);

    return 0;
}

int response_engine_push_to_dashboard(const struct ksentinel_alert *alert)
{
    /* TODO: Implement HTTP POST or Unix socket push to dashboard backend.
     * For now, this is a placeholder that will be connected in Phase 4. */
    (void)alert;
    if (!g_config.dashboard_endpoint)
        return -1;

    /* Future: Use libcurl or a Unix domain socket to push JSON */
    return 0;
}

int response_engine_execute(const struct ksentinel_event *event,
                            const struct ksentinel_detection_result *detection,
                            struct ksentinel_alert *alert_out)
{
    if (!g_initialized || !event || !detection)
        return -1;

    enum ksentinel_response_action action = detection->recommended_action;

    /* Determine if we should actually kill */
    int should_kill = 0;
    if (action == KSENTINEL_ACTION_SIGKILL) {
        if (g_config.auto_kill_enabled &&
            detection->severity >= g_config.min_kill_severity) {
            should_kill = 1;
        }

        /* Note: If the eBPF program already killed the process (honeyfile),
         * we still log it but don't need to kill again */
        if (event->flags & KSENTINEL_FLAG_KILLED) {
            should_kill = 0; /* Already killed in kernel space */
        }
    }

    /* Execute the kill if warranted */
    int kill_success = 0;
    if (should_kill) {
        int ret = response_engine_kill_process(event->pid, SIGKILL);
        kill_success = (ret == 0) ? 1 : 0;
    }

    /* Also consider if the kernel already killed it */
    if (event->flags & KSENTINEL_FLAG_KILLED) {
        kill_success = 1;
        action = KSENTINEL_ACTION_SIGKILL;
    }

    /* Populate alert output if provided */
    if (alert_out) {
        alert_out->action_taken = action;
        alert_out->kill_success = kill_success;
    }

    /* Log the alert */
    if (alert_out) {
        response_engine_log_alert(alert_out);
    }

    /* Push to dashboard */
    if (alert_out && detection->severity >= KSENTINEL_SEV_MEDIUM) {
        response_engine_push_to_dashboard(alert_out);
    }

    return 0;
}

void response_engine_destroy(void)
{
    if (g_incident_log) {
        fclose(g_incident_log);
        g_incident_log = NULL;
    }
    g_initialized = 0;
    fprintf(stderr, "[K-Sentinel] Response engine destroyed\n");
}

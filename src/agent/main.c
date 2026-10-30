/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * main.c — Agent entry point and BPF program loader
 *
 * This is the main user-space process that:
 *   1. Loads the compiled eBPF program into the kernel
 *   2. Attaches tracepoints to syscall hooks
 *   3. Populates the honeyfile hash map from the canary configuration
 *   4. Polls the ring buffer for events and dispatches them
 *   5. Handles graceful shutdown on SIGINT/SIGTERM
 *
 * Build: This file must be compiled on Linux with libbpf linked.
 *        The eBPF skeleton header (ksentinel.skel.h) is generated
 *        by bpftool during the build process.
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
#include <getopt.h>
#include <sys/resource.h>
#include <time.h>

/*
 * NOTE: The following includes require Linux + libbpf.
 * They will fail on macOS — this is expected. The code is written
 * on macOS but compiled inside the Lima VM.
 */
#ifdef __linux__
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ksentinel.skel.h"    /* Auto-generated BPF skeleton */
#endif

#include "../include/ksentinel_common.h"
#include "../include/ksentinel_events.h"
#include "event_handler.h"
#include "detection_engine.h"
#include "response_engine.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Version & Banner
 * ───────────────────────────────────────────────────────────────────────────── */

#define KSENTINEL_VERSION "0.1.0"
#define KSENTINEL_BANNER \
    "\n" \
    "  ██╗  ██╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     \n" \
    "  ██║ ██╔╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     \n" \
    "  █████╔╝     ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     \n" \
    "  ██╔═██╗     ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     \n" \
    "  ██║  ██╗    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ \n" \
    "  ╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ \n" \
    "\n" \
    "  Kernel-Space Security Sentinel v" KSENTINEL_VERSION "\n" \
    "  eBPF-Driven Runtime Security Agent & Ransomware Mitigation Engine\n" \
    "  ─────────────────────────────────────────────────────────────────\n\n"

/* ─────────────────────────────────────────────────────────────────────────────
 * Global State
 * ───────────────────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_running = 1;
static time_t g_start_time;

/* ─────────────────────────────────────────────────────────────────────────────
 * Agent Configuration (parsed from CLI args or config file)
 * ───────────────────────────────────────────────────────────────────────────── */

struct agent_config {
    /* Honeyfile paths to register in the BPF map */
    const char *honeyfile_list_path;

    /* Logging */
    const char *alert_log_path;
    const char *incident_log_path;
    int verbose;

    /* Response behavior */
    int auto_kill;
    int dry_run;

    /* Dashboard */
    const char *dashboard_endpoint;
};

static struct agent_config g_agent_config = {
    .honeyfile_list_path = "/etc/ksentinel/honeyfiles.txt",
    .alert_log_path      = "/var/log/ksentinel/alerts.json",
    .incident_log_path   = "/var/log/ksentinel/incidents.json",
    .verbose             = 1,
    .auto_kill           = 1,
    .dry_run             = 0,
    .dashboard_endpoint  = NULL,
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Signal Handler — graceful shutdown
 * ───────────────────────────────────────────────────────────────────────────── */

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * CLI Argument Parsing
 * ───────────────────────────────────────────────────────────────────────────── */

static void print_usage(const char *progname)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n\n"
        "Options:\n"
        "  -f, --honeyfiles <path>   Path to honeyfile list (one path per line)\n"
        "  -l, --alert-log <path>    Path to alert JSON log\n"
        "  -i, --incident-log <path> Path to incident JSON log\n"
        "  -d, --dashboard <url>     Dashboard push endpoint\n"
        "  -k, --auto-kill           Enable automatic process killing (default)\n"
        "  -K, --no-auto-kill        Disable automatic process killing\n"
        "  -n, --dry-run             Log actions without killing processes\n"
        "  -v, --verbose             Enable verbose console output (default)\n"
        "  -q, --quiet               Disable verbose console output\n"
        "  -h, --help                Show this help message\n"
        "  -V, --version             Show version\n\n",
        progname);
}

static int parse_args(int argc, char **argv)
{
    static struct option long_options[] = {
        {"honeyfiles",   required_argument, 0, 'f'},
        {"alert-log",    required_argument, 0, 'l'},
        {"incident-log", required_argument, 0, 'i'},
        {"dashboard",    required_argument, 0, 'd'},
        {"auto-kill",    no_argument,       0, 'k'},
        {"no-auto-kill", no_argument,       0, 'K'},
        {"dry-run",      no_argument,       0, 'n'},
        {"verbose",      no_argument,       0, 'v'},
        {"quiet",        no_argument,       0, 'q'},
        {"help",         no_argument,       0, 'h'},
        {"version",      no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "f:l:i:d:kKnvqhV",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 'f': g_agent_config.honeyfile_list_path = optarg; break;
        case 'l': g_agent_config.alert_log_path = optarg; break;
        case 'i': g_agent_config.incident_log_path = optarg; break;
        case 'd': g_agent_config.dashboard_endpoint = optarg; break;
        case 'k': g_agent_config.auto_kill = 1; break;
        case 'K': g_agent_config.auto_kill = 0; break;
        case 'n': g_agent_config.dry_run = 1; break;
        case 'v': g_agent_config.verbose = 1; break;
        case 'q': g_agent_config.verbose = 0; break;
        case 'V':
            fprintf(stderr, "K-Sentinel v%s\n", KSENTINEL_VERSION);
            exit(0);
        case 'h':
        default:
            print_usage(argv[0]);
            exit(opt == 'h' ? 0 : 1);
        }
    }

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Honeyfile Map Population
 *
 * Reads a text file containing one honeyfile path per line and inserts
 * each path into the BPF honeyfile hash map.
 * ───────────────────────────────────────────────────────────────────────────── */

#ifdef __linux__
static int populate_honeyfile_map(int map_fd, const char *list_path)
{
    FILE *f = fopen(list_path, "r");
    if (!f) {
        fprintf(stderr, "[K-Sentinel] ERROR: Cannot open honeyfile list: %s (%s)\n",
                list_path, strerror(errno));
        return -1;
    }

    char line[KSENTINEL_MAX_FILENAME_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        if (len == 0 || line[0] == '#')
            continue;  /* Skip empty lines and comments */

        struct honeyfile_key key = {};
        strncpy(key.path, line, sizeof(key.path) - 1);

        __u8 value = 1;
        int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
        if (ret != 0) {
            fprintf(stderr, "[K-Sentinel] WARNING: Failed to add honeyfile: %s\n",
                    line);
        } else {
            fprintf(stderr, "[K-Sentinel] Registered honeyfile: %s\n", line);
            count++;
        }
    }

    fclose(f);
    fprintf(stderr, "[K-Sentinel] Loaded %d honeyfile paths\n", count);
    return count;
}
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * Libbpf Debug Callback
 * ───────────────────────────────────────────────────────────────────────────── */

#ifdef __linux__
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !g_agent_config.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * Resource Limits — unlock memlock for BPF maps
 * ───────────────────────────────────────────────────────────────────────────── */

static int bump_rlimit_memlock(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
        fprintf(stderr, "[K-Sentinel] WARNING: Failed to set RLIMIT_MEMLOCK: %s\n",
                strerror(errno));
        fprintf(stderr, "  You may need to run as root or set "
                        "kernel.unprivileged_bpf_disabled=0\n");
        return -1;
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Periodic Maintenance — called every few seconds
 * ───────────────────────────────────────────────────────────────────────────── */

static void periodic_maintenance(void)
{
    static time_t last_cleanup = 0;
    time_t now = time(NULL);

    /* Cleanup stale PID entries every 30 seconds */
    if (now - last_cleanup >= 30) {
        detection_engine_cleanup_stale();
        last_cleanup = now;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Main Entry Point
 * ───────────────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    int err = 0;

    /* Print banner */
    fprintf(stderr, "%s", KSENTINEL_BANNER);

    /* Parse CLI arguments */
    if (parse_args(argc, argv) != 0)
        return 1;

    /* Register signal handlers for graceful shutdown */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    g_start_time = time(NULL);

    /* ── Initialize subsystems ───────────────────────────────────────── */

    fprintf(stderr, "[K-Sentinel] Initializing subsystems...\n");

    /* Detection engine */
    if (detection_engine_init(NULL) != 0) {
        fprintf(stderr, "[K-Sentinel] FATAL: Detection engine init failed\n");
        return 1;
    }

    /* Event handler */
    struct event_handler_config eh_config = {
        .alert_log_path = g_agent_config.alert_log_path,
        .verbose = g_agent_config.verbose,
        .min_log_severity = KSENTINEL_SEV_LOW,
        .min_console_severity = KSENTINEL_SEV_INFO,
    };
    if (event_handler_init(&eh_config) != 0) {
        fprintf(stderr, "[K-Sentinel] FATAL: Event handler init failed\n");
        return 1;
    }

    /* Response engine */
    struct response_config resp_config = {
        .auto_kill_enabled = g_agent_config.auto_kill,
        .min_kill_severity = KSENTINEL_SEV_HIGH,
        .incident_log_path = g_agent_config.incident_log_path,
        .dashboard_endpoint = g_agent_config.dashboard_endpoint,
        .dry_run = g_agent_config.dry_run,
    };
    if (response_engine_init(&resp_config) != 0) {
        fprintf(stderr, "[K-Sentinel] FATAL: Response engine init failed\n");
        return 1;
    }

#ifdef __linux__
    /* ── Linux-specific BPF loading ──────────────────────────────────── */

    /* Set up libbpf debug output */
    libbpf_set_print(libbpf_print_fn);

    /* Bump memlock limit for BPF maps */
    bump_rlimit_memlock();

    /* Open the BPF skeleton (auto-generated from ksentinel.bpf.c) */
    struct ksentinel_bpf *skel = ksentinel_bpf__open();
    if (!skel) {
        fprintf(stderr, "[K-Sentinel] FATAL: Failed to open BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    /* Load and verify the BPF programs */
    err = ksentinel_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[K-Sentinel] FATAL: Failed to load BPF programs: %d\n",
                err);
        goto cleanup_skel;
    }

    fprintf(stderr, "[K-Sentinel] eBPF programs loaded successfully\n");

    /* Attach tracepoints */
    err = ksentinel_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[K-Sentinel] FATAL: Failed to attach BPF programs: %d\n",
                err);
        goto cleanup_skel;
    }

    fprintf(stderr, "[K-Sentinel] Tracepoints attached:\n");
    fprintf(stderr, "  ✓ tracepoint/syscalls/sys_enter_openat\n");
    fprintf(stderr, "  ✓ tracepoint/syscalls/sys_enter_write\n");
    fprintf(stderr, "  ✓ tracepoint/syscalls/sys_enter_renameat2\n");
    fprintf(stderr, "  ✓ tracepoint/syscalls/sys_enter_unlinkat\n");

    /* Populate honeyfile map */
    int map_fd = bpf_map__fd(skel->maps.honeyfile_map);
    populate_honeyfile_map(map_fd, g_agent_config.honeyfile_list_path);

    /* Set auto-kill config in BPF map */
    int config_map_fd = bpf_map__fd(skel->maps.config_map);
    __u32 config_key = 1;
    __u64 config_val = g_agent_config.auto_kill ? 1 : 0;
    bpf_map_update_elem(config_map_fd, &config_key, &config_val, BPF_ANY);

    /* Exempt the agent itself from auto-kill */
    __u32 self_pid = (__u32)getpid();
    __u8 allow_val = 1;
    bpf_map_update_elem(bpf_map__fd(skel->maps.allowlist_map),
                        &self_pid, &allow_val, BPF_ANY);

    /* Create ring buffer */
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        event_handler_ringbuf_callback,
        NULL,
        NULL
    );
    if (!rb) {
        fprintf(stderr, "[K-Sentinel] FATAL: Failed to create ring buffer\n");
        err = 1;
        goto cleanup_skel;
    }

    /* ── Main Event Loop ─────────────────────────────────────────────── */

    fprintf(stderr, "\n[K-Sentinel] ══════════════════════════════════════════\n");
    fprintf(stderr, "[K-Sentinel]  Agent is ACTIVE — monitoring filesystem\n");
    fprintf(stderr, "[K-Sentinel] ══════════════════════════════════════════\n\n");

    while (g_running) {
        /* Poll the ring buffer with 100ms timeout */
        err = ring_buffer__poll(rb, 100 /* timeout_ms */);
        if (err == -EINTR) {
            /* Interrupted by signal — check g_running */
            err = 0;
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "[K-Sentinel] Ring buffer poll error: %d\n", err);
            break;
        }

        /* Periodic housekeeping */
        periodic_maintenance();
    }

    /* ── Cleanup ─────────────────────────────────────────────────────── */

    ring_buffer__free(rb);

cleanup_skel:
    ksentinel_bpf__destroy(skel);

cleanup:

#else
    /* ── macOS stub — cannot run eBPF on macOS ───────────────────────── */

    fprintf(stderr, "[K-Sentinel] WARNING: Running on macOS — eBPF is not available.\n");
    fprintf(stderr, "[K-Sentinel] This binary was compiled for development/testing only.\n");
    fprintf(stderr, "[K-Sentinel] To run the full agent, compile and run inside the Lima VM.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "[K-Sentinel] Subsystems initialized successfully.\n");
    fprintf(stderr, "[K-Sentinel] Detection engine, event handler, and response engine\n");
    fprintf(stderr, "[K-Sentinel] are ready. Use the ransomware simulator to test logic.\n");

    /* Keep running to allow testing of non-BPF subsystems */
    while (g_running) {
        sleep(1);
        periodic_maintenance();
    }

#endif /* __linux__ */

    /* ── Shutdown ─────────────────────────────────────────────────────── */

    time_t uptime = time(NULL) - g_start_time;
    fprintf(stderr, "\n[K-Sentinel] Shutting down (uptime: %ld seconds)...\n",
            (long)uptime);

    event_handler_destroy();
    detection_engine_destroy();
    response_engine_destroy();

    fprintf(stderr, "[K-Sentinel] Goodbye.\n");
    return err;
}

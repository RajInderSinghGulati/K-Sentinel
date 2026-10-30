/*
 * K-Sentinel — Kernel-Space Security Sentinel
 * event_handler.h — Ring buffer event processing interface
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

#ifndef __KSENTINEL_EVENT_HANDLER_H
#define __KSENTINEL_EVENT_HANDLER_H

#include "../include/ksentinel_common.h"
#include "../include/ksentinel_events.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Event Handler Configuration
 * ───────────────────────────────────────────────────────────────────────────── */

struct event_handler_config {
    /* Path to the JSON alert log file */
    const char *alert_log_path;

    /* Enable/disable console output for events */
    int verbose;

    /* Minimum severity to log */
    enum ksentinel_severity min_log_severity;

    /* Minimum severity to print to console */
    enum ksentinel_severity min_console_severity;
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Callback Types
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * Alert callback — invoked whenever a detection result warrants an alert.
 * Used to push events to the dashboard or external SIEM.
 */
typedef void (*alert_callback_fn)(const struct ksentinel_alert *alert, void *ctx);

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * Initialize the event handler subsystem.
 * Opens the alert log file and prepares internal state.
 * Returns 0 on success, -1 on failure.
 */
int event_handler_init(const struct event_handler_config *config);

/*
 * Ring buffer callback function.
 *
 * This function is registered with libbpf's ring_buffer__new() and is
 * called for every event received from the kernel. It:
 *   1. Deserializes the event
 *   2. Passes it to the detection engine
 *   3. Passes the detection result to the response engine
 *   4. Logs the alert if warranted
 *
 * Parameters:
 *   ctx  — user-provided context pointer
 *   data — pointer to the raw event data (struct ksentinel_event)
 *   sz   — size of the data
 *
 * Returns 0 to continue processing, negative value to stop.
 */
int event_handler_ringbuf_callback(void *ctx, void *data, size_t sz);

/*
 * Register an external alert callback.
 * The callback will be invoked for every alert at or above the
 * specified minimum severity.
 */
void event_handler_register_alert_callback(alert_callback_fn callback,
                                           void *ctx,
                                           enum ksentinel_severity min_severity);

/*
 * Get current agent statistics.
 */
const struct ksentinel_stats *event_handler_get_stats(void);

/*
 * Shut down the event handler and flush pending logs.
 */
void event_handler_destroy(void);

#endif /* __KSENTINEL_EVENT_HANDLER_H */

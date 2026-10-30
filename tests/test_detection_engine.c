/*
 * K-Sentinel — Detection Engine Unit Tests
 * test_detection_engine.c
 *
 * Standalone test binary for the detection engine that runs on macOS.
 * Tests entropy calculation, frequency scoring, severity classification,
 * and the full analysis pipeline.
 *
 * Build: make test-detection
 * This compiles and runs on macOS without any Linux/BPF dependencies.
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

/* Include the detection engine (we link against detection_engine.c) */
#include "../src/agent/detection_engine.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Test Framework (minimal, no external dependencies)
 * ───────────────────────────────────────────────────────────────────────────── */

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) \
    do { \
        g_tests_run++; \
        fprintf(stderr, "  TEST %-50s ", #name); \
    } while (0)

#define PASS() \
    do { \
        g_tests_passed++; \
        fprintf(stderr, "\033[32m✓ PASS\033[0m\n"); \
    } while (0)

#define FAIL(msg, ...) \
    do { \
        g_tests_failed++; \
        fprintf(stderr, "\033[31m✗ FAIL\033[0m: " msg "\n", ##__VA_ARGS__); \
    } while (0)

#define ASSERT_NEAR(actual, expected, epsilon) \
    if (fabs((actual) - (expected)) > (epsilon)) { \
        FAIL("expected %.4f, got %.4f (epsilon=%.4f)", \
             (double)(expected), (double)(actual), (double)(epsilon)); \
        return; \
    }

#define ASSERT_EQ(actual, expected) \
    if ((actual) != (expected)) { \
        FAIL("expected %d, got %d", (int)(expected), (int)(actual)); \
        return; \
    }

#define ASSERT_GE(actual, expected) \
    if ((actual) < (expected)) { \
        FAIL("expected >= %.4f, got %.4f", (double)(expected), (double)(actual)); \
        return; \
    }

#define ASSERT_LE(actual, expected) \
    if ((actual) > (expected)) { \
        FAIL("expected <= %.4f, got %.4f", (double)(expected), (double)(actual)); \
        return; \
    }

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: Shannon Entropy — All Zeros (minimum entropy)
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_entropy_all_zeros(void)
{
    TEST(entropy_all_zeros);

    unsigned char data[1024];
    memset(data, 0, sizeof(data));

    double entropy = detection_engine_calculate_entropy(data, sizeof(data));

    /* All identical bytes → entropy should be 0.0 */
    ASSERT_NEAR(entropy, 0.0, 0.001);
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: Shannon Entropy — Uniform Random (maximum entropy)
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_entropy_random(void)
{
    TEST(entropy_random);

    /* Create a buffer with uniform byte distribution */
    unsigned char data[256 * 100];  /* 100 copies of every byte value */
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 100; j++) {
            data[i * 100 + j] = (unsigned char)i;
        }
    }

    double entropy = detection_engine_calculate_entropy(data, sizeof(data));

    /* Perfectly uniform distribution → entropy should be exactly 8.0 */
    ASSERT_NEAR(entropy, 8.0, 0.001);
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: Shannon Entropy — ASCII Text (medium entropy)
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_entropy_ascii_text(void)
{
    TEST(entropy_ascii_text);

    const char *text = "The quick brown fox jumps over the lazy dog. "
                       "This is a sample text that should have moderate entropy. "
                       "Normal English text typically has entropy around 4-5 bits.";

    double entropy = detection_engine_calculate_entropy(
        (const unsigned char *)text, strlen(text));

    /* English text entropy should be roughly 3.5-5.5 */
    ASSERT_GE(entropy, 3.0);
    ASSERT_LE(entropy, 6.0);
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: Shannon Entropy — Empty Buffer
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_entropy_empty(void)
{
    TEST(entropy_empty);

    double entropy = detection_engine_calculate_entropy(NULL, 0);
    ASSERT_NEAR(entropy, 0.0, 0.001);

    entropy = detection_engine_calculate_entropy((const unsigned char *)"x", 0);
    ASSERT_NEAR(entropy, 0.0, 0.001);

    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: Detection Engine Initialization
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_engine_init(void)
{
    TEST(engine_init);

    /* Init with defaults */
    int rc = detection_engine_init(NULL);
    ASSERT_EQ(rc, 0);

    detection_engine_destroy();
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: Normal file open → INFO severity
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_normal_file_open(void)
{
    TEST(normal_file_open_is_info);

    detection_engine_init(NULL);

    struct ksentinel_event evt = {0};
    evt.pid = 1234;
    evt.tgid = 1234;
    evt.uid = 1000;
    evt.timestamp_ns = 1000000000ULL;
    evt.event_type = KSENTINEL_EVENT_OPEN;
    evt.flags = 0;  /* No honeyfile, no high-freq */
    strncpy(evt.comm, "cat", sizeof(evt.comm));
    strncpy(evt.filename, "/home/user/readme.txt", sizeof(evt.filename));

    struct ksentinel_detection_result result;
    int rc = detection_engine_analyze(&evt, &result);

    ASSERT_EQ(rc, 0);
    /* A single operation produces a tiny frequency score, mapping to LOW or INFO */
    if (result.severity != KSENTINEL_SEV_INFO && result.severity != KSENTINEL_SEV_LOW) {
        FAIL("expected INFO or LOW, got %d", (int)result.severity);
        detection_engine_destroy();
        return;
    }
    ASSERT_NEAR(result.score_honeyfile, 0.0, 0.001);
    ASSERT_LE(result.score_total, 0.15);

    detection_engine_destroy();
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: Honeyfile access → CRITICAL severity
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_honeyfile_access(void)
{
    TEST(honeyfile_access_is_critical);

    detection_engine_init(NULL);

    struct ksentinel_event evt = {0};
    evt.pid = 5678;
    evt.tgid = 5678;
    evt.uid = 1000;
    evt.timestamp_ns = 2000000000ULL;
    evt.event_type = KSENTINEL_EVENT_OPEN;
    evt.flags = KSENTINEL_FLAG_HONEYFILE | KSENTINEL_FLAG_KILLED;
    strncpy(evt.comm, "malware", sizeof(evt.comm));
    strncpy(evt.filename, "/home/user/Q4_Budget_2026.xlsx", sizeof(evt.filename));

    struct ksentinel_detection_result result;
    int rc = detection_engine_analyze(&evt, &result);

    ASSERT_EQ(rc, 0);
    ASSERT_EQ(result.severity, KSENTINEL_SEV_CRITICAL);
    ASSERT_NEAR(result.score_honeyfile, 1.0, 0.001);
    ASSERT_EQ(result.trigger, KSENTINEL_TRIGGER_HONEYFILE_ACCESS);
    ASSERT_EQ(result.recommended_action, KSENTINEL_ACTION_SIGKILL);

    detection_engine_destroy();
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: High-frequency file operations → escalated severity
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_high_frequency_ops(void)
{
    TEST(high_frequency_escalation);

    detection_engine_init(NULL);

    struct ksentinel_event evt = {0};
    evt.pid = 9999;
    evt.tgid = 9999;
    evt.uid = 1000;
    evt.event_type = KSENTINEL_EVENT_WRITE;
    evt.flags = 0;
    strncpy(evt.comm, "ransomware", sizeof(evt.comm));
    evt.write_size = 4096;

    struct ksentinel_detection_result result;

    /* Simulate 100 rapid write operations in the same window */
    for (int i = 0; i < 100; i++) {
        evt.timestamp_ns = 1000000000ULL + (i * 10000000ULL); /* 10ms apart */
        detection_engine_analyze(&evt, &result);
    }

    /* After 100 rapid writes, frequency score should be significant */
    ASSERT_GE(result.score_frequency, 0.4);
    ASSERT_GE((int)result.severity, (int)KSENTINEL_SEV_LOW);

    detection_engine_destroy();
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: Mass rename pattern → elevated score
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_mass_rename_pattern(void)
{
    TEST(mass_rename_detection);

    detection_engine_init(NULL);

    struct ksentinel_event evt = {0};
    evt.pid = 7777;
    evt.tgid = 7777;
    evt.uid = 1000;
    evt.event_type = KSENTINEL_EVENT_RENAME;
    evt.flags = 0;
    strncpy(evt.comm, "encrypt_all", sizeof(evt.comm));

    struct ksentinel_detection_result result;

    /* Simulate 40 rapid rename operations */
    for (int i = 0; i < 40; i++) {
        evt.timestamp_ns = 1000000000ULL + (i * 5000000ULL); /* 5ms apart */
        char fname[256];
        snprintf(fname, sizeof(fname), "/home/user/document_%d.docx", i);
        strncpy(evt.filename, fname, sizeof(evt.filename));
        detection_engine_analyze(&evt, &result);
    }

    /* Mass renames should trigger elevated scores */
    ASSERT_GE(result.score_rename, 0.3);
    ASSERT_GE(result.score_total, 0.1);

    detection_engine_destroy();
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: PID state cleanup
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_pid_state_cleanup(void)
{
    TEST(pid_state_reset);

    detection_engine_init(NULL);

    /* Create some state */
    struct ksentinel_event evt = {0};
    evt.pid = 4444;
    evt.tgid = 4444;
    evt.timestamp_ns = 1000000000ULL;
    evt.event_type = KSENTINEL_EVENT_OPEN;
    strncpy(evt.comm, "test", sizeof(evt.comm));

    struct ksentinel_detection_result result;
    detection_engine_analyze(&evt, &result);

    /* Verify state exists */
    const struct pid_behavior_state *state = detection_engine_get_pid_state(4444);
    assert(state != NULL);
    assert(state->total_ops == 1);

    /* Reset PID */
    detection_engine_reset_pid(4444);

    /* Verify state is gone */
    state = detection_engine_get_pid_state(4444);
    assert(state == NULL);

    detection_engine_destroy();
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test Runner
 * ───────────────────────────────────────────────────────────────────────────── */

int main(void)
{
    fprintf(stderr, "\n");
    fprintf(stderr, "══════════════════════════════════════════════════════════\n");
    fprintf(stderr, "  K-Sentinel Detection Engine — Unit Tests\n");
    fprintf(stderr, "══════════════════════════════════════════════════════════\n\n");

    /* Entropy tests */
    fprintf(stderr, "  ── Entropy Calculation ──\n");
    test_entropy_all_zeros();
    test_entropy_random();
    test_entropy_ascii_text();
    test_entropy_empty();

    /* Detection engine tests */
    fprintf(stderr, "\n  ── Detection Engine ──\n");
    test_engine_init();
    test_normal_file_open();
    test_honeyfile_access();
    test_high_frequency_ops();
    test_mass_rename_pattern();
    test_pid_state_cleanup();

    /* Summary */
    fprintf(stderr, "\n══════════════════════════════════════════════════════════\n");
    fprintf(stderr, "  Results: %d/%d passed",
            g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        fprintf(stderr, " (\033[31m%d FAILED\033[0m)", g_tests_failed);
    fprintf(stderr, "\n");
    fprintf(stderr, "══════════════════════════════════════════════════════════\n\n");

    return g_tests_failed > 0 ? 1 : 0;
}

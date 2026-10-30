#!/usr/bin/env python3
"""
K-Sentinel — Ransomware Simulator (SAFE)
ransomware_simulator.py

A safe, educational ransomware behavior simulator for testing K-Sentinel's
detection capabilities. This script mimics common ransomware filesystem
patterns WITHOUT actually encrypting any data.

Behaviors simulated:
  1. Rapid directory traversal (walking /tmp/ksentinel_test/)
  2. High-frequency file open/read/write cycles
  3. File renaming with ransomware-style extensions (.encrypted, .locked)
  4. File deletion after "encryption"
  5. Honeyfile access attempt

SAFETY: All operations are performed in an isolated test directory
(/tmp/ksentinel_test/) that is created and cleaned up by this script.
No real user data is ever touched.

Usage:
  python3 ransomware_simulator.py [--mode all|honeyfile|frequency|rename]
  python3 ransomware_simulator.py --cleanup

Copyright (c) 2026 K-Sentinel Project
SPDX-License-Identifier: MIT
"""

import argparse
import os
import random
import shutil
import string
import sys
import time


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

TEST_DIR = "/tmp/ksentinel_test"
NUM_TEST_FILES = 50
HONEYFILE_NAME = "Q4_Budget_Report_2026.xlsx"  # Matches canary template
RAPID_OP_DELAY = 0.01  # 10ms between operations (very fast)
RANSOMWARE_EXTENSIONS = [".encrypted", ".locked", ".cry", ".WNCRY", ".locky"]


# ─────────────────────────────────────────────────────────────────────────────
# Setup: Create isolated test environment
# ─────────────────────────────────────────────────────────────────────────────

def setup_test_environment():
    """Create test directory with sample files."""
    print(f"\n{'═' * 60}")
    print(f"  K-Sentinel Ransomware Simulator — TEST ENVIRONMENT")
    print(f"{'═' * 60}")
    print(f"\n  ⚠  This is a SAFE simulator. No real data is harmed.")
    print(f"  📁 Test directory: {TEST_DIR}")
    print()

    # Clean any previous test data
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)

    # Create directory structure
    subdirs = [
        os.path.join(TEST_DIR, "documents"),
        os.path.join(TEST_DIR, "documents", "financial"),
        os.path.join(TEST_DIR, "photos"),
        os.path.join(TEST_DIR, "projects"),
        os.path.join(TEST_DIR, "backups"),
    ]

    for d in subdirs:
        os.makedirs(d, exist_ok=True)

    # Create sample files
    extensions = [".txt", ".pdf", ".docx", ".xlsx", ".jpg", ".py", ".sql"]
    created = 0

    for subdir in subdirs:
        for i in range(NUM_TEST_FILES // len(subdirs)):
            ext = random.choice(extensions)
            name = "".join(random.choices(string.ascii_lowercase, k=8))
            filepath = os.path.join(subdir, f"{name}{ext}")

            content = os.urandom(random.randint(1024, 65536))
            with open(filepath, "wb") as f:
                f.write(content)
            created += 1

    # Create a honeyfile in the test directory
    honeyfile_path = os.path.join(TEST_DIR, "documents", "financial", HONEYFILE_NAME)
    with open(honeyfile_path, "wb") as f:
        f.write(os.urandom(8192))

    print(f"  ✓ Created {created} test files across {len(subdirs)} directories")
    print(f"  ✓ Deployed honeyfile: {honeyfile_path}")
    print()

    return honeyfile_path


# ─────────────────────────────────────────────────────────────────────────────
# Simulation: Honeyfile Access
# ─────────────────────────────────────────────────────────────────────────────

def simulate_honeyfile_access(honeyfile_path):
    """
    Simulate a ransomware process accessing a honeyfile.

    This is the most critical detection vector. Any process that opens
    a honeyfile should be immediately terminated by K-Sentinel.
    """
    print(f"  {'─' * 56}")
    print(f"  SIMULATION: Honeyfile Access")
    print(f"  {'─' * 56}")
    print(f"  Attempting to open honeyfile: {honeyfile_path}")
    print(f"  >>> If K-Sentinel is active, this process will be KILLED <<<")
    print()

    try:
        with open(honeyfile_path, "rb") as f:
            data = f.read(1024)
            print(f"  Read {len(data)} bytes from honeyfile")
            print(f"  ⚠  K-Sentinel should have killed us by now!")
    except Exception as e:
        print(f"  ✓ Access blocked or process interrupted: {e}")

    time.sleep(0.5)


# ─────────────────────────────────────────────────────────────────────────────
# Simulation: High-Frequency File Operations
# ─────────────────────────────────────────────────────────────────────────────

def simulate_high_frequency_ops():
    """
    Simulate rapid file open/read/write cycles.

    Ransomware typically processes files extremely quickly — opening,
    reading, encrypting, and writing them in rapid succession. This
    pattern triggers K-Sentinel's frequency-based detection.
    """
    print(f"  {'─' * 56}")
    print(f"  SIMULATION: High-Frequency File Operations")
    print(f"  {'─' * 56}")

    ops_count = 0
    start_time = time.time()

    for root, _, files in os.walk(TEST_DIR):
        for fname in files:
            if fname == HONEYFILE_NAME:
                continue  # Skip honeyfile for this test

            filepath = os.path.join(root, fname)
            try:
                # Open → Read → Write (simulated "encryption")
                with open(filepath, "rb") as f:
                    data = f.read()

                # "Encrypt" by XOR with a random byte (simulated)
                key = random.randint(1, 255)
                encrypted = bytes(b ^ key for b in data)

                with open(filepath, "wb") as f:
                    f.write(encrypted)

                ops_count += 1
                elapsed = time.time() - start_time

                print(f"  [{ops_count:3d}] {elapsed:6.2f}s  "
                      f"Processed: {os.path.basename(filepath)}")

                time.sleep(RAPID_OP_DELAY)

            except Exception as e:
                print(f"  ✗ Error processing {filepath}: {e}")

    elapsed = time.time() - start_time
    rate = ops_count / elapsed if elapsed > 0 else 0
    print(f"\n  Completed {ops_count} operations in {elapsed:.2f}s "
          f"({rate:.1f} ops/sec)")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Simulation: Mass File Renaming
# ─────────────────────────────────────────────────────────────────────────────

def simulate_mass_rename():
    """
    Simulate ransomware renaming files with encryption extensions.

    Many ransomware families rename files after encrypting them,
    appending extensions like .encrypted, .locked, .WNCRY, etc.
    """
    print(f"  {'─' * 56}")
    print(f"  SIMULATION: Mass File Renaming")
    print(f"  {'─' * 56}")

    renamed = 0

    for root, _, files in os.walk(TEST_DIR):
        for fname in files:
            if fname == HONEYFILE_NAME:
                continue

            filepath = os.path.join(root, fname)
            ext = random.choice(RANSOMWARE_EXTENSIONS)
            new_path = filepath + ext

            try:
                os.rename(filepath, new_path)
                renamed += 1
                print(f"  [{renamed:3d}] Renamed: {fname} → {fname}{ext}")
                time.sleep(RAPID_OP_DELAY)
            except Exception as e:
                print(f"  ✗ Error renaming {fname}: {e}")

    print(f"\n  Renamed {renamed} files with ransomware extensions")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Simulation: Mass File Deletion
# ─────────────────────────────────────────────────────────────────────────────

def simulate_mass_delete():
    """
    Simulate ransomware deleting original files after encryption.
    """
    print(f"  {'─' * 56}")
    print(f"  SIMULATION: Mass File Deletion")
    print(f"  {'─' * 56}")

    deleted = 0

    for root, _, files in os.walk(TEST_DIR):
        for fname in files:
            if fname == HONEYFILE_NAME:
                continue

            filepath = os.path.join(root, fname)
            try:
                os.unlink(filepath)
                deleted += 1
                print(f"  [{deleted:3d}] Deleted: {filepath}")
                time.sleep(RAPID_OP_DELAY)
            except Exception as e:
                print(f"  ✗ Error deleting {fname}: {e}")

    print(f"\n  Deleted {deleted} files")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────────

def cleanup():
    """Remove the test directory."""
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
        print(f"  ✓ Cleaned up test directory: {TEST_DIR}")
    else:
        print(f"  Nothing to clean up.")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="K-Sentinel Ransomware Behavior Simulator (SAFE)",
    )
    parser.add_argument(
        "--mode",
        choices=["all", "honeyfile", "frequency", "rename", "delete"],
        default="all",
        help="Simulation mode (default: all)",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Clean up test directory and exit",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.01,
        help="Delay between operations in seconds (default: 0.01)",
    )

    args = parser.parse_args()

    global RAPID_OP_DELAY
    RAPID_OP_DELAY = args.delay

    if args.cleanup:
        cleanup()
        return

    # Setup
    honeyfile_path = setup_test_environment()

    print(f"  Starting simulation in 3 seconds...")
    print(f"  (If K-Sentinel is active, watch for SIGKILL!)")
    time.sleep(3)

    # Run simulations
    if args.mode in ("all", "frequency"):
        simulate_high_frequency_ops()

    if args.mode in ("all", "rename"):
        # Re-setup since frequency mode may have modified files
        if args.mode == "all":
            setup_test_environment()
        simulate_mass_rename()

    if args.mode in ("all", "delete"):
        simulate_mass_delete()

    if args.mode in ("all", "honeyfile"):
        simulate_honeyfile_access(honeyfile_path)

    # Cleanup
    print(f"\n{'═' * 60}")
    print(f"  Simulation complete!")
    print(f"  Run 'python3 {sys.argv[0]} --cleanup' to remove test files")
    print(f"{'═' * 60}\n")


if __name__ == "__main__":
    main()

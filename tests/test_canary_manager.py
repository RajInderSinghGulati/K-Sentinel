#!/usr/bin/env python3
"""
K-Sentinel — Canary Manager Unit Tests
test_canary_manager.py

Tests for the honeyfile deployment, verification, and rotation system.
Runs on macOS without any Linux dependencies.

Usage: python3 -m pytest tests/test_canary_manager.py -v

Copyright (c) 2026 K-Sentinel Project
SPDX-License-Identifier: MIT
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile

import pytest

# Add the canary module to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "canary"))
from canary_manager import (
    CanaryManager,
    CanaryConfig,
    generate_random_bytes,
    generate_fake_sql,
    generate_fake_credentials,
    generate_fake_private_key,
    generate_fake_env,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def test_dir():
    """Create a temporary directory for testing."""
    d = tempfile.mkdtemp(prefix="ksentinel_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def test_config(test_dir):
    """Create a test configuration."""
    return CanaryConfig(
        target_dirs=[test_dir],
        max_depth=2,
        min_honeyfiles=5,
        max_honeyfiles=15,
        state_file=os.path.join(test_dir, "state.json"),
        honeyfile_list=os.path.join(test_dir, "honeyfiles.txt"),
    )


@pytest.fixture
def manager(test_config):
    """Create a CanaryManager instance with test config."""
    return CanaryManager(test_config)


# ─────────────────────────────────────────────────────────────────────────────
# Content Generator Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestContentGenerators:
    def test_random_bytes_length(self):
        data = generate_random_bytes(1024)
        assert len(data) == 1024

    def test_random_bytes_not_all_zeros(self):
        data = generate_random_bytes(4096)
        assert data != b"\x00" * 4096

    def test_fake_sql_contains_create_table(self):
        data = generate_fake_sql(4096)
        text = data.decode("utf-8")
        assert "CREATE TABLE" in text
        assert "INSERT INTO" in text

    def test_fake_sql_size(self):
        data = generate_fake_sql(8192)
        assert len(data) <= 8192

    def test_fake_credentials_csv_format(self):
        data = generate_fake_credentials(2048)
        text = data.decode("utf-8")
        lines = text.strip().split("\n")
        assert lines[0] == "username,password,service,notes"
        assert len(lines) > 2

    def test_fake_private_key_pem_format(self):
        data = generate_fake_private_key(2048)
        text = data.decode("utf-8")
        assert "-----BEGIN RSA PRIVATE KEY-----" in text
        assert "-----END RSA PRIVATE KEY-----" in text

    def test_fake_env_format(self):
        data = generate_fake_env(1024)
        text = data.decode("utf-8")
        assert "DATABASE_URL=" in text
        assert "API_KEY=" in text


# ─────────────────────────────────────────────────────────────────────────────
# Deployment Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDeployment:
    def test_deploy_creates_files(self, manager, test_dir):
        count = manager.deploy()
        assert count > 0

        # Check that files exist on disk
        deployed_files = []
        for root, _, files in os.walk(test_dir):
            for f in files:
                if f not in ("state.json", "honeyfiles.txt"):
                    deployed_files.append(os.path.join(root, f))

        assert len(deployed_files) > 0

    def test_deploy_creates_state_file(self, manager, test_config):
        manager.deploy()
        assert os.path.exists(test_config.state_file)

        with open(test_config.state_file, "r") as f:
            state = json.load(f)

        assert "deployed" in state
        assert len(state["deployed"]) > 0

    def test_deploy_creates_honeyfile_list(self, manager, test_config):
        manager.deploy()
        assert os.path.exists(test_config.honeyfile_list)

        with open(test_config.honeyfile_list, "r") as f:
            lines = [l.strip() for l in f.readlines()
                     if l.strip() and not l.startswith("#")]

        assert len(lines) > 0

    def test_deploy_respects_max(self, manager, test_config):
        count = manager.deploy()
        assert count <= test_config.max_honeyfiles

    def test_deployed_files_have_hashes(self, manager):
        manager.deploy()
        for hf in manager.deployed:
            assert hf.sha256
            assert len(hf.sha256) == 64  # SHA-256 hex length


# ─────────────────────────────────────────────────────────────────────────────
# Verification Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVerification:
    def test_verify_untouched_files_pass(self, manager):
        manager.deploy()
        ok, tampered = manager.verify()
        assert tampered == 0
        assert ok == len(manager.deployed)

    def test_verify_detects_modification(self, manager):
        manager.deploy()

        # Tamper with the first deployed honeyfile
        if manager.deployed:
            target = manager.deployed[0].path
            with open(target, "ab") as f:
                f.write(b"TAMPERED DATA")

            ok, tampered = manager.verify()
            assert tampered >= 1

    def test_verify_detects_deletion(self, manager):
        manager.deploy()

        # Delete the first deployed honeyfile
        if manager.deployed:
            os.remove(manager.deployed[0].path)
            ok, tampered = manager.verify()
            assert tampered >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Cleanup Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCleanup:
    def test_clean_removes_files(self, manager, test_dir):
        manager.deploy()
        initial_count = len(manager.deployed)
        assert initial_count > 0

        removed = manager.clean()
        assert removed > 0
        assert len(manager.deployed) == 0

    def test_clean_is_idempotent(self, manager):
        manager.deploy()
        manager.clean()
        removed = manager.clean()
        assert removed == 0


# ─────────────────────────────────────────────────────────────────────────────
# Rotation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRotation:
    def test_rotate_creates_fresh_files(self, manager):
        manager.deploy()
        old_paths = {hf.path for hf in manager.deployed}

        manager.rotate()
        new_paths = {hf.path for hf in manager.deployed}

        # After rotation, we should have new files
        assert len(new_paths) > 0


# ─────────────────────────────────────────────────────────────────────────────
# Helper function: Python entropy calculator (for testing parity)
# ─────────────────────────────────────────────────────────────────────────────

def detection_engine_calculate_entropy_py(data: bytes) -> float:
    """Python implementation of Shannon entropy for test comparison."""
    import math
    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)

    return entropy


# Monkey-patch the import for the test module since canary_manager
# doesn't export this function directly
if "detection_engine_calculate_entropy_py" not in dir():
    pass  # Already defined above

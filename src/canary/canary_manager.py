#!/usr/bin/env python3
"""
K-Sentinel — Kernel-Space Security Sentinel
canary_manager.py — Honeyfile Deployment and Integrity Management

This module manages the lifecycle of canary files (honeyfiles) used by
the K-Sentinel agent for ransomware detection. It handles:

  1. Deployment   — Create honeyfiles across monitored directories
  2. Verification — SHA-256 integrity checks to detect tampering
  3. Rotation     — Periodic re-deployment with fresh content
  4. Registration — Output paths for the eBPF honeyfile hash map

Honeyfiles are decoy files strategically placed in directories that
legitimate applications would never access. Any process that opens,
modifies, renames, or deletes a honeyfile is immediately flagged as
suspicious by the eBPF kernel-space monitor.

Usage:
  python3 canary_manager.py deploy   [-c config.yaml]
  python3 canary_manager.py verify   [-c config.yaml]
  python3 canary_manager.py rotate   [-c config.yaml]
  python3 canary_manager.py list     [-c config.yaml]
  python3 canary_manager.py clean    [-c config.yaml]

Copyright (c) 2026 K-Sentinel Project
SPDX-License-Identifier: MIT
"""

import argparse
import hashlib
import json
import logging
import os
import random
import string
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

# Optional: YAML support (falls back to JSON config if unavailable)
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ─────────────────────────────────────────────────────────────────────────────
# Logging Configuration
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[K-Sentinel/Canary] %(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("canary_manager")

# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HoneyfileTemplate:
    """Defines a type of honeyfile to deploy."""
    name: str                  # Template name (e.g., "financial_doc")
    filename: str              # Filename to use (e.g., "Q4_Budget_2026.xlsx")
    content_type: str          # Content generation strategy
    size_range: tuple = (1024, 65536)  # Min/max size in bytes
    hidden: bool = False       # Prefix with '.' to hide


@dataclass
class DeployedHoneyfile:
    """Tracks a deployed honeyfile instance."""
    path: str                  # Absolute path
    template: str              # Template name used
    sha256: str                # SHA-256 hash at deployment
    deployed_at: str           # ISO 8601 timestamp
    size: int                  # File size in bytes
    verified_at: Optional[str] = None
    tampered: bool = False


@dataclass
class CanaryConfig:
    """Configuration for the canary file manager."""
    # Directories to deploy honeyfiles into
    target_dirs: list = field(default_factory=lambda: [
        "/home",
        "/tmp",
        "/var/tmp",
        "/opt",
    ])

    # How deep to recurse into target directories
    max_depth: int = 2

    # Minimum number of honeyfiles to deploy
    min_honeyfiles: int = 10

    # Maximum number of honeyfiles to deploy
    max_honeyfiles: int = 50

    # State file to track deployed honeyfiles
    state_file: str = "/etc/ksentinel/canary_state.json"

    # Output file for the eBPF honeyfile path list
    honeyfile_list: str = "/etc/ksentinel/honeyfiles.txt"

    # Rotation interval in hours
    rotation_hours: int = 24

    # Honeyfile templates
    templates: list = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Default Honeyfile Templates
#
# These templates create realistic-looking files that would attract
# ransomware. The filenames mimic high-value targets like financial
# documents, databases, and credentials.
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_TEMPLATES = [
    HoneyfileTemplate(
        name="financial_spreadsheet",
        filename="Q4_Budget_Report_2026.xlsx",
        content_type="random_bytes",
        size_range=(8192, 131072),
    ),
    HoneyfileTemplate(
        name="database_backup",
        filename="customer_db_backup.sql",
        content_type="fake_sql",
        size_range=(4096, 65536),
    ),
    HoneyfileTemplate(
        name="credentials_file",
        filename="passwords_backup.csv",
        content_type="fake_credentials",
        size_range=(1024, 4096),
    ),
    HoneyfileTemplate(
        name="important_document",
        filename="Contract_Draft_Final.docx",
        content_type="random_bytes",
        size_range=(16384, 262144),
    ),
    HoneyfileTemplate(
        name="private_key",
        filename=".ssh_key_backup.pem",
        content_type="fake_private_key",
        size_range=(1600, 3200),
        hidden=True,
    ),
    HoneyfileTemplate(
        name="photo_archive",
        filename="Family_Photos_2025.zip",
        content_type="random_bytes",
        size_range=(32768, 524288),
    ),
    HoneyfileTemplate(
        name="config_backup",
        filename=".env.backup",
        content_type="fake_env",
        size_range=(512, 2048),
        hidden=True,
    ),
    HoneyfileTemplate(
        name="wallet_file",
        filename="crypto_wallet_backup.dat",
        content_type="random_bytes",
        size_range=(2048, 8192),
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# Content Generators
# ─────────────────────────────────────────────────────────────────────────────

def generate_random_bytes(size: int) -> bytes:
    """Generate random bytes (simulates encrypted/binary content)."""
    return os.urandom(size)


def generate_fake_sql(size: int) -> bytes:
    """Generate fake SQL dump content."""
    lines = [
        "-- MySQL dump 10.13  Distrib 8.0.36\n",
        "-- Host: localhost    Database: customer_db\n",
        "-- Server version: 8.0.36\n\n",
        "CREATE TABLE `customers` (\n",
        "  `id` int NOT NULL AUTO_INCREMENT,\n",
        "  `name` varchar(255) NOT NULL,\n",
        "  `email` varchar(255) NOT NULL,\n",
        "  `phone` varchar(20) DEFAULT NULL,\n",
        "  `address` text,\n",
        "  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,\n",
        "  PRIMARY KEY (`id`)\n",
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n",
        "INSERT INTO `customers` VALUES\n",
    ]
    content = "".join(lines)

    # Generate fake rows until we reach the target size
    row_id = 1
    while len(content) < size:
        name = "".join(random.choices(string.ascii_letters, k=random.randint(5, 15)))
        email = f"{name.lower()}@example.com"
        phone = f"+1-{random.randint(200, 999)}-{random.randint(100, 999)}-{random.randint(1000, 9999)}"
        content += f"({row_id},'{name}','{email}','{phone}','123 Main St'),\n"
        row_id += 1

    return content[:size].encode("utf-8")


def generate_fake_credentials(size: int) -> bytes:
    """Generate fake CSV credentials file."""
    content = "username,password,service,notes\n"
    services = ["AWS", "GitHub", "Gmail", "Slack", "Jira", "SSH", "VPN", "DB"]

    while len(content) < size:
        user = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 10)))
        passwd = "".join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=16))
        service = random.choice(services)
        content += f"{user},{passwd},{service},backup copy\n"

    return content[:size].encode("utf-8")


def generate_fake_private_key(size: int) -> bytes:
    """Generate a fake PEM private key."""
    header = "-----BEGIN RSA PRIVATE KEY-----\n"
    footer = "-----END RSA PRIVATE KEY-----\n"
    overhead = len(header) + len(footer)
    body_size = max(64, size - overhead)
    lines = []
    current = 0
    while current < body_size:
        chunk_len = min(64, body_size - current)
        line = "".join(random.choices(string.ascii_letters + string.digits + "+/", k=chunk_len))
        lines.append(line)
        current += chunk_len
    content = header + "\n".join(lines) + "\n" + footer
    return content.encode("utf-8")


def generate_fake_env(size: int) -> bytes:
    """Generate a fake .env file."""
    keys = [
        "DATABASE_URL", "API_KEY", "SECRET_KEY", "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET_KEY", "REDIS_URL",
        "SMTP_PASSWORD", "JWT_SECRET", "ENCRYPTION_KEY",
    ]
    content = "# Production Environment Variables\n# DO NOT COMMIT\n\n"
    for key in keys:
        value = "".join(random.choices(string.ascii_letters + string.digits, k=32))
        content += f"{key}={value}\n"
        if len(content) >= size:
            break
    return content[:size].encode("utf-8")


CONTENT_GENERATORS = {
    "random_bytes": generate_random_bytes,
    "fake_sql": generate_fake_sql,
    "fake_credentials": generate_fake_credentials,
    "fake_private_key": generate_fake_private_key,
    "fake_env": generate_fake_env,
}

# ─────────────────────────────────────────────────────────────────────────────
# Canary Manager Class
# ─────────────────────────────────────────────────────────────────────────────

class CanaryManager:
    """Manages deployment and lifecycle of honeyfiles."""

    def __init__(self, config: CanaryConfig):
        self.config = config
        self.deployed: list[DeployedHoneyfile] = []
        self.templates = DEFAULT_TEMPLATES

        # Load existing state if available
        self._load_state()

    def _load_state(self):
        """Load previously deployed honeyfile state."""
        state_path = Path(self.config.state_file)
        if state_path.exists():
            try:
                with open(state_path, "r") as f:
                    data = json.load(f)
                self.deployed = [
                    DeployedHoneyfile(**entry) for entry in data.get("deployed", [])
                ]
                log.info(f"Loaded state: {len(self.deployed)} deployed honeyfiles")
            except (json.JSONDecodeError, TypeError) as e:
                log.warning(f"Failed to load state file: {e}")
                self.deployed = []

    def _save_state(self):
        """Persist current deployment state to disk."""
        state_path = Path(self.config.state_file)
        state_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": 1,
            "updated_at": datetime.now().isoformat(),
            "deployed": [asdict(h) for h in self.deployed],
        }

        with open(state_path, "w") as f:
            json.dump(data, f, indent=2)

        log.info(f"State saved to {state_path}")

    def _write_honeyfile_list(self):
        """Write the list of honeyfile paths for the eBPF agent."""
        list_path = Path(self.config.honeyfile_list)
        list_path.parent.mkdir(parents=True, exist_ok=True)

        with open(list_path, "w") as f:
            f.write("# K-Sentinel Honeyfile Path List\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total: {len(self.deployed)} honeyfiles\n\n")
            for hf in self.deployed:
                f.write(f"{hf.path}\n")

        log.info(f"Honeyfile list written to {list_path} ({len(self.deployed)} paths)")

    def _find_deployment_dirs(self) -> list[str]:
        """Find suitable directories for honeyfile deployment."""
        dirs = []
        for target in self.config.target_dirs:
            target_path = Path(target)
            if not target_path.exists():
                log.warning(f"Target directory does not exist: {target}")
                continue

            # Add the root target directory
            if os.access(str(target_path), os.W_OK):
                dirs.append(str(target_path))

            # Recurse into subdirectories up to max_depth
            for depth in range(1, self.config.max_depth + 1):
                pattern = "/".join(["*"] * depth)
                for subdir in target_path.glob(pattern):
                    if subdir.is_dir() and os.access(str(subdir), os.W_OK):
                        dirs.append(str(subdir))

        log.info(f"Found {len(dirs)} writable directories for deployment")
        return dirs

    def _sha256(self, filepath: str) -> str:
        """Calculate SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def deploy(self) -> int:
        """Deploy honeyfiles across target directories."""
        log.info("═" * 60)
        log.info("Starting honeyfile deployment")
        log.info("═" * 60)

        dirs = self._find_deployment_dirs()
        if not dirs:
            log.error("No writable directories found for deployment!")
            return 0

        # Determine how many honeyfiles to deploy
        count = min(
            self.config.max_honeyfiles,
            max(self.config.min_honeyfiles, len(dirs))
        )

        deployed_count = 0
        for i in range(count):
            # Select a random directory and template
            target_dir = random.choice(dirs)
            template = random.choice(self.templates)

            # Generate the file path
            filename = template.filename
            if template.hidden and not filename.startswith("."):
                filename = f".{filename}"

            filepath = os.path.join(target_dir, filename)

            # Skip if file already exists (don't overwrite real files)
            if os.path.exists(filepath):
                continue

            # Generate content
            size = random.randint(*template.size_range)
            generator = CONTENT_GENERATORS.get(template.content_type,
                                                generate_random_bytes)
            content = generator(size)

            # Write the file
            try:
                with open(filepath, "wb") as f:
                    f.write(content)

                # Calculate hash
                file_hash = self._sha256(filepath)

                # Record deployment
                honeyfile = DeployedHoneyfile(
                    path=os.path.abspath(filepath),
                    template=template.name,
                    sha256=file_hash,
                    deployed_at=datetime.now().isoformat(),
                    size=len(content),
                )
                self.deployed.append(honeyfile)
                deployed_count += 1

                log.info(f"  ✓ Deployed: {filepath} ({len(content)} bytes)")

            except (OSError, PermissionError) as e:
                log.warning(f"  ✗ Failed: {filepath} — {e}")

        # Save state and honeyfile list
        self._save_state()
        self._write_honeyfile_list()

        log.info(f"\nDeployment complete: {deployed_count} honeyfiles deployed")
        return deployed_count

    def verify(self) -> tuple[int, int]:
        """Verify integrity of all deployed honeyfiles."""
        log.info("═" * 60)
        log.info("Verifying honeyfile integrity")
        log.info("═" * 60)

        ok_count = 0
        tampered_count = 0

        for hf in self.deployed:
            if not os.path.exists(hf.path):
                log.error(f"  ✗ MISSING: {hf.path}")
                hf.tampered = True
                tampered_count += 1
                continue

            current_hash = self._sha256(hf.path)
            if current_hash != hf.sha256:
                log.error(f"  ✗ TAMPERED: {hf.path}")
                log.error(f"    Expected: {hf.sha256}")
                log.error(f"    Got:      {current_hash}")
                hf.tampered = True
                tampered_count += 1
            else:
                log.info(f"  ✓ OK: {hf.path}")
                hf.verified_at = datetime.now().isoformat()
                ok_count += 1

        self._save_state()

        log.info(f"\nVerification complete: {ok_count} OK, {tampered_count} tampered")
        return ok_count, tampered_count

    def rotate(self):
        """Remove old honeyfiles and deploy fresh ones."""
        log.info("═" * 60)
        log.info("Rotating honeyfiles")
        log.info("═" * 60)

        # Remove existing honeyfiles
        self.clean()

        # Deploy fresh honeyfiles
        self.deploy()

        log.info("Rotation complete")

    def list_honeyfiles(self):
        """List all deployed honeyfiles."""
        log.info("═" * 60)
        log.info("Deployed Honeyfiles")
        log.info("═" * 60)

        if not self.deployed:
            log.info("  No honeyfiles deployed.")
            return

        for i, hf in enumerate(self.deployed, 1):
            status = "✓" if not hf.tampered else "✗ TAMPERED"
            log.info(f"  {i:3d}. [{status}] {hf.path}")
            log.info(f"       Template: {hf.template} | Size: {hf.size} bytes")
            log.info(f"       Deployed: {hf.deployed_at}")
            if hf.verified_at:
                log.info(f"       Verified: {hf.verified_at}")

    def clean(self) -> int:
        """Remove all deployed honeyfiles."""
        log.info("═" * 60)
        log.info("Cleaning up honeyfiles")
        log.info("═" * 60)

        removed = 0
        for hf in self.deployed:
            try:
                if os.path.exists(hf.path):
                    os.remove(hf.path)
                    log.info(f"  ✓ Removed: {hf.path}")
                    removed += 1
            except OSError as e:
                log.warning(f"  ✗ Failed to remove: {hf.path} — {e}")

        self.deployed.clear()
        self._save_state()

        log.info(f"\nCleanup complete: {removed} files removed")
        return removed


# ─────────────────────────────────────────────────────────────────────────────
# Configuration Loading
# ─────────────────────────────────────────────────────────────────────────────

def load_config(config_path: str) -> CanaryConfig:
    """Load configuration from YAML or JSON file."""
    config = CanaryConfig()

    if not os.path.exists(config_path):
        log.warning(f"Config file not found: {config_path}, using defaults")
        return config

    with open(config_path, "r") as f:
        if config_path.endswith((".yaml", ".yml")) and HAS_YAML:
            data = yaml.safe_load(f)
        else:
            data = json.load(f)

    if not data:
        return config

    # Apply configuration values
    if "target_dirs" in data:
        config.target_dirs = data["target_dirs"]
    if "max_depth" in data:
        config.max_depth = data["max_depth"]
    if "min_honeyfiles" in data:
        config.min_honeyfiles = data["min_honeyfiles"]
    if "max_honeyfiles" in data:
        config.max_honeyfiles = data["max_honeyfiles"]
    if "state_file" in data:
        config.state_file = data["state_file"]
    if "honeyfile_list" in data:
        config.honeyfile_list = data["honeyfile_list"]
    if "rotation_hours" in data:
        config.rotation_hours = data["rotation_hours"]

    return config


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="K-Sentinel Canary File Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  deploy    Deploy honeyfiles to target directories
  verify    Check integrity of deployed honeyfiles
  rotate    Remove old and deploy fresh honeyfiles
  list      List all deployed honeyfiles
  clean     Remove all deployed honeyfiles
        """,
    )

    parser.add_argument(
        "command",
        choices=["deploy", "verify", "rotate", "list", "clean"],
        help="Action to perform",
    )
    parser.add_argument(
        "-c", "--config",
        default="canary_config.yaml",
        help="Path to configuration file (default: canary_config.yaml)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load config
    config = load_config(args.config)

    # Create manager
    manager = CanaryManager(config)

    # Execute command
    if args.command == "deploy":
        count = manager.deploy()
        sys.exit(0 if count > 0 else 1)
    elif args.command == "verify":
        ok, tampered = manager.verify()
        sys.exit(0 if tampered == 0 else 1)
    elif args.command == "rotate":
        manager.rotate()
    elif args.command == "list":
        manager.list_honeyfiles()
    elif args.command == "clean":
        manager.clean()


if __name__ == "__main__":
    main()

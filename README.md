# 🛡️ K-Sentinel — Kernel-Space Security Sentinel

> **An eBPF-Driven Runtime Security Agent and Automated Ransomware Mitigation Engine**

---

## 🎯 Objective

To design and implement a **low-overhead, kernel-level endpoint detection and response (EDR) agent** that utilizes Extended Berkeley Packet Filter (eBPF) tracepoints to achieve real-time behavioral profiling of file system operations. The system intercepts low-level `sys_enter` system calls, evaluates process execution patterns against a proactive **canary-file (honeyfile) framework** and in-kernel **write-buffer entropy sampling**, and executes autonomous mitigation (`bpf_send_signal`) to terminate ransomware processes **from kernel space** with bounded data loss (measured: ~2.4% of files in our tests, see [Evaluation](#-evaluation-measured-results)).

---

## 🏗️ Architecture

```
┌─────────────── KERNEL SPACE ──────────────────┐
│                                                │
│  eBPF Programs (BPF CO-RE)                     │
│  ┌────────────┐  ┌──────────────┐              │
│  │  File       │  │  Process     │              │
│  │  Monitor    │  │  Monitor     │              │
│  │  • openat   │  │  • execve    │              │
│  │  • write    │  │  • exit      │              │
│  │  • rename   │  │              │              │
│  │  • unlink   │  │              │              │
│  └──────┬──────┘  └──────┬───────┘              │
│         │                │                      │
│         ▼                ▼                      │
│  ┌─────────────────────────────┐                │
│  │    Ring Buffer + Hash Maps  │                │
│  └────────────┬────────────────┘                │
│               │ bpf_send_signal(SIGKILL)        │
├═══════════════╪═════════════════════════════════┤
│               ▼                                 │
│  ┌─────────── USER SPACE ────────────────────┐  │
│  │  K-Sentinel Agent                         │  │
│  │  ├── Detection Engine (scoring)           │  │
│  │  ├── Response Engine (kill + log)         │  │
│  │  └── Canary Manager (honeyfiles)          │  │
│  │                                           │  │
│  │  Web Dashboard (real-time monitoring)     │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## 🧠 Core Detection Strategies

| Strategy | Mechanism | Response |
|----------|-----------|----------|
| **Honeyfile Detection** | O(1) hash map lookup on every `openat()` | Instant `SIGKILL` in kernel space |
| **Frequency Analysis** | Sliding window operation counter per PID | Escalated severity scoring |
| **Entropy Analysis** | eBPF samples the first 256 bytes of each large `write()`; the agent computes Shannon entropy with a small-sample (Miller–Madow) bias correction | High-entropy writes flagged |
| **Mass Rename Detection** | Rename-to-total ratio analysis | Behavioral score boost |
| **Composite Scoring** | Weighted multi-factor score (honeyfile 0.40, frequency 0.25, entropy 0.25, rename 0.10, delete 0.05). Frequency or entropy alone stays below MEDIUM; **both together reach HIGH** (corroboration) | Graduated response (log → alert → kill) |

## 📁 Project Structure

```
K-Sentinel/
├── src/
│   ├── bpf/ksentinel.bpf.c          # eBPF kernel-space program
│   ├── include/                       # Shared headers
│   ├── agent/                         # User-space agent (C/libbpf)
│   │   ├── main.c                     # BPF loader & event loop
│   │   ├── detection_engine.c         # Behavioral analysis
│   │   ├── event_handler.c            # Ring buffer processor
│   │   └── response_engine.c          # Mitigation actions
│   └── canary/                        # Honeyfile manager (Python)
├── dashboard/                         # Real-time web dashboard
├── tests/                             # Unit tests & simulator
├── configs/                           # Lima VM & agent configs
├── scripts/                           # Setup & demo scripts
└── docs/                              # Architecture documentation
```

## 🚀 Quick Start

### Prerequisites

- **macOS** with Homebrew installed
- **Lima** (`brew install lima`) for Linux VM

### 1. Set Up the Linux VM

```bash
# Run the automated setup script
chmod +x scripts/setup-lima-vm.sh
./scripts/setup-lima-vm.sh
```

This creates an Ubuntu 24.04 VM with all eBPF tools pre-installed.

### 2. Build K-Sentinel (inside the VM)

```bash
limactl shell ebpf-dev
cd /Users/$USER/Downloads/Cybersec_Proj/K-Sentinel   # Lima mounts your home at the same path as on macOS
make vmlinux   # Generate kernel type headers
make all       # Compile eBPF programs + agent
```

### 3. Deploy Honeyfiles

```bash
sudo python3 src/canary/canary_manager.py deploy
```

### 4. Run the Agent

```bash
sudo ./build/ksentinel-agent --honeyfiles /etc/ksentinel/honeyfiles.txt -i /tmp/ks-incidents.json -q
```

### 5. Open the Dashboard

**Simulated demo (macOS, no VM):** open `dashboard/index.html` and click **"Simulate"**.

**Live agent data:** in the VM, run

```bash
python3 scripts/dashboard_bridge.py --log /tmp/ks-incidents.json --port 8080
```

then open `http://localhost:8080/?live=1` on macOS (Lima forwards the port).

### 6. Test with Ransomware Simulator

```bash
python3 tests/ransomware_simulator.py --mode all
```

## 🧪 Testing on macOS (No Linux Required)

```bash
# Test the detection engine (Shannon entropy, scoring, etc.)
make test-detection

# Test the canary file manager
pip3 install pytest
make test-canary

# Open the interactive dashboard
make dashboard
```

## 🔬 Technical Highlights

- **BPF CO-RE**: Compile Once, Run Everywhere — portable across kernel versions
- **Ring Buffer**: High-performance, lock-free event channel (256 KB)
- **Zero-Copy**: Events processed in-place from the ring buffer
- **O(1) Honeyfile Lookup**: BPF hash map for constant-time path matching
- **Kernel-Space Kill**: `bpf_send_signal(SIGKILL)` is issued from the syscall hook; the kernel delivers it when the offending thread returns to user mode, so the triggering syscall itself still completes (see Limitations)

## 📊 Evaluation (measured results)

Measured inside the Lima VM (Ubuntu 24.04, kernel 6.8, aarch64). Scripts are in `scripts/`.

| Experiment | Result |
|---|---|
| Honeyfile touched (`test-honeyfile-kill.sh`) | Process killed on first access |
| Simulator, frequency / rename / delete modes (`eval-simulator.sh`) | All killed (HIGH → SIGKILL) |
| Files encrypted before kill (`eval-metrics.sh`, 500 × 32 KB, 3 trials) | **12 / 500 (2.4%)** each trial |
| False positives: rebuild, `tar czf`, `cp -r`, text writes, `grep -r` (`eval-false-positives.sh`) | 0 alerts above LOW, 0 kills |
| Runtime overhead, tar+gzip+grep workload | ≈ 6.9% (short workload; noisy) |
| Unit tests | 10/10 C detection tests, 18/18 canary tests |

**Stealth boundary** (`eval-stealth.sh`, 100 files): the attacker is killed at 0–0.2 s delay per file (11–12 files lost) but **evades detection at 0.5 s per file** (all 100 encrypted) unless it touches a honeyfile.

## ⚠️ Limitations & Threat Model

- **Kill latency is not zero.** `SIGKILL` takes effect when the thread returns to user mode; a few operations complete before the process dies.
- **Low-and-slow ransomware evades behavioural scoring** (see stealth boundary). Honeyfiles remain the defence against it.
- **Sampling can be evaded.** Only the first 256 bytes of each write ≥128 bytes are sampled; an attacker could pad writes with low-entropy data.
- **Honeyfile matching uses the path string passed to the syscall.** Relative paths, `dfd`-relative opens and symlinks can bypass it.
- **Needs root / CAP_BPF**, and a root-level attacker could unload the programs.
- **False-positive coverage is limited** to the workloads listed above; backup tools, databases and archive extraction are untested.
- Evaluation used a Python simulator and a single VM, not real ransomware samples.

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*K-Sentinel — Catching ransomware in flight, not in the aftermath.*

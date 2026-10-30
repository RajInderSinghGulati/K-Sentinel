#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# K-Sentinel — Lima VM Setup Script
# setup-lima-vm.sh
#
# Automates the complete setup of the eBPF development environment on macOS:
#   1. Installs Lima (if not present)
#   2. Creates and starts the eBPF development VM
#   3. Generates vmlinux.h inside the VM
#   4. Verifies the environment is ready
#
# Usage: ./scripts/setup-lima-vm.sh
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LIMA_CONFIG="$PROJECT_DIR/configs/ebpf-dev.yaml"
VM_NAME="ebpf-dev"

echo -e "${CYAN}"
echo "  ██╗  ██╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     "
echo "  ██║ ██╔╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     "
echo "  █████╔╝     ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     "
echo "  ██╔═██╗     ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     "
echo "  ██║  ██╗    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ "
echo "  ╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ "
echo -e "${RESET}"
echo -e "${BOLD}  Lima VM Setup — eBPF Development Environment${RESET}"
echo "  ─────────────────────────────────────────────────────────────"
echo ""

# ── Step 1: Check/Install Lima ────────────────────────────────────────────────
echo -e "${BOLD}[1/5] Checking Lima installation...${RESET}"

if command -v limactl &> /dev/null; then
    LIMA_VERSION=$(limactl --version 2>&1 | head -1)
    echo -e "  ${GREEN}✓${RESET} Lima is installed: $LIMA_VERSION"
else
    echo -e "  ${YELLOW}⚠${RESET} Lima not found. Installing via Homebrew..."

    if ! command -v brew &> /dev/null; then
        echo -e "  ${RED}✗${RESET} Homebrew is not installed!"
        echo "    Install it from: https://brew.sh"
        exit 1
    fi

    brew install lima
    echo -e "  ${GREEN}✓${RESET} Lima installed successfully"
fi

# ── Step 2: Check if VM already exists ────────────────────────────────────────
echo ""
echo -e "${BOLD}[2/5] Checking VM status...${RESET}"

if limactl list --json 2>/dev/null | grep -q "\"name\":\"$VM_NAME\""; then
    VM_STATUS=$(limactl list --json | python3 -c "
import sys, json
vms = json.load(sys.stdin)
for vm in vms:
    if vm.get('name') == '$VM_NAME':
        print(vm.get('status', 'unknown'))
        break
" 2>/dev/null || echo "unknown")

    echo -e "  ${GREEN}✓${RESET} VM '$VM_NAME' exists (status: $VM_STATUS)"

    if [ "$VM_STATUS" != "Running" ]; then
        echo -e "  ${CYAN}→${RESET} Starting VM..."
        limactl start "$VM_NAME"
    fi
else
    echo -e "  ${CYAN}→${RESET} Creating VM '$VM_NAME' from $LIMA_CONFIG..."
    echo "    This will download Ubuntu 24.04 and install eBPF tools."
    echo "    This may take 5-10 minutes on first run."
    echo ""

    limactl start --name="$VM_NAME" "$LIMA_CONFIG"
    echo -e "  ${GREEN}✓${RESET} VM created and started"
fi

# ── Step 3: Generate vmlinux.h ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[3/5] Generating vmlinux.h...${RESET}"

BPF_DIR="$PROJECT_DIR/src/bpf"
VMLINUX_PATH="$BPF_DIR/vmlinux.h"

limactl shell "$VM_NAME" -- bash -c "
    if command -v bpftool &> /dev/null; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c
    else
        echo 'ERROR: bpftool not available'
        exit 1
    fi
" > "$VMLINUX_PATH" 2>/dev/null

if [ -s "$VMLINUX_PATH" ]; then
    VMLINUX_SIZE=$(wc -c < "$VMLINUX_PATH" | tr -d ' ')
    echo -e "  ${GREEN}✓${RESET} vmlinux.h generated ($VMLINUX_SIZE bytes)"
else
    echo -e "  ${YELLOW}⚠${RESET} vmlinux.h generation failed. You can generate it manually:"
    echo "    limactl shell $VM_NAME"
    echo "    bpftool btf dump file /sys/kernel/btf/vmlinux format c > ~/Downloads/Cybersec_Proj/K-Sentinel/src/bpf/vmlinux.h"
fi

# ── Step 4: Verify Environment ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[4/5] Verifying eBPF development environment...${RESET}"

limactl shell "$VM_NAME" -- bash -c '
    echo "  Kernel:    $(uname -r)"
    echo "  Arch:      $(uname -m)"
    echo "  Clang:     $(clang --version 2>/dev/null | head -1 || echo "not found")"
    echo "  libbpf:    $(pkg-config --modversion libbpf 2>/dev/null || echo "not found")"
    echo "  bpftool:   $(bpftool version 2>/dev/null | head -1 || echo "not found")"
    echo "  BTF:       $(test -f /sys/kernel/btf/vmlinux && echo "available" || echo "not available")"
    echo "  Python:    $(python3 --version 2>/dev/null || echo "not found")"
    echo "  GCC:       $(gcc --version 2>/dev/null | head -1 || echo "not found")"
'

# ── Step 5: Print Next Steps ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[5/5] Setup Complete!${RESET}"
echo ""
echo "  ═══════════════════════════════════════════════════════════"
echo -e "  ${GREEN}✓ Your eBPF development environment is ready!${RESET}"
echo "  ═══════════════════════════════════════════════════════════"
echo ""
echo "  To enter the VM:"
echo -e "    ${CYAN}limactl shell $VM_NAME${RESET}"
echo ""
echo "  To build K-Sentinel inside the VM:"
echo -e "    ${CYAN}cd ~/Downloads/Cybersec_Proj/K-Sentinel${RESET}"
echo -e "    ${CYAN}make all${RESET}"
echo ""
echo "  To run the agent (inside VM, as root):"
echo -e "    ${CYAN}sudo ./build/ksentinel-agent --honeyfiles /etc/ksentinel/honeyfiles.txt${RESET}"
echo ""
echo "  To stop the VM:"
echo -e "    ${CYAN}limactl stop $VM_NAME${RESET}"
echo ""

#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# K-Sentinel — 40% Milestone Demonstration Script (macOS / Cross-Platform)
# scripts/demo-40percent.sh
#
# Walks through all pillars of the 40% implementation milestone:
#   [1/5] Core Detection Engine Tests (C Heuristics, Shannon Entropy, Scores)
#   [2/5] Canary File Manager Unit Tests (18 PyTest cases)
#   [3/5] Honeyfile Deployment, Listing, Verification & Cleanup
#   [4/5] Ransomware Behavior Simulation (Safe sandbox test)
#   [5/5] Launching the Interactive Web Dashboard
#
# Usage: ./scripts/demo-40percent.sh
# ══════════════════════════════════════════════════════════════════════════════

set -e

# Terminal colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# ── Header ────────────────────────────────────────────────────────────────────
clear
echo -e "${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════════════════╗"
echo "  ║                                                                   ║"
echo "  ║     🛡️  K-SENTINEL — 40% IMPLEMENTATION MILESTONE DEMO             ║"
echo "  ║     eBPF Runtime Security & Behavioral Ransomware Defense         ║"
echo "  ║                                                                   ║"
echo "  ╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Check Virtual Environment ────────────────────────────────────────────────
if [ -d "$PROJECT_DIR/venv" ]; then
    echo -e "${GREEN}✓${RESET} Activating Python virtual environment..."
    # shellcheck disable=SC1091
    source "$PROJECT_DIR/venv/bin/activate"
    PYTHON="$PROJECT_DIR/venv/bin/python3"
else
    PYTHON="python3"
fi

pause_step() {
    echo ""
    echo -e "${YELLOW}➔ Press [ENTER] to continue to the next step...${RESET}"
    read -r
    echo ""
}

# ── STEP 1: Detection Engine (C Unit Tests) ──────────────────────────────────
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}[STEP 1/5] Core Detection Engine Heuristics & Shannon Entropy Tests${RESET}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "Testing mathematical core: Shannon entropy calculation, sliding-window"
echo -e "frequency scoring, mass rename detection, and PID tracking state machine.\n"

make test-detection

pause_step

# ── STEP 2: Canary Manager PyTest Suite ──────────────────────────────────────
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}[STEP 2/5] Canary File Manager Test Suite (18 Unit Tests)${RESET}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "Testing honeyfile deployment logic, realistic decoy content generators,"
echo -e "SHA-256 integrity verification, and decoy rotation.\n"

$PYTHON -m pytest tests/test_canary_manager.py -v

pause_step

# ── STEP 3: Honeyfile Deployment & Verification Lifecycle ────────────────────
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}[STEP 3/5] Live Canary Deployment, Verification & Tamper Detection${RESET}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"

LOCAL_CONFIG="$PROJECT_DIR/configs/canary_local.yaml"
mkdir -p /tmp/ksentinel_canaries

echo -e "${BOLD}(a) Deploying realistic decoy honeyfiles...${RESET}"
$PYTHON src/canary/canary_manager.py deploy -c "$LOCAL_CONFIG"

echo -e "\n${BOLD}(b) Listing active deployed honeyfiles:${RESET}"
$PYTHON src/canary/canary_manager.py list -c "$LOCAL_CONFIG"

echo -e "\n${BOLD}(c) Verifying SHA-256 cryptographic integrity:${RESET}"
$PYTHON src/canary/canary_manager.py verify -c "$LOCAL_CONFIG"

echo -e "\n${BOLD}(d) Cleaning up test honeyfiles:${RESET}"
$PYTHON src/canary/canary_manager.py clean -c "$LOCAL_CONFIG"

pause_step

# ── STEP 4: Ransomware Behavior Simulation ───────────────────────────────────
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}[STEP 4/5] Safe Ransomware Behavioral Simulation${RESET}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "Simulating rapid filesystem traversal, high-frequency I/O burst rate,"
echo -e "mass file extension renaming (.locked, .encrypted), and canary access.\n"

$PYTHON tests/ransomware_simulator.py --mode all

echo -e "\nCleaning up simulator sandbox directory..."
$PYTHON tests/ransomware_simulator.py --cleanup

pause_step

# ── STEP 5: Live Interactive Dashboard ───────────────────────────────────────
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}[STEP 5/5] Launching Real-Time Monitoring Dashboard${RESET}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "Opening dashboard in browser. Click the ${BOLD}'Simulate'${RESET} button to see"
echo -e "real-time threat scoring, live I/O burst frequency charts, and SIGKILL mitigation!\n"

if [ "$(uname -s)" = "Darwin" ]; then
    open "$PROJECT_DIR/dashboard/index.html"
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$PROJECT_DIR/dashboard/index.html"
else
    echo -e "Open the dashboard at: ${CYAN}file://$PROJECT_DIR/dashboard/index.html${RESET}"
fi

echo -e "${GREEN}${BOLD}"
echo "  ═══════════════════════════════════════════════════════════════"
echo "  ✓ 40% Milestone Demonstration Complete!"
echo "  ═══════════════════════════════════════════════════════════════"
echo -e "${RESET}"

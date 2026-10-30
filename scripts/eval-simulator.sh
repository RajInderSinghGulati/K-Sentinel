#!/bin/bash
# K-Sentinel — live evaluation: ransomware simulator vs. running agent (run inside the VM)
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
T=/tmp/ks_eval; rm -rf "$T"; mkdir -p "$T"
HF=/tmp/ksentinel_test/documents/financial/Q4_Budget_Report_2026.xlsx

for MODE in frequency rename delete honeyfile; do
    if [ "$MODE" = honeyfile ]; then echo "$HF" > "$T/honeyfiles.txt"; else echo "/nonexistent/none" > "$T/honeyfiles.txt"; fi
    : > "$T/inc.json"
    sudo ./build/ksentinel-agent -f "$T/honeyfiles.txt" -i "$T/inc.json" -q > "$T/agent.log" 2>&1 &
    AG=$!; sleep 3
    START=$(date +%s.%N)
    python3 tests/ransomware_simulator.py --mode "$MODE" > "$T/sim_$MODE.log" 2>&1
    END=$(date +%s.%N)
    sleep 1; sudo pkill -INT ksentinel-agent; wait "$AG" 2>/dev/null
    SIM=$(grep -c '"comm":"python3"' "$T/inc.json")
    HIGH=$(grep '"comm":"python3"' "$T/inc.json" | grep -c '"severity":"\(HIGH\|CRITICAL\)"')
    MED=$(grep '"comm":"python3"' "$T/inc.json" | grep -c '"severity":"MEDIUM"')
    KILLS=$(grep -c '"kill_success":true' "$T/inc.json")
    FIRST=$(grep '"comm":"python3"' "$T/inc.json" | grep -m1 '"severity":"\(HIGH\|CRITICAL\)"' | cut -c1-200)
    printf "MODE=%-10s events=%-5s medium=%-4s high+=%-4s kills=%-3s runtime=%.1fs\n" \
        "$MODE" "$SIM" "$MED" "$HIGH" "$KILLS" "$(echo "$END - $START" | bc)"
    echo "   first HIGH+: ${FIRST:-none}"
done
python3 tests/ransomware_simulator.py --cleanup >/dev/null 2>&1

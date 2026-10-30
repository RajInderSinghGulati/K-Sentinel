#!/bin/bash
# K-Sentinel — live honeyfile kill test (run inside the Lima VM)
# Usage: ./scripts/test-honeyfile-kill.sh
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ "$(uname -s)" != "Linux" ]; then
    echo "Error: This test requires the Linux kernel eBPF subsystem."
    echo "Run inside the Lima VM: limactl shell ebpf-dev"
    exit 1
fi

T=/tmp/ks_test
rm -rf "$T"; mkdir -p "$T/docs"
cat > "$T/canary.json" <<EOF
{
  "target_dirs": ["$T/docs"],
  "max_depth": 1,
  "min_honeyfiles": 3,
  "max_honeyfiles": 5,
  "state_file": "$T/state.json",
  "honeyfile_list": "$T/honeyfiles.txt",
  "rotation_hours": 24
}
EOF

sudo python3 src/canary/canary_manager.py -c "$T/canary.json" deploy
echo "--- honeyfiles:"; cat "$T/honeyfiles.txt"

sudo ./build/ksentinel-agent -f "$T/honeyfiles.txt" -i "$T/incidents.json" -q > "$T/agent.log" 2>&1 &
AGENT=$!
sleep 3

HF=$(grep -v '^#' "$T/honeyfiles.txt" | grep -v '^$' | head -1)
echo "--- touching honeyfile with 'cat': $HF"
bash -c "cat '$HF' > /dev/null; sleep 5; echo SURVIVED" ; RC=$?
echo "exit code: $RC  (137 = SIGKILL => PASS)"

sleep 1
sudo kill "$AGENT" 2>/dev/null; sleep 1
echo "--- incidents:"; tail -3 "$T/incidents.json" 2>/dev/null
if grep -q 'Processes killed:  [1-9]' "$T/agent.log"; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
echo "--- agent log tail:"; tail -8 "$T/agent.log"

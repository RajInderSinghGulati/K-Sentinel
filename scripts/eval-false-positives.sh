#!/bin/bash
# K-Sentinel — false-positive check: benign heavy workloads under a live agent (run in the VM)
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
T=/tmp/ks_fp; rm -rf "$T"; mkdir -p "$T"
echo "/nonexistent/none" > "$T/hf.txt"

sudo ./build/ksentinel-agent -f "$T/hf.txt" -i "$T/inc.json" -q > "$T/agent.log" 2>&1 &
sleep 3
run() { echo "== $1"; bash -c "$2" > /dev/null 2>&1; echo "   exit=$?"; }
run "compile (clean + build)" "make clean && make all"
run "tar + gzip of project"   "tar czf $T/p.tgz src docs tests"
run "recursive copy"          "mkdir -p $T/copy && cp -r src docs $T/copy"
run "text log generation"     "for i in \$(seq 1 3000); do echo line \$i lorem ipsum dolor sit amet >> $T/t.log; done"
run "find + grep over tree"   "grep -r include src | wc -l"
sleep 1; sudo pkill -INT ksentinel-agent; sleep 1
echo "--- HIGH+ alerts on benign work: $(grep -c '"severity":"\(HIGH\|CRITICAL\)"' "$T/inc.json")"
echo "--- processes killed: $(grep -c '"kill_success":true' "$T/inc.json")"
echo "--- MEDIUM alerts: $(grep -c '"severity":"MEDIUM"' "$T/inc.json")"
grep '"severity":"\(HIGH\|CRITICAL\)"' "$T/inc.json" | head -3 | cut -c1-230

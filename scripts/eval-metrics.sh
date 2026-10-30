#!/bin/bash
# K-Sentinel — key metrics (run inside the VM):
#   1. files encrypted before the attacker is killed (no honeyfile registered)
#   2. runtime overhead of the agent on a benign workload
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
T=/tmp/ks_metrics; rm -rf "$T"; mkdir -p "$T/victim"
echo "/nonexistent/none" > "$T/hf.txt"
N=500

cat > "$T/attacker.py" <<'EOF'
import os, sys
d, n = sys.argv[1], int(sys.argv[2])
for i in range(n):
    p = f"{d}/f{i}.txt"
    data = open(p, "rb").read()
    with open(p + ".enc", "wb") as o:
        o.write(os.urandom(len(data)))      # "encrypted" payload
    os.remove(p)
EOF

echo "== 1. Files lost before kill (N=$N files, 32 KB each)"
for TRIAL in 1 2 3; do
    rm -rf "$T/victim"; mkdir -p "$T/victim"
    for i in $(seq 0 $((N-1))); do head -c 32768 /dev/zero | tr '\0' 'a' > "$T/victim/f$i.txt"; done
    sudo ./build/ksentinel-agent -f "$T/hf.txt" -i "$T/inc.json" -q > "$T/agent.log" 2>&1 &
    sleep 3
    python3 "$T/attacker.py" "$T/victim" $N 2>/dev/null
    RC=$?
    sleep 1; sudo pkill -INT ksentinel-agent; sleep 1
    LOST=$(ls "$T/victim" | grep -c '\.enc$')
    echo "   trial $TRIAL: attacker exit=$RC  files encrypted before kill: $LOST / $N"
done

echo "== 2. Overhead (tar+gzip + grep over the repo, 5 runs)"
work() { for i in 1 2 3 4 5; do tar czf "$T/o.tgz" src docs tests >/dev/null 2>&1; grep -r include src >/dev/null; done; }
S=$(date +%s.%N); work; E=$(date +%s.%N); BASE=$(echo "$E - $S" | bc)
sudo ./build/ksentinel-agent -f "$T/hf.txt" -i "$T/inc2.json" -q > "$T/agent2.log" 2>&1 &
sleep 3
S=$(date +%s.%N); work; E=$(date +%s.%N); WITH=$(echo "$E - $S" | bc)
sudo pkill -INT ksentinel-agent; sleep 1
printf "   baseline=%.2fs  with agent=%.2fs  overhead=%.1f%%\n" "$BASE" "$WITH" "$(echo "($WITH - $BASE) * 100 / $BASE" | bc -l)"

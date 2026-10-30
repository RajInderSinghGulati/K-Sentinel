#!/bin/bash
# K-Sentinel — stealth evaluation: how slow must ransomware be to evade detection? (run in the VM)
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
T=/tmp/ks_stealth; rm -rf "$T"; mkdir -p "$T"
echo "/nonexistent/none" > "$T/hf.txt"
N=100

cat > "$T/attacker.py" <<'EOF'
import os, sys, time
d, n, delay = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
for i in range(n):
    p = f"{d}/f{i}.txt"
    data = open(p, "rb").read()
    with open(p + ".enc", "wb") as o:
        o.write(os.urandom(len(data)))
    os.remove(p)
    time.sleep(delay)
EOF

printf "%-12s %-10s %s\n" "delay/file" "killed" "files encrypted (of $N)"
for DELAY in 0 0.05 0.1 0.2 0.5; do
    rm -rf "$T/v"; mkdir -p "$T/v"
    for i in $(seq 0 $((N-1))); do head -c 32768 /dev/zero | tr '\0' 'a' > "$T/v/f$i.txt"; done
    sudo ./build/ksentinel-agent -f "$T/hf.txt" -i "$T/inc.json" -q > "$T/agent.log" 2>&1 &
    sleep 3
    timeout 90 python3 "$T/attacker.py" "$T/v" $N $DELAY 2>/dev/null; RC=$?
    sleep 1; sudo pkill -INT ksentinel-agent; sleep 1
    DONE=$(ls "$T/v" | grep -c '\.enc$')
    printf "%-12s %-10s %s\n" "${DELAY}s" "$([ $RC -eq 137 ] && echo YES || echo no)" "$DONE"
done

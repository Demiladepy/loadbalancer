#!/bin/bash
# Build a two-backend direct-server-return lab and record what it actually does.
set -u

cd /src
RESULT=/tmp/lab-result.txt
: > "$RESULT"

log() {
    printf '%s\n' "$*" | tee -a "$RESULT"
}

cleanup() {
    set +e
    if [ -n "${LOADER_PID:-}" ]; then
        kill "$LOADER_PID" 2>/dev/null
        wait "$LOADER_PID" 2>/dev/null
    fi
    pkill -f scripts/backend.py 2>/dev/null
    for ns in client be0 be1; do
        ip netns del "$ns" 2>/dev/null
    done
    for link in vc-b b0-b b1-b; do
        ip link del "$link" 2>/dev/null
    done
}
trap cleanup EXIT

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null

for ns in client be0 be1; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
done

ip link add vc-a type veth peer name vc-b
ip link add b0-a type veth peer name b0-b
ip link add b1-a type veth peer name b1-b

ip link set vc-a netns client
ip link set b0-a netns be0
ip link set b1-a netns be1

ip netns exec client ip link set vc-a name eth0
ip netns exec be0 ip link set b0-a name eth0
ip netns exec be1 ip link set b1-a name eth0

ip link set vc-b up
ip link set b0-b up
ip link set b1-b up
ip addr add 10.0.0.1/24 dev vc-b
ip addr add 10.0.1.1/24 dev b0-b
ip addr add 10.0.2.1/24 dev b1-b
sysctl -w net.ipv4.conf.vc-b.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.b0-b.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.b1-b.rp_filter=0 >/dev/null

setup_ns() {
    local ns="$1" addr="$2"
    ip netns exec "$ns" ip link set eth0 up
    ip netns exec "$ns" ip addr add "$addr" dev eth0
    ip netns exec "$ns" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    ip netns exec "$ns" sysctl -w net.ipv4.conf.eth0.rp_filter=0 >/dev/null
}

setup_ns client 10.0.0.2/24
setup_ns be0 10.0.1.2/24
setup_ns be1 10.0.2.2/24

ip netns exec client ip route add 10.0.0.10/32 via 10.0.0.1
for ns in be0 be1; do
    ip netns exec "$ns" ip addr add 10.0.0.10/32 dev lo
    ip netns exec "$ns" sysctl -w net.ipv4.conf.all.arp_ignore=1 >/dev/null
    ip netns exec "$ns" sysctl -w net.ipv4.conf.all.arp_announce=2 >/dev/null
done
ip netns exec be0 ip route add default via 10.0.1.1
ip netns exec be1 ip route add default via 10.0.2.1

MAC0=$(ip netns exec be0 cat /sys/class/net/eth0/address)
MAC1=$(ip netns exec be1 cat /sys/class/net/eth0/address)

ip netns exec be0 env BACKEND_NAME=be0 PIDFILE=/tmp/be0.pid python3 /src/scripts/backend.py >/tmp/be0.log 2>&1 &
ip netns exec be1 env BACKEND_NAME=be1 PIDFILE=/tmp/be1.pid python3 /src/scripts/backend.py >/tmp/be1.log 2>&1 &

for _ in 1 2 3 4 5 6 7 8 9 10; do
    ok0=$(ip netns exec be0 curl -s --max-time 1 http://127.0.0.1:8080/ || true)
    ok1=$(ip netns exec be1 curl -s --max-time 1 http://127.0.0.1:8080/ || true)
    if [ "$ok0" = "be0" ] && [ "$ok1" = "be1" ]; then
        break
    fi
    sleep 0.2
done
log "direct: be0=$(ip netns exec be0 curl -s --max-time 1 http://127.0.0.1:8080/ || echo down) be1=$(ip netns exec be1 curl -s --max-time 1 http://127.0.0.1:8080/ || echo down)"

./xdp_loader --iface vc-b --vip 10.0.0.10 --port 8080 \
    --interval 1 --fail 2 --success 1 \
    --backend "10.0.1.2,${MAC0},b0-b" \
    --backend "10.0.2.2,${MAC1},b1-b" \
    >/tmp/loader.log 2>&1 &
LOADER_PID=$!

for _ in 1 2 3 4 5 6 7 8 9 10; do
    if grep -q attached /tmp/loader.log 2>/dev/null; then
        break
    fi
    sleep 0.2
done
if ! grep -q attached /tmp/loader.log; then
    log "FAIL loader did not attach"
    cat /tmp/loader.log | tee -a "$RESULT"
    exit 1
fi
log "loader: $(head -n 5 /tmp/loader.log | tr '\n' ' ')"

be0_hits=0
be1_hits=0
fail_hits=0
for _ in $(seq 1 20); do
    body=$(ip netns exec client curl -s --max-time 1 "http://10.0.0.10:8080/" || true)
    case "$body" in
        be0) be0_hits=$((be0_hits + 1)) ;;
        be1) be1_hits=$((be1_hits + 1)) ;;
        *) fail_hits=$((fail_hits + 1)) ;;
    esac
done
log "spread: be0=${be0_hits} be1=${be1_hits} fail=${fail_hits}"

# Stop be0 only. pkill scans the container's global pid list and would
# also kill be1, which shares this pid namespace.
be0_pid=$(cat /tmp/be0.pid 2>/dev/null || true)
kill "$be0_pid" 2>/dev/null || true
start_ms=$(date +%s%3N)
# interval * fail_limit is 2s, plus one interval of phase. Give the probes
# time to run, then require six answers from the survivor.
end_ms=$((start_ms + 8000))
window_fail=0
stable=0
eject_ms=0
while [ "$(date +%s%3N)" -lt "$end_ms" ]; do
    body=$(ip netns exec client curl -s --max-time 1 "http://10.0.0.10:8080/" || true)
    if [ "$body" = "be1" ]; then
        stable=$((stable + 1))
        if [ "$stable" -ge 6 ] && [ "$eject_ms" -eq 0 ]; then
            now_ms=$(date +%s%3N)
            eject_ms=$((now_ms - start_ms))
            break
        fi
    else
        stable=0
        window_fail=$((window_fail + 1))
    fi
done
if kill -0 "$be0_pid" 2>/dev/null; then
    log "be0 pid ${be0_pid} still alive"
else
    log "be0 pid ${be0_pid} dead"
fi
log "after killing be0: failed_or_other=${window_fail} ms_until_six_be1=${eject_ms}"
log "loader tail: $(tail -n 12 /tmp/loader.log | tr '\n' ' ')"

if [ "$be0_hits" -gt 0 ] && [ "$be1_hits" -gt 0 ] && [ "$fail_hits" -eq 0 ] && [ "$eject_ms" -gt 0 ]; then
    log "LAB PASS"
    exit 0
fi
log "LAB FAIL"
exit 1

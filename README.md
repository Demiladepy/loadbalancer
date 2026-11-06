# eBPF XDP load balancer

Layer-4 balancer. An XDP program on the ingress interface picks a backend, rewrites the destination MAC, and `bpf_redirect`s the frame. It does not rewrite IP addresses, so the IP checksum stays valid. Each backend owns the VIP on loopback and answers directly (direct server return).

`xdp_lb.c` is the kernel program. `xdp_loader.c` loads it, writes the maps, and runs the health checks. The loader attaches with `XDP_FLAGS_SKB_MODE` (generic XDP).

## What it balances, and what that is bad at

IPv4 TCP with a fixed 20-byte IP header only. Anything else is `XDP_PASS`.

A connection has to stay on one backend. Per-packet round robin splits the handshake: the SYN lands on one backend and the ACK on the other, and the second backend resets the flow. The program hashes the source address and source port onto the list of backends that are healthy right now.

Linux gives a fresh client even source ports first and then steps by two, so the low bit of the port does not change. The hash folds that port byte before the modulus. Without the fold, a short run of new connections all sticks to one backend.

There is no connection table. The hash is `flow % active_count`. That is bad at two things:

- One long flow stays on one backend. The balancer spreads connections, not bytes, so one heavy connection is never moved.
- Removing a backend changes the modulus. New connections skip the dead backend. Existing connections are not pinned, so a flow that was healthy can land on a different backend after the set shrinks, and a flow that was on the dead backend breaks.

The active list holds at most 16 backends.

## Dead backends

The loader opens a non-blocking TCP connection to each backend's own address, on the VIP port, every `--interval` seconds (default 1). It ejects a backend after `--fail` consecutive misses (default 3) and readmits it after `--success` consecutive successes (default 2).

The check loop sleeps for one interval, then probes. A backend that dies just after a successful probe is removed on the Nth miss, so the worst case is `interval * fail` seconds. With the defaults that is 3 seconds. The lab below uses `--interval 1 --fail 2`, so the bound is 2 seconds.

## Run the lab

The lab needs a privileged container. It builds two network namespaces, attaches the program, sends 20 requests, kills one backend, and checks that later requests move to the other one.

```bash
docker build -t xdp-lb .
docker run --privileged --rm xdp-lb
```

The image is Ubuntu 24.04 with clang, llvm, and libbpf. `make` in that image is the build. On a Linux host with those packages installed, `make` in this directory does the same thing. WSL here cannot `sudo apt`, which is why the lab runs in Docker.

Attach it yourself with:

```bash
./xdp_loader --iface IFACE --vip A.B.C.D --port PORT \
    --backend IP,MAC,EGRESS_IFACE [--backend ...]
```

## Measured

One lab run, 6 Nov 2026, generic XDP, two backends, 20 requests from the client namespace to `10.0.0.10:8080`:

| | |
| --- | --- |
| Responses | be0 11, be1 9, failures 0 |
| After be0 was killed | 11 responses that were not be1, then six in a row from be1 |
| Time from the kill to those six | 1999 ms |
| Configured eject bound | 1s interval, 2 misses, 2 seconds |

No packet-rate, p95, or nginx comparison was run. Those numbers are not filled in. Details and the packet counters from this run are in `BENCHMARKS.md`.

## Limits

- Direct server return. The backend must own the VIP, ignore ARP for it (`arp_ignore=1`, `arp_announce=2`), and have a route back to the client. This lab turns on `ip_forward` and turns off `rp_filter` so the reply can cross the veths. The balancer never NATs.
- The redirect is a destination-MAC rewrite out a specific interface. The backend has to be reachable at layer 2 from that interface.
- Health checks are userspace TCP connects to the backend's real address, not probes inside the XDP program. A backend that accepts TCP and then fails the request still looks healthy.
- Generic XDP in this lab, not a NIC driver. Forwarding cost is not what native XDP would do on a physical NIC.

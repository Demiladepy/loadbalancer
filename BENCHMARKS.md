# Benchmarks

Numbers below are from one run of `scripts/lab.sh` inside the `xdp-lb` image (`docker run --privileged --rm xdp-lb`) on 6 Nov 2026. The program was attached with `XDP_FLAGS_SKB_MODE` to `vc-b`. Two backends, VIP `10.0.0.10:8080`, health checks every 1s, eject after 2 misses, readmit after 1 success.

This is not a throughput or latency run. No `hey` or nginx comparison was done, and there is no p50/p95/p99.

## Spread

20 requests from the client namespace, one TCP connection each, before either backend was killed.

| backend | responses |
| --- | --- |
| be0 | 11 |
| be1 | 9 |
| failed | 0 |

Both backends answered. The split is not even on a sample this small. The hash spreads connections from one client by source port. It does not balance bytes, and it has no connection table, so shrinking the live set remaps flows.

## Ejection

be0's listener was killed. The loader logged `eject 10.0.1.2 after 2 failures`. Requests kept going to the VIP.

| | |
| --- | --- |
| Responses that were not be1 before recovery | 11 |
| Time from the kill until six consecutive be1 responses | 1999 ms |
| Configured worst case (`interval * fail`) | 2 s |

The 1999 ms includes those six requests, not only the map update. The 11 other responses are new connections that still hashed onto be0 before the second missed probe.

The stats line printed on that same eject was `packets 202 redirected 202 be0=83 be1=119`. Those are packet counters for the whole run up to that line (handshakes and health traffic included), not a packet rate.

## Not measured

Throughput, p95, and a comparison against nginx or any other proxy. Generic XDP on a veth pair is the wrong setup to quote as a NIC forwarding rate, so none is given.

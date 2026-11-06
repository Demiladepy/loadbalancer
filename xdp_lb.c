//go:build ignore
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct server_info);
    __uint(max_entries, MAX_BACKENDS);
} servers_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct vip_cfg);
    __uint(max_entries, 1);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_BACKENDS);
} backend_counts SEC(".maps");

/* Dense list of servers_map indexes that are currently healthy.
 * Indexing this with hash % active spreads flows across the live set.
 * Walking servers_map itself does not: empty slots above the live ones
 * all fall through to slot 0.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_BACKENDS);
} active_map SEC(".maps");

static __always_inline void count_packet(void *data, void *data_end, int redirected) {
    __u32 key = 0;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!rec)
        return;
    rec->rx_packets++;
    rec->rx_bytes += (data_end - data);
    if (redirected)
        rec->redirected++;
    else
        rec->passed++;
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    /* A variable IHL makes the TCP header offset unknown to the verifier. */
    if (iph->ihl != 5 || iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(iph + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 cfg_key = 0;
    struct vip_cfg *cfg = bpf_map_lookup_elem(&vip_map, &cfg_key);
    if (!cfg || cfg->vip == 0)
        return XDP_PASS;
    if (iph->daddr != cfg->vip)
        return XDP_PASS;
    if (cfg->port != 0 && bpf_ntohs(tcp->dest) != cfg->port)
        return XDP_PASS;

    /* One TCP connection must stay on one backend. A per-packet counter
     * splits the handshake and the other backend sends RST.
     *
     * tcp->source is network order. On this little-endian load the byte
     * that changes between consecutive client ports sits in bits 8..15.
     * Linux hands a fresh client even ports first and steps by 2, so bit 0
     * of that byte stays 0. Fold it or every new connection lands on one
     * backend when the live set has size 2.
     */
    __u32 raw_sport = tcp->source;
    __u32 b = (raw_sport >> 8) & 0xff;
    b ^= b >> 1;
    __u32 start = (b * 0x9E3779B1u) ^ ((raw_sport & 0xff) << 8) ^ iph->saddr;

    __u32 n = cfg->active;
    if (n == 0 || n > MAX_BACKENDS) {
        count_packet(data, data_end, 0);
        return XDP_PASS;
    }
    __u32 pick = start % n;
    if (pick >= MAX_BACKENDS)
        pick = 0;
    __u32 *backend = bpf_map_lookup_elem(&active_map, &pick);
    if (!backend || *backend >= MAX_BACKENDS) {
        count_packet(data, data_end, 0);
        return XDP_PASS;
    }
    __u32 key = *backend;
    struct server_info *srv = bpf_map_lookup_elem(&servers_map, &key);
    if (!srv || srv->ip == 0 || !srv->healthy || srv->ifindex == 0) {
        count_packet(data, data_end, 0);
        return XDP_PASS;
    }

    __builtin_memcpy(eth->h_dest, srv->mac, ETH_ALEN);
    __u64 *hits = bpf_map_lookup_elem(&backend_counts, &key);
    if (hits)
        *hits += 1;
    count_packet(data, data_end, 1);
    return bpf_redirect(srv->ifindex, 0);
}

char _license[] SEC("license") = "GPL";

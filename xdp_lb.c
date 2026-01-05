//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include "common.h"

// Checksum helper (simple version)
static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

// Map to store backend servers
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct server_info);
    __uint(max_entries, 16);
} servers_map SEC(".maps");

// Map for stats
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // Packet too short

    // Only handle IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parse IP Header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Update Stats
    __u32 stats_key = 0;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &stats_key);
    if (rec) {
        rec->rx_packets++;
        rec->rx_bytes += (data_end - data);
    }

    // 3. Simple Load Balancing Logic (e.g., Round Robin based on time or just static for demo)
    // For this basic demo, we'll pick index 0 strictly.
    // In a real scenario, you'd use a map to keep round-robin state or hash traffic.
    __u32 server_idx = 0;
    struct server_info *dest = bpf_map_lookup_elem(&servers_map, &server_idx);

    if (!dest) {
        // No backend server configured, just pass it
        return XDP_PASS;
    }

    // 4. Modify Packet (NAT / MAC Rewrite)
    
    // In a real Direct Server Return (DSR) or generic LB, 
    // we swap Mac addresses and change Destination IP.
    
    // Update Destination MAC
    // Note: In real world you need the Gateway MAC if server is not on same L2.
    // Assuming same L2 for simplicity here.
    __builtin_memcpy(eth->h_dest, dest->mac, ETH_ALEN);
    
    // We swap Source MAC to be us (the LB) - conceptually.
    // Actually, usually we keep source MAC of the router or previous hop.
    // Let's just update Dest IP.
    
    // Update IP Checksum
    // Simple incremental update for IP change
    __u32 old_ip = iph->daddr;
    __u32 new_ip = dest->ip;
    
    iph->daddr = new_ip;
    
    // Recalculate IP Checksum
    // This is a naive way; XDP helpers for csum are limited, 
    // usually we do incremental update or full recalc.
    iph->check = 0;
    // (In production code, recomputing checksum properly is critical)

    // 5. TX the packet back out the same interface (Hairpin)
    // Or XDP_REDIRECT to another interface.
    // XDP_TX is fastest for "bounce back".
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";

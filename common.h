#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

#define MAX_BACKENDS 16

/* One backend. ip == 0 means the slot is empty.
 * ifindex is the interface bpf_redirect sends the rewritten frame out of.
 * mac is the backend's own MAC. healthy == 0 takes the slot out of rotation.
 */
struct server_info {
    __u32 ip;
    __u32 ifindex;
    __u8 mac[6];
    __u8 healthy;
    __u8 pad;
};

/* vip and port identify which packets are balanced.
 * port is host byte order. port == 0 matches any TCP port.
 * active is how many healthy backends are packed into active_map.
 */
struct vip_cfg {
    __u32 vip;
    __u16 port;
    __u16 active;
};

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 passed;
    __u64 redirected;
};

#endif

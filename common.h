#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

// Definition of a backend server
struct server_info {
    __u32 ip;          // IPv4 address
    __u8 mac[6];       // MAC address
    __u8 pad[2];       // Padding for alignment
};

// Simple stats structure
struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

#endif

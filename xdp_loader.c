#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_link.h> /* XDP flags */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "common.h"

// If xdp_lb.skel.h was generated, we would use it. 
// For raw libbpf usage without skeleton:

static int verbose = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, map_servers_fd, map_stats_fd;
    int ifindex = -1;
    char *ifname = NULL;
    int err;

    // Parse Args
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    // load BPF object
    obj = bpf_object__open_file("xdp_lb.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // load BPF program
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // find the program
    prog = bpf_object__find_program_by_name(obj, "xdp_load_balancer");
    if (!prog) {
        fprintf(stderr, "ERROR: finding BPF program failed\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    // find maps
    map_servers_fd = bpf_object__find_map_fd_by_name(obj, "servers_map");
    map_stats_fd = bpf_object__find_map_fd_by_name(obj, "xdp_stats_map");
    if (map_servers_fd < 0 || map_stats_fd < 0) {
        fprintf(stderr, "ERROR: finding maps failed\n");
        return 1;
    }

    // update map with a dummy backend (e.g., 192.168.1.100)
    struct server_info srv = {};
    srv.ip = inet_addr("192.168.1.100");
    // MAC: 02:00:00:00:00:02 (Dummy)
    srv.mac[0] = 0x02; srv.mac[1] = 0x00; srv.mac[2] = 0x00;
    srv.mac[3] = 0x00; srv.mac[4] = 0x00; srv.mac[5] = 0x02;

    int key = 0;
    err = bpf_map_update_elem(map_servers_fd, &key, &srv, BPF_ANY);
    if (err) {
        fprintf(stderr, "ERROR: updating server map failed\n");
        return 1;
    }
    printf("Configured backend server 192.168.1.100\n");

    // Attach XDP
    // In modern kernels, we use bpf_xdp_attach, but standard link setup is:
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "ERROR: attaching XDP program to %s failed\n", ifname);
        return 1;
    }

    printf("Successfully attached XDP program to %s\n", ifname);
    printf("Press Ctrl+C to stop...\n");

    // Stats Loop
    while (1) {
        sleep(2);
        
        // Read per-cpu array
        // We need to alloc for num_cpus
        int num_cpus = libbpf_num_possible_cpus();
        struct datarec *values = calloc(num_cpus, sizeof(struct datarec));
        
        __u32 stats_key = 0;
        if (bpf_map_lookup_elem(map_stats_fd, &stats_key, values) == 0) {
            __u64 total_pkts = 0;
            __u64 total_bytes = 0;
            for (int i = 0; i < num_cpus; i++) {
                total_pkts += values[i].rx_packets;
                total_bytes += values[i].rx_bytes;
            }
            printf("\rBytes: %llu | Packets: %llu   ", total_bytes, total_pkts);
            fflush(stdout);
        }
        free(values);
    }

    // Cleanup happens on exit usually, but detaching is polite
    bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    return 0;
}

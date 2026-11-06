#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "common.h"

static volatile sig_atomic_t stop;

static void on_signal(int sig) {
    (void)sig;
    stop = 1;
}

static int parse_mac(const char *text, __u8 mac[6]) {
    unsigned int b[6];
    if (sscanf(text, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xff)
            return -1;
        mac[i] = (__u8)b[i];
    }
    return 0;
}

static int tcp_probe(__u32 ip_be, __u16 port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return 0;

    struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = ip_be,
    };
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        close(fd);
        return 1;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return 0;
    }

    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    rc = poll(&pfd, 1, 200);
    int ok = 0;
    if (rc > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0)
            ok = 1;
    }
    close(fd);
    return ok;
}

/* Pack healthy backend indexes into active_map[0..count), then publish
 * the count. The data plane hashes onto this dense list. Writing the
 * list before the count means a reader never indexes a stale slot with
 * a larger count than the list that was just written.
 */
static int publish_active(int active_fd, int vip_fd, struct vip_cfg *vip,
                          const int *healthy, int nbackends) {
    __u32 slot = 0;
    for (int i = 0; i < nbackends; i++) {
        if (!healthy[i])
            continue;
        __u32 backend = (__u32)i;
        if (bpf_map_update_elem(active_fd, &slot, &backend, BPF_ANY) != 0)
            return -1;
        slot++;
    }
    __u32 none = MAX_BACKENDS;
    for (__u32 key = slot; key < MAX_BACKENDS; key++) {
        if (bpf_map_update_elem(active_fd, &key, &none, BPF_ANY) != 0)
            return -1;
    }
    vip->active = (__u16)slot;
    __u32 zero = 0;
    return bpf_map_update_elem(vip_fd, &zero, vip, BPF_ANY);
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s --iface IFACE --vip A.B.C.D --port PORT \\\n"
            "          [--interval SEC] [--fail N] [--success M] \\\n"
            "          --backend IP,MAC,EGRESS_IFACE [--backend ...]\n"
            "\n"
            "Direct server return. The program does not rewrite IP addresses.\n"
            "Each backend must own the VIP on loopback. A backend is removed\n"
            "after N failed TCP probes and returned after M successes.\n"
            "Worst case from death to ejection is interval * N seconds.\n",
            argv0);
}

int main(int argc, char **argv) {
    const char *iface = NULL;
    const char *vip_text = NULL;
    int vip_port = 0;
    int interval = 1;
    int fail_limit = 3;
    int success_limit = 2;
    struct server_info backends[MAX_BACKENDS] = {};
    int nbackends = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "--vip") == 0 && i + 1 < argc) {
            vip_text = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            vip_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            interval = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--fail") == 0 && i + 1 < argc) {
            fail_limit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--success") == 0 && i + 1 < argc) {
            success_limit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            if (nbackends >= MAX_BACKENDS) {
                fprintf(stderr, "at most %d backends\n", MAX_BACKENDS);
                return 1;
            }
            char *spec = argv[++i];
            char *comma1 = strchr(spec, ',');
            char *comma2 = comma1 ? strchr(comma1 + 1, ',') : NULL;
            if (!comma1 || !comma2) {
                fprintf(stderr, "backend must be IP,MAC,EGRESS_IFACE\n");
                return 1;
            }
            *comma1 = 0;
            *comma2 = 0;
            struct server_info *srv = &backends[nbackends];
            if (inet_pton(AF_INET, spec, &srv->ip) != 1 || parse_mac(comma1 + 1, srv->mac) != 0) {
                fprintf(stderr, "bad backend address or MAC\n");
                return 1;
            }
            srv->ifindex = if_nametoindex(comma2 + 1);
            if (!srv->ifindex) {
                fprintf(stderr, "unknown egress interface %s\n", comma2 + 1);
                return 1;
            }
            srv->healthy = 1;
            nbackends++;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!iface || !vip_text || vip_port <= 0 || vip_port > 65535 || nbackends == 0 ||
        interval <= 0 || fail_limit <= 0 || success_limit <= 0) {
        usage(argv[0]);
        return 1;
    }

    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "unknown ingress interface %s\n", iface);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file("xdp_lb.o", NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "opening xdp_lb.o failed\n");
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "loading xdp_lb.o failed\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_load_balancer");
    if (!prog) {
        fprintf(stderr, "program xdp_load_balancer not found\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);
    int servers_fd = bpf_object__find_map_fd_by_name(obj, "servers_map");
    int vip_fd = bpf_object__find_map_fd_by_name(obj, "vip_map");
    int stats_fd = bpf_object__find_map_fd_by_name(obj, "xdp_stats_map");
    int counts_fd = bpf_object__find_map_fd_by_name(obj, "backend_counts");
    int active_fd = bpf_object__find_map_fd_by_name(obj, "active_map");
    if (servers_fd < 0 || vip_fd < 0 || stats_fd < 0 || counts_fd < 0 || active_fd < 0) {
        fprintf(stderr, "finding maps failed\n");
        return 1;
    }

    struct server_info empty = {};
    for (__u32 key = 0; key < MAX_BACKENDS; key++) {
        if (bpf_map_update_elem(servers_fd, &key, &empty, BPF_ANY) != 0) {
            fprintf(stderr, "clearing backend slot failed\n");
            return 1;
        }
    }
    for (int i = 0; i < nbackends; i++) {
        __u32 key = (__u32)i;
        if (bpf_map_update_elem(servers_fd, &key, &backends[i], BPF_ANY) != 0) {
            fprintf(stderr, "installing backend %d failed\n", i);
            return 1;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &backends[i].ip, ip, sizeof(ip));
        printf("backend %d %s via ifindex %u\n", i, ip, backends[i].ifindex);
    }

    struct vip_cfg vip = {};
    if (inet_pton(AF_INET, vip_text, &vip.vip) != 1) {
        fprintf(stderr, "bad VIP\n");
        return 1;
    }
    vip.port = (__u16)vip_port;
    __u32 zero = 0;
    int healthy[MAX_BACKENDS];
    for (int i = 0; i < nbackends; i++)
        healthy[i] = 1;
    if (publish_active(active_fd, vip_fd, &vip, healthy, nbackends) != 0) {
        fprintf(stderr, "installing VIP failed\n");
        return 1;
    }

    __u32 flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (bpf_xdp_attach(ifindex, prog_fd, flags, NULL) != 0) {
        fprintf(stderr, "attaching XDP to %s failed: %s\n", iface, strerror(errno));
        return 1;
    }
    printf("attached to %s, VIP %s:%d, eject after %d misses, readmit after %d hits, every %ds\n",
           iface, vip_text, vip_port, fail_limit, success_limit, interval);
    printf("worst case death to ejection: %d seconds\n", interval * fail_limit);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int fails[MAX_BACKENDS] = {};
    int oks[MAX_BACKENDS] = {};

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1)
        ncpus = 1;

    while (!stop) {
        sleep(interval);
        if (stop)
            break;

        int changed = 0;
        for (int i = 0; i < nbackends; i++) {
            int up = tcp_probe(backends[i].ip, (__u16)vip_port);
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &backends[i].ip, ip, sizeof(ip));
            if (up) {
                fails[i] = 0;
                oks[i]++;
                if (!healthy[i] && oks[i] >= success_limit) {
                    healthy[i] = 1;
                    backends[i].healthy = 1;
                    changed = 1;
                    printf("readmit %s after %d successes\n", ip, oks[i]);
                }
            } else {
                oks[i] = 0;
                fails[i]++;
                if (healthy[i] && fails[i] >= fail_limit) {
                    healthy[i] = 0;
                    backends[i].healthy = 0;
                    changed = 1;
                    printf("eject %s after %d failures\n", ip, fails[i]);
                }
            }
        }
        if (changed) {
            /* Take it out of the hash set before clearing the healthy bit,
             * so a flow is not pointed at a backend the program will refuse.
             */
            if (publish_active(active_fd, vip_fd, &vip, healthy, nbackends) != 0)
                fprintf(stderr, "updating the active set failed\n");
            for (int i = 0; i < nbackends; i++) {
                __u32 key = (__u32)i;
                bpf_map_update_elem(servers_fd, &key, &backends[i], BPF_ANY);
            }
        }

        struct datarec *values = calloc((size_t)ncpus, sizeof(*values));
        __u64 packets = 0, redirected = 0;
        if (values && bpf_map_lookup_elem(stats_fd, &zero, values) == 0) {
            for (int cpu = 0; cpu < ncpus; cpu++) {
                packets += values[cpu].rx_packets;
                redirected += values[cpu].redirected;
            }
        }
        free(values);
        printf("packets %llu redirected %llu",
               (unsigned long long)packets, (unsigned long long)redirected);
        for (int i = 0; i < nbackends; i++) {
            __u32 key = (__u32)i;
            __u64 *percpu = calloc((size_t)ncpus, sizeof(*percpu));
            __u64 total = 0;
            if (percpu && bpf_map_lookup_elem(counts_fd, &key, percpu) == 0) {
                for (int cpu = 0; cpu < ncpus; cpu++)
                    total += percpu[cpu];
            }
            free(percpu);
            printf(" be%d=%llu", i, (unsigned long long)total);
        }
        printf("\n");
        fflush(stdout);
    }

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    printf("\ndetached from %s\n", iface);
    return 0;
}

// eBPF XDP program to drop TCP packets on a configurable port
// Port is stored in a BPF Array Map, configurable from userspace
// without recompiling this program.
//
// Attach type: XDP (eXpress Data Path)
// Hook point:  Network driver — earliest possible intercept point

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// BPF Array Map — shared between kernel and userspace
// Key: 0 (single entry), Value: port number to drop
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} port_map SEC(".maps");

SEC("xdp")
int drop_tcp_port(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header — bounds check required by eBPF verifier
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // Only process TCP packets
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // Read configured port from BPF map (set by userspace loader)
    __u32 key = 0;
    __u16 *port = bpf_map_lookup_elem(&port_map, &key);
    if (!port) return XDP_PASS;

    // Drop packet if destination port matches configured port
    if (tcp->dest == bpf_htons(*port)) {
        bpf_printk("Dropping TCP packet on port %d\n", *port);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

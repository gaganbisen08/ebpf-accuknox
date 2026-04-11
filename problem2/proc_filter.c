// eBPF cgroup egress program to filter traffic for a specific process
// Attached to root cgroup — allows only configured port, drops everything else
//
// Attach type: cgroup_skb/egress
// Hook point:  cgroup egress — intercepts all outgoing packets

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// BPF Map — stores the one allowed port
// Configurable from userspace without recompiling
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} allowed_port_map SEC(".maps");

// Attached to cgroup — all traffic from processes
// in this cgroup passes through here
SEC("cgroup_skb/egress")
int filter_process_traffic(struct __sk_buff *skb) {

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse IP header
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end) return 1;

    // Only filter TCP traffic — allow UDP/ICMP etc
    if (ip->protocol != IPPROTO_TCP) return 1;

    // Parse TCP header
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return 1;

    // Read allowed port from BPF map (set by userspace)
    __u32 key = 0;
    __u16 *allowed = bpf_map_lookup_elem(&allowed_port_map, &key);
    if (!allowed) return 0;

    // If map not set yet — allow all
    if (*allowed == 0) return 1;

    __u16 dst_port = bpf_ntohs(tcp->dest);

    // Allow only configured port
    if (tcp->dest == bpf_htons(*allowed)) {
        bpf_printk("ALLOW: port %d\n", dst_port);
        return 1; // ALLOW
    }

    bpf_printk("DROP: port %d\n", dst_port);
    return 0; // DROP
}

char _license[] SEC("license") = "GPL";

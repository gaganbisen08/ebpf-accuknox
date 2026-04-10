// Userspace loader for drop_port eBPF program
// Loads the compiled eBPF object, attaches it to a network
// interface via XDP, and sets the target port via BPF map.
//
// Usage: sudo ./loader [port] [interface]
// Default: port=4040, interface=lo

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv) {
    const char *iface = "lo";
    __u16 port = 4040;

    if (argc >= 2) port = (__u16)atoi(argv[1]);
    if (argc >= 3) iface = argv[2];

    // Get network interface index
    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Interface %s not found\n", iface);
        return 1;
    }

    // Open compiled eBPF object file
    struct bpf_object *obj = bpf_object__open_file("drop_port.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // Load eBPF program into kernel (runs verifier)
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        return 1;
    }

    // Find the XDP program by name
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "drop_tcp_port");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);

    // Attach XDP program to network interface
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "XDP attach failed: %s\n", strerror(errno));
        return 1;
    }

    // Update BPF map with target port (userspace → kernel communication)
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "port_map");
    if (!map) {
        fprintf(stderr, "Map not found\n");
        return 1;
    }

    int map_fd = bpf_map__fd(map);
    __u32 key = 0;
    bpf_map_update_elem(map_fd, &key, &port, BPF_ANY);

    printf("Dropping TCP on port %d on interface '%s'\n", port, iface);
    printf("Press Ctrl+C to stop...\n");
    pause(); // wait until Ctrl+C

    // Detach XDP program on exit
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    printf("Detached.\n");
    return 0;
}

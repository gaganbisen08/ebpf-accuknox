// Userspace loader for proc_filter eBPF program
// Loads eBPF object, writes allowed port to BPF map,
// attaches program to root cgroup for process filtering.
//
// Usage: sudo ./proc_loader [allowed_port]
// Default: port=4040

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv) {
    __u16 port = 4040;
    if (argc >= 2) port = (__u16)atoi(argv[1]);

    const char *cgroup_path = "/sys/fs/cgroup";
    const char *bpf_obj     = "proc_filter.bpf.o";

    printf("==================================\n");
    printf(" eBPF Per-Process Traffic Filter \n");
    printf("==================================\n");
    printf(" Allowed port : %d\n", port);
    printf(" All others   : DROPPED\n");
    printf("==================================\n");

    // Step 1: Open and load eBPF object
    // Maps are created at this point — important!
    printf("[+] Loading eBPF object...\n");
    struct bpf_object *obj = bpf_object__open_file(bpf_obj, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: Cannot open %s\n", bpf_obj);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: Cannot load BPF object: %s\n", strerror(errno));
        return 1;
    }
    printf("[+] eBPF loaded\n");

    // Step 2: Write port to map IMMEDIATELY after load
    // Must use the SAME map fd the program uses
    struct bpf_map *port_map = bpf_object__find_map_by_name(obj, "allowed_port_map");
    if (!port_map) {
        fprintf(stderr, "ERROR: allowed_port_map not found\n");
        return 1;
    }

    int map_fd = bpf_map__fd(port_map);
    __u32 key = 0;

    if (bpf_map_update_elem(map_fd, &key, &port, BPF_ANY) < 0) {
        fprintf(stderr, "ERROR: Map update failed: %s\n", strerror(errno));
        return 1;
    }

    // Verify port was written correctly
    __u16 verify = 0;
    bpf_map_lookup_elem(map_fd, &key, &verify);
    printf("[+] Port written: %d, verified: %d\n", port, verify);

    if (verify != port) {
        fprintf(stderr, "ERROR: Port verification failed!\n");
        return 1;
    }

    // Step 3: Get program file descriptor
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "filter_process_traffic");
    if (!prog) {
        fprintf(stderr, "ERROR: Program 'filter_process_traffic' not found\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    // Step 4: Open root cgroup
    printf("[+] Opening cgroup...\n");
    int cgroup_fd = open(cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "ERROR: Cannot open cgroup %s: %s\n",
                cgroup_path, strerror(errno));
        return 1;
    }

    // Step 5: Attach eBPF program to cgroup egress
    printf("[+] Attaching to cgroup...\n");
    if (bpf_prog_attach(prog_fd, cgroup_fd,
                        BPF_CGROUP_INET_EGRESS,
                        BPF_F_ALLOW_MULTI) < 0) {
        fprintf(stderr, "ERROR: Attach failed: %s\n", strerror(errno));
        close(cgroup_fd);
        return 1;
    }

    printf("[+] Attached!\n");
    printf("\n==================================\n");
    printf(" Filter ACTIVE!\n");
    printf(" Port %d         -> ALLOWED\n", port);
    printf(" All other ports -> DROPPED\n");
    printf("\n");
    printf(" Watch logs:\n");
    printf(" sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("\n Press Ctrl+C to stop\n");
    printf("==================================\n");

    // Wait for Ctrl+C
    pause();

    // Cleanup — detach program on exit
    printf("\n[+] Detaching...\n");
    bpf_prog_detach2(prog_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
    close(cgroup_fd);
    bpf_object__close(obj);
    printf("[+] Done!\n");
    return 0;
}

// loader.c
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>

// Function to load and attach the XDP program
int load_xdp_program(const char *ifname, const char *filename) {
    struct bpf_object *obj;
    int prog_fd, ifindex, err;

    // Open the eBPF object file
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));
        return -1;
    }

    // Load the eBPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %d\n", err);
        bpf_object__close(obj);
        return -1;
    }

    // Find the XDP program within the object
    struct bpf_program *prog = bpf_object__find_program_by_title(obj, "xdp_pass");
    if (!prog) {
        fprintf(stderr, "Error finding XDP program in object\n");
        bpf_object__close(obj);
        return -1;
    }

    // Get the file descriptor for the program
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error getting program fd\n");
        bpf_object__close(obj);
        return -1;
    }

    // Get the interface index
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error getting index of interface %s\n", ifname);
        bpf_object__close(obj);
        return -1;
    }

    // Attach the XDP program to the interface
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (err < 0) {
        fprintf(stderr, "Error attaching XDP program to interface: %s\n", strerror(errno));
        bpf_object__close(obj);
        return -1;
    }

    printf("XDP program loaded and attached to interface %s\n", ifname);
    bpf_object__close(obj);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ifname> <xdp_prog.o>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    const char *filename = argv[2];

    if (load_xdp_program(ifname, filename) != 0) {
        fprintf(stderr, "Failed to load XDP program\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


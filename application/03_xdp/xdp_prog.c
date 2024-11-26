// xdp_prog.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// XDP program that passes all packets
SEC("xdp_pass")
int xdp_pass_all(struct xdp_md *ctx) {
    bpf_printk("xdp_pass_all\n");
    return XDP_PASS;
}

// Specify license for the eBPF program
char LICENSE[] SEC("license") = "GPL";


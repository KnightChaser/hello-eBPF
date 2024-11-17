// tail_call_three.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Define the map for tail call programs
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3); // Allow three programs in this array
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

// First program: entry point
SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("First program: Entered handle_openat()\n");

    // Tail call to the second program
    bpf_tail_call(ctx, &prog_array, 1); // Call program at index 1

    bpf_printk("Tail call failed in handle_openat\n");
    return 0;
}

// Second program
SEC("tp/syscalls/sys_enter_openat")
int handle_openat_second(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("Second program: Entered handle_openat_second()\n");

    // Tail call to the third program
    bpf_tail_call(ctx, &prog_array, 2); // Call program at index 2

    bpf_printk("Tail call failed in handle_openat_second\n");
    return 0;
}

// Third program
SEC("tp/syscalls/sys_enter_openat")
int handle_openat_third(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("Third program: Entered handle_openat_third()\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";


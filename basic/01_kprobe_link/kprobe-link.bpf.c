// To regenerate vmlinux.h, run: (Considering Ubuntu 22.04 LTS)
// sudo apt update
// sudo apt install linux-headers-$(uname -r) clang llvm libbpf-dev gcc-multilib make
// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlikat, int dfd, struct filename *name) {
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s", pid, filename);

    return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret) {
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);

    return 0;
}

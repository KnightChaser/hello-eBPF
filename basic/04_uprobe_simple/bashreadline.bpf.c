#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

char LICENSE[] SEC("license") = "GPL";

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret) {
    char str[MAX_LINE_SIZE];
    char comm[TASK_COMM_LEN];
    u32 pid, uid;

    if (!ret)
        return 0;

    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid() >> 32;
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;  // Extract UID

    bpf_probe_read_user_str(str, sizeof(str), ret);

    // Split the message across two print calls to avoid argument limits
    // Geenrally, bpf_printk() receives up to 3 arguments at once :(
    bpf_printk("UID %d, PID %d (%s)", uid, pid, comm);
    bpf_printk("Command: %s", str);

    return 0;
}


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 256 

SEC("tracepoint/syscalls/sys_enter_chdir")
int tracepoint__syscalls__sys_enter_chdir(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    const char *filename = (const char *)ctx->args[0];
    char path[MAX_FILENAME_LEN];

    if (bpf_probe_read_user_str(&path, sizeof(path), filename) < 0) {
        bpf_printk("chdir: Failed to read filename for PID %d by the user whose UID is %d\n", pid, uid);
        return 0;
    }

    bpf_printk("PID %d(UID: %d) called chdir with filename: %s\n", pid, uid, path);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int tracepoint__syscalls__sys_exit_chdir(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    long ret = ctx->ret;
    bpf_printk("PID %d chdir returned with %ld\n", pid, ret);
    
    return 0;
}


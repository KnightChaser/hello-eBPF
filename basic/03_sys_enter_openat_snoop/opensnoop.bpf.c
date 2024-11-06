#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const volatile int pid_target = 0;      // Process ID to trace

#define MAX_FILENAME_LEN 256            // Arbitrarily expected length

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // If pid_target is set, filter by PID
    if (pid_target && pid_target != pid)
        return 0;

    // The second argument of sys_enter_openat is the pathname
    const char *pathname = (const char *)ctx->args[1];
    char filename[MAX_FILENAME_LEN];

    // Safely read the pathname from user space
    if (bpf_probe_read_user_str(&filename, sizeof(filename), pathname) < 0) {
        // If reading fails, you might choose to log or handle it differently
        return 0;
    }

    bpf_printk("PID %d opened file: %s\n", pid, filename);
    return 0;
}


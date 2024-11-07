#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 256

char LICENSE[] SEC("license") = "GPL";

struct ProcessData {
    __u64 startTime;
    __u64 endTime;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ProcessData);
} ProcessTimes SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_process_start(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ProcessData data = {};

    data.startTime = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Store the start time and command name to the hashmap
    bpf_map_update_elem(&ProcessTimes, &pid, &data, BPF_ANY);

    bpf_printk("Process start: PID %d, Comm: %s\n", pid, data.comm);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_process_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ProcessData *processData = bpf_map_lookup_elem(&ProcessTimes, &pid);
    if (!processData)
        return 0;

    // Record the end time and calculate the runtime
    processData->endTime = bpf_ktime_get_ns();
    __u64 runtimeInNanoSecond = processData->endTime - processData->startTime;
    int processReturnValue = ctx->ret;
    bpf_printk("PID %d (%s) ran for %llu nsec, returning %d\n", pid, processData->comm, runtimeInNanoSecond, processReturnValue);

    // Clean up the map entry
    bpf_map_delete_elem(&ProcessTimes, &pid);
    
    return 0;
}


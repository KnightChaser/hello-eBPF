#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAXIMUM_COMMAND_LINE_LENGTH 128
#define MAXIMUM_FILENAME_LENGTH 128
#define MAXIMUM_ARGV_COUNT 6
#define MAXIMUM_ARGV_LENGTH 32

struct ProcessData {
    __u64 startTime;
    __u64 endTime;
    char comm[MAXIMUM_COMMAND_LINE_LENGTH];
    char filename[MAXIMUM_FILENAME_LENGTH];
    char argv[MAXIMUM_ARGV_COUNT][MAXIMUM_ARGV_LENGTH];
    long ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ProcessData);
} ProcessTimes SEC(".maps");

// Helper function to safely copy strings from user space
static __always_inline int safe_strncpy(const char *srcBuffer, char *dstBuffer, int bufferSize) {
    int result = bpf_probe_read_user_str(dstBuffer, bufferSize, srcBuffer);
    if (result < 0)
        dstBuffer[0] = '\0';
    return result;
}

// A new process is working
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_process_start(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ProcessData data = {};

    data.startTime = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Get the filename
    const char *filename_ptr;
    filename_ptr = (const char *)ctx->args[0];
    safe_strncpy(filename_ptr, data.filename, sizeof(data.filename));

    // Get the argv
    const char **argvPointer;
    argvPointer = (const char **)ctx->args[1];

    #pragma unroll
    for (int index = 0; index < MAXIMUM_ARGV_COUNT; index++) {
        const char *argPointer = NULL;
        bpf_probe_read_user(&argPointer, sizeof(argPointer), &argvPointer[index]);
        if (argPointer == NULL)
            break;
        safe_strncpy(argPointer, data.argv[index], MAXIMUM_ARGV_LENGTH);
    }

    // Store the start time, command name, and filenames to the hashmap
    bpf_map_update_elem(&ProcessTimes, &pid, &data, BPF_ANY);

    return 0;
}

// A process has finished(terminated)
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_process_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ProcessData *processData = bpf_map_lookup_elem(&ProcessTimes, &pid);
    if (!processData)
        return 0;

    // Record the end time and calculate the runtime
    processData->endTime = bpf_ktime_get_ns();
    processData->ret = ctx->ret;
    __u64 runtimeInNanoSeconds = processData->endTime - processData->startTime;

    bpf_printk("PID %d (%s) executed '%s' and ran for %llu nsec.\n",
               pid, processData->comm, processData->filename, runtimeInNanoSeconds);

    // Also print the arguments
    for (int index = 0; index < MAXIMUM_ARGV_COUNT; index++) {
        if (processData->argv[index][0] == '\0')
            break;
        bpf_printk("  argv[%d] = '%s'\n", index, processData->argv[index]);
    }

    bpf_map_delete_elem(&ProcessTimes, &pid);

    return 0;
}


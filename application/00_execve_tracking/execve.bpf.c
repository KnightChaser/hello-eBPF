// execve.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Maximum number of arguments to capture
#define MAX_ARGS 10
#define MAX_ARG_LEN 256

// Define the structure of the event to be sent to user space
struct event {
    u32 uid;
    u32 pid;
    char comm[16];
    char filename[256];
    u32 argc;
    char args[MAX_ARGS][MAX_ARG_LEN];
};

// Declare a ring buffer map named "events"
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

// A helper function to read a single argument from the user space
static __always_inline int read_user_string(char *dst, int dst_size, unsigned long addr) {
    return bpf_probe_read_user_str(dst, dst_size, (const char *)addr);
}

// Tracepoint for sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const char *filename;
    const char *const *argv;

    // Allocate space in the ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    // Initialize argc
    e->argc = 0;

    // Get current PID and UID
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() >> 32;

    // Get the command name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Extract the filename argument from execve (first argument)
    filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    // Extract the argv array (second argument)
    argv = (const char *const *)ctx->args[1];

    // Iterate over the argv array and capture arguments
    for (u32 index = 0; index < MAX_ARGS; index++) {
        const char *arg;

        // Read the pointer to the argument string from argv[index]
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[index]) != 0)
            break;

        // If the argument is NULL, we've reached the end
        if (arg == NULL)
            break;

        // Read the argument string
        if (read_user_string(e->args[index], sizeof(e->args[index]), (unsigned long)arg) < 0)
            break;

        e->argc++;
    }

    // Submit the event to user space
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";


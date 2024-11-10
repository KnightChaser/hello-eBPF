// chdir.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 256 

const volatile int pid_target = 0;

// Structure for storing chdir result information
struct chdir_event {
    u32 pid;
    u32 uid;
    char filename[MAX_FILENAME_LEN];
    bool success;
};

// Define a ring buffer to send chdir events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} chdir_events SEC(".maps");

// Define the hash map for pairing sys_enter_chdir and sys_exit_chdir
struct chdir_info {
    u32 uid;
    char filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct chdir_info);
    __uint(max_entries, 1024);
} chdir_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_chdir")
int tracepoint__syscalls__sys_enter_chdir(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    const char *filename = (const char *)ctx->args[0];
    struct chdir_info info = {};
    info.uid = uid;

    if (bpf_probe_read_user_str(info.filename, sizeof(info.filename), filename) < 0) {
        return 0;
    }

    bpf_map_update_elem(&chdir_map, &pid, &info, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int tracepoint__syscalls__sys_exit_chdir(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct chdir_info *info = bpf_map_lookup_elem(&chdir_map, &pid);
    if (!info)
        return 0;

    long ret = ctx->ret;

    // Prepare the chdir_event structure for the ring buffer
    struct chdir_event *chdir_event = bpf_ringbuf_reserve(&chdir_events, sizeof(struct chdir_event), 0);
    if (!chdir_event)
        return 0;

    chdir_event->pid = pid;
    chdir_event->uid = info->uid;
    __builtin_memcpy(chdir_event->filename, info->filename, sizeof(chdir_event->filename));
    chdir_event->success = (ret == 0);

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(chdir_event, 0);

    // Remove the entry from the map since we don't need it anymore
    bpf_map_delete_elem(&chdir_map, &pid);
    
    return 0;
}


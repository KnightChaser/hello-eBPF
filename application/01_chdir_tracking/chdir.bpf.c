#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 256 

const volatile int pid_target = 0;

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
        bpf_printk("Failed to read filename from PID: %d/UID: %d\n", pid, uid);
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

    if (ret == 0)
        bpf_printk("PID %d (UID: %d) successfully changed the working directory to %s\n", pid, uid, info->filename);
    else
        bpf_printk("PID %d (UID: %d) failed to change the working directory to %s\n", pid, uid, info->filename);

    // Remove the entry from the map since we don't need it anymore
    bpf_map_delete_elem(&chdir_map, &pid);
    
    return 0;
}


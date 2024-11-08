// hello.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct event {
    u32 pid;        // A Process ID of a process who invoked the command
    char msg[12];   // A custom message
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_event(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_strncpy(e->msg, "Hello, World!", sizeof(e->msg));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";


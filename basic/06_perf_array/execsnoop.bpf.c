#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} exec_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter* context) {
    // pid for process ID and tgid for thread group ID
    u64 pid_tgid;
    pid_t process_id, thread_group_id;
    struct exec_event exec_event_data = {0};
    struct task_struct *task_struct_pointer;    // Represents the current pointer

    uid_t user_id = (u32)bpf_get_current_uid_gid();
    pid_tgid = bpf_get_current_pid_tgid();
    thread_group_id = pid_tgid >> 32;

    exec_event_data.process_id = thread_group_id;
    exec_event_data.user_id = user_id;
    task_struct_pointer = (struct task_struct*)bpf_get_current_task();
    // Reads the parent’s TGID by accessing the real_parent field of task_struct. (task_struct_pointer->real_parent->tgid)
    exec_event_data.parent_process_id = BPF_CORE_READ(task_struct_pointer, real_parent, tgid);

    // Read the first argument of execve() (the command name) using tracepoint's context (context->args[0])
    char *command_pointer = (char *)BPF_CORE_READ(context, args[0]);
    bpf_probe_read_str(&exec_event_data.command, sizeof(exec_event_data.command), command_pointer);

    // This helper function sends the exec_event_data to the exec_events map for retrieval by user space.
    // - context: The context pointer
    // - &exec_events: The map file descriptor (reference to the eBPF map)
    // - BPF_F_CURRENT_CPU: Ensurs the data is written to the CPU-local buffer
    // - &exec_event_data: The data being sent
    // - sizeof(exec_event_data): The size of the data being sent
    bpf_perf_event_output(context, &exec_events, BPF_F_CURRENT_CPU, &exec_event_data, sizeof(exec_event_data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";


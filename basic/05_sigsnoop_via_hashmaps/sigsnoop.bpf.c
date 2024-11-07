#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240       // Maximum number of entries for BPF programs
#define TASK_COMM_LENGTH 16     // Length of the task command name

struct Event {
    unsigned int pid;               // PID of the process sending the signal
    unsigned int targetPid;         // PID of the process receiving the signal
    int signal;                     // Signal number sent
    int returnValue;                // Return value of the invoked syscall (kill in this case) 
    char comm[TASK_COMM_LENGTH];    // Command name of the sending proces
};

// The map structure to store the event data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);        // Hash map type
    __uint(max_entries, MAX_ENTRIES);       // Max entries allowed in the map
    __type(key, __u32);                     // key type: threadId
    __type(value, struct Event);            // value type: signal (Event struct)
} eventMap SEC(".maps");

/**
 * @brief Handles the entry of the kill syscall.
 *
 * @param targetPid The PID to which the signal is sent.
 * @param signal The signal number sent.
 * @return int Returns 0 on success.
 */
static int handleKillEntry(pid_t targetPid, int signal) {
    struct Event event = {};
    __u64 pidTgid;
    __u32 threadId;

    pidTgid = bpf_get_current_pid_tgid();
    threadId = (__u32)pidTgid;
    event.pid = pidTgid >> 32;
    event.targetPid = targetPid;
    event.signal = signal;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Update the map with the event data
    bpf_map_update_elem(&eventMap, &threadId, &event, BPF_ANY);

    return 0;
}

/**
 * @brief Handles the exit of the kill syscall.
 *
 * @param context The context of the syscall exit.
 * @param returnValue The return value of the kill syscall.
 * @return int Returns 0 on success.
 */
static int handleKillExit(void *context, int returnValue) {
    __u64 pidTgid = bpf_get_current_pid_tgid();
    __u32 threadId = (__u32)pidTgid;
    struct Event *eventPointer;

    // Lookup the event in the map
    eventPointer = bpf_map_lookup_elem(&eventMap, &threadId);
    if (!eventPointer)
        return 0;

    // Update the return value
    eventPointer->returnValue = returnValue;

    // Print debug information
    bpf_printk("PID %d (%s) sent signal %d ", eventPointer->pid, eventPointer->comm, eventPointer->signal);
    bpf_printk("to PID %d, return = %d", eventPointer->targetPid, eventPointer->returnValue);

    // Cleanup the map entry
    bpf_map_delete_elem(&eventMap, &threadId);
    return 0;
}

// Attach to the entry point of the kill syscall
SEC("tracepoint/syscalls/sys_enter_kill")
int tracepointSysEnterKill(struct trace_event_raw_sys_enter *context) {
    pid_t targetPid = (pid_t)context->args[0];
    int signal = (int)context->args[1];

    return handleKillEntry(targetPid, signal);
}

// Attach to the exit point of the kill syscall
SEC("tracepoint/syscalls/sys_exit_kill")
int tracepointSysExitKill(struct trace_event_raw_sys_exit *context) {
    return handleKillExit(context, context->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";


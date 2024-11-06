#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const volatile int pid_target = 0; // Process ID to trace

// root@blustrada:~# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
// name: sys_enter_openat
// ID: 706
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;
// 
// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:int dfd;	offset:16;	size:8;	signed:0;
// 	field:const char * filename;	offset:24;	size:8;	signed:0;
// 	field:int flags;	offset:32;	size:8;	signed:0;
// 	field:umode_t mode;	offset:40;	size:8;	signed:0;
// 
// print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))

// Define the custom structure matching the tracepoint format
struct sys_enter_openat_event {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

#define MAX_FILENAME_LEN 256

// File open flags
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_EXCL      0x0080
#define O_NOCTTY    0x0100
#define O_TRUNC     0x0200
#define O_APPEND    0x0400
#define O_NONBLOCK  0x0800
#define O_DSYNC     0x1000
#define O_DIRECT    0x2000
#define O_LARGEFILE 0x4000
#define O_DIRECTORY 0x8000
#define O_NOFOLLOW  0x010000
#define O_CLOEXEC   0x020000

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct sys_enter_openat_event *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // If pid_target is set, filter by PID
    if (pid_target && pid_target != pid)
        return 0;

    // Extract the filename pointer from user space
    const char *filename_ptr = ctx->filename;
    char filename[MAX_FILENAME_LEN];

    // Safely read the filename string from user space
    if (bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr) < 0) {
        return 0;
    }

    // Extract other fields
    long dfd = ctx->dfd;
    long flags = ctx->flags;
    long mode = ctx->mode;

    // Interpret flags
    bpf_printk("PID %d called openat(dfd: %ld, filename: %s, flags: 0x%lx, mode: 0x%lx)\n", pid, dfd, filename, flags, mode);
    
    if ((flags & O_RDONLY) == O_RDONLY) bpf_printk("Flag set: O_RDONLY ");
    if ((flags & O_WRONLY) == O_WRONLY) bpf_printk("Flag set: O_WRONLY ");
    if ((flags & O_RDWR) == O_RDWR)     bpf_printk("Flag set: O_RDWR ");
    if (flags & O_CREAT)                bpf_printk("Flag set: O_CREAT ");
    if (flags & O_EXCL)                 bpf_printk("Flag set: O_EXCL ");
    if (flags & O_NOCTTY)               bpf_printk("Flag set: O_NOCTTY ");
    if (flags & O_TRUNC)                bpf_printk("Flag set: O_TRUNC ");
    if (flags & O_APPEND)               bpf_printk("Flag set: O_APPEND ");
    if (flags & O_NONBLOCK)             bpf_printk("Flag set: O_NONBLOCK ");
    if (flags & O_DSYNC)                bpf_printk("Flag set: O_DSYNC ");
    if (flags & O_DIRECT)               bpf_printk("Flag set: O_DIRECT ");
    if (flags & O_LARGEFILE)            bpf_printk("Flag set: O_LARGEFILE ");
    if (flags & O_DIRECTORY)            bpf_printk("Flag set: O_DIRECTORY ");
    if (flags & O_NOFOLLOW)             bpf_printk("Flag set: O_NOFOLLOW ");
    if (flags & O_CLOEXEC)              bpf_printk("Flag set: O_CLOEXEC ");
    bpf_printk("\n");

    return 0;
}


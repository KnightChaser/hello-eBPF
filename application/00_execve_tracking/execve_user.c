// execve_user.c
#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pwd.h>

// Maximum number of arguments to capture
#define MAX_ARGS 10
#define MAX_ARG_LEN 256

struct event {
    __u32 uid;
    __u32 pid;
    char comm[16];
    char filename[256];
    __u32 argc;
    char args[MAX_ARGS][MAX_ARG_LEN];
};

// Flag for program termination
static volatile sig_atomic_t exiting = 0;

// Signal handler for graceful termination
static void handle_signal(int sig) {
    exiting = 1;
}

// Callback function to handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    struct passwd pwd, *pwd_p;
    char username[256];
    int ret;

    // Get the username from UID
    ret = getpwuid_r(e->uid, &pwd, username, sizeof(username), &pwd_p);
    if (ret != 0 || pwd_p == NULL) {
        // If failed to get username, use UID as string
        snprintf(username, sizeof(username), "%d", e->uid);
    }

    printf("PID: %d | USER: %s(%d) | COMM: %s | FILENAME: %s | ARGC: %d\n", 
           e->pid, username, e->uid, e->comm, e->filename, e->argc);

    if (e->argc > 0) {
        for (__u32 index = 0; index < e->argc; index++)
            printf(" argv[%d]: %s\n", index, e->args[index]);
    }

    return 0;
}

int main(int argc, char* argv[]) {
    struct ring_buffer *rb = NULL;
    struct bpf_program *prog;
    struct bpf_object *obj;
    struct bpf_link *link = NULL;
    int map_fd;
    int err;

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open the eBPF object file
    obj = bpf_object__open_file("execve.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file\n");
        return 1;
    }

    // Load the eBPF program into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load eBPF object\n");
        goto cleanup;
    }

    // Find the eBPF program by section name
    prog = bpf_object__find_program_by_name(obj, "trace_execve");
    if (!prog) {
        fprintf(stderr, "Failed to find eBPF program\n");
        goto cleanup;
    }

    // Attach the eBPF program to the tracepoint
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        goto cleanup;
    }

    // Find the ring buffer map file descriptor
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ring buffer map\n");
        goto cleanup;
    }

    // Create a ring buffer to receive events
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Listening for execve events... Press Ctrl+C to exit.\n");

    // Poll the ring buffer for events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        // No events, continue
    }

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}


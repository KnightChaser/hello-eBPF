// chdir_user.c
#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <pwd.h>

#define MAX_FILENAME_LEN 256 

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define RESET "\033[0m"

// Structure for storing chdir result information
struct chdir_event {
    __u32 pid;
    __u32 uid;
    char filename[MAX_FILENAME_LEN];
    bool success;
};

// Flag for program termination
static volatile sig_atomic_t exiting = 0;

// Signal handler for graceful termination
static void handle_signal(int sig) {
    exiting = 1;
}

// Hold the latest event for duplication handling
// Generally, failed chdir attempts generate the same duplicated failed logs (same PID)
static struct chdir_event last_event;
static bool first_event = true;

// Callback function to handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct chdir_event *e = data;

    if (!first_event &&
        e->pid == last_event.pid &&
        e->uid == last_event.uid &&
        e->success == last_event.success &&
        strcmp(e->filename, last_event.filename) == 0) {
            // Skip duplicated event
            return 0;
        }

    // Update the last event
    last_event = *e;
    first_event = false;

    struct passwd pwd, *pwd_p;
    char username[256]; 
    int ret;

    // Get the username from UID
    ret = getpwuid_r(e->uid, &pwd, username, sizeof(username), &pwd_p);
    if (ret != 0 || pwd_p == NULL) {
        // If failed to get username, use UID as string
        snprintf(username, sizeof(username), "%d", e->uid);
    }

    if (e->success) {
        printf(GREEN "[+] chdir: %s (PID: %d, UID: %s)\n" RESET, e->filename, e->pid, username);
    } else {
        printf(RED "[-] chdir: %s (PID: %d, UID: %s)\n" RESET, e->filename, e->pid, username);
    }

    return 0;
}

int main(int argc, char* argv[]) {
    struct ring_buffer *rb = NULL;
    struct bpf_program *prog_enter, *prog_exit;
    struct bpf_object  *obj;
    struct bpf_link    *link_enter = NULL, *link_exit = NULL;
    int map_fd;
    int err = 0;

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open the eBPF object file
    obj = bpf_object__open_file("chdir.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening eBPF object file\n");
        return 1;
    }

    // Load the eBPF program into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load eBPF object\n");
        goto cleanup;
    }

    // Find the eBPF programs by section name. (Capture all tracepoints)
    // When tracing system calls that require state to be maintained across the entry and exit points (like capturing arguments and return values), both the sys_enter and sys_exit tracepoints need to be used.
    prog_enter = bpf_object__find_program_by_name(obj, "tracepoint__syscalls__sys_enter_chdir");
    prog_exit = bpf_object__find_program_by_name(obj, "tracepoint__syscalls__sys_exit_chdir");
    if (!prog_enter || !prog_exit) {
        fprintf(stderr, "Failed to find eBPF programs\n");
        goto cleanup;
    }

    // Attach the eBPF programs to the tracepoints
    link_enter = bpf_program__attach(prog_enter);
    if (libbpf_get_error(link_enter)) {
        fprintf(stderr, "Failed to attach eBPF program for sys_enter_chdir\n");
        link_enter = NULL;
        goto cleanup;
    }
    link_exit = bpf_program__attach(prog_exit);
    if (libbpf_get_error(link_exit)) {
        fprintf(stderr, "Failed to attach eBPF program for sys_exit_chdir\n");
        link_exit = NULL;
        goto cleanup;
    }

    // Find the ring buffer map file descriptor
    map_fd = bpf_object__find_map_fd_by_name(obj, "chdir_events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find chdir_events map\n");
        goto cleanup;
    }

    // Create a ring buffer to receive events
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Listening for chdir events... Press Ctrl-C to exit\n");

    // Poll the ring buffer for events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, milliseconds */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (link_enter)
        bpf_link__destroy(link_enter);
    if (link_exit)
        bpf_link__destroy(link_exit);
    bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}


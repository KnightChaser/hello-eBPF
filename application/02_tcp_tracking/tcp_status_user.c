#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "tcp_events.h"

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define RESET "\033[0m"

// Flag for program termination
static volatile sig_atomic_t exiting = 0;

static volatile __u64 tcp_packet_count = 0;

// Signal handler for graceful termination
static void handle_signal(int sig) {
    exiting = 1;
}

// Callback function to handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct tcp_event *event = data;

    // Display the TCP event details
    printf(GREEN);
    printf("[%lld] TCP EVENT:\n", tcp_packet_count);
    printf(RESET);
    printf("  Task Name: %s\n", event->task_name);
    printf("  PID: %u\n", event->process_id);
    printf("  Source Address: %s\n", inet_ntoa((struct in_addr){event->source_address}));
    printf("  Destination Address: %s\n", inet_ntoa((struct in_addr){event->destination_address}));
    printf("  Source Port: %u\n", event->source_port);
    printf("  Destination Port: %u\n", event->destination_port);
    printf("  Previous(old) State: %d\n", event->old_state);
    printf("  Current(new) State: %d\n", event->new_state);
    printf("  Timestamp (us): %llu\n", event->timestamp_us);
    printf("  Elapsed Time (us): %llu\n", event->elapsed_time_us);

    return 0;
}

int main(int argc, char* argv[]) {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int map_fd;
    int err = 0;

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open the eBPF object file
    obj = bpf_object__open_file("tcp_status.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening eBPF object file\n");
        return 1;
    }

    // Load the eBPF program into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load eBPF object\n");
        goto cleanup;
    }

    // Find the eBPF program by section name
    prog = bpf_object__find_program_by_name(obj, "handle_socket_state_change");
    if (!prog) {
        fprintf(stderr, "Failed to find the eBPF program\n");
        goto cleanup;
    }

    // Attach the eBPF program to the tracepoint
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        link = NULL;
        goto cleanup;
    }

    // Find the ring buffer map file descriptor
    map_fd = bpf_object__find_map_fd_by_name(obj, "tcp_events_ringbuf");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find events_ringbuf map\n");
        goto cleanup;
    }

    // Create a ring buffer to receive events
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Listening for TCP state change events... Press Ctrl-C to exit\n");

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
    if (link)
        bpf_link__destroy(link);
    bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}


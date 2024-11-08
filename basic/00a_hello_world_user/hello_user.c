// hello_user.c
#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>

struct event {
    unsigned int pid;
    char msg[12];
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("PID: %d says: %s\n", e->pid, e->msg);
    return 0;
}

int main(int argc, char* argv[]) {
    struct ring_buffer *rb = NULL;      // Ring buffer to receive events
    int map_fd;                         // File descriptor of the ring buffer map
    struct bpf_object *obj;             // BPF object file (eBPF bytecode)
    struct bpf_program *prog;           // BPF program (eBPF bytecode)
    struct bpf_link *link;              // BPF program link (attached to a tracepoint)

    // Open the BPF object file
    obj = bpf_object__open_file("hello.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // Load the BPF object into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Find the BPF program by its name (the function itself is called -> hello.bpf.c's int hello_event)
    prog = bpf_object__find_program_by_name(obj, "hello_event");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program 'hello_event'\n");
        return 1;
    }

    // Attach the BPF program to the tracepoint
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    // Find the ring buffer map file descriptor (ring buffer named "events", events SEC(".maps"))
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ring buffer map\n");
        return 1;
    }

    // Create a ring buffer to receive events from the kernel
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for events...\n");

    // Poll the ring buffer for events
    while (true) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // Clean up resources
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}


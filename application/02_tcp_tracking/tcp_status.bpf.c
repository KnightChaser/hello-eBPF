#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcp_events.h"

#define MAX_HASH_ENTRIES 10240
#define IPV4_FAMILY      2
#define IPV6_FAMILY      10

const volatile bool enable_sport_filter = false;
const volatile bool enable_dport_filter = false;
const volatile short target_protocol_family = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HASH_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} source_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HASH_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} destination_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HASH_ENTRIES);
    __type(key, struct sock *);
    __type(value, __u64);
} socket_timestamps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} tcp_events_ringbuf SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_socket_state_change(struct trace_event_raw_inet_sock_set_state *context)
{
    struct sock *socket = (struct sock *)context->skaddr;
    __u16 protocol_family = context->family;
    __u16 source_port = context->sport;
    __u16 destination_port = context->dport;
    __u64 *previous_timestamp, elapsed_time_us, current_timestamp;
    struct tcp_event *socket_event;

    if (context->protocol != IPPROTO_TCP) {
        // We are only interested in TCP sockets
        return 0;
    }

    if (target_protocol_family && target_protocol_family != protocol_family) {
        // We are only interested in sockets of the target protocol family
        return 0;
    }

    if (enable_sport_filter && !bpf_map_lookup_elem(&source_ports, &source_port)) {
        // We are only interested in sockets with the source port in the filter
        return 0;
    }

    if (enable_dport_filter && !bpf_map_lookup_elem(&destination_ports, &destination_port)) {
        // We are only interested in sockets with the destination port in the filter
        return 0;
    }

    previous_timestamp = bpf_map_lookup_elem(&socket_timestamps, &socket);
    current_timestamp = bpf_ktime_get_ns();
    elapsed_time_us = previous_timestamp ? (current_timestamp - *previous_timestamp) / 1000 : 0;

    socket_event = bpf_ringbuf_reserve(&tcp_events_ringbuf, sizeof(*socket_event), 0);
    if (!socket_event)
        return 0;

    socket_event->socket_address    = (__u64)socket;
    socket_event->timestamp_us      = current_timestamp / 1000;
    socket_event->elapsed_time_us   = elapsed_time_us;
    socket_event->process_id        = bpf_get_current_pid_tgid() >> 32;
    socket_event->old_state         = context->oldstate;
    socket_event->new_state         = context->newstate;
    socket_event->protocol_family   = protocol_family;
    socket_event->source_port       = source_port;
    socket_event->destination_port  = destination_port;
    bpf_get_current_comm(&socket_event->task_name, sizeof(socket_event->task_name));

    if (protocol_family == IPV4_FAMILY) {
        bpf_probe_read_kernel(&socket_event->source_address, sizeof(socket_event->source_address), &socket->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&socket_event->destination_address, sizeof(socket_event->destination_address), &socket->__sk_common.skc_daddr);
    } else {
        // IPv6 family
        bpf_probe_read_kernel(&socket_event->source_address, sizeof(socket_event->source_address), &socket->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&socket_event->destination_address, sizeof(socket_event->destination_address), &socket->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_ringbuf_submit(socket_event, 0);

    if (context->newstate == TCP_CLOSE)
        bpf_map_delete_elem(&socket_timestamps, &socket);
    else
        bpf_map_update_elem(&socket_timestamps, &socket, &current_timestamp, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";


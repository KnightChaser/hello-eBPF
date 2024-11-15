#ifndef __TCP_EVENT_H
#define __TCP_EVENT_H

#define TASK_NAME_LENGTH 16

typedef unsigned long long __u64;
typedef unsigned int __u32;
typedef unsigned short __u16;

struct tcp_event {
    unsigned __int128   source_address;
    unsigned __int128   destination_address;
    __u64               socket_address;
    __u64               timestamp_us;
    __u64               elapsed_time_us;
    __u32               process_id;
    int                 old_state;
    int                 new_state;
    __u16               protocol_family;
    __u16               source_port;
    __u16               destination_port;
    char                task_name[TASK_NAME_LENGTH];
};

#endif /* __TCP_EVENT_H */


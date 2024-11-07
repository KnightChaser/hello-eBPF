#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define COMMAND_NAME_LENGTH 16

struct exec_event {
    int process_id;
    int parent_process_id;
    int user_id;
    int return_value;
    bool is_exit;
    char command[COMMAND_NAME_LENGTH];
};

#endif /* __EXECSNOOP_H */


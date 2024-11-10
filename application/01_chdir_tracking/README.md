Tracking `cd`(change directory) behaviors eBPF.

Since `cd` command is a builtin feature of shell(e.g. `/bin/bash`), it's not a syscall. So, we can't track it via `strace` or `ltrace`. But, we can track it via eBPF generally. However, using the trick below,
```sh
stty -echo
cat | strace bash > /dev/null
```
And then, type `cd (arbitrary valid path)` command, we can see which function calls are used indirectly like below.
```
...
access("/usr/bin/bash", R_OK)           = 0
getpid()                                = 8857
getppid()                               = 8854
getpid()                                = 8857
getppid()                               = 8854
getpgrp()                               = 8853
ioctl(2, TIOCGPGRP, [8853])             = 0
rt_sigaction(SIGCHLD, {sa_handler=0x555c40d9dd70, sa_mask=[], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7f7ab6ff9520}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7f7ab6ff9520}, 8) = 0
prlimit64(0, RLIMIT_NPROC, NULL, {rlim_cur=126533, rlim_max=126533}) = 0
rt_sigprocmask(SIG_BLOCK, NULL, [], 8)  = 0
fcntl(0, F_GETFL)                       = 0 (flags O_RDONLY)
newfstatat(0, "", {st_mode=S_IFIFO|0600, st_size=0, ...}, AT_EMPTY_PATH) = 0
lseek(0, 0, SEEK_CUR)                   = -1 ESPIPE (Illegal seek)
read(0, "\n", 1)                        = 1
read(0, "\n", 1)                        = 1
read(0, "\n", 1)                        = 1
read(0, "\n", 1)                        = 1
read(0, "c", 1)                         = 1
read(0, "d", 1)                         = 1
read(0, " ", 1)                         = 1
read(0, "~", 1)                         = 1
read(0, "/", 1)                         = 1
read(0, "g", 1)                         = 1
read(0, "h", 1)                         = 1
read(0, "-", 1)                         = 1
read(0, "r", 1)                         = 1
read(0, "e", 1)                         = 1
read(0, "p", 1)                         = 1
read(0, "o", 1)                         = 1
read(0, "/", 1)                         = 1
read(0, "\n", 1)                        = 1
newfstatat(AT_FDCWD, "/home", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
newfstatat(AT_FDCWD, "/home/knightchaser", {st_mode=S_IFDIR|0750, st_size=4096, ...}, 0) = 0
newfstatat(AT_FDCWD, "/home/knightchaser/gh-repo", {st_mode=S_IFDIR|0775, st_size=4096, ...}, 0) = 0
chdir("/home/knightchaser/gh-repo")     = 0
```
As we can see above, `chdir` was used, meaning we have to trace this tracepoint-equivalent function call via eBPF.

The syscall format of `chdir` is defined as below...:
```
root@liberra:/sys/kernel/debug/tracing/events/syscalls# cat sys_enter_chdir/format
name: sys_enter_chdir
ID: 665
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * filename;	offset:16;	size:8;	signed:0;

print fmt: "filename: 0x%08lx", ((unsigned long)(REC->filename))
```

```
root@liberra:/sys/kernel/debug/tracing/events/syscalls# cat sys_exit_chdir/format
name: sys_exit_chdir
ID: 664
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
```

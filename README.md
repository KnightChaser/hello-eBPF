# hello-eBPF

Playing with eBPF on Linux, which enables you to see deep internals of Linux system :)

## Note

To create `vmlinux.h` which was used in the given exercise eBPF code, run

```bash
sudo apt update
sudo apt install linux-headers-$(uname -r) clang llvm libbpf-dev gcc-multilib make
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

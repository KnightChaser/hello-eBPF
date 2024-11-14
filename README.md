# hello-eBPF

Playing with eBPF on Linux, which enables you to see deep internals of Linux system :)

## Note

To create `vmlinux.h` which was used in the given exercise eBPF code, run

```bash
sudo apt update
sudo apt install linux-headers-$(uname -r) clang llvm libbpf-dev gcc-multilib make
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

It requires [`libbpf`](https://github.com/libbpf/libbpf) with `1.0.0` or later version(preferably, `v1.5.0`) to make the codes compatible with Ubuntu kernel version 6, not only 5.

- Make sure about the version

```bash
root@liberra:~/gh-repo/hello-eBPF/application/00_execve_tracking$ locate pkgconfig | grep libbpf
/usr/lib64/pkgconfig/libbpf.pc
root@liberra:~/gh-repo/hello-eBPF/application/00_execve_tracking$ pkg-config  --modversion libbpf
1.5.0
root@liberra:~/gh-repo/hello-eBPF/application/00_execve_tracking$ pkg-config libbpf --libs --cflags
-L/usr/lib64 -lbpf
```

- While trying to run the compiled eBPF user application binary after `make`, if you encountered the error like `error while loading shared libraries: libbpf.so.1: cannot open shared object file: No such file or directory`, consider adding `libbpf.so.1` path
  - Add `$LD_LIBRARY_PATH` variable

```bash
echo 'export LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

- Add library path to `/etc/ld.so.conf.d`

```bash
echo "/usr/lib64" | sudo tee /etc/ld.so.conf.d/libbpf.conf
sudo ldconfig
```

## Note for newbies like me

### 1. **`LD_LIBRARY_PATH` Only Affects the Current Session**

- The `LD_LIBRARY_PATH` environment variable is session-based, meaning it only affects the session where it’s set.
- It doesn’t persist after logging out or restarting.
- Running commands with `sudo` typically creates a new session that doesn’t inherit `LD_LIBRARY_PATH` unless you use `sudo -E`. However, using `sudo -E` is not always ideal for security or consistency.

### 2. **`/etc/ld.so.conf.d/` Provides a Persistent, System-Wide Path**

- Adding paths to files in `/etc/ld.so.conf.d/` (e.g., `/etc/ld.so.conf.d/libbpf.conf`) makes them available to all users and sessions, including `sudo`.
- After adding a library path here, running `ldconfig` updates the system’s library cache so these paths are always available. This is particularly useful for system-wide installations or when multiple users need access to the libraries.

### 3. **The Purpose of `ldconfig` for Updating the Library Cache**

- `ldconfig` updates `/etc/ld.so.cache`, which the linker (`ld.so`) uses to locate libraries. This makes searches for libraries more efficient and ensures consistency across all user sessions.
- Running `ldconfig` after adding a path in `/etc/ld.so.conf.d/` makes the new path available immediately without needing to modify `LD_LIBRARY_PATH` in each session.

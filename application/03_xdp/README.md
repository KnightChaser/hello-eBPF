# XDP Quick Reference Guide

This is a quick guide to help me (future me) remember how to work with XDP programs. Keep it simple and useful!

---

## What is XDP?

- **XDP (eXpress Data Path)**: A high-performance network processing mechanism in the Linux kernel.
- It hooks directly into the **network device driver**, allowing you to process packets before they hit the kernel's networking stack.
- Use cases: Filtering, redirecting, or modifying packets at **line rate**.

---

## Attach an XDP Program

1. **Compile the Program:**

   ```bash
   clang -O2 -g -target bpf -c xdp_prog.c -o xdp_prog.o
   ```

2. **Attach to Interface:**

   Using the loader program:

   ```bash
   sudo ./loader <interface> xdp_prog.o
   ```

   Example:

   ```bash
   sudo ./loader eth0 xdp_prog.o
   ```

3. **Check if Attached:**

   Use `ip link`:

   ```bash
   ip link show dev <interface>
   ```

   Example output:

   ```
   3: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
       link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
       prog/xdp id 42
   ```

   If `prog/xdp id` is present, the program is attached.

---

## Detach an XDP Program

1. **Detach from Interface:**

   ```bash
   sudo ip link set dev <interface> xdp off
   ```

   Example:

   ```bash
   sudo ip link set dev eth0 xdp off
   ```

2. **Verify Detachment:**

   Run `ip link` again. If `prog/xdp id` is gone, it worked.

---

## Common Commands

- **Compile eBPF Program:**

  ```bash
  clang -O2 -g -target bpf -c xdp_prog.c -o xdp_prog.o
  ```

- **Attach XDP Program:**

  ```bash
  sudo ./loader eth0 xdp_prog.o
  ```

- **Detach XDP Program:**

  ```bash
  sudo ip link set dev eth0 xdp off
  ```

- **Check Active XDP Programs:**

  ```bash
  ip link show dev eth0
  ```

- **Remove XDP Program from All Interfaces:**

  Just in case things go sideways:

  ```bash
  for iface in $(ls /sys/class/net); do sudo ip link set dev $iface xdp off; done

- See the kernel output:

  ```bash
  sudo cat /sys/kernel/debug/tracing/trace_pipe
  ```

---

## Tips for Debugging

- **Log Kernel Messages:**

  Use `dmesg` to see logs (useful for debugging program loading issues):

  ```bash
  dmesg | tail -n 20
  ```

- **Validate eBPF Program:**

  Use `bpftool` to check if the program is loaded:

  ```bash
  bpftool prog show
  ```

- **Use `tcpdump` to Test:**

  Confirm traffic is being processed:

  ```bash
  sudo tcpdump -i eth0
  ```

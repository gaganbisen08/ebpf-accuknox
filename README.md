# eBPF Packet Filter — Accuknox Assignment

## Demo Video
▶️ [Watch on YouTube](https://youtu.be/6WFmuQZQIUc)

eBPF Packet Filter — Accuknox Assignment
A Linux kernel-level packet filtering solution built with eBPF/XDP to drop TCP packets on configurable ports, with per-process filtering support.
---
Table of Contents
Overview
Problem Statement 1 — Drop TCP Packets on a Port
Problem Statement 2 — Drop Packets for a Specific Process
Problem Statement 3 — Go Code Explanation
Project Structure
Prerequisites
Installation
Usage
Demo
How It Works
---
Overview
This project demonstrates the use of core Linux kernel primitives — specifically eBPF (Extended Berkeley Packet Filter) and XDP (eXpress Data Path) — to perform high-performance packet filtering at the kernel level.
Problem	Description	Status
Problem 1	Drop TCP packets on a configurable port	✅ Complete
Problem 2	Drop all traffic for a process except one port	✅ Complete
Problem 3	Go concurrency code explanation	✅ Complete
---
Problem Statement 1
Drop TCP Packets on Port 4040 (Configurable)
The eBPF/XDP program hooks into the Linux network stack at the earliest possible point and drops all incoming TCP packets destined for a specified port. The port number is stored in a BPF Map, making it configurable from userspace without recompiling the kernel program.
Architecture
```
Network Packet Arrives
        │
        ▼
  [ XDP Hook ]  ◄──── eBPF program attached to network interface
        │
        ▼
  Parse Ethernet → IP → TCP headers
        │
        ▼
  Lookup port from BPF Map  ◄──── userspace can update this anytime
        │
   ┌────┴────┐
   │         │
  Match    No Match
   │         │
   ▼         ▼
XDP_DROP  XDP_PASS
(dropped) (allowed)
```
Files
File	Description
`problem1/drop_port.c`	eBPF kernel program — XDP hook that parses packets and drops matching port
`problem1/loader.c`	Userspace loader — loads eBPF program, attaches to interface, sets port via BPF map
Key Concepts Used
XDP (eXpress Data Path) — hooks into the network driver before the kernel networking stack, giving near line-rate performance
BPF Maps (ARRAY type) — shared memory between kernel eBPF program and userspace, used to store the configurable port number
Packet parsing — manual parsing of Ethernet, IP, and TCP headers with bounds checking required by the eBPF verifier
---
Problem Statement 2
Drop All Traffic for a Process Except Port 4040
Uses cgroup_skb eBPF hooks combined with PID tracking via BPF Hash Maps to filter traffic on a per-process basis. The target process is identified by name from userspace, its PID is registered in a BPF map, and all its outgoing TCP traffic is dropped except for the allowed port.
Architecture
```
Process "myprocess" sends packet
        │
        ▼
  [ cgroup_skb/egress hook ]
        │
        ▼
  bpf_get_current_pid_tgid()
        │
        ▼
  Is this PID in target_pids map?
        │
   ┌────┴────┐
   │         │
  YES        NO
   │         │
   ▼         ▼
Check     XDP_PASS
dest port  (not our process)
   │
   ├── port == allowed_port → ALLOW ✅
   │
   └── port != allowed_port → DROP ❌
```
Files
File	Description
`problem2/proc_filter.c`	eBPF kernel program — cgroup egress hook with PID-based filtering
`problem2/proc_loader.c`	Userspace loader — finds PID by process name, registers in BPF map
---
Problem Statement 3
Go Code Explanation
The Code:
```go
package main

import "fmt"

func main() {
    cnp := make(chan func(), 10)
    for i := 0; i < 4; i++ {
        go func() {
            for f := range cnp {
                f()
            }
        }()
    }
    cnp <- func() {
        fmt.Println("HERE1")
    }
    fmt.Println("Hello")
}
```
Explanation
`make(chan func(), 10)` — Buffered Function Channel
Creates a buffered channel that holds up to 10 values of type `func()`. This is the classic worker pool / task queue pattern in Go. Functions are pushed into the channel and goroutines pull and execute them asynchronously.
Use cases:
Parallel task processing pipelines
Web server request handlers with fixed concurrency
Background job queues
The `for` loop with 4 iterations — Worker Pool
Spawns 4 goroutines that all listen on the same channel. Any function sent to `cnp` is picked up and executed by whichever worker is free first. The number 4 typically maps to CPU core count for CPU-bound tasks.
`for f := range cnp` — Continuous Worker
Each goroutine loops forever, blocking when the channel is empty and waking up when a new function arrives. The loop exits only when the channel is closed.
Why "HERE1" is never printed — Race Condition
```
Timeline:
main goroutine:
  1. Spawns 4 worker goroutines (scheduled but not yet running)
  2. Sends function to channel (buffered — doesn't block)
  3. Prints "Hello"
  4. main() returns → PROGRAM EXITS

Worker goroutines:
  - Never get CPU time before main exits
  - Function sits in channel, never executed
```
Since `main()` has no synchronization mechanism (no `sync.WaitGroup`, no blocking call), it exits before any worker goroutine gets scheduled.
The Fix:
```go
package main

import (
    "fmt"
    "sync"
)

func main() {
    cnp := make(chan func(), 10)
    var wg sync.WaitGroup

    for i := 0; i < 4; i++ {
        go func() {
            for f := range cnp {
                f()
                wg.Done()
            }
        }()
    }

    wg.Add(1)
    cnp <- func() {
        fmt.Println("HERE1") // now prints ✅
    }

    wg.Wait()
    close(cnp)
    fmt.Println("Hello")
}
```
---
Project Structure
```
ebpf-project/
├── README.md
├── problem1/
│   ├── drop_port.c        # eBPF XDP kernel program
│   └── loader.c           # Userspace loader (C)
├── problem2/
│   ├── proc_filter.c      # eBPF cgroup kernel program
│   └── proc_loader.c      # Userspace loader with PID resolution
└── problem3/
    ├── main.go            # Original broken code (demonstrates bug)
    └── main_fixed.go      # Fixed version with WaitGroup
```
---
Prerequisites
Linux kernel 5.15+
Kali Linux / Ubuntu 22.04 or newer
`clang` 14+
`libbpf-dev` 1.x
`bpftool`
`gcc`
---
Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ebpf-project.git
cd ebpf-project

# Install dependencies (Kali/Ubuntu)
sudo apt update && sudo apt install -y \
  clang llvm libelf-dev libbpf-dev \
  linux-headers-$(uname -r) gcc make \
  iproute2 tcpdump netcat-openbsd bpftool
```
---
Usage
Problem 1 — Drop packets on port 4040
```bash
cd problem1

# Compile eBPF kernel program
clang -O2 -g -target bpf \
  -I/usr/include/x86_64-linux-gnu \
  -c drop_port.c -o drop_port.bpf.o

# Compile userspace loader
gcc -o loader loader.c -lbpf -lelf -lz

# Run — drops TCP on port 4040 on loopback
sudo ./loader 4040 lo

# Run with custom port and interface
sudo ./loader 8080 eth0
```
Test it
```bash
# Terminal 1 — start filter
sudo ./loader 4040 lo

# Terminal 2 — start listener
nc -l 4040

# Terminal 3 — try to connect (will be BLOCKED)
nc -v 127.0.0.1 4040

# Terminal 3 — try different port (will CONNECT)
nc -v 127.0.0.1 4041
```
View kernel logs
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
Stop the filter
Press `Ctrl+C` in the loader terminal. The XDP program detaches automatically.
---
Demo
```
# Port 4040 — BLOCKED by eBPF
$ nc -v 127.0.0.1 4040
(hangs — packets dropped at kernel level) ✅

# Port 4041 — ALLOWED (not in drop rule)
$ nc -v 127.0.0.1 4041
Connection to 127.0.0.1 4041 port [tcp/*] succeeded! ✅

# Change port to 8080 dynamically (no recompile needed)
$ sudo ./loader 8080 lo
Dropping TCP on port 8080 on interface 'lo' ✅
```
---
How It Works
eBPF / XDP Flow
```
NIC receives packet
      │
      ▼
 XDP program runs (kernel space)
      │
      ├── Parse Ethernet header
      ├── Check if IPv4
      ├── Check if TCP
      ├── Parse TCP destination port
      └── Compare with port_map value
            │
       ┌────┴────┐
     Match     No Match
       │           │
   XDP_DROP    XDP_PASS
```
BPF Map — Userspace ↔ Kernel Communication
```
Userspace (loader.c)              Kernel (drop_port.c)
─────────────────────             ──────────────────────
bpf_map_update_elem()  ────────►  bpf_map_lookup_elem()
writes port number                reads port number
to port_map                       from port_map
```
The BPF Array Map acts as shared memory between userspace and the kernel eBPF program, allowing the port to be changed at runtime without reloading the program.
---
Environment
Component	Version
OS	Kali Linux (Debian)
Kernel	6.x
clang	21.1.8
libbpf	1.6.3
bpftool	7.7.0

eBPF Packet Filter — Accuknox Assignment

Demo Video
---
▶️ [Watch on YouTube](https://youtu.be/6WFmuQZQIUc?si=IYK_OQLiHB6jwAaj)

Table of Contents
Overview
Problem 1 — Drop TCP Packets on a Port
Problem 2 — Drop Packets for a Specific Process
Problem 3 — Go Code Explanation
Project Structure
Prerequisites
Installation
---
Overview
This project demonstrates the use of core Linux kernel primitives — eBPF, XDP, and cgroup hooks — to perform high-performance packet filtering at the kernel level.
Problem	Description	Status
Problem 1	Drop TCP packets on a configurable port	✅ Complete
Problem 2	Drop all traffic for a process except one port	✅ Complete
Problem 3	Go concurrency code explanation	✅ Complete
---
Problem 1
Drop TCP Packets on Port 4040 (Configurable)
eBPF/XDP program hooks into the Linux network stack at the earliest possible point and drops all incoming TCP packets on a specified port. Port is stored in a BPF Map — configurable from userspace without recompiling.
Architecture
```
Network Packet Arrives
        │
        ▼
  [ XDP Hook ] ◄── eBPF attached to network interface
        │
        ▼
  Parse Ethernet → IP → TCP
        │
        ▼
  Lookup port from BPF Map ◄── userspace can update anytime
        │
   ┌────┴────┐
   │         │
  Match    No Match
   ▼         ▼
XDP_DROP  XDP_PASS
```
Build & Run
```bash
cd problem1
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c drop_port.c -o drop_port.bpf.o
gcc -o loader loader.c -lbpf -lelf -lz
sudo ./loader 4040 lo
```
Test
```bash
nc -l 4040          # listener
nc -v 127.0.0.1 4040  # blocked — hangs ❌
nc -v 127.0.0.1 4041  # allowed — connects ✅
```
---
Problem 2
Drop All Traffic for a Process Except Port 4040
## Demo Video
---
▶️ [Watch on YouTube](https://youtu.be/j5LyH7vfGd8)

Uses cgroup_skb eBPF hooks on the root cgroup. Intercepts all egress packets and drops everything except the configured allowed port.
Architecture
```
Process sends packet
        │
        ▼
  [ cgroup_skb/egress hook ]
        │
        ▼
  Read allowed port from BPF Map
        │
   ┌────┴────┐
  YES        NO
   ▼         ▼
 ALLOW      DROP
  ✅          ❌
```
Build & Run
```bash
cd problem2
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c proc_filter.c -o proc_filter.bpf.o
gcc -o proc_loader proc_loader.c -lbpf -lelf -lz
sudo ./proc_loader 4040
```
Test
```bash
nc -l 4040 &              # listener on allowed port
nc -l 8888 &              # listener on blocked port
sudo ./proc_loader 4040   # start filter
nc -v 127.0.0.1 4040      # connects ✅
nc -v 127.0.0.1 8888      # hangs ❌
sudo cat /sys/kernel/debug/tracing/trace_pipe  # live logs
```
Kernel Logs
```
ALLOW: port 4040   ✅
DROP:  port 8888   ❌
DROP:  port 39398  ❌
```
---
Problem 3
Go Code Explanation
```go
package main
import "fmt"

func main() {
    cnp := make(chan func(), 10)
    for i := 0; i < 4; i++ {
        go func() {
            for f := range cnp { f() }
        }()
    }
    cnp <- func() { fmt.Println("HERE1") }
    fmt.Println("Hello")
}
```
`make(chan func(), 10)` — Buffered channel holding up to 10 functions. Classic worker pool pattern.
4 goroutines — Worker pool of 4 concurrent workers all reading from same channel.
Why HERE1 never prints — main() exits before any worker goroutine gets scheduled. No synchronization mechanism exists to make main() wait.
Fix:
```go
var wg sync.WaitGroup
wg.Add(1)
cnp <- func() {
    fmt.Println("HERE1") // now prints ✅
    wg.Done()
}
wg.Wait()
```
---
Project Structure
```
ebpf-accuknox/
├── README.md
├── Makefile
├── .gitignore
├── problem1/
│   ├── drop_port.c
│   └── loader.c
├── problem2/
│   ├── proc_filter.c
│   └── proc_loader.c
└── problem3/
    ├── main.go
    └── main_fixed.go
```
---
Prerequisites
Linux kernel 5.15+ (tested on 6.x)
Kali Linux / Ubuntu 22.04+
clang 14+, libbpf-dev 1.x, bpftool, gcc, golang 1.18+
---
Installation
```bash
git clone https://github.com/YOUR_USERNAME/ebpf-accuknox.git
cd ebpf-accuknox

sudo apt update && sudo apt install -y \
  clang llvm libelf-dev libbpf-dev \
  linux-headers-$(uname -r) gcc make \
  iproute2 tcpdump netcat-openbsd bpftool golang-go
```
---
Environment
Component	Version
OS	Kali Linux (Debian)
Kernel	6.x
clang	21.1.8
libbpf	1.6.3
bpftool	7.7.0

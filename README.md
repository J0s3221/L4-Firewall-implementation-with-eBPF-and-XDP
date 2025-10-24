# L4 Firewall implementation with eBPF and XDP

This project implements a simple **Layer 4 firewall** using **eBPF** and **XDP**.  
Its goal is to explore how programmable data plane technologies (like eBPF) can be used to build efficient packet filtering systems and to compare their performance against traditional firewalls.

Developed as part of the **Programmable Networks** course at **IST–METI**.

In this repository there are two programs:
- A simple and static program that implements one packet parsing rule using eBPF/XDP;
- A more complex layer 4 firewall dynamic solution.

This README has instructions on how to run and compile both this programs and also information on their implementation and setup.

### Disclaimer
Both this programs use eBPF and XDP which are UnixOS dependent, meaning this program **will not work on other OSes**. We developed this code in a machine running Ubuntu 25.04, in the overview of the first program tutorial we give some commands to check your developement environment. We **recomend** doing both tutorials in other since both programs were developed squencally and so the second one builds on the first.

# Simple static proof of concept program

## Overview

The first program is simpler and static, it implements one single rule: **drop UDP port 1005 traffic**.

To test the program we create two virtual ethernet interfaces in two seperate namespaces (`veth0` and `veth1`) and load the program into `veth0`. Then simulate traffic between them. The program intiates two counter using bpf map arrays, the counter 0 counts the packets that pass and the counter 1 the ones that were dropped. If the program is working correctly it increments the counter accordingly.

### Check development environment

This project relies on **Linux-native networking and eBPF tools**, which are only fully supported on **modern Unix-like systems**.
It was developed and tested on Ubuntu **25.04 (Lunar Lobster)**, but it should also work on most recent Ubuntu or Debian-based distributions (22.04+).

Before building and running the program, make sure your environment meets the following requirements.

**1. Check kernel version**

The Linux kernel must support XDP and eBPF (version 5.4 or newer is recommended):
```bash
uname -r
```

Expected output:
```bash
5.4.0 or higher
```

If your kernel is older, update it:
```bash
sudo apt update && sudo apt full-upgrade -y
```

**2. Install required packages**

Install the necessary development tools and utilities:
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev build-essential \
                    iproute2 iputils-ping net-tools bpftool ethtool make
```

These packages provide:
- **clang/llvm** – to compile eBPF programs
- **libbpf-dev** and libelf-dev – to work with ELF and BPF objects
- **iproute2** – to manage network namespaces and interfaces
- **bpftool** – to inspect and debug eBPF objects
- **ethtool** – to query and manage interface driver information
- **make** – to run the automated Makefile build/test commands

**3. Verify bpftool and clang availability**

Make sure both are available and working:
```bash
bpftool version
clang --version
```

Example outputs:
```bash
bpftool v7.2.0
clang version 17.0.0
```

**4. Optional: enable BPF sysctl settings**

Ensure the system allows loading BPF programs:
```bash
sudo sysctl net.core.bpf_jit_enable
```

If the output is `0`, enable it permanently:
```bash
echo "net.core.bpf_jit_enable=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Once these checks pass, your environment is ready for compilation and testing ✅.
You can now proceed to Compiling the program.

## Manual Setup & Testing

The process of setting up namespaces, compiling the eBPF program, loading it into the kernel, and testing it manually is both time-consuming and error-prone. So we made a dedicated Makefile to automate all routine operations related to compilation, network configuration, and testing. If you simply wanna compile and run the program you can jump to the makefile subsection for a simpler and quicker setup-compile-run.

To test the program, we simulate two hosts using **Linux network namespaces** and a **veth pair** (`veth0`, `veth1`) that connects them.

### Compiling the program 

To compile the eBPF code run the command:
```bash
clang -O2 -g -target bpf -c \
        -I/usr/include \
        -I/usr/include/x86_64-linux-gnu \
        bpf/xdp_l4_poc.c -o build/xdp_l4_poc.o
```

### Create namespaces and interfaces

To create the virtual ethernet interfaces run the following commands:
```bash
sudo ip netns add ns1
sudo ip netns add ns2
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 netns ns1
sudo ip link set veth1 netns ns2
sudo ip -n ns1 addr add 10.0.0.1/24 dev veth0
sudo ip -n ns2 addr add 10.0.0.2/24 dev veth1
sudo ip -n ns1 link set veth0 up
sudo ip -n ns2 link set veth1 up
```

### Load the program 

To load the program into the kernel (on `veth0`):
```bash
sudo ip netns exec ns1 ip link set dev veth0 xdpgeneric obj build/xdp_l4_poc.o sec xdp
sudo ip netns exec ns1 bpftool net
```

After this the program is ready to be tested.

### Check the setup (sanity check)

Before running the tests, make sure all components were correctly created, compiled, and loaded.
Run the following checks to confirm that your setup is complete and consistent:

**1. Verify namespaces**

Ensure both `ns1` and `ns2` were created:
```bash
ip netns list
```

Expected output:
```bash
ns2
ns1
```

**2. Verify interfaces inside namespaces**

Check that `veth0` and `veth1` are correctly assigned and up:
```bash
sudo ip netns exec ns1 ip link show veth0
sudo ip netns exec ns2 ip link show veth1
```

Expected output:
```bash
veth0@ifX: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
veth1@ifY: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

You should also see the assigned IPs:
```bash
sudo ip netns exec ns1 ip addr show veth0
sudo ip netns exec ns2 ip addr show veth1
```

Expected addresses:
```bash
10.0.0.1/24  (on veth0)
10.0.0.2/24  (on veth1)
```

**4. Verify that the XDP program is attached**

Check that the XDP program is loaded on `veth0` inside namespace `ns1`:
```bash
sudo ip netns exec ns1 bpftool net
```

You should see output similar to:
```bash
4: veth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
    prog/xdp id 42 tag 8a2c9b name xdp_l4_poc
```

If you see no `prog/xdp` entry then it wasn't properly loaded, try reattaching it using the makefile command (more info in the makefile section):
```bash
make load
```

**5. Verify BPF maps are created**

List the BPF maps to ensure the counters exist:
```bash
sudo ip netns exec ns1 bpftool map show
```

Expected output should include something like:
```bash
id 3 name counters type array key 4B value 8B max_entries 2
```

If all checks pass, your setup is correct and you’re ready to move to the **Test the program section**.

### Test the program

The results should follow:

| Traffic Type  | Destination Port | Expected Behavior |
| ------------- | ---------------- | ----------------- |
| UDP           | 1005             | ❌ Dropped         |
| UDP           | 9999             | ✅ Passed          |
| Other traffic | Any              | ✅ Passed          |

To test the program send test traffic using netcat:
```bash
sudo ip netns exec ns2 bash -c 'echo "drop" | nc -u -w1 10.0.0.1 1005'  # should be dropped
sudo ip netns exec ns2 bash -c 'echo "pass" | nc -u -w1 10.0.0.1 9999'  # should pass
```
Get the map id by running the following command, `the map_id` you want is from an array type with to entries:
```bash
sudo ip netns exec ns1 bpftool map show
```

Now check counters, if it worked the counters should have the number of packets passed and dropped:

```bash
sudo ip netns exec ns1 bpftool map show # name counters
```

```bash
sudo ip netns exec ns1 bpftool map dump id <map_id> # id -> name counters
```


The expected output should be something like:
```bash
    key: 00 00 00 00 value: 0a 00 00 00 00 00 00 00 # packets passed
    key: 01 00 00 00 value: 0a 00 00 00 00 00 00 00 # packets dropped
    Found 2 elements
```

If your counters were correctly implemented the program worked! ✅😊

## Makefile Setup & Testing

Since the manual setup is lengthy, we automated everything with a **Makefile**.
You can find it in the root directory of this repository.

| Command        | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| `make setup`   | Creates network namespaces and connects them with veth pairs |
| `make all`     | Compiles the eBPF program into a BPF object file             |
| `make load`    | Loads the XDP program into `veth0` in namespace `ns1`        |
| `make unload`  | Detaches the XDP program                                     |
| `make test`    | Sends UDP packets between namespaces to test the firewall    |
| `make clean`   | Removes namespaces, links, and build artifacts               |
| `make rebuild` | Performs a full clean + setup + build + load cycle           |

To setup, load, compile and run the tests you can ran the following commands in order:
```bash
make setup
make all
make load
make test
```

The results should follow:

| Traffic Type  | Destination Port | Expected Behavior |
| ------------- | ---------------- | ----------------- |
| UDP           | 1005             | ❌ Dropped         |
| UDP           | 9999             | ✅ Passed          |
| Other traffic | Any              | ✅ Passed          |

Now check counters, if it worked the counters should have the number of packets passed and dropped:

```bash
sudo ip netns exec ns1 bpftool map show # name counters
```

```bash
sudo ip netns exec ns1 bpftool map dump id <map_id> # id -> name counters
```

The expected output should be something like:
```bash
    key: 00 00 00 00 value: 0a 00 00 00 00 00 00 00 # packets passed
    key: 01 00 00 00 value: 0a 00 00 00 00 00 00 00 # packets dropped
    Found 2 elements
```

If your counters were correctly implemented the program worked! ✅😊

# Dynamic layer 4 firewall implementation

## Overview

The second program is a **dynamic Layer 4 firewall** that extends the static proof of concept by allowing **runtime configuration of filtering rules**.
Instead of hardcoding a single blocked port in the source code, this version uses an eBPF hash map named `blocked_ports`, enabling the user to add or remove blocked UDP ports on the fly using `bpftool`.

This provides the flexibility of a real firewall, where filtering policies can change at runtime without recompiling or reloading the XDP program.

### How it works

The program defines a new BPF map that stores the destination ports to block:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u16);   // Destination port
    __type(value, __u8);  // 1 = blocked
} blocked_ports SEC(".maps");
```

When a UDP packet arrives, the program looks up its destination port in this map:

```c
__u16 dport = bpf_ntohs(udp->dest);
__u8 *blocked = bpf_map_lookup_elem(&blocked_ports, &dport);
if (blocked)
    return XDP_DROP;
```

If the port exists in the `blocked_ports` map, the packet is dropped; otherwise, it is passed and counted normally.
This logic makes it possible to modify firewall rules at runtime directly from user space.

## Dynamic configuration

Using `bpftool`, you can dynamically manage which ports are blocked without recompiling or restarting the program:

```bash
# Add UDP port 1005 to the blocked list
sudo bpftool map update name blocked_ports key 1005 value 1

# Remove UDP port 1005 from the blocked list
sudo bpftool map delete name blocked_ports key 1005

# Show all currently blocked ports
sudo bpftool map dump name blocked_ports
```

After adding a port to the map, any UDP packets sent to that port will be dropped immediately.
When removed, traffic to that port will be allowed again — all without touching the code or restarting the XDP program.

## Makefile Setup & Testing

The dynamic firewall uses the same virtual environment as the static one, with two namespaces (`ns1`, `ns2`) connected by a veth pair (`veth0`–`veth1`).
A dedicated **Makefile** in the `dynamic/` folder automates the entire build and testing process.

To compile, load, and test the program:

```bash
make clean
make setup
make all
make load
make test
```

Expected output from `make test`:

```
🧪 Sending UDP packets (dynamic mode test: blocked & passed)...
📊 Current counters:
key: 00 00 00 00  value: 05 00 00 00 00 00 00 00   # Dropped packets
key: 01 00 00 00  value: 05 00 00 00 00 00 00 00   # Passed packets
✅ Dynamic test completed successfully.
```

## Results

| Traffic Type  | Destination Port | Expected Behavior |
| ------------- | ---------------- | ----------------- |
| UDP           | 1005 (blocked)   | ❌ Dropped         |
| UDP           | 9999 (allowed)   | ✅ Passed          |
| Other traffic | Any              | ✅ Passed          |

You can confirm the counters with:

```bash
sudo bpftool map dump name counters
```

## Summary

The dynamic implementation transforms the initial proof of concept into a **fully configurable eBPF/XDP firewall**,
capable of adapting its filtering rules at runtime while maintaining kernel-level performance.

It demonstrates the power and flexibility of eBPF maps for **real-time user–kernel communication**, showing how modern programmable networking can achieve both speed and adaptability in packet processing.


**Devolopers**: José Oliveira (J0s3221) & Tiago Videira (tiagovideira8)
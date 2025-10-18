# L4 Firewall implementation with eBPF and XDP

This project implements a simple **Layer 4 firewall** using **eBPF** and **XDP**.  
Its goal is to explore how programmable data plane technologies (like eBPF) can be used to build efficient packet filtering systems and to compare their performance against traditional firewalls.

Developed as part of the **Programmable Networks** course at **IST–METI**.

In this repository theres to programs:
    - A simple and static program that implements one packet parsing rule using eBPF/XDP;
    - A more complex layer 4 firewall dynamic solution.

This README has instructions on how to run and compile both this programs and also information on their implementation and setup.

### Disclaimer
Both this programs use eBPF and XDP which are UnixOS dependent, meaning this program will not work on other OSes. We developed this code in a machine running Ubuntu 25.04, in the overview of the first program tutorial we give some commands to check your developement environment. We **recomend** doing both tutorials in other since both programs were developed squencally and so the second one builds on the first.

# Simple static proof of concept program

## Overview

The first program is simpler and static, it implements one single rule: **drop UDP port 1005 traffic**.

To test the program we create two virtual ethernet interfaces in two seperate namespaces (`veth0` and `veth1`) and load the program into `veth0`. Then simulate traffic between them. The program intiates two counter using bpf map arrays, the counter 0 counts the packets that pass and the counter 1 the ones that were dropped. If the program is working correctly it increments the counter accordingly.

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
sudo ip netns exec ns1 bpftool map show
sudo ip netns exec ns1 bpftool map dump id <map_id>
```

The expected output should be something like:
```bash
    key: 00 00 00 00 value: 9f 98 00 00 00 00 00 00 # packets passed
    key: 01 00 00 00 value: 9f 98 00 00 00 00 00 00 # packets dropped
    Found 2 elements
```

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

# Dynamic layer 4 firewall implementation

The second program is yet to be done.

**Devolopers**: José Oliveira (J0s3221) & Tiago Videira (tiagovideira8)
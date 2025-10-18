# L4 Firewall implementation with eBPF and XDP

This project implements a simple **Layer 4 firewall** using **eBPF** and **XDP**.  
Its goal is to explore how programmable data plane technologies (like eBPF) can be used to build efficient packet filtering systems and to compare their performance against traditional firewalls.

Developed as part of the **Programmable Networks** course at **IST–METI**.

# Simple static proof of concept program

## Overview

The first program is simpler and static, it implements one single rule: drop UDP port 1005 traffic.

To test the program we create two virtual ethernet interfaces in two seperate names spaces (veth0 and veth1) and load the program into veth0. Then simulate traffic between them. The program intiates two counter using bpf map arrays, the counter 0 counts the packets that pass and the counter 1 the ones that were dropped. If the program is working correctly it increments the counter accordingly.

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
To load the program into the kernel (on veth0):
```bash
sudo ip netns exec ns1 ip link set dev veth0 xdpgeneric obj build/xdp_l4_poc.o sec xdp
sudo ip netns exec ns1 bpftool net
```

After this the program is ready to be tested.

### Check the setup

### Test the program

## Makefile Setup & Testing

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

## How to compile and run the second program

The second program is yet to be done.

Devolopers: José Oliveira & Tiago Videira
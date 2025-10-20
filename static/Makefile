# ===================================================
#  Makefile for L4 Firewall with eBPF + XDP - Phase 1
# ===================================================

BPF_SRC = bpf/xdp_l4_poc.c
BPF_OBJ = build/xdp_l4_poc.o
IFACE_NS1 = veth0
NETNS1 = ns1
NETNS2 = ns2
PORT_BLOCK = 1005
PORT_PASS  = 9999

CC = clang
CFLAGS = -O2 -g -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu

# ========================
# Default target
# ========================
all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@mkdir -p build
	@echo "🔧 Compiling BPF program..."
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "✅ Build done: $@"

# ========================
# Setup namespaces & veth
# ========================
setup:
	@echo "🌐 Setting up namespaces and veth pair..."
	-sudo ip link del $(IFACE_NS1) 2>/dev/null || true
	-sudo ip netns del $(NETNS1) 2>/dev/null || true
	-sudo ip netns del $(NETNS2) 2>/dev/null || true
	sudo ip netns add $(NETNS1)
	sudo ip netns add $(NETNS2)
	sudo ip link add $(IFACE_NS1) type veth peer name veth1
	sudo ip link set $(IFACE_NS1) netns $(NETNS1)
	sudo ip link set veth1 netns $(NETNS2)
	sudo ip netns exec $(NETNS1) ip addr add 10.0.0.1/24 dev $(IFACE_NS1)
	sudo ip netns exec $(NETNS1) ip link set $(IFACE_NS1) up
	sudo ip netns exec $(NETNS2) ip addr add 10.0.0.2/24 dev veth1
	sudo ip netns exec $(NETNS2) ip link set veth1 up
	@echo "✅ Network namespaces ready (ns1 <-> ns2)"

# ========================
# Attach & Detach program
# ========================
load: $(BPF_OBJ)
	@echo "🚀 Attaching XDP program to $(IFACE_NS1) in $(NETNS1)..."
	sudo ip netns exec $(NETNS1) ip link set dev $(IFACE_NS1) xdpgeneric obj $(BPF_OBJ) sec xdp
	@sudo ip netns exec $(NETNS1) bpftool net
	@echo "✅ XDP program loaded!"

unload:
	@echo "🧹 Detaching XDP program..."
	-sudo ip netns exec $(NETNS1) ip link set dev $(IFACE_NS1) xdpgeneric off 2>/dev/null || true
	@echo "✅ Program detached!"

# ========================
# Test & Verify
# ========================
test:
	@echo "🧪 Sending UDP packets (port $(PORT_BLOCK) blocked, $(PORT_PASS) passed)..."
	sudo ip netns exec $(NETNS2) bash -c 'for i in {1..5}; do echo -n "drop" | nc -u -w1 10.0.0.1 $(PORT_BLOCK); done'
	sudo ip netns exec $(NETNS2) bash -c 'for i in {1..5}; do echo -n "pass" | nc -u -w1 10.0.0.1 $(PORT_PASS); done'
	@echo "📊 Current counters:"
	@sudo ip netns exec $(NETNS1) bash -c 'ID=$$(bpftool net | awk "/generic id/ {print \$$5}"); \
		bpftool prog show id $$ID | grep map_ids; \
		M=$$(bpftool prog show id $$ID | sed -n "s/.*map_ids: \[\(.*\)\].*/\1/p"); \
		echo ""; bpftool map dump id $$M'

# ========================
# Clean everything
# ========================
clean:
	@echo "🧽 Cleaning build files and tearing down namespaces..."
	-sudo ip netns exec $(NETNS1) ip link set dev $(IFACE_NS1) xdpgeneric off 2>/dev/null || true
	-sudo ip link del $(IFACE_NS1) 2>/dev/null || true
	-sudo ip netns del $(NETNS1) 2>/dev/null || true
	-sudo ip netns del $(NETNS2) 2>/dev/null || true
	rm -rf build
	@echo "✅ Clean complete!"

# ========================
# Shortcuts
# ========================
reload: unload load
rebuild: clean setup all load

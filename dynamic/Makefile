# Makefile - Dynamic Test Environment for L4 Firewall (eBPF + XDP)

BPF_OBJ = build/xdp_l4_dynamic.o
BPF_SRC = ../static/bpf/xdp_l4_poc.c
NETNS1 = ns1
NETNS2 = ns2
IFACE1 = veth0
IFACE2 = veth1

.PHONY: all clean setup load unload test show

all: $(BPF_OBJ)
	@echo "✅ Build done: $(BPF_OBJ)"

$(BPF_OBJ): $(BPF_SRC)
	@echo "🔧 Compiling BPF program..."
	mkdir -p build
	clang -O2 -g -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -c $(BPF_SRC) -o $(BPF_OBJ)

setup:
	@echo "🌐 Setting up namespaces and veth pair..."
	sudo ip link del $(IFACE1) 2>/dev/null || true
	sudo ip netns del $(NETNS1) 2>/dev/null || true
	sudo ip netns del $(NETNS2) 2>/dev/null || true
	sudo ip netns add $(NETNS1)
	sudo ip netns add $(NETNS2)
	sudo ip link add $(IFACE1) type veth peer name $(IFACE2)
	sudo ip link set $(IFACE1) netns $(NETNS1)
	sudo ip link set $(IFACE2) netns $(NETNS2)
	sudo ip netns exec $(NETNS1) ip addr add 10.0.0.1/24 dev $(IFACE1)
	sudo ip netns exec $(NETNS1) ip link set $(IFACE1) up
	sudo ip netns exec $(NETNS2) ip addr add 10.0.0.2/24 dev $(IFACE2)
	sudo ip netns exec $(NETNS2) ip link set $(IFACE2) up
	@echo "✅ Network namespaces ready ($(NETNS1) <-> $(NETNS2))"

load:
	@echo "🚀 Attaching XDP dynamic program to $(IFACE1) in $(NETNS1)..."
	sudo ip netns exec $(NETNS1) ip link set dev $(IFACE1) xdpgeneric obj $(BPF_OBJ) sec xdp
	@echo "✅ Dynamic XDP program loaded!"

unload:
	@echo "🧹 Removing XDP dynamic program..."
	sudo ip netns exec $(NETNS1) ip link set dev $(IFACE1) xdpgeneric off || true
	@echo "✅ Dynamic XDP program unloaded."

test:
	@echo "🧪 Sending UDP packets (dynamic mode test: blocked & passed)..."
	@sudo ip netns exec $(NETNS2) bash -c 'for i in {1..5}; do echo -n "block" | nc -u -w1 10.0.0.1 1005 >/dev/null 2>&1; done'
	@sudo ip netns exec $(NETNS2) bash -c 'for i in {1..5}; do echo -n "allow" | nc -u -w1 10.0.0.1 9999 >/dev/null 2>&1; done'
	@echo "📊 Current counters:"
	@sudo bpftool map show name counters 2>/dev/null || echo "⚠️  No counters map found"
	@sudo bpftool map dump name counters 2>/dev/null || echo "⚠️  Unable to dump counters map contents"
	@echo "✅ Dynamic test completed successfully."

show:
	@echo "🔍 Listing loaded dynamic XDP programs and maps..."
	sudo bpftool prog show
	sudo bpftool map show

clean:
	@echo "🧹 Cleaning build files and namespaces..."
	sudo ip netns del $(NETNS1) 2>/dev/null || true
	sudo ip netns del $(NETNS2) 2>/dev/null || true
	rm -rf build
	@echo "✅ Clean done."
	
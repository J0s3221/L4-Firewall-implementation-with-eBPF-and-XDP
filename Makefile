# ============================================
#  Makefile for L4 Firewall (Task 2 - Dynamic)
# ============================================

BPF_SRC_POC = bpf/xdp_l4_poc.c
BPF_OBJ_POC = build/xdp_l4_poc.o
BPF_SRC_DYN = bpf/xdp_l4_fw_dynamic.c
BPF_OBJ_DYN = build/xdp_l4_fw_dynamic.o

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
all: build $(BPF_OBJ_POC) $(BPF_OBJ_DYN)
	@echo "✅ Both PoC and Dynamic Firewall built."

build:
	@mkdir -p build

$(BPF_OBJ_POC): $(BPF_SRC_POC)
	@echo "🔧 Compiling PoC..."
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "✅ Build done: $@"

$(BPF_OBJ_DYN): $(BPF_SRC_DYN)
	@echo "🔧 Compiling Dynamic Firewall..."
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "✅ Build done: $@"

# ========================
# Setup namespaces
# ========================
setup:
	@echo "🌐 Setting up namespaces..."
	-sudo ip link del $(IFACE_NS1) 2>/dev/null || true
	-sudo ip netns del $(NETNS1) 2>/dev/null || true
	-sudo ip netns del $(NETNS2) 2>/dev/null || true
	sudo ip netns add $(NETNS1)
	sudo ip netns add $(NETNS2)
	sudo ip link add $(IFACE_NS1) type veth peer name veth1
	sudo ip link set $(IFACE_NS1) netns $(NETNS1)
	sudo ip link set veth1 netns $(NETNS2)
	sudo ip netns exec $(NETNS1) ip addr add 10.0.0.1/24 dev $(IFACE_NS1)
	sudo ip netns exec $(NETNS2) ip addr add 10.0.0.2/24 dev veth1
	sudo ip netns exec $(NETNS1) ip link set $(IFACE_NS1) up
	sudo ip netns exec $(NETNS2) ip link set veth1 up
	@echo "✅ Network namespaces ready (ns1 <-> ns2)"

# ========================
# Load Dynamic Program
# ========================
load-dynamic: $(BPF_OBJ_DYN)
	@echo "🚀 Loading Dynamic Firewall on $(IFACE_NS1)..."

	# Montar /sys/fs/bpf dentro da namespace (se ainda não estiver)
	@sudo ip netns exec $(NETNS1) bash -c '\
		mkdir -p /sys/fs/bpf; \
		if ! mountpoint -q /sys/fs/bpf; then \
			echo "📦 Mounting BPF filesystem in ns1..."; \
			mount -t bpf bpf /sys/fs/bpf; \
		fi'

	# Carregar o programa XDP
	sudo ip netns exec $(NETNS1) ip link set dev $(IFACE_NS1) xdpgeneric obj $(BPF_OBJ_DYN) sec xdp
	@echo "✅ XDP program loaded successfully."

	# Obter IDs dos mapas e fazer o pin dentro da ns1
	@echo "📎 Pinning maps inside ns1..."
	@RID=$$(sudo ip netns exec $(NETNS1) bpftool map show | awk '/ name rules /{print $$1}' | tr -d ":"); \
	CID=$$(sudo ip netns exec $(NETNS1) bpftool map show | awk '/ name counters /{print $$1}' | tr -d ":"); \
	if [ -z "$$RID" ] || [ -z "$$CID" ]; then \
		echo "❌ Could not find maps (rules/counters). Check bpftool output."; exit 1; \
	fi; \
	sudo ip netns exec $(NETNS1) bpftool map pin id $$RID /sys/fs/bpf/rules; \
	sudo ip netns exec $(NETNS1) bpftool map pin id $$CID /sys/fs/bpf/counters; \
	echo "📌 Rules pinned -> /sys/fs/bpf/rules"; \
	echo "📌 Counters pinned -> /sys/fs/bpf/counters"
	@echo "✅ Dynamic Firewall fully loaded and pinned inside ns1."

# ========================
# Add / List Rules
# ========================
rule-add:
	@echo "➕ Adding DROP rule for UDP port $(PORT_BLOCK)..."
	sudo ip netns exec $(NETNS1) bash -c '\
		if [ ! -e /sys/fs/bpf/rules ]; then \
			echo "❌ Map not pinned. Run: make load-dynamic"; exit 1; fi; \
		bpftool map update pinned /sys/fs/bpf/rules key hex 11 03 ed value hex 01; \
		echo "✅ Rule added (UDP port 1005 -> DROP)";'

rule-list:
	sudo ip netns exec $(NETNS1) bash -c '\
		if [ -e /sys/fs/bpf/rules ]; then \
			echo "📜 Current rules:"; bpftool map dump pinned /sys/fs/bpf/rules; \
		else \
			echo "⚠️  No rules map pinned."; fi'

# ========================
# Test Packets
# ========================
test:
	@echo "🧪 Sending test UDP packets..."
	sudo ip netns exec $(NETNS2) bash -c 'for i in {1..5}; do echo -n "drop" | nc -u -w1 10.0.0.1 $(PORT_BLOCK); done'
	sudo ip netns exec $(NETNS2) bash -c 'for i in {1..5}; do echo -n "pass" | nc -u -w1 10.0.0.1 $(PORT_PASS); done'
	@echo "📊 Counters:"
	@sudo ip netns exec $(NETNS1) bpftool map dump pinned /sys/fs/bpf/counters

# ========================
# Cleanup
# ========================
clean:
	@echo "🧹 Cleaning up..."
	-sudo ip netns exec $(NETNS1) ip link set dev $(IFACE_NS1) xdpgeneric off 2>/dev/null || true
	-sudo ip link del $(IFACE_NS1) 2>/dev/null || true
	-sudo ip netns del $(NETNS1) 2>/dev/null || true
	-sudo ip netns del $(NETNS2) 2>/dev/null || true
	sudo rm -f /sys/fs/bpf/rules /sys/fs/bpf/counters 2>/dev/null || true
	rm -rf build
	@echo "✅ Clean complete!"

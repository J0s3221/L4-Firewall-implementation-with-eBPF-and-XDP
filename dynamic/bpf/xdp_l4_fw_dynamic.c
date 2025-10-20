// bpf/xdp_l4_fw_dynamic.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* counters map: index 0 = drops, index 1 = pass */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u64));
} counters SEC(".maps");

/* rule key: 1 byte proto + 2 bytes dest port (network byte order) => total 3 bytes */
struct rule_key {
    __u8 proto;     /* 6 = TCP, 17 = UDP */
    __be16 dport;   /* network byte order */
} __attribute__((packed));

/* rules map: hash keyed by rule_key, value = 1 byte action (0 = PASS, 1 = DROP) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __uint(key_size, sizeof(struct rule_key));
    __uint(value_size, sizeof(__u8));
} rules SEC(".maps");

/* helper: increment counter idx (0 drop, 1 pass) and return action */
static __always_inline int bump_counter_and_return(int idx, int action)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
    return action;
}

SEC("xdp")
int xdp_l4_fw_dynamic(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    /* L2 bounds */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    /* minimal VLAN handling (skip up to two 802.1Q headers) */
#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            if ((void *)eth + sizeof(*eth) + 4 > data_end)
                return bump_counter_and_return(1, XDP_PASS);
            __u16 *p = (void *)eth + sizeof(*eth) + 2;
            h_proto = *p;
            eth = (void *)eth + 4;
        }
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return bump_counter_and_return(1, XDP_PASS);

    /* IP header */
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return bump_counter_and_return(1, XDP_PASS);

    __u64 ip_hlen = ip->ihl * 4;
    if ((void *)ip + ip_hlen > data_end)
        return bump_counter_and_return(1, XDP_PASS);

    struct rule_key key = {};
    /* Only handle TCP and UDP for L4 rules */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) > data_end)
            return bump_counter_and_return(1, XDP_PASS);
        key.proto = IPPROTO_UDP;
        key.dport = udp->dest; /* already __be16 */
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return bump_counter_and_return(1, XDP_PASS);
        key.proto = IPPROTO_TCP;
        key.dport = tcp->dest; /* __be16 */
    } else {
        /* other protocols: pass */
        return bump_counter_and_return(1, XDP_PASS);
    }

    /* lookup rule */
    __u8 *action = bpf_map_lookup_elem(&rules, &key);
    if (action) {
        if (*action == 1)
            return bump_counter_and_return(0, XDP_DROP); /* DROP */
        else
            return bump_counter_and_return(1, XDP_PASS); /* PASS */
    }

    /* default: PASS */
    return bump_counter_and_return(1, XDP_PASS);
}

char _license[] SEC("license") = "GPL";

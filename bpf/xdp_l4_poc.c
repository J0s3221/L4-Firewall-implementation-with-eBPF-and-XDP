#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u64));
} counters SEC(".maps");

SEC("xdp")
int xdp_l4_poc(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        if (udp->dest == __constant_htons(53)) {
            int key = 0;   /* drop counter */
            __u64 *val = bpf_map_lookup_elem(&counters, &key);
            if (val) __sync_fetch_and_add(val, 1);
            return XDP_DROP;
        }
    }

    int key = 1;
    __u64 *val = bpf_map_lookup_elem(&counters, &key);
    if (val) __sync_fetch_and_add(val, 1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

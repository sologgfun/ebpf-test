//go:build ignore

#include <vmlinux.h>
// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>
// #include <linux/udp.h>
// #include <linux/in.h> // 添加此行以包含 IPPROTO_TCP 和 IPPROTO_UDP 的定义
// #include <linux/icmp.h> // 添加此行以包含 ICMP 的定义

struct traffic_event {
    __u8 src_ip[4];
    __u8 dst_ip[4];
    __u16 src_port;
    __u16 dst_port;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} traffic_map SEC(".maps");

SEC("xdp") int monitor_traffic(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    struct traffic_event event = {};
    event.bytes = data_end - data;

    __builtin_memcpy(event.src_ip, &ip->saddr, sizeof(event.src_ip));
    __builtin_memcpy(event.dst_ip, &ip->daddr, sizeof(event.dst_ip));

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        event.src_port = tcp->source;
        event.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        event.src_port = udp->source;
        event.dst_port = udp->dest;
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
        if ((void *)(icmp + 1) > data_end) {
            return XDP_PASS;
        }
        event.src_port = 0;
        event.dst_port = 0;
    }

    bpf_perf_event_output(ctx, &traffic_map, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
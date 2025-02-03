#define KBUILD_MODNAME "foo"
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682

struct vlan_hdr {
    __u16	h_vlan_TCI;
    __u16	h_vlan_encapsulated_proto;
};

static __always_inline int get_udpdport(void *trans_data, void *data_end,
        __u8 protocol)
{
    struct udphdr *uh;

    uh = (struct udphdr *)trans_data;
    if ((void *)(uh + 1) > data_end)
        return -1;
    return uh->dest;

}

#define VXLAN_HEADER_SIZE   8

static int __always_inline filter_ipv4(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    if (iph->protocol == IPPROTO_UDP) {
        if (get_udpdport(iph + 1, data_end, iph->protocol) == __constant_htons(4789)) {
            nh_off += VXLAN_HEADER_SIZE + sizeof(struct iphdr) + sizeof(struct udphdr);
            if (data + nh_off > data_end)
                return XDP_DROP;
            if (bpf_xdp_adjust_head(ctx, 0 + nh_off))
                return XDP_DROP;
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}

int SEC("xdp") xdp_loadfilter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == __constant_htons(ETH_P_IP))
        return filter_ipv4(ctx, data, nh_off, data_end);
    else
        return XDP_PASS;
}

char __license[] SEC("license") = "Stamus";

__u32 __version SEC("version") = LINUX_VERSION_CODE;

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

#include <stdbool.h>

#include "types.h"


struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __be64);
  __type(value, struct Router);
  __uint(max_entries, MAX_MAP_ENTRIES);
} router_map SEC(".maps");


SEC("tc") // rx
int tc_ingress(struct __sk_buff *skb)
{
    const int l3_off = ETH_HLEN;    // IP header offset
    const int l4_off = l3_off + 20; // TCP header offset: l3_off + sizeof(struct iphdr)
    __be32 sum;                     // IP checksum

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data_end < data + l4_off) { // not our packet
        return TC_ACT_OK;
    }

    struct iphdr *ip4 = (struct iphdr *)(data + l3_off);
    if (ip4->protocol != IPPROTO_TCP /* || tcp->dport == 80 */) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = (struct tcphdr*)(data + l4_off);
    if ((void *)(tcph + 1) > data_end) //
      return TC_ACT_OK;


    __be32 sourceIp = ip4->saddr;
    __be16 sourcePort = tcph->source;
    __be32 destIp = ip4->daddr;
    __be16 destPort = tcph->dest;

    __be64 key = (__be64)(((__be64)sourceIp)<<16) + (__be64)sourcePort;

    struct Router *value = bpf_map_lookup_elem(&router_map, &key);
    if (value != 0) {
        /*
        来源数据，保证是控制服务器来的数据
        sourceIP和sourcePort都是控制服务器的地址，并且于之通讯的被控端端口
        并且通讯的目的端口不能为空
        */
        if (sourceIp == value->cip && 
            sourcePort == value->cport && 
            value->nativeport != 0 ){       
            
            const __be32 client_port = value->nativeport;
            // SNAT: pod_ip -> cluster_ip, then update L3 and L4 header
            sum = bpf_csum_diff((void *)&tcph->dest, 4, (void *)&client_port, 4, 0);
            bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, dest), (void *)&client_port, 2, 0);
            bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);

            if (value->connport == 0) {
                struct Router tmp;
                __builtin_memcpy(&tmp, value, sizeof(struct Router));
                tmp.connport = destPort;
                bpf_map_update_elem(&router_map, &key, &tmp, BPF_ANY);
            }
        }
    }


    // const __be32 client_port = bpf_htons(g_backendserver_port);
    // // SNAT: pod_ip -> cluster_ip, then update L3 and L4 header
    // sum = bpf_csum_diff((void *)&tcph->dest, 4, (void *)&client_port, 4, 0);
    // bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, dest), (void *)&client_port, 2, 0);
	// bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);

    return TC_ACT_OK;
}

SEC("tc") // tx
int tc_egress(struct __sk_buff *skb)
{
    const int l3_off = ETH_HLEN;    // IP header offset
    const int l4_off = l3_off + 20; // TCP header offset: l3_off + sizeof(struct iphdr)
    __be32 sum;                     // IP checksum

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data_end < data + l4_off) { // not our packet
        return TC_ACT_OK;
    }

    struct iphdr *ip4 = (struct iphdr *)(data + l3_off);
    if (ip4->protocol != IPPROTO_TCP /* || tcp->dport == 80 */) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = (struct tcphdr*)(data + l4_off);
    if ((void *)(tcph + 1) > data_end) //
      return TC_ACT_OK;


    __be32 sourceIp = ip4->saddr;
    __be16 sourcePort = tcph->source;
    __be32 destIp = ip4->daddr;
    __be16 destPort = tcph->dest;

    __be64 key = (__be64)(((__be64)destIp)<<16) + (__be64)destPort;
    struct Router *value = bpf_map_lookup_elem(&router_map, &key);
    if (value != 0) {
        /*
        出网数据，必须保证destIP destPort 是控制端IP和端口，
        出网端口必须指定
        */
        if (destIp == value->cip && 
            destPort == value->cport && 
            value->connport != 0){
            
            const __be32 sourceport = value->connport;
            // SNAT: pod_ip -> cluster_ip, then update L3 and L4 header
            sum = bpf_csum_diff((void *)&tcph->source, 4, (void *)&sourceport, 4, 0);
            bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, source), (void *)&sourceport, 2, 0);
            bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);    

            if (value->nativeport == 0) {
                struct Router tmp;
                __builtin_memcpy(&tmp, value, sizeof(struct Router));
                tmp.nativeport = sourcePort;
                bpf_map_update_elem(&router_map, &key, &tmp, BPF_ANY);
            }
        }
    }



  return TC_ACT_OK;
}






char __license[] SEC("license") = "GPL";
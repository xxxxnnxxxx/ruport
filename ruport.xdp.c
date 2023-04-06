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

#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

// 获取信息
static __inline _Bool is_ins_package(void *data, void *data_end) {

  // 获取校验值
  // a^2 + b^2 = c
  __be16 s1 = *(__be16*)data;
  if ((void*)(data + 2 + sizeof(__be16)) > data_end)
    return false;
  __be16 s2 = *(__be16*)(data + 2);
  if ((void*)(data + 4 + sizeof(__be64)) > data_end)
    return false;
  __be64 s3 = *(__be64*)(data + 4);
  __be64 ss1 = (__be32)s1 * (__be32)s1;
  __be64 ss2 = (__be32)s2 * (__be32)s2;

  // 判断校验
  if (ss1 + ss2 != s3)
    return false;

  return true;
}

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __be64);
  __type(value, struct Message);
  __uint(max_entries, MAX_MAP_ENTRIES);
} message_map SEC(".maps");

static __inline void parse_package(void *data_begin, void *data_end) 
{
    struct ethhdr *eth = data_begin;

    // Check packet's size
    // the pointer arithmetic is based on the size of data type, current_address plus int(1) means:
    // new_address= current_address + size_of(data type)
    if ((void *)(eth + 1) > data_end) //
        return;

    // Check if Ethernet frame has IP packet
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1); // or (struct iphdr *)( ((void*)eth) + ETH_HLEN );
        if ((void *)(iph + 1) > data_end) 
          return;


        // ipv4
        if (iph->version != 4)
          return;

        // Check if IP packet contains a TCP segment
        if (iph->protocol != IPPROTO_TCP)
          return;
        // 
        struct tcphdr *tcph = (struct tcphdr*)((void*)iph + iph->ihl*4);
        if ((void *)(tcph + 1) > data_end) 
          return;

        // get the data fo tcp
        unsigned int len_total = bpf_ntohs(iph->tot_len);
        unsigned short lenofiph = iph->ihl*4;
        unsigned char lenoftcph = tcph->doff*4;

        unsigned char *pdata = (unsigned char*)((unsigned char*)tcph + tcph->doff*4);
        if ((void *)(pdata + 1) > data_end)
          return;

        // 判断是否为节点
        if ((data_end - (void*)pdata) < 12 + sizeof(struct Message)) {
          return;
        }
        if (!is_ins_package(pdata, data_end)){
          return;
        }

        struct Message msg;
        if ((void*)(pdata + 12 + sizeof(struct Message)) > data_end)
          return;

        ///
        msg.ins = *(__be16*)(pdata + 12);
        msg.cip = *(__be32*)(pdata + 14);
        msg.cport = *(__be16*)(pdata + 18);
        msg.connport = *(__be16*)(pdata + 20);
        msg.nativeport = *(__be16*)(pdata + 22);
        __builtin_memcpy(msg.ext, pdata + 24, LEN_DEFAULT_BUF);
        

        __be64 key = (__be64)((__be64)msg.cip << 16) + (__be64)msg.cport;

        // 计算获取结果
        struct Message *value = bpf_map_lookup_elem(&message_map, &key);
        if (value == 0) {
          bpfprint(":insert a message into the map.");
          bpf_map_update_elem(&message_map, &key, &msg, BPF_ANY);
        }

    }
    return;
}


SEC("xdp")
int xdp_parse(struct xdp_md *ctx)
{
  //bpfprint("Entering xdp section\n");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  int pkt_sz = data_end - data;

  parse_package(data, data_end);

  return XDP_PASS;
}


char __license[] SEC("license") = "GPL";

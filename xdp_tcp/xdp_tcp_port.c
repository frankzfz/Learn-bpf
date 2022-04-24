#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_vlan.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


static __always_inline int get_dport(void *trans_data, void *data_end, int protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void*)(th + 1) > data_end)
                return -1;
            return th->dest;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end)
                return -1;
            return uh->dest;
        default:
            return 0;
    }
    
}

SEC("mysection")
int myprogram(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  char fmt[] = "source = %d \n";
  struct iphdr *ip;
  int dport;
  int hdport;
  struct ethhdr *eth = data;
  struct iphdr *iph = data + sizeof(struct ethhdr);

    if ((void *)(iph + 1) > data_end) {
        return XDP_DROP;
    }

  dport = get_dport(iph + 1, data_end,iph->protocol);
  
  if (dport == -1 || dport == bpf_htons(8000)) {
        bpf_trace_printk(fmt,sizeof(fmt),bpf_ntohs(dport));
      return XDP_DROP;
  }
  
  return XDP_PASS;
}
char _license [] SEC ("license") = "GPL";

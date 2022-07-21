#!/usr/bin/env python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <uapi/linux/icmp.h>
#include <linux/icmp.h>
#include <uapi/linux/ip.h>
#include <linux/ip.h>


static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

int icmp_rcv_cb(struct pt_regs *ctx, struct sk_buff *skb)
{
            struct icmphdr *icmph ;
            struct iphdr *iph = skb_to_iphdr(skb);
            bpf_trace_printk("ipsrc:%pI4  ipdst:%pI4 \\n",&iph->saddr, &iph->daddr);
            icmph = (struct icmphdr *)skb->data;
            bpf_trace_printk("devname:%s ----- icmp_type:%d  \\n",skb->dev->name, icmph->type);
            return 0;
};

"""
# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="icmp_rcv", fn_name="icmp_rcv_cb")
#end format output
while 1:
    # Read messages from kernel pipe
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    print("task:%s pid: %d %s " % (task, pid, msg))
#b.trace_print()

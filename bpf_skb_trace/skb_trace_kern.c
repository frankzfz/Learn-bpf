#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/skbuff.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/icmp.h>
#include <bpf/bpf_core_read.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/compiler.h>

#include "skb_packet.h"
#include "skb_event.h"


struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(__u32));
        __uint(max_entries, 64);
} skb_event SEC(".maps");

#define MAX_STACK_DEPTH 50
struct {
     __uint(type, BPF_MAP_TYPE_STACK_TRACE);
     __uint(max_entries, 256);
     __uint(key_size, sizeof(__u32));
     __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
 } print_stack_map SEC(".maps");



typedef __u16  u16;
typedef __u8 u8;
typedef __u64 u64;

static void bpf_strncpy(char *dst, const char *src, int n)
{
    int i = 0, j;
 #define CPY(n) \
    do{  \
    for(;i<n;i++){ \
        if(src[i] == 0) return; \
            dst[i] = src[i]; \
        } \
    }while(0) \

    for (j = 10; j < 64; j += 10)
        CPY(j);
    CPY(64);
 #undef CPY
}

static inline char *safe_strncpy(char *dst, const char *src, size_t size)
{
      if (!size)
          return dst;
      strncpy(dst, src, size - 1);
       dst[size - 1] = '\0';
      return dst;
}

#define _(P)                                                                   \
  ({                                                                     \
         typeof(P) val = 0;                                             \
         bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
         val;                                                           \
    })

#define MAC_HEADER_SIZE 14;
#define member_address(source_struct, source_member)            \
    ({                                                          \
      void* __ret;                                            \
      __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
      __ret;                                                  \
      })                                                          

#define member_read(destination, source_struct, source_member)    \
    do{                                                           \
      bpf_probe_read(                                             \
      destination,                                              \
      sizeof(source_struct->source_member),                     \
      member_address(source_struct, source_member)              \
      );                                                          \
    }while(0)

static bool skb_l2_check(u16 header)
{
     return !header || header == (u16)~0U;
}

static bool skb_l4_check(u16 l4, u16 l3)
{
     return l4 == 0xFFFF || l4 <= l3;
}


/*static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
     // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
     return (struct tcphdr *)(_(skb->head) + _(skb->transport_header));
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
     // unstable API. verify logic in ip_hdr() -> skb_network_header().
     return (struct iphdr *)(_(skb->head) + _(skb->network_header));
}
*/

static int set_packet_data(struct sk_buff *skb,packet_data *pkt)
{
    char *skb_head = 0;
    u16 l4_off;
    u16 l3_off;
    void *ip;
    u8 iphdr_first_byte;
    u16 proto_l3;

    char *l2_header_address;
    char *l3_header_address;
    char *l4_header_address;

    u16 mac_header;
    u16 network_header;

    // struct tcphdr *tcp = skb_to_tcphdr(skb);


   //bpf_probe_read_kernel(&skb_head,sizeof(skb->head),skb->head);
   //member_read(&skb_head,skb, head);

   skb_head = BPF_CORE_READ(skb, head);
   l3_off = BPF_CORE_READ(skb, network_header);
   l4_off = BPF_CORE_READ(skb, transport_header);
   //member_read(&mac_header,skb, mac_header);
   //member_read(&network_header,skb, network_header);

    if(network_header == 0) {
       network_header = mac_header + MAC_HEADER_SIZE;
    }

    struct iphdr *tmp = (struct iphdr *) (skb_head + l3_off);
    bpf_probe_read(&iphdr_first_byte, sizeof(u8), tmp);
    proto_l3 = iphdr_first_byte >> 4 & 0xf;

    //ip = (void *) (l3_header_address);
    
    if(proto_l3 == ETH_P_IPV6)
    {
        struct ipv6hdr *ipv6;
        bpf_probe_read(ipv6, sizeof(ipv6), tmp);

        bpf_probe_read_kernel(pkt->l3.ipv6.saddr,sizeof(ipv6->saddr),&ipv6->saddr);
        bpf_probe_read_kernel(pkt->l3.ipv6.daddr,sizeof(ipv6->daddr),&ipv6->daddr);

        pkt->proto_l4 = ipv6->nexthdr;
    }
    else
    {
        //struct iphdr *ipv4 =(struct iphdr *)ip;
        struct iphdr ipv4;
        bpf_probe_read(&ipv4, sizeof(ipv4), tmp);
        __u8 proto_l4;

        u32 saddr, daddr;
        saddr = ipv4.saddr;
        daddr = ipv4.daddr;

        pkt->proto_l4 = ipv4.protocol;
        //proto_l4 = ipv4.protocol;
        pkt->l3.ipv4.saddr = saddr;
        pkt->l3.ipv4.daddr = daddr;
        if(saddr !=0 && daddr !=0)
        {
        char fmt[]="saddr=%pI4 daddr = %pI4\n";
        bpf_trace_printk(fmt,sizeof(fmt),&saddr,&daddr);
    }
 
       // bpf_probe_read_kernel(pkt->l3.ipv4.saddr,sizeof(ipv4_hdr->saddr),&ipv4_hdr->saddr);
       // bpf_probe_read_kernel(pkt->l3.ipv4.daddr,sizeof(ipv4_hdr->daddr),&ipv4_hdr->daddr);
        //pkt->proto_l4 = _(ipv4_hdr->protocol);
    }

    switch(pkt->proto_l4)
    {
        case IPPROTO_TCP:{
            
            //struct tcphdr *tcp = (struct tcphdr *)(l4_header_address);
            struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);
            bpf_probe_read(&pkt->l4.tcp.sport,sizeof(tcp->source),&tcp->source);
            bpf_probe_read(&pkt->l4.tcp.dport,sizeof(tcp->dest),&tcp->dest);
        }
        case IPPROTO_UDP:{

            //struct udphdr *udp = (struct udphdr *)(l4_header_address);

            struct udphdr *udp = (struct udphdr *) (skb_head + l4_off);
            bpf_probe_read(&pkt->l4.udp.sport,sizeof(udp->source),&udp->source);
            bpf_probe_read(&pkt->l4.udp.dport,sizeof(udp->dest),&udp->dest);
        }
        case IPPROTO_ICMP:{

            //struct icmphdr *icmp = (struct icmphdr *)(skb_head + l4_header_address);
            //struct icmphdr *icmp = (struct icmphdr *)(l4_header_address);
            struct icmphdr *icmp = (struct icmphdr *) (skb_head + l4_off);
            bpf_probe_read(&pkt->l4.icmp.code,sizeof(icmp->code),&icmp->code);
            bpf_probe_read(&pkt->l4.icmp.type,sizeof(icmp->type),&icmp->type);
            bpf_probe_read(&pkt->l4.icmp.seq,sizeof(icmp->un.echo.sequence),&icmp->un.echo.sequence);
        }
        break;
            goto err;
    }
    return 0;

err:
    return -1;
    
}


static int set_output(struct pt_regs *ctx,struct sk_buff *skb,skb_event_t *event_t)
{
    set_packet_data(skb,&event_t->pkt);
    return  1;

}
static int handle_packet_skb(struct sk_buff *skb,const char *fun_name,struct pt_regs *ctx)
{
    skb_event_t event_t = {}; 
    struct net_device *dev;
    char fmt[]="devname =%s\n";

 
    set_output(ctx,skb,&event_t);

    dev = _(skb->dev);
    bpf_probe_read_kernel(event_t.devname, sizeof(dev->name), dev->name);

    event_t.pid = bpf_get_current_pid_tgid();
    event_t.addr = PT_REGS_IP(ctx);
    bpf_strncpy(event_t.fun_name, fun_name, FUNCNAME_MAX_LEN);
    event_t.skb_addr = (u64) skb;
    event_t.ts = bpf_ktime_get_ns();
    event_t.cpu_id = bpf_get_smp_processor_id();


    bpf_perf_event_output(ctx, &skb_event, BPF_F_CURRENT_CPU, &event_t, sizeof(event_t));
    return 0;
}


SEC("kprobe/icmp_rcv")
//SEC("kprobe/__netif_receive_skb_core")
int icmp_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);

    return handle_packet_skb(skb,__func__,ctx);
}


//SEC("kprobe/ip_rcv")
SEC("kprobe/ip_rcv")
int ip_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);

    return handle_packet_skb(skb,__func__, ctx);
}

/*SEC("kprobe/tcp_v4_rcv")
int tcp_v4_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
  
    return handle_packet_skb(skb,__func__, ctx);
}
*/

SEC("kprobe/ip_local_deliver")
int ip_local_deliver(struct pt_regs *ctx)
{
    struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
  
    return handle_packet_skb(skb,__func__, ctx);
}

char  __license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;


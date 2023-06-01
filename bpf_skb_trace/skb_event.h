#ifndef  H_SKB_BPF_EVENT
#define  H_SKB_BPF_EVENT
 
#include "skb_packet.h"
//#include <bpf/bpf_helpers.h>


#define FUNCNAME_MAX_LEN 64
typedef struct {
        packet_data pkt;
        __u32 pid;
        __u64 addr;
        __u64 skb_addr;
        __u32 cpu_id;
        __u64 ts;
        __s64 print_stack_id;
        char devname[64];
        char fun_name[64];
} skb_event_t;

#endif



#ifndef SKB_PACKET
#define SKB_PACKET

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
 


typedef struct {
    union {
        struct {
            __u32 saddr;
            __u32 daddr;
        }ipv4;

        struct {
            __u8 saddr[16];
            __u8 daddr[16];
        }ipv6;
    } l3;

    union {
        struct {
            __u16 sport;
            __u16 dport;
            __u16 seq;
        }tcp;
    
        struct {
            __u16 sport;
            __u16 dport;
        }udp;

        struct {
            __u16 type;
            __u16 code;
            __u16 seq;
        }icmp;
    }l4;
    __u32 proto_l3;
    __u8 proto_l4;
} packet_data;


static inline void i2ip(char *dest, __u32 ip)
{
    __u8 *t = (__u8 *)&ip;
    sprintf(dest, "%d.%d.%d.%d", t[0], t[1], t[2], t[3]);
}

#define MAX_ADDR_LENGTH   48

/*struct config {
    u8 ipv6;
    union addr saddr;
    union addr daddr;
    u8 l4_proto;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct config);
} cfg_map SEC(".maps");
*/


/*typedef struct {
        void *data;
        struct sk_buff *skb;
        packet_data *pkt;
        __u16 mac_header;
        __u16 network_header;
        __u16 trans_header;
}parse_ctx;
*/

#endif

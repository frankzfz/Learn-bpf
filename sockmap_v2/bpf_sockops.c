#include "bpf_sockops.h"

static void sk_extract4_key(struct bpf_sock_ops *ops,struct sock_key *key)
{
    key->dip4 = ops->remote_ip4;
    key->sip4 = ops->local_ip4;
    key->family = 1;

    key->sport = ops->local_port;
    key->dport = bpf_ntohl(ops->remote_port);
}

static void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
    struct sock_key key = {};
    int ret;
    char info_fmt[] = "bpf_hash_update faile %d\n";
    char info_fmt1[] = "sockmap op:%d,port %d -- > %d\n";
    
    sk_extract4_key(skops,&key);

    ret = bpf_sock_hash_update(skops,&sock_ops_map,&key,BPF_NOEXIST);

    if(ret)
    {
            bpf_trace_printk(info_fmt,sizeof(info_fmt),ret);
    }

    bpf_trace_printk(info_fmt1,sizeof(info_fmt1),skops->op,key.sport,key.dport);

}


SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    __u32  family,op;
    
    family = skops->family;
    op = skops->op;

    switch(op)
    {
            case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
                if(family == AF_INET)
                {                
                    bpf_sock_ops_ipv4(skops);
                }
                break;
            default:
                break;
    }

    return 0;
}

 char _license[] SEC("license") = "GPL";


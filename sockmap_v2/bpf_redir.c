#include <stdint.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <sys/socket.h>

#include "bpf_sockops.h"

static void extract_key4_from_msg(struct sk_msg_md *msg,struct sock_key *key)
{
    key->sip4 = msg->remote_ip4;
    key->dip4 = msg->local_ip4;

    key->family = 1;

    key->dport = msg->local_port;
    key->sport = bpf_ntohl(msg->remote_port);
}


SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
    struct sock_key key = {};
    char info_fmt[] = "rediect port %d  ---> %d\n";
    int ret;

    if(msg->family != AF_INET)
        return SK_PASS;

    extract_key4_from_msg(msg, &key);

    ret = bpf_msg_redirect_hash(msg,&sock_ops_map,&key,BPF_F_INGRESS);


    if(ret != SK_PASS)
    {
        bpf_printk("bpf_msg_redirct_hash failed\n");
    }
    else
    {
        bpf_trace_printk(info_fmt,sizeof(info_fmt),msg->local_port,bpf_ntohl(msg->remote_port));
    }

    
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";

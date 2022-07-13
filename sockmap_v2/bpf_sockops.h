#ifndef BPF_SOCKOPS_H
#define BPF_SOCKOPS_H

#include <sys/socket.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bits/types.h>


#define MAX_SOCK_OPS_MAP_ENTRIES 65535

struct sock_key {
	__u32 sip4;
	__u32  dip4;
	__u8  family;
	__u8  pad1;
	__u16 pad2;
	// this padding required for 64bit alignment
	// else ebpf kernel verifier rejects loading
	// of the program
	__u32 pad3;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct bpf_map_def SEC("maps") sock_ops_map = {
    .type = BPF_MAP_TYPE_SOCKHASH,
    .key_size  = sizeof (struct sock_key),
    .value_size = sizeof (int),
    .max_entries = MAX_SOCK_OPS_MAP_ENTRIES,
    .map_flags = 0,
};

#endif




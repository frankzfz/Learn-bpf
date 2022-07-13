#!/bin/bash

set -x

set -e

mount -t bpf bpf /sys/fs/bpf/

clang -O2 -g -target bpf   -c bpf_sockops.c -o bpf_sockops.o

bpftool prog load bpf_sockops.o "/sys/fs/bpf/bpf_sockop"
bpftool cgroup attach "/root/cgroup2/" sock_ops pinned "/sys/fs/bpf/bpf_sockop"

MAP_ID=$(bpftool prog show pinned "/sys/fs/bpf/bpf_sockop" | grep -o -E 'map_ids [0-9]+' | awk '{print $2}')
bpftool map pin id $MAP_ID "/sys/fs/bpf/sock_ops_map"


clang -O2 -g -target bpf  -c bpf_redir.c -o bpf_redir.o
bpftool prog load bpf_redir.o "/sys/fs/bpf/bpf_redir" map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map"
bpftool prog attach pinned "/sys/fs/bpf/bpf_redir" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"

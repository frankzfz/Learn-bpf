#!/bin/bash
rm /sys/fs/bpf/bpf-tcp-rto
PROG_ID=$(bpftool prog show | grep set_init_rto | cut -d ":"  -f  1)
bpftool cgroup detach /root/cgroup2/ sock_ops id $PROG_ID

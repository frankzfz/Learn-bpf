#!/bin/bash
 bpftool prog load bpf_tcp_rto.o /sys/fs/bpf/bpf-tcp-rto
 PROG_ID=$(bpftool prog show | grep set_init_rto | cut -d ":"  -f  1)
 bpftool cgroup attach /root/cgroup2/ sock_ops id $PROG_ID


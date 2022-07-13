#!/bin/bash

set -x

bpftool prog detach pinned "/sys/fs/bpf/bpf_redir" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"
rm "/sys/fs/bpf/bpf_redir"

bpftool cgroup detach "/root/cgroup2/" sock_ops pinned "/sys/fs/bpf/bpf_sockop"
rm "/sys/fs/bpf/bpf_sockop"

rm "/sys/fs/bpf/sock_ops_map"

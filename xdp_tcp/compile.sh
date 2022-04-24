#!/bin/bash
clang -g -c -O2 -target bpf -c xdp_tcp_port.c -o xdp_tcp_port.o

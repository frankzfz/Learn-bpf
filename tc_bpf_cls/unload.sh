#!/bin/bash
IFNAME=$1
tc qdisc del dev $IFNAME clsact

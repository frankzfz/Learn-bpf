#Note:
cme frome linux-observability-with-bpf  chapter 6 BPF-Based Traffic Control Classifier,
Some code modifications were made to adapt to the new kernel version
machine environment: centos7.6   Linux kernel  5.16.11   kernel-src: v5.17  clang15


In the machine A:

Build the program
```bash
./build.sh
```

It will create an ELF file named `classifier.o`

Now, since this example is using Traffic Control as a loader, we don't need to build a loader
ourselves but we just use the `load.sh` script that uses `tc` to load the program on an interface
passed as first argument.


Since the program `classifier.c` writes with `bpf_trace_printk` it will dump the output to `/sys/kernel/debug/tracing/trace_pipe`.

A machine:

curl http//:[B machine IP]:8000

B machine:

python3 -m http.server
```

It will show:

```
if  ./load.sh eth0
sudo cat /sys/kernel/debug/tracing/trace_pipe
            <idle>-0       [002] d.s3.  4642.783085: bpf_trace_printk: Yes! It is HTTP!

if ./load_egress.sh eth0
 sudo cat /sys/kernel/debug/tracing/trace_pipe

            curl-4304    [002] d..2.  4682.426892: bpf_trace_printk: This is GET HTTP

```

At this point, you will want to unload the program, to do so:

sudo ./unload.sh eth0

commands:
tc exec bpf dbg
tc filter show dev eth0 egress
tc filter show dev eth0 ingress

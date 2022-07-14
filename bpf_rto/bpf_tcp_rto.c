#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>

SEC("sockops")
int set_init_rto(struct bpf_sock_ops *skops)
{
    const int timeout = 3;
    const int hz = 1000;

    int op = (int)skops->op;
    if (op == BPF_SOCK_OPS_TIMEOUT_INIT)
    {
        skops->reply = hz * timeout;
        bpf_printk("Set tcp connect timeout = %d\n",timeout);
        return 1;
    }

    bpf_printk("op = %d\n",op);
    return 1;
}

char _license[] SEC("license") = "GPL";

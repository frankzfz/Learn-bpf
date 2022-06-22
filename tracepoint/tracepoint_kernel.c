#include <stdlib.h>
#include <linux/types.h>
#include <stdio.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <fcntl.h>

  
struct syscalls_enter_openat_ctx {
    __u64 pad;
    int syscall_nr;
    const char *filename;
    int flags;
    unsigned short modep;

};

SEC("tracepoint/syscalls/sys_enter_openat")
int bpf_tp_prog(struct syscalls_enter_openat_ctx *ctx)
{
    char fmt[] = "tracepoint Hello Word!\n";
    int flags = ctx->flags;

    if ((flags & O_RDONLY) == O_RDONLY)
            bpf_trace_printk(fmt,sizeof(fmt));
    return 0;
}

char _license[] SEC("license") = "GPL";

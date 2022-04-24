#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
from collections import defaultdict

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE 256
struct data_t {
      u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
      char comm[TASK_COMM_LEN];
      char argv[ARGSIZE];
 };

BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx,
                   const char  __user *filename,
                   const char  __user *const __user *__argv,
                   const char  __user *const __user *__envp)
{
    struct data_t data = {};


    bpf_trace_printk("Hello, World!222%s\\n",filename);
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm,sizeof(data.comm));

    bpf_probe_read_user(data.argv, sizeof(data.argv), filename);

    events.perf_submit(ctx, &data, sizeof(struct data_t));

    return 0;
}

"""
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
print("%-18s %-16s %-14s" % ("COMM", "PID","ARGS"))


argv = defaultdict(list)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    argv[event.pid].append(event.argv)

    argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')

    print("%-18s %-16d  %-14s" % (event.comm, event.pid,argv_text))


b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

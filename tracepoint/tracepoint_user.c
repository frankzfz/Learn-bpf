#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <linux/bpf.h>


#define DEBUGFS "/sys/kernel/debug/tracing/"

void read_trace_pipe(void)
{
        int trace_fd;

        trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
        if (trace_fd < 0)
                return;

        while (1) {
                static char buf[4096];
                ssize_t sz;

                sz = read(trace_fd, buf, sizeof(buf) - 1);
                if (sz > 0) {
                        buf[sz] = 0;
                        puts(buf);
                }
        }
}

int main(int argc, char **argv)
{
    int fd;
    struct bpf_object *obj;
    int prog_fd;
    struct bpf_program *prog;
    struct bpf_link *link;

    if (bpf_prog_load("tracepoint_kernel.o", BPF_PROG_TYPE_TRACEPOINT,&obj, &prog_fd))
        return 1;

    prog = bpf_object__find_program_by_title(obj,"tracepoint/syscalls/sys_enter_openat");

   link =  bpf_program__attach_tracepoint(prog,"syscalls","sys_enter_openat");

    fd = open("file.txt",O_RDONLY);
    read_trace_pipe();

  return 0;

}

#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <unistd.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"

int load_bpf_file(char *path)
{
     struct bpf_object *obj;
     struct bpf_program *prog;
     struct bpf_link *link = NULL;
     int progs_fd;
 
     obj = bpf_object__open_file(path, NULL);
     if (libbpf_get_error(obj))
     {
         fprintf(stderr, "ERROR: opening BPF object file failed\n");
         return 0;
     }


     prog = bpf_object__find_program_by_name(obj, "bpf_prog");
     if (!prog) {
         printf("finding a prog in obj file failed\n");
         goto cleanup;
     }

     if (bpf_object__load(obj)) 
     {
         fprintf(stderr, "ERROR: loading BPF object file failed\n");
         goto cleanup;
     }


     link = bpf_program__attach(prog);
     if (libbpf_get_error(link)) {
         fprintf(stderr, "ERROR: bpf_program__attach failed\n");
         link = NULL;
         goto cleanup;
     }

cleanup:
     bpf_link__destroy(link);
     bpf_object__close(obj);
     return 0;
}

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
int main(int argc, char **argv) {
  if (load_bpf_file("bpf_program.o") != 0) {
    printf("The kernel didn't load the BPF program\n");
    return -1;
  }

  read_trace_pipe();

  return 0;
}

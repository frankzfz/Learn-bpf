#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include "skb_packet.h"
#include "skb_event.h"
#include "trace_helpers.h"
int proto_l4 = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void){
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if(setrlimit(RLIMIT_MEMLOCK, &rlim_new)){
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;
static void sig_handler(int sig){
	exiting = true;
}

static void handle_event(void *ctx, int cpu,void *data ,unsigned int data_size)
{
    skb_event_t *event_t = (skb_event_t *)data;
    char saddr[MAX_ADDR_LENGTH],daddr [MAX_ADDR_LENGTH];

    packet_data *pkt = &event_t->pkt;

    struct tm *tm;
	char ts[32];
	time_t t;

    i2ip(saddr, pkt->l3.ipv4.saddr);
    i2ip(daddr, pkt->l3.ipv4.daddr);

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    if(proto_l4 == pkt->proto_l4)
    {
        printf("%-10d %-20llx  %-10s  saddr->daddr:%-10s  %-15s %-20s\n",pkt->proto_l4,(unsigned long long)event_t->skb_addr,event_t->devname,saddr,daddr,event_t->fun_name);
        if(proto_l4 == 17)
        {
            printf("%-10d %-20llx  %-10s  saddr->daddr:%-10s:%d %-15s:%-10d %-20s\n",pkt->proto_l4,(unsigned long long)event_t->skb_addr,event_t->devname,saddr,pkt->l4.udp.sport,daddr,pkt->l4.udp.dport,event_t->fun_name);
        } 
        if(proto_l4 == 6 )
        {
            printf("%-10d %-20llx  %-10s  saddr->daddr:%-10s:%d %-15s:%-10d %-20s\n",pkt->proto_l4,(unsigned long long)event_t->skb_addr,event_t->devname,saddr,pkt->l4.tcp.sport,daddr,pkt->l4.tcp.dport,event_t->fun_name);
        } 
        if(pkt->proto_l4 == 1)
        {
            printf("%-10d %-20llx  %-10s  saddr->daddr:%-10s %-15s %-10d %-20s\n",pkt->proto_l4,(unsigned long long)event_t->skb_addr,event_t->devname,saddr,daddr,pkt->l4.icmp.type,event_t->fun_name);
        } 
    } 
    // printf("%-10d %-20llx  %-10s  ipsaddr->ipdaddr:%-10s  %-15s %-20s\n",pkt->proto_l4,(unsigned long long)event_t->skb_addr,event_t->devname,saddr,daddr,event_t->fun_name);
}

static const struct option long_options[] = {
     {"help",      no_argument,       NULL, 'h'},
     {"proto",     required_argument, NULL, 'p'},
};

static void usage(char *cmd)
{
    printf("eBPF trace Linux kernel skb packet!\n"
            "Usage: %s <options>\n"
            "       --help,   -h  this menu\n"
            "       --proto,  -p  <proto>  trace proto name\n"
            , cmd
          );
}

static int parse_command_line(int argc,char **argv)
{ 
    int longindex = 0;
    int opt;

    while ((opt = getopt_long(argc, argv, "hp:",long_options, &longindex)) != -1) {
        switch (opt) {
            case 'p':
                if(strcmp(optarg,"udp") == 0){
                    proto_l4 = 17; 
                } else if(strcmp(optarg,"tcp") == 0){
                    proto_l4 = 6;
                }else if(!strcmp(optarg,"icmp")){
                    proto_l4 = 1;
                }else{
                    fprintf(stderr, "ERROR: invalid arg : %s\n",
                            optarg);
                    usage(argv[0]);
                }
                break;
            case 'h':
            default:
                usage(argv[0]);
                return -1;
        }
    }
    return proto_l4;
}

int main(int argc,char **argv)
{
    struct perf_buffer *pb = NULL;
    struct perf_buffer_opts pb_opts = {};
    struct bpf_link *links[20];   
    struct bpf_link *link;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int map_fd, ret = 0;
	char filename[256],symbol[256];
    const char *section;
    int j = 0,proto_num;

    int err;

    proto_num = parse_command_line(argc, argv);
    
    if(proto_num < 0)
    {
        printf("arg Error！please input argv\n");
        return 0;
    }

    if (load_kallsyms()) {
        printf("failed to process /proc/kallsyms\n");
        return 2;
    }


	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "skb_event");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

    bpf_object__for_each_program(prog, obj) {
        section = bpf_program__section_name(prog);
           if (sscanf(section, "kprobe/%s", symbol) != 1)
               continue;
  
           // Attach prog only when symbol exists 
           if (ksym_get_addr(symbol)) {
               links[j] = bpf_program__attach(prog);
               if (libbpf_get_error(links[j])) {
                   fprintf(stderr, "bpf_program__attach failed\n");
                   links[j] = NULL;
                   goto cleanup;
               }
               j++;
           }
       }
 
/*	prog = bpf_object__find_program_by_name(obj, "ip_rcv");
	if (libbpf_get_error(prog)) {

		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

    */

	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(map_fd, 8, &pb_opts);
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return 1;
	}

    libbpf_set_print(libbpf_print_fn);

    bump_memlock_rlimit();

    signal(SIGINT,sig_handler);
    signal(SIGTERM,sig_handler);

    printf("%-10s %-20s %-30s  %-20s  %-10s %-20s\n","l4_proto","skb_addr","INTERFACE","PTK_INFO","TYPE","FUN_NAME");

    while(!exiting){
        err = perf_buffer__poll(pb,100);
        if(err == -EINTR){
            err = 0;
            break;
        }
        if(err  < 0){
            printf("Error polling perf buffer:%d\n",err);
            break;
        }
    }

cleanup:
    for(j--;j>0;j--)
    {
	    bpf_link__destroy(links[j]);
    } 
	bpf_object__close(obj);

    return ret; 

}

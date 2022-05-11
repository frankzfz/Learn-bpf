#include <linux/unistd.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bpf/bpf.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <stddef.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include "sock_example.h"

char bpf_log_buf[BPF_LOG_BUF_SIZE];


int main(int argc, char **argv) {
  int sock = -1, i, key, prog_fd,map_fd,value;
  int tcp_cnt, udp_cnt, icmp_cnt;
  struct bpf_object *obj;

  char filename[256];
  snprintf(filename, sizeof(filename), "%s", argv[1]);

  if (bpf_prog_load(filename, BPF_PROG_TYPE_SOCKET_FILTER,&obj, &prog_fd))
      return 1;

    map_fd = bpf_object__find_map_fd_by_name(obj, "countmap");


  sock = open_raw_sock("eth0");//Modified to available interface exp:lo  ping  127.0.0.1
  /*
   *
   *  FILE *f;

   f = popen("ping -4 -c5 localhost", "r");
   (void)f;

    */
  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,sizeof(prog_fd))) {
    printf("setsockopt %s\n", strerror(errno));
    return 0;
  }

  for (i = 0; i < 10; i++) {
    key = IPPROTO_TCP;
    assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

    key = IPPROTO_UDP;
    assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

    key = IPPROTO_ICMP;
    assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

    printf("TCP %d UDP %d ICMP %d packets\n", tcp_cnt, udp_cnt, icmp_cnt);
    sleep(1);
  }
cleanup:
   return 0;
}

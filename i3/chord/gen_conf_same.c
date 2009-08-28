#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include "chord.h"

int main(int argc, char **argv)
{
  int i, j, n;
  Node *nodes;
  in_addr_t addr;
  char filename[100];
  FILE *fp;
  struct in_addr ia;

  if (argc != 2) {
    fprintf(stderr, "ussage: %s num_servers\n", argv[0]);
    exit(-1);
  }
  n = atoi(argv[1]);
  srandom(getpid() ^ time(0));

  addr = ntohl(get_addr());

  nodes = (Node *) malloc(n * sizeof(Node));
  for (i = 0; i < n; i++) {
    nodes[i].id = rand_ID();
    nodes[i].addr = addr;
    nodes[i].port = 6500 + i;
  }

  for (i = 0; i < n; i++) {
    sprintf(filename, "conf.%d", i);
    fp = fopen(filename, "w");
    fprintf(fp, "%d ", nodes[i].port);
    print_id(fp, &nodes[i].id);
    fprintf(fp, "\n");
    for (j = 0; j < n; j++) {
      if (j == i) continue;
      ia.s_addr = htonl(nodes[j].addr);
      fprintf(fp, "%s:%d\n", inet_ntoa(ia), nodes[j].port);
    }
    fclose(fp);
  }

  return 0;
}

/*
 * Get data from client and send it back (echo server). Use this with
 * conntest-client.
 *
 * Bugs: 
 * - this is a kludge
 *
 * Todo:
 * - rewrite/refactor for better modularity
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netdb.h>
/* Workaround for some compilation problems on Debian */
#ifndef __user
#  define __user
#endif
#include <signal.h>
#include "conntest.h"

static void sig_handler(int signo) {
	if (signo == SIGTERM) {
		// close socket
		HIP_DIE("Sigterm\n");
	} else {
		HIP_DIE("Signal %d\n", signo);
	}
}

int main(int argc,char *argv[]) {

	int port;
	int type;

	if (signal(SIGTERM, sig_handler) == SIG_ERR) {
		exit(1);
	}
  
	if (argc != 3) {
		fprintf(stderr, "Usage: %s tcp|udp port\n", argv[0]);
		exit(1);
	}
	
	if (strcmp(argv[1], "tcp") == 0) {
		type = SOCK_STREAM;
	} else if (strcmp(argv[1], "udp") == 0) {
		type = SOCK_DGRAM;
	} else {
		fprintf(stderr, "error: protonum != tcp|udp\n");
		exit(1);
	}
  
	port = atoi(argv[2]);
	if (port <= 0 || port >= 65535) {
		fprintf(stderr, "error: port < 0 || port > 65535\n");
		exit(1);
	}

	main_server(type, port);

	return(0);
}

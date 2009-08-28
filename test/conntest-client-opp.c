/*
 * Echo STDIN to a selected machine via tcp or udp using ipv6. Use this
 * with conntest-server.
 *
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
#include <sys/time.h>
#include <time.h>
#include "debug.h"
#include "ife.h"

#include "conntest.h"

int main(int argc,char *argv[]) {
	
	int socktype, i, err = 0;
	char *type_name, *peer_port_name, *peer_name;
	const char *cfile = "default";

	hip_set_logtype(LOGTYPE_STDERR);
	hip_set_logfmt(LOGFMT_LONG);
	HIP_IFEL(hip_set_auto_logdebug(cfile), -1,
	  "Error: Cannot set the debugging parameter.\n");

	argc--;
	if (argc % 3 || argc < 3) {
		fprintf(stderr, "Usage: %s host tcp|udp port [host tcp|udp port...]\n", argv[0]);
		exit(1);
	}

	if (argc > 3) printf("Making %d connections...\n", argc / 3);

	for (i = 0; i < argc; i += 3)
	{
		peer_name = argv[i + 1];
		type_name = argv[i + 2];
		peer_port_name = argv[i + 3];
	
		if (strcmp(type_name, "tcp") == 0) {
			socktype = SOCK_STREAM;
		} else if (strcmp(type_name, "udp") == 0) {
			socktype = SOCK_DGRAM;
		} else {
			fprintf(stderr, "error: proto != tcp|udp\n");
			exit(1);
		}
		
		HIP_IFEL(main_client_gai(socktype, peer_name, peer_port_name,
			 0), -2,"Error: Cannot set the client.\n");
	}

 out_err:
	return err;

}

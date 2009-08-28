/*
 * Echo server: get data from client and send it back. Use this with
 * conntest-client-native.
 *
 * Bugs: 
 * - xx
 *
 * Todo:
 * - rewrite the kludge stuff
 * - use native API stuff
 * - reuse port!
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
#include <net/if.h>
/* Workaround for some compilation problems on Debian */
#ifndef __user
#  define __user
#endif
#include <signal.h>

#include "debug.h"

static void sig_handler(int signo) {
	if (signo == SIGTERM) {
		// close socket
		HIP_DIE("Sigterm\n");
	} else {
		HIP_DIE("Signal %d\n", signo);
	}
}

int main(int argc,char *argv[]) {
	int socktype;

	hip_set_logtype(LOGTYPE_STDERR);

	if (signal(SIGTERM, sig_handler) == SIG_ERR) {
		return(1);
	}
  
	if (argc < 3 || argc > 4) {
		HIP_ERROR("Usage: %s tcp|udp port [local_addr]\n", argv[0]);
		return(1);
	}
  
	if (strcmp(argv[1], "tcp") == 0) {
		socktype = SOCK_STREAM;
	} else if (strcmp(argv[1], "udp") == 0) {
		socktype = SOCK_DGRAM;
	} else {
		HIP_ERROR("error: uknown socket type\n");
		return(1);
	}

	if (argc == 3) {
		return(main_server_native(socktype, argv[2], NULL));
	} else {
		return(main_server_native(socktype, argv[2], argv[3]));
	}

}

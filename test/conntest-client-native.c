/*
 * Echo STDIN to a selected server which should echo it back.
 * Use this application with conntest-server-xx.
 *
 * usage: ./conntest-client-native host tcp|udp port
 *        (reads stdin)
 *
 * Notes:
 * - assumes that udp packets arrive in order (high probability within same
 *   network)
 * Bugs:
 * - none
 * Todo:
 * - rewrite/refactor for better modularity
 * @note: HIPU: does not work on MAC OS X
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
#include <arpa/inet.h>
#include <net/if.h>
#include "debug.h"
#include "ife.h"

#include "conntest.h"

int main(int argc,char *argv[]) {
	char *type_name, *peer_port_name, *peer_name;
	int socktype, err = 0;
	const char *cfile = "default";

	hip_set_logtype(LOGTYPE_STDERR);
	//hip_set_logfmt(LOGFMT_SHORT);
	HIP_IFEL(hip_set_auto_logdebug(cfile), -1,
	  "Error: Cannot set the debugging parameter.\n");


	if (argc != 4) {
		HIP_ERROR("Usage: %s host tcp|udp port\n", argv[0]);
		return(1);
	}
  
	peer_name = argv[1];
	type_name = argv[2];
	peer_port_name = argv[3];
  
	/* Set transport protocol */
	if (strcmp(type_name, "tcp") == 0) {
		socktype = SOCK_STREAM;
	} else if (strcmp(type_name, "udp") == 0) {
		socktype = SOCK_DGRAM;
	} else {
		HIP_ERROR("Error: only TCP and UDP supported.\n");
		return(1);
	}

	HIP_IFEL(main_client_native(socktype, peer_name, peer_port_name), -2,
	  "Error: Cannot set the client.\n");

 out_err:
	return err;


}

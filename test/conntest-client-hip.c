/** @file
 * A test client for testing connection between hosts. Use this in context
 * with conntest-server. "gai" stands for "give all information" :D
 *
 * @author  Lauri Silvennoinen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
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

#define MINPORTNUM 1
#define MAXPORTNUM 65535

/**
 * Main function.
 * 
 * @param argc command line argument count.
 * @param argv command line arguments.
 * @return     EXIT_FAILURE on failure, EXIT_SUCCESS on success.
 */
int main(int argc, char *argv[]) {
	
	int socktype = -1, err = 0;
	const char *cfile = "default";
	char usage[100];
	char ping_help[512];
	in_port_t port = 0;

	sprintf(usage, "Usage: %s <host> tcp|udp <port>", argv[0]);

	hip_set_logtype(LOGTYPE_STDERR);
	hip_set_logfmt(LOGFMT_SHORT);
	hip_set_logdebug(LOGDEBUG_MEDIUM);
	
	HIP_IFEL(hip_set_auto_logdebug(cfile), -1,
		 "Error: Cannot set the debugging parameter.\n");
	
	if(argc < 4) {
		HIP_INFO("Not enough arguments.\n%s\n", usage);
		return EXIT_FAILURE;
	}else if(argc > 4) {
		HIP_INFO("Too many arguments.\n%s\n", usage);
		return EXIT_FAILURE;
	}
	
	if (strcmp(argv[2], "tcp") == 0) {
		socktype = SOCK_STREAM;
	} else if (strcmp(argv[2], "udp") == 0) {
		socktype = SOCK_DGRAM;
	} else {
		HIP_INFO("Invalid protocol: '%s'\n%s\n", argv[2], usage);
		return EXIT_FAILURE;
	}
	
	port = atoi(argv[3]);

	/* Disabled since this comparison is always true with the current
	   port number boundaries.
	if(port < MINPORTNUM || port > MAXPORTNUM){
		HIP_INFO("Invalid port number, allowed port numbers are "\
			 "from %d to %d.\n%s\n", MINPORTNUM, MAXPORTNUM,
			 usage);
		return EXIT_FAILURE;
	}
	*/

	HIP_INFO("=== Testing %s connection to '%s' on port %s ===\n",
		 (socktype == SOCK_STREAM ? "TCP" : "UDP"), argv[1],
		 argv[3]);

	/* Call the main function to do the actual logic. */
	err = main_client_gai(socktype, argv[1], argv[3], 0);

 out_err:
	if(err == 0) {
		HIP_INFO("=== Connection test result: "\
			 "\e[92mSUCCESS\e[00m ===\n");
		return EXIT_SUCCESS;
	} else {
		_HIP_DEBUG("err: %d, errno: %d .\n", err, errno);

		/* Get a help string for pinging etc. */
		sprintf(ping_help, "You can try the 'ping', 'ping6', "\
			"'traceroute' or 'traceroute6' programs to\n"\
			"track down the problem.\n");
		
		/* Check our specially tailored 'err' values first.
		/* getaddrinfo() returns an error value as defined in
		   /usr/include/netdb.h. We have stored that error value in
		   errno. */
		if(err == -EHADDRINFO) {
			HIP_ERROR("Error when retrieving address information "\
				  "for the peer.\n");
			if(errno == EAI_NONAME) {
				HIP_ERROR("Connection refused.\nDo you have a "\
					  "local HIP daemon up and running?\n");
			} else if(errno == EAI_AGAIN) {
				HIP_ERROR("Temporary failure in name "\
					  "resolution.\n");
			}
		} else if(err == -EBADMSG) {
			HIP_INFO("Error when communicating with the peer.\n"\
				 "The peer is supposed to echo back the sent "\
				 "data,\nbut the sent and received data do "\
				 "not match.\n");
		}
		/* Then move to errno handling. Note that the errno is set
		   in somewhat randomly in libinet6 functions and therefore
		   these error messages do not neccessarily hold. Well, better
		   than nothing... */
		else if(errno == ECONNREFUSED) {
			HIP_ERROR("The peer was reached but it refused the "\
				  "connection.\nThere is no one listening on "\
				  "the remote address.\nIf you are trying to "\
				  "establish a HIP connection,\nyou need both "\
				  "a HIP daemon and a server running at the "\
				  "other end.\nFor an IP connection you only "\
				  "need a server running at the other end.\n");
		} else if(errno == ENOTSOCK) {
			HIP_ERROR("Socket operation on non-socket.\n"\
				  "Is the host you are trying to connect local");
			
		} else if(errno == ENETUNREACH) {
			HIP_ERROR("Network is unreachable.\n%s", ping_help);
		} else if(errno == EBADF) {
			HIP_ERROR("Bad file descriptor.\nThe file descriptor "\
				  "used when trying to connect to the remote "\
				  "host is not a\nvalid index in the "\
				  "descriptor table.\n");
		} else if(errno == EAFNOSUPPORT) {
			HIP_ERROR("Address family not supported by protocol.\n"\
				  "Only IPv4, IPv6 and HIP address families "\
				  "are supported.\nAre you trying to "\
				  "communicate between processes on the same "\
				  "machine?\n");
		}
		/* Just to make sure we don't print 'success' when the
		   connection test has actually failed we check errno != 0. */
		else if (errno != 0) {
			HIP_PERROR("");
		}

		HIP_INFO("=== Connection test result: "\
			 "\e[91mFAILURE\e[00m ===\n");
		
		return EXIT_FAILURE;
	}
}

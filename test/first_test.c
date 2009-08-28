/*
 * Program which allows for measuring the base exchange between two hosts of HIP in userspace.
 * At the moment the results (time of connection: BEX + TCP handshaking) are saved
 * into the default file /tmp/results.txt
 *
 * Authors:
 * - Beltrami Diego <diego.beltrami@gmail.com>
 *
 * Licence: GNU/GPL
 *
 * TODO:
 * - decide whether to save results in file or not
 * - build an "on-purpose" kernel/daemon which allows to measure the BEX time
 *
 * BUGS:
 *
 */

#include "first_test.h"

extern char *optarg;
extern int optind, opterr, optopt;

const char *usage_str = "first_test -h for help\n"
	"first_test               to run one base exchange\n"
	"first_test -n [NUM]      to run NUM times the base exchange\n"
	"\n"
	;

void usage_f()
{
	printf("Usage:\n%s\n", usage_str);
}

/**
 * send_bos(): it allows to send a BOS packet
 *
 * Returns:0 on success, non-zero value on error
 */
int send_bos()
{
	struct hip_common *msg;
	int err = 0;
	
	msg = malloc(HIP_MAX_PACKET);
	if (!msg) {
		HIP_ERROR("malloc failed\n");
		goto out;
	}
	hip_msg_init(msg);

	printf("Sending BOS... ");
	err = hip_conf_handle_bos(msg, 0, (const char **) NULL, 0, 0);
	if (err) {
		HIP_ERROR("\nfailed to handle msg\n");
		goto out_err;
	}
	
	if (hip_get_msg_type(msg) == 0) {
		err = -1;
		goto out_err;
	}
	
	err = hip_send_recv_daemon_info(msg, 0, 0);
	if (err) {
		HIP_ERROR("\nsending msg failed\n");
		goto out_err;
	}
	printf(" SENT\n");
out_err:
	free(msg);
out:
	return err;
}

/**
 * u_install_modules: it allows the modules and rerun the HIP daemon
 *
 * Returns:0 on success, non-zero value on error
 */
int u_install_modules() 
{
	struct hip_common *msg;
	int err = 0;
        /* Initializing the msg for installing the modules */
	msg = malloc(HIP_MAX_PACKET);
	if (!msg) {
		HIP_ERROR("malloc failed\n");
		err = -1;
		goto out;
	}
	hip_msg_init(msg);

	err = main_install(msg);
	if (err)
		goto out_err;
out_err:
	free(msg);
out:
	return err;
	
}

/**
 * handle_single_connection: general function which handles the connection
 * between two hosts. The used policy is that the host having higher HIT is
 * set to be the initiator. The connection is established when a BOS packet is
 * received. In order to established whether the BOS packet has been received,
 * the presence of at least one entry in the database is checked.
 *
 * Returns:0 on success, non-zero value on error
 */
int handle_single_connection()
{
	int err = 0, port = DEFAULT_PORT, i, sock = 0;

	struct in6_addr my_hit, any = IN6ADDR_ANY_INIT;
	struct addrinfo hints, *res = NULL, *ai;
	char buf[20];

	if (u_install_modules())
		goto out_err;
	printf("\n");
	sleep(5);
	
	/* Retrieving our HIT */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_HIP | AI_PASSIVE;
	hints.ai_family = AF_INET6; /* Legacy API supports only HIT-in-IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	sprintf(buf, "%d",DEFAULT_PORT);
	err = getaddrinfo(NULL, buf, &hints, &res);

	if (err) {
		printf("GAI ERROR %d: %s\n", err, gai_strerror(err));
		return(1);
	}
	if (res) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) res->ai_addr;
		ipv6_addr_copy(&my_hit, &sin6->sin6_addr);
		/* Now that I have the HIT I can free the memory allocated for res */
		freeaddrinfo(res);
		res = NULL;
	} else {
		HIP_ERROR("Cannot find my HIT\n");
		goto out_err;
	}
	
	/* By calling getaddrinfo with the flags set to AI_HIP | AI_KERNEL_LIST, the beet database
	 * is scrolled and if any entry is found, then it means that the BOS packets has been received
	 */
	hints.ai_flags = AI_HIP | AI_KERNEL_LIST;
		
	while (!res) {
		/* BOS */
		if (send_bos())
			goto out_err;
		sleep(5);
			
		err = getaddrinfo(NULL, buf, &hints, &res);
		if (err < 0) {
			printf("GAI ERROR %d: %s\n", err, gai_strerror(err));
			return(1);
		} else if (err > 0) {
			/*The BOS packet has been received because at least one entry has been found*/
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) res->ai_addr;
			
			HIP_HEXDUMP("sin6->sin6_addr is: ", &sin6->sin6_addr, 16);
			
			if (ipv6_addr_cmp(&my_hit, &sin6->sin6_addr) > 0) {
				/* my_hit is greater ---> I am the initiator */
				printf("Initiator mode ...\n");
				
				hip_set_logtype(LOGTYPE_STDERR);
				hip_set_logfmt(LOGFMT_SHORT);

				hip_connect_func(res, &sock);
				if (sock)
					close(sock);
				
			} else {
				int peer, serversock;
				unsigned int peerlen = sizeof(struct sockaddr_in6);
				struct sockaddr_in6 peeraddr;
				/* my_hit is smaller ---> I am the responder */
				printf("Responder mode ...\n");

				serversock = create_serversocket(SOCK_STREAM, DEFAULT_PORT);
				/* Base Exchange Responder */
				peer = accept(serversock, (struct sockaddr *)&peeraddr, &peerlen);
				if (peer < 0) {
					perror("accept");
					if (res)
						freeaddrinfo(res);
					goto out_err;
				}
				close(peer);
				close(serversock);
			}
			printf("Connection closed\n");
		} else {
				
			if (res)
				freeaddrinfo(res);
			res = NULL;
		}
	}
		
	if (res)
		freeaddrinfo(res);
		
out_err:
	return err;
}

/**
 * main: if the number of times the connection has to be estalibhed (n option)
 * only one base exchange is run. Otherwise the connection is established Ntimes times.
 * At the end, if everything goes well, the connection is kept established.
 * At the moment, in order to restart the connection, the modules and HIP daemon
 * are reset.
 *
 * Returns:0 on success, non-zero value on error
 */
int main(int argc, char *argv[])
{
	int c, err = 0, Ntimes = 1, i;

	if(argc > 3){
		printf("Number of args wrong \n");
		usage_f();
		return 0;
	}
	
	while ((c = getopt(argc, argv, ":hn:")) != -1)
	{
		switch (c){
		case 'h':
			usage_f();
			goto out_err;
		case 'n':
			Ntimes = atoi(optarg);
			printf("NTimes = %d\n", Ntimes);
			if (Ntimes <= 0) {
				HIP_ERROR("The specified number cannot be negative or zero\n");
				goto out_err;
			}
			break;
		case ':':
			/*Missing arguments*/
			Ntimes = 1;
			break;
		case '?':
			printf("Unknown option %c\n", optopt);
			usage_f();
			goto out_err;
		}
	}

	for (i = 0; i < Ntimes; i++) {
		err = handle_single_connection();
		if (!err)
			goto out_err;
	}

out_err:
	return err;

}

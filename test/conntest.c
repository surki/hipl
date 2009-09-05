#include "conntest.h"

/* @todo: why the heck do we need this here on linux? */
struct in6_pktinfo
{
  struct in6_addr ipi6_addr;  /* src/dst IPv6 address */
  unsigned int ipi6_ifindex;  /* send/recv interface index */
};

/**
 * create_serversocket - given the port and the protocol
 * it binds the socket and listen to it
 * @param proto type of protocol
 * @param port the kind of protocol
 *
 * @return the socket id,
 * exits on error.
 */
int create_serversocket(int type, in_port_t port) {
	int fd = -1, on = 1, err = 0;
	struct sockaddr_in6 addr;
	
	fd = socket(AF_INET6, type, 0);
	if (fd < 0) {
		perror("socket");
		err = -1;
		goto out_err;
	}

	/* Receive anchillary data with UDP */
        err = setsockopt(fd, IPPROTO_IPV6,
			 IPV6_2292PKTINFO, &on, sizeof(on));
	if (err != 0) {
		perror("setsockopt IPV6_RECVPKTINFO");
		goto out_err;
	}

	err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (err != 0) {
		perror("setsockopt SO_REUSEADDR,");
		goto out_err;
	}

	/* UDP cannot bind to both IPv4 and IPv6 */
	if (type == SOCK_DGRAM) {
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
				 &on, sizeof(on));
		if (err != 0) {
			perror("setsockopt IPV6_V6ONLY");
			goto out_err;
		}
	}

 	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;
	addr.sin6_flowinfo = 0;
	
	if (bind(fd, (struct sockaddr *)&addr,
		 sizeof(struct sockaddr_in6)) < 0) {
		perror("bind");
		err = -1;
		goto out_err;
	}

	if (type == SOCK_STREAM) {
		if (listen(fd, 1) < 0) {
			perror("listen");
			err = -1;
			goto out_err;
		}
	}

out_err:
	if (err) {
		close(fd);
		fd = -1;
	}

	return fd;
}

int main_server_tcp(int serversock) {
	int peerfd = 0, err = 0;
	socklen_t locallen;
	unsigned int peerlen;
	struct sockaddr_in6 localaddr, peeraddr;
	char mylovemostdata[IP_MAXPACKET];
	int recvnum, sendnum;
	char addrstr[INET6_ADDRSTRLEN];

	peerlen = sizeof(struct sockaddr_in6);

	peerfd = accept(serversock, (struct sockaddr *)&peeraddr, &peerlen);
	
	if (peerfd < 0) {
		perror("accept");
		err = -1;
		goto out_err;
	}

	locallen = sizeof(localaddr);
	if (!getsockname(serversock,
			 (struct sockaddr *)&localaddr,
			 &locallen))
		HIP_DEBUG_HIT("local addr", &localaddr.sin6_addr);
	HIP_DEBUG_HIT("peer addr", &peeraddr.sin6_addr);
	
	while((recvnum = recv(peerfd, mylovemostdata,
			      sizeof(mylovemostdata), 0)) > 0 ) {
		mylovemostdata[recvnum] = '\0';
		printf("Client sends:\n%s", mylovemostdata);
		fflush(stdout);
		if (recvnum == 0) {
			close(peerfd);
			err = -1;
			break;
		}
		
		/* send reply */
		sendnum = send(peerfd, mylovemostdata, recvnum, 0);
		if (sendnum < 0) {
			perror("send");
			err = -1;
			break;
		}
		printf("Client has been replied.\n");
	}
	if (peerfd)
		close(peerfd);

out_err:
	return err;
}

int create_udp_ipv4_socket(in_port_t local_port) {
	int ipv4_sock = -1, err = 0, on = 1, sendnum;
	struct sockaddr_in inaddr_any;

	/* IPv6 "server" sockets support incoming IPv4 packets with
	   IPv4-in-IPv6 format. However, outgoing packets with IPv4-in-IPv6
	   formatted address stop working in some kernel version. Here
	   we create a socket for sending IPv4 packets. */
	ipv4_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (ipv4_sock < 0) {
		printf("ipv4 socket\n");
		err = -1;
		goto out_err;
	}

	err = setsockopt(ipv4_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (err != 0) {
		perror("setsockopt SO_REUSEADDR");
		goto out_err;
	}

        err = setsockopt(ipv4_sock, IPPROTO_IP,
			 IP_PKTINFO, &on, sizeof(on));
	if (err != 0) {
		perror("setsockopt IP_PKTINFO");
		goto out_err;
	}

	/* Weird, but we have to set this option to receive
	   IPv4 addresses for UDP. We don't get them in mapped format. */ 
        err = setsockopt(ipv4_sock, IPPROTO_IP,
			 IP_PKTINFO, &on, sizeof(on));
	if (err != 0) {
		perror("setsockopt IP_PKTINFO");
		goto out_err;
	}

	_HIP_DEBUG("my local port %d\n", local_port);

	inaddr_any.sin_family = AF_INET;
	inaddr_any.sin_port = htons(local_port);
	inaddr_any.sin_addr.s_addr = htonl(INADDR_ANY);
	err = bind(ipv4_sock, (struct sockaddr *) &inaddr_any,
		   sizeof(inaddr_any));
	if (err) {
		perror("bind\n");
		goto out_err;
	}

out_err:
	if (err == 0)
		return ipv4_sock;
	else
		return -1;

}

int udp_send_msg(int sock, uint8_t *data, size_t data_len,
		 struct sockaddr *local_addr,
		 struct sockaddr *peer_addr) {
	int err = 0, on = 1, sendnum;
	int is_ipv4 = ((peer_addr->sa_family == AF_INET) ? 1 : 0);
	uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        struct cmsghdr *cmsg; // = (struct cmsghdr *) cmsgbuf;
	struct msghdr msg;
	struct iovec iov;
	union {
		struct in_pktinfo *in4;
		struct in6_pktinfo *in6;
	} pktinfo;

	/* The first memset is mandatory. Results in otherwise weird
	   EMSGSIZE errors. */
	memset(&msg, 0, sizeof(struct msghdr));	
	memset(cmsgbuf, 0, sizeof(cmsgbuf));

	/* Fill message header */

	msg.msg_name = peer_addr;
	if (is_ipv4)
		msg.msg_namelen = sizeof(struct sockaddr_in);
	else
		msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;
	
	iov.iov_base = data;
	iov.iov_len = data_len;

	/* Set local address */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (is_ipv4)
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	else
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsg->cmsg_level = (is_ipv4) ? IPPROTO_IP : IPPROTO_IPV6;
	cmsg->cmsg_type = (is_ipv4) ? IP_PKTINFO : IPV6_2292PKTINFO;

	pktinfo.in6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
	if (is_ipv4)
		pktinfo.in4->ipi_addr.s_addr =
			((struct sockaddr_in *) local_addr)->sin_addr.s_addr;
	else
		memcpy(&pktinfo.in6->ipi6_addr,
		       &(((struct sockaddr_in6 *) local_addr)->sin6_addr),
		       sizeof(struct in6_addr));
	
	/* Send reply using the ORIGINAL src/dst address pair */
	sendnum = sendmsg(sock, &msg, 0);
	if (sendnum < 0) {
		perror("sendmsg");
		err = -1;
		goto out_err;
	}
	
	printf("=== Sent string successfully back ===\n");
	printf("=== Server listening IN6ADDR_ANY ===\n");

out_err:

	return err;
}

int main_server_udp(int ipv4_sock, int ipv6_sock, in_port_t local_port) {
	/* Use recvmsg/sendmsg instead of recvfrom/sendto because
	   the latter combination may choose a different source
	   HIT for the server */
	int err = 0, on = 1, recvnum, sendnum, is_ipv4 = 0;
	int cmsg_level, cmsg_type, highest_descriptor = -1;
        fd_set read_fdset;
	union {
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} peer_addr, local_addr;
	uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	uint8_t mylovemostdata[IP_MAXPACKET];
	struct iovec iov;
        struct cmsghdr *cmsg = (struct cmsghdr *) cmsgbuf;
	union {
		struct in_pktinfo *in4;
		struct in6_pktinfo *in6;
	} pktinfo;
	struct msghdr msg;

	FD_ZERO(&read_fdset);
	FD_SET(ipv4_sock, &read_fdset);
	FD_SET(ipv6_sock, &read_fdset);
	highest_descriptor = maxof(2, ipv4_sock, ipv6_sock);

	printf("=== Server listening INADDR_ANY/IN6ADDR_ANY ===\n");
	
	while(select((highest_descriptor + 1), &read_fdset,
		     NULL, NULL, NULL)) {

		/* XX FIXME: receiving two packets at the same time */

		if (FD_ISSET(ipv4_sock, &read_fdset)) {
			is_ipv4 = 1;
			//FD_CLR(ipv4_sock, &read_fdset);
		} else if (FD_ISSET(ipv6_sock, &read_fdset)) {
			is_ipv4 = 0;
			//FD_CLR(ipv6_sock, &read_fdset);
		} else {
			printf("Unhandled select event\n");
			goto reset;
		}

		msg.msg_name = &peer_addr.in6;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
		msg.msg_flags = 0;
		
		iov.iov_base = mylovemostdata;
		iov.iov_len = sizeof(mylovemostdata);
		
		memset(mylovemostdata, 0, sizeof(mylovemostdata));
		memset(&peer_addr, 0, sizeof(peer_addr));
		memset(cmsgbuf, 0, sizeof(cmsgbuf));

		recvnum = recvmsg((is_ipv4 ? ipv4_sock : ipv6_sock), &msg, 0);
		if (recvnum < 0) {
			perror("recvmsg\n");
			goto reset;
		}
		printf("Received %d bytes\n", recvnum);

		//is_ipv4 = IN6_IS_ADDR_V4MAPPED(&peer_addr.in6.sin6_addr);
	
		cmsg_level = (is_ipv4) ? IPPROTO_IP : IPPROTO_IPV6;
		cmsg_type = (is_ipv4) ? IP_PKTINFO : IPV6_2292PKTINFO;
	
		/* Local address comes from ancillary data passed
		 * with msg due to IPV6_PKTINFO socket option */
		for (cmsg=CMSG_FIRSTHDR(&msg); cmsg;
		     cmsg=CMSG_NXTHDR(&msg,cmsg)){
			if ((cmsg->cmsg_level == cmsg_level) &&
			    (cmsg->cmsg_type == cmsg_type)) {
				/* The structure is a union, so this fills
				   also the pktinfo_in6 pointer */
				pktinfo.in4 =
					(struct in_pktinfo *)CMSG_DATA(cmsg);
				break;
			}
		}
	
		if (is_ipv4) {
			local_addr.in4.sin_family = AF_INET;
			local_addr.in4.sin_port = htons(local_port);
			//local_addr.in4.sin_port = peer_addr.in6.sin6_port;
			local_addr.in4.sin_addr.s_addr =
				pktinfo.in4->ipi_addr.s_addr;
			HIP_DEBUG_INADDR("local addr",
					 &local_addr.in4.sin_addr);
			HIP_DEBUG("local port %d\n",
				  ntohs(local_addr.in4.sin_port));
			HIP_DEBUG_INADDR("peer addr",
					 &peer_addr.in4.sin_addr);
			HIP_DEBUG("peer port %d\n",
				  ntohs(peer_addr.in4.sin_port));
			
		} else {
			local_addr.in6.sin6_family = AF_INET6;
			memcpy(&local_addr.in6.sin6_addr,
			       &pktinfo.in6->ipi6_addr,
			       sizeof(struct in6_addr));
			local_addr.in6.sin6_port = htons(local_port);
			HIP_DEBUG_IN6ADDR("local addr",
					  &local_addr.in6.sin6_addr);
			HIP_DEBUG("local port %d\n",
				  ntohs(local_addr.in6.sin6_port));
			HIP_DEBUG_IN6ADDR("peer addr",
					  &peer_addr.in6.sin6_addr);
			HIP_DEBUG("peer port %d\n",
				  ntohs(peer_addr.in6.sin6_port));
		}

		err = udp_send_msg((is_ipv4 ? ipv4_sock : ipv6_sock),
				   mylovemostdata, recvnum,
				   (struct sockaddr *) &local_addr,
				   (struct sockaddr *) &peer_addr);
		if (err) {
			printf("Failed to echo data back\n");
		}

	reset:

		FD_ZERO(&read_fdset);
		FD_SET(ipv4_sock, &read_fdset);
		FD_SET(ipv6_sock, &read_fdset);
	}

out_err:
	return err;
}

/**
 * main_server - given the port and the protocol
 * it handles the functionality of the responder
 * @param proto type of protocol
 * @param port the kind of protocol
 *
 * @return the socket id,
 * exits on error.
 */
int main_server(int type, in_port_t port)
{
	int ipv6_sock = 0, err = 0, ipv4_sock = -1;
	
	ipv6_sock = create_serversocket(type, port);
	if (ipv6_sock < 0)
		err = -1;

	/* Create a separate IPv4 socket for receiving and sending UDP
	   packets even though a single IPv6 socket could be used
	   for receiving IPv4 packets, but not sending them. */
	if (type == SOCK_DGRAM) {
		ipv4_sock = create_udp_ipv4_socket(port);
		if (ipv4_sock < 0) {
			printf("Could not create ipv4 socket\n");
			err = -1;
			goto out_err;
		}
	}
  
	while(err == 0) {
		if (type == SOCK_STREAM) {
			err = main_server_tcp(ipv6_sock);
		} else {
			err = main_server_udp(ipv4_sock, ipv6_sock, port);
		}
	}

out_err:

	if (ipv6_sock)
		close(ipv6_sock);
	if (ipv4_sock < 0)
		close(ipv4_sock);
	return err;
}

/**
 * Creates a socket and connects it a remote socket address. The connection is
 * tried using addresses in the @c peer_ai in the order specified by the linked
 * list of the structure. If a connection is successful, the rest of the
 * addresses are omitted. The socket is bound to the peer HIT, not to the peer
 * IP addresses.
 *
 * @param peer_ai a pointer to peer address info.
 * @param sock    a target buffer where the socket file descriptor is to be
 *                stored.
 * @return        zero on success, negative on failure. Possible error values
 *                are the @c errno values of socket(), connect() and close()
 *                with a minus sign.
 */
int hip_connect_func(struct addrinfo *peer_ai, int *sock)
{
	int err = 0, connect_err = 0;
	unsigned long microseconds = 0;
	struct timeval stats_before, stats_after;
	char ip_str[INET6_ADDRSTRLEN];
	struct addrinfo *ai = NULL;
	struct in_addr *ipv4 = NULL;
	struct in6_addr *ipv6 = NULL;

	/* Set the memory allocated from the stack to zeros. */
	memset(&stats_before, 0, sizeof(stats_before));
	memset(&stats_after, 0, sizeof(stats_after));
	memset(ip_str, 0, sizeof(ip_str));
	
	/* Loop through every address in the address info. */
	for(ai = peer_ai; ai != NULL; ai = ai->ai_next) {
	        if (ai->ai_family == AF_INET)
		  _HIP_DEBUG("AF_INET\n");
		else
		  _HIP_DEBUG("af_inet6\n");
	}
	for(ai = peer_ai; ai != NULL; ai = ai->ai_next) {
	        ipv4 = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
		ipv6 = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;

		/* Check the type of address we are connecting to and print
		   information about the address to the user. If address is
		   not supported the move to next address in peer_ai. */
		if (ai->ai_family == AF_INET) {
			inet_ntop(AF_INET, ipv4, ip_str, sizeof(ip_str));
			
			if(IS_LSI32(ipv4->s_addr)) {
				HIP_INFO("Connecting to LSI %s.\n", ip_str);
			} else {
				HIP_INFO("Connecting to IPv4 address %s.\n",
					 ip_str);
			}
		} else if(ai->ai_family == AF_INET6 ||
			  ai->ai_family == AF_HIP) {
			inet_ntop(AF_INET6, ipv6, ip_str, sizeof(ip_str));
			
			if(ipv6_addr_is_hit(ipv6)){
				HIP_INFO("Connecting to HIT %s.\n", ip_str);
			} else if (IN6_IS_ADDR_V4MAPPED(ipv6)) {
				HIP_INFO("Connecting to IPv6-mapped IPv4 "\
					 "address %s.\n", ip_str);
			} else {
				HIP_INFO("Connecting to IPv6 address %s.\n",
					 ip_str);
			}
		} else {
			_HIP_DEBUG("Trying to connect to a non-inet address "\
				  "family address. Skipping.\n");
			/* If there are no more address in peer_ai, these err
			   and errno values are returned. */
			errno = EAFNOSUPPORT;
			err = -1;
			continue;
		}

		err = 0;
		errno = 0;
		
		/* Get a socket for sending. */
		*sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if(*sock < 3) {
			HIP_ERROR("Unable to get a socket for sending.\n");
			err = -1;
			goto out_err;
		}
		
		gettimeofday(&stats_before, NULL);
		connect_err = connect(*sock, ai->ai_addr, ai->ai_addrlen);
		
		/* If we're unable to connect to the remote address we try next
		   address in peer_ai. We back off if the closing of the socket
		   fails. */
		if(connect_err != 0){
			_HIP_ERROR("Unable to connect to the remote address.\n");
			if(close(*sock) != 0) {
				HIP_ERROR("Unable to close a socket.\n");
				err = -1;
				break;
			}
			*sock = 0;
			err = -1;
			continue;
		}
	
		gettimeofday(&stats_after, NULL);
		
		microseconds  =
			((stats_after.tv_sec - stats_before.tv_sec) * 1000000)
			+ (stats_after.tv_usec - stats_before.tv_usec);
		
		printf("Connecting socket to remote socket address took "\
		       "%.5f seconds.\n", microseconds / 1000000.0 );
		
		if (connect_err != 0) {
			if(close(*sock) != 0) {
				HIP_ERROR("Unable to close a socket.\n");
				err = -1;
				break;
			}
			*sock = 0;
			/* Try the next address in peer_ai. */
			continue;
		} else {
			/* Connect succeeded and data can be sent/received. */
			break;
		}
	}
		
 out_err:
	return err;
}

/**
 * Does the logic of the "conntest-client-gai" command line utility. 
 *
 * @param socktype  the type of socket (SOCK_STREAM or SOCK_DGRAM)
 * @param peer_name the host name of the peer as read from the command lien
 * @param port_name the port number as a string as read from the command line
 * @param flags     flags that are set to addrinfo flags.
 *
 * @return          zero on success, non-zero otherwise.
 * @note            This function uses printf instead of the debug macros because
 *                  conntest-client-opp and opp library debugs get tangled.
 */
int main_client_gai(int socktype, char *peer_name, char *port_name, int flags)
{
	int recvnum = 0, sendnum = 0, datalen = 0, port = 0, bytes_sent = 0;
	int bytes_received = 0, c = 0, sock = 0, err = 0;
	char sendbuffer[IP_MAXPACKET], receivebuffer[IP_MAXPACKET];
	unsigned long microseconds = 0;
	struct addrinfo search_key, *peer_ai = NULL;
	struct timeval stats_before, stats_after;
	
	/* Set the memory allocated from the stack to zeros. */
	memset(&search_key, 0, sizeof(search_key));
	memset(&stats_before, 0, sizeof(stats_before));
	memset(&stats_after, 0, sizeof(stats_after));
	memset(sendbuffer, 0, sizeof(sendbuffer));
	memset(receivebuffer, 0, sizeof(receivebuffer));
	
	/* Fill in the socket address structure to host and service name. */
	search_key.ai_flags = flags;
	/* If peer_name is not specified the destination is looked in the
	   hadb. (?) */
	if (peer_name == NULL)
		search_key.ai_flags |= AI_KERNEL_LIST;

	/* Legacy API supports only HIT-in-IPv6 */
	search_key.ai_family = AF_UNSPEC;
	search_key.ai_socktype = socktype;
	
	/* Get the peer's address info. Set a generic -EHADDRINFO for */
	if (getaddrinfo(peer_name, port_name, &search_key, &peer_ai)) {
	    err = -EHADDRINFO;
	    printf("Name '%s' or service '%s' is unknown.\n",
		   peer_name, port_name);
	    goto out_err;
	}
	
	printf("Please input some text to be sent to '%s'.\n"\
	       "Empty row or \"CTRL+d\" sends data.\n", peer_name);
	
	/* Read user input from the standard input. */
	while((c = getc(stdin)) != EOF && (datalen < IP_MAXPACKET))
	{
		datalen++;
		if((sendbuffer[datalen-1] = c) == '\n'){
			/* First character is a newlinefeed. */
			if(datalen == 1){
				break;
			}
			c = getc(stdin);
			if(c == '\n' || c == EOF){
				break;
			} else {
				ungetc(c, stdin);
			}
		}
	}
	
	if(datalen == 0) {
		printf("No input data given.\nRunning plain connection test "\
		       "with no payload data exchange.\n");
	}
	
	/* Get a socket for sending and receiving data. */
	if (err = hip_connect_func(peer_ai, &sock)) {
		printf("Failed to connect.\n");
		goto out_err;
	}

	gettimeofday(&stats_before, NULL);
	
	if(datalen > 0) {
		/* Send and receive data from the socket. */
		while((bytes_sent < datalen) || (bytes_received < datalen)) {
			/* send() returns the number of bytes sent or negative
			   on error. */
			if (bytes_sent < datalen) {
				HIP_IFEL(((sendnum =
					   send(sock, sendbuffer + bytes_sent,
						datalen - bytes_sent, 0)) < 0),
					 err = -ECOMM,
					 "Communication error on send.\n");
				bytes_sent += sendnum;
			}
		
			/* recv() returns the number of bytes sent, negative
			   on error or zero when the peer has performed an
			   orderly shutdown. */
			if (bytes_received < datalen) {
				recvnum = recv(sock,
					       receivebuffer + bytes_received,
					       datalen - bytes_received, 0);
			
				if (recvnum == 0) {
					HIP_INFO("The peer has performed an "\
						 "orderly shutdown.\n");
					goto out_err;
				} else if(recvnum < 0) {
					err = -ENODATA;
					HIP_ERROR("Communication error on "\
						  "receive.\n");
				}
				
				bytes_received += recvnum;
			}
		}
	}

	gettimeofday(&stats_after, NULL);
	
	microseconds  =
		((stats_after.tv_sec - stats_before.tv_sec) * 1000000)
		+ (stats_after.tv_usec - stats_before.tv_usec);
	
	printf("Data exchange took %.5f seconds.\n",
	       microseconds / 1000000.0 );

	printf("Sent/received %d/%d bytes payload data to/from '%s'.\n",
	       bytes_sent, bytes_received, peer_name);
	
	if (memcmp(sendbuffer, receivebuffer, IP_MAXPACKET) != 0) {
		err = -EBADMSG;
	}

 out_err:
	if (peer_ai != NULL) {
		freeaddrinfo(peer_ai);
	}
	if (sock > 0) {
		close(sock);
	}

	return err;
}

/**
 * main_client_native - it handles the functionality of the client-native
 * @param proto type of protocol
 * @param socktype the type of socket
 * @param peer_name the peer name
 * @param peer_port_name the prot number
 *
 * @return 1 with success, 0 otherwise.
 */
int main_client_native(int socktype, char *peer_name, char *peer_port_name)
{
	//struct endpointinfo hints, *epinfo = NULL, *res = NULL;
	//struct endpointinfo *epinfo;
	struct addrinfo hints, *res = NULL;
	struct timeval stats_before, stats_after;
	struct sockaddr_hip peer_sock;
	unsigned long stats_diff_sec, stats_diff_usec;
	char mylovemostdata[IP_MAXPACKET];
	char receiveddata[IP_MAXPACKET];
	int recvnum, sendnum;
	int datalen = 0;
	int datasent = 0;
	int datareceived = 0;
	int ch;
	int err = 0;
	int sockfd = -1;
	se_family_t endpoint_family;

	endpoint_family = PF_HIP;

	sockfd = socket(endpoint_family, socktype, 0);
	HIP_IFEL(sockfd < 0, 1, "creation of socket failed\n");

#if 0
	/* set up host lookup information  */
	memset(&hints, 0, sizeof(hints));
	//hints.ei_socktype = socktype;
	//hints.ei_family = endpoint_family;
	hints.ai_socktype = socktype;
	hints.ai_family = endpoint_family;
	/* Use the following flags to use only the kernel list for name resolution
	 * hints.ei_flags = AI_HIP | AI_KERNEL_LIST;
	 */

	/* lookup host */
	//err = getendpointinfo(peer_name, peer_port_name, &hints, &res);
	if (err) {
		HIP_ERROR("getendpointfo failed\n");
		goto out_err;
	}
	//hints.ai_flags |= AI_EXTFLAGS;
	//hints.ai_eflags |= HIP_PREFER_ORCHID;

	err = getaddrinfo(peer_name, peer_port_name, &hints, &res);
	if (err) {
		HIP_ERROR("getaddrinfo failed (%d): %s\n", err, gepi_strerror(err));
		goto out_err;
	}
	if (!res) {
		HIP_ERROR("NULL result, TODO\n");
		goto out_err;
	}

/*
	HIP_DEBUG("family=%d value=%d\n", res->ei_family,
		  ntohs(((struct sockaddr_eid *) res->ei_endpoint)->eid_val));
*/
#endif

	/* XX TODO: Do a proper getaddrinfo() */
	memset(&peer_sock, 0, sizeof(peer_sock));
	peer_sock.ship_family = PF_HIP;
	HIP_IFEL(inet_pton(AF_INET6, peer_name, &peer_sock.ship_hit) != 1, 1, "Failed to parse HIT\n");
	peer_sock.ship_port = htons(atoi(peer_port_name));
	HIP_DEBUG("Connecting to %s port %d\n", peer_name, peer_sock.ship_port);

	// data from stdin to buffer
	memset(receiveddata, 0, IP_MAXPACKET);
	memset(mylovemostdata, 0, IP_MAXPACKET);

	printf("Input some text, press enter and ctrl+d\n");

	// horrible code
	while ((ch = fgetc(stdin)) != EOF && (datalen < IP_MAXPACKET)) {
		mylovemostdata[datalen] = (unsigned char) ch;
		datalen++;
	}

	gettimeofday(&stats_before, NULL);

#if 0
	epinfo = res;
	while(epinfo) {
		err = connect(sockfd, (struct sockaddr *) epinfo->ei_endpoint, epinfo->ei_endpointlen);
		//err = connect(sockfd, res->ai_addr, res->ai_addrlen);
		if (err) {
			HIP_PERROR("connect");
			goto out_err;
		}
		epinfo = epinfo->ei_next;
	}
#endif

	err = connect(sockfd, &peer_sock, sizeof(peer_sock));
	if (err) {
		HIP_PERROR("connect: ");
		goto out_err;
	}

	gettimeofday(&stats_after, NULL);
	stats_diff_sec  = (stats_after.tv_sec - stats_before.tv_sec) * 1000000;
	stats_diff_usec = stats_after.tv_usec - stats_before.tv_usec;

	HIP_DEBUG("connect took %.10f sec\n",
		  (stats_diff_sec + stats_diff_usec) / 1000000.0);

	/* Send the data read from stdin to the server and read the response.
	   The server should echo all the data received back to here. */
	while((datasent < datalen) || (datareceived < datalen)) {

		if (datasent < datalen) {
			sendnum = send(sockfd, mylovemostdata + datasent, datalen - datasent, 0);
      
			if (sendnum < 0) {
				HIP_PERROR("send");
				err = 1;
				goto out_err;
			}
			datasent += sendnum;
		}

		if (datareceived < datalen) {
			recvnum = recv(sockfd, receiveddata + datareceived,
				       datalen-datareceived, 0);
			if (recvnum <= 0) {
				HIP_PERROR("recv");
				err = 1;
				goto out_err;
			}
			datareceived += recvnum;
		}
	}

	HIP_IFEL(memcmp(mylovemostdata, receiveddata, IP_MAXPACKET),
				1, "Sent and received data did not match\n");

out_err:
	/*if (res)
		//free_endpointinfo(res);
		freeaddrinfo(res);*/
	if (sockfd > -1)
		close(sockfd); // discard errors

	HIP_INFO("Result of data transfer: %s.\n", (err ? "FAIL" : "OK"));

	return err;
}

/**
 * main_server_native - it handles the functionality of the client-native
 * @param socktype the type of socket
 * @param port_name the prot number
 *
 * @return 1 with success, 0 otherwise.
 */
int main_server_native(int socktype, char *port_name, char *name)
{
	struct endpointinfo hints, *res = NULL;
	struct sockaddr_eid peer_eid;
	struct sockaddr_hip our_sockaddr, peer_sock;
	char mylovemostdata[IP_MAXPACKET];
	int recvnum, sendnum, serversock = 0, sockfd = 0, err = 0, on = 1;
	int endpoint_family = PF_HIP;
	socklen_t peer_eid_len = sizeof(struct sockaddr_hip);

	/* recvmsg() stuff for UDP multihoming */
	char control[CMSG_SPACE(40)];
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pktinfo;
	struct iovec iov = { &mylovemostdata, sizeof(mylovemostdata) - 1 };
	struct msghdr msg = { &peer_sock, sizeof(peer_sock), &iov, 1,
						&control, sizeof(control), 0 };

	serversock = socket(endpoint_family, socktype, 0);
	if (serversock < 0) {
		HIP_PERROR("socket: ");
		err = 1;
		goto out_err;
	}

	setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (socktype == SOCK_DGRAM)
		setsockopt(serversock, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));

	memset(&hints, 0, sizeof(struct endpointinfo));
	hints.ei_family = endpoint_family;
	hints.ei_socktype = socktype;

	HIP_DEBUG("Native server calls getendpointinfo\n");

	err = getendpointinfo(NULL, port_name, &hints, &res);
	if (err || !res) {
		HIP_ERROR("Resolving of peer identifiers failed (%d)\n", err);
		goto out_err;
	}

	memset(&our_sockaddr, 0, sizeof(struct sockaddr_hip));
	if (name) {
		HIP_IFEL(inet_pton(AF_INET6, name, &our_sockaddr.ship_hit) != 1,
						    1, "Failed to parse HIT\n");
	}
	our_sockaddr.ship_port = htons(atoi(port_name));
	HIP_DEBUG("Binding to port %d\n", ntohs(our_sockaddr.ship_port));
	our_sockaddr.ship_family = endpoint_family;

	if (bind(serversock, &our_sockaddr, sizeof(struct sockaddr_hip)) < 0) {
		HIP_PERROR("bind: ");
		err = 1;
		goto out_err;
	}
	
	HIP_DEBUG("Native server calls listen\n");

	if (socktype == SOCK_STREAM && listen(serversock, 1) < 0) {
		HIP_PERROR("listen: ");
		err = 1;
		goto out_err;
	}

	HIP_DEBUG("Native server waits connection request\n");

	while(1) {
		if (socktype == SOCK_STREAM) {
			sockfd = accept(serversock, (struct sockaddr *) &peer_sock,
					&peer_eid_len);
			if (sockfd < 0) {
				HIP_PERROR("accept: ");
				err = 1;
				goto out_err;
			}

			while((recvnum = recv(sockfd, mylovemostdata,
					      sizeof(mylovemostdata), 0)) > 0 ) {
				mylovemostdata[recvnum] = '\0';
				printf("%s", mylovemostdata);
				fflush(stdout);

				sendnum = send(sockfd, mylovemostdata, recvnum, 0);
				if (sendnum < 0) {
					HIP_PERROR("send: ");
					err = 1;
					goto out_err;
				}
			}
		} else { /* UDP */
			sockfd = serversock;
			serversock = 0;
			while((recvnum = recvmsg(sockfd, &msg, 0)) > 0) {
				for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IPV6 &&
					    cmsg->cmsg_type == IPV6_2292PKTINFO) {
						pktinfo = CMSG_DATA(cmsg);
						break;
					}
				}
				HIP_DEBUG_HIT("localaddr", &pktinfo->ipi6_addr);
				iov.iov_len = strlen(mylovemostdata);

				/* ancillary data contains the src
				 * and dst addresses */
				sendnum = sendmsg(sockfd, &msg, 0);
				if (sendnum < 0) {
					HIP_PERROR("sendto: ");
					err = 1;
					goto out_err;
				}
			}
		}
	}

out_err:

	if (res)
		free_endpointinfo(res);

	if (sockfd)
		close(sockfd); // discard errors
	if (serversock)
		close(serversock); // discard errors

	return err;
}

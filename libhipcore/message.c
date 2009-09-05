/** @file
 * HIP userspace communication mechanism between userspace and kernelspace.
 * The mechanism is used by hipd, hipconf and unittest.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @version 1.0
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see     message.h
 * @todo    Asynchronous term should be replaced with a better one.
 * @todo    Asynchronous messages should also have a counterpart that receives
 *          a response from kernel.
 */
#include "message.h"
#ifdef ANDROID_CHANGES
#include <netinet/in.h>
#else
/* @todo: why the heck do we need this here on linux? */
struct in6_pktinfo
{
  struct in6_addr ipi6_addr;  /* src/dst IPv6 address */
  unsigned int ipi6_ifindex;  /* send/recv interface index */
};
#endif

/**
 * Finds out how much data is coming from a socket
 *
 * @param  socket         a file descriptor.
 * @param  encap_hdr_size udp etc header size
 * @param  timeout        -1 for blocking sockets, 0 or positive nonblocking
 * @return Number of bytes received on success or a negative error value on
 *         error.
 */
int hip_peek_recv_total_len(int socket, int encap_hdr_size, long timeout)
{
	int bytes = 0, err = 0, flags = MSG_PEEK;
	long timeout_left = timeout;
	int hdr_size = encap_hdr_size + sizeof(struct hip_common);
	char *msg = NULL;
	hip_common_t *hip_hdr = NULL;
	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec =  100000000;

        /* We're using system call here add thus reseting errno. */
	errno = 0;

	msg = (char *)malloc(hdr_size);
	HIP_IFEL(!msg, -ENOMEM, "Error allocating memory.\n");

	/* Make sure the socket does not block (bug id 806) */
	if (timeout >= 0)
		flags |= MSG_DONTWAIT;

	do {
		errno = 0;
		nanosleep(&ts, NULL);
		bytes = recv(socket, msg, hdr_size, flags);
		timeout_left -= ts.tv_nsec;
		_HIP_DEBUG("tol=%ld, ts=%ld, bytes=%d errno=%d\n",
			   timeout_left, ts.tv_nsec, bytes, errno);
	} while (timeout_left > 0 && errno == EAGAIN && bytes < 0);

	if(bytes < 0) {
		HIP_ERROR("recv() peek error (is hipd running?)\n");
		err = -EAGAIN;
		goto out_err;
	} else if (bytes < hdr_size) {
		HIP_ERROR("Packet payload is smaller than HIP header. Dropping.\n");
		/* Read and discard the datagram */
		recv(socket, msg, 0, 0);
		err = -bytes;
		goto out_err;
	}

	hip_hdr = (struct hip_common *) (msg + encap_hdr_size);
	bytes = hip_get_msg_total_len(hip_hdr);

	if(bytes == 0) {
		HIP_ERROR("HIP message is of zero length. Dropping.\n");
		recv(socket, msg, 0, 0);
		err = -EBADMSG;
		errno = EBADMSG;
		goto out_err;
	}

	/* The maximum possible length value is equal to HIP_MAX_PACKET.
	if(bytes > HIP_MAX_PACKET) {
		HIP_ERROR("HIP message max length exceeded. Dropping.\n");
		recv(socket, msg, 0, 0);
		err = -EMSGSIZE;
		errno = EMSGSIZE;
		goto out_err;
	} */

	bytes += encap_hdr_size;

 out_err:
	if (msg != NULL)
		free(msg);

	if (err)
		return err;

	return bytes;
}

int hip_daemon_connect(int hip_user_sock) {
	int err = 0, n, len;
	int hip_agent_sock = 0;
	struct sockaddr_in6 daemon_addr;
	// We're using system call here add thus reseting errno.
	errno = 0;

	memset(&daemon_addr, 0, sizeof(daemon_addr));
	daemon_addr.sin6_family = AF_INET6;
	daemon_addr.sin6_port = htons(HIP_DAEMON_LOCAL_PORT);
	daemon_addr.sin6_addr = in6addr_loopback;

	HIP_IFEL(connect(hip_user_sock, (struct sockaddr *) &daemon_addr,
			 sizeof(daemon_addr)), -1,
		 "connection to daemon failed\n");

 out_err:

	return err;
}

int hip_daemon_bind_socket(int socket, struct sockaddr *sa) {
	int err = 0, port = 0, on = 1;
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *) sa;

	HIP_ASSERT(addr->sin6_family == AF_INET6);

	errno = 0;

	if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
		HIP_DEBUG ("Failed to set socket option SO_REUSEADDR %s \n",  strerror(errno));
	}

	if (addr->sin6_port) {
		HIP_DEBUG("Bind to fixed port %d\n", addr->sin6_port);
		err = bind(socket,(struct sockaddr *)addr,
			   sizeof(struct sockaddr_in6));
		err = -errno;
		goto out_err;
	}

	/* try to bind first to a priviledged port and then to ephemeral */
	port = 1000;
	while (port++ < 61000) {
		_HIP_DEBUG("trying bind() to port %d\n", port);
		addr->sin6_port = htons(port);
		err = bind(socket,(struct sockaddr *)addr,
			   hip_sockaddr_len(addr));
		if (err == -1) {
			if (errno == EACCES) {
				/* Ephemeral ports:
				   /proc/sys/net/ipv4/ip_local_port_range */
				_HIP_DEBUG("Skipping to ephemeral range\n");
				port = 32768;
				errno = 0;
				err = 0;
			} else if (errno == EADDRINUSE) {
				_HIP_DEBUG("Port %d in use, skip\n", port);
				errno = 0;
				err = 0;
			} else {
				HIP_ERROR("Error %d bind() wasn't succesful\n",
					  errno);
				err = -1;
				goto out_err;
			}
		}
		else {
			_HIP_DEBUG("Bind() to port %d successful\n", port);
			goto out_err;
		}
	}

	if (port == 61000) {
		HIP_ERROR("All privileged ports were occupied\n");
		err = -1;
	}

 out_err:
	return err;
}

/* do not call this function directly, use hip_send_recv_daemon_info instead */
int hip_sendto_hipd(int socket, struct hip_common *msg, int len)
{
	/* Variables. */
	struct sockaddr_in6 sock_addr;
	int n = -1, alen;

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_DAEMON_LOCAL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;

	alen = sizeof(sock_addr);

	HIP_DEBUG("Sending user message %d to HIPD on socket %d\n",
		  hip_get_msg_type(msg), socket);

	n = sendto(socket, msg, /*hip_get_msg_total_len(msg)*/ len, MSG_NOSIGNAL,
		   (struct sockaddr *)&sock_addr, alen);
	HIP_DEBUG("Sent %d bytes\n", n);

	return n;
}

/*
 * Don't call this function directly. Use hip_send_recv_daemon_info instead
 */
int hip_send_recv_daemon_info_internal(struct hip_common *msg, int opt_socket) {

	int hip_user_sock = 0, err = 0, n = 0, len = 0;
	struct sockaddr_in6 addr;
	uint8_t msg_type_old, msg_type_new;
	
	msg_type_old = hip_get_msg_type(msg);

	// We're using system call here and thus reseting errno.
	errno = 0;

	if (opt_socket) {
		hip_user_sock = opt_socket;
	} else {
		HIP_IFE(((hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0), EHIP);

		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_loopback;

		HIP_IFEL(hip_daemon_bind_socket(hip_user_sock,
						(struct sockaddr *) &addr), -1,
			 "bind failed\n");
		/* Connect to hipd. Otherwise e.g. "hipconf get ha all"
		   blocks when hipd is not running. */
		HIP_IFEL(hip_daemon_connect(hip_user_sock), -1,
			 "connect failed\n");
	}

	if ((len = hip_get_msg_total_len(msg)) < 0) {
		err = -EBADMSG;
		goto out_err;
	}

	/* Require a response from hipd */
	hip_set_msg_response(msg, 1);

	n = hip_sendto_hipd(hip_user_sock, msg, len);
	if (n < len) {
		HIP_ERROR("Could not send message to daemon.\n");
		err = -ECOMM;
		goto out_err;
	}

	HIP_DEBUG("Waiting to receive daemon info.\n");

	if((len = hip_peek_recv_total_len(hip_user_sock, 0, HIP_DEFAULT_MSG_TIMEOUT)) < 0) {
		err = len;
		goto out_err;
	}

	n = recv(hip_user_sock, msg, len, 0);

	/* You have a message synchronization problem if you see this error. */
	msg_type_new = hip_get_msg_type(msg);
	HIP_IFEL((msg_type_new != msg_type_old), -1,
		 "Message sync problem. Expected %d, got %d\n",
		 msg_type_old, msg_type_new);

	HIP_DEBUG("%d bytes received from HIP daemon\n", n);

	if (n == 0) {
		HIP_INFO("The HIP daemon has performed an "\
			 "orderly shutdown.\n");
		// Note. This is not an error condition, thus we return zero.
		goto out_err;
	} else if(n < sizeof(struct hip_common)) {
		HIP_ERROR("Could not receive message from daemon.\n");
		goto out_err;
	}

	if (hip_get_msg_err(msg)) {
		HIP_ERROR("HIP message contained an error.\n");
		err = -EHIP;
	}

	_HIP_DEBUG("Message received successfully\n");

 out_err:

	if (!opt_socket && hip_user_sock)
		close(hip_user_sock);

	return err;
}

int hip_send_recv_daemon_info(struct hip_common *msg, int send_only, int opt_socket) {
	int hip_user_sock = 0, err = 0, n, len;
	struct sockaddr_in6 addr;

	if (!send_only)
		return hip_send_recv_daemon_info_internal(msg, opt_socket);

	if (opt_socket) {
		hip_user_sock = opt_socket;
	} else {
		HIP_IFE(((hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0), -1);
		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_loopback;
		
		HIP_IFEL(hip_daemon_bind_socket(hip_user_sock,
						(struct sockaddr *) &addr), -1,
			 "bind failed\n");
		HIP_IFEL(hip_daemon_connect(hip_user_sock), -1,
			 "connect failed\n");
	}

	len = hip_get_msg_total_len(msg);
	n = send(hip_user_sock, msg, len, 0);

	if (n < len) {
		HIP_ERROR("Could not send message to daemon.\n");
		err = -1;
		goto out_err;
	}

 out_err:
	if (!opt_socket && hip_user_sock)
		close(hip_user_sock);

	return err;
}

int hip_recv_daemon_info(struct hip_common *msg, uint16_t info_type) {
	/** @todo required by the native HIP API */
	/* Call first send_daemon_info with info_type and then recvfrom */
	return -1;
}

int hip_read_user_control_msg(int socket, struct hip_common *hip_msg,
			      struct sockaddr_in6 *saddr)
{
	int err = 0, bytes, hdr_size = sizeof(struct hip_common), total;
	socklen_t len;

	memset(saddr, 0, sizeof(*saddr));

	len = sizeof(*saddr);

	HIP_IFEL(((total = hip_peek_recv_total_len(socket, 0, HIP_DEFAULT_MSG_TIMEOUT)) <= 0), -1,
		 "recv peek failed\n");

	_HIP_DEBUG("msg total length = %d\n", total);

	/** @todo Compiler warning;
	    warning: pointer targets in passing argument 6 of 'recvfrom'
	    differ in signedness. */
	HIP_IFEL(((bytes = recvfrom(socket, hip_msg, total, 0,
				    (struct sockaddr *) saddr,
				    &len)) != total), -1, "recv\n");

	HIP_DEBUG("received user message from local port %d\n",
		   ntohs(saddr->sin6_port));
	_HIP_DEBUG("read_user_control_msg recv len=%d\n", len);
	_HIP_HEXDUMP("recv saddr ", saddr, sizeof(struct sockaddr_un));
	_HIP_DEBUG("read %d bytes succesfully\n", bytes);
 out_err:
	if (bytes < 0 || err)
		HIP_PERROR("perror: ");

	return err;
}

/* Moved function doxy descriptor to the header file. Lauri 11.03.2008 */
int hip_read_control_msg_all(int socket, struct hip_common *hip_msg,
                             struct in6_addr *saddr,
                             struct in6_addr *daddr,
                             hip_portpair_t *msg_info,
                             int encap_hdr_size, int is_ipv4)
{
	struct sockaddr_storage addr_from, addr_to;
	struct sockaddr_in *addr_from4 = ((struct sockaddr_in *) &addr_from);
	struct sockaddr_in6 *addr_from6 =
		((struct sockaddr_in6 *) &addr_from);
        struct cmsghdr *cmsg;
        struct msghdr msg;
	union {
		struct in_pktinfo *pktinfo_in4;
		struct in6_pktinfo *pktinfo_in6;
	} pktinfo;
        struct iovec iov;
        char cbuff[CMSG_SPACE(256)];
        int err = 0, len;
	int cmsg_level, cmsg_type;

	HIP_ASSERT(saddr);
	HIP_ASSERT(daddr);

	HIP_DEBUG("hip_read_control_msg_all() invoked.\n");

	HIP_IFEL(((len = hip_peek_recv_total_len(socket, encap_hdr_size, HIP_DEFAULT_MSG_TIMEOUT))<= 0),
		 -1, "Bad packet length (%d)\n", len);

	memset(msg_info, 0, sizeof(hip_portpair_t));
	memset(&msg, 0, sizeof(msg));
	memset(cbuff, 0, sizeof(cbuff));
	memset(&addr_to, 0, sizeof(addr_to));

        /* setup message header with control and receive buffers */
        msg.msg_name = &addr_from;
        msg.msg_namelen = sizeof(struct sockaddr_storage);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        memset(cbuff, 0, sizeof(cbuff));
        msg.msg_control = cbuff;
        msg.msg_controllen = sizeof(cbuff);
        msg.msg_flags = 0;

        iov.iov_len = len;
        iov.iov_base = hip_msg;

	pktinfo.pktinfo_in4 = NULL;

	len = recvmsg(socket, &msg, 0);

	HIP_IFEL((len < 0), -1, "ICMP%s error: errno=%d, %s\n",
		 (is_ipv4 ? "v4" : "v6"), errno, strerror(errno));

	cmsg_level = (is_ipv4) ? IPPROTO_IP : IPPROTO_IPV6;
	cmsg_type = (is_ipv4) ? IP_PKTINFO : IPV6_2292PKTINFO;

	/* destination address comes from ancillary data passed
	 * with msg due to IPV6_PKTINFO socket option */
	for (cmsg=CMSG_FIRSTHDR(&msg); cmsg; cmsg=CMSG_NXTHDR(&msg,cmsg)){
		if ((cmsg->cmsg_level == cmsg_level) &&
		    (cmsg->cmsg_type == cmsg_type)) {
			/* The structure is a union, so this fills also the
			   pktinfo_in6 pointer */
			pktinfo.pktinfo_in4 =
				(struct in_pktinfo*)CMSG_DATA(cmsg);
			break;
		}
	}

	/* If this fails, change IPV6_2292PKTINFO to IPV6_PKTINFO in
	   hip_init_raw_sock_v6 */
	HIP_IFEL(!pktinfo.pktinfo_in4, -1,
		 "Could not determine dst addr, dropping\n");

	/* UDP port numbers */
	if (is_ipv4 && encap_hdr_size == HIP_UDP_ZERO_BYTES_LEN) {
		HIP_DEBUG("hip_read_control_msg_all() source port = %d\n",
			  ntohs(addr_from4->sin_port));
		msg_info->src_port = ntohs(addr_from4->sin_port);
		/* Destination port is known from the bound socket. */
		msg_info->dst_port = hip_get_local_nat_udp_port();
	}

	/* IPv4 addresses */
	if (is_ipv4) {
		struct sockaddr_in *addr_to4 = (struct sockaddr_in *) &addr_to;
		IPV4_TO_IPV6_MAP(&addr_from4->sin_addr, saddr);
		IPV4_TO_IPV6_MAP(&pktinfo.pktinfo_in4->ipi_addr,
				 daddr);
		addr_to4->sin_family = AF_INET;
		addr_to4->sin_addr = pktinfo.pktinfo_in4->ipi_addr;
		addr_to4->sin_port = msg_info->dst_port;
	} else /* IPv6 addresses */ {
		struct sockaddr_in6 *addr_to6 =
			(struct sockaddr_in6 *) &addr_to;
		memcpy(saddr, &addr_from6->sin6_addr,
		       sizeof(struct in6_addr));
		memcpy(daddr, &pktinfo.pktinfo_in6->ipi6_addr,
		       sizeof(struct in6_addr));
		addr_to6->sin6_family = AF_INET6;
		ipv6_addr_copy(&addr_to6->sin6_addr, daddr);
	}

//added by santtu
	if (hip_read_control_msg_plugin_handler(hip_msg,len, saddr,msg_info->src_port))
		goto out_err;
//endadd

	if (is_ipv4 && (encap_hdr_size == IPV4_HDR_SIZE)) {/* raw IPv4, !UDP */
		/* For some reason, the IPv4 header is always included.
		   Let's remove it here. */
		memmove(hip_msg, ((char *)hip_msg) + IPV4_HDR_SIZE,
			HIP_MAX_PACKET - IPV4_HDR_SIZE);
	} else if (is_ipv4 && encap_hdr_size == HIP_UDP_ZERO_BYTES_LEN) {
		/* remove 32-bits of zeroes between UDP and HIP headers */
		memmove(hip_msg, ((char *)hip_msg) + HIP_UDP_ZERO_BYTES_LEN,
			HIP_MAX_PACKET - HIP_UDP_ZERO_BYTES_LEN);
	}

	HIP_IFEL(hip_verify_network_header(hip_msg,
					   (struct sockaddr *) &addr_from,
					   (struct sockaddr *) &addr_to,
					   len - encap_hdr_size), -1,
		 "verifying network header failed\n");



	if (saddr)
		HIP_DEBUG_IN6ADDR("src", saddr);
	if (daddr)
		HIP_DEBUG_IN6ADDR("dst", daddr);

 out_err:
	return err;
}

int hip_read_control_msg_v6(int socket, struct hip_common *hip_msg,
			    struct in6_addr *saddr,
			    struct in6_addr *daddr,
                            hip_portpair_t *msg_info,
                            int encap_hdr_size)
{
	return hip_read_control_msg_all(socket, hip_msg, saddr,
					daddr, msg_info, encap_hdr_size, 0);
}

int hip_read_control_msg_v4(int socket, struct hip_common *hip_msg,
			    struct in6_addr *saddr,
			    struct in6_addr *daddr,
			    hip_portpair_t *msg_info,
			    int encap_hdr_size)
{
	return hip_read_control_msg_all(socket, hip_msg, saddr,
					daddr, msg_info, encap_hdr_size, 1);
}


int hip_read_control_msg_plugin_handler(void* msg, int len, in6_addr_t * src_addr,in_port_t port){
	int err = 0;
#if 0
	//handle stun msg
	if (hip_external_ice_receive_pkt_all(msg, len, src_addr,port)) {
		err = 1;
		goto out_err;
	}
#endif
out_err:
	return err;
}

/** @file
 * A header file for message.c.
 * 
 * @author  Miika Komu <miika_iki.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @version 1.0
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_MESSAGE_H
#define HIP_MESSAGE_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <netinet/in.h>

#include "nlink.h"
#include "debug.h"
#include "icomm.h"
#include "nat.h"
#include "hipconf.h"

//#define HIP_DAEMON_PORT 3030
#define HIP_DEFAULT_MSG_TIMEOUT 4000000000 /* nanosecs */

/**
 * .
 *
 * @param  socket         a socket file descriptor.
 * @param  encap_hdr_size .
 * @return 
 */ 
int hip_peek_recv_total_len(int socket, int encap_hdr_size, long timeout);

/**
 * Connects a socket to the HIP daemon. Connects a socket identified by file
 * descriptor @c hip_user_sock to the HIP daemon. This function resets @c errno
 * before connecting to the daemon.
 *
 * @param  hip_user_sock a socket file descriptor.
 * @return               zero on success, -1 on error.
 */
int hip_daemon_connect(int hip_user_sock);

/**
 * .
 *
 * @param  msg       a pointer to a HIP message.
 * @param  send_only 1 if waits for return message, otherwise 0
 * @param  socket    optional socket (otherwise ephemeral socket is created)
 * @return           zero on success, non-zero on error
 */
int hip_send_recv_daemon_info(struct hip_common *msg, int send_only, int socket);

/**
 * .
 *
 * @param  msg       a pointer to a HIP message. 
 * @param  only_send .
 * @return           .
 */
int hip_send_daemon_info(const struct hip_common *msg, int only_send);

/**
 * .
 *
 * @param  msg       a pointer to a HIP message. 
 * @param  info_type .
 * @return           .
 */
int hip_recv_daemon_info(struct hip_common *msg, uint16_t info_type);

/**
 * .
 *
 * @param  socket  a socket file descriptor.
 * @param  hip_msg a pointer to a HIP message. 
 * @param  saddr   a pointer to an IPv6 source address socket
 *                 structure.
 * @return           .
 */
int hip_read_user_control_msg(int socket, struct hip_common *hip_msg,
			      struct sockaddr_in6 *saddr);


/**
 * Prepares a @c hip_common struct based on information received from a socket.
 * 
 * Prepares a @c hip_common struct, allocates memory for buffers and nested
 * structs. Receives a message from socket and fills the @c hip_common struct
 * with the values from this message.
 *
 * @param socket         a socket to read from.
 * @param hip_msg        a pointer to a buffer where to put the received HIP
 *                       common header. This is returned as filled struct.
 * @param read_addr      a flag whether the adresses should be read from the
 *                       received packet. <b>1</b>:read addresses,
 *                       <b>0</b>:don't read addresses.
 * @param saddr          a pointer to a buffer where to put the source IP
 *                       address of the received message (if @c read_addr is set
 *                       to 1).
 * @param daddr          a pointer to a buffer where to put the destination IP
 *                       address of the received message (if @c read_addr is set
 *                       to 1).
 * @param msg_info       a pointer to a buffer where to put the source and 
 *                       destination ports of the received message.
 * @param encap_hdr_size size of encapsulated header in bytes.
 * @param is_ipv4        a boolean value to indicate whether message is received
 *                       on IPv4.
 * @return               -1 in case of an error, 0 otherwise.
 */
int hip_read_control_msg_all(int socket, struct hip_common *hip_msg,
                             struct in6_addr *saddr,
                             struct in6_addr *daddr,
                             hip_portpair_t *msg_info,
                             int encap_hdr_size, int is_ipv4
							);

/**
 * Reads an IPv6 control message.
 *
 * @param  socket         a socket file descriptor.
 * @param  hip_msg        a pointer to a HIP message. 
 * @param  saddr          source IPv6 address.
 * @param  daddr          destination IPv6 address.
 * @param  msg_info       transport layer source and destination port numbers.
 * @param  encap_hdr_size .
 * @return                .
 */
int hip_read_control_msg_v6(int socket, struct hip_common *hip_msg,
			    struct in6_addr *saddr,
			    struct in6_addr *daddr,
                            hip_portpair_t *msg_info,
                            int encap_hdr_size);
/**
 * Reads an IPv4 control message.
 *
 * @param  socket         a socket file descriptor.
 * @param  hip_msg        a pointer to a HIP message. 
 * @param  saddr          source IPv4 address.
 * @param  daddr          destination IPv4 address.
 * @param  msg_info       transport layer source and destination port numbers.
 * @param  encap_hdr_size .
 * @return                .
 */
int hip_read_control_msg_v4(int socket, struct hip_common *hip_msg,
			    struct in6_addr *saddr,
			    struct in6_addr *daddr,
			    hip_portpair_t *msg_info,
			    int encap_hdr_size);

int hip_sendto(int sock, const struct hip_common *msg,
	       const struct sockaddr_in6 *dst);

int hip_read_control_msg_plugin_handler(void* msg, int len, in6_addr_t * src_addr,in_port_t port);

#endif /* HIP_MESSAGE_H */

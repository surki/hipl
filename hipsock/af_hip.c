/*
*  HIP socket handler loadable kernel module
*  for kernel 2.6
*
* Description:
* 
*
* Authors: 
*   - Tobias Heer <heer@tobobox.de> 2006
*   - Miika Komu <miika@iki.fi>
*   - Laura Takkinen <laura.takkinen@hut.fi>
* Licence: GNU/GPL
* @note HIPU: This is a kernel module specifically for Linux. It needs to be rewritten for MAC OS X.
*
*/

#include "af_hip.h"

//const struct in6_addr in6addr_any;

int hsock_init_module(void)
{
	int err = 0;

	//memset((struct in6_addr *) &in6addr_any, 0, sizeof(in6addr_any));

	HIP_DEBUG("Loading HIP socket module\n");
	HIP_IFEL(hip_init_socket_handler(), -1, "HIP socket init failed\n");
	HIP_DEBUG("HIP socket module loaded successfully\n");
	
out_err:	
	return err;
}

void hsock_cleanup_module(void)
{
	int err = 0;
	HIP_IFEL(hip_uninit_socket_handler(), -1, "HIP clean-up failed\n"); 
 out_err:
	return;
}

module_init(hsock_init_module);
module_exit(hsock_cleanup_module);
 
MODULE_LICENSE("GPL"); 
/***************************************************************
 *               Socket handler functions                      *
 ***************************************************************/

int hip_select_socket_handler(struct socket *sock,
                              struct proto_ops **handler)
{
        int err = 0;

        HIP_ASSERT(sock && sock->sk);

        HIP_DEBUG("sock_type=%d sk_proto=%d\n",
                  sock->sk->sk_type, sock->sk->sk_protocol);

        /* XX FIXME: How to handle IPPROTO_RAW? */
        /* XX FIXME: How to react on IPPROTO_HIP */

        switch (sock->sk->sk_protocol) {
        case IPPROTO_TCP:
          *handler = &inet6_stream_ops;
          break;
        case IPPROTO_UDP:
          *handler = &inet6_dgram_ops;
          break;
        default:
          *handler = NULL;
          err = -EPROTONOSUPPORT;
          HIP_ERROR("Cannot select protocol handler for proto %d.",
                    sock->sk->sk_protocol);
          break;
        }

        return err;
}
#if 0
int hip_socket_get_eid_info(struct socket *sock,
                            struct proto_ops **socket_handler,
                            const struct sockaddr_eid *eid,
                            int eid_is_local,
                            struct hip_lhi *lhi)
{
	struct hip_eid_owner_info owner_info;
        int err = 0;

        err = hip_select_socket_handler(sock, socket_handler);
        if (err) {
                HIP_ERROR("Failed to select a socket handler\n");
                goto out_err;
        }

        HIP_DEBUG("Querying for eid value %d\n", ntohs(eid->eid_val));

        err = hip_db_get_lhi_by_eid(eid, lhi, &owner_info, eid_is_local);
        if (err) {
                HIP_ERROR("Failed to map %s EID to HIT\n",
                          (eid_is_local ? "local" : "peer"));
                goto out_err;
        }

        /* XX FIXME: CHECK ACCESS RIGHTS FROM OWNER_INFO */

        /* Access control for EDs */
        if(eid_is_local) {
                HIP_DEBUG("current->uid:%d, current->gid:%d,current->pid:%d\n",
                          current->uid, current->gid, current->pid);
                HIP_DEBUG("ED->uid:%d, ED->gid:%d, ED->pid:%d\n",
                          owner_info.uid, owner_info.gid, owner_info.pid);
                HIP_DEBUG("flags:%d\n",owner_info.flags);
                if(owner_info.flags & HIP_HI_REUSE_ANY) {
                        HIP_DEBUG("Access control check to ED, REUSE_ANY\n");
                        goto out_err;   

                } else if((owner_info.flags & HIP_HI_REUSE_GID) && 
                          (current->gid == owner_info.gid)) {
                        HIP_DEBUG("Access control check to ED, REUSE_GID\n");
                        goto out_err;   

                } else if((owner_info.flags & HIP_HI_REUSE_UID) && 
                          (current->uid == owner_info.uid)) {
                        HIP_DEBUG("Access control check to ED, REUSE_UID\n");
                        goto out_err;

                } else if(current->pid == owner_info.pid) {
                        HIP_DEBUG("Access control check to ED, PID ok\n");
                        goto out_err;

                } else {
                        err = -EACCES;
                        HIP_INFO("Access denied to ED\n");
                        goto out_err;
                }
        }

 out_err:

        return err;
}
#endif
/** hip_init_socket_handler - initialize socket handler
 *  @return 	returns -1 in case of an error, 0 otherwise
 */ 
int hip_init_socket_handler(void)
{	
	int err = 0;
	HIP_IFEL(sock_register(&hip_family_ops), -1,
		 "HIP socket registration failed\n");
	
out_err:
	return err;
}

/** hip_uinit_socket_handler - unregister socket handler
 *  @return 	returns -1 in case of an error, 0 otherwise
 */ 
int hip_uninit_socket_handler(void)
{
	/* Returns void */
	sock_unregister(PF_HIP);

	return 0;
}

/** hip_create_socket - create a new HIP socket
 * 
 *  @param sock function pointer to socket (used as return value)
 *  @param protocol protocol number
 *  @return returns 1 in case of an error, 0 otherwise
 */ 
int hip_create_socket(struct net *net, struct socket *sock, int protocol)
{
	int err = 0;
	HIP_DEBUG("HIP socket handler: create socket!\n");

	// XX TODO: REPLACE WITH A SELECTOR
	HIP_IFEL(inet6_create(net, sock, protocol), -1, "inet6_create\n");

	// XX LOCK AND UNLOCK?
	sock->ops = &hip_socket_ops;
	/* Note: we cannot set sock->sk->family ever to PF_HIP because it
	   simply does not work if we want to use inet6 sockets. */

 out_err:
	return err;
}


int hip_socket_release(struct socket *sock)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	if (sock->sk == NULL)
		goto out_err;

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->release(sock);
	if (err) {
		HIP_ERROR("Socket handler failed (%d)\n", err);
		goto out_err;
	}
	
 out_err:

	return err;
	
}


int hip_socket_bind(struct socket *sock, 
		    struct sockaddr *umyaddr,
		    int sockaddr_len)
{
	int err = 0;
	struct sockaddr_in6 sockaddr_in6;
	struct proto_ops *socket_handler;
	struct hip_lhi lhi;
	struct sockaddr_hip *sockaddr_hip = (struct sockaddr_hip *) umyaddr;

	HIP_DEBUG("hip_socket_bind called\n");

        err = hip_select_socket_handler(sock, &socket_handler);
        if (err) {
                HIP_ERROR("Failed to select a socket handler\n");
                goto out_err;
        }

	memset(&sockaddr_in6, 0, sizeof(struct sockaddr_in6));
	sockaddr_in6.sin6_family = PF_INET6;
	sockaddr_in6.sin6_port = sockaddr_hip->ship_port;
	memcpy(&sockaddr_in6.sin6_addr, &sockaddr_hip->ship_hit, sizeof(struct in6_addr));

	HIP_DEBUG_HIT("hip_socket_bind(): HIT", &sockaddr_in6.sin6_addr);
	err = socket_handler->bind(sock, (struct sockaddr *) &sockaddr_in6,
				   sizeof(struct sockaddr_in6));
	if (err) {
		HIP_ERROR("Socket handler failed (%d).\n", err);
		goto out_err;
	}
	
 out_err:
	
	return err;
}


int hip_socket_socketpair(struct socket *sock1, 
			  struct socket *sock2)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock1, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->socketpair(sock1, sock2);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:
	return err;
}


int hip_socket_connect(struct socket *sock, 
		       struct sockaddr *uservaddr,
		       int sockaddr_len,
		       int flags)
{
	int err = 0;
	struct sockaddr_in6 sockaddr_in6;
	struct proto_ops *socket_handler;
	struct hip_lhi lhi;
	struct sockaddr_hip *sockaddr_hip = (struct sockaddr_hip *) uservaddr;

	HIP_DEBUG("hip_socket_connect called\n");

	err = hip_select_socket_handler(sock, &socket_handler);

	memset(&sockaddr_in6, 0, sizeof(struct sockaddr_in6));
	sockaddr_in6.sin6_family = PF_INET6;
	sockaddr_in6.sin6_port = sockaddr_hip->ship_port;
	memcpy(&sockaddr_in6.sin6_addr, &sockaddr_hip->ship_hit, sizeof(struct in6_addr));

	HIP_DEBUG_HIT("connecting to the source HIT\n", &sockaddr_in6.sin6_addr);
	/* Note: connect calls autobind if the application has not already
	   called bind manually. */

	/* XX CHECK: check does the autobind actually bind to an IPv6 address
	   or HIT? Or inaddr_any? Should we do the autobind manually here? */

	HIP_DEBUG("socket state %d \n", sock->state);

	err = socket_handler->connect(sock, (struct sockaddr *) &sockaddr_in6,
				      sizeof(struct sockaddr_in6), flags);
	if (err) {
		HIP_ERROR("Socket handler failed (%d).\n", err);
		goto out_err;
	}

 out_err:

	return err;
}


int hip_socket_accept(struct socket *sock, 
		      struct socket *newsock,
		      int flags)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("hip_socket_accept called\n");

	if(!sock){
	  HIP_DEBUG("sock is NULL\n");
	}
	if(!newsock){
	  HIP_DEBUG("newsock is NULL\n");
	}

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		HIP_ERROR("Failed to select socket handler.\n");
		goto out_err;
	}

	HIP_DEBUG("socket handler selected\n");
	err = socket_handler->accept(sock, newsock, flags);
	if (err) {
		/* Can return e.g. ERESTARTSYS */
		HIP_DEBUG("Socket handler returned (%d)\n", err);
		goto out_err;
	}

	HIP_DEBUG("accepted\n");

	/* XX FIXME: do something to the newsock? */

 out_err:

	return err;
}


int hip_socket_getname(struct socket *sock, 
		       struct sockaddr *uaddr,
		       int *usockaddr_len,
		       int peer)
{
	int err = 0;

	struct proto_ops *socket_handler;
	//struct hip_lhi lhi;
	//struct hip_eid_owner_info owner_info;
	struct sock *sk = sock->sk;
	struct ipv6_pinfo *pinfo = inet6_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in6 sockaddr_in6_tmp;
	//struct sockaddr_eid *sockaddr_eid = (struct sockaddr_eid *) uaddr;
	struct sockaddr_hip *sockaddr_hip = (struct sockaddr_hip *) uaddr;
	int sockaddr_in6_tmp_len;

	HIP_DEBUG("\n");

	/* XX CHECK access perms? */

	HIP_DEBUG("getname for %s called\n", (peer ? "peer" : "local"));

	HIP_HEXDUMP("daddr", &pinfo->daddr,
		    sizeof(struct in6_addr));
	HIP_HEXDUMP("rcv_saddr", &pinfo->rcv_saddr,
		    sizeof(struct in6_addr));

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		HIP_ERROR("Failed to select a socket handler\n");
		goto out_err;
	}

	HIP_DEBUG("port: %d\n", ntohs((peer ? inet->dport : inet->sport)));

	err = socket_handler->getname(sock,
				      (struct sockaddr *) &sockaddr_in6_tmp,
				      &sockaddr_in6_tmp_len, peer);
	if (err) {
		HIP_ERROR("Socket handler failed (%d)\n", err);
		goto out_err;
	}

	HIP_ASSERT(sockaddr_in6_tmp_len == sizeof(struct sockaddr_in6));
	HIP_DEBUG_IN6ADDR("inet6 getname returned addr",
			  &sockaddr_in6_tmp.sin6_addr);
#if 0
	owner_info.uid = current->uid;
	owner_info.gid = current->gid;
	owner_info.pid = current->pid;
	owner_info.flags = 0;

	memcpy(&lhi.hit, &pinfo->daddr,
	       sizeof(struct in6_addr));
	lhi.anonymous = 0; /* XX FIXME: should be really set to -1 */

	err = hip_db_set_eid(sockaddr_eid, &lhi, &owner_info, !peer);
	if (err) {
		HIP_ERROR("Setting of %s eid failed\n",
			  (peer ? "peer" : "local"));
		goto out_err;
	}

	sockaddr_eid->eid_port = (peer) ? inet->dport : inet->sport;
	*usockaddr_len = sizeof(struct sockaddr_eid);
#endif

	memcpy(&sockaddr_hip->ship_hit, &sockaddr_in6_tmp.sin6_addr,
						sizeof(struct in6_addr));
	sockaddr_hip->ship_port = sockaddr_in6_tmp.sin6_port;
	HIP_DEBUG("port %d\n", sockaddr_hip->ship_port);
	*usockaddr_len = sizeof(struct sockaddr_hip);

 out_err:

	return err;
}


/*
 * XX TODO: fall back to IPV6 POLL
 */
unsigned int hip_socket_poll(struct file *file,
			     struct socket *sock,
			     struct poll_table_struct *wait)
{
	int err = 0;
	int mask = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		mask = POLLERR;
		goto out_err;
	}

	mask = socket_handler->poll(file, sock, wait);

 out_err:

	return mask;
}

int hip_socket_ioctl(struct socket *sock, 
		     unsigned int cmd,
		     unsigned long arg)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->ioctl(sock, cmd, arg);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;
}


int hip_socket_listen(struct socket *sock, int backlog)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->listen(sock, backlog);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;
}


int hip_socket_shutdown(struct socket *sock, int flags)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->shutdown(sock, flags);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;
}


int hip_socket_setsockopt(struct socket *sock,
			  int   level,
			  int   optname,
			  char *optval,
			  int   optlen)
{
	int err = 0;
	struct proto_ops *socket_handler;
	struct hip_common *msg = (struct hip_common *) optval;
	int msg_type;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	/* The message was destined to TCP or IP - forward */
	if (level != IPPROTO_HIP) {
		err = socket_handler->setsockopt(sock, level, optname, optval,
						 optlen);
		goto out_err;
	}

	if (!(optname == SO_HIP_GLOBAL_OPT || optname == SO_HIP_SOCKET_OPT)) {
		err = -ESOCKTNOSUPPORT;
		HIP_ERROR("optname (%d) was incorrect\n", optname);
		goto out_err;
	}

	err = hip_check_userspace_msg(msg);
	if (err) {
		HIP_ERROR("HIP socket option was invalid\n");
		goto out_err;
	}

	msg_type = hip_get_msg_type(msg);
	switch(msg_type) {
#if 0
	case SO_HIP_ADD_LOCAL_HI:
		err = hip_wrap_handle_add_local_hi(msg);
		break;
	case SO_HIP_DEL_LOCAL_HI:
		err = hip_socket_handle_del_local_hi(msg);
		break;
	case SO_HIP_ADD_PEER_MAP_HIT_IP:
		err = hip_socket_handle_add_peer_map_hit_ip(msg);
		break;
	case SO_HIP_DEL_PEER_MAP_HIT_IP:
		err = hip_socket_handle_del_peer_map_hit_ip(msg);
		break;
	case SO_HIP_RST:
		err = hip_socket_handle_rst(msg);
		break;
	case SO_HIP_ADD_DEL_SERVER:
		err = hip_socket_handle_rvs(msg);
		break;
        /** @todo Not supported for now, this message should be moved as
	    such to the userspace anyway i.e. create WORKORDER: */
        // HIP_WO_SUBTYPE_SEND_BOS:
	case SO_HIP_BOS:
		err = hip_socket_bos_wo(msg);
		//err = hip_socket_send_bos(msg);
		break;
#endif
	default:
		HIP_ERROR("Unknown socket option (%d)\n", msg_type);
		err = -ESOCKTNOSUPPORT;
	}

 out_err:
	return err;
}


/*
 * The socket options that need a return value.
 */
int hip_socket_getsockopt(struct socket *sock,
			  int   level,
			  int   optname,
			  char *optval,
			  int  *optlen)
{
        int err = 0;
	struct proto_ops *socket_handler;
	struct hip_common *msg = (struct hip_common *) optval;

	HIP_DEBUG("hip_socket_getsockopt called\n");

	if(optval == NULL)
	  HIP_DEBUG("optval == NULL\n");
#if 0 
	if (optname == SO_HIP_GET_HIT_LIST) {
		/* In this case the level corresponds to the port number */
		struct my_addrinfo **pai = (struct my_addrinfo **)optval;
		HIP_DEBUG("Got it\n");
		return (handle_bos_peer_list(AF_INET6, level, pai, *optlen));
	}
#endif

	HIP_DEBUG("Level %d\n", level);

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	HIP_DEBUG("Debug1\n");

	/* The message was destined to TCP or IP - forward */
	if (level != IPPROTO_HIP) {
		err = socket_handler->getsockopt(sock, level, optname, optval,
						 optlen);
		goto out_err;
	}

	HIP_DEBUG("Debug2\n");

	if (!(optname == SO_HIP_GLOBAL_OPT || optname == SO_HIP_SOCKET_OPT)) {
		err = -ESOCKTNOSUPPORT;
		goto out_err;
	}

	HIP_DEBUG("Debug3\n");

	err = hip_check_userspace_msg(msg);
	if (err) {
		HIP_ERROR("HIP socket option was malformed\n");
		goto out_err;
	}

	HIP_DEBUG("Debug4\n");
   
	HIP_DEBUG("optlen = %d\n", *optlen);

	if (hip_get_msg_total_len(msg) != *optlen) {
		HIP_ERROR("HIP socket option length was incorrect\n");
		err = -EMSGSIZE;
		goto out_err;		
	}

	HIP_DEBUG("Debug5\n");

	/* XX FIX: we make the assumtion here that the socket option return
	   value has enough space... */
	
	switch(hip_get_msg_type(msg)) {
#if 0
        case SO_HIP_RUN_UNIT_TEST:
	  err = hip_socket_handle_unit_test(msg);
	  break;
//#endif
	case SO_HIP_SET_MY_EID:
	  HIP_DEBUG("SO_HIP_SET_MY_EID option found\n");
	  err = hip_socket_handle_set_my_eid(msg);
	  break;
	case SO_HIP_SET_PEER_EID:
	  HIP_DEBUG("SO_HIP_PEER_EID option found\n");
	    err = hip_socket_handle_set_peer_eid(msg);
		break;
#endif
	default:
		err = -ESOCKTNOSUPPORT;
	}


 out_err:

	return err;
}


int hip_socket_sendmsg(struct kiocb *iocb, struct socket *sock, 
		       struct msghdr *m, size_t total_len)

{
	int err = 0;
	struct proto_ops *socket_handler;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *pinfo = inet6_sk(sk);

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	HIP_DEBUG("sport=%d dport=%d\n", ntohs(inet->sport), ntohs(inet->dport));

	HIP_HEXDUMP("daddr", &pinfo->daddr,
		    sizeof(struct in6_addr));
	HIP_HEXDUMP("rcv_saddr", &pinfo->rcv_saddr,
		    sizeof(struct in6_addr));

	/* Returns the number of bytes sent on success */
	err = socket_handler->sendmsg(iocb, sock, m, total_len);
	HIP_DEBUG("Socket handler returned (%d)\n", err);

 out_err:

	return err;
}


int hip_socket_recvmsg(struct kiocb *iocb, struct socket *sock, 
		       struct msghdr *m, size_t total_len,
		       int flags)
{
	int err = 0;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *pinfo = inet6_sk(sk);
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	HIP_DEBUG("sport=%d dport=%d\n", ntohs(inet->sport),
		  ntohs(inet->dport));

	HIP_HEXDUMP("daddr", &pinfo->daddr,
		    sizeof(struct in6_addr));
	HIP_HEXDUMP("rcv_saddr", &pinfo->rcv_saddr,
		    sizeof(struct in6_addr));

	/* Returns the number of bytes received on success */
	err = socket_handler->recvmsg(iocb, sock, m, total_len, flags);
	HIP_DEBUG("Socket handler returned (%d)\n", err);


 out_err:

	return err;
}


int hip_socket_mmap(struct file *file, struct socket *sock,
		    struct vm_area_struct *vma)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->mmap(file, sock, vma);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;
}


ssize_t hip_socket_sendpage(struct socket *sock, struct page *page, int offset,
			    size_t size, int flags)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->sendpage(sock, page, offset, size, flags);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:
	return err;
}

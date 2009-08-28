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
*
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/types.h>
#include <linux/net.h>
#include <linux/socket.h>

#include "debug.h"
#include "eid_db.h"

#ifndef IPPROTO_HIP
#  define IPPROTO_HIP             139 /* Also in libinet6/include/netinet/in.h */
#endif

#define NETLINK_HIP             32   /* Host Identity Protocol signalling messages */

extern struct net_proto_family hip_family_ops;
extern struct proto_ops inet_stream_ops;
extern struct proto_ops inet_dgram_ops;
extern struct proto_ops inet6_stream_ops;
extern struct proto_ops inet6_dgram_ops;
extern int inet6_create(struct net *net, struct socket *sock, int protocol);


// kernel module related functions
int  hsock_init_module(void);

void hsock_cleanup_module(void);


// socket handler functions (mostly taken from khipmod/socket.c)
int  hip_init_socket_handler(void);

int hip_uninit_socket_handler(void);

int  hip_create_socket(struct net *net, struct socket *sock, int protocol);


// protocol functions (mostly taken from khipmod/socket.c)
int hip_socket_release(struct socket *sock);

int hip_socket_bind(struct socket *sock,
		    struct sockaddr *umyaddr,
		    int sockaddr_len);
		    
int hip_socket_connect(struct socket *sock,
		       struct sockaddr *uservaddr,
		       int sockaddr_len, int flags);
		       
int hip_socket_socketpair(struct socket *sock1, 
			  struct socket *sock2);
			  
int hip_socket_accept(struct socket *sock, 
		      struct socket *newsock,
		      int flags);
		      
int hip_socket_getname(struct socket *sock, 
		       struct sockaddr *uaddr,
		       int *usockaddr_len,
		       int peer);
		       
unsigned int hip_socket_poll(struct file *file,
			     struct socket *sock,
			     struct poll_table_struct *wait);

int hip_socket_ioctl(struct socket *sock, 
		     unsigned int cmd,
		     unsigned long arg);    


int hip_socket_listen(struct socket *sock, int backlog);

int hip_socket_shutdown(struct socket *sock, int flags);

int hip_socket_setsockopt(struct socket *sock,
			  int   level,
			  int   optname,
			  char *optval,
			  int   optlen);

int hip_socket_sendmsg(struct kiocb *iocb,
		       struct socket *sock, 
		       struct msghdr *m,
		       size_t total_len);


int hip_socket_recvmsg(struct kiocb *iocb,
		       struct socket *sock, 
		       struct msghdr *m, 
		       size_t total_len,
		       int    flags);
		          
int hip_socket_mmap(struct file *file,
		    struct socket *sock,
		    struct vm_area_struct *vma);
		    
ssize_t hip_socket_sendpage(struct socket *sock,
			    struct page *page,
			    int    offset,
			    size_t size,
			    int    flags);

int hip_socket_getsockopt(struct socket *sock,
			  int   level,
			  int   optname,
			  char *optval,
			  int  *optlen);
			  			    




/* struct with function pointers to the socket creation
   function */ 
struct net_proto_family hip_family_ops = {
	family:         PF_HIP,
	create:         hip_create_socket
};

/* struct with function pointers to the handling functions */
static struct proto_ops hip_socket_ops = {
	family:		PF_HIP,

	release:	hip_socket_release,
	bind:		hip_socket_bind,
	connect:	hip_socket_connect,
	socketpair:	hip_socket_socketpair,
	accept:		hip_socket_accept,
	getname:	hip_socket_getname,
	poll:		hip_socket_poll,
	ioctl:		hip_socket_ioctl,
	listen:		hip_socket_listen,
	shutdown:	hip_socket_shutdown,
	setsockopt:	hip_socket_setsockopt,
	getsockopt:	hip_socket_getsockopt,
	sendmsg:	hip_socket_sendmsg,
	recvmsg:	hip_socket_recvmsg,
	mmap:		hip_socket_mmap,
	sendpage:	hip_socket_sendpage
};

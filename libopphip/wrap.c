/** @file
 * HIP wrapper file to override functions. All functions that need to be
 * overriden should be put here.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @version 1.0
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note    HIPU: MAC OS X requires LD_PRELOAD conversion
 */
#ifdef CONFIG_HIP_OPPORTUNISTIC
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <dlfcn.h>
#include <pthread.h>
#include <poll.h>

#include "debug.h"
#include "hadb.h"
#include "hashtable.h"
#include "libinet6/util.h"
#include "icomm.h"
#include "wrap_db.h"

//static
int hip_db_exist = 0;

// used for dlsym_util
#define NUMBER_OF_DLSYM_FUNCTIONS 17

/* open() has varying number of args, so it is not in the list. fopen(),
   fdopen and create() are not in the list because they operate only on
   files, similarly as open. The separation between files and sockets is
   done with in socket() or dynamically in read() or write() calls. */
struct {
	int (*socket_dlsym)(int domain, int type, int protocol);
	int (*bind_dlsym)(int socket, const struct sockaddr *sa,
			  socklen_t sa_len);
	int (*connect_dlsym)(int a, const struct sockaddr * b, socklen_t c);
	ssize_t (*send_dlsym)(int s, const void *buf, size_t len, int flags);
	ssize_t (*sendto_dlsym)(int s, const void *buf, size_t len, int flags, 
				const struct sockaddr *to, socklen_t tolen);
	ssize_t (*sendmsg_dlsym)(int s, const struct msghdr *msg, int flags);
	ssize_t (*recv_dlsym)(int s, const void *buf, size_t len, int flags);
	ssize_t (*recvfrom_dlsym)(int s, void *buf, size_t len, int flags, 
				  struct sockaddr *from, socklen_t *fromlen);
	ssize_t (*recvmsg_dlsym)(int s, struct msghdr *msg, int flags);
	int (*accept_dlsym)(int sockfd, struct sockaddr *addr,
			    socklen_t *addrlen);
	ssize_t (*write_dlsym)(int fd, const void *buf, size_t count);
	ssize_t (*read_dlsym)(int fd, void *buf, size_t count);
	int (*close_dlsym)(int fd);
	int (*listen_dlsym)(int sockfd, int backlog);
	ssize_t (*readv_dlsym)(int fd, const struct iovec *vector, int count);
	ssize_t (*writev_dlsym)(int fd, const struct iovec *vector, int count);
        int (*poll_dlsym)(struct pollfd *fds, nfds_t nfds, int timeout);
        
} dl_function_ptr;
/* XX TODO: ADD: clone() dup(), dup2(), fclose(), select ? */

void *dl_function_fd[NUMBER_OF_DLSYM_FUNCTIONS];
void *dl_function_name[] =
{"socket", "bind", "connect", "send", "sendto",
 "sendmsg", "recv", "recvfrom", "recvmsg", "accept",
 "write", "read", "close", "listen", "readv",
 "writev", "poll"};

void hip_init_dlsym_functions()
{
	int err = 0, i;
	char *error = NULL;
	
	for (i = 0; i < NUMBER_OF_DLSYM_FUNCTIONS; i++) {
		dl_function_fd[i] = dlopen(SOFILE, RTLD_LAZY);
		HIP_ASSERT(dl_function_fd[i]);
		((int **) (&dl_function_ptr))[i] =
			dlsym(dl_function_fd[i], dl_function_name[i]);
	}
	
	error = dlerror();
	if (err){
		HIP_DIE("dlerror: %s\n", error);
	}
}

void hip_uninit_dlsym_functions()
{
	int i = 0;
	for (i = 0; i < NUMBER_OF_DLSYM_FUNCTIONS; i++) {
		dlclose(dl_function_fd[i]);
	}
}

void hip_uninitialize_db()
{
	hip_uninit_dlsym_functions();
	hip_uninit_socket_db();
}

void hip_initialize_db_when_not_exist()
{

        const char *cfile = "default";
	int err = 0;
	
	if (hip_db_exist)
		return;

	srand(getpid());
	
	hip_set_logtype(LOGTYPE_SYSLOG);
	//hip_set_logtype(LOGTYPE_STDERR);
	hip_set_logfmt(LOGFMT_LONG);
	HIP_IFEL(hip_set_auto_logdebug(cfile), -1,
	  "Error: Cannot set the debugging parameter.\n");

	hip_init_dlsym_functions();
	hip_init_socket_db();
	HIP_DEBUG("socketdb initialized\n");
	// XX FIXME: SHOULD HAVE ALSO SIGNAL HANDLERS?
	atexit(hip_uninitialize_db);
	hip_db_exist = 1;

     out_err:
	return;

}

int hip_get_local_hit_wrapper(hip_hit_t *hit)
{
	int err = 0;
	char *param;
	struct hip_common *msg = NULL;
	//struct gaih_addrtuple *at = NULL;

	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT, 0),
		 -1, "Fail to get hits");
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send/recv\n");
	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_HIT)), -1,
		 "No HIT received\n");
	ipv6_addr_copy(hit, hip_get_param_contents_direct(param));
	_HIP_DEBUG_HIT("hit", hit);
	
#if 0
	err = get_local_hits(NULL, &at);
	if (err)
		HIP_ERROR("getting local hit failed\n");
	else
		memcpy(hit, &at->addr, sizeof(hip_hit_t));
	
	if (at)
		HIP_FREE(at);
#endif
 out_err:
	if (msg)
		free(msg);
	return err;
}

inline int hip_domain_is_inet(int domain)
{
	return (domain == PF_INET || domain == PF_INET6);
}

inline int hip_type_is_stream_or_dgram(int type)
{
	return (type == SOCK_STREAM || type == SOCK_DGRAM);
}

inline int hip_check_domain_type_protocol(int domain, int type, int protocol)
{
	return (!hip_domain_is_inet(domain)) ||
		(!hip_type_is_stream_or_dgram(type)) || 
		(!(protocol == 0));
}

inline int hip_check_msg_name(const struct msghdr *msg)
{
	return ((msg->msg_name != NULL) && \
		(!(((struct sockaddr_in6 *)(&msg->msg_name))->sin6_family == PF_INET || \
		   ((struct sockaddr_in6 *)(&msg->msg_name))->sin6_family == PF_INET6)));
}

inline int hip_sockaddr_wrapping_is_applicable(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET6)
		if (ipv6_addr_is_hit(hip_cast_sa_addr(sa)) || IN6_IS_ADDR_LOOPBACK(hip_cast_sa_addr(sa)))
			return 0;
	
	if (!(sa->sa_family == AF_INET || sa->sa_family == AF_INET6))
		return 0;

	if (sa->sa_family == AF_INET) {
		struct in_addr *oip = hip_cast_sa_addr(sa);
		if (oip->s_addr == htonl(INADDR_LOOPBACK) /*|| oip->s_addr == htonl(INADDR_ANY)*/)
			return 0;
	}

	return 1;
}


inline int hip_wrapping_is_applicable(const struct sockaddr *sa, hip_opp_socket_t *entry)
{
	HIP_ASSERT(entry);

	if (!(entry->protocol == 0 ||
	      entry->protocol == IPPROTO_TCP ||
	      entry->protocol == IPPROTO_UDP ||
	      entry->protocol == IPPROTO_ICMP ||
	      entry->protocol == IPPROTO_ICMPV6))
		return 0;	

	if (!(entry->domain == PF_INET6 || entry->domain == PF_INET))
		return 0;

	if (!(entry->type == SOCK_STREAM ||
	      entry->type == SOCK_DGRAM ||
	      entry->type == SOCK_RAW))
		return 0;

	if(entry->type == SOCK_RAW){
		if(!(entry->protocol == IPPROTO_ICMP ||
		     entry->protocol == IPPROTO_ICMPV6))
			return 0;
	}

	if (entry->force_orig)
		return 0;

	if (sa && !hip_sockaddr_wrapping_is_applicable(sa)) {
		HIP_DEBUG_SOCKADDR("wrap not applicable for addr", sa);
		return 0;
	}

	if (entry->orig_local_id.ss_family)
		if (hip_sockaddr_wrapping_is_applicable(&entry->orig_local_id) == 0)
				return 0;

	if (entry->orig_peer_id.ss_family)
		if (hip_sockaddr_wrapping_is_applicable(&entry->orig_peer_id) == 0)
			return 0;

	HIP_DEBUG("Wrapping applicable\n");

	return 1;
}

#if 0
/* Some unfinished code for msg header handling. We probably need a complete
   msghdr in opp entry. Consider that pktinfo may be for IPv4 communications
   and we need to wrap it to IPv6. */
int hip_get_pktinfo_addr(struct msghdr *msg, int is_ipv4,
			 struct in6_addr **saddr,
			 struct in6_addr **daddr)
{
	struct sockaddr_storage addr_from;
	struct sockaddr_in *addr_from4 = ((struct sockaddr_in *) &addr_from);
	struct sockaddr_in6 *addr_from6 =
		((struct sockaddr_in6 *) &addr_from);
        struct cmsghdr *cmsg;
        //struct msghdr msg;
	union {
		struct in_pktinfo *pktinfo_in4;
		struct in6_pktinfo *pktinfo_in6;
	} pktinfo;
        int err = 0;
	int cmsg_level, cmsg_type;

	pktinfo.pktinfo_in4 = NULL;

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
	HIP_IFEL(!pktinfo.pktinfo_in4 && read_addr, -1,
		 "Could not determine dst addr, dropping\n");

	/* IPv4 addresses */
	if (is_ipv4) {
		if (saddr)
			IPV4_TO_IPV6_MAP(&addr_from4->sin_addr, saddr);
		if (daddr)
			IPV4_TO_IPV6_MAP(&pktinfo.pktinfo_in4->ipi_addr,
					 daddr);
	} else {
		/* IPv6 addresses */
		if (saddr)
			memcpy(saddr, &addr_from6->sin6_addr,
			       sizeof(struct in6_addr));
		if (daddr)
			memcpy(daddr, &pktinfo.pktinfo_in6->ipi6_addr,
			       sizeof(struct in6_addr));
	}

	if (saddr)
		HIP_DEBUG_IN6ADDR("src", saddr);
	if (daddr)
		HIP_DEBUG_IN6ADDR("dst", daddr);

 out_err:
	return err;
}
#endif

void hip_store_orig_socket_info(hip_opp_socket_t *entry, int is_peer, const int socket,
			    const struct sockaddr *sa, const socklen_t sa_len)
{
	/* Fill in the information of original socket */
	entry->orig_socket = socket;
	if (is_peer) {
		memcpy(&entry->orig_peer_id, sa, sa_len);
		entry->orig_peer_id_len = sa_len;
	} else {
		memcpy(&entry->orig_local_id, sa, sa_len);
		entry->orig_local_id_len = sa_len;
	}
}


int hip_request_peer_hit_from_hipd(const struct in6_addr *peer_ip,
				   struct in6_addr *peer_hit,
				   const struct in6_addr *local_hit,
				   in_port_t *src_tcp_port,//the local TCP port needed for the TCP i1 option negotiation
				   in_port_t *dst_tcp_port, //the TCP port at the peer needed for the TCP i1 option negotiation
				   int *fallback,
				   int *reject)
{
	struct hip_common *msg = NULL;
	struct in6_addr *hit_recv = NULL;
	hip_hit_t *ptr = NULL;
	int err = 0;
	int ret = 0;

	*fallback = 1;
	*reject = 0;
	
	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	
	HIP_IFEL(hip_build_param_contents(msg, (void *)(local_hit),
					  HIP_PARAM_HIT_PEER,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_HIT  failed\n");
	HIP_IFEL(hip_build_param_contents(msg, (void *)(local_hit),
					  HIP_PARAM_HIT_LOCAL,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_HIT  failed\n");
	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_ip),
					  HIP_PARAM_IPV6_ADDR_PEER,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_IPV6_ADDR failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (void *)(src_tcp_port),
					  HIP_PARAM_SRC_TCP_PORT,
					  sizeof(in_port_t)), -1,
		 "build param HIP_PARAM_SRC_TCP_PORT failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (void *)(dst_tcp_port),
					  HIP_PARAM_DST_TCP_PORT,
					  sizeof(in_port_t)), -1,
		 "build param HIP_PARAM_DST_TCP_PORT failed\n");
	
	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT, 0), -1,
		 "build hdr failed\n");
	
	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");
	
	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");
	
	ptr = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT_PEER);
	if (ptr) {
		memcpy(peer_hit, ptr, sizeof(hip_hit_t));
		HIP_DEBUG_HIT("peer_hit", peer_hit);
		*fallback = 0;
	}

	ptr = hip_get_param(msg, HIP_PARAM_AGENT_REJECT);
	if (ptr)
	{
		HIP_DEBUG("Connection is to be rejected\n");
		*reject = 1;
	}
	
 out_err:
	
	if(msg)
		free(msg);
	
	return err;
}

void hip_translate_to_original(hip_opp_socket_t *entry, int is_peer)
{
	/* translated entries correspond to originals   */
	_HIP_DEBUG("Translating to original %d\n", entry->orig_socket);

	entry->translated_socket = entry->orig_socket;
	if (is_peer) {
		memcpy(&entry->translated_peer_id, &entry->orig_peer_id,
		       sizeof(struct sockaddr_storage));
		entry->peer_id_is_translated = 1;
	} else {
		memcpy(&entry->translated_local_id, &entry->orig_local_id,
		       sizeof(struct sockaddr_storage));
		entry->local_id_is_translated = 1;
	}
}

inline int hip_create_new_hit_socket(hip_opp_socket_t *entry) {
	return dl_function_ptr.socket_dlsym(AF_INET6,
					    entry->type,
					    entry->protocol);
}

int hip_set_translation(hip_opp_socket_t *entry,
			struct sockaddr_in6 *hit,
			int is_peer) {
	int err = 0;
	
	if (!entry->translated_socket) {
		int new_socket = hip_create_new_hit_socket(entry);
		HIP_DEBUG("Created new translatable socket %d\n", new_socket);
		if (new_socket <= 0) {
			err = -1;
			HIP_ERROR("socket allocation failed\n");
			goto out_err;
		}
		entry->translated_socket = new_socket;
		_HIP_DEBUG("Inserted translated socket in: pid=%d orig_socket=%d new_socket=%d domain=%d\n",
		          entry->pid, entry->orig_socket,
		          entry->translated_socket,
		          entry->domain);
	}
	
	if (is_peer) {
		memcpy(&entry->translated_peer_id, hit, hip_sockaddr_len(hit));
		entry->translated_peer_id_len = hip_sockaddr_len(hit);
		entry->peer_id_is_translated = 1;
	} else {
		memcpy(&entry->translated_local_id, hit, hip_sockaddr_len(hit));
		entry->translated_local_id_len = hip_sockaddr_len(hit);
		entry->local_id_is_translated = 1;
	}
	
 out_err:
	return err;
	
}

int hip_autobind_port(hip_opp_socket_t *entry, struct sockaddr_in6 *hit) {
	int err = 0;
	pid_t pid = getpid();

	_HIP_DEBUG("autobind called\n");

	do { /* XX FIXME: CHECK UPPER BOUNDARY */
		hit->sin6_port = htons(rand());
	} while (ntohs(hit->sin6_port) < 1024);

	_HIP_DEBUG("autobind selected port %d\n", ntohs(hit->sin6_port));

  	HIP_IFE(hip_set_translation(entry, hit, 0), -1);

	err = dl_function_ptr.bind_dlsym(entry->translated_socket,
					 (struct sockaddr *) &entry->translated_local_id,
					 hip_sockaddr_len(&entry->translated_local_id));
	if (err) {
		HIP_PERROR("autobind");
		goto out_err;
	}
	
 out_err:
	return err;
}

int hip_translate_new(hip_opp_socket_t *entry,
		      const int orig_socket,
		      const struct sockaddr *orig_id,
		      const socklen_t orig_id_len,
		      int is_peer, int is_dgram,
		      int is_translated, int wrap_applicable)
{
	int err = 0, pid = getpid();
	in_port_t src_opptcp_port = 0, dst_opptcp_port = 0;/*the ports needed to send the TCP SYN i1*/
	struct sockaddr_in6 src_hit, dst_hit,
		*hit = (is_peer ? &dst_hit : &src_hit);
	socklen_t translated_id_len;
	struct sockaddr_in6 mapped_addr;

	//HIP_ASSERT((entry->type == SOCK_STREAM) || orig_id);

	/* i.e. socket(PF_FILE), connect and read */
	HIP_IFEL(!orig_id, 0, "No new id to translate, bailing out\n");
	
	HIP_DEBUG("Translating to new socket (orig %d)\n", orig_socket);
	
	memset(&src_hit, 0, sizeof(src_hit));
	memset(&dst_hit, 0, sizeof(dst_hit));
	src_hit.sin6_family = AF_INET6;

	HIP_IFEL(hip_get_local_hit_wrapper(&src_hit.sin6_addr), -1,
		 "Querying of local HIT failed (no hipd running?)\n");

	if (is_peer && !entry->local_id_is_translated) {
		/* Can happen also with UDP based sockets with
		   connect() + send() */
		HIP_IFEL(hip_autobind_port(entry, &src_hit), -1,
			 "autobind failed\n");
	} else {
		_HIP_DEBUG("autobind was not necessary\n");
	}

	_HIP_DEBUG_IN6ADDR("translate new: src addr", &src_hit.sin6_addr);
	
	/* hipd requires IPv4 addresses in IPv6 mapped format */
	if (orig_id->sa_family == AF_INET) {
		IPV4_TO_IPV6_MAP(&((struct sockaddr_in *) orig_id)->sin_addr,
				 &mapped_addr.sin6_addr);
		_HIP_DEBUG_SOCKADDR("ipv4 addr", orig_id);
		dst_opptcp_port = ((struct sockaddr_in *)orig_id)->sin_port;
	} else if (orig_id->sa_family == AF_INET6) {
		memcpy(&mapped_addr, orig_id, orig_id_len);
		_HIP_DEBUG_SOCKADDR("ipv6 addr\n", orig_id);
		dst_opptcp_port = ((struct sockaddr_in6 *)orig_id)->sin6_port;
	} else {
		HIP_ASSERT("Not an IPv4/IPv6 socket: wrapping_is_applicable failed?\n");
	}
	mapped_addr.sin6_family = orig_id->sa_family;
	mapped_addr.sin6_port = dst_opptcp_port;
	
	hit->sin6_port = dst_opptcp_port;
	
	_HIP_DEBUG("sin_port=%d\n", ntohs(dst_opptcp_port));
	_HIP_DEBUG_IN6ADDR("sin6_addr ip = ", ip);


	/*find the local TCP port where the
	application	initiated the connection,
	we need it for sending the TCP SYN_i1*/
	struct sockaddr *sa = (struct sockaddr*)&(entry->translated_local_id);
  	if(sa->sa_family == AF_INET)
    		src_opptcp_port = ((struct sockaddr_in *) sa)->sin_port;
  	else//AF_INET6
    		src_opptcp_port = ((struct sockaddr_in6 *) sa)->sin6_port;


	/* Try opportunistic base exchange to retrieve peer's HIT */
	if (is_peer) {
		int fallback, reject;
		/* Request a HIT of the peer from hipd. This will possibly
		   launch an I1 with NULL HIT that will block until R1 is
		   received. Called e.g. in connect() or sendto(). If
		   opportunistic HIP fails, it can return an IP address
		   instead of a HIT */
		HIP_DEBUG("requesting hit from hipd\n");
		HIP_DEBUG_IN6ADDR("ip addr", &mapped_addr.sin6_addr);
		HIP_IFEL(hip_request_peer_hit_from_hipd(&mapped_addr.sin6_addr,
							&dst_hit.sin6_addr,
							&src_hit.sin6_addr,
							(in_port_t *) &src_opptcp_port,
							(in_port_t *) &dst_opptcp_port,
							&fallback,
							&reject),
			 -1, "Request from hipd failed\n");
		if (reject) {
			HIP_DEBUG("Connection should be rejected\n");
			err = -1;
			goto out_err;
		}

		if (fallback) {
			HIP_DEBUG("Peer does not support HIP, fallback\n");
			goto out_err;
		}
		dst_hit.sin6_family = AF_INET6;
	} else {
		/* Called e.g. in bind() */
		HIP_DEBUG("Binding to inaddr6_any\n");
		src_hit.sin6_addr = in6addr_any;
		src_hit.sin6_family = AF_INET6;
	}
	
	if (err || IN6_IS_ADDR_V4MAPPED(&hit->sin6_addr) ||
	    (!ipv6_addr_any(&hit->sin6_addr) && !ipv6_addr_is_hit(&hit->sin6_addr))) {
		HIP_DEBUG("Localhost/peer does not support HIP, falling back to IP\n");
		goto out_err;
	}

	HIP_DEBUG("HIT translation was successful\n");
	
	/* We have now successfully translated an IP to an HIT. The HIT
	   requires a new socket. Also, we need set the return values
	   correctly */
	HIP_IFE(hip_set_translation(entry, hit, is_peer), -1);

	_HIP_DEBUG("translation: pid %p, orig socket %p, translated sock %p\n",
		  entry->pid, entry->orig_socket, entry->translated_socket);
	
	return err;
	
 out_err:
	hip_translate_to_original(entry, is_peer);
	return err;
}

int hip_old_translation_is_ok(hip_opp_socket_t *entry,
			  const int orig_socket,
			  const struct sockaddr *orig_id,
			  const socklen_t orig_id_len,
			  int is_peer, int is_dgram,
			  int is_translated, int wrap_applicable)
{
	void *translated_id =
	  (is_peer ? &entry->translated_peer_id : &entry->translated_local_id);

	/*
	 * An entry does not require translation when...
	 *
	 * (1) the entry must be already translated once
	 *
	 * and one of the following:
	 *
	 * (2) connection oriented socket call does not require new translation
	 * (3) original id was not given (e.g. recvfrom with NULL src)
	 * (4) optimization: we don't do a new translation unless the app
	 *     layer id has changed. Note: this optimization may have
	 *     limitations when addressing hosts behind a remote NAT network
	 */
	
	if (is_translated &&                                /* 1 */
	    (!is_dgram ||                                   /* 2 */
	     !orig_id  ||                                   /* 3 */
	     !memcmp(translated_id, orig_id, orig_id_len))) /* 4 */ {
		_HIP_DEBUG("Old translation ok %d\n", entry->orig_socket);
		return 1;
	} else {
		_HIP_DEBUG("New translation required\n");
		return 0;
	}
}

hip_opp_socket_t *hip_create_new_opp_entry(int pid, const int fd, pthread_t tid)
{
	hip_opp_socket_t *entry = NULL;
	int err = 0;

	_HIP_DEBUG("\n");
	
	hip_initialize_db_when_not_exist();

	if (!hip_exists_translation(pid, fd, tid))
		err = hip_socketdb_add_entry(pid, fd, tid);
	if(err) {
		HIP_ERROR("Could not add entry\n");
		goto out_err;
	}

	entry = hip_socketdb_find_entry(pid, fd, pthread_self());
	HIP_ASSERT(entry);
	
 out_err:
	_HIP_DEBUG("Called socket_dlsym fd=%d\n", fd);  

	return entry;
}

int hip_create_nontranslable_socket(int domain, int type, int protocol) {
	hip_opp_socket_t *entry;
	int fd = dl_function_ptr.socket_dlsym(domain, type, protocol);
	
	entry = hip_create_new_opp_entry(getpid(), fd, pthread_self());
	entry->protocol = -1; /* prevents translation */
	return fd;
}

int hip_add_orig_socket_to_db(int socket_fd, int domain, int type,
			      int protocol)
{
	hip_opp_socket_t *entry = NULL;
	int pid = 0, err = 0;
	pthread_t tid = pthread_self();

	_HIP_DEBUG("socket fd %d\n", socket_fd);
	
	if(socket_fd == -1) {
		HIP_ERROR("Socket error\n");
		goto out_err;
	}

	pid = getpid();

	//HIP_ASSERT(!hip_socketdb_find_entry(pid, socket_fd));

	/* Workaround: see bug id 271. For some unknown reason, the library
	   is not catching all close() calls from libinet6. */
	if (entry = hip_socketdb_find_entry(pid, socket_fd, tid)) {
		hip_socketdb_del_entry_by_entry(entry);
	}

	entry = hip_create_new_opp_entry(pid, socket_fd, tid);
	HIP_ASSERT(entry);
	entry->domain = domain;
	entry->type = type;
	if (protocol == -1) {
		entry->protocol = protocol;
		entry->force_orig = 1;
	} else {
		entry->protocol = protocol;
	}

 out_err:
	return err;
}

int hip_translate_socket(const int *orig_socket, const struct sockaddr *orig_id,
			 const socklen_t *orig_id_len, int **translated_socket,
			 struct sockaddr **translated_id,
			 socklen_t **translated_id_len, int is_peer,
			 int is_dgram, int force_orig)
{
	int err = 0, pid = 0, is_translated = 0, wrap_applicable = 0;
	hip_opp_socket_t *entry = NULL;
	int fu = 0;
	pthread_t tid;

	pid = getpid();
	tid = pthread_self();

	hip_initialize_db_when_not_exist();

	HIP_ASSERT(orig_socket);
	entry = hip_socketdb_find_entry(pid, *orig_socket, tid);

	if (!entry) {
	        _HIP_DEBUG("entry was not foundin db\n");
		/* Can happen in the case of read() or write() on a fd;
		   we are not wrapping open() or creat() calls which means
		   that we don't have an entry for them. */
		entry = hip_create_new_opp_entry(pid, *orig_socket, tid);
		/* PF_LOCAL guarantees that the socket won't be translated */
		entry->domain = PF_LOCAL;
		_HIP_DEBUG("created untranslated entry\n");
	}
	HIP_ASSERT(entry);

	entry->force_orig = entry->force_orig | force_orig;
	
	is_translated =
		(is_peer ? entry->peer_id_is_translated :
		 entry->local_id_is_translated);
	wrap_applicable = hip_wrapping_is_applicable(orig_id, entry);

	_HIP_DEBUG("orig_id=%p is_dgram=%d wrap_applicable=%d already=%d is_peer=%d force=%d\n",
		  orig_id, is_dgram, wrap_applicable, is_translated, is_peer,
		  force_orig);

	if (orig_id) {
		if (orig_id->sa_family == AF_INET)
			_HIP_DEBUG_SOCKADDR("orig_id", orig_id);
		else if (orig_id->sa_family == AF_INET6)
			_HIP_DEBUG_SOCKADDR("orig_id", orig_id);
		else
			_HIP_DEBUG("orig_id family %d\n", orig_id->sa_family);
	}
	
	if (!is_translated && orig_id)
		hip_store_orig_socket_info(entry, is_peer, *orig_socket,
					   orig_id, *orig_id_len);

	if (!wrap_applicable)
		hip_translate_to_original(entry, is_peer);
	else if (hip_old_translation_is_ok(entry, *orig_socket, orig_id,
					   *orig_id_len, is_peer, is_dgram,
					   is_translated, wrap_applicable))
		_HIP_DEBUG("Keeping the existing translation\n");
	else
		err = hip_translate_new(entry, *orig_socket, orig_id,
					*orig_id_len, is_peer, is_dgram,
					is_translated, wrap_applicable);

	if (err) {
		HIP_ERROR("Error occurred during translation\n");
	}

	if (entry->orig_socket == entry->translated_socket) {
		_HIP_DEBUG("No translation occured, returning original socket and id\n");
		*translated_socket = (int *) orig_socket;
		*translated_id = (struct sockaddr *) orig_id;
		*translated_id_len = (socklen_t *) orig_id_len;
	} else {
		HIP_DEBUG("Returning translated socket and id\n");
		*translated_socket = &entry->translated_socket;
		*translated_id = (struct sockaddr *)
			(is_peer ? &entry->translated_peer_id :
			 &entry->translated_local_id);
		*translated_id_len =
			(is_peer ? &entry->translated_peer_id_len :
			 &entry->translated_local_id_len);
	}

 out_err:
	
	_HIP_DEBUG("translation: pid %p, orig socket %p, translated sock %p\n",
		  pid, orig_socket, *translated_socket);
	_HIP_DEBUG_HIT("orig_local_id", hip_cast_sa_addr(&entry->orig_local_id));
	_HIP_DEBUG_HIT("orig_dst_id", hip_cast_sa_addr(&entry->orig_peer_id));
	_HIP_DEBUG_HIT("trans_local_id", hip_cast_sa_addr(&entry->translated_local_id));
	_HIP_DEBUG_HIT("trans_dst_id", hip_cast_sa_addr(&entry->translated_peer_id));
	_HIP_DEBUG("orig_id %p, translated_id %p\n", orig_id, *translated_id);
	_HIP_DEBUG("orig fd %d, translated fd %d\n", entry->orig_socket,
		  entry->translated_socket);

	return err;
}

int socket(int domain, int type, int protocol)
{
	int socket_fd = -1, err = 0;

	hip_initialize_db_when_not_exist();
	
	_HIP_DEBUG("creating socket domain=%d type=%d protocol=%d\n",
		  domain, type, protocol);

	socket_fd = dl_function_ptr.socket_dlsym(domain, type, ((protocol == -1) ? 0 : protocol));

	if (socket_fd > 0)
		err = hip_add_orig_socket_to_db(socket_fd, domain, type, protocol);
	if (err) {
		HIP_ERROR("Failed to add orig socket to db\n");
		goto out_err;
	}

  out_err:
	_HIP_DEBUG("Called socket_dlsym socket_fd=%d\n", socket_fd);  
	 return socket_fd;
}

int close(int orig_fd)
{
	int err = 0, pid = 0;
	hip_opp_socket_t *entry = NULL;
	char *error = NULL;
	pthread_t tid = pthread_self();

	/* The database and the function pointers may not be initialized
	   because e.g. open call is not wrapped. We need only the
	   dl_function_ptr.close_dlsym to be initialized here, but let's
	   initialize everything anyway. This way, there is no need to
	   check hip_db_exist value everywhere. */
	hip_initialize_db_when_not_exist();
	
	_HIP_DEBUG("close() orig fd %d\n", orig_fd);

	//if (hip_db_exist) hip_socketdb_dump();

	/* close original socket */
	err = dl_function_ptr.close_dlsym(orig_fd);

	pid = getpid();

	entry = hip_socketdb_find_entry(pid, orig_fd, tid);
	if (!entry)
		goto out_err;

	//HIP_ASSERT(entry);

	/* close new_socket */
	if(entry->translated_socket &&
	   entry->orig_socket != entry->translated_socket) {
		err = dl_function_ptr.close_dlsym(entry->translated_socket);
		hip_socketdb_del_entry_by_entry(entry);
		_HIP_DEBUG("old_socket %d new_socket %d  deleted!\n", 
			  entry->orig_socket,
			  entry->translated_socket);	  
	}else{
	        hip_socketdb_del_entry_by_entry(entry);
	        _HIP_DEBUG("old_socket %d new_socket %d  DELETED2!\n",
			  entry->orig_socket,
			  entry->translated_socket);	  
	  }
	if (err)
		HIP_ERROR("Err %d close trans socket\n", err);
	//hip_socketdb_dump();
 out_err:
	_HIP_DEBUG("close_dlsym called with err %d\n", err);
	
  return err;
}

int bind(int orig_socket, const struct sockaddr *orig_id,
	 socklen_t orig_id_len)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;

	_HIP_DEBUG("bind: orig sock = %d\n", orig_socket);

	/* the address will be translated to in6addr_any */

	err = hip_translate_socket(&orig_socket, orig_id, &orig_id_len,
				   &translated_socket, &translated_id,
				   &translated_id_len, 0, 0, 0);

	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	err = dl_function_ptr.bind_dlsym(*translated_socket, translated_id,
					 *translated_id_len);
	if (err) {
		HIP_PERROR("bind error:");
	}
	
 out_err:
	return err;
}

int listen(int orig_socket, int backlog)
{
	int err = 0, *translated_socket, zero = 0;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;

	_HIP_DEBUG("listen: orig sock = %d\n", orig_socket);

	err = hip_translate_socket(&orig_socket, NULL, &zero,
				   &translated_socket, &translated_id,
				   &translated_id_len, 0, 0, 0);

	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	err = dl_function_ptr.listen_dlsym(*translated_socket, backlog);
	if (err) {
		HIP_PERROR("connect error:");
	}
	
 out_err:
	return err;
}

int accept(int orig_socket, struct sockaddr *orig_id, socklen_t *orig_id_len)
{
	int err = 0, *translated_socket, new_sock;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;
	hip_opp_socket_t *entry = NULL;
	struct sockaddr_storage peer_id;
	socklen_t peer_id_len = 0;
	pthread_t tid = pthread_self();

	_HIP_DEBUG("accept: orig_socket %d orig_id %p\n",
		  orig_socket, orig_id);

	entry = hip_socketdb_find_entry(getpid(), orig_socket, tid);
	if (!entry) {
		HIP_DEBUG("Did not find entry, should not happen? Fallbacking..\n");
		new_sock = dl_function_ptr.accept_dlsym(orig_socket,
							(struct sockaddr *) &peer_id,
							&peer_id_len);
		goto out_err;
	}

	HIP_ASSERT(entry);

	/* The bind() was done on in6_addr any. It supports also ipv4 mapped
	   addresses and we can therefore safely just accept() that. */

	new_sock = dl_function_ptr.accept_dlsym(entry->translated_socket,
						(struct sockaddr *) &peer_id,
						&peer_id_len);
	if (new_sock < 0) {
		HIP_PERROR("accept error:");
		goto out_err;
	}

	err = hip_add_orig_socket_to_db(new_sock,
					entry->domain,
					entry->type,
					entry->protocol);
	if (err) {
		HIP_ERROR("Failed to add orig socket to db\n");
		goto out_err;
	}
	
	err = hip_translate_socket(&new_sock,
				   (struct sockaddr *) &entry->translated_local_id,
				   &entry->translated_local_id_len,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len, 0, 0, 1);
	if (err) {
		HIP_ERROR("Local id translation failure\n");
		goto out_err;
	}

	err = hip_translate_socket(&new_sock, (struct sockaddr *) &peer_id,
				   &peer_id_len,
				   &translated_socket, &translated_id,
				   &translated_id_len, 1, 0, 1);
	if (err) {
		HIP_ERROR("Peer id translation failure\n");
		goto out_err;
	}

 out_err:

	memcpy(orig_id, &peer_id, peer_id_len);
	memcpy(orig_id_len, &peer_id_len, sizeof(socklen_t));

	return new_sock;
}

int connect(int orig_socket, const struct sockaddr *orig_id,
	    socklen_t orig_id_len)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;
	
	_HIP_DEBUG("connect: orig_socket=%d\n", orig_socket);

	err = hip_translate_socket(&orig_socket, orig_id, &orig_id_len,
				   &translated_socket, &translated_id,
				   &translated_id_len, 1, 0, 0);

	_HIP_DEBUG("connect: translated_socket=%d\n", translated_socket);
	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	err = dl_function_ptr.connect_dlsym(*translated_socket, translated_id,
					    *translated_id_len);
	if (err) {
		HIP_PERROR("connect error\n");
	}

 out_err:
	return err;
}

/** 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t send(int orig_socket, const void * b, size_t c, int flags)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len, zero = 0;
	struct sockaddr *translated_id;
	ssize_t chars = -1;

	_HIP_DEBUG("send: %d\n", orig_socket);

	err = hip_translate_socket(&orig_socket, NULL, &zero,
				   &translated_socket, &translated_id,
				   &translated_id_len, 1, 0, 0);

	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	chars = dl_function_ptr.send_dlsym(*translated_socket, b, c, flags);
	
	_HIP_DEBUG("Called send_dlsym with number of returned char=%d, err=%d\n",
		  chars, err);
	
 out_err:
	
	return chars;
}

ssize_t write(int orig_socket, const void * b, size_t c)
{
	int err = 0, *translated_socket;
	ssize_t chars = -1;
	socklen_t *translated_id_len, zero = 0;
	struct sockaddr *translated_id;
	
	/* This functions is almost identical with send() */

	_HIP_DEBUG("write: orig_socket %d\n", orig_socket);

	err = hip_translate_socket(&orig_socket,
				   NULL,
				   &zero,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len,
				   1, 0, 0);

	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}

	chars = dl_function_ptr.write_dlsym(*translated_socket, b, c);
	
	_HIP_DEBUG("Called write_dlsym with number of returned char=%d\n",
		   chars);
	
 out_err:
	
	return chars;
}

ssize_t writev(int orig_socket, const struct iovec *vector, int count)
{
	int err = 0, *translated_socket;
	ssize_t chars = -1;
	socklen_t *translated_id_len, zero = 0;
	struct sockaddr *translated_id;
	
	/* This functions is almost identical with send() */

	_HIP_DEBUG("writev: orig_socket %d\n", orig_socket);

	err = hip_translate_socket(&orig_socket,
				   NULL,
				   &zero,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len,
				   1, 0, 0);

	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}

	chars = dl_function_ptr.writev_dlsym(*translated_socket, vector, count);
	
	_HIP_DEBUG("Called writev_dlsym with number of returned char=%d\n",
		  chars);
	
 out_err:
	
	return chars;
}

/** 
 * The calls return the number of characters sent, or -1 if an error occurred.
 * Untested.
 */
ssize_t sendto(int orig_socket, const void *buf, size_t buf_len, int flags, 
	       const struct sockaddr  *orig_id, socklen_t orig_id_len)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;
	ssize_t chars = -1;
	
	_HIP_DEBUG("sendto: orig sock = %d\n", orig_socket);

	err = hip_translate_socket(&orig_socket,
				   orig_id,
				   &orig_id_len,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len,
				   1, 1, 0);

	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	chars = dl_function_ptr.sendto_dlsym(*translated_socket, buf, buf_len,
					   flags,
					   translated_id,
					   *translated_id_len);

 out_err:

  return chars;
}

/** 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t sendmsg(int a, const struct msghdr *msg, int flags)
{
	int charnum;
	/** @todo See hip_get_pktinfo_addr(). */
	charnum = dl_function_ptr.sendmsg_dlsym(a, msg, flags);
	
	_HIP_DEBUG("Called sendmsg_dlsym with number of returned chars=%d\n", charnum);
	
	return charnum;
}

ssize_t recv(int orig_socket, void *b, size_t c, int flags)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len, zero = 0;
	struct sockaddr *translated_id;
	ssize_t chars = -1;
	
	_HIP_DEBUG("recv: orig sock = %d\n", orig_socket);

	err = hip_translate_socket(&orig_socket,
				   NULL,
				   &zero,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len,
				   0, 0, 0);

	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}

	chars = dl_function_ptr.recv_dlsym(*translated_socket, b, c, flags);

	_HIP_DEBUG("Called recv_dlsym with number of returned char=%d, err=%d\n",
		   chars, err);
	
 out_err:
	
	return chars;
}

ssize_t read(int orig_socket, void *b, size_t c)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len, zero = 0;
	struct sockaddr *translated_id;
	ssize_t chars = -1;
	
	/* This functions is almost identical with recv() */

	_HIP_DEBUG("read: orig_socket %d\n", orig_socket);

	err = hip_translate_socket(&orig_socket,
				   NULL,
				   &zero,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len,
				   0, 0, 0);

	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	if(translated_socket){
	  HIP_DEBUG("read: translated_socket %d\n", *translated_socket);
	  chars = dl_function_ptr.read_dlsym(*translated_socket, b, c);
	}else
	  HIP_DEBUG("read: no translated_socket found!\n");

	_HIP_DEBUG("Called read_dlsym with number of returned char=%d\n", chars);
	
 out_err:
	return chars;
}

ssize_t readv(int orig_socket, const struct iovec *vector, int count)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len, zero = 0;
	struct sockaddr *translated_id;
	ssize_t chars = -1;
	
	/* This functions is almost identical with recv() */

	_HIP_DEBUG("readv: orig_socket %d\n", orig_socket);

	err = hip_translate_socket(&orig_socket,
				   NULL,
				   &zero,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len,
				   0, 0, 0);

	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	chars = dl_function_ptr.readv_dlsym(*translated_socket, vector, count);
	
	_HIP_DEBUG("Called readv_dlsym with number of returned char=%d\n",
		  chars);
	
 out_err:
	
	return chars;
}

ssize_t recvfrom(int orig_socket, void *buf, size_t len, int flags, 
		 struct sockaddr *orig_id, socklen_t *orig_id_len)
{
	int err = 0, *translated_socket = NULL;
	socklen_t *translated_id_len = NULL;
	struct sockaddr *translated_id = NULL;
	ssize_t chars = -1;
	
	_HIP_DEBUG("recvfrom: orig sock = %d\n", orig_socket);

	/** @todo In the case of UDP server, this creates additional
	    HIP traffic even though the connection is not necessarily
	    secured. */
	err = hip_translate_socket(&orig_socket, orig_id, orig_id_len,
				   &translated_socket, &translated_id,
				   &translated_id_len, 0, 1, 0);
	
	if (err) {
		HIP_ERROR("Translation failure\n");
		chars = err;
		goto out_err;
	}
	
	chars = dl_function_ptr.recvfrom_dlsym(
		*translated_socket, buf, len, flags, translated_id,
		translated_id_len);
	
	_HIP_DEBUG("recvfrom: chars = %d\n", chars);

 out_err:
	return chars;
}

#if 0
/* poll (and maybe ppoll) should be wrapped conveniently for 
   applications such as ssh.*/
int poll(struct pollfd *orig_fds, nfds_t nfds, int timeout)
{
        int n, err = 0, zero = 0;
	int *translated_socket;
	struct pollfd *translated_fds;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;
	pthread_t tid = pthread_self();
	pid_t pid = getpid();

	for (n = 0; n < nfds; n++){
	      HIP_DEBUG("poll: orig_socket=%d\n", orig_fds[n].fd);
	      HIP_DEBUG("poll: events=%d\n", orig_fds[n].events);
	      HIP_DEBUG("poll: revents=%d\n", orig_fds[n].revents);
	      HIP_DEBUG("poll:  nfds=%d\n", nfds);
	      hip_socketdb_dump();

	      if(hip_exists_translation(pid, orig_fds[n].fd, tid)){
		     err = hip_translate_socket(&orig_fds[n].fd, NULL, &zero,
					 &translated_socket, &translated_id,
					 &translated_id_len, 1, 0, 0);
		    orig_fds[n].fd = *translated_socket;
		    HIP_DEBUG("poll: translation happened\n");
	      }
	      HIP_DEBUG("poll: translated_socket=%d\n", orig_fds[n].fd);
	      _HIP_DEBUG("poll: events=%d\n", translated_fds[n].events);
	      _HIP_DEBUG("poll: revents=%d\n", translated_fds[n].revents);
	      if (err) {
		     HIP_ERROR("Translation failure\n");
		     goto out_err;
	      }
	}
	HIP_DEBUG("calling poll: timeout=%d\n",timeout);
	err = dl_function_ptr.poll_dlsym(orig_fds, nfds, timeout);
	HIP_DEBUG("coming back from  poll: err=%d\n",err);
	if (err) {
		HIP_PERROR("connect error\n");
	}

 out_err:
	return err;
}
#endif


ssize_t recvmsg(int s, struct msghdr *msg, int flags)
{
	int err;
	int charnum = 0;  
	char *error = NULL;
	
	// XX TODO: see hip_get_pktinfo_addr
	charnum = dl_function_ptr.recvmsg_dlsym(s, msg, flags);
	
	_HIP_DEBUG("Called recvmsg_dlsym with number of returned chars=%d\n",
		  charnum);
	
	return charnum;
}

// used to test socketdb
void test_db(){
	int pid = getpid();
	int socket = 1;
	int err = 0;
	hip_opp_socket_t *entry = NULL;
	//  struct hip_opp_socket_entry *entry = NULL;
	
	HIP_DEBUG("1111 pid=%d, socket=%d\n", pid, socket);
	entry =   hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(!entry);
	err = hip_socketdb_add_entry(pid, socket, pthread_self());
	HIP_ASSERT(!err);
	entry =  hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(entry);
	hip_socketdb_dump();
	
	//  pid++; 
	socket++;
	HIP_DEBUG("2222 pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(!entry);
	err = hip_socketdb_add_entry(pid, socket, pthread_self());
	HIP_ASSERT(!err);
	entry = hip_socketdb_find_entry(pid, socket, pthread_self());
	entry->translated_socket = socket+100;
	HIP_ASSERT(entry);
	hip_socketdb_dump();
	
	
	//pid++; 
	socket++;
	HIP_DEBUG("3333 pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(!entry);
	err = hip_socketdb_add_entry(pid, socket, pthread_self());
	HIP_ASSERT(!err);
	entry = NULL;
	entry =  hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(entry);
	hip_socketdb_dump();
	
	HIP_DEBUG("3333  testing del entry\n\n");
	HIP_DEBUG("pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(entry);
	entry = NULL;
	err = hip_socketdb_del_entry(pid, socket, pthread_self());
	HIP_ASSERT(!err);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(!entry);
	hip_socketdb_dump();
	
	
	HIP_DEBUG("2222 testing del entry by entry\n\n");
	socket--;
	HIP_DEBUG("pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(entry);
	hip_socketdb_del_entry_by_entry(entry);
	entry = NULL;
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(!entry);
	hip_socketdb_dump();
	
	HIP_DEBUG("1111 testing del entry by entry\n\n");
	socket--;
	HIP_DEBUG("pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(entry);
	hip_socketdb_del_entry_by_entry(entry);
	entry = NULL;
	entry =  hip_socketdb_find_entry(pid, socket, pthread_self());
	HIP_ASSERT(!entry);
	hip_socketdb_dump();
	HIP_DEBUG("end of testing db\n");
}
#endif /* CONFIG_HIP_OPPORTUNISTIC */



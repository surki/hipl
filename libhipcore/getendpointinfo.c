/*
 * getendpointinfo: native HIP API resolver
 *
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Anthony D. Joseph <adj@hiit.fi>
 * Copyright: The Inner Net License v2.00.
 * Notes:     This file uses the code in this directory from Craig Metz.
 *
 * Todo:
 * - there is a lot of redundant code in this file to scan hosts files;
 *   reimplement with for_each() and function pointers
 * Bugs:
 * - xx
 */


#ifdef _USAGI_LIBINET6
#include "libc-compat.h"
#endif

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <ctype.h>
#include <openssl/dsa.h>

#include "builder.h"
#include "crypto.h"
#include "libinet6/util.h"
#include "icomm.h"
#include "hipd.h"
#include "debug.h"
#include "hadb.h"
#include "user.h"

#include "getendpointinfo.h"

//#include <ifaddrs.h>

// needed due to missing system inlcude for openWRT
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX		64
#endif

int convert_port_string_to_number(const char *servname, in_port_t *port)
{
  int err = 0;
  struct servent *servent;
  long int strtol_port;

  servent = getservbyname(servname, NULL);
  if (servent) {
    *port = ntohs(servent->s_port);
  } else {
    /* Try strtol if getservbyname fails, e.g. if the servname is "12345". */
    strtol_port = strtol(servname, NULL, 0);
    if (strtol_port == LONG_MIN || strtol_port == LONG_MAX ||
	strtol_port <= 0) {
      HIP_PERROR("strtol failed:");
      err = EEI_NONAME;
      goto out_err;
    }
    *port = strtol_port;
  }

 out_err:

  endservent();

  return err;

}
#if 0
char* hip_in6_ntop(const struct in6_addr *in6, char *buf)
{
        if (!buf)
                return NULL;
        sprintf(buf,
                "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                ntohs(in6->s6_addr16[0]), ntohs(in6->s6_addr16[1]),
                ntohs(in6->s6_addr16[2]), ntohs(in6->s6_addr16[3]),
                ntohs(in6->s6_addr16[4]), ntohs(in6->s6_addr16[5]),
                ntohs(in6->s6_addr16[6]), ntohs(in6->s6_addr16[7]));
        return buf;
}
#endif

int setmyeid(struct sockaddr_eid *my_eid,
	     const char *servname,
	     const struct endpoint *endpoint,
	     const struct if_nameindex *ifaces)
{
  int err = 0;
  struct hip_common *msg = NULL;
  int iface_num = 0;
  struct if_nameindex *iface;
  struct hip_sockaddr_eid *sa_eid;
  struct endpoint_hip *ep_hip = (struct endpoint_hip *) endpoint;
  socklen_t msg_len;
  in_port_t port;
  int socket_fd = 0;
  unsigned int len = 0;

  if (ep_hip->family != PF_HIP) {
    HIP_ERROR("Only HIP endpoints are supported\n");
    err = EEI_FAMILY;
    goto out_err;
  }

  _HIP_HEXDUMP("host_id in endpoint: ", &ep_hip->id.host_id,
	      hip_get_param_total_len(&ep_hip->id.host_id));

  msg = hip_msg_alloc();
  if (!msg) {
    err = EEI_MEMORY;
    goto out_err;
  }

  if (servname == NULL || strlen(servname) == 0) {
    port = 0; /* Ephemeral port */
    goto skip_port_conversion;
  }

  err = convert_port_string_to_number(servname, &port);
  if (err) {
    HIP_ERROR("Port conversion failed (%d)\n", err);
    goto out_err;
  }

 skip_port_conversion:

  /* Handler emphemeral port number */
  if (port == 0) {
    while (port < 1024) /* XX FIXME: CHECK UPPER BOUNDARY */
	   port = rand();
  }

  HIP_DEBUG("port=%d\n", port);

  hip_build_user_hdr(msg, SO_HIP_SET_MY_EID, 0);

  err = hip_build_param_eid_endpoint(msg, ep_hip);
  if (err) {
    err = EEI_MEMORY;
    goto out_err;
  }

  struct hip_host_id *host_identity = &ep_hip->id.host_id;
  if(hip_host_id_contains_private_key(host_identity)){

    HIP_DEBUG("Private key found from hip_host_id\n");

    err = hip_private_host_id_to_hit(host_identity, &ep_hip->id.hit,
				     HIP_HIT_TYPE_HASH100);
    if (err) {
      HIP_ERROR("Failed to calculate HIT from private HI.");
      goto out_err;
    }
  }
  /* Only public key*/
  else {

     HIP_DEBUG("Public key found from hip_host_id\n");

    /*Generate HIT from the public HI */
    err = hip_host_id_to_hit(host_identity, &ep_hip->id.hit,
			     HIP_HIT_TYPE_HASH100);

    if (err) {
      HIP_ERROR("Failed to calculate HIT from public key.");
      goto out_err;
    }
  }

  HIP_DEBUG_HIT("Calculated HIT from hip_host_id", &ep_hip->id.hit);

  err = hip_build_param_contents(msg, (void *) &ep_hip->id.hit, HIP_PARAM_HIT,
                                      sizeof(struct in6_addr));
  if (err) {
    HIP_ERROR("Build param hit failed: %s\n", strerror(err));
    goto out_err;
  }

  /*Currently ifaces is NULL, so this for loop is skipped*/
  for(iface = (struct if_nameindex *) ifaces;
      iface && iface->if_index != 0; iface++) {
    err = hip_build_param_eid_iface(msg, iface->if_index);
    if (err) {
      err = EEI_MEMORY;
      goto out_err;
    }
  }

#if 0 //hip_recv_daemon_info returns currently -1, temporary solution is shown below.
  err = hip_recv_daemon_info(msg, 0);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Failed to recv msg\n");
    goto out_err;
  }
#endif

  /*Laura*********************/
  //hip_send_daemon_info(msg_HIT); // for app. specified HIs
  _HIP_DEBUG("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n calling socket..\n\n\n");
  socket_fd = socket(PF_HIP, SOCK_STREAM, 0);
  if(socket_fd == -1){
    HIP_ERROR("Couldn't create socket\n");
    err = -1;
    goto out_err;
  }
  _HIP_DEBUG("\n\n\n\n\n\n\n\n\n\n great no error..\n\n\n");

  len = hip_get_msg_total_len(msg);
  err = getsockopt(socket_fd, IPPROTO_HIP, SO_HIP_SOCKET_OPT, (void *)msg, &len);

  if (err) {
    HIP_ERROR("getsockopt failed\n");
    goto out_err;
  }

  /***************************/
  /* getsockopt wrote the corresponding EID into the message, use it */

  err = hip_get_msg_err(msg);
  if (err) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  sa_eid = hip_get_param_contents(msg, HIP_PARAM_EID_SOCKADDR);
  if (!sa_eid) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  memcpy(my_eid, sa_eid, sizeof(struct sockaddr_eid));

  /* Fill the port number also because the HIP module did not fill it */
  my_eid->eid_port = htons(port);

  HIP_DEBUG("eid val=%d, port=%d\n", htons(my_eid->eid_val),
	    htons(my_eid->eid_port));

  HIP_DEBUG("\n");

 out_err:

  if (msg)
    hip_msg_free(msg);

  return err;
}

int setpeereid(struct sockaddr_eid *peer_eid,
	       const char *servname,
	       const struct endpoint *endpoint,
	       const struct addrinfo *addrinfo)
{
  int err = 0, len = 0;
  struct hip_common *msg = NULL, *msg_mapping;
  struct addrinfo *addr;
  struct sockaddr_eid *sa_eid;
  in_port_t port = 0;
  struct endpoint_hip *ep_hip = (struct endpoint_hip *) endpoint;
  int socket_fd = 0;
  unsigned int msg_len = 0;

  HIP_DEBUG("\n");

  if (endpoint->family != PF_HIP) {
    HIP_ERROR("Only HIP endpoints are supported\n");
    err = EEI_FAMILY;
    goto out_err;
  }

#ifdef CONFIG_HIP_DEBUG
  {

    if (ep_hip->flags & HIP_ENDPOINT_FLAG_HIT) {
      _HIP_HEXDUMP("setpeereid hit: ", &ep_hip->id.hit,
		  sizeof(struct in6_addr));
    } else {
      _HIP_HEXDUMP("setpeereid hi: ", &ep_hip->id.host_id,
		  hip_get_param_total_len(&ep_hip->id.host_id));
    }
  }
#endif

  msg = hip_msg_alloc();
  if (!msg) {
    err = EEI_MEMORY;
    goto out_err;
  }

  if (servname != NULL) {
    err = convert_port_string_to_number(servname, &port);
    if (err) {
      HIP_ERROR("Port conversion failed (%d)\n", err);
      goto out_err;
    }
  }

  HIP_DEBUG("port=%d\n", port);

  hip_build_user_hdr(msg, SO_HIP_SET_PEER_EID, 0);

  err = hip_build_param_eid_endpoint(msg, (struct endpoint_hip *) endpoint);
  if (err) {
    err = EEI_MEMORY;
    goto out_err;
  }


#if 0 //hip_recv_daemon_info returns currently -1, temporary solution is shown below.
  err = hip_recv_daemon_info(msg, 0);
  if (err) {
    err = EEI_SYSTEM;
    goto out_err;
  }
#endif

  /*Revove this part after hip_recv_daemon has beem implemented (2.3.2006 Laura)*/

  /* Send HIT-IP mapping to the daemon.********************************/

  msg_mapping = hip_msg_alloc();
  if (!msg_mapping) {
    err = EEI_MEMORY;
    goto out_err;
  }

  /* Is it possible that there are several public HITs for the peer (/etc/hip/hosts)?
   * Do we send all possible mappings to the daemon?
  */
  for(addr = (struct addrinfo *) addrinfo; addr; addr = addr->ai_next) {
    struct sockaddr_in6 *sock_addr_ipv6;
    struct in6_addr ipv6_addr;

    if(addr->ai_family != AF_INET6)
      continue;

    sock_addr_ipv6 = (struct sockaddr_in6 *)addrinfo->ai_addr;
    ipv6_addr = sock_addr_ipv6->sin6_addr;

    HIP_DEBUG("Adding HIP-IP mapping: ");
    HIP_DEBUG_IN6ADDR("HIT", (struct in6_addr *) &ep_hip->id.hit);
    HIP_DEBUG_IN6ADDR("IP", &ipv6_addr);

    hip_msg_init(msg_mapping);
    err = hip_build_param_contents(msg_mapping, (void *) &ep_hip->id.hit, HIP_PARAM_HIT,
				   sizeof(struct in6_addr));

    if (err) {
      HIP_ERROR("build param hit failed: %s\n", strerror(err));
      goto out_err;
    }

    err = hip_build_param_contents(msg_mapping, (void *) &ipv6_addr, HIP_PARAM_IPV6_ADDR,
				   sizeof(struct in6_addr));

    if (err) {
      HIP_ERROR("build param ipv6 failed: %s\n", strerror(err));
      goto out_err;
    }

    hip_build_user_hdr(msg_mapping, SO_HIP_ADD_PEER_MAP_HIT_IP, 0);
    hip_send_recv_daemon_info(msg_mapping, 0, 0);
  }
  free(msg_mapping);

  /**************************************/


  /* Type of the socket? Does it matter?*/
  socket_fd = socket(PF_HIP, SOCK_STREAM, 0);
  if(socket_fd == -1){
    HIP_ERROR("Couldn't create socket\n");
    err = -1;
    goto out_err;
  }

  msg_len = hip_get_msg_total_len(msg);
  err = getsockopt(socket_fd, IPPROTO_HIP, SO_HIP_SOCKET_OPT, (void *)msg, &msg_len);
  if(err) {
    HIP_ERROR("getsockopt failed\n");
    close(socket_fd);
    goto out_err;
  }

  close(socket_fd);
  /***************************************************************************/

  /* The HIP module wrote the eid into the msg. Let's use it. */

  sa_eid = hip_get_param_contents(msg, HIP_PARAM_EID_SOCKADDR);
  if (!sa_eid) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  memcpy(peer_eid, sa_eid, sizeof(struct sockaddr_eid));

  /* Fill the port number also because the HIP module did not fill it */
  peer_eid->eid_port = htons(port);

 out_err:

  if (msg)
    hip_msg_free(msg);

  return err;
}

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * XX FIXME: grep for public / private word from the filename and
 * call either load_private or load_public correspondingly.
 * Are application specified identities always anonymous?
 */
int load_hip_endpoint_pem(const char *filename,
			  struct endpoint **endpoint)
{
  int err = 0, algo = 0;
  char first_key_line[30];
  DSA *dsa = NULL;
  RSA *rsa = NULL;
  FILE* fp;

  *endpoint = NULL;

  /* check the algorithm from PEM format private key */
  fp = fopen(filename, "rb");
  if (!fp) {
    HIP_ERROR("Couldn't open key file %s for reading\n", filename);
    err = -ENOMEM;
    goto out_err;
  }
  else
    HIP_DEBUG("open key file %s for reading\n", filename);
  fgets(first_key_line,30,fp);  //read first line.
  _HIP_DEBUG("1st key line: %s", first_key_line);
  fclose(fp);

  if(findsubstring(first_key_line, "RSA"))
    algo = HIP_HI_RSA;
  else if(findsubstring(first_key_line, "DSA"))
    algo = HIP_HI_DSA;
  else {
    HIP_ERROR("Wrong kind of key file: %s\n",filename);
    err = -ENOMEM;
    goto out_err;
  }

  if(algo == HIP_HI_RSA)
    err = load_rsa_private_key(filename, &rsa);
  else
    err = load_dsa_private_key(filename, &dsa);
  if (err) {
    HIP_ERROR("Failed to load private key %s (%d)\n",filename, err);
    goto out_err;
  }

  // XX FIX: host_id_hdr->rdata.flags = htons(0x0200); /* key is for a host */
  if(algo == HIP_HI_RSA)
    err = rsa_to_hip_endpoint(rsa, (struct endpoint_hip **) endpoint,
			      HIP_ENDPOINT_FLAG_ANON, "");
  else
    err = dsa_to_hip_endpoint(dsa, (struct endpoint_hip **) endpoint,
			      HIP_ENDPOINT_FLAG_ANON, "");
  if (err) {
    HIP_ERROR("Failed to convert private key to HIP endpoint (%d)\n", err);
    goto out_err;
  }

 out_err:

  if (dsa)
    DSA_free(dsa);
  if (rsa)
    RSA_free(rsa);
  if (err && *endpoint)
    free(*endpoint);

  return err;
}

void free_endpointinfo(struct endpointinfo *res)
{
  struct endpointinfo *tmp;

  HIP_DEBUG("\n");

  while(res) {

    if (res->ei_endpoint)
      free(res->ei_endpoint);

    if (res->ei_canonname)
      free(res->ei_canonname);

    HIP_DEBUG("Freeing res\n");

    /* Save the next pointer from the data structure before the data
       structure is freed. */
    tmp = res;
    res = tmp->ei_next;

    /* The outermost data structure must be freed last. */
    free(tmp);
  }

}

/**
 * get_localhost_endpointinfo - query endpoint info about the localhost
 * @param basename the basename for the hip/hosts file (included for easier writing
 *            of unit tests)
 * @param servname the service port name (e.g. "http" or "12345")
 * @param hints selects which type of endpoints is going to be resolved
 * @param res the result of the query
 *
 * This function is for libinet6 internal purposes only. This function does
 * not resolve private identities, only public identities. The locators of
 * the localhost are not resolved either because interfaces are used on the
 * localhost instead of addresses. This means that the addrlist is just zeroed
 * on the result.
 *
 * Only one identity at a time can be resolved with this function. If multiple
 * identities are needed, one needs to call this function multiple times
 * with different basename arguments and link the results together.
 *
 * XX FIX: LOCAL RESOLVER SHOULD RESOLVE PUBLIC KEYS, NOT
 * PRIVATE. CHECK THAT IT WORKS WITH THE USER-KEY TEST PROGRAM.
 *
 * @return zero on success, or negative error value on failure
 */
int get_localhost_endpointinfo(const char *basename,
			       const char *servname,
			       struct endpointinfo *hints,
			       struct endpointinfo **res)
{
  int err = 0, algo = 0;
  DSA *dsa = NULL;
  RSA *rsa = NULL;
  struct endpoint_hip *endpoint_hip = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
  struct if_nameindex *ifaces = NULL;
  char first_key_line[30];
  FILE* fp;
  const char *pub_suffix = "_pub";

  *res = NULL;

  _HIP_DEBUG("glhepi\n");
  HIP_ASSERT(hints);

  // XX TODO: check flags?
  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  err = gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
  if (err) {
    HIP_ERROR("gethostname failed (%d)\n", err);
    err = EEI_NONAME;
    goto out_err;
  }

  /* select between anonymous/public HI based on the file name */
  if(!findsubstring(basename, pub_suffix))
    hints->ei_flags |= HIP_ENDPOINT_FLAG_ANON;

  /* System specific HIs should be added into the kernel with the
     HIP_HI_REUSE_ANY flag set. We set the flag
     (specific for setmyeid) 'wrongly' here
     because this way we make the HIs readable by all processes.
     This function calls setmyeid() internally.. */
  hints->ei_flags |= HIP_HI_REUSE_ANY;

  /*Support for HITs (14.3.06 Laura)*/
  hints->ei_flags |= HIP_ENDPOINT_FLAG_HIT;

  /* check the algorithm from PEM format key */
  fp = fopen(basename, "rb");
  if (!fp) {
    HIP_ERROR("Couldn't open key file %s for reading\n", basename);
    err = -ENOMEM;
    goto out_err;
  }

  /*Laura 10.4.
  fgets(first_key_line,30,fp);  //read first line.
  HIP_DEBUG("1st key line: %s",first_key_line);
  fclose(fp);

  if(findsubstring(first_key_line, "RSA"))
    algo = HIP_HI_RSA;
  else if(findsubstring(first_key_line, "DSA"))
    algo = HIP_HI_DSA;
  else {
    HIP_ERROR("Wrong kind of key file: %s\n",basename);
    err = -ENOMEM;
    goto out_err;
  }*/

  HIP_DEBUG("Debug1\n");


  if(findsubstring(basename, "rsa"))
    algo = HIP_HI_RSA;
  else if(findsubstring(basename, "dsa"))
    algo = HIP_HI_DSA;
  else {
    HIP_ERROR("Wrong kind of key file: %s\n",basename);
    err = -ENOMEM;
    goto out_err;
    }

  HIP_DEBUG("Debug2: basename %s\n", basename);

  /* Only private keys are handled. */
  if(algo == HIP_HI_RSA)
    err = load_rsa_public_key(basename, &rsa);
  //err = load_rsa_private_key(basename, &rsa);
  else
    err = load_dsa_public_key(basename, &dsa);
    //err = load_dsa_private_key(basename, &dsa);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Loading of private key %s failed\n", basename);
    goto out_err;
  }

  HIP_DEBUG("Debug3\n");

  if(algo == HIP_HI_RSA)
    err = rsa_to_hip_endpoint(rsa, &endpoint_hip, hints->ei_flags, hostname);
  else
    err = dsa_to_hip_endpoint(dsa, &endpoint_hip, hints->ei_flags, hostname);
  if (err) {
    HIP_ERROR("Failed to allocate and build endpoint.\n");
    err = EEI_SYSTEM;
    goto out_err;
  }

  HIP_DEBUG("Debug4\n");

  _HIP_HEXDUMP("host identity in endpoint: ", &endpoint_hip->id.host_id,
	       hip_get_param_total_len(&endpoint_hip->id.host_id));

  _HIP_HEXDUMP("hip endpoint: ", endpoint_hip, endpoint_hip->length);

#if 0 /* XX FIXME */
  ifaces = if_nameindex();
  if (ifaces == NULL || (ifaces->if_index == 0)) {
    HIP_ERROR("%s\n", (ifaces == NULL) ? "Iface error" : "No ifaces.");
    err = 1;
    goto out_err;
  }
#endif

  *res = calloc(1, sizeof(struct endpointinfo));
  if (!*res) {
    err = EEI_MEMORY;
    goto out_err;
  }

  (*res)->ei_endpoint = malloc(sizeof(struct sockaddr_eid));
  if (!(*res)->ei_endpoint) {
    err = EEI_MEMORY;
    goto out_err;
  }

  if (hints->ei_flags & EI_CANONNAME) {
    int len = strlen(hostname) + 1;
    if (len > 1) {
      (*res)->ei_canonname = malloc(len);
      if (!((*res)->ei_canonname)) {
	err = EEI_MEMORY;
	goto out_err;
      }
      memcpy((*res)->ei_canonname, hostname, len);
    }
  }

//  err = setmyeid(((struct sockaddr_eid *) (*res)->ei_endpoint), servname,
//		 (struct endpoint *) endpoint_hip, ifaces);
  if (err) {
    HIP_ERROR("Failed to set up my EID (%d)\n", err);
    err = EEI_SYSTEM;
    goto out_err;
  }

#ifdef CONFIG_HIP_DEBUG
  {
    struct sockaddr_eid *eid = (struct sockaddr_eid *) (*res)->ei_endpoint;
    HIP_DEBUG("eid family=%d value=%d\n", eid->eid_family,
	      ntohs(eid->eid_val));
  }
#endif

  (*res)->ei_flags = 0; /* FIXME: what about anonymous identities? */
  (*res)->ei_family = PF_HIP;
  (*res)->ei_socktype = hints->ei_socktype;
  (*res)->ei_protocol = hints->ei_protocol;
  (*res)->ei_endpointlen = sizeof(struct sockaddr_eid);
  /* ei_endpoint has already been set */
  /* canonname has already been set */
  (*res)->ei_next = NULL; /* only one local HI currently supported */

 out_err:

  if (rsa)
    RSA_free(rsa);

 if (dsa)
    DSA_free(dsa);

  if (endpoint_hip)
    free(endpoint_hip);

  if (ifaces)
    if_freenameindex(ifaces);

  /* Free allocated memory on error. Nullify the result in case the
     caller tries to deallocate the result twice with free_endpointinfo. */
  if (err) {
    if (*res) {
      if ((*res)->ei_endpoint)
	free((*res)->ei_endpoint);
      if ((*res)->ei_canonname)
	free((*res)->ei_canonname);

      free(*res);
      *res = NULL;
    }
  }

  return err;
}

/**
 * get_hipd_peer_list - query hipd for list of known peers
 * @param nodename the name of the peer to be resolved
 * @param servname the service port name (e.g. "http" or "12345")
 * @param hints selects which type of endpoints is going to be resolved
 * @param res the result of the query
 * @param alt_flag flag for an alternate query (after a file query has been done)
 *             This flag will add entries (if found) to an existing result
 *
 * This function is for libinet6 internal purposes only.
 *
 * @return zero on success, or negative error value on failure
 * @todo: this function is outdated; query for SO_HIP_GET_HA_INFO instead
 *
 */
int get_hipd_peer_list(const char *nodename, const char *servname,
			 const struct endpointinfo *hints,
			 struct endpointinfo **res, int alt_flag)
{
  int err = 0;
  struct hip_common *msg = NULL;
  unsigned int *count, *acount;
  struct hip_host_id *host_id;
  hip_hit_t *hit;
  struct in6_addr *addr;
  int i, j;
  struct endpointinfo *einfo = NULL;
  char *fqdn_str;
  int nodename_str_len = 0;
  int fqdn_str_len = 0;
  struct endpointinfo *previous_einfo = NULL;
  /* Only HITs are supported, so endpoint_hip is statically allocated */
  struct endpoint_hip endpoint_hip;
  in_port_t port = 0;
  struct addrinfo ai_hints, *ai_tail, *ai_res = NULL;
  char hit_str[46];

  if (!alt_flag)
    *res = NULL; /* The NULL value is used in the loop below. */

  HIP_DEBUG("\n");
  HIP_ASSERT(hints);

  if (nodename != NULL)
    nodename_str_len = strlen(nodename);

  memset(&ai_hints, 0, sizeof(struct addrinfo));
  /* ai_hints.ai_flags = hints->ei_flags; */
  /* Family should be AF_ANY but currently the HIP module supports only IPv6.
     In any case, the family cannot be copied directly from hints, because
     it contains PF_HIP. */
  ai_hints.ai_family = AF_INET6;
  ai_hints.ai_socktype = hints->ei_socktype;
  ai_hints.ai_protocol = hints->ei_protocol;

  /* The getaddrinfo is called only once and the results are copied in each
     element of the endpointinfo linked lists. */
  err = getaddrinfo(NULL, servname, &ai_hints, &ai_res);
  if (err) {
    HIP_ERROR("getaddrinfo failed: %s", gai_strerror(err));
    goto out_err;
  }

  /* Call the kernel to get the list of known peer addresses */
  msg = hip_msg_alloc();
  if (!msg) {
    err = EEI_MEMORY;
    goto out_err;
  }

  /* Build the message header */
  err = hip_build_user_hdr(msg, SO_HIP_GET_PEER_LIST, 0);
  if (err) {
    err = EEI_MEMORY;
    goto out_err;
  }

  /* Call the kernel */
  err = hip_send_recv_daemon_info(msg, 0, 0);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Failed to recv msg\n");
    goto out_err;
  }

  /* getsockopt wrote the peer list into the message, now process it
   * Format is:
     <unsigned integer> - Number of entries
     [<host id> - Host identifier
      <hit> - HIT
      <unsigned integer> - Number of addresses
      [<ipv6 address> - IPv6 address
       ...]
     ...]
  */
  err = hip_get_msg_err(msg);
  if (err) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  /* Get count of entries in peer list */
  count = hip_get_param_contents(msg, HIP_PARAM_UINT);
  if (!count) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  for (i = 0; i < *count; i++) {
    /* Get the next peer HOST ID */
    host_id = hip_get_param(msg, HIP_PARAM_HOST_ID);
    if (!host_id) {
      HIP_ERROR("no host identity pubkey in response\n");
      err = EEI_SYSTEM;
      goto out_err;
    }

    /* Extract the peer hostname, and determine its length */
    fqdn_str = hip_get_param_host_id_hostname(host_id);
    fqdn_str_len = strlen(fqdn_str);

    /* Get the peer HIT */
    hit = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT);
    if (!hit) {
      HIP_ERROR("no hit in response\n");
      err = EEI_SYSTEM;
      goto out_err;
    }

    /* Get the number of addresses */
    acount = hip_get_param_contents(msg, HIP_PARAM_UINT);
    if (!acount) {
      err = EEI_SYSTEM;
      goto out_err;
    }

    /* Parse the hit into text form for comparison below */
    hip_in6_ntop((const struct in6_addr *)&hit, hit_str);

    /* Check if the nodename or the endpoint in the hints matches the
       scanned entries. */
    if (nodename_str_len && (fqdn_str_len == nodename_str_len) &&
	(strcmp(fqdn_str, nodename) == 0)) {
      /* XX FIX: foobar should match to foobar.org, depending on resolv.conf */
      HIP_DEBUG("Nodename match\n");
    } else if(hints->ei_endpointlen && hints->ei_endpoint &&
	      (strlen(hit_str) == hints->ei_endpointlen) &&
	      (strcmp(hit_str, (char *) hints->ei_endpoint) == 0)) {
      HIP_DEBUG("Endpoint match\n");
    } else if (!nodename_str_len) {
      HIP_DEBUG("Null nodename, returning as matched\n");
    } else {
      /* Not matched, so skip the addresses in the kernel response */
      for (j = 0; j < *acount; j++) {
	addr = (struct in6_addr *)hip_get_param_contents(msg,
							 HIP_PARAM_IPV6_ADDR);
	if (!addr) {
	  HIP_ERROR("no ip addr in response\n");
	  err = EEI_SYSTEM;
	  goto out_err;
	}
      }
      continue;
    }

    /* Allocate a new endpointinfo */
    einfo = calloc(1, sizeof(struct endpointinfo));
    if (!einfo) {
      err = EEI_MEMORY;
      goto out_err;
    }

    /* Allocate a new endpoint */
    einfo->ei_endpoint = calloc(1, sizeof(struct sockaddr_eid));
    if (!einfo->ei_endpoint) {
      err = EEI_MEMORY;
      goto out_err;
    }

    /* Copy the name if the flag is set */
    if (hints->ei_flags & EI_CANONNAME) {
      einfo->ei_canonname = malloc(fqdn_str_len + 1);
      if (!(einfo->ei_canonname)) {
	err = EEI_MEMORY;
	goto out_err;
      }
      HIP_ASSERT(strlen(fqdn_str) == fqdn_str_len);
      strcpy(einfo->ei_canonname, fqdn_str);
      /* XX FIX: we should append the domain name if it does not exist */
    }

    _HIP_DEBUG("*** %p %p\n", einfo, previous_einfo);

    HIP_ASSERT(einfo); /* Assertion 1 */

    /* Allocate and fill the HI. Note that here we are assuming that the
       endpoint is really a HIT. The following assertion checks that we are
       dealing with a HIT. Change the memory allocations and other code when
       HIs are really supported. */

    memset(&endpoint_hip, 0, sizeof(struct endpoint_hip));
    endpoint_hip.family = PF_HIP;

    /* Only HITs are supported, so endpoint_hip is not dynamically allocated
       and sizeof(endpoint_hip) is enough */
    endpoint_hip.length = sizeof(struct endpoint_hip);
    endpoint_hip.flags = HIP_ENDPOINT_FLAG_HIT;
    memcpy(&endpoint_hip.id.hit, hit, sizeof(struct in6_addr));

    _HIP_HEXDUMP("peer HIT: ", &endpoint_hip.id.hit, sizeof(struct in6_addr));

    HIP_ASSERT(einfo && einfo->ei_endpoint); /* Assertion 2 */

    /* Now replace the addresses that we got from getaddrinfo in the ai_res
       structure, with the entries from the kernel. If there are not enough
       entries already present, allocate and fill new ones */
    ai_tail = ai_res;
    for (j = 0; j < *acount; j++, ai_tail = ai_tail->ai_next) {
      addr = (struct in6_addr *) hip_get_param_contents(msg,
							HIP_PARAM_IPV6_ADDR);
      if (!addr) {
	HIP_ERROR("no ip addr in response\n");
	err = EEI_SYSTEM;
	goto out_err;
      }

      /* Should we always include our entries, even if there are none? */
      if (!ai_res) continue;

      if (!ai_tail) {
	/* We ran out of entries, so copy the first one so we get the
	   flags and other info*/
	ai_tail = malloc(sizeof(struct addrinfo));
	memcpy(ai_tail, ai_res, sizeof(struct addrinfo));
	ai_tail->ai_addr = malloc(sizeof(struct sockaddr_in6));
	memcpy(ai_tail->ai_addr, ai_res->ai_addr,sizeof(struct sockaddr_in6));
	ai_tail->ai_canonname = malloc(strlen(ai_res->ai_canonname)+1);
	strcpy(ai_tail->ai_canonname, ai_res->ai_canonname);
      }

      /* Now, save the address from the kernel */
      memcpy(&(((struct sockaddr_in6 *)ai_tail->ai_addr)->sin6_addr), addr,
	       sizeof(struct in6_addr));
    }

    /* Call the kernel for the peer eid */
    err = setpeereid((struct sockaddr_eid *) einfo->ei_endpoint, servname,
		     (struct endpoint *) &endpoint_hip, ai_res);
    if (err) {
      HIP_ERROR("association failed (%d): %s\n", err);
      goto out_err;
    }

    /* Fill the rest of the fields in the einfo */
    einfo->ei_flags = hints->ei_flags;
    einfo->ei_family = PF_HIP;
    einfo->ei_socktype = hints->ei_socktype;
    einfo->ei_protocol = hints->ei_protocol;
    einfo->ei_endpointlen = sizeof(struct sockaddr_eid);

    /* The einfo structure has been filled now. Now, append it to the linked
       list. */

    /* Set res point to the first memory allocation, so that the starting
       point of the linked list will not be forgotten. The res will be set
       only once because on the next iteration of the loop it will non-null. */
    if (!*res)
      *res = einfo;

    HIP_ASSERT(einfo && einfo->ei_endpoint && *res); /* 3 */

    /* Link the previous endpoint info structure to this new one. */
    if (previous_einfo) {
      previous_einfo->ei_next = einfo;
    }

    /* Store a pointer to this einfo so that we can link this einfo to the
       following einfo on the next iteration. */
    previous_einfo = einfo;

    HIP_ASSERT(einfo && einfo->ei_endpoint && *res &&
	       previous_einfo == einfo); /* 4 */
  }

  HIP_DEBUG("Kernel list scanning ended\n");

 out_err:

  if (ai_res)
    freeaddrinfo(ai_res);

  if (msg)
    hip_msg_free(msg);

  /* Free all of the reserved memory on error */
  if (err) {
    /* Assertions 1, 2 and 3: einfo has not been linked to *res and
       it has to be freed separately. In English: free only einfo
       if it has not been linked into the *res list */
    if (einfo && previous_einfo != einfo) {
      if (einfo->ei_endpoint)
	free(einfo->ei_endpoint);
      if (einfo->ei_canonname)
	free(einfo->ei_canonname);
      free(einfo);
    }

    /* Assertion 4: einfo has been linked into the *res. Free all of the
     *res list elements (einfo does not need be freed separately). */
    if (*res) {
      free_endpointinfo(*res);
      /* In case the caller of tries to free the res again */
      *res = NULL;
    }
  }

  return err;
}

/**
 * get_peer_endpointinfo - query endpoint info about a peer
 * @param hostsfile the filename where the endpoint information is stored
 * @param nodename the name of the peer to be resolved
 * @param servname the service port name (e.g. "http" or "12345")
 * @param hints selects which type of endpoints is going to be resolved
 * @param res the result of the query
 *
 * This function is for libinet6 internal purposes only.
 *
 * @return zero on success, or negative error value on failure
 *
 */
int get_peer_endpointinfo(const char *hostsfile,
			  const char *nodename,
			  const char *servname,
			  const struct endpointinfo *hints,
			  struct endpointinfo **res)
{
  int err = 0, match_found = 0, ret = 0, i=0;
  unsigned int lineno = 0, fqdn_str_len = 0;
  FILE *hosts = NULL;
  char fqdn_str[HOST_NAME_MAX];
  struct endpointinfo *einfo = NULL, *current = NULL, *new = NULL;
  struct addrinfo ai_hints, *ai_res = NULL;
  struct endpointinfo *previous_einfo = NULL;
  /* Only HITs are supported, so endpoint_hip is statically allocated */
  struct endpoint_hip endpoint_hip;
  char line[500];
  struct in6_addr hit;
  List mylist;

  *res = NULL; /* The NULL value is used in the loop below. */

  HIP_DEBUG("\n");

  HIP_ASSERT(nodename);
  HIP_ASSERT(hints);

  hosts = fopen(hostsfile, "r");
  if (!hosts) {
    err = EEI_SYSTEM;
    HIP_ERROR("Failed to open %s\n", hostsfile);
    goto out_err;
  }

  memset(&ai_hints, 0, sizeof(struct addrinfo));
  ai_hints.ai_flags = hints->ei_flags;
  /* Family should be AF_ANY but currently the HIP module supports only IPv6.
     In any case, the family cannot be copied directly from hints, because
     it contains PF_HIP. */
  ai_hints.ai_family = AF_INET6;
  ai_hints.ai_socktype = hints->ei_socktype;
  ai_hints.ai_protocol = hints->ei_protocol;

  /* The getaddrinfo is called only once and the results are copied in each
     element of the endpointinfo linked lists. */
  err = getaddrinfo(nodename, servname, &ai_hints, &ai_res);
  if (err) {
    HIP_ERROR("getaddrinfo failed: %s\n", gai_strerror(err));
    goto fallback;
  }

  /*! \todo check and handle flags here */

  HIP_ASSERT(!*res); /* Pre-loop invariable */

  //HIP_IFEL(err, -1, "Failed to map id to hostname\n");

  memset(fqdn_str, 0, sizeof(fqdn_str));
  if (inet_pton(AF_INET6, nodename, &hit) > 0) {
    _HIP_DEBUG("Nodename is numerical address\n");
    err = hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
				       hip_map_first_id_to_hostname_from_hosts,
				       &hit, fqdn_str);
  } else {
    strncpy(fqdn_str, nodename, HOST_NAME_MAX);
  }
  fqdn_str_len = strlen(fqdn_str);

  if (!err && hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
				   hip_map_first_hostname_to_hit_from_hosts,
				   fqdn_str, &hit) == 0)
    /* create endpointinfo structure for every HIT */
    {
      einfo = calloc(1, sizeof(struct endpointinfo));

      HIP_IFE(!einfo, EEI_MEMORY);
      
      einfo->ei_endpoint = calloc(1, sizeof(struct sockaddr_eid));
      HIP_IFE(!einfo->ei_endpoint, EEI_MEMORY);

      if (hints->ei_flags & EI_CANONNAME) {
	einfo->ei_canonname = malloc(fqdn_str_len + 1);
	HIP_IFE(!einfo->ei_canonname, EEI_MEMORY);
	HIP_ASSERT(strlen(fqdn_str) == fqdn_str_len);
	strcpy(einfo->ei_canonname, fqdn_str);
	/* XX FIX: we should append the domain name if it does not exist */
      }

      _HIP_DEBUG("*** %p %p\n", einfo, previous_einfo);

      HIP_ASSERT(einfo); /* Assertion 1 */

      /* Allocate and fill the HI. Note that here we are assuming that the
	 endpoint is really a HIT. The following assertion checks that we are
	 dealing with a HIT. Change the memory allocations and other code when
	 HIs are really supported. */
      //THIS ISN'T TRUE ALWAYS: _HIP_ASSERT(hi_str_len == 4 * 8 + 7 * 1);

      memset(&endpoint_hip, 0, sizeof(struct endpoint_hip));
      endpoint_hip.family = PF_HIP;

      /* Only HITs are supported, so endpoint_hip is not dynamically allocated
	 and sizeof(endpoint_hip) is enough */
      endpoint_hip.length = sizeof(struct endpoint_hip);
      endpoint_hip.flags = HIP_ENDPOINT_FLAG_HIT;

      ipv6_addr_copy(&endpoint_hip.id.hit, &hit);

      HIP_ASSERT(einfo && einfo->ei_endpoint); /* Assertion 2 */

      err = setpeereid((struct sockaddr_eid *) einfo->ei_endpoint, servname,
		       (struct endpoint *) &endpoint_hip, ai_res);
      if (err) {
	HIP_ERROR("association failed (%d): %s\n", err);
	goto out_err;
      }

      /* Fill the rest of the fields in the einfo */
      einfo->ei_flags = hints->ei_flags;
      einfo->ei_family = PF_HIP;
      einfo->ei_socktype = hints->ei_socktype;
      einfo->ei_protocol = hints->ei_protocol;
      einfo->ei_endpointlen = sizeof(struct sockaddr_eid);

      /* The einfo structure has been filled now. Now, append it to the linked
	 list. */

      /* Set res point to the first memory allocation, so that the starting
	 point of the linked list will not be forgotten. The res will be set
	 only once because on the next iteration of the loop it will non-null.
      */
      if (!*res)
	*res = einfo;

      HIP_ASSERT(einfo && einfo->ei_endpoint && *res); /* 3 */

      /* Link the previous endpoint info structure to this new one. */
      if (previous_einfo) {
	previous_einfo->ei_next = einfo;
      }

      /* Store a pointer to this einfo so that we can link this einfo to the
	 following einfo on the next iteration. */
      previous_einfo = einfo;

      HIP_ASSERT(einfo && einfo->ei_endpoint && *res &&
		 previous_einfo == einfo); /* 4 */
      destroy(&mylist);
  }

  _HIP_DEBUG("Scanning ended\n");


 fallback:

#if 0 /* XX FIXME: the function below does not work */
  /* If no entries are found, fallback on the kernel's list */
  if (!*res) {
    HIP_DEBUG("No entries found, querying hipd for entries\n");
    err = get_hipd_peer_list(nodename, servname, hints, res, 1);
    if (err) {
      HIP_ERROR("Failed to get kernel peer list (%d)\n", err);
      goto out_err;
    }
    HIP_DEBUG("Done with hipd entries\n");
    if (*res) {
      match_found = 1;
    }
  }
#endif

  HIP_ASSERT(err == 0);

  if (!match_found) {
    err = EEI_NONAME;
  }

 out_err:

  if (ai_res)
    freeaddrinfo(ai_res);

  if (hosts)
    fclose(hosts);

  /* Free all of the reserved memory on error */
  if (err) {
    /* Assertions 1, 2 and 3: einfo has not been linked to *res and
       it has to be freed separately. In English: free only einfo
       if it has not been linked into the *res list */
    if (einfo && previous_einfo != einfo) {
      if (einfo->ei_endpoint)
	free(einfo->ei_endpoint);
      if (einfo->ei_canonname)
	free(einfo->ei_canonname);
      free(einfo);
    }

    /* Assertion 4: einfo has been linked into the *res. Free all of the
     *res list elements (einfo does not need be freed separately). */
    if (*res) {
      free_endpointinfo(*res);
      /* In case the caller of tries to free the res again */
      *res = NULL;
    }
  }
  return err;
}

int getendpointinfo(const char *nodename, const char *servname,
		    const struct endpointinfo *hints,
		    struct endpointinfo **res)
{
  int err = 0;
  struct endpointinfo modified_hints;
  struct endpointinfo *first, *current, *new;
  char *filenamebase = NULL;
  int filenamebase_len, ret, i;
  List list;

  initlist(&list);

  /* Only HIP is currently supported */
  if (hints && hints->ei_family != PF_HIP) {
    err = -EEI_FAMILY;
    HIP_ERROR("Only HIP is currently supported\n");
    goto err_out;
  }
  /* XX:TODO Check flag values from hints!!!
   E.g. EI_HI_ANY* should cause the resolver to output only a single socket
   address containing an ED that would be received using the corresponding
   HIP_HI_*ANY macro. EI_ANON flag causes the resolver to return only local
   anonymous ids.
  */

  if (hints) {
    memcpy(&modified_hints, hints, sizeof(struct endpointinfo));
  } else {
    /* No hints given, assign default hints */
    memset(&modified_hints, 0, sizeof(struct endpointinfo));
    modified_hints.ei_family = PF_HIP;
  }
  /* getaddrinfo has been modified to support the legacy HIP API and this
     ensures that the legacy API does not do anything funny */
  modified_hints.ei_flags |= AI_HIP_NATIVE;

  /* Note about the hints: the hints is overloaded with AI_XX and EI_XX flags.
     We make the (concious and lazy) decision not to separate them into
     different flags and assume that both getendpointinfo and getaddrinfo
     can survive the overloaded flags. The AI_XX and EI_XX in netdb.h have
     distinct values, so this should be ok. */

#if 0 /* the function below should be reimplemented */
  /* Check for kernel list request */
  if (modified_hints.ei_flags & AI_KERNEL_LIST) {
    err = get_hipd_peer_list(nodename, servname, &modified_hints, res, 0);
    goto err_out;
  }
#endif

  if (nodename == NULL) {
    *res = calloc(1, sizeof(struct endpointinfo));
    if (!*res) {
      err = EEI_MEMORY;
      goto err_out;
    }

    /*DEFAULT_CONFIG_DIR = /etc/hip/*/
    findkeyfiles(DEFAULT_CONFIG_DIR, &list);

    /* allocate the first endpointinfo
       and then link the others to it */

    filenamebase_len = strlen(DEFAULT_CONFIG_DIR) + 1 +
      strlen(getitem(&list,0)) + 1;

    filenamebase = malloc(filenamebase_len);
    if (!filenamebase) {
      HIP_ERROR("Couldn't allocate file name\n");
      err = -ENOMEM;
      goto err_out;
    }
    ret = snprintf(filenamebase, filenamebase_len, "%s/%s",
		   DEFAULT_CONFIG_DIR,
		   getitem(&list,0));
    if (ret <= 0) {
      err = -EINVAL;
      goto err_out;
    }
    err = get_localhost_endpointinfo(filenamebase, servname,
				     &modified_hints, &first);

    free(filenamebase);
    current = first;

    for(i=1; i<length(&list); i++) {
      _HIP_DEBUG ("%s\n", getitem(&list,i));

      filenamebase_len = strlen(DEFAULT_CONFIG_DIR) + 1 +
	strlen(getitem(&list,i)) + 1;

      filenamebase = malloc(filenamebase_len);
      if (!filenamebase) {
	HIP_ERROR("Couldn't allocate file name\n");
	err = -ENOMEM;
	goto err_out;
      }

      ret = snprintf(filenamebase, filenamebase_len, "%s/%s",
		     DEFAULT_CONFIG_DIR,
		     getitem(&list,i));
      if (ret <= 0) {
	err = -EINVAL;
	goto err_out;
      }

      err = get_localhost_endpointinfo(filenamebase, servname,
				       &modified_hints, &new);
      if (err) {
	HIP_ERROR("get_localhost_endpointinfo() failed\n");
	goto err_out;
      }

      current->ei_next = new;
      current = new;

    }

    *res = first;

  } else {
#ifdef CONFIG_HIP_AGENT
    /* Communicate the name and port output to the agent
       synchronously with netlink. First send the name + port
       and then wait for answer (select). The agent filters
       or modifies the list. The agent implements get_peer_endpointinfo
       with some filtering. */
#endif /* add #elseif */

    /*_PATH_HIP_HOSTS=/etc/hip/hosts*/
    err = get_peer_endpointinfo(_PATH_HIP_HOSTS, nodename, servname,
				&modified_hints, res);
  }

 err_out:

  if(filenamebase_len)
    free(filenamebase);
  if(length(&list)>0)
    destroy(&list);

  return err;
}

const char *gepi_strerror(int errcode)
{
  return "HIP native resolver failed"; /* XX FIXME */
}


int get_localhost_endpoint_no_setmyeid(const char *basename,
				       const char *servname,
				       struct endpointinfo *hints,
				       struct endpointinfo **res,
				       struct hip_lhi *lhi)
{
  int err = 0, algo = 0;
  DSA *dsa = NULL;
  RSA *rsa = NULL;
  unsigned char *key_rr = NULL;
  int key_rr_len = 0;
  struct endpoint_hip *endpoint_hip = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
  struct if_nameindex *ifaces = NULL;
  char first_key_line[30];
  FILE* fp;
  const char *pub_suffix = "_pub";

  *res = NULL;

  _HIP_DEBUG("get_localhost_endpoint()\n");
  HIP_ASSERT(hints);

  // XX TODO: check flags?
  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  err = gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
  if (err) {
    HIP_ERROR("gethostname failed (%d)\n", err);
    err = EEI_NONAME;
    goto out_err;
  }

  /* System specific HIs should be added into the kernel with the
     HIP_HI_REUSE_ANY flag set, because this way we make the HIs
     readable by all processes. This function calls setmyeid() internally.. */
  hints->ei_flags |= HIP_HI_REUSE_ANY;

  /* select between anonymous/public HI based on the file name */
  if(!findsubstring(basename, pub_suffix)) {
	  hints->ei_flags |= HIP_ENDPOINT_FLAG_ANON;
	  HIP_DEBUG("Anonymous HI\n");
  } else {
	  HIP_DEBUG("Published HI\n");
  }

  if(findsubstring(basename, "rsa"))
    algo = HIP_HI_RSA;
  else if(findsubstring(basename, "dsa"))
    algo = HIP_HI_DSA;
  else {
    HIP_ERROR("Wrong kind of key file: %s\n",basename);
    err = -ENOMEM;
    goto out_err;
  }

  if(algo == HIP_HI_RSA)
    //modified according Laura's suggestion
    //    err = load_rsa_private_key(basename, &rsa);
    err = load_rsa_public_key(basename, &rsa);
  else
    //err = load_dsa_private_key(basename, &dsa);
    err = load_dsa_public_key(basename, &dsa);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Loading of private key %s failed\n", basename);
    goto out_err;
  }

  if(algo == HIP_HI_RSA)
    err = rsa_to_hip_endpoint(rsa, &endpoint_hip, hints->ei_flags, hostname);
  else
    err = dsa_to_hip_endpoint(dsa, &endpoint_hip, hints->ei_flags, hostname);
  if (err) {
    HIP_ERROR("Failed to allocate and build endpoint.\n");
    err = EEI_SYSTEM;
    goto out_err;
  }

  _HIP_HEXDUMP("host identity in endpoint: ", &endpoint_hip->id.host_id,
	      hip_get_param_total_len(&endpoint_hip->id.host_id));

  _HIP_HEXDUMP("hip endpoint: ", endpoint_hip, endpoint_hip->length);

  if(algo == HIP_HI_RSA) {
    key_rr_len = rsa_to_dns_key_rr(rsa, &key_rr);
    if (key_rr_len <= 0) {
      HIP_ERROR("rsa_key_rr_len <= 0\n");
      err = -EFAULT;
      goto out_err;
    }
    //    err = hip_private_rsa_to_hit(rsa, key_rr, HIP_HIT_TYPE_HASH120, &lhi->hit);
    err = hip_public_rsa_to_hit(rsa, key_rr, HIP_HIT_TYPE_HASH100, &lhi->hit);
    if (err) {
      HIP_ERROR("Conversion from RSA to HIT failed\n");
      goto out_err;
    }
    _HIP_HEXDUMP("Calculated RSA HIT: ", &lhi->hit,
		 sizeof(struct in6_addr));
  } else {
    key_rr_len = dsa_to_dns_key_rr(dsa, &key_rr);
    if (key_rr_len <= 0) {
      HIP_ERROR("dsa_key_rr_len <= 0\n");
      err = -EFAULT;
      goto out_err;
    }
    //err = hip_private_dsa_to_hit(dsa, key_rr, HIP_HIT_TYPE_HASH120, &lhi->hit);
    err = hip_public_dsa_to_hit(dsa, key_rr, HIP_HIT_TYPE_HASH100, &lhi->hit);
    if (err) {
      HIP_ERROR("Conversion from DSA to HIT failed\n");
      goto out_err;
    }
    _HIP_HEXDUMP("Calculated DSA HIT: ", &lhi->hit,
		sizeof(struct in6_addr));
  }

#if 0 /* XX FIXME */
  ifaces = if_nameindex();
  if (ifaces == NULL || (ifaces->if_index == 0)) {
    HIP_ERROR("%s\n", (ifaces == NULL) ? "Iface error" : "No ifaces.");
    err = 1;
    goto out_err;
  }
#endif

  *res = calloc(1, sizeof(struct endpointinfo));
  if (!*res) {
    err = EEI_MEMORY;
    goto out_err;
  }

  (*res)->ei_endpoint = malloc(sizeof(struct sockaddr_eid));
  if (!(*res)->ei_endpoint) {
    err = EEI_MEMORY;
    goto out_err;
  }

  if (hints->ei_flags & EI_CANONNAME) {
    int len = strlen(hostname) + 1;
    if (len > 1) {
      (*res)->ei_canonname = malloc(len);
      if (!((*res)->ei_canonname)) {
	err = EEI_MEMORY;
	goto out_err;
      }
      memcpy((*res)->ei_canonname, hostname, len);
    }
  }

 out_err:

  if (rsa)
    RSA_free(rsa);

  if (dsa)
    DSA_free(dsa);

  if (endpoint_hip)
    free(endpoint_hip);

  if (ifaces)
    if_freenameindex(ifaces);

  if (key_rr)
    free(key_rr);

  return err;
}

int get_localhost_endpoint(const char *basename,
			    const char *servname,
			    struct endpointinfo *hints,
			    struct endpointinfo **res,
			    struct hip_lhi *lhi)
{
  int err = 0, algo = 0;
  DSA *dsa = NULL;
  RSA *rsa = NULL;
  unsigned char *key_rr = NULL;
  int key_rr_len = 0;
  struct endpoint_hip *endpoint_hip = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
  struct if_nameindex *ifaces = NULL;
  char first_key_line[30];
  FILE* fp;
  const char *pub_suffix = "_pub";

  *res = NULL;

  _HIP_DEBUG("get_localhost_endpoint()\n");
  HIP_ASSERT(hints);

  // XX TODO: check flags?
  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  err = gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
  if (err) {
    HIP_ERROR("gethostname failed (%d)\n", err);
    err = EEI_NONAME;
    goto out_err;
  }

  /* System specific HIs should be added into the kernel with the
     HIP_HI_REUSE_ANY flag set, because this way we make the HIs
     readable by all processes. This function calls setmyeid() internally.. */
  hints->ei_flags |= HIP_HI_REUSE_ANY;

  /* select between anonymous/public HI based on the file name */
  if(!findsubstring(basename, pub_suffix))
    hints->ei_flags |= HIP_ENDPOINT_FLAG_ANON;

  /* check the algorithm from PEM format key */
  /* Bing, replace the following code:
  fp = fopen(basename, "rb");
  if (!fp) {
    HIP_ERROR("Couldn't open key file %s for reading\n", basename);
    err = -ENOMEM;
    goto out_err;
  }
  fgets(first_key_line,30,fp);  //read first line.
  _HIP_DEBUG("1st key line: %s",first_key_line);
  fclose(fp);

  if(findsubstring(first_key_line, "RSA"))
    algo = HIP_HI_RSA;
  else if(findsubstring(first_key_line, "DSA"))
    algo = HIP_HI_DSA;
  else {
    HIP_ERROR("Wrong kind of key file: %s\n",basename);
    err = -ENOMEM;
    goto out_err;
  }
  */
  /*Bing, the following code is used instead of the above code*/
  if(findsubstring(basename, "rsa"))
    algo = HIP_HI_RSA;
  else if(findsubstring(basename, "dsa"))
    algo = HIP_HI_DSA;
  else {
    HIP_ERROR("Wrong kind of key file: %s\n",basename);
    err = -ENOMEM;
    goto out_err;
  }

  if(algo == HIP_HI_RSA)
    //modified according Laura's suggestion
    //    err = load_rsa_private_key(basename, &rsa);
    err = load_rsa_public_key(basename, &rsa);
  else
    //err = load_dsa_private_key(basename, &dsa);
    err = load_dsa_public_key(basename, &dsa);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Loading of private key %s failed\n", basename);
    goto out_err;
  }

  if(algo == HIP_HI_RSA)
    err = rsa_to_hip_endpoint(rsa, &endpoint_hip, hints->ei_flags, hostname);
  else
    err = dsa_to_hip_endpoint(dsa, &endpoint_hip, hints->ei_flags, hostname);
  if (err) {
    HIP_ERROR("Failed to allocate and build endpoint.\n");
    err = EEI_SYSTEM;
    goto out_err;
  }

  _HIP_HEXDUMP("host identity in endpoint: ", &endpoint_hip->id.host_id,
	      hip_get_param_total_len(&endpoint_hip->id.host_id));


  _HIP_HEXDUMP("hip endpoint: ", endpoint_hip, endpoint_hip->length);

  if(algo == HIP_HI_RSA) {
    key_rr_len = rsa_to_dns_key_rr(rsa, &key_rr);
    if (key_rr_len <= 0) {
      HIP_ERROR("rsa_key_rr_len <= 0\n");
      err = -EFAULT;
      goto out_err;
    }
    //    err = hip_private_rsa_to_hit(rsa, key_rr, HIP_HIT_TYPE_HASH120, &lhi->hit);
    err = hip_public_rsa_to_hit(rsa, key_rr, HIP_HIT_TYPE_HASH100, &lhi->hit);
    if (err) {
      HIP_ERROR("Conversion from RSA to HIT failed\n");
      goto out_err;
    }
    _HIP_HEXDUMP("Calculated RSA HIT: ", &lhi->hit,
		sizeof(struct in6_addr));
  } else {
    key_rr_len = dsa_to_dns_key_rr(dsa, &key_rr);
    if (key_rr_len <= 0) {
      HIP_ERROR("dsa_key_rr_len <= 0\n");
      err = -EFAULT;
      goto out_err;
    }
    //err = hip_private_dsa_to_hit(dsa, key_rr, HIP_HIT_TYPE_HASH120, &lhi->hit);
    err = hip_public_dsa_to_hit(dsa, key_rr, HIP_HIT_TYPE_HASH100, &lhi->hit);
    if (err) {
      HIP_ERROR("Conversion from DSA to HIT failed\n");
      goto out_err;
    }
    _HIP_HEXDUMP("Calculated DSA HIT: ", &lhi->hit,
		sizeof(struct in6_addr));
  }

#if 0 /* XX FIXME */
  ifaces = if_nameindex();
  if (ifaces == NULL || (ifaces->if_index == 0)) {
    HIP_ERROR("%s\n", (ifaces == NULL) ? "Iface error" : "No ifaces.");
    err = 1;
    goto out_err;
  }
#endif

  *res = calloc(1, sizeof(struct endpointinfo));
  if (!*res) {
    err = EEI_MEMORY;
    goto out_err;
  }

  (*res)->ei_endpoint = malloc(sizeof(struct sockaddr_eid));
  if (!(*res)->ei_endpoint) {
    err = EEI_MEMORY;
    goto out_err;
  }

  if (hints->ei_flags & EI_CANONNAME) {
    int len = strlen(hostname) + 1;
    if (len > 1) {
      (*res)->ei_canonname = malloc(len);
      if (!((*res)->ei_canonname)) {
	err = EEI_MEMORY;
	goto out_err;
      }
      memcpy((*res)->ei_canonname, hostname, len);
    }
  }

  err = setmyeid(((struct sockaddr_eid *) (*res)->ei_endpoint), servname,
		 (struct endpoint *) endpoint_hip, ifaces);
  if (err) {
    HIP_ERROR("Failed to set up my EID (%d)\n", err);
    err = EEI_SYSTEM;
    goto out_err;
  }

#ifdef CONFIG_HIP_DEBUG
  {
    struct sockaddr_eid *eid = (struct sockaddr_eid *) (*res)->ei_endpoint;
    _HIP_DEBUG("eid family=%d value=%d\n", eid->eid_family,
	       ntohs(eid->eid_val));
  }
#endif

 out_err:

  if (rsa)
    RSA_free(rsa);

  if (dsa)
    DSA_free(dsa);

  if (endpoint_hip)
    free(endpoint_hip);

  if (ifaces)
    if_freenameindex(ifaces);

  if (key_rr)
    free(key_rr);

  return err;
}

/**
 * get_local_hits - Query about local HITs and add the corresponding HIs into
 * kernel database. This function is used by getaddrinfo() in getaddrinfo.c
 *
 * @param servname the service port name (e.g. "http" or "12345")
 * @param adr the result of the query - HITs in a linked list
 *
 * @return zero on success, or negative error value on failure
 *
 * @todo: rewrite the function to actually return a list
 *
 */
int get_local_hits(const char *servname, struct gaih_addrtuple **adr) {
  int err = 0, i;
  struct hip_lhi hit;
  char *filenamebase = NULL;
  int filenamebase_len, ret;
  struct endpointinfo modified_hints;
  struct endpointinfo *new = NULL;
  //struct hip_common *msg;
  //struct in6_addr *hiphit;
  //struct hip_tlv_common *det;
  hip_hit_t *allhit;
  List list;

  _HIP_DEBUG("\n");

  /* assign default hints */
  memset(&modified_hints, 0, sizeof(struct endpointinfo));
  modified_hints.ei_family = PF_HIP;

  initlist(&list);
  /* find key files from /etc/hosts */
  /* or */
  /* find key files from /etc/hip */
  findkeyfiles(DEFAULT_CONFIG_DIR, &list);
  _HIP_DEBUG("LEN:%d\n",length(&list));

  //hip_build_user_hdr(&msg,HIP_PARAM_IPV6_ADDR, sizeof(struct endpointinfo));
  for(i=0; i<length(&list); i++) {

	_HIP_DEBUG("%s\n",getitem(&list,i));
	filenamebase_len = strlen(DEFAULT_CONFIG_DIR) + 1 +
      	strlen(getitem(&list,i)) + 1;

    filenamebase = malloc(filenamebase_len);
    HIP_IFEL(!filenamebase, -ENOMEM, "Couldn't allocate file name\n");

    ret = snprintf(filenamebase, filenamebase_len, "%s/%s",
		   DEFAULT_CONFIG_DIR,
		   getitem(&list,i));
    HIP_IFE(ret <= 0, -EINVAL);

    //    get_localhost_endpoint(filenamebase, servname,
    //		   &modified_hints, &new, &hit);
    get_localhost_endpoint_no_setmyeid(filenamebase, servname,
				       &modified_hints, &new, &hit);

    _HIP_DEBUG_HIT("Got HIT: ", &hit.hit);

    if (*adr == NULL) {
      *adr = malloc(sizeof(struct gaih_addrtuple));
      (*adr)->scopeid = 0;
    }
    (*adr)->next = NULL;
    (*adr)->family = AF_INET6;
    memcpy((*adr)->addr, &hit.hit, sizeof(struct in6_addr));
    adr = &((*adr)->next); // for opp mode -miika

    free(filenamebase);
    free(new->ei_canonname);
    free(new->ei_endpoint);
    free(new);
  }

  filenamebase = NULL;
  //new = NULL;

 out_err:
  if(filenamebase)
    free(filenamebase);
  //if(new)
    //free(new);
  if(list.head)
    destroy(&list);

  return err;

}

/**
 * Handles the hipconf commands where the type is @c load. This function is in
 * this file due to some interlibrary dependencies -miika
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_load(struct hip_common *msg, int action,
		    const char *opt[], int optc, int send_only)
{
  	int arg_len, err = 0, i, len;
	FILE *hip_config = NULL;

	List list;
	char *c, line[128], *hip_arg, ch, str[128], *fname, *args[64],
		*comment, *nl;

	HIP_IFEL((optc != 1), -1, "Missing arguments\n");

	if (!strcmp(opt[0], "default"))
		fname = HIPD_CONFIG_FILE;
	else
		fname = (char *) opt[0];


	HIP_IFEL(!(hip_config = fopen(fname, "r")), -1,
		 "Error: can't open config file %s.\n", fname);

	while(err == 0 && fgets(line, sizeof(line), hip_config) != NULL) {
		_HIP_DEBUG("line %s\n", line);
		/* Remove whitespace */
		c = line;
		while (*c == ' ' || *c == '\t')
			c++;

		/* Line is a comment or empty */
		if (c[0] =='#' || c[0] =='\n' || c[0] == '\0')
			continue;

		/* Terminate before (the first) trailing comment */
		comment = strchr(c, '#');
		if (comment)
			*comment = '\0';

		/* prefix the contents of the line with" hipconf"  */
		memset(str, '\0', sizeof(str));
		strcpy(str, "hipconf");
		str[strlen(str)] = ' ';
		hip_arg = strcat(str, c);
		/* replace \n with \0  */
		nl = strchr(hip_arg, '\n');
		if (nl)
			*nl = '\0';

		/* split the line into an array of strings and feed it
		   recursively to hipconf */
		initlist(&list);
		extractsubstrings(hip_arg, &list);
		len = length(&list);
		for(i = 0; i < len; i++) {
			/* the list is backwards ordered */
			args[len - i - 1] = getitem(&list, i);
		}
		err = hip_do_hipconf(len, args, 1);
		if (err) {
			HIP_ERROR("Error on the following line: %s\n", line);
			HIP_ERROR("Ignoring error on hipd configuration\n");
			err = 0;
		}

		destroy(&list);
	}

 out_err:
	if (hip_config)
		fclose(hip_config);

	return err;

}

/**
 * Handles the hipconf commands where the type is @c del. This function is in this file due to some interlibrary dependencies -miika
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 *
 */
int hip_conf_handle_hi_get(struct hip_common *msg, int action,
		      const char *opt[], int optc)
{
	struct gaih_addrtuple *at = NULL;
	struct gaih_addrtuple *tmp;
	int err = 0;

 	HIP_IFEL((optc != 1), -1, "Missing arguments\n");

	/* XX FIXME: THIS IS KLUDGE; RESORTING TO DEBUG OUTPUT */
	/*err = get_local_hits(NULL, &at);*/
	if (err)
		goto out_err;

	tmp = at;
	while (tmp) {
		/* XX FIXME: THE LIST CONTAINS ONLY A SINGLE HIT */
		_HIP_DEBUG_HIT("HIT", &tmp->addr);
		tmp = tmp->next;
	}

	_HIP_DEBUG("*** Do not use the last HIT (see bugzilla 175 ***\n");

out_err:
	if (at)
		HIP_FREE(at);
	return err;
}

/* getendpointfo() modified for sockaddr_hip instead of sockaddr_eid */

int get_hit_addrinfo(const char *nodename, const char *servname,
		    const struct addrinfo *hints,
		    struct addrinfo **res)
{
  int err = 0;
  struct addrinfo modified_hints;
  struct addrinfo *current = NULL;

  struct sockaddr_hip *sock_hip;
  struct hip_tlv_common *current_param = NULL;
  hip_tlv_type_t param_type = 0;
  struct endpoint_hip *endp = NULL;
  struct hip_common *msg;

  *res = NULL;

  if (hints) {
    memcpy(&modified_hints, hints, sizeof(struct addrinfo));
  } else {
    memset(&modified_hints, 0, sizeof(struct addrinfo));
    modified_hints.ai_family = PF_HIP;
  }

  if (!nodename) { /* Query local hits from daemon */

    HIP_IFE(!(msg = hip_msg_alloc()), -ENOMEM);
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HITS, 0), -1,
			"Failed to build message to daemon\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, 
			"Failed to receive message from daemon\n");

    while((current_param = hip_get_next_param(msg, current_param)) != NULL) {
      param_type = hip_get_param_type(current_param);
      if (param_type == HIP_PARAM_EID_ENDPOINT){
	if(!current) {
	  *res = calloc(1, sizeof(struct addrinfo));
	  HIP_IFE(!*res, -ENOMEM);
	  current = *res;
	} else {
	  current->ai_next = calloc(1, sizeof(struct addrinfo));
	  HIP_IFE(!current->ai_next, -ENOMEM);
	  current = current->ai_next;
	}

	sock_hip = calloc(1, sizeof(struct sockaddr_hip));
	HIP_IFE(!sock_hip, -ENOMEM);
	endp = hip_get_param_contents_direct(current_param);
	memcpy(&sock_hip->ship_hit , &endp->id.hit, sizeof(struct in6_addr));

	current->ai_addr = sock_hip;
	current->ai_family = PF_HIP;
	current->ai_socktype = hints->ai_socktype;
	current->ai_protocol = hints->ai_protocol;
	current->ai_addrlen = sizeof(struct sockaddr_hip);
	}
  }

  } else if (!strcmp(nodename, "0.0.0.0")) {

    (*res) = calloc(1, sizeof(struct addrinfo));
    (*res)->ai_addr = calloc(1, sizeof(struct sockaddr_hip));
    (*res)->ai_family = PF_HIP;
    (*res)->ai_socktype = hints->ai_socktype;
    (*res)->ai_protocol = hints->ai_protocol;
    (*res)->ai_addrlen = sizeof(struct sockaddr_hip);

  } else {

    err = get_peer_addrinfo_hit(_PATH_HIP_HOSTS, nodename, servname,
				&modified_hints, res);
  }
 out_err:

  return err;
}


int get_addrinfo_from_key(const char *basename,
			       const char *servname,
			       struct addrinfo *hints,
			       struct addrinfo **res)
{
  int err = 0, algo = 0, anon = 0;
  DSA *dsa = NULL;
  RSA *rsa = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
  struct if_nameindex *ifaces = NULL;
  FILE* fp;
  struct sockaddr_hip *sock_hip;

  *res = NULL;

  HIP_ASSERT(hints);

  if (hints->ai_flags & AI_CANONNAME) {
    memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
    err = gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
    if (err) {
      HIP_ERROR("gethostname failed (%d)\n", err);
      err = EEI_NONAME;
      goto out_err;
    }
  }

  if(!findsubstring(basename, DEFAULT_PUB_HI_FILE_NAME_SUFFIX))
    anon = HIP_ENDPOINT_FLAG_ANON;

  fp = fopen(basename, "rb");
  if (!fp) {
    HIP_ERROR("Couldn't open key file %s for reading\n", basename);
    err = -ENOMEM;
    goto out_err;
  }

  if(findsubstring(basename, "rsa"))
    algo = HIP_HI_RSA;
  else if(findsubstring(basename, "dsa"))
    algo = HIP_HI_DSA;
  else {
    HIP_ERROR("Key file not RSA or DSA: %s\n",basename);
    err = -ENOMEM;
    goto out_err;
  }

  HIP_DEBUG("basename %s\n", basename);

  if(algo == HIP_HI_RSA)
    err = load_rsa_public_key(basename, &rsa);
  else
    err = load_dsa_public_key(basename, &dsa);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Loading of key %s failed\n", basename);
    goto out_err;
  }

  *res = calloc(1, sizeof(struct addrinfo));
  if (!*res) {
    err = EEI_MEMORY;
    goto out_err;
  }

  (*res)->ai_addr = malloc(sizeof(struct sockaddr_hip));
  if (!(*res)->ai_addr) {
    err = EEI_MEMORY;
    goto out_err;
  }

  sock_hip = (struct sockaddr_hip *)(*res)->ai_addr;
  if (algo == HIP_HI_RSA)
    err = hip_public_rsa_to_hit(rsa, NULL, anon, &sock_hip->ship_hit);
  else
    err = hip_public_dsa_to_hit(dsa, NULL, anon, &sock_hip->ship_hit);

  if (err) {
    HIP_ERROR("Failed to get HIT from key.\n");
    err = EEI_SYSTEM;
    goto out_err;
  }

  if (hints->ai_flags & AI_CANONNAME) {
    int len = strlen(hostname) + 1;
    if (len > 1) {
      (*res)->ai_canonname = malloc(len);
      if (!((*res)->ai_canonname)) {
	err = EEI_MEMORY;
	goto out_err;
      }
      memcpy((*res)->ai_canonname, hostname, len);
    }
  }

  (*res)->ai_flags = 0;
  (*res)->ai_family = PF_HIP;
  (*res)->ai_socktype = hints->ai_socktype;
  (*res)->ai_protocol = hints->ai_protocol;
  (*res)->ai_addrlen = sizeof(struct sockaddr_hip);
  /* ai_addr, ai_canonname already set */

 out_err:

  if (rsa)
    RSA_free(rsa);
  if (dsa)
    DSA_free(dsa);

  if (err && *res) {
    if ((*res)->ai_addr)
      free((*res)->ai_addr);
    if ((*res)->ai_canonname)
      free((*res)->ai_canonname);
    free(*res);
    *res = NULL;
  }
  
  return err;
}

int get_sockaddr_hip_from_key(const char *filename, struct sockaddr_hip **hit)
{
  int err = 0;
  struct addrinfo hints;
  struct addrinfo *res = NULL;

  memset(&hints, 0, sizeof(hints));

  err = get_addrinfo_from_key(filename, NULL, &hints, &res);
  if (err)
    goto out_err;

  *hit = res->ai_addr;

 out_err:
  if (res)
    free(res);
  return err;
}

int get_peer_addrinfo_hit(const char *hostsfile,
			  const char *nodename,
			  const char *servname,
			  const struct addrinfo *hints,
			  struct addrinfo **res)
{
  int err = 0, ret = 0, i=0;
  unsigned int lineno = 0, fqdn_str_len = 0;
  char fqdn_str[HOST_NAME_MAX];
  struct in6_addr hit;
  struct sockaddr_hip *addr;

  HIP_DEBUG("Called, nodename: %s\n", nodename);
  *res = NULL;
  memset(fqdn_str, 0, sizeof(fqdn_str));

  if (inet_pton(AF_INET6, nodename, &hit) > 0) {
    HIP_DEBUG("Nodename is numerical address\n");
    hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
				       hip_map_first_id_to_hostname_from_hosts,
				       &hit, fqdn_str);
  } else {
    strncpy(fqdn_str, nodename, HOST_NAME_MAX);

    HIP_IFEL(hip_for_each_hosts_file_line(hostsfile,
		hip_map_first_hostname_to_hit_from_hosts, fqdn_str, &hit), -1,
		"Couldn't map nodename to HIT\n");
  }

  fqdn_str_len = strlen(fqdn_str);

  (*res) = calloc(1, sizeof(struct addrinfo));
  HIP_IFE(!(*res), EEI_MEMORY);
  (*res)->ai_addr = calloc(1, sizeof(struct sockaddr_hip));
  HIP_IFE(!(*res)->ai_addr, EEI_MEMORY);

  if (hints->ai_flags & AI_CANONNAME) {
    (*res)->ai_canonname = malloc(fqdn_str_len + 1);
    HIP_IFE(!(*res)->ai_canonname, EEI_MEMORY);
    HIP_ASSERT(strlen(fqdn_str) == fqdn_str_len);
    strcpy((*res)->ai_canonname, fqdn_str);
    /* XX FIX: we should append the domain name if it does not exist */
  }

  addr = (struct sockaddr_hip *)(*res)->ai_addr;
  memcpy(&addr->ship_hit, &hit, sizeof(hit));

  (*res)->ai_flags = hints->ai_flags;
  (*res)->ai_family = PF_HIP;
  (*res)->ai_socktype = hints->ai_socktype;
  (*res)->ai_protocol = hints->ai_protocol;
  (*res)->ai_addrlen = sizeof(struct sockaddr_hip);

 out_err:

  if (err && *res) {
      if((*res)->ai_addr)
        free((*res)->ai_addr);
      if((*res)->ai_canonname)
	free((*res)->ai_canonname);
      free(*res);
      *res = NULL;
  }

  return err;
}

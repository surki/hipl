/*
 * Echo STDIN to a selected server which should echo it back.
 * Use this application with conntest-server-xx.
 *
 * usage: ./conntest-client-native-user-key host tcp|udp port
 *        (reads stdin)
 *
 * Notes:
 * - assumes that udp packets arrive in order (high probability within same
 *   network)
 * Bugs:
 * - none
 * Todo:
 * - rewrite/refactor for better modularity
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

int main(int argc,char *argv[]) {
  struct endpointinfo hints, *epinfo, *res = NULL;
  struct sockaddr_eid my_eid;
  struct timeval stats_before, stats_after;
  unsigned long stats_diff_sec, stats_diff_usec;
  char mylovemostdata[IP_MAXPACKET];
  char receiveddata[IP_MAXPACKET];
  char *type_name, *peer_port_name, *peer_name;
  int recvnum, sendnum;
  int datalen = 0;
  int type;
  int datasent = 0;
  int datareceived = 0;
  int ch;
  int err = 0;
  int sockfd = 0, socktype;
  se_family_t endpoint_family;
  char *user_key_base = "/etc/hip/hip_host_dsa_key";
  struct endpoint *endpoint;
  const char *cfile = "default";

  hip_set_logtype(LOGTYPE_STDERR);
  hip_set_logfmt(LOGFMT_SHORT);
  HIP_IFEL(hip_set_auto_logdebug(cfile), -1,
	   "Error: Cannot set the debugging parameter.\n");

 
  if (argc != 4) {
    HIP_ERROR("Usage: %s host tcp|udp port\n", argv[0]);
    err = 1;
    goto out;
  }
  
  peer_name = argv[1];
  type_name = argv[2];
  peer_port_name = argv[3];
  endpoint_family = PF_HIP;
  
  /* Set transport protocol */
  if (strcmp(type_name, "tcp") == 0) {
    socktype = SOCK_STREAM;
  } else if (strcmp(type_name, "udp") == 0) {
    socktype = SOCK_DGRAM;
  } else {
    HIP_ERROR("Error: only TCP and UDP supported.\n");
    err = 1;
    goto out;
  }

  sockfd = socket(endpoint_family, socktype, 0);
  if (sockfd == -1) {
    HIP_ERROR("creation of socket failed\n");
    err = 1;
    goto out;
  }

  err = load_hip_endpoint_pem(user_key_base, &endpoint);
  if (err) {
    HIP_ERROR("Failed to load user HIP key %s\n", user_key_base);
    goto out;
  }

  err = setmyeid(&my_eid, "", endpoint, NULL);
  if (err) {
    HIP_ERROR("Failed to set up my EID (%d)\n", err);
    err = 1;
    goto out;
  }

  /* We have to bind to the EID to use it. */
  err = bind(sockfd, (struct sockaddr *) &my_eid, sizeof(struct sockaddr_eid));
  if (err) {
    HIP_PERROR("bind failed");
    goto out;
  }

  /* set up endpoint lookup information  */
  memset(&hints, 0, sizeof(struct endpointinfo));
  hints.ei_socktype = socktype;
  hints.ei_family = endpoint_family;

  /* Lookup endpoint. We do not need to call setpeereid because
     getendpointinfo does it automatically. */
  err = getendpointinfo(peer_name, peer_port_name, &hints, &res);
  if (err) {
    HIP_ERROR("getendpointinfo failed (%d): %s\n", err, gepi_strerror(err));
    goto out;
  }

  HIP_DEBUG("family=%d value=%d\n", res->ei_family,
	    ntohs(((struct sockaddr_eid *) res->ei_endpoint)->eid_val));

  // data from stdin to buffer
  bzero(receiveddata, IP_MAXPACKET);
  bzero(mylovemostdata, IP_MAXPACKET);

  printf("Input some text, press enter and ctrl+d\n");

  // horrible code
  while ((ch = fgetc(stdin)) != EOF && (datalen < IP_MAXPACKET)) {
    mylovemostdata[datalen] = (unsigned char) ch;
    datalen++;
  }

  gettimeofday(&stats_before, NULL);

  epinfo = res;
  while(epinfo) {
    err = connect(sockfd, epinfo->ei_endpoint, epinfo->ei_endpointlen);
    if (err) {
      HIP_PERROR("connect");
      goto out;
    }
    epinfo = epinfo->ei_next;
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
	goto out;
      }
      datasent += sendnum;
    }
    
    if (datareceived < datalen) {
      recvnum = recv(sockfd, receiveddata + datareceived,
		     datalen-datareceived, 0);
      if (recvnum <= 0) {
	HIP_PERROR("recv");
	err = 1;
	goto out;
      }
      datareceived += recvnum;
    }
  }

  if (memcmp(mylovemostdata, receiveddata, IP_MAXPACKET)) {
    HIP_ERROR("Sent and received data did not match\n");
    err = 1;
    goto out;
  }

out:

  if (sockfd)
    close(sockfd); // discard errors
  if (res)
     free_endpointinfo(res);

  HIP_INFO("Result of data transfer: %s.\n", (err ? "FAIL" : "OK"));

out_err:
  return err;
}

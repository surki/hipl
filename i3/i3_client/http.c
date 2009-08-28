/* webclient.c written by detour@metalshell.com
 *
 * This code will connect to a host and attempt to download
 * the source for an http page.  
 *
 * run: ./webclient <host>
 *
 * http://www.metalshell.com/
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#ifndef _WIN32
	#include <unistd.h>
#endif
#include "../utils/netwrap.h"

#include "http.h"
#include "i3_id.h"
#include "i3_debug.h"

#define PROTOCOL "tcp"
#define SERVICE "http"

#define STR_LEN 256
#define STR_ID_LEN   41  /* two chars per real "byte" plus one for end of string */
#define PORT_LEN 10 /* just enough to store a port in ascii */
#define IP_LEN   65  /* just in case, for IPv6 */
#define BUF_SIZE 65535 
#define CHAR_LEN 4

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif


/* get host name and format get command from input 
 * example,
 *   input: www.cs.berkeley.edu/~istoica/index.html
 *   host:  www.cs.berkeley.edu
 *   get_cmd: GET /~istoica/index.html HTTP/1.0 */
void get_args(char *input, char *host, char *get_cmd, 
		int *port, int buf_len) 
{
  char *p1, *p2, *end, *ptemp;

  if (strlen(input) >= buf_len) {
    fprintf(stderr, "input string too large: %s\n", input);
    return;
  }
      
  /* get host name */
  ptemp = get_cmd;
  strcpy(ptemp, "GET ");
  ptemp += strlen("GET ");

  end = input + strlen(input);
  p1 = strstr(input, "/");
  p2 = strstr(input, ":");

  if (NULL == p1) p1 = end;
  if (NULL == p2) p2 = p1;

  if (p1 != end) {
      strcpy(ptemp, p1);
      ptemp += strlen(p1);
  } else {
      strcpy(ptemp, "/ ");
      ptemp += strlen("/ ");
  }
  
  if (p2 != p1) {
      memcpy(host, p2+1, p1-p2-1);
      host[p1-p2-1] = 0;
      *port = atoi(host);
  } else {
      *port = 0;
  }
  
  memcpy(host, input, p2-input);
  host[p2-input] = 0;
  
  strcpy(ptemp, " HTTP/1.0\n\n");
}   

/* get an entry containing the host IP address, port number, and 20 byte ID */ 
int get_entry(char *buf, char *end, char *ip_addr, int *port,
		char *id, char *status, float *latitude, float *longitude)
{
  char *ip_start, *port_start, *id_start, *status_start, *coord_start, *temp, *p1, *p2;
  char num_str[PORT_LEN];
  int len_id;
  *status = FALSE;
  
  /* split fields */
  ip_start = strstr(buf, " ");
  if (ip_start == NULL || ip_start > end)
    return 0;
  else
    ip_start++;
  id_start = strstr(ip_start, " ");
  if (id_start == NULL || id_start > end)
    return 0;
  else
    id_start++;
  status_start = strstr(id_start, " ");
  if (status_start == NULL || status_start > end)
    return 0;
  else
    status_start++;
  coord_start = strstr(status_start, " ");
  if (coord_start == NULL || coord_start > end)
      return 0;
  else
      coord_start++;

  /* lat_start = strstr(status_start, " ");
  if (lat_start == NULL || lat_start > end)
      return 0;
  else
      lat_start++;
  long_start = strstr(lat_start, " ");
  if (long_start == NULL || long_start > end)
      return 0;
  else
      long_start++;*/
 
  /* look for delimiter between ip address and port number ":" ... */
  port_start = strstr(ip_start, ":");
  if (port_start == NULL || port_start >= id_start)
    return 0;
  else
    port_start++;

  /* ... make sure that at the left of ":" there is an IP address */ 
  for (temp = port_start-1; *temp != '.'; temp--) {
    if (port_start-1 - temp > CHAR_LEN) {
      /* not an IP address return */
      return 0;
    }
  }
    
  /* get address */
  if (port_start-1 - ip_start > IP_LEN)
    return 0;
  memcpy(ip_addr, ip_start, port_start-1 - ip_start);
  ip_addr[port_start-1 - ip_start] = 0;
  
  /* get port */
  if (id_start-1 - port_start > PORT_LEN)
    return 0;
  memcpy(num_str, port_start, id_start-1 - port_start);
  num_str[id_start-1 - port_start] = 0;
  *port = atoi(num_str);

  /* get id */
  if (status_start-1 - id_start > STR_ID_LEN)
    len_id = STR_ID_LEN;
  else
    len_id = status_start-1 - id_start;
  memcpy(id, id_start, len_id);
  id[len_id] = 0;

  /* get coordinates: TODO checks */
  sscanf(coord_start, "%f %f", latitude, longitude);
  
  /* get status */
  if ((p1 = strstr(status_start, "No")) > end)
    p1 = NULL;
  if ((p2 = strstr(status_start, "Running")) > end)
    p2 = NULL;

  if (p1 && p2)
    return 0;
  else if (p2) {
    *status = TRUE;
    return 1;
  }
  else if (p1)
    return 1;
    
  return 0;
}

int get_address(char *web_url, I3ServerList *list)
{
  nw_skt_t sockid;
  int bufsize;
  char host[STR_LEN];
  char get_cmd[STR_LEN];
  char buffer[BUF_SIZE];
  char ip_addr[IP_LEN];
  char id[STR_ID_LEN];
  char status;
  int  port;
  Coordinates coord;
  struct sockaddr_in socketaddr;
  struct hostent *hostaddr;
  struct servent *servaddr;
  struct protoent *protocol;
  char *p, *next;
  int offset = 0;

  /* get host name and format the get command */
  get_args(web_url, host, get_cmd, &port, STR_LEN);

  /* Resolve the host name */
  if (!(hostaddr = gethostbyname(host))) {
    fprintf(stderr, "Getting server list: error resolving host %s.", host);
    return -1;
  }

  /* clear and initialize socketaddr */
  memset(&socketaddr, 0, sizeof(socketaddr));
  socketaddr.sin_family = AF_INET;

  /* setup the servent struct using getservbyname */
  servaddr = getservbyname(SERVICE, PROTOCOL);
  if (0 == port)
      socketaddr.sin_port = servaddr->s_port;
  else
      socketaddr.sin_port = htons(port);

  memcpy(&socketaddr.sin_addr, hostaddr->h_addr, hostaddr->h_length);

  /* protocol must be a number when used with socket()
     since we are using tcp protocol->p_proto will be 0 */
  protocol = getprotobyname(PROTOCOL);

  sockid = socket(AF_INET, SOCK_STREAM, protocol->p_proto);
  if (sockid < 0) {
    fprintf(stderr, "get: error creating socket\n");
    return -1;
  }

  /* everything is setup, now we connect */
  if(connect(sockid, (struct sockaddr *)&socketaddr, sizeof(socketaddr)) == -1) {
    fprintf(stderr, "get: error connecting\n");
    nw_close(sockid);
    return -1;
  }

  /* send our get request for http */
  if (send(sockid, get_cmd, strlen(get_cmd), 0) == -1) {
    fprintf(stderr, "get: error sending data\n");
    nw_close(sockid);
    return -1;
  }

  //printf ("8888:   start get\n");
  /* read the socket until its clear then exit */
  while ( (bufsize = recv(sockid, buffer+offset, sizeof(buffer)-offset-1, 0))) {

    if (bufsize == -1) {
        I3_PRINT_DEBUG1 (I3_DEBUG_LEVEL_MINIMAL,
                "Error while getting list of i3 servers in get_addr: %s.\n",
                strerror (errno)
            );
        break;
    }

    buffer[offset+bufsize] = 0;
    p = buffer;

    while ((next = strstr(p, "\n")) != NULL) {
      if (get_entry(p, next, ip_addr, &port, id, &status, 
		  &(coord.latitude), &(coord.longitude))) {
	if (status) {
	    I3_PRINT_DEBUG5(I3_DEBUG_LEVEL_VERBOSE, "GET: %s %d %s %.1f %.1f\n",
		    ip_addr, port, id, coord.latitude, coord.longitude);
	    update_i3server(list, ntohl(inet_addr(ip_addr)), 
		    	    port, atoi3id(id), coord);
	}
      }
      p = next + 1;
    }

    memmove(buffer, p, strlen(p));
    offset = strlen(p);
  }
  //printf ("8888:   stop get\n");
  nw_close(sockid);
  return 0;
}

void update_i3_server_list(char *web_url, I3ServerList *list,
			   I3ServerListNode **next_ping)
{
    mark_i3servers_dead(list);
    if (get_address(web_url, list) >= 0) {
	delete_dead_i3servers(list);
	*next_ping = list->list;
    }
}

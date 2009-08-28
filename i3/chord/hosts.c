/* host registration (mainly for testing) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <netdb.h>
extern int h_errno;
#include <net/if.h>
#include "chord.h"

#define TRIVIAL_LOCAL_ADDR	"127.0.0.1"
#define MAX_NUM_INTERFACES	3
#define IFNAME_LEN		256

/***************************************************************************
 * 
 * Purpose: Get IP address of local machine by ioctl on eth0-ethk
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
static uint32_t get_local_addr_eth(void)
{
  int i, tempfd;
  struct sockaddr_in addr;
  char ifname[IFNAME_LEN];
  struct ifreq ifr;		
  
  for (i = 0; i < MAX_NUM_INTERFACES; i++) {
    sprintf(ifname, "eth%d", i);
    strcpy(ifr.ifr_name, ifname);
    tempfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (-1 != ioctl(tempfd, SIOCGIFFLAGS, (char *)&ifr)) {
      if (0 != (ifr.ifr_flags & IFF_UP)) {
	if (-1 != ioctl(tempfd, SIOCGIFADDR, (char *)&ifr)) {
	  addr = *((struct sockaddr_in *) &ifr.ifr_addr);
	  close(tempfd);
	  return addr.sin_addr.s_addr;
	}
      }
    }
    close(tempfd);
  }
  
  return inet_addr(TRIVIAL_LOCAL_ADDR);
}

/***************************************************************************
 * 
 * Purpose: Get the IP address of an arbitrary machine
 *	given the name of the machine
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
static uint32_t name_to_addr(const char *name)
{
    int i;
    struct hostent *hptr = gethostbyname(name);
    if (!hptr) {
      weprintf("gethostbyname(%s) failed", name);
    }
    else {
      for (i = 0; i < hptr->h_length/sizeof(uint32_t); i++) {
	uint32_t addr = *((uint32_t *) hptr->h_addr_list[i]);
	if (inet_addr(TRIVIAL_LOCAL_ADDR) != addr)
	  return addr;
      }
    }
    return 0;
}


/***************************************************************************
 * 
 * Purpose: Get IP address of local machine by uname/gethostbyname
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
static uint32_t get_local_addr_uname(void)
{
  struct utsname myname;
  uint32_t addr;

  if (uname(&myname) < 0) {
    weprintf("uname failed:");
  } else {
    addr = name_to_addr(myname.nodename);
  }
  
  if (addr == 0)
    return inet_addr(TRIVIAL_LOCAL_ADDR);
  else
    return addr;
}

/***************************************************************************
 * 
 * Purpose: Get IP address of local machine
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
static uint32_t get_local_addr(void)
{
  uint32_t addr;
  
  /* First try uname/gethostbyname */
  if ((addr = get_local_addr_uname()) != inet_addr(TRIVIAL_LOCAL_ADDR))
    return addr;
  /* If that is unsuccessful, try ioctl on eth interfaces */
  if ((addr = get_local_addr_eth()) != inet_addr(TRIVIAL_LOCAL_ADDR))
    return addr;
  
  /* This is hopeless, return TRIVIAL_IP */
  return(inet_addr(TRIVIAL_LOCAL_ADDR));
}

/***********************************************************************/
/* get_addr: get IP address of server */
in_addr_t
get_addr(void)
{
  return (in_addr_t) get_local_addr();
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#ifndef _WIN32

	#include <sys/types.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <sys/utsname.h>
	#include <netdb.h>
	extern int h_errno;
	#include <sys/ioctl.h>
	#include <net/if.h>

	#include <sys/sysctl.h>
#endif

#include "eprintf.h"


#define TRIVIAL_LOCAL_ADDR	"127.0.0.1"
#define MAX_NUM_INTERFACES	3
#define IFNAME_LEN		256

#ifndef _WIN32
/***************************************************************************
 * 
 * Purpose: Get IP address of local machine by ioctl on eth0-ethk
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
uint32_t get_local_addr_eth(void)
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
uint32_t name_to_addr(const char *name)
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
uint32_t get_local_addr_uname(void)
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
 * Purpose: Get IP address of local machine by trying out all possible
 * interfaces starting with interfaceName.  For eg:, if interfaceName = "eth",
 * try out eth0, eth1, eth2, etc.
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
uint32_t get_local_addr_by_interface(char *interfaceName)
{
  int i, tempfd;
  struct sockaddr_in addr;
  char ifname[IFNAME_LEN];
  struct ifreq ifr;		
  
  for (i = 0; i < MAX_NUM_INTERFACES; i++) {
    sprintf(ifname, "%s%d", interfaceName, i);
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
 * Purpose: Get IP address of local machine
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
uint32_t get_local_addr(void)
{
    uint32_t addr;

    // TODO  Don't hardcode eth, wlan, ath..  Either read from main 
    // proxy config file or get a better, portable way to decide all 
    // interfaces on the system.

    /* First try ioctl on eth interfaces */
    if ((addr = get_local_addr_by_interface("eth")) != 
	inet_addr(TRIVIAL_LOCAL_ADDR)) {
      return addr;
    }
    
    /* First try ioctl on wlan interfaces */
    if ((addr = get_local_addr_by_interface("wlan")) != 
	inet_addr(TRIVIAL_LOCAL_ADDR)) {
      return addr;
    }

    /* First try ioctl on eth interfaces */
    if ((addr = get_local_addr_by_interface("ath")) != 
	inet_addr(TRIVIAL_LOCAL_ADDR)) {
      return addr;
    }
    
    /* If that is unsuccessful, try uname/gethostbyname */
    if ((addr = get_local_addr_uname()) != inet_addr(TRIVIAL_LOCAL_ADDR)) {
      return addr;
    }

    /* This is hopeless, return TRIVIAL_IP */
    return(inet_addr(TRIVIAL_LOCAL_ADDR));
}


#else
/*** WIN32 IMPLEMENTATION ***/

#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <Iphlpapi.h>
#include <assert.h>
#include "inetfns.h"
#include "eprintf.h"

#include "netwrap.h"

/***************************************************************************
 * 
 * Purpose: Get IP address of local machine
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
uint32_t get_local_addr(void)
{
    uint32_t addr;

    PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pai;

    ULONG OutBufLen = 0;

    addr = inet_addr(TRIVIAL_LOCAL_ADDR);

    GetAdaptersInfo(NULL, &OutBufLen);
    pAdapterInfo = (PIP_ADAPTER_INFO)malloc(OutBufLen);
    GetAdaptersInfo(pAdapterInfo, &OutBufLen);
    
    pai = pAdapterInfo;
    while (pai) {
      if (pai->GatewayList.IpAddress.String[0] != 0)
			addr = inet_addr(pai->IpAddressList.IpAddress.String);
      pai = pai->Next;
    }
    free(pAdapterInfo);
    return addr;

}

uint32_t
get_local_addr_eth()
{
    return get_local_addr();
}

uint32_t
name_to_addr(const char *name)
{
    uint32_t ret_val = 0;
    int err = 0;
    struct addrinfo hints;
    struct addrinfo* res = NULL;

    hints.ai_flags = 0;
    hints.ai_family = PF_INET;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;
    hints.ai_addrlen = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    err = getaddrinfo(name, // const char* nodename,
			NULL, // const char* servname,
			&hints, // const struct addrinfo* hints,
			&res); // struct addrinfo** res

    if (0 == err) {
	struct sockaddr_in *addr;

	assert(NULL != res);
	assert(NULL != res->ai_addr);
	addr = (struct sockaddr_in*)res->ai_addr;
	assert(PF_INET == addr->sin_family);

	ret_val = addr->sin_addr.S_un.S_addr;
	freeaddrinfo(res);
	return ret_val;
    } else {
	weprintf("getaddrinfo(%s) failed: %s", name, strerror(WSAGetLastError()));
	return 0;
    }
}

uint32_t
get_local_addr_uname()
{
    char *buf;
    int buf_size = 1024;
    uint32_t ret;

    buf = calloc(buf_size, 1);
    assert(NULL != buf);

    if (0 == gethostname(buf, buf_size)) {
	ret = name_to_addr(buf);
    } else {
	weprintf("Unable to retrieve host name!");
	ret = 0;
    }
    free(buf);

    return ret;
}
/*
uint32_t
get_local_addr()
{
    // - retrieve information about all network adapters
    // - look for the first non-loopback interface
    DWORD err = 0;
    PIP_ADAPTER_ADDRESSES addresses = NULL;
    ULONG size;
    uint32_t lb_addr, ret_val;

    lb_addr = inet_addr("127.0.0.1");

    // allocate a Real Large Buffer hoping that it's big enough
    size = sizeof(IP_ADAPTER_ADDRESSES) * 64;
    addresses = (PIP_ADAPTER_ADDRESSES)calloc(size, 1);
    assert(NULL != addresses);

    err = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST || GAA_FLAG_SKIP_FRIENDLY_NAME || GAA_FLAG_SKIP_MULTICAST || GAA_FLAG_SKIP_DNS_SERVER, NULL, addresses, &size);
    switch(err)
    {
	case ERROR_SUCCESS:
	    while (NULL != addresses) {
		PIP_ADAPTER_UNICAST_ADDRESS addr = addresses->FirstUnicastAddress;
		while (NULL != addr) {
		    if (AF_INET == addr->Address.lpSockaddr->sa_family && ((SOCKADDR_IN*)addr->Address.lpSockaddr)->sin_addr.S_un.S_addr != lb_addr) {
			ret_val = ((SOCKADDR_IN*)addr->Address.lpSockaddr)->sin_addr.S_un.S_addr;
			free(addresses);
			return ret_val;
		    }
		    addr = addr->Next;
		}
		addresses = addresses->Next;
	    }
	    break;
	case ERROR_NOT_ENOUGH_MEMORY:
	    weprintf("GetAdaptersAddresses returned NOT ENOUGH MEMORY!");
	    break;
	case ERROR_BUFFER_OVERFLOW:
	    weprintf("GetAdaptersAddresses returned BUFFER OVERFLOW\n");
	    break;
	case ERROR_INVALID_PARAMETER:
	    weprintf("GetAdaptersAddresses returned INVALID PARAMETER\n");
	    break;
	default:
	    weprintf("GetAdaptersAddresses returned unknown return code\n");
	    break;
    }
    free(addresses);
    return 0;
}
*/

#endif //_WIN32

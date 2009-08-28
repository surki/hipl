#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "debug.h"

int main(int argc,char *argv[]) {
  struct ifaddrs *g_ifaces = NULL, *g_iface;
  struct if_nameindex *i_ifaces = NULL, *i_iface;
  int err = 0;
  char *default_str = "<unknown>";
  char addr_str[INET6_ADDRSTRLEN+1]; /* Segfault? Alloc this dynamically?x */

  /* getifaddrs */
  
  err = getifaddrs(&g_ifaces);
  if (err) {
    HIP_ERROR("getifaddr failed\n");
    goto out;
  }
  
  printf("===getifaddrs===\n");
  for (g_iface = g_ifaces; g_iface; g_iface = g_iface->ifa_next) {
    sa_family_t family = g_iface->ifa_addr->sa_family;
    fprintf(stderr, "name: %s, family: %d, address ", g_iface->ifa_name, family);
    HIP_DEBUG_SOCKADDR(NULL, g_iface->ifa_addr);
  }

  /* if_nameindex */

  printf("===nameindex===\n");
  i_ifaces = if_nameindex();
  for (i_iface = i_ifaces; i_iface->if_index; i_iface++) {
    fprintf(stderr, "name: %s index: %d\n", i_iface->if_name, i_iface->if_index);
  }

 out:

  if (g_ifaces)
    freeifaddrs(g_ifaces);
  if (i_ifaces)
    if_freenameindex(i_ifaces);
}

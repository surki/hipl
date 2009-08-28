#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include "chord.h"

/* join: Send join messages to hosts in file */
void join(Server *srv, FILE *fp)
{
    char addr[100], *p;
    struct hostent *hp;

    // printf("join\n");
    while (nknown < MAX_WELLKNOWN && fscanf(fp, " %s\n", addr) == 1) {
        p = strchr(addr, ':');
	printf("addr=%s\n", addr);
        assert(p != NULL);
	*(p++) = '\0';

	/* resolve address */	
	hp = gethostbyname(addr);
	if (hp == NULL)
	    eprintf("gethostbyname(%s) failed:", addr);

	well_known[nknown].addr = ntohl(*((in_addr_t *) hp->h_addr));
	well_known[nknown].port = (in_port_t) atoi(p);
	nknown++;
    }

    if (nknown == 0)
        printf("Didn't find any known hosts.");
       // eprintf("Didn't find any known hosts."); xxxx

    chord_update_range(&srv->node.id, &srv->node.id);
    set_stabilize_timer();
    stabilize(srv);
}

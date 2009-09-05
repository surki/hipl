/**
 * Some of the code is from OpenHIP hip_netlink.c
 *
 */
 
#include "netdev.h"
#include "maintenance.h"
#include "libdht/libhipopendht.h"
#include "debug.h"
#include "libinet6/util.h"
#include "libhipcore/hipconf.h"
#include <netinet/in.h>

/**
 * We really don't expect more than a handfull of interfaces to be on
 * our white list.
 */
#define HIP_NETDEV_MAX_WHITE_LIST 5

extern struct addrinfo *opendht_serving_gateway;
extern struct addrinfo *opendht_serving_port;


/**
 * This is the white list. For every interface, which is in our white list,
 * this array has a fixed size, because there seems to be no need at this
 * moment to deal with dynamic memory - which would complicate the code
 * and cost size and performance at least equal if not more to this fixed
 * size array.
 * Free slots are signaled by the value -1.
 */
static int hip_netdev_white_list[HIP_NETDEV_MAX_WHITE_LIST];
static int hip_netdev_white_list_count=0;

static void hip_netdev_white_list_add_index(int if_index)
{
	if(hip_netdev_white_list_count<HIP_NETDEV_MAX_WHITE_LIST)
		hip_netdev_white_list[hip_netdev_white_list_count++]=if_index;
	else
		/* We should NEVER run out of white list slots!!! */
		HIP_DIE("Error: ran out of space for white listed interfaces!\n");
}

int hip_netdev_is_in_white_list(int if_index)
{
	int i=0;
	for(i=0;i<hip_netdev_white_list_count;i++)
		if(hip_netdev_white_list[i]==if_index)
			return 1;
	return 0;
}

int hip_netdev_white_list_add(char* device_name)
{
	struct ifreq ifr = {0};
   int sock = 0;
	int ret=0;


   ifr.ifr_ifindex = -1;
   strncpy(ifr.ifr_name,device_name,(size_t)IFNAMSIZ);
   sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

   if(ioctl(sock, SIOCGIFINDEX, &ifr)==0){
		ret=1;
		hip_netdev_white_list_add_index(ifr.ifr_ifindex);
		HIP_DEBUG("Adding device <%s> to white list with index <%i>.\n",
				device_name,
				ifr.ifr_ifindex);
	}else{
		ret=0;
	}
   
   close(sock);
	return ret;
}


unsigned long hip_netdev_hash(const void *ptr) {
	struct netdev_address *na = (struct netdev_address *) ptr;
	uint8_t hash[HIP_AH_SHA_LEN];

	hip_build_digest(HIP_DIGEST_SHA1, &na->addr,
			 sizeof(struct sockaddr_storage), hash);

	return *((unsigned long *) hash);
}

int hip_netdev_match(const void *ptr1, const void *ptr2) {
	return hip_netdev_hash(ptr1) != hip_netdev_hash(ptr2);
}

static int count_if_addresses(int ifindex)
{
	struct netdev_address *na;
	hip_list_t *n, *t;
	int i = 0, c;

	list_for_each_safe(n, t, addresses, c) {
		na = list_entry(n);
		if (na->if_index == ifindex)
			i++;
	}
	return i;
}


#define FA_IGNORE 0
#define FA_ADD 1

/**
 * Filters addresses that are allowed for this host.
 * 
 * @param addr a pointer to a socket address structure.
 * @return     FA_ADD if the given address @c addr is allowed to be one of the
 *             addresses of this host, FA_IGNORE otherwise.
 */
int filter_address(struct sockaddr *addr)
{
	char s[INET6_ADDRSTRLEN];
	struct in6_addr *a_in6 = NULL;
	in_addr_t a_in;
	
	switch (addr->sa_family) {
	case AF_INET6:
	        a_in6 = hip_cast_sa_addr(addr);
		inet_ntop(AF_INET6, &((struct sockaddr_in6*)addr)->sin6_addr, s,
			  INET6_ADDRSTRLEN);
				
		HIP_DEBUG("IPv6 address to filter is %s.\n", s);
		
		_HIP_DEBUG("Address is%san Teredo address\n", 
			  ipv6_addr_is_teredo(a_in6)==1?" ":" not ");
		
		if(suppress_af_family == AF_INET) {
			HIP_DEBUG("Address ignored: address family "\
				  "suppression set to IPv4 addresses.\n");
			return FA_IGNORE;
		} else if (IN6_IS_ADDR_UNSPECIFIED(a_in6)) {
			HIP_DEBUG("Address ignored: UNSPECIFIED.\n");
			return FA_IGNORE;
		} else if (IN6_IS_ADDR_LOOPBACK(a_in6)) {
			HIP_DEBUG("Address ignored: IPV6_LOOPBACK.\n");
			return FA_IGNORE;
		} else if (IN6_IS_ADDR_MULTICAST(a_in6)) {
			HIP_DEBUG("Address ignored: MULTICAST.\n");
			return FA_IGNORE;
		} else if (IN6_IS_ADDR_LINKLOCAL(a_in6)) {
			HIP_DEBUG("Address ignored: LINKLOCAL.\n");
			return FA_IGNORE;
#if 0 /* For Juha-Matti's experiments  */
		} else if (IN6_IS_ADDR_SITELOCAL(a_in6)) {
			HIP_DEBUG("Address ignored: SITELOCAL.\n");
			return FA_IGNORE;
#endif
		} else if (IN6_IS_ADDR_V4MAPPED(a_in6)) {
			HIP_DEBUG("Address ignored: V4MAPPED.\n");
			return FA_IGNORE;
		} else if (IN6_IS_ADDR_V4COMPAT(a_in6)) {
			HIP_DEBUG("Address ignored: V4COMPAT.\n");
			return FA_IGNORE;
		} else if (ipv6_addr_is_hit(a_in6)) {
			HIP_DEBUG("Address ignored: address is HIT.\n");
			return FA_IGNORE;
		} else
			return FA_ADD;
		break;
		
	case AF_INET:
		a_in = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
		inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, s,
			  INET6_ADDRSTRLEN);
		
		HIP_DEBUG("IPv4 address to filter is %s.\n", s);

		if(suppress_af_family == AF_INET6) {
			HIP_DEBUG("Address ignored: address family "\
				  "suppression set to IPv6 addresses.\n");
			return FA_IGNORE;
		} else if (a_in == INADDR_ANY) {
			HIP_DEBUG("Address ignored: INADDR_ANY.\n");
			return FA_IGNORE;
		} else if (a_in == INADDR_BROADCAST) {
			HIP_DEBUG("Address ignored: INADDR_BROADCAST.\n");
			return FA_IGNORE;
		} else if (IN_MULTICAST(ntohs(a_in))) {
			HIP_DEBUG("Address ignored: MULTICAST.\n");
			return FA_IGNORE;
		} else if (IS_LSI32(a_in)) {
			HIP_DEBUG("Address ignored: LSI32.\n");
			return FA_IGNORE;
		} else if (IS_IPV4_LOOPBACK(a_in)) {
			HIP_DEBUG("Address ignored: IPV4_LOOPBACK.\n");
			return FA_IGNORE;
		} else if (IS_LSI((struct sockaddr_in *)addr)) {
			HIP_DEBUG("Address ignored: address is LSI.\n");
			return FA_IGNORE;
		} else 
			return FA_ADD;
		break;

	default:
		HIP_DEBUG("Address ignored: address family is unknown.\n");
		return FA_IGNORE;
	}
}

int exists_address_family_in_list(struct in6_addr *addr) {
	struct netdev_address *n;
	hip_list_t *tmp, *t;
	int c;
	int mapped = IN6_IS_ADDR_V4MAPPED(addr);

	list_for_each_safe(tmp, t, addresses, c) {
		int map;
		n = list_entry(tmp);
		
		if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)hip_cast_sa_addr(&n->addr)) == mapped)
			return 1;
	}
	
        return 0;
}

int exists_address_in_list(struct sockaddr *addr, int ifindex)
{
	struct netdev_address *n;
	hip_list_t *tmp, *t;
	int c;
        struct in6_addr *in6;
        struct in_addr *in;

	list_for_each_safe(tmp, t, addresses, c) {
		int mapped = 0;
		int addr_match = 0;
		int family_match = 0;
		n = list_entry(tmp);
		
		mapped = hip_sockaddr_is_v6_mapped(&n->addr);
		HIP_DEBUG("mapped=%d\n", mapped);
		
		if (mapped) {
			in6 = (struct in6_addr * )hip_cast_sa_addr(&n->addr);
			in = (struct in_addr *) hip_cast_sa_addr(addr);
			addr_match = IPV6_EQ_IPV4(in6, in);
			family_match = 1;
		} else if (!mapped && addr->sa_family == AF_INET6) {
			addr_match = !memcmp(hip_cast_sa_addr(&n->addr), 
                                             hip_cast_sa_addr(addr),
					     hip_sa_addr_len(&n->addr));
			family_match = (n->addr.ss_family == addr->sa_family);
		} else { // addr->sa_family == AF_INET
			HIP_DEBUG("Addr given was not IPv6 nor IPv4.\n");
		}
		
		HIP_DEBUG("n->addr.ss_family=%d, addr->sa_family=%d, "
                          "n->if_index=%d, ifindex=%d\n",
			  n->addr.ss_family, addr->sa_family, n->if_index, ifindex);
		if (n->addr.ss_family == AF_INET6) {
			HIP_DEBUG_IN6ADDR("addr6", hip_cast_sa_addr(&n->addr));
		} else if (n->addr.ss_family == AF_INET) {
			HIP_DEBUG_INADDR("addr4", hip_cast_sa_addr(&n->addr));
		}
		if (n->if_index == ifindex && family_match && addr_match) {
			HIP_DEBUG("Address exist in the list\n");
			return 1;
		}
	}
	
	HIP_DEBUG("Address exists in the list\n");
	return 0;
}

/**
 * Adds an IPv6 address into ifindex2spi map.
 *
 * Adds an IPv6 address into ifindex2spi map if the address passes
 * filter_address() test.
 *
 * @param  a pointer to a socket address structure.
 * @param  network device interface index.
 */ 
void add_address_to_list(struct sockaddr *addr, int ifindex, int flags)
{
	struct netdev_address *n;
        unsigned char tmp_secret[40];
        int err_rand = 0;
	
	/* filter_address() prints enough debug info of the address, no need to
	   print address related debug info here. */
	if (filter_address(addr)) {
		HIP_DEBUG("Address passed the address filter test.\n");
	} else {
		HIP_DEBUG("Address failed the address filter test.\n");
		return;
	}
	
	if((n = (struct netdev_address *) malloc(sizeof(struct netdev_address)))
	   == NULL) {
		HIP_ERROR("Error when allocating memory to a network device "\
			  "address.\n");
		return;
	}
	
	memset(n, 0, sizeof(struct netdev_address));

	/* Convert IPv4 address to IPv6 */
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in6 temp;
		memset(&temp, 0, sizeof(temp));
		temp.sin6_family = AF_INET6;
		IPV4_TO_IPV6_MAP(&(((struct sockaddr_in *)addr)->sin_addr),
				 &temp.sin6_addr);
	        memcpy(&n->addr, &temp, hip_sockaddr_len(&temp));
	} else {
		memcpy(&n->addr, addr, hip_sockaddr_len(addr));
	}
	
        /* Add secret to address. Used with openDHT removable puts. */        
        memset(tmp_secret, 0, sizeof(tmp_secret));
        err_rand = RAND_bytes(tmp_secret,40);
        memcpy(&n->secret, &tmp_secret, sizeof(tmp_secret));

        /* Clear the timestamp, initially 0 so everything will be sent. */
        memset(&n->timestamp, 0, sizeof(time_t));

        n->if_index = ifindex;
	list_add(n, addresses);
	address_count++;
	n->flags = flags;

	HIP_DEBUG("Added a new IPv6 address to ifindex2spi map. The map has "\
		  "%d addresses.\n", address_count);
}

static void delete_address_from_list(struct sockaddr *addr, int ifindex)
{
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	int i, deleted = 0;
        struct sockaddr_in6 addr_sin6;

        if (addr && addr->sa_family == AF_INET) {
            memset(&addr_sin6, 0, sizeof(addr_sin6));
            addr_sin6.sin6_family = AF_INET6;
            IPV4_TO_IPV6_MAP(((struct in_addr *) hip_cast_sa_addr(addr)),
                             ((struct in6_addr *) hip_cast_sa_addr(&addr_sin6)));
	} else if (addr && addr->sa_family == AF_INET6) {
            memcpy(&addr_sin6, addr, sizeof(addr_sin6));
	}       

        HIP_DEBUG_HIT("Address to delete = ",hip_cast_sa_addr(&addr_sin6));

	list_for_each_safe(item, tmp, addresses, i) {
            n = list_entry(item);
            deleted = 0;
            /* remove from list if if_index matches */
            if (!addr) {
		    if (n->if_index == ifindex) {
			    HIP_DEBUG_IN6ADDR("Deleting address",
					  hip_cast_sa_addr(&n->addr)); 
			    list_del(n, addresses);
			    deleted = 1;
		    }
            } else {
		    /* remove from list if address matches */            
		    _HIP_DEBUG_IN6ADDR("Address to compare",
				      hip_cast_sa_addr(&n->addr)); 
		    if (ipv6_addr_cmp(hip_cast_sa_addr(&n->addr), 
				      hip_cast_sa_addr(&addr_sin6)) == 0) {
			HIP_DEBUG_IN6ADDR("Deleting address",
					  hip_cast_sa_addr(&n->addr)); 
			list_del(n, addresses);
			deleted = 1;
		    }
            }
            if (deleted)
                address_count--;
	}

	if (address_count < 0)
		HIP_ERROR("BUG: address_count < 0\n", address_count);
}

void delete_all_addresses(void)
{
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	int i;

	if (address_count)
	{
		list_for_each_safe(item, tmp, addresses, i)
		{
			n = list_entry(item);
			HIP_DEBUG_HIT("address to be deleted\n",hip_cast_sa_addr(&n->addr));
			list_del(n, addresses);
			HIP_FREE(n);
			address_count--;
		}
		if (address_count != 0) HIP_DEBUG("address_count %d != 0\n", address_count);
	}
}
/**
 * Gets the interface index of a socket address.
 *
 * @param  addr a pointer to a socket address whose interface index is to be
 *              searched.
 * @return      interface index if the network address is bound to one, zero if
 *              no interface index was found.
 */
int hip_netdev_find_if(struct sockaddr *addr)
{
	struct netdev_address *n = NULL;
	hip_list_t *item = NULL, *tmp = NULL;
	int i = 0;

#ifdef CONFIG_HIP_DEBUG /* Debug block. */
	{
		char ipv6_str[INET6_ADDRSTRLEN], *fam_str = NULL;
		
		if(addr->sa_family == AF_INET6) {
			fam_str = "AF_INET6";
			inet_ntop(AF_INET6,
				  &(((struct sockaddr_in6 *)addr)->sin6_addr),
				  ipv6_str, INET6_ADDRSTRLEN);
		} else if(addr->sa_family == AF_INET) {
			fam_str = "AF_INET";
			inet_ntop(AF_INET,
				  &(((struct sockaddr_in *)addr)->sin_addr),
				  ipv6_str, INET6_ADDRSTRLEN);
		} else {
			fam_str = "not AF_INET or AF_INET6";
			memset(ipv6_str, 0, INET6_ADDRSTRLEN);
		}
		
		HIP_DEBUG("Trying to find interface index for a network "\
			  "device with IP address %s of address family %s.\n",
			  ipv6_str, fam_str);
	}
#endif
	/* Loop through all elements in list "addresses" and break if the loop
	   address matches the search address. The "addresses" list stores
	   socket address storages. */
	list_for_each_safe(item, tmp, addresses, i)
		{
			n = list_entry(item);
			
			_HIP_DEBUG("Search item address family %s, interface "\
				  "index %d.\n", (n->addr.ss_family == AF_INET)
				  ? "AF_INET" : "AF_INET6", n->if_index);
			_HIP_DEBUG_IN6ADDR("Search item IP address",
					  &(((struct sockaddr_in6 *)
					     &(n->addr))->sin6_addr));
			
			if ((n->addr.ss_family == addr->sa_family) &&
			    ((memcmp(hip_cast_sa_addr(&n->addr),
				     hip_cast_sa_addr(addr),
				     hip_sa_addr_len(addr))==0)) ||
			    IPV6_EQ_IPV4(&(((struct sockaddr_in6 *)
					    &(n->addr))->sin6_addr),
					 &((struct sockaddr_in *)
					   addr)->sin_addr))
			{
				HIP_DEBUG("Matching network device index is "\
					  "%d.\n", n->if_index);
				return n->if_index;
			}
		}

	HIP_DEBUG("No matching network device index found.\n");
	return 0;
}

/**
 * Gets a interface index of a network address.
 * 
 * Base exchange IPv6 addresses need to be put into ifindex2spi map, so we need
 * a function that gets the ifindex of the network device which has the address
 * @c addr.
 *
 * @param  addr a pointer to an IPv6 address whose interface index is to be
 *              searched.
 * @return      interface index if the network address is bound to one, zero if
 *              no interface index was found and negative in error case.
 * @todo        The caller of this should be generalized to both IPv4 and IPv6
 *              so that this function can be removed (tkoponen).
 */
int hip_devaddr2ifindex(struct in6_addr *addr)
{
	struct sockaddr_in6 a;
	a.sin6_family = AF_INET6;
	ipv6_addr_copy(&a.sin6_addr, addr);
	return hip_netdev_find_if((struct sockaddr *)&a);
}

int static add_address(const struct nlmsghdr *h, int len, void *arg)
{
        struct sockaddr_storage ss_addr;
        struct sockaddr *addr = (struct sockaddr*) &ss_addr;

	while (NLMSG_OK(h, len)) {
		struct ifaddrmsg *ifa;
		struct rtattr *rta, *tb[IFA_MAX+1];

		memset(tb, 0, sizeof(tb));
		/* exit this loop on end or error */
		if (h->nlmsg_type == NLMSG_DONE)
		{
			int *done = (int *)arg;
			*done = 1;
			break;
		}

		if (h->nlmsg_type == NLMSG_ERROR)
		{
			HIP_ERROR("Error in Netlink response.\n");
			return -1;
		}

		ifa = NLMSG_DATA(h);
		rta = IFA_RTA(ifa);
		len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));

		if ((ifa->ifa_family != AF_INET) &&
		    (ifa->ifa_family != AF_INET6))
			continue;

		/* parse list of attributes into table
		 * (same as parse_rtattr()) */
		while (RTA_OK(rta, len))
		{
			if (rta->rta_type <= IFA_MAX)
				tb[rta->rta_type] = rta;
			rta = RTA_NEXT(rta,len);
		}

		/* fix tb entry for inet6 */
		if (!tb[IFA_LOCAL])
			tb[IFA_LOCAL] = tb[IFA_ADDRESS];
		if (!tb[IFA_ADDRESS])
			tb[IFA_ADDRESS] = tb[IFA_LOCAL];

		/* save the addresses we care about */
		if (tb[IFA_LOCAL])
		{
			addr->sa_family = ifa->ifa_family;
			memcpy(hip_cast_sa_addr(addr), RTA_DATA(tb[IFA_LOCAL]),
			       RTA_PAYLOAD(tb[IFA_LOCAL]));
			add_address_to_list(addr, ifa->ifa_index, 0);
                                _HIP_DEBUG("ifindex=%d\n", ifa->ifa_index);
		}
		h = NLMSG_NEXT(h, len);
	}

	return 0;
}

/*
 * Note: this creates a new NETLINK socket (via getifaddrs), so this has to be
 * run before the global NETLINK socket is opened. I did not have the time
 * and energy to import all of the necessary functionality from iproute2.
 * -miika
 */
int hip_netdev_init_addresses(struct rtnl_handle *nl)
{
	struct ifaddrs *g_ifaces = NULL, *g_iface = NULL;
	int err = 0, if_index = 0;

	/* Initialize address list */
	HIP_DEBUG("Initializing addresses...\n");
	//INIT_LIST_HEAD(addresses);
	addresses = hip_ht_init(hip_netdev_hash, hip_netdev_match);

	HIP_IFEL(getifaddrs(&g_ifaces), -1,
		 "getifaddrs failed\n");

	for (g_iface = g_ifaces; g_iface; g_iface = g_iface->ifa_next)
	{
		if (!g_iface->ifa_addr)
			continue;
		if (exists_address_in_list(g_iface->ifa_addr, if_index))
			continue;
		HIP_IFEL(!(if_index = if_nametoindex(g_iface->ifa_name)),
			 -1, "if_nametoindex failed\n");
		/* Check if our interface is in the whitelist */
		if ((hip_netdev_white_list_count > 0) && (! hip_netdev_is_in_white_list(if_index)))
			continue;

		add_address_to_list(g_iface->ifa_addr, if_index, 0);
 	}
	
 out_err:
	if (g_ifaces)
		freeifaddrs(g_ifaces);
	return err;
}

/*
 * hip_find_address. Find an IPv4/IPv6 address present in the file /etc/hosts
 * that has as domain name fqdn_str
*/
int hip_find_address(char *fqdn_str, struct in6_addr *res){
        int lineno = 0, err = 0, i;
	struct in6_addr ipv6_dst;
	struct in_addr ipv4_dst;
	char line[500];
	char *temp_str;
	FILE *hosts = NULL;
	List mylist;

        hosts = fopen(HOSTS_FILE, "r");
	
	if (!hosts) {
	        err = -1;
		HIP_ERROR("Failed to open %s \n", HOSTS_FILE);
		goto out_err;
	}

	HIP_DEBUG("Looking up for hostname %s in /etc/hosts\n",fqdn_str);

	while(getwithoutnewline(line, 500, hosts) != NULL ) {
	        lineno++;
		if(strlen(line)<=1) continue; 
		initlist(&mylist);
		extractsubstrings(line, &mylist);
     
		/* find out the fqdn string amongst the Ipv4/Ipv6 addresses - 
		   it's a non-valid ipv6 addr */
		for(i = 0; i<length(&mylist); i++) {
		        if(inet_pton(AF_INET6, getitem(&mylist,i), &ipv6_dst)<1||
			        inet_pton(AF_INET, getitem(&mylist,i), &ipv4_dst)<1){
			        temp_str = getitem(&mylist,i);
				if((strlen(temp_str)==strlen(fqdn_str))&&(strcmp(temp_str,fqdn_str)==0)) {
				        int j;
					for(j=0;j<length(&mylist);j++){
					        if(inet_pton(AF_INET6, getitem(&mylist,j), &ipv6_dst)>0) {
						        HIP_DEBUG("Peer Address found from '/etc/hosts' is %s\n",
								  getitem(&mylist,j));
							memcpy((void *)res,(void *)&ipv6_dst,sizeof(struct in6_addr));
							err = 1;
							goto out_err;
						} else if(inet_pton(AF_INET, getitem(&mylist,j), &ipv4_dst)>0) {
						        HIP_DEBUG("Peer Address found from '/etc/hosts' is %s\n",
								  getitem(&mylist,j));
							IPV4_TO_IPV6_MAP(&ipv4_dst,res);
							err = 1;
							goto out_err;
						}  
					}//for j
				}
			} 
		}//for i
	}
 out_err:
	destroy(&mylist);
	return err;
}

/*this function returns the locator for the given HIT from opendht(lookup)*/
int opendht_get_endpointinfo1(const char *node_hit, void *msg)
{
	int err = -1;
	char dht_locator_last[1024];
	extern int hip_opendht_inuse;
	int locator_item_count = 0;
	struct hip_locator_info_addr_item *locator_address_item = NULL;
	struct in6_addr addr6;
	struct hip_locator *locator ;
	         
#ifdef CONFIG_HIP_OPENDHT
	if (hip_opendht_inuse == SO_HIP_DHT_ON) {
    	memset(dht_locator_last, '\0', sizeof(dht_locator_last));
		HIP_IFEL(hip_opendht_get_key(&handle_hdrr_value, opendht_serving_gateway, node_hit, msg,1), -1, 
			"DHT get in opendht_get_endpoint failed!\n"); 
		inet_pton(AF_INET6, node_hit, &addr6.s6_addr) ; 
		//HDRR verification 
		HIP_IFEL(verify_hdrr((hip_common_t*)msg, &addr6), -1, "HDRR Signature and/or host id verification failed!\n");
               
		locator = hip_get_param((hip_common_t*)msg, HIP_PARAM_LOCATOR);
		locator_item_count = hip_get_locator_addr_item_count(locator);
		if (locator_item_count > 0)
			err = 0;
		}
#endif	/* CONFIG_HIP_OPENDHT */
out_err:
	return(err);
}


/*this function returns the locator for the given HIT from opendht(lookup)*/
int opendht_get_endpointinfo(const char *node_hit, struct in6_addr *addr)
{
	int err = -1;
	char dht_locator_last[1024];
	extern int hip_opendht_inuse;
	int locator_item_count = 0;
	struct hip_locator_info_addr_item *locator_address_item = NULL;
	struct in6_addr addr6, result = {0};
	struct hip_locator *locator;
	char dht_response[HIP_MAX_PACKET] = {0};

#ifdef CONFIG_HIP_OPENDHT
	if (hip_opendht_inuse == SO_HIP_DHT_ON) {
    		memset(dht_locator_last, '\0', sizeof(dht_locator_last));
		HIP_IFEL(hip_opendht_get_key(&handle_hdrr_value,
					opendht_serving_gateway,
					node_hit,
					dht_response,
					1),
			 -1, "DHT get in opendht_get_endpoint failed!\n");
		inet_pton(AF_INET6, node_hit, &addr6.s6_addr);

		//HDRR verification 
		HIP_IFEL(verify_hdrr((struct hip_common_t*)dht_response, &addr6),
			 -1, "HDRR Signature and/or host id verification failed!\n");

		locator = hip_get_param((struct hip_common_t*)dht_response,
					HIP_PARAM_LOCATOR);
		locator_item_count = hip_get_locator_addr_item_count(locator);
		if (locator_item_count > 0)
			err = 0;
			hip_get_suitable_locator_address(
				(struct hip_common *)dht_response, addr);
	}
#endif	/* CONFIG_HIP_OPENDHT */

out_err:
	return(err);
}

int hip_map_id_to_addr(hip_hit_t *hit, hip_lsi_t *lsi, struct in6_addr *addr) {
	int err = -1, skip_namelookup = 0; /* Assume that resolving fails */
    	extern int hip_opendht_inuse;
	hip_hit_t hit2;
	hip_ha_t *ha = NULL;

	HIP_ASSERT(hit || lsi);

	/* Search first from hadb */
	
	if (hit && !ipv6_addr_any(hit))
		ha = hip_hadb_try_to_find_by_peer_hit(hit);
	else
		ha = hip_hadb_try_to_find_by_peer_lsi(lsi);

	if (ha && !ipv6_addr_any(&ha->peer_addr)) {
		ipv6_addr_copy(addr, &ha->peer_addr);
		HIP_DEBUG("Found peer address from hadb, skipping hosts and opendht look up\n");
		err = 0;
		goto out_err;
	}

	/* Try to resolve the HIT or LSI to a hostname from /etc/hip/hosts,
	   then resolve the hostname to an IP, and a HIT or LSI,
	   depending on dst_hit value.
	   If dst_hit is a HIT -> find LSI and hostname
	   If dst_hit is an LSI -> find HIT and hostname
	   The natural place to handle this is either in the getaddrinfo or
	   getendpointinfo function with AI_NUMERICHOST flag set.
	   We can fallback to e.g. DHT search if the mapping is not
	   found from local files.*/

	/* try to resolve HIT to IPv4/IPv6 address by '/etc/hip/hosts' 
	 * and '/etc/hosts' files 	
	 */
	HIP_IFEL(!hip_map_id_to_ip_from_hosts_files(hit, lsi, addr),
		 0, "hip_map_id_to_ip_from_hosts_files succeeded\n");

	if (hit) {
		ipv6_addr_copy(&hit2, hit);
	} else {
		if (hip_map_lsi_to_hit_from_hosts_files(lsi, &hit2))
			skip_namelookup = 1;
	}

	/* Check for 5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net records in DNS */
	if (hip_get_hit_to_ip_status() && !skip_namelookup) {
		HIP_DEBUG("looking for hit-to-ip record in dns\n");
		HIP_DEBUG("operation may take a while..\n");
		//struct in6_addr tmp_in6_addr;
		//struct in6_addr *tmp_in6_addr_ptr = &tmp_in6_addr;
		int res = hip_hit_to_ip(hit, addr);

		if (res==OK) {
			HIP_DEBUG_IN6ADDR("found hit-to-ip addr ", addr);
			err = 0;
			goto out_err;
		}
	}
	
	/* Try to resolve HIT to IPv4/IPv6 address with OpenDHT server */
        if (hip_opendht_inuse == SO_HIP_DHT_ON && !skip_namelookup) {
		char hit_str[INET6_ADDRSTRLEN];    

		memset(hit_str, 0, sizeof(hit_str));
		hip_in6_ntop(&hit2, hit_str);
		_HIP_DEBUG("### HIT STRING ### %s\n", (const char *)hit_str);
                err = opendht_get_endpointinfo((const char *) hit_str, addr);
		_HIP_DEBUG_IN6ADDR("### ADDR ###", addr);
/*
		char *hit_str = NULL;
		//HIP_IFE((!(hit_str = HIP_MALLOC(INET6_ADDRSTRLEN, 0))), -1);
		//memset(hit_str, 0, INET6_ADDRSTRLEN);

		memset(hit_str, 0, sizeof(hit_str));
		hip_in6_ntop(&hit2, hit_str);

		//hit_str =  hip_convert_hit_to_str(hit, NULL);
		HIP_DEBUG("### HIT STRING ### %s\n", (const char *)hit_str);

                err = opendht_get_endpointinfo((const char *) hit_str, addr);
*/
                if (err)
			HIP_DEBUG("Got IP for HIT from DHT err = \n", err);
        }


	HIP_DEBUG_IN6ADDR("Found addr: ", addr);

out_err:
	return err;
	
}

int hip_netdev_trigger_bex(hip_hit_t *src_hit,
			   hip_hit_t *dst_hit,
			   hip_lsi_t *src_lsi,
			   hip_lsi_t *dst_lsi,
			   struct in6_addr *src_addr,
			   struct in6_addr *dst_addr) {
	int err = 0, if_index = 0, is_ipv4_locator,
		reuse_hadb_local_address = 0, ha_nat_mode = hip_nat_status,
        old_global_nat_mode = hip_nat_status;
        in_port_t ha_peer_port = hip_get_peer_nat_udp_port();
	hip_ha_t *entry;
	int is_loopback = 0;
	hip_lsi_t dlsi, slsi;
	struct in6_addr dhit, shit, saddr, dst6_lsi;
	struct in6_addr daddr, ha_match;
	struct sockaddr_storage ss_addr;
	struct sockaddr *addr;
	addr = (struct sockaddr*) &ss_addr;
	int broadcast = 0, shotgun_status_orig;

	/* Make sure that dst_hit is not a NULL pointer */
	hip_copy_in6addr_null_check(&dhit, dst_hit);
	dst_hit = &dhit;
	HIP_DEBUG_HIT("dst hit", dst_hit);

	/* Make sure that src_hit is not a NULL pointer */
	hip_copy_in6addr_null_check(&shit, src_hit);
	if (!src_hit)
		hip_get_default_hit(&shit);
	src_hit = &shit;
	HIP_DEBUG_HIT("src hit", src_hit);

	/* Initialize mapped format of dst lsi before pointer
	   changes just below */
	if (dst_lsi) {
		IPV4_TO_IPV6_MAP(dst_lsi, &dst6_lsi);
	} else {
		memset(&dst6_lsi, 0, sizeof(dst6_lsi));
	}

	/* Make sure that dst_lsi is not a NULL pointer */
	hip_copy_inaddr_null_check(&dlsi, dst_lsi);
	dst_lsi = &dlsi;
	HIP_DEBUG_LSI("dst lsi", dst_lsi);

	/* Make sure that src_lsi is not a NULL pointer */
	hip_copy_inaddr_null_check(&slsi, src_lsi);
	src_lsi = &slsi;
	HIP_DEBUG_LSI("src lsi", src_lsi);

	/* Make sure that dst_addr is not a NULL pointer */
	hip_copy_in6addr_null_check(&daddr, dst_addr);
	dst_addr = &daddr;
	HIP_DEBUG_IN6ADDR("dst addr", dst_addr);

	/* Make sure that src_addr is not a NULL pointer */
	hip_copy_in6addr_null_check(&saddr, src_addr);
	src_addr = &saddr;
	HIP_DEBUG_IN6ADDR("src addr", src_addr);

	/* Only LSIs specified, but no HITs. Try to map LSIs to HITs
	   using hadb or hosts files. */

	if (src_lsi->s_addr && dst_lsi->s_addr && ipv6_addr_any(dst_hit)) {
		entry = hip_hadb_try_to_find_by_pair_lsi(src_lsi, dst_lsi);
		if (entry) {
			/* peer info already mapped because of e.g.
			   hipconf command */
			ipv6_addr_copy(dst_hit, &entry->hit_peer);
			src_hit = &entry->hit_our;
		} else {
			err = hip_map_lsi_to_hit_from_hosts_files(dst_lsi,
								  dst_hit);
			HIP_IFEL(err, -1, "Failed to map LSI to HIT\n");
		}
		if (ipv6_addr_any(src_hit))
			hip_get_default_hit(src_hit);
	}

	HIP_DEBUG_HIT("src hit", src_hit);

	/* Now we should have at least source HIT and destination HIT.
	   Sometimes we get deformed HITs from kernel, skip them */
	HIP_IFEL(!(ipv6_addr_is_hit(src_hit) && ipv6_addr_is_hit(dst_hit) &&
		   hip_hidb_hit_is_our(src_hit) &&
		   hit_is_real_hit(dst_hit)), -1,
		 "Received rubbish from netlink, skip\n");

	/* Existing entry found. No need for peer IP checks */
	entry = hip_hadb_find_byhits(src_hit, dst_hit);
	if (entry && !ipv6_addr_any(&entry->our_addr)) {
		reuse_hadb_local_address = 1;
		goto send_i1;
	}

 fill_dest_addr:

	/* Search for destination HIT if it wasn't specified yet.
	   Assume that look up fails by default. */
	err = 1;
	HIP_DEBUG("No entry found; find first IP matching\n");

#ifdef CONFIG_HIP_I3
	if(hip_get_hi3_status()){
		struct in6_addr lpback = IN6ADDR_LOOPBACK_INIT;
		memcpy(dst_addr, &lpback, sizeof(struct in6_addr));
		err = 0;
	}
#endif

	if (err && !ipv6_addr_any(dst_addr)) {
			/* Destination address given; no need to look up */
			err = 0;
	}
	
	/* Map peer address to loopback if hit is ours  */
	if (err && hip_hidb_hit_is_our(dst_hit)) {
		struct in6_addr lpback = IN6ADDR_LOOPBACK_INIT;
		ipv6_addr_copy(dst_addr, &lpback);
		ipv6_addr_copy(src_addr, &lpback);
		is_loopback = 1;
		reuse_hadb_local_address = 1;
		err = 0;
	}

        /* Look up peer ip from hadb entries */
	if (err) {
		/* Search HADB for existing entries */
		entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);
		if (entry) {
			HIP_DEBUG_IN6ADDR("reusing HA",
					  &entry->peer_addr);
			ipv6_addr_copy(dst_addr, &entry->peer_addr);
			ha_peer_port = entry->peer_udp_port;
			ha_nat_mode = entry->nat_mode;
			err = 0;
		}
	}

	/* Try to look up peer ip from hosts and opendht */
	if (err) {
	        err = hip_map_id_to_addr(dst_hit, dst_lsi, dst_addr);
	}

	/* No peer address found; set it to broadcast address
	   as a last resource */
	if (err) {
		struct in_addr bcast = { INADDR_BROADCAST };
		/* IPv6 multicast (see bos.c) failed to bind() to link local,
		   so using IPv4 here -mk */
		HIP_DEBUG("No information of peer found, trying broadcast\n");
		broadcast = 1;
		shotgun_status_orig = hip_shotgun_status;
		hip_shotgun_status = SO_HIP_SHOTGUN_ON;
		IPV4_TO_IPV6_MAP(&bcast, dst_addr);
		err = 0;
	}

        /* Next, create state into HADB. Make sure that we choose the right
	   NAT mode and source IP address in case there was some related HAs
	   with the peer that gave use hints on the best NAT mode or source
	   address. */

	/* @fixme: changing global state won't work with threads */
	hip_nat_status = ha_nat_mode;
		
	/* To make it follow the same route as it was doing before HDRR/loactors */
	HIP_IFEL(hip_hadb_add_peer_info(dst_hit, dst_addr,
					dst_lsi, NULL), -1,
		 "map failed\n");

        /* restore nat status */
	hip_nat_status = old_global_nat_mode;
	
        HIP_IFEL(!(entry = hip_hadb_find_byhits(src_hit, dst_hit)), -1,
		 "Internal lookup error\n");

        if (is_loopback)
		ipv6_addr_copy(&entry->our_addr, src_addr);
	
	/* Preserve NAT status with peer */
	entry->peer_udp_port = ha_peer_port;
	entry->nat_mode = ha_nat_mode;

	reuse_hadb_local_address = 1;

send_i1:

	if (entry->hip_msg_retrans.buf == NULL) {
		HIP_DEBUG("Expired retransmissions, sending i1\n");
	} else {
		HIP_DEBUG("I1 was already sent, ignoring\n");
		goto out_err;
	}

	is_ipv4_locator = IN6_IS_ADDR_V4MAPPED(&entry->peer_addr);

	memset(addr, 0, sizeof(struct sockaddr_storage));
	addr->sa_family = (is_ipv4_locator ? AF_INET : AF_INET6);

	if (!reuse_hadb_local_address && src_addr) {
		ipv6_addr_copy(&entry->our_addr, src_addr);
	}

	memcpy(hip_cast_sa_addr(addr), &entry->our_addr,
	       hip_sa_addr_len(addr));

	HIP_DEBUG_HIT("our hit", &entry->hit_our);
        HIP_DEBUG_HIT("peer hit", &entry->hit_peer);
	HIP_DEBUG_IN6ADDR("peer locator", &entry->peer_addr);
	HIP_DEBUG_IN6ADDR("our locator", &entry->our_addr);

	if_index = hip_devaddr2ifindex(&entry->our_addr);
	HIP_IFEL((if_index < 0), -1, "if_index NOT determined\n");
        /* we could try also hip_select_source_address() here on failure,
	   but it seems to fail too */

	HIP_DEBUG("Using ifindex %d\n", if_index);

	//add_address_to_list(addr, if_index /*acq->sel.ifindex*/);
 
	HIP_IFEL(hip_send_i1(&entry->hit_our, &entry->hit_peer, entry), -1,
		 "Sending of I1 failed\n");

out_err:
	if (broadcast)
		hip_shotgun_status = shotgun_status_orig;

	return err;
}

int hip_netdev_handle_acquire(const struct nlmsghdr *msg) {
	hip_hit_t *src_hit = NULL, *dst_hit = NULL;
	hip_lsi_t *src_lsi = NULL, *dst_lsi = NULL;
	struct in6_addr saddr, *src_addr = NULL, *dst_addr = NULL;
	struct xfrm_user_acquire *acq;
	hip_ha_t *entry;
	int err = 0;

	HIP_DEBUG("Acquire (pid: %d) \n", msg->nlmsg_pid);

	acq = (struct xfrm_user_acquire *)NLMSG_DATA(msg);
	src_hit = (hip_hit_t *) &acq->sel.saddr;
	dst_hit = (hip_hit_t *) &acq->sel.daddr;

	HIP_DEBUG_HIT("src HIT", src_hit);
	HIP_DEBUG_HIT("dst HIT", dst_hit);
	HIP_DEBUG("acq->sel.ifindex=%d\n", acq->sel.ifindex);
	
	entry = hip_hadb_find_byhits(src_hit, dst_hit);

	if (entry) {
		HIP_IFEL((entry->state == HIP_STATE_ESTABLISHED), 0,
			"State established, not triggering bex\n");

	        src_lsi = &(entry->lsi_our);
	        dst_lsi = &(entry->lsi_peer);
	}

	err = hip_netdev_trigger_bex(src_hit, dst_hit, src_lsi, dst_lsi, src_addr, dst_addr);

 out_err:

	return err;
}

int hip_netdev_trigger_bex_msg(struct hip_common *msg) {
	hip_hit_t *our_hit = NULL, *peer_hit = NULL;
	struct in6_addr *our_lsi6 = NULL, *peer_lsi6 = NULL;
	hip_lsi_t our_lsi, peer_lsi;
	struct in6_addr *our_addr = NULL, *peer_addr = NULL;
	struct hip_tlv_common *param;
	hip_ha_t *entry = NULL;
	struct hip_locator *locator = NULL;
	int err = 0, locator_item_count = 0, i;
	struct hip_locator_info_addr_item *locator_address_item = NULL;
	
	HIP_DUMP_MSG(msg);
	
	memset(&peer_lsi, 0, sizeof(peer_lsi));
	memset(&our_lsi, 0, sizeof(our_lsi));

	/* Destination HIT - mandatory*/
	param = hip_get_param(msg, HIP_PARAM_HIT);
	if (param && hip_get_param_type(param) == HIP_PARAM_HIT)
		peer_hit = hip_get_param_contents_direct(param);
	
	if (ipv6_addr_is_null(peer_hit))
	        peer_hit = NULL;
	else
	  HIP_DEBUG_HIT("trigger_msg_peer_hit:", peer_hit);
	
	/* Source HIT */
	param = hip_get_next_param(msg, param);
	if (param && hip_get_param_type(param) == HIP_PARAM_HIT)
		our_hit = hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("trigger_msg_our_hit:", our_hit);

	if (ipv6_addr_is_null(our_hit))
	        peer_hit = NULL;
	else
	  HIP_DEBUG_HIT("trigger_msg_peer_hit:", our_hit);
	
	/* Peer LSI */
	param = hip_get_param(msg, HIP_PARAM_LSI);
	if (param){
		peer_lsi6 = hip_get_param_contents_direct(param);
		if (IN6_IS_ADDR_V4MAPPED(peer_lsi6)){
		        IPV6_TO_IPV4_MAP(peer_lsi6, &peer_lsi);	
		        HIP_DEBUG_LSI("trigger_msg_peer_lsi:", &peer_lsi);	
		}
	}

	// @todo: check if peer lsi is all zeroes?

	/* Local LSI */
	param = hip_get_next_param(msg, param);
	if (param && hip_get_param_type(param) == HIP_PARAM_LSI){
		our_lsi6 = hip_get_param_contents_direct(param);
		if (IN6_IS_ADDR_V4MAPPED(our_lsi6))
		        IPV6_TO_IPV4_MAP(our_lsi6, &our_lsi);
	}
	HIP_DEBUG_LSI("trigger_msg_our_lsi:", &our_lsi);

	// @todo: check if local lsi is all zeroes?

	/* Destination IP */
	param = hip_get_param(msg, HIP_PARAM_IPV6_ADDR);
	if (param)
		peer_addr = hip_get_param_contents_direct(param);

        /* Source IP */
        param = hip_get_next_param(msg, param);
        if (param && hip_get_param_type(param) == HIP_PARAM_IPV6_ADDR)
		our_addr = hip_get_param_contents_direct(param);
	
	HIP_DEBUG_IN6ADDR("trigger_msg_our_addr:", our_addr);
	
	locator = hip_get_param((hip_common_t*)msg, HIP_PARAM_LOCATOR);
	if (locator) {
		locator_address_item = hip_get_locator_first_addr_item(locator);
		locator_item_count = hip_get_locator_addr_item_count(locator);
	}

	/* For every address found in the locator of Peer HDRR
	 * Add it to the HADB. It stores first to some temp location in entry
	 * and then copies it to the SPI Out's peer addr list, ater BE */
	if (locator_item_count > 0) {
		for (i = 0; i < locator_item_count ; i++) {
			struct in6_addr dht_addr;
			memcpy(&dht_addr, 
			       (struct in6_addr*) &locator_address_item[i].address, 
			       sizeof(struct in6_addr));
			HIP_IFEL(hip_hadb_add_peer_info(peer_hit, &dht_addr,
							&peer_lsi, NULL), -1,
				 "map failed\n");
		}
	}			
	
	err = hip_netdev_trigger_bex(our_hit, peer_hit,
				     &our_lsi, &peer_lsi,
				     our_addr, peer_addr);
	
 out_err:
  	return err;
}

int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg)
{
     int err = 0, l = 0, is_add=0, i=0, ii=0;
	struct ifinfomsg *ifinfo; /* link layer specific message */
	struct ifaddrmsg *ifa; /* interface address message */
	struct rtattr *rta = NULL, *tb[IFA_MAX+1];
	struct sockaddr_storage ss_addr;
	struct sockaddr *addr;
        struct hip_locator *loc;
	struct hip_locator_addr_item *locators;
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	int pre_if_address_count;
        struct hip_common * locator_msg;

	addr = (struct sockaddr*) &ss_addr;

	for (; NLMSG_OK(msg, (u32)len);
	     msg = NLMSG_NEXT(msg, len))
	{
		int ifindex, addr_exists;
		ifinfo = (struct ifinfomsg*)NLMSG_DATA(msg);
		ifindex = ifinfo->ifi_index;


		HIP_DEBUG("handling msg type %d ifindex=%d\n",
			  msg->nlmsg_type, ifindex);
		switch(msg->nlmsg_type)
		{
		case RTM_NEWLINK:
			HIP_DEBUG("RTM_NEWLINK\n");
			/* wait for RTM_NEWADDR to add addresses */
			break;
		case RTM_DELLINK:
			HIP_DEBUG("RTM_DELLINK\n");
			//ifinfo = (struct ifinfomsg*)NLMSG_DATA(msg);
			//delete_address_from_list(NULL, ifinfo->ifi_index);
			//delete_address_from_list(NULL, ifindex);
			/* should do here
			   hip_send_update_all(NULL, 0, ifindex, SEND_UPDATE_REA);
			   but ifconfig ethX down never seems to come here
			*/
			break;
			/* Add or delete address from addresses */
		case RTM_NEWADDR:
		case RTM_DELADDR:
			HIP_DEBUG("RTM_NEWADDR/DELADDR\n");
			ifa = (struct ifaddrmsg*)NLMSG_DATA(msg);
			rta = IFA_RTA(ifa);
			l = msg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));

			/* Check if our interface is in the whitelist */
			if ((hip_netdev_white_list_count > 0) && ( ! hip_netdev_is_in_white_list(ifindex)))
				continue;

			if ((ifa->ifa_family != AF_INET) &&
			    (ifa->ifa_family != AF_INET6))
				continue;

			memset(tb, 0, sizeof(tb));
			memset(addr, 0, sizeof(struct sockaddr_storage));
			is_add = ((msg->nlmsg_type == RTM_NEWADDR) ? 1 : 0);

			/* parse list of attributes into table
			 * (same as parse_rtattr()) */
			while (RTA_OK(rta, l))
			{
				if (rta->rta_type <= IFA_MAX)
					tb[rta->rta_type] = rta;
				rta = RTA_NEXT(rta, l);
			}
			/* fix tb entry for inet6 */
			if (!tb[IFA_LOCAL])
				tb[IFA_LOCAL] = tb[IFA_ADDRESS];
			if (!tb[IFA_ADDRESS])
				tb[IFA_ADDRESS] = tb[IFA_LOCAL];

			if (!tb[IFA_LOCAL])
				continue;
			addr->sa_family = ifa->ifa_family;
			memcpy(hip_cast_sa_addr(addr), RTA_DATA(tb[IFA_LOCAL]),
			       RTA_PAYLOAD(tb[IFA_LOCAL]) );
			HIP_DEBUG("Address event=%s ifindex=%d\n",
				  is_add ? "add" : "del", ifa->ifa_index);

                        if (addr->sa_family == AF_INET)
                                HIP_DEBUG_LSI("Addr", hip_cast_sa_addr(addr));
                        else if (addr->sa_family == AF_INET6)
                                HIP_DEBUG_HIT("Addr", hip_cast_sa_addr(addr));
                        else
                                HIP_DEBUG("Unknown addr family in addr\n");

			/* update our address list */
			pre_if_address_count = count_if_addresses(ifa->ifa_index);
			HIP_DEBUG("%d addr(s) in ifindex %d before add/del\n",
				  pre_if_address_count, ifa->ifa_index);

			addr_exists = exists_address_in_list(addr,
							     ifa->ifa_index);
			HIP_DEBUG("is_add=%d, exists=%d\n", is_add, addr_exists);
			if ((is_add && addr_exists) ||
			    (!is_add && !addr_exists))
			{
				/* radvd can try to add duplicate addresses.
				   This can confused our address cache. */
				HIP_DEBUG("Address %s discarded.\n",
					  (is_add ? "add" : "del"));
				return 0;
			}

			if (is_add) {
			  add_address_to_list(addr, ifa->ifa_index, 0);
			} else {
				delete_address_from_list(addr, ifa->ifa_index);
				// hip_for_each_ha();
			}

			i = count_if_addresses(ifa->ifa_index);
       
			HIP_DEBUG("%d addr(s) in ifindex %d\n", i, ifa->ifa_index);

			/* handle HIP readdressing */

			/* Should be counted globally over all interfaces 
			   because they might have addresses too --Samu BUGID 663 */
			/*
			  if (i == 0 && pre_if_address_count > 0 &&
			    msg->nlmsg_type == RTM_DELADDR) {
			*/
			if (address_count == 0 && pre_if_address_count > 0 &&
			    msg->nlmsg_type == RTM_DELADDR) {
				/* send 0-address REA if this was deletion of
				   the last address */
				HIP_DEBUG("sending 0-addr UPDATE\n");
				hip_send_update_all(NULL, 0, ifa->ifa_index,
						    SEND_UPDATE_LOCATOR, is_add, addr);
				
				goto out_err;
			} 
			/* Looks like this is not needed or can anyone 
			   tell me how to get to this situation --Samu
			else if (i == 0)
			{
				HIP_DEBUG("no need to readdress\n");
				goto skip_readdr;
		}
			*/
                        /* Locator_msg is just a container for building */
                        locator_msg = malloc(HIP_MAX_PACKET);
                        HIP_IFEL(!locator_msg, -1, "Failed to malloc locator_msg\n");
                        hip_msg_init(locator_msg);                                
                        HIP_IFEL(hip_build_locators(locator_msg, 0, hip_get_nat_mode(NULL)), -1, 
                                 "Failed to build locators\n");
                        HIP_IFEL(hip_build_user_hdr(locator_msg, 
                                                    SO_HIP_SET_LOCATOR_ON, 0), -1,
                                 "Failed to add user header\n");
                        loc = hip_get_param(locator_msg, HIP_PARAM_LOCATOR);
			hip_print_locator_addresses(locator_msg);
			locators = hip_get_locator_first_addr_item(loc);
			/* this is changed to address count because the i contains
			   only one interface we can have multiple and global count
			   is zero if last is deleted */
                        HIP_DEBUG("UPDATE to be sent contains %i addr(s)\n", address_count);
                        hip_send_update_all(locators, address_count,
                                            ifa->ifa_index, 
                                            SEND_UPDATE_LOCATOR, is_add, addr);
                        if (hip_locator_status == SO_HIP_SET_LOCATOR_ON)
                                hip_recreate_all_precreated_r1_packets();    
                        if (locator_msg)
				free(locator_msg);
                        break;
		case XFRMGRP_ACQUIRE:
			/* XX TODO  does this ever happen? */
			HIP_DEBUG("\n");
			return -1;
			break;
		case XFRMGRP_EXPIRE:
			HIP_DEBUG("received expiration, ignored\n");
			return 0;
			break;
#if 0
		case XFRMGRP_SA:
			/* XX TODO  does this ever happen? */
			return -1;
			break;
		case XFRMGRP_POLICY:
			/* XX TODO  does this ever happen? */
			return -1;
			break;
#endif
		case XFRM_MSG_GETSA:
			return -1;
			break;
		case XFRM_MSG_ALLOCSPI:
			return -1;
			break;
		case XFRM_MSG_ACQUIRE:
		        HIP_DEBUG("handled msg XFRM_MSG_ACQUIRE\n");
			return hip_netdev_handle_acquire(msg);
			break;
		case XFRM_MSG_EXPIRE:
			return -1;
			break;
		case XFRM_MSG_UPDPOLICY:
			return -1;
			break;
		case XFRM_MSG_UPDSA:
			return -1;
			break;
		case XFRM_MSG_POLEXPIRE:
			return -1;
			break;
#if 0
		case XFRM_MSG_FLUSHSA:
			return -1;
			break;
		case XFRM_MSG_FLUSHPOLICY:
			return -1;
			break;
#endif
		skip_readdr:
			break;
		default:
			HIP_DEBUG("unhandled msg type %d\n", msg->nlmsg_type);
			break;
		}
	}

 out_err:

	return 0;
}

int hip_add_iface_local_hit(const hip_hit_t *local_hit)
{
	int err = 0;
	char hit_str[INET6_ADDRSTRLEN + 2];
	struct idxmap *idxmap[16] = {0};

	hip_convert_hit_to_str(local_hit, HIP_HIT_PREFIX_STR, hit_str);
	HIP_DEBUG("Adding HIT: %s\n", hit_str);

	HIP_IFE(hip_ipaddr_modify(&hip_nl_route, RTM_NEWADDR, AF_INET6,
				  hit_str, HIP_HIT_DEV, idxmap), -1);

 out_err:

	return err;
}

int hip_add_iface_local_route(const hip_hit_t *local_hit)
{
	int err = 0;
	char hit_str[INET6_ADDRSTRLEN + 2];
	struct idxmap *idxmap[16] = {0};

	hip_convert_hit_to_str(local_hit, HIP_HIT_FULL_PREFIX_STR, hit_str);
	HIP_DEBUG("Adding local HIT route: %s\n", hit_str);
	HIP_IFE(hip_iproute_modify(&hip_nl_route, RTM_NEWROUTE,
				   NLM_F_CREATE|NLM_F_EXCL,
				   AF_INET6, hit_str, HIP_HIT_DEV, idxmap),
		-1);

 out_err:

	return err;
}

int hip_select_source_address(struct in6_addr *src, struct in6_addr *dst)
{
	int err = 0;
	int family = AF_INET6;
//	int rtnl_rtdsfield_init;
//	char *rtnl_rtdsfield_tab[256] = { 0 };
	struct idxmap *idxmap[16] = { 0 };
	struct in6_addr lpback = IN6ADDR_LOOPBACK_INIT;
		
	/* rtnl_rtdsfield_initialize() */
//	rtnl_rtdsfield_init = 1;
	
//	rtnl_tab_initialize("/etc/iproute2/rt_dsfield", rtnl_rtdsfield_tab, 256);

	_HIP_DEBUG_IN6ADDR("Source", src);
	HIP_DEBUG_IN6ADDR("dst", dst);

	/* Required for loopback connections */
	if (!ipv6_addr_cmp(dst, &lpback)) {
		ipv6_addr_copy(src, dst);
		goto out_err;
	}

	HIP_IFEL(!exists_address_family_in_list(dst), -1, "No address of the same family\n");

	if (ipv6_addr_is_teredo(dst)) {
		struct netdev_address *na;
		struct in6_addr *in6;
		hip_list_t *n, *t;
		int c, match = 0;

		list_for_each_safe(n, t, addresses, c) {
			na = list_entry(n);
			in6 = hip_cast_sa_addr(&na->addr);
			if (ipv6_addr_is_teredo(in6)) {
				ipv6_addr_copy(src, in6);
				match = 1;
			}
		}
		HIP_IFEL(!match, -1, "No src addr found for Teredo\n");
	} else  {
		HIP_IFEL(hip_iproute_get(&hip_nl_route, src, dst, NULL, NULL, family, idxmap), -1, "Finding ip route failed\n");
	}

	HIP_DEBUG_IN6ADDR("src", src);

out_err:
	return err;
}

int hip_select_default_router_address(struct in6_addr * addr) {
  int err = 0;
  HIP_DEBUG("Default router");
  
 out_err:
  return err;
}

int hip_get_default_hit(struct in6_addr *hit)
{
	return hip_get_any_localhost_hit(hit, HIP_HI_RSA, 0);
}

int hip_get_default_hit_msg(struct hip_common *msg)
{
	int err = 0;
	hip_hit_t hit;
 	hip_lsi_t lsi;
	
	hip_get_default_hit(&hit);
 	hip_get_default_lsi(&lsi);
	HIP_DEBUG_HIT("Default hit is ", &hit);
 	HIP_DEBUG_LSI("Default lsi is ", &lsi);
	hip_build_param_contents(msg, &hit, HIP_PARAM_HIT, sizeof(hit));
 	hip_build_param_contents(msg, &lsi, HIP_PARAM_LSI, sizeof(lsi));
	
 out_err:
	return err;
}

int hip_get_default_lsi(struct in_addr *lsi)
{
	int err = 0, family = AF_INET, rtnl_rtdsfield_init = 1, i;
	char *rtnl_rtdsfield_tab[256] = { 0 };
	struct idxmap *idxmap[16] = { 0 };
	struct in6_addr lsi_addr;
	struct in6_addr lsi_aux6;
	hip_lsi_t lsi_tmpl;
	
        rtnl_tab_initialize("/etc/iproute2/rt_dsfield",rtnl_rtdsfield_tab, 256);
	memset(&lsi_tmpl, 0, sizeof(lsi_tmpl));
	set_lsi_prefix(&lsi_tmpl);
	IPV4_TO_IPV6_MAP(&lsi_tmpl, &lsi_addr);
	HIP_IFEL(hip_iproute_get(&hip_nl_route, &lsi_aux6, &lsi_addr, NULL,
				 NULL, family, idxmap), -1,
		 "Failed to find IP route.\n");

	if(IN6_IS_ADDR_V4MAPPED(&lsi_aux6))
	        IPV6_TO_IPV4_MAP(&lsi_aux6, lsi);
 out_err:

	for (i = 0; i < 256; i++) {
	    if (rtnl_rtdsfield_tab[i])
		free(rtnl_rtdsfield_tab[i]);
	}

	return err;
}
//get the puzzle difficulty and return result to hipconf
int hip_get_puzzle_difficulty_msg(struct hip_common *msg){
	int err = 0, diff = 0;
	hip_hit_t *dst_hit = NULL;
	hip_hit_t all_zero_hit = {0};

	//obtain the hit
	dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
	
#ifdef CONFIG_HIP_COOKIE
	if(ipv6_addr_cmp(&all_zero_hit, dst_hit) != 0)
		diff = hip_get_cookie_difficulty(dst_hit);
	else{
#endif
		diff = hip_get_cookie_difficulty(NULL);
#ifdef CONFIG_HIP_COOKIE
	}
#endif

	_HIP_DEBUG("Puzzle difficulty is %d\n", diff);
	hip_build_param_contents(msg, &diff, HIP_PARAM_INT, sizeof(diff));
	
 out_err:
	return err;
}


//set the puzzle difficulty acc to msg sent by hipconf
int hip_set_puzzle_difficulty_msg(struct hip_common *msg){
	int err = 0, diff = 0, *newVal = NULL;
	hip_hit_t *dst_hit = NULL;
	hip_hit_t all_zero_hit = {0};

	dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
	newVal = hip_get_param_contents(msg, HIP_PARAM_INT);

#ifdef CONFIG_HIP_COOKIE
	if(ipv6_addr_cmp(&all_zero_hit, dst_hit) != 0)
		hip_set_cookie_difficulty(dst_hit, *newVal);
	else{
#endif
		hip_set_cookie_difficulty(NULL, *newVal);
#ifdef CONFIG_HIP_COOKIE
	}
#endif

out_err:
	return err;
}


/**
 * get the ip mapping from DHT
 * 
 * hipconf dht get <HIT>
 */
int hip_get_dht_mapping_for_HIT_msg(struct hip_common *msg){
	int err = 0, socket, err_value = 0, ret_HIT = 0, ret_HOSTNAME = 0;
	char ip_str[INET_ADDRSTRLEN], hit_str[INET6_ADDRSTRLEN+2], *hostname = NULL;
	hip_hit_t *dst_hit = NULL;
	char dht_response[HIP_MAX_PACKET] = {0};
	hip_tlv_type_t param_type = 0;
	struct hip_tlv_common *current_param = NULL;

#ifdef CONFIG_HIP_OPENDHT
	HIP_DEBUG("\n");

	HIP_IFEL((msg == NULL), -1, "msg null, skip\n");

	current_param = hip_get_next_param(msg, current_param);
	if(current_param)
		param_type = hip_get_param_type(current_param);
	else
		goto out_err;
	if(param_type == HIP_PARAM_HOSTNAME) {
		ret_HOSTNAME = 1;
		//get hostname
		HIP_IFEL(((hostname = hip_get_param(msg, HIP_PARAM_HOSTNAME)) == NULL), -1,
			"hostname null\n");
		hostname = hip_get_param_contents_direct(hostname);
	}else if(param_type == HIP_PARAM_HIT) {
		ret_HIT = 1;
    		HIP_IFEL(((dst_hit = hip_get_param(msg, HIP_PARAM_HIT)) == NULL),
			 -1, "dst hit null\n");
    		dst_hit = hip_get_param_contents_direct(dst_hit);
		hip_convert_hit_to_str(dst_hit, NULL, hit_str);
	}

	//convert hw addr to str
	inet_ntop(AF_INET,
		  &(((struct sockaddr_in*)opendht_serving_gateway->ai_addr)->sin_addr),
		  ip_str,
		  INET_ADDRSTRLEN);

	/* init the dht gw socket */
	socket = init_dht_gateway_socket_gw(socket, opendht_serving_gateway);
	//the connection to the gw here should be done using binding
	err = connect_dht_gateway(socket, opendht_serving_gateway, 1);

	if(err != 0){
		err_value = 1;
		err = 0;
		hip_build_param_contents(msg, &err_value,
					 HIP_PARAM_INT, sizeof(int));
		goto out_err;
	}

	/* obtain value from dht gateway */
	err = 0;

	if(ret_HIT){
		err = opendht_get(socket, (unsigned char *)hit_str,
			  (unsigned char *)ip_str, opendht_serving_gateway_port);
	}
	else if(ret_HOSTNAME){
		err = opendht_get(socket, (unsigned char *)hostname,
			  (unsigned char *)ip_str, opendht_serving_gateway_port);
	}
	//get response from dht server
	err = opendht_read_response(socket, dht_response);

	if(err != 0){
		err_value = 2;
		err = 0;
		hip_build_param_contents(msg, &err_value,
					 HIP_PARAM_INT, sizeof(int));
		goto out_err;
	}

	//attach output to the msg back to hipconf
	hip_attach_locator_addresses((struct hip_common *)dht_response, msg);

out_err:

	close(socket);
#endif	/* CONFIG_HIP_OPENDHT */

	return err;
}

/**
 * attach the reply we got from the dht gateway
 * to the message back to hipconf
 */
void hip_attach_locator_addresses(struct hip_common * in_msg,
				  struct hip_common *msg){
    struct hip_locator *locator;
    int i = 0, err_value = 0;
    unsigned char * tmp = NULL;
    struct hip_locator_info_addr_item *item   = NULL;
    struct hip_locator_info_addr_item2 *item2 = NULL;
    char *address_pointer;
    struct in6_addr reply6;
    struct in6_addr all_zero_ipv6 = {0};
	
    _HIP_DUMP_MSG(in_msg);

    locator = hip_get_param((struct hip_common *)in_msg,
                            HIP_PARAM_LOCATOR);
    if(locator){	
	address_pointer =(char*) (locator + 1);
	for(;address_pointer < ((char*)locator) + hip_get_param_contents_len(locator); ){
	    if(((struct hip_locator_info_addr_item*)address_pointer)->locator_type 
                 == HIP_LOCATOR_LOCATOR_TYPE_UDP){
		item2 = (struct hip_locator_info_addr_item2 *)address_pointer;
		hip_build_param_contents(msg, &item2->address,
					 HIP_PARAM_SRC_ADDR, sizeof(struct in6_addr));
		//HIP_DEBUG_HIT("LOCATOR", (struct in6_addr *)&item2->address);
		address_pointer += sizeof(struct hip_locator_info_addr_item2);
	    }else if(((struct hip_locator_info_addr_item*)address_pointer)->locator_type 
                        == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI){
		item = (struct hip_locator_info_addr_item *)address_pointer;
		hip_build_param_contents(msg, &item->address,
					 HIP_PARAM_SRC_ADDR, sizeof(struct in6_addr));
		//HIP_DEBUG_HIT("LOCATOR", (struct in6_addr *)&item->address);
		address_pointer += sizeof(struct hip_locator_info_addr_item);
	    }else if(((struct hip_locator_info_addr_item*)address_pointer)->locator_type 
                        == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
		item = (struct hip_locator_info_addr_item *)address_pointer;
		hip_build_param_contents(msg, &item->address,
					 HIP_PARAM_SRC_ADDR, sizeof(struct in6_addr));
		//HIP_DEBUG_HIT("LOCATOR", (struct in6_addr *)&item->address);
		address_pointer += sizeof(struct hip_locator_info_addr_item);
	    }else
		address_pointer += sizeof(struct hip_locator_info_addr_item);
	}	
    }else{
	memcpy(&((&reply6)->s6_addr), in_msg, sizeof(reply6.s6_addr));
	//HIP_DEBUG_HIT("LOCATOR", &reply6);
	if(ipv6_addr_cmp(&all_zero_ipv6, &reply6)){
		hip_build_param_contents(msg, &reply6,
					 HIP_PARAM_SRC_ADDR,
					 sizeof(struct in6_addr));
	}else{
		err_value = 3;//Entry not found at DHT gateway
		hip_build_param_contents(msg, &err_value,
					 HIP_PARAM_INT, sizeof(int));
	}
    }
}



/**
choose from addresses obtained from the dht server.
Currently, the latest address, if any, is returned
*/
void hip_get_suitable_locator_address(struct hip_common * in_msg,
				      struct in6_addr *addr){
    struct hip_locator *locator;
    int i = 0, err_value = 0;
    unsigned char * tmp = NULL;
    struct hip_locator_info_addr_item *item   = NULL;
    struct hip_locator_info_addr_item2 *item2 = NULL;
    char *address_pointer;
    struct in6_addr reply6;
    struct in6_addr all_zero_ipv6 = {0};
	
    _HIP_DUMP_MSG(in_msg);

    locator = hip_get_param((struct hip_common *)in_msg,
                            HIP_PARAM_LOCATOR);
    if(locator){	
	address_pointer =(char*) (locator + 1);
	for(;address_pointer < ((char*)locator) + hip_get_param_contents_len(locator); ){
	    if(((struct hip_locator_info_addr_item*)address_pointer)->locator_type 
                 == HIP_LOCATOR_LOCATOR_TYPE_UDP){
		item2 = (struct hip_locator_info_addr_item2 *)address_pointer;

		////hip_build_param_contents(msg, &item2->address,
		////			 HIP_PARAM_SRC_ADDR, sizeof(struct in6_addr));
		HIP_DEBUG_HIT("LOCATOR", (struct in6_addr *)&item2->address);
		memcpy(addr, (struct in6_addr *)&item2->address, sizeof(struct in6_addr));
		address_pointer += sizeof(struct hip_locator_info_addr_item2);
	    }else if(((struct hip_locator_info_addr_item*)address_pointer)->locator_type 
                        == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI){
		item = (struct hip_locator_info_addr_item *)address_pointer;

		////hip_build_param_contents(msg, &item->address,
		////			 HIP_PARAM_SRC_ADDR, sizeof(struct in6_addr));
		HIP_DEBUG_HIT("LOCATOR", (struct in6_addr *)&item->address);
		memcpy(addr, (struct in6_addr *)&item->address, sizeof(struct in6_addr));
		address_pointer += sizeof(struct hip_locator_info_addr_item);
	    }else if(((struct hip_locator_info_addr_item*)address_pointer)->locator_type 
                        == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
		item = (struct hip_locator_info_addr_item *)address_pointer;

		////hip_build_param_contents(msg, &item->address,
		////			 HIP_PARAM_SRC_ADDR, sizeof(struct in6_addr));
		HIP_DEBUG_HIT("LOCATOR", (struct in6_addr *)&item->address);
		memcpy(addr, (struct in6_addr *)&item->address, sizeof(struct in6_addr));
		address_pointer += sizeof(struct hip_locator_info_addr_item);
	    }else
		address_pointer += sizeof(struct hip_locator_info_addr_item);
	}	
    }else{
	memcpy(&((&reply6)->s6_addr), in_msg, sizeof(reply6.s6_addr));
	//HIP_DEBUG_HIT("LOCATOR", &reply6);
	if(ipv6_addr_cmp(&all_zero_ipv6, &reply6)){
		////hip_build_param_contents(msg, &reply6,
		////			 HIP_PARAM_SRC_ADDR,
		////			 sizeof(struct in6_addr));
	}else{
		err_value = 3;//Entry not found at DHT gateway
		////hip_build_param_contents(msg, &err_value,
		////			 HIP_PARAM_INT, sizeof(int));
	}
    }

    HIP_DEBUG_IN6ADDR("####", addr);
}



/* This function copies the addresses stored in entry->peer_addr_list_to_be_added
 * to entry->spi_out->peer_addr_list after R2 has been received
 * @param entry: state after base exchange */
void hip_copy_peer_addrlist_to_spi(hip_ha_t *entry) {
	hip_list_t *item = NULL, *tmp = NULL; 
	struct hip_peer_addr_list_item *addr_li;
	struct hip_spi_out_item *spi_out;
	int i = 0;
	struct hip_spi_out_item *spi_list;

	if (!entry->peer_addr_list_to_be_added)
		return;

	spi_list = hip_hadb_get_spi_list(entry, entry->default_spi_out);

	if (!spi_list)
	{
		HIP_ERROR("did not find SPI list for SPI 0x%x\n", entry->default_spi_out);
		
	}
	list_for_each_safe(item, tmp, entry->peer_addr_list_to_be_added, i) {
			addr_li = list_entry(item);
			list_add(addr_li, spi_list->peer_addr_list);
			HIP_DEBUG_HIT("SPI out address", &addr_li->address);
	}
	hip_ht_uninit(entry->peer_addr_list_to_be_added);
	entry->peer_addr_list_to_be_added = NULL;
	hip_print_peer_addresses (entry);
}

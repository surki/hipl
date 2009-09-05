#ifndef lib_opendht

#define lib_opendht


/* Resolve the gateway address using opendht.nyuld.net */
//#define OPENDHT_GATEWAY "opendht.nyuld.net"
//#define OPENDHT_GATEWAY "hipdht2.infrahip.net"
#define OPENDHT_GATEWAY "193.167.187.134"
#define OPENDHT_PORT 5851
#define OPENDHT_TTL 120
#define STATE_OPENDHT_IDLE 0
#define STATE_OPENDHT_WAITING_ANSWER 1
#define STATE_OPENDHT_WAITING_CONNECT 2
#define STATE_OPENDHT_START_SEND 3
#ifdef ANDROID_CHANGES
#   define OPENDHT_SERVERS_FILE "/data/hip/dhtservers"
#else
#   define OPENDHT_SERVERS_FILE "/etc/hip/dhtservers"
#endif
#define OPENDHT_ERROR_COUNT_MAX 3

int init_dht_gateway_socket_gw(int, struct addrinfo *);

int resolve_dht_gateway_info(char *, struct addrinfo **, in_port_t, int);

int connect_dht_gateway(int, struct addrinfo *, int);

int opendht_put_rm(int, unsigned char *, unsigned char *, 
                   unsigned char *, unsigned char *, int, int);

//int opendht_put(int, unsigned char *, unsigned char *, 
 //               unsigned char *, int, int, struct hip_queue *x);

int opendht_rm(int, unsigned char *, unsigned char *,
               unsigned char *, unsigned char *, int, int);

int opendht_get(int, unsigned char *, unsigned char *, int);

/*int opendht_get_key(struct addrinfo *, const unsigned char *,
		    unsigned char *);
*/
int opendht_handle_key(char *, char *);

int opendht_handle_value(char *, char *);


int opendht_read_response(int, char *);

int (*value_handler)(unsigned char * packet, void * answer);  

int handle_hdrr_value (unsigned char *packet, void *hdrr);
int handle_locator_value (unsigned char *packet, void *locator_ipv4);
int handle_hit_value (unsigned char *packet, void *hit); 
int handle_locator_all_values (unsigned char *packet, void *locator_complete);
int handle_ip_value (unsigned char *packet, void *ip);
int verify_hddr_lib (struct hip_common *hipcommonmsg,struct in6_addr *addrkey);
#endif /* lib_opendht */

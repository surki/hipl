/** @file
 * The HIPL main file containing the daemon main loop.
 *
 * @date 28.01.2008
 * @note Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note HIPU: libm.a is not availble on OS X. The functions are present in libSystem.dyld, though
 * @note HIPU: lcap is used by HIPD. It needs to be changed to generic posix functions.
 */
#include "hipd.h"

/* Defined as a global just to allow freeing in exit(). Do not use outside
   of this file! */
struct hip_common *hipd_msg = NULL;
struct hip_common *hipd_msg_v4 = NULL;

int is_active_handover = 1;  /**< Which handover to use active or lazy? */
int hip_blind_status = 0; /**< Blind status */

/** Suppress advertising of none, AF_INET or AF_INET6 address in UPDATEs.
    0 = none = default, AF_INET, AF_INET6 */
int suppress_af_family = 0;

/* For sending HIP control messages */
int hip_raw_sock_output_v6 = 0;
int hip_raw_sock_output_v4 = 0;

/* For receiving HIP control messages */
int hip_raw_sock_input_v6 = 0;
int hip_raw_sock_input_v4 = 0;

/** File descriptor of the socket used for sending HIP control packet 
 *  NAT traversal on UDP/IPv4 
 */
int hip_nat_sock_output_udp = 0;

/** File descriptor of the socket used for receiving HIP control packet 
 *  NAT traversal on UDP/IPv4 
 */
int hip_nat_sock_input_udp = 0;

/** Specifies the NAT status of the daemon. This value indicates if the current
    machine is behind a NAT. */
hip_transform_suite_t hip_nat_status = 0;

/** ICMPv6 socket and the interval 0 for interval means off **/
int hip_icmp_sock = 0;
int hip_icmp_interval = HIP_NAT_KEEP_ALIVE_INTERVAL;

/** Specifies the HIP PROXY status of the daemon. This value indicates if the HIP PROXY is running. */
int hipproxy = 0;

/*SAVAH modes*/
int hipsava_client = 0;
int hipsava_server = 0;

/* Encrypt host id in I2 */
int hip_encrypt_i2_hi = 0;

/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock = 0;
struct sockaddr_un hip_user_addr;

/** For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec  = { 0 };

/** For getting/setting routes and adding HITs (it was not possible to use
    nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route = { 0 };

int hip_agent_status = 0;

struct sockaddr_in6 hip_firewall_addr;
int hip_firewall_sock = 0;

/* used to change the transform order see hipconf usage to see the usage
   This is set to AES, 3DES, NULL by default see hipconf trasform order for
   more information.
*/
int hip_transform_order = 123;

/* OpenDHT related variables */
int hip_opendht_sock_fqdn = -1; /* FQDN->HIT mapping */
int hip_opendht_sock_hit = -1; /* HIT->IP mapping */
int hip_opendht_fqdn_sent = STATE_OPENDHT_IDLE;
int hip_opendht_hit_sent = STATE_OPENDHT_IDLE;

int opendht_queue_count = 0;
int opendht_error = 0;
char opendht_response[HIP_MAX_PACKET];
struct addrinfo * opendht_serving_gateway = NULL;
int opendht_serving_gateway_port = OPENDHT_PORT;
int opendht_serving_gateway_ttl = OPENDHT_TTL;

struct in6_addr * sava_serving_gateway = NULL;

char opendht_name_mapping[HIP_HOST_ID_HOSTNAME_LEN_MAX]; /* what name should be used as key */
char opendht_host_name[256];

unsigned char opendht_hdrr_secret[40];
hip_common_t * opendht_current_hdrr;
char opendht_current_key[INET6_ADDRSTRLEN + 2];

/* now DHT is always off, so you have to set it on if you want to use it */
int hip_opendht_inuse = SO_HIP_DHT_OFF;
int hip_opendht_error_count = 0; /* Error count, counting errors from libhipopendht */

int hip_buddies_inuse = SO_HIP_BUDDIES_OFF;

/* Tells to the daemon should it build LOCATOR parameters to R1 and I2 */
int hip_locator_status = SO_HIP_SET_LOCATOR_OFF;

/* It tells the daemon to set tcp timeout parameters. Added By Tao Wan, on 09.Jan.2008 */
int hip_tcptimeout_status = SO_HIP_SET_TCPTIMEOUT_ON;

/* Create /etc/hip stuff and exit (used for binary hipfw packaging) */
int create_configs_and_exit = 0;

/* We are caching the IP addresses of the host here. The reason is that during
   in hip_handle_acquire it is not possible to call getifaddrs (it creates
   a new netlink socket and seems like only one can be open per process).
   Feel free to experiment by porting the required functionality from
   iproute2/ip/ipaddrs.c:ipaddr_list_or_flush(). It would make these global
   variable and most of the functions referencing them unnecessary -miika */

int address_count;
HIP_HASHTABLE *addresses;
time_t load_time;

//char *hip_i3_config_file = NULL;
//int hip_use_i3 = 0; // false

/*Define hip_use_userspace_ipsec variable to indicate whether use
 * userspace ipsec or not. If it is 1, hip uses the user space ipsec.
 * It will not use if hip_use_userspace_ipsec = 0. Added By Tao Wan
 */
int hip_use_userspace_ipsec = 0;

int esp_prot_num_transforms = 0;
uint8_t esp_prot_transforms[NUM_TRANSFORMS];

int hip_shotgun_status = SO_HIP_SHOTGUN_ON;

int hip_use_opptcp = 0; // false
int hip_use_hi3    = 0; // false
#ifdef CONFIG_HIP_AGENT
sqlite3 *daemon_db ;
#endif

/* the opp tcp */
void hip_set_opportunistic_tcp_status(struct hip_common *msg){
	struct sockaddr_in6 sock_addr;
	int retry, type, n;

	type = hip_get_msg_type(msg);

	_HIP_DEBUG("type=%d\n", type);

	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;

	for (retry = 0; retry < 3; retry++) {
		/* Switched from hip_sendto() to hip_sendto_user() due to
		   namespace collision. Both message.h and user.c had functions
		   hip_sendto(). Introducing a prototype hip_sendto() to user.h
		   led to compiler errors --> user.c hip_sendto() renamed to
		   hip_sendto_user().

		   Lesson learned: use function prototypes unless functions are
		   ment only for local (inside the same file where defined) use.
		   -Lauri 11.07.2008 */
		n = hip_sendto_user(msg, &sock_addr);
		if (n <= 0) {
			HIP_ERROR("hipconf opptcp failed (round %d)\n", retry);
			HIP_DEBUG("Sleeping few seconds to wait for fw\n");
			sleep(2);
		} else {
			HIP_DEBUG("hipconf opptcp ok (sent %d bytes)\n", n);
			break;
		}
	}

	if (type == SO_HIP_SET_OPPTCP_ON)
		hip_use_opptcp = 1;
	else
		hip_use_opptcp = 0;

	HIP_DEBUG("Opportunistic tcp set %s\n",
		  (hip_use_opptcp ? "on" : "off"));
}

int hip_get_opportunistic_tcp_status(){
        return hip_use_opptcp;
}


/* hi3 */
#ifdef CONFIG_HIP_I3
void hip_set_hi3_status(struct hip_common *msg){
	struct sockaddr_in6 sock_addr;
	int retry, type, n;

	type = hip_get_msg_type(msg);

	_HIP_DEBUG("type=%d\n", type);

	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;

	for (retry = 0; retry < 3; retry++) {
		n = hip_sendto_user(msg, &sock_addr);
		if (n <= 0) {
			HIP_ERROR("hipconf hi3 failed (round %d)\n", retry);
			HIP_DEBUG("Sleeping few seconds to wait for fw\n");
			sleep(2);
		} else {
			HIP_DEBUG("hipconf hi3 ok (sent %d bytes)\n", n);
			break;
		}
	}

	if(type == SO_HIP_SET_HI3_ON){
		hip_i3_init();
		hip_use_hi3 = 1;
		hip_locator_status = SO_HIP_SET_LOCATOR_ON;
	}
	else{
		hip_locator_status = SO_HIP_SET_LOCATOR_OFF;
		hip_hi3_clean();
		hip_use_hi3 = 0;
	}

	HIP_DEBUG("hi3 set %s\n",
		  (hip_use_hi3 ? "on" : "off"));
}

int hip_get_hi3_status(){
        return hip_use_hi3;
}
#endif

void usage() {
  //	fprintf(stderr, "HIPL Daemon %.2f\n", HIPL_VERSION);
        fprintf(stderr, "Usage: hipd [options]\n\n");
	fprintf(stderr, "  -b run in background\n");
	fprintf(stderr, "  -k kill existing hipd\n");
	fprintf(stderr, "  -N do not flush ipsec rules on exit\n");
	fprintf(stderr, "\n");
}

int hip_send_agent(struct hip_common *msg) {
        struct sockaddr_in6 hip_agent_addr;
        int alen;

        memset(&hip_agent_addr, 0, sizeof(hip_agent_addr));
        hip_agent_addr.sin6_family = AF_INET6;
        hip_agent_addr.sin6_addr = in6addr_loopback;
        hip_agent_addr.sin6_port = htons(HIP_AGENT_PORT);

        alen = sizeof(hip_agent_addr);

        return sendto(hip_user_sock, msg, hip_get_msg_total_len(msg), 0,
                       (struct sockaddr *)&hip_agent_addr, alen);
}

/**
 * Receive message from agent socket.
 */
int hip_recv_agent(struct hip_common *msg)
{
	int n, err = 0;
	socklen_t alen;
	hip_hdr_type_t msg_type;
	hip_opp_block_t *entry;
	char hit[40];
	struct hip_uadb_info *uadb_info ;

	HIP_DEBUG("Received a message from agent\n");

	msg_type = hip_get_msg_type(msg);

	if (msg_type == SO_HIP_AGENT_PING)
	{
		memset(msg, 0, HIP_MAX_PACKET);
		hip_build_user_hdr(msg, SO_HIP_AGENT_PING_REPLY, 0);
		n = hip_send_agent(msg);
		HIP_IFEL(n < 0, 0, "sendto() failed on agent socket\n");

		if (err == 0)
		{
			HIP_DEBUG("HIP agent ok.\n");
			if (hip_agent_status == 0)
			{
				hip_agent_status = 1;
				hip_agent_update();
			}
			hip_agent_status = 1;
		}
	}
	else if (msg_type == SO_HIP_AGENT_QUIT)
	{
		HIP_DEBUG("Agent quit.\n");
		hip_agent_status = 0;
	}
	else if (msg_type == HIP_R1 || msg_type == HIP_I1)
	{
		struct hip_common *emsg;
		struct in6_addr *src_addr, *dst_addr;
		hip_portpair_t *msg_info;
		void *reject;

		emsg = hip_get_param_contents(msg, HIP_PARAM_ENCAPS_MSG);
		src_addr = hip_get_param_contents(msg, HIP_PARAM_SRC_ADDR);
		dst_addr = hip_get_param_contents(msg, HIP_PARAM_DST_ADDR);
		msg_info = hip_get_param_contents(msg, HIP_PARAM_PORTPAIR);
		reject = hip_get_param(msg, HIP_PARAM_AGENT_REJECT);

		if (emsg && src_addr && dst_addr && msg_info && !reject)
		{
			HIP_DEBUG("Received accepted I1/R1 packet from agent.\n");
			hip_receive_control_packet(emsg, src_addr, dst_addr, msg_info, 0);
		}
		else if (emsg && src_addr && dst_addr && msg_info)
		{
#ifdef CONFIG_HIP_OPPORTUNISTIC

			HIP_DEBUG("Received rejected R1 packet from agent.\n");
			err = hip_for_each_opp(hip_handle_opp_reject, src_addr);
			HIP_IFEL(err, 0, "for_each_ha err.\n");
#endif
		}
#ifdef CONFIG_HIP_AGENT
		/*Store the accepted HIT info from agent*/
		uadb_info = hip_get_param(msg, HIP_PARAM_UADB_INFO);
		if (uadb_info)
		{
			HIP_DEBUG("Received User Agent accepted HIT info from agent.\n");
			hip_in6_ntop(&uadb_info->hitl, hit);
        	_HIP_DEBUG("Value: %s\n", hit);
        	add_cert_and_hits_to_db(uadb_info);
		}
#endif	/* CONFIG_HIP_AGENT */
	}

out_err:
	return err;
}

#ifdef CONFIG_HIP_AGENT
/**
 * add_cert_and_hits_to_db - Adds information recieved from the agent to
 * the daemon database
 * @param *uadb_info structure containing data sent by the agent
 * @return 0 on success, -1 on failure
 */
int add_cert_and_hits_to_db (struct hip_uadb_info *uadb_info)
{
	int err = 0 ;
	char insert_into[512];
	char hit[40];
	char hit2[40];
	char *file = HIP_CERT_DB_PATH_AND_NAME;

	HIP_IFE(!daemon_db, -1);
	hip_in6_ntop(&uadb_info->hitr, hit);
	hip_in6_ntop(&uadb_info->hitl, hit2);
	_HIP_DEBUG("Value: %s\n", hit);
	sprintf(insert_into, "INSERT INTO hits VALUES("
                        "'%s', '%s', '%s');",
                        hit2, hit, uadb_info->cert);
    err = hip_sqlite_insert_into_table(daemon_db, insert_into);

out_err:
	return (err) ;
}
#endif	/* CONFIG_HIP_AGENT */

int hip_sendto_firewall(const struct hip_common *msg){
#ifdef CONFIG_HIP_FIREWALL
        int n = 0;
	HIP_DEBUG("CONFIG_HIP_FIREWALL DEFINED AND STATUS IS %d\n", hip_get_firewall_status());
	struct sockaddr_in6 hip_firewall_addr;
	socklen_t alen = sizeof(hip_firewall_addr);

	bzero(&hip_firewall_addr, alen);
	hip_firewall_addr.sin6_family = AF_INET6;
	hip_firewall_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	hip_firewall_addr.sin6_addr = in6addr_loopback;

	if (hip_get_firewall_status()) {
	        n = sendto(hip_firewall_sock, msg, hip_get_msg_total_len(msg),
			   0, &hip_firewall_addr, alen);
		return n;
	}
#else
	HIP_DEBUG("Firewall is disabled.\n");
	return 0;
#endif // CONFIG_HIP_FIREWALL
}


/**
 * Daemon main function.
 */
int hipd_main(int argc, char *argv[])
{
	int ch, killold = 0;
	//	char buff[HIP_MAX_NETLINK_PACKET];
	fd_set read_fdset;
        fd_set write_fdset;
	int foreground = 1, highest_descriptor = 0, s_net, err = 0;
	struct timeval timeout;
	struct hip_work_order ping;

	struct msghdr sock_msg;
        /* The flushing is enabled by default. The reason for this is that
	   people are doing some very experimental features on some branches
	   that may crash the daemon and leave the SAs floating around to
	   disturb further base exchanges. Use -N flag to disable this. */
	int flush_ipsec = 1;

	int cc = 0, polling = 0;
	struct msghdr msg;

	/* Parse command-line options */
	while ((ch = getopt(argc, argv, ":bkNch")) != -1)
	{
		switch (ch)
		{
		case 'b':
			foreground = 0;
			break;
		case 'k':
			killold = 1;
			break;
		case 'N':
			flush_ipsec = 0;
			break;
		case 'c':
			create_configs_and_exit = 1;
			break;
		case '?':
		case 'h':
		default:
			usage();
			return err;
		}
	}

	hip_set_logfmt(LOGFMT_LONG);

	/* Configuration is valid! Fork a daemon, if so configured */
	if (foreground)
	{
		hip_set_logtype(LOGTYPE_STDERR);
		HIP_DEBUG("foreground\n");
	}
	else
	{
		hip_set_logtype(LOGTYPE_SYSLOG);
		if (fork() > 0)
			return(0);
	}

	HIP_INFO("hipd pid=%d starting\n", getpid());
	time(&load_time);
	
	/* Default initialman sization function. */
	HIP_IFEL(hipd_init(flush_ipsec, killold), 1, "hipd_init() failed!\n");

	HIP_IFEL(create_configs_and_exit, 0,
		 "Configs created, exiting\n");

	highest_descriptor = maxof(9, hip_nl_route.fd, hip_raw_sock_input_v6,
				   hip_user_sock, hip_nl_ipsec.fd,
				   hip_raw_sock_input_v4, hip_nat_sock_input_udp,
				   hip_opendht_sock_fqdn, hip_opendht_sock_hit,
		                   hip_icmp_sock);

	/* Allocate user message. */
	HIP_IFE(!(hipd_msg = hip_msg_alloc()), 1);
        HIP_IFE(!(hipd_msg_v4 = hip_msg_alloc()), 1);
	HIP_DEBUG("Daemon running. Entering select loop.\n");
	/* Enter to the select-loop */
	HIP_DEBUG_GL(HIP_DEBUG_GROUP_INIT,
		     HIP_DEBUG_LEVEL_INFORMATIVE,
		     "Hipd daemon running.\n"
		     "Starting select loop.\n");
	hipd_set_state(HIPD_STATE_EXEC);
	while (hipd_get_state() != HIPD_STATE_CLOSED)
	{
		/* prepare file descriptor sets */
	        if (hip_opendht_inuse == SO_HIP_DHT_ON) {
                        FD_ZERO(&write_fdset);
                        if (hip_opendht_fqdn_sent == STATE_OPENDHT_WAITING_CONNECT)
                                FD_SET(hip_opendht_sock_fqdn, &write_fdset);
                        if (hip_opendht_hit_sent == STATE_OPENDHT_WAITING_CONNECT)
                                FD_SET(hip_opendht_sock_hit, &write_fdset);
		}
		FD_ZERO(&read_fdset);
		FD_SET(hip_nl_route.fd, &read_fdset);
		FD_SET(hip_raw_sock_input_v6, &read_fdset);
		FD_SET(hip_raw_sock_input_v4, &read_fdset);
		FD_SET(hip_nat_sock_input_udp, &read_fdset);
		FD_SET(hip_user_sock, &read_fdset);
		FD_SET(hip_nl_ipsec.fd, &read_fdset);
		FD_SET(hip_icmp_sock, &read_fdset);
		/* FD_SET(hip_firewall_sock, &read_fdset); */

		if (hip_opendht_fqdn_sent == STATE_OPENDHT_WAITING_ANSWER)
			FD_SET(hip_opendht_sock_fqdn, &read_fdset);
		if (hip_opendht_hit_sent == STATE_OPENDHT_WAITING_ANSWER)
			FD_SET(hip_opendht_sock_hit, &read_fdset);

		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;

		//HIP_DEBUG("select loop value hip_raw_socket_v4 = %d \n",hip_raw_sock_v4);
		/* wait for socket activity */
	
		/* If DHT is on have to use write sets for asynchronic communication */
		if (hip_opendht_inuse == SO_HIP_DHT_ON) 
		{
			err = select((highest_descriptor + 1), &read_fdset,
                                               &write_fdset, NULL, &timeout);
		}
		else
		{
			err = select((highest_descriptor + 1), &read_fdset,
                                               NULL, NULL, &timeout);
		}

		if (err < 0) 
		{
			HIP_ERROR("select() error: %s.\n", strerror(errno));
			goto to_maintenance;
		} else if (err == 0) 
		{
			/* idle cycle - select() timeout */
			_HIP_DEBUG("Idle.\n");
			goto to_maintenance;
		}
                 /* see bugzilla bug id 392 to see why */
                if (FD_ISSET(hip_raw_sock_input_v6, &read_fdset) &&
                    FD_ISSET(hip_raw_sock_input_v4, &read_fdset)) {
                    int type, err_v6 = 0, err_v4 = 0;
                    struct in6_addr saddr, daddr;
                    struct in6_addr saddr_v4, daddr_v4;
                    hip_portpair_t pkt_info;
                    HIP_DEBUG("Receiving messages on raw HIP from IPv6/HIP and IPv4/HIP\n");
                    hip_msg_init(hipd_msg);
                    hip_msg_init(hipd_msg_v4);
                    err_v4 = hip_read_control_msg_v4(hip_raw_sock_input_v4, hipd_msg_v4,
                                                     &saddr_v4, &daddr_v4,
                                                     &pkt_info, IPV4_HDR_SIZE);
                    err_v6 = hip_read_control_msg_v6(hip_raw_sock_input_v6, hipd_msg,
                                                     &saddr, &daddr, &pkt_info, 0);
                    if (err_v4 > -1) {
                        type = hip_get_msg_type(hipd_msg_v4);
                        if (type == HIP_R2) {
				err = hip_receive_control_packet(hipd_msg_v4, &saddr_v4,
                                                             &daddr_v4, &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
                            err = hip_receive_control_packet(hipd_msg, &saddr, &daddr,
                                                             &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
                        } else {
                            err = hip_receive_control_packet(hipd_msg, &saddr, &daddr,
                                                             &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
                            err = hip_receive_control_packet(hipd_msg_v4, &saddr_v4,
                                                             &daddr_v4, &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
                        }
                    }
                } else {
                    if (FD_ISSET(hip_raw_sock_input_v6, &read_fdset)) {
                        /* Receiving of a raw HIP message from IPv6 socket. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;
			HIP_DEBUG("Receiving a message on raw HIP from "\
				  "IPv6/HIP socket (file descriptor: %d).\n",
				  hip_raw_sock_input_v6);
			hip_msg_init(hipd_msg);
			if (hip_read_control_msg_v6(hip_raw_sock_input_v6, hipd_msg,
			                            &saddr, &daddr, &pkt_info, 0)) {
                            HIP_ERROR("Reading network msg failed\n");
			} else {
                            err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
			}
                    }

                    if (FD_ISSET(hip_raw_sock_input_v4, &read_fdset)){
		        HIP_DEBUG("HIP RAW SOCKET\n");
			/* Receiving of a raw HIP message from IPv4 socket. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;
			HIP_DEBUG("Receiving a message on raw HIP from "\
				  "IPv4/HIP socket (file descriptor: %d).\n",
				  hip_raw_sock_input_v4);
			hip_msg_init(hipd_msg);
			HIP_DEBUG("Getting a msg on v4\n");
			/* Assuming that IPv4 header does not include any
			   options */
			if (hip_read_control_msg_v4(hip_raw_sock_input_v4, hipd_msg,
			                            &saddr, &daddr, &pkt_info, IPV4_HDR_SIZE)) {
                            HIP_ERROR("Reading network msg failed\n");
			} else {
                            err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
			}

                    }
                }


		if (FD_ISSET(hip_icmp_sock, &read_fdset))
		{
			HIP_IFEL(hip_icmp_recvmsg(hip_icmp_sock), -1,
				 "Failed to recvmsg from ICMPv6\n");
		}

		if (FD_ISSET(hip_nat_sock_input_udp, &read_fdset))
		{
			/* Data structures for storing the source and
			   destination addresses and ports of the incoming
			   packet. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;

			/* Receiving of a UDP message from NAT socket. */
			HIP_DEBUG("Receiving a message on UDP from NAT "\
				  "socket (file descriptor: %d).\n",
				  hip_nat_sock_input_udp);

			/* Initialization of the hip_common header struct. We'll
			   store the HIP header data here. */
			hip_msg_init(hipd_msg);

			/* Read in the values to hip_msg, saddr, daddr and
			   pkt_info. */
        		/* if ( hip_read_control_msg_v4(hip_nat_sock_udp, hipd_msg,&saddr, &daddr,&pkt_info, 0) ) */
			err = hip_read_control_msg_v4(hip_nat_sock_input_udp, hipd_msg,&saddr, &daddr,&pkt_info, HIP_UDP_ZERO_BYTES_LEN);
			if (err)
			{
                                HIP_ERROR("Reading network msg failed\n");


				/* If the values were read in succesfully, we
				   do the UDP specific stuff next. */
                        }
			else
			{
			   err =  hip_receive_udp_control_packet(hipd_msg, &saddr, &daddr, &pkt_info);
                        }

		}
	
		if (FD_ISSET(hip_user_sock, &read_fdset))
		{
			/* Receiving of a message from user socket. */
			struct sockaddr_storage app_src;

			HIP_DEBUG("Receiving user message.\n");

			hip_msg_init(hipd_msg);
			
			if (hip_read_user_control_msg(hip_user_sock, hipd_msg, &app_src)) {
				HIP_ERROR("Reading user msg failed\n");
			}
			else {
				err = hip_handle_user_msg(hipd_msg, &app_src);
			}
		}
#ifdef CONFIG_HIP_OPENDHT
                /* DHT SOCKETS HANDLING */
                if (hip_opendht_inuse == SO_HIP_DHT_ON && hip_opendht_sock_fqdn != -1) {
                        if (FD_ISSET(hip_opendht_sock_fqdn, &read_fdset) &&
                            FD_ISSET(hip_opendht_sock_fqdn, &write_fdset) &&
                            (hip_opendht_inuse == SO_HIP_DHT_ON)) {
                                /* Error with the connect */
                                HIP_ERROR("Error OpenDHT socket is readable and writable\n");
                        } else if (FD_ISSET(hip_opendht_sock_fqdn, &write_fdset)) {
                                hip_opendht_fqdn_sent = STATE_OPENDHT_START_SEND;
                        }
                        if (FD_ISSET(hip_opendht_sock_fqdn, &read_fdset) &&
                            (hip_opendht_inuse == SO_HIP_DHT_ON)) {
                                /* Receive answer from openDHT FQDN->HIT mapping */
                                if (hip_opendht_fqdn_sent == STATE_OPENDHT_WAITING_ANSWER) {
                                        memset(opendht_response, '\0', sizeof(opendht_response));
                                        opendht_error = opendht_read_response(hip_opendht_sock_fqdn,
                                                                              opendht_response);
                                        if (opendht_error == -1) {
                                                HIP_DEBUG("Put was unsuccesfull \n");
                                                hip_opendht_error_count++;
                                                HIP_DEBUG("DHT error count now %d/%d.\n",
                                                          hip_opendht_error_count, OPENDHT_ERROR_COUNT_MAX);
                                        }
                                        else
                                                HIP_DEBUG("Put was success (FQDN->HIT)\n");

                                        close(hip_opendht_sock_fqdn);
                                        hip_opendht_sock_fqdn = 0;
                                        hip_opendht_sock_fqdn = init_dht_gateway_socket_gw(hip_opendht_sock_fqdn, opendht_serving_gateway);
                                        hip_opendht_fqdn_sent = STATE_OPENDHT_IDLE;
                                        opendht_error = 0;
                                }
                        }
                        if (FD_ISSET(hip_opendht_sock_hit, &read_fdset) &&
                            FD_ISSET(hip_opendht_sock_hit, &write_fdset) &&
                            (hip_opendht_inuse == SO_HIP_DHT_ON)) {
                                /* Error with the connect */
                                HIP_ERROR("Error OpenDHT socket is readable and writable\n");
                        } else if (FD_ISSET(hip_opendht_sock_hit, &write_fdset)) {
                                hip_opendht_hit_sent = STATE_OPENDHT_START_SEND;
                        }
                        if ((FD_ISSET(hip_opendht_sock_hit, &read_fdset)) &&
                            (hip_opendht_inuse == SO_HIP_DHT_ON)) {
                                /* Receive answer from openDHT HIT->IP mapping */
                                if (hip_opendht_hit_sent == STATE_OPENDHT_WAITING_ANSWER) {
                                        memset(opendht_response, '\0', sizeof(opendht_response));
                                        opendht_error = opendht_read_response(hip_opendht_sock_hit,
                                                                              opendht_response);
                                        if (opendht_error == -1) {
                                                HIP_DEBUG("Put was unsuccesfull \n");
                                                hip_opendht_error_count++;
                                                HIP_DEBUG("DHT error count now %d/%d.\n",
                                                          hip_opendht_error_count, OPENDHT_ERROR_COUNT_MAX);
                                        }
                                        else
                                                HIP_DEBUG("Put was success (HIT->IP)\n");
                                        close(hip_opendht_sock_hit);
                                        hip_opendht_sock_hit = 0;
                                        hip_opendht_sock_hit = init_dht_gateway_socket_gw(hip_opendht_sock_hit, opendht_serving_gateway);
                                        hip_opendht_hit_sent = STATE_OPENDHT_IDLE;
                                        opendht_error= 0;
                                }
                        }
                }
#endif	/* CONFIG_HIP_OPENDHT */
                /* END DHT SOCKETS HANDLING */

		if (FD_ISSET(hip_nl_ipsec.fd, &read_fdset))
		{
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink receive\n");
			if (hip_netlink_receive(&hip_nl_ipsec,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		}

		if (FD_ISSET(hip_nl_route.fd, &read_fdset))
		{
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink route receive\n");
			if (hip_netlink_receive(&hip_nl_route,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		}

to_maintenance:
		err = periodic_maintenance();
		if (err)
		{
			HIP_ERROR("Error (%d) ignoring. %s\n", err,
				  ((errno) ? strerror(errno) : ""));
			err = 0;
		}
	}

out_err:
	/* free allocated resources */
	hip_exit(err);

	HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), err);

	return err;
}


int main(int argc, char *argv[])
{
	int err = 0;
	uid_t euid;

	euid = geteuid();
	HIP_IFEL((euid != 0), -1, "hipd must be started as root\n");			// We need to recreate the NAT UDP sockets to bind to the new port.

	HIP_IFE(hipd_main(argc, argv), -1);
	if (hipd_get_flag(HIPD_FLAG_RESTART))
	{
		HIP_INFO(" !!!!! HIP DAEMON RESTARTING !!!!! \n");
		hip_handle_exec_application(0, EXEC_LOADLIB_NONE, argc, argv);
	}

out_err:
	return err;
}


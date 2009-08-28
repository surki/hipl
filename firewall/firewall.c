/** @file
 * HIP Firewall
 *
 * @note: This code is GNU/GPL.
 * @note: HIPU: requires libipq, might need pcap libraries
 */

#include "firewall.h"

/* NOTE: if buffer size is changed, make sure to check
 * 		 the HIP packet size in hip_fw_init_context() */
#define BUFSIZE HIP_MAX_PACKET

int statefulFiltering = 1;
int escrow_active = 0;
int accept_normal_traffic_by_default = 1;
int accept_hip_esp_traffic_by_default =
  HIP_FW_ACCEPT_HIP_ESP_TRAFFIC_BY_DEFAULT;
int system_based_opp_mode = 0;
int log_level = LOGDEBUG_NONE;

int counter = 0;
int hip_proxy_status = 0;
int foreground = 1;
int filter_traffic = HIP_FW_FILTER_TRAFFIC_BY_DEFAULT;
int hip_opptcp = 0;
int hip_userspace_ipsec = 0;
int hip_kernel_ipsec_fallback = 0;
int hip_esp_protection = 0;
int hip_stun = 0;
int hip_lsi_support = 0;
int hip_sava_router = 0;
int hip_sava_client = 0;
int restore_filter_traffic = HIP_FW_FILTER_TRAFFIC_BY_DEFAULT;
int restore_accept_hip_esp_traffic = HIP_FW_ACCEPT_HIP_ESP_TRAFFIC_BY_DEFAULT;

/* Use this to send and receive responses to hipd. Notice that
   firewall_control.c has a separate socket for receiving asynchronous
   messages from hipd (i.e. messages that were not requests from hipfw).
   The two sockets need to be kept separate because the hipfw might
   mistake a an asynchronous message from hipd to an response. The alternative
   to two sockets are sequence numbers but it would have required reworking
   too much of the firewall. -miika
*/
int hip_fw_sock = 0;

/*
 * Use this socket *only* for receiving async messages from hipd
 */
int hip_fw_async_sock = 0;

/* Default HIT - do not access this directly, call hip_fw_get_default_hit() */
struct in6_addr default_hit;

/* We need to have SAVAH IP and HIT*/
struct in6_addr sava_router_hit;
struct in6_addr sava_router_ip;

/*
 * The firewall handlers do not accept rules directly. They should return
 * zero when they transformed packet and the original should be dropped.
 * Non-zero means that there was an error or the packet handler did not
 * know what to do with the packet.
 */
hip_fw_handler_t hip_fw_handler[NF_IP_NUMHOOKS][FW_PROTO_NUM];

extern struct hip_hadb_user_info_state ha_cache;

void print_usage(){
	printf("HIP Firewall\n");
	printf("Usage: hipfw [-f file_name] [-t timeout] [-d|-v] [-F] [-H] [-A] [-b] [-k] [-h]\n");
	printf("      -H = drop all non-HIP traffic (default: accept non-HIP traffic)\n");
	printf("      -A = accept all HIP traffic, still do HIP filtering (default: drop all non-authed HIP traffic)\n");
 	printf("      -F = accept all HIP traffic, deactivate HIP traffic filtering\n");
	printf("      -f file_name = is a path to a file containing firewall filtering rules (default %s)\n",
			HIP_FW_DEFAULT_RULE_FILE);
	printf("      -d = debugging output\n");
	printf("      -v = verbose output\n");
	printf("      -t = timeout for packet capture (default %d secs)\n",
	       HIP_FW_DEFAULT_TIMEOUT);
	printf("      -b = fork the firewall to background\n");
	printf("      -p = run with lowered priviledges. iptables rules will not be flushed on exit\n");
	printf("      -k = kill running firewall pid\n");
	printf("      -l = activate lsi support\n");
 	printf("      -i = switch on userspace ipsec\n");
 	printf("      -I = as -i, also allow fallback to kernel ipsec when exiting hipfw\n");
 	printf("      -e = use esp protection extension (also sets -i)\n");
#if 0
 	printf("      -a = use SAVA HIP (SAVAH) router extension \n");
	printf("      -c = use SAVA HIP (SAVAH) client extention \n");
#endif
 	printf("      -s = stun/ice message support\n");
	printf("      -h = print this help\n");
	printf("      -o = system-based opportunistic mode\n\n");
}

//currently done at all times, rule_management
//delete rule needs checking for state options in

//all chains
void set_stateful_filtering(int v){
	statefulFiltering = 1;
}


int get_stateful_filtering(){
	return statefulFiltering;
}


void set_escrow_active(int active){
	escrow_active = active;
}


int is_escrow_active(){
	return escrow_active;
}

int hip_fw_init_sava_client() {
  int err = 0;
  if (hip_sava_client) {
    HIP_DEBUG(" hip_fw_init_sava_client() \n");
       HIP_IFEL(hip_sava_client_init_all(), -1,
	     "Error initializing SAVA client \n");
       /* IPv4 packets	*/
       system("iptables -I HIPFW-OUTPUT -p tcp ! -d 127.0.0.1 -j QUEUE 2>/dev/null");
       system("iptables -I HIPFW-OUTPUT -p udp ! -d 127.0.0.1 -j QUEUE 2>/dev/null");
       /* IPv6 packets	*/
       system("ip6tables -I HIPFW-OUTPUT -p tcp ! -d ::1 -j QUEUE 2>/dev/null");
       system("ip6tables -I HIPFW-OUTPUT -p udp ! -d ::1 -j QUEUE 2>/dev/null");
  }
out_err:
  return err;
}

void hip_fw_uninit_sava_client() {
  int err = 0;
  if (hip_sava_client) {
   /* IPv4 packets	*/
   system("iptables -D HIPFW-OUTPUT -p tcp ! -d 127.0.0.1 -j QUEUE 2>/dev/null");
   system("iptables -D HIPFW-OUTPUT -p udp ! -d 127.0.0.1 -j QUEUE 2>/dev/null");
   /* IPv6 packets	*/
   system("ip6tables -D HIPFW-OUTPUT -p tcp ! -d ::1 -j QUEUE 2>/dev/null");
   system("ip6tables -D HIPFW-OUTPUT -p udp ! -d ::1 -j QUEUE 2>/dev/null");
  }
}

int hip_fw_init_sava_router() {
        int err = 0;

	/*
	 * We need to capture each and every packet
	 * that passes trough the firewall to verify the packets
	 * source address
	 */
	if (hip_sava_router) {
	        HIP_DEBUG("Initializing SAVA client mode \n");
	        HIP_IFEL(hip_sava_init_all(), -1,
		   "Error inializing SAVA IP DB \n");

		//system("iptables -P HIPFW-FORWARD -j DROP 2>/dev/null");
		system("ip6tables -P HIPFW-FORWARD -j DROP 2>/dev/null");

		system("iptables -I HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null");
		system("iptables -I HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null");
		/* IPv6 packets	*/
		system("ip6tables -I HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null");
		system("ip6tables -I HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null");
		system("ip6tables -I HIPFW-FORWARD -p 0 -j QUEUE 2>/dev/null");
		/*	Queue HIP packets as well */
		system("iptables -I HIPFW-INPUT -p 139 -j QUEUE 2>/dev/null");
		system("ip6tables -I HIPFW-INPUT -p 139 -j QUEUE 2>/dev/null");
	}
 out_err:
	return err;
}

void hip_fw_uninit_sava_router() {
	if (hip_sava_router) {
 	        HIP_DEBUG("Uninitializing SAVA server mode \n");
		/* IPv4 packets	*/
		system("iptables -D HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null");
		system("iptables -D HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null");
		/* IPv6 packets	*/
		system("ip6tables -D HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null");
		system("ip6tables -D HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null");

		/*	Stop queueing HIP packets */
		system("iptables -D HIPFW-INPUT -p 139 -j ACCEPT 2>/dev/null");
		system("ip6tables -D HIPFW-INPUT -p 139 -j ACCEPT 2>/dev/null");
	}
	return;
}

void hip_fw_init_opptcp(){
	HIP_DEBUG("\n");

	system("iptables -I HIPFW-INPUT -p 6 ! -d 127.0.0.1 -j QUEUE"); /* @todo: ! LSI PREFIX */ // proto 6 TCP and proto 17
	system("iptables -I HIPFW-OUTPUT -p 6 ! -d 127.0.0.1 -j QUEUE");  /* @todo: ! LSI PREFIX */

	system("ip6tables -I HIPFW-INPUT -p 6 ! -d 2001:0010::/28 -j QUEUE");
	system("ip6tables -I HIPFW-OUTPUT -p 6 ! -d 2001:0010::/28 -j QUEUE");
}


void hip_fw_uninit_opptcp(){

	HIP_DEBUG("\n");

	system("iptables -D HIPFW-INPUT -p 6 ! -d 127.0.0.1 -j QUEUE 2>/dev/null");  /* @todo: ! LSI PREFIX */
	system("iptables -D HIPFW-OUTPUT -p 6 ! -d 127.0.0.1 -j QUEUE 2>/dev/null"); /* @todo: ! LSI PREFIX */
	system("ip6tables -D HIPFW-INPUT -p 6 ! -d 2001:0010::/28 -j QUEUE 2>/dev/null");
	system("ip6tables -D HIPFW-OUTPUT -p 6 ! -d 2001:0010::/28 -j QUEUE 2>/dev/null");


}
void hip_fw_init_proxy()
{
	system("iptables -I HIPFW-FORWARD -p tcp -j QUEUE");	system("iptables -I HIPFW-FORWARD -p udp -j QUEUE");

	//system("iptables -I FORWARD -p icmp -j QUEUE");
	//system("iptables -I FORWARD -p icmpv6 -j QUEUE");

	//system("iptables -t nat -A POSTROUTING -o vmnet2 -j SNAT --to-source 10.0.0.1");

	system("ip6tables -I HIPFW-FORWARD -p tcp ! -d 2001:0010::/28 -j QUEUE");
	system("ip6tables -I HIPFW-FORWARD -p udp ! -d  2001:0010::/28 -j QUEUE");
	//system("ip6tables -I FORWARD -p icmp -j QUEUE");
	//system("ip6tables -I FORWARD -p icmpv6 -j QUEUE");

	system("ip6tables -I HIPFW-INPUT -p tcp -d 2001:0010::/28 -j QUEUE");
	system("ip6tables -I HIPFW-INPUT -p udp -d 2001:0010::/28 -j QUEUE");

	//system("ip6tables -I INPUT -p tcp  -j QUEUE");
	//system("ip6tables -I INPUT -p udp -j QUEUE");
	//system("ip6tables -I INPUT -p icmp -j QUEUE");
	//system("ip6tables -I INPUT -p icmpv6 -j QUEUE");

	hip_init_proxy_db();
	hip_proxy_init_raw_sockets();
	hip_init_conn_db();

}


void hip_fw_uninit_proxy(){
	//delete forward hip packets

	system("iptables -D HIPFW-FORWARD -p 139 -j ACCEPT 2>/dev/null");
	system("iptables -D HIPFW-FORWARD -p 139 -j ACCEPT 2>/dev/null");

	system("iptables -D HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null");
	system("iptables -D HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null");
	//system("iptables -D FORWARD -p icmp -j QUEUE 2>/dev/null");
	//system("iptables -D FORWARD -p icmpv6 -j QUEUE 2>/dev/null");

	//delete forward hip packets

	system("ip6tables -D HIPFW-FORWARD -p 139 -j ACCEPT 2>/dev/null");
	system("ip6tables -D HIPFW-FORWARD -p 139 -j ACCEPT 2>/dev/null");

	system("ip6tables -D HIPFW-FORWARD -p tcp ! -d 2001:0010::/28 -j QUEUE 2>/dev/null");
	system("ip6tables -D HIPFW-FORWARD -p udp ! -d  2001:0010::/28 -j QUEUE 2>/dev/null");
	//system("ip6tables -D FORWARD -p icmp -j QUEUE 2>/dev/null");
	//system("ip6tables -D FORWARD -p icmpv6 -j QUEUE 2>/dev/null");

	system("ip6tables -D HIPFW-INPUT -p tcp -d 2001:0010::/28 -j QUEUE 2>/dev/null");
	system("ip6tables -D HIPFW-INPUT -p udp -d 2001:0010::/28 -j QUEUE 2>/dev/null");
	//system("ip6tables -D INPUT -p tcp  -j QUEUE 2>/dev/null");
	//system("ip6tables -D INPUT -p udp -j QUEUE 2>/dev/null");
	//system("ip6tables -D INPUT -p icmp -j QUEUE 2>/dev/null");
	//system("ip6tables -D INPUT -p icmpv6 -j QUEUE 2>/dev/null");
}


int hip_fw_init_userspace_ipsec(){
	int err = 0;
	int ver_c;
	struct utsname name;

	HIP_IFEL(uname(&name), -1, "Failed to retrieve kernel information: %s\n", strerror(err));
	ver_c = atoi(&name.release[4]);

	if (hip_userspace_ipsec)
	{
		if (ver_c >= 27)
			HIP_INFO("You are using kernel version %s. Userspace " \
			"ipsec is not necessary with version 2.6.27 or higher.\n",
			name.release);

		HIP_IFEL(userspace_ipsec_init(), -1,
				"failed to initialize userspace ipsec\n");

		// queue incoming ESP over IPv4 and IPv4 UDP encapsulated traffic
		system("iptables -I HIPFW-INPUT -p 50 -j QUEUE"); /*  */
		system("iptables -I HIPFW-INPUT -p 17 --dport 50500 -j QUEUE");
		system("iptables -I HIPFW-INPUT -p 17 --sport 50500 -j QUEUE");

		/* no need to queue outgoing ICMP, TCP and UDP sent to LSIs as
		 * this is handled elsewhere */

		/* queue incoming ESP over IPv6
		 *
		 * @note this is where you would want to add IPv6 UDP encapsulation */
		system("ip6tables -I HIPFW-INPUT -p 50 -j QUEUE");

		// queue outgoing ICMP, TCP and UDP sent to HITs
		system("ip6tables -I HIPFW-OUTPUT -p 58 -d 2001:0010::/28 -j QUEUE");
		system("ip6tables -I HIPFW-OUTPUT -p 6 -d 2001:0010::/28 -j QUEUE");
		system("ip6tables -I HIPFW-OUTPUT -p 1 -d 2001:0010::/28 -j QUEUE");
		system("ip6tables -I HIPFW-OUTPUT -p 17 -d 2001:0010::/28 -j QUEUE");
	} else if (ver_c < 27)
		HIP_INFO("You are using kernel version %s. Userspace ipsec should" \
		" be used with versions below 2.6.27.\n", name.release);

  out_err:
  	return err;
}


int hip_fw_uninit_userspace_ipsec(){
	int err = 0;

	if (hip_userspace_ipsec)
	{
		// set global variable to off
		hip_userspace_ipsec = 0;

		HIP_IFEL(userspace_ipsec_uninit(), -1, "failed to uninit user ipsec\n");

		// delete all rules previously set up for this extension
		system("iptables -D HIPFW-INPUT -p 50 -j QUEUE 2>/dev/null"); /*  */
		system("iptables -D HIPFW-INPUT -p 17 --dport 50500 -j QUEUE 2>/dev/null");
		system("iptables -D HIPFW-INPUT -p 17 --sport 50500 -j QUEUE 2>/dev/null");

		system("ip6tables -D HIPFW-INPUT -p 50 -j QUEUE 2>/dev/null");

		system("ip6tables -D HIPFW-OUTPUT -p 58 -d 2001:0010::/28 -j QUEUE 2>/dev/null");
		system("ip6tables -D HIPFW-OUTPUT -p 6 -d 2001:0010::/28 -j QUEUE 2>/dev/null");
		system("ip6tables -D HIPFW-OUTPUT -p 17 -d 2001:0010::/28 -j QUEUE 2>/dev/null");
	}

  out_err:
  	return err;
}


int hip_fw_init_esp_prot(){
	int err = 0;

	if (hip_esp_protection)
	{
		// userspace ipsec is a prerequisite for esp protection
		if (hip_userspace_ipsec)
		{
			HIP_IFEL(esp_prot_init(), -1, "failed to init esp protection\n");

		} else
		{
			HIP_ERROR("userspace ipsec needs to be turned on for this to work\n");

			err = 1;
			goto out_err;
		}
	}

  out_err:
    return err;
}


int hip_fw_uninit_esp_prot(){
	int err = 0;

	if (hip_esp_protection)
	{
		// set global variable to off in fw
		hip_esp_protection = 0;

		HIP_IFEL(esp_prot_uninit(), -1, "failed to uninit esp protection\n");
	}

  out_err:
    return err;
}


int hip_fw_init_esp_prot_conntrack(){
	int err = 0;

	if (filter_traffic)
	{
		HIP_IFEL(esp_prot_conntrack_init(), -1,
				"failed to init esp protection conntracking\n");
	}

  out_err:
    return err;
}


int hip_fw_uninit_esp_prot_conntrack(){
	int err = 0;

	if (filter_traffic)
	{
		HIP_IFEL(esp_prot_conntrack_uninit(), -1,
				"failed to uninit esp protection conntracking\n");
	}

  out_err:
    return err;
}


int hip_fw_init_lsi_support(){
	int err = 0;

	if (hip_lsi_support)
	{
		// add the rule
		system("iptables -I HIPFW-OUTPUT -d " HIP_FULL_LSI_STR " -j QUEUE");

		/* LSI support: incoming HIT packets, captured to decide if
		   HITs may be mapped to LSIs */
		system("ip6tables -I HIPFW-INPUT -d 2001:0010::/28 -j QUEUE");
	}

  out_err:
  	return err;
}

int hip_fw_uninit_lsi_support(){
	int err = 0;

	if (hip_lsi_support)
	{
		// set global variable to off
		hip_lsi_support = 0;

		// remove the rule
		system("iptables -D HIPFW-OUTPUT -d " HIP_FULL_LSI_STR " -j QUEUE 2>/dev/null");

		system("ip6tables -D HIPFW-INPUT -d 2001:0010::/28 -j QUEUE 2>/dev/null");

		//empty the firewall db
		hip_firewall_delete_hldb();

		//empty tha firewall cache
		hip_firewall_cache_delete_hldb();
	}

  out_err:
  	return err;
}

void hip_fw_init_system_based_opp_mode(void) {
	system("iptables -N HIPFWOPP-INPUT");
	system("iptables -N HIPFWOPP-OUTPUT");

	system("iptables -I HIPFW-OUTPUT -d ! 127.0.0.1 -j QUEUE");
	system("ip6tables -I HIPFW-INPUT -d 2001:0010::/28 -j QUEUE");

	system("iptables -I HIPFW-INPUT -j HIPFWOPP-INPUT");
	system("iptables -I HIPFW-OUTPUT -j HIPFWOPP-OUTPUT");
}

void hip_fw_uninit_system_based_opp_mode(void) {
	system("iptables -D HIPFW-INPUT -j HIPFWOPP-INPUT");
	system("iptables -D HIPFW-OUTPUT -j HIPFWOPP-OUTPUT");

	system("iptables -D HIPFW-OUTPUT -d ! 127.0.0.1 -j QUEUE");
	system("ip6tables -D HIPFW-INPUT -d 2001:0010::/28 -j QUEUE");

	system("iptables -F HIPFWOPP-INPUT");
	system("iptables -F HIPFWOPP-OUTPUT");
	system("iptables -X HIPFWOPP-INPUT");
	system("iptables -X HIPFWOPP-OUTPUT");
}

/*----------------INIT/EXIT FUNCTIONS----------------------*/

/*
 * Rules:
 *
 * Output:
 *
 * - HIP:
 *   1. default rule checks for hip
 *   1. filter_hip
 *
 * - ESP:
 *   1. default rule checks for esp
 *   2. filter_esp
 *
 * - TCP:
 *   1. default rule checks for non-hip
 *   2.
 *   - destination is hit (userspace ipsec output)
 *   - destination is lsi (lsi output)
 *   - destination not hit or lsi
 *     1. opp tcp filtering (TBD)
 *
 * - Other
 *   - Same as with TCP except no opp tcp filtering
 *
 * Input:
 *
 * - HIP:
 *   1. default rule checks for hip
 *   2. filter_hip
 *
 * - ESP:
 *   1. default rule checks for hip
 *   2. filter_esp
 *   3. userspace_ipsec input
 *   4. lsi input
 *
 * - Other:
 *   - Same as with TCP except no opp tcp input
 *
 * - TCP:
 *   1. default rule checks for non-hip
 *   2. opp tcp input
 *   3. proxy input
  *
 * Forward:
 *
 * - HIP:
 *   1. None
 *
 * - ESP:
 *   1. None
 *
 * - TCP:
 *   1. Proxy input
 *
 * - Other:
 *   2. Proxy input
 *
 */
int firewall_init_rules(){
	int err = 0;

	HIP_DEBUG("Initializing firewall\n");

	HIP_DEBUG("in=%d out=%d for=%d\n", NF_IP_LOCAL_IN, NF_IP_LOCAL_OUT, NF_IP_FORWARD);

	// funtion pointers for the respective packet handlers
	hip_fw_handler[NF_IP_LOCAL_IN][OTHER_PACKET] = hip_fw_handle_other_input;
	hip_fw_handler[NF_IP_LOCAL_IN][HIP_PACKET] = hip_fw_handle_hip_input;
	hip_fw_handler[NF_IP_LOCAL_IN][ESP_PACKET] = hip_fw_handle_esp_input;
	hip_fw_handler[NF_IP_LOCAL_IN][TCP_PACKET] = hip_fw_handle_tcp_input;

	hip_fw_handler[NF_IP_LOCAL_OUT][OTHER_PACKET] = hip_fw_handle_other_output;
	hip_fw_handler[NF_IP_LOCAL_OUT][HIP_PACKET] = hip_fw_handle_hip_output;
	hip_fw_handler[NF_IP_LOCAL_OUT][ESP_PACKET] = hip_fw_handle_esp_output;
	hip_fw_handler[NF_IP_LOCAL_OUT][TCP_PACKET] = hip_fw_handle_tcp_output;

	hip_fw_handler[NF_IP_FORWARD][OTHER_PACKET] = hip_fw_handle_other_forward;

	//apply rules for forwarded hip and esp traffic
	hip_fw_handler[NF_IP_FORWARD][HIP_PACKET] = hip_fw_handle_hip_forward;
	hip_fw_handler[NF_IP_FORWARD][ESP_PACKET] = hip_fw_handle_esp_forward;
	//do not drop those files by default
	hip_fw_handler[NF_IP_FORWARD][TCP_PACKET] = hip_fw_handle_tcp_forward;

	HIP_DEBUG("Enabling forwarding for IPv4 and IPv6\n");
	system("echo 1 >/proc/sys/net/ipv4/conf/all/forwarding");

	/* Flush in case previous hipfw process crashed */
	hip_fw_flush_iptables();

	system("iptables -N HIPFW-INPUT");
	system("iptables -N HIPFW-OUTPUT");
	system("iptables -N HIPFW-FORWARD");
	system("ip6tables -N HIPFW-INPUT");
	system("ip6tables -N HIPFW-OUTPUT");
	system("ip6tables -N HIPFW-FORWARD");

	/* Register signal handlers */
	signal(SIGINT, firewall_close);
	signal(SIGTERM, firewall_close);

	// TARGET (-j) QUEUE will transfer matching packets to userspace
	// these packets will be handled using libipq

	if(hip_proxy_status)
	{
		/* Note: this block radvd advertisements */
		system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding");
		hip_fw_init_proxy();
	}
	else
	{
		/* @todo: remove the following line */
		system("echo 0 >/proc/sys/net/ipv6/conf/all/forwarding");

		// this has to be set up first in order to be the default behavior
		if (!accept_normal_traffic_by_default)
		{
			// make DROP the default behavior of all chains
			// TODO don't drop LSIs -> else IPv4 apps won't work
			// -> also messaging between HIPd and firewall is blocked here
			system("iptables -I HIPFW-FORWARD ! -d 127.0.0.1 -j DROP");  /* @todo: ! LSI PREFIX */
			system("iptables -I HIPFW-INPUT ! -d 127.0.0.1 -j DROP");  /* @todo: ! LSI PREFIX */
			system("iptables -I HIPFW-OUTPUT ! -d 127.0.0.1 -j DROP");  /* @todo: ! LSI PREFIX */

			// but still allow loopback and HITs as destination
			system("ip6tables -I HIPFW-FORWARD ! -d 2001:0010::/28 -j DROP");
			system("ip6tables -I HIPFW-INPUT ! -d 2001:0010::/28 -j DROP");
			system("ip6tables -I HIPFW-OUTPUT ! -d 2001:0010::/28 -j DROP");
			system("ip6tables -I HIPFW-FORWARD -d ::1 -j ACCEPT");
			system("ip6tables -I HIPFW-INPUT -d ::1 -j ACCEPT");
			system("ip6tables -I HIPFW-OUTPUT -d ::1 -j ACCEPT");
		}

		if (filter_traffic)
		{
			// this will allow the firewall to handle HIP traffic
			// HIP protocol
			system("iptables -I HIPFW-FORWARD -p 139 -j QUEUE");
			// ESP protocol
			system("iptables -I HIPFW-FORWARD -p 50 -j QUEUE");
			// UDP encapsulation for HIP
			system("iptables -I HIPFW-FORWARD -p 17 --dport 50500 -j QUEUE");
			system("iptables -I HIPFW-FORWARD -p 17 --sport 50500 -j QUEUE");

			system("iptables -I HIPFW-INPUT -p 139 -j QUEUE");
			system("iptables -I HIPFW-INPUT -p 50 -j QUEUE");
			system("iptables -I HIPFW-INPUT -p 17 --dport 50500 -j QUEUE");
			system("iptables -I HIPFW-INPUT -p 17 --sport 50500 -j QUEUE");

			system("iptables -I HIPFW-OUTPUT -p 139 -j QUEUE");
			system("iptables -I HIPFW-OUTPUT -p 50 -j QUEUE");
			system("iptables -I HIPFW-OUTPUT -p 17 --dport 50500 -j QUEUE");
			system("iptables -I HIPFW-OUTPUT -p 17 --sport 50500 -j QUEUE");

			system("ip6tables -I HIPFW-FORWARD -p 139 -j QUEUE");
			system("ip6tables -I HIPFW-FORWARD -p 50 -j QUEUE");
			system("ip6tables -I HIPFW-FORWARD -p 17 --dport 50500 -j QUEUE");
			system("ip6tables -I HIPFW-FORWARD -p 17 --sport 50500 -j QUEUE");

			system("ip6tables -I HIPFW-INPUT -p 139 -j QUEUE");
			system("ip6tables -I HIPFW-INPUT -p 50 -j QUEUE");
			system("ip6tables -I HIPFW-INPUT -p 17 --dport 50500 -j QUEUE");
			system("ip6tables -I HIPFW-INPUT -p 17 --sport 50500 -j QUEUE");

			system("ip6tables -I HIPFW-OUTPUT -p 139 -j QUEUE");
			system("ip6tables -I HIPFW-OUTPUT -p 50 -j QUEUE");
			system("ip6tables -I HIPFW-OUTPUT -p 17 --dport 50500 -j QUEUE");
			system("ip6tables -I HIPFW-OUTPUT -p 17 --sport 50500 -j QUEUE");
		}
	}

	if (system_based_opp_mode)
		hip_fw_init_system_based_opp_mode();

	if (hip_opptcp)
		hip_fw_init_opptcp();

	HIP_IFEL(hip_fw_init_lsi_support(), -1, "failed to load extension\n");
	HIP_IFEL(hip_fw_init_userspace_ipsec(), -1, "failed to load extension\n");
	HIP_IFEL(hip_fw_init_esp_prot(), -1, "failed to load extension\n");
	HIP_IFEL(hip_fw_init_sava_router(), -1, "failed to load SAVA router extension \n");
	HIP_IFEL(hip_fw_init_sava_client(), -1, "failed to load SAVA client extension \n");
	HIP_IFEL(hip_fw_init_esp_prot_conntrack(), -1, "failed to load extension\n");

	/* XX FIXME these inits should be done in the respective init-function depending
	 *    on the state variable for the extension */

	/* TURN translation */
	if (hip_stun) {
		system("iptables -I HIPFW-OUTPUT -p 17 --sport 40400 -j QUEUE");
	}

	// Initializing local database for mapping LSI-HIT in the firewall
	firewall_init_hldb();

	// Initializing local cache database
	firewall_cache_init_hldb();

	// Initializing local port cache database
	firewall_port_cache_init_hldb();

	system("iptables -I INPUT -j HIPFW-INPUT");
	system("iptables -I OUTPUT -j HIPFW-OUTPUT");
	system("iptables -I FORWARD -j HIPFW-FORWARD");
	system("ip6tables -I INPUT -j HIPFW-INPUT");
	system("ip6tables -I OUTPUT -j HIPFW-OUTPUT");
	system("ip6tables -I FORWARD -j HIPFW-FORWARD");

 out_err:
	return err;
}


void firewall_close(int signal){
	HIP_DEBUG("Closing firewall...\n");
	//hip_uninit_proxy_db();
	//hip_uninit_conn_db();
	firewall_exit();
	exit(signal);
}

void hip_fw_flush_iptables(void)
{
	HIP_DEBUG("Firewall flush; may cause warnings on hipfw init\n");
	HIP_DEBUG("Deleting hipfw subchains from main chains\n");

	system("iptables -D INPUT -j HIPFW-INPUT 2>/dev/null");
	system("iptables -D OUTPUT -j HIPFW-OUTPUT 2>/dev/null");
	system("iptables -D FORWARD -j HIPFW-FORWARD 2>/dev/null");
	system("ip6tables -D INPUT -j HIPFW-INPUT 2>/dev/null");
	system("ip6tables -D OUTPUT -j HIPFW-OUTPUT 2>/dev/null");
	system("ip6tables -D FORWARD -j HIPFW-FORWARD 2>/dev/null");

	HIP_DEBUG("Flushing hipfw chains\n");

	/* Flush in case there are some residual rules */
	system("iptables -F HIPFW-INPUT 2>/dev/null");
	system("iptables -F HIPFW-OUTPUT 2>/dev/null");
	system("iptables -F HIPFW-FORWARD 2>/dev/null");
	system("ip6tables -F HIPFW-INPUT 2>/dev/null");
	system("ip6tables -F HIPFW-OUTPUT 2>/dev/null");
	system("ip6tables -F HIPFW-FORWARD 2>/dev/null");

	HIP_DEBUG("Deleting hipfw chains\n");

	system("iptables -X HIPFW-INPUT 2>/dev/null");
	system("iptables -X HIPFW-OUTPUT 2>/dev/null");
	system("iptables -X HIPFW-FORWARD 2>/dev/null");
	system("ip6tables -X HIPFW-INPUT 2>/dev/null");
	system("ip6tables -X HIPFW-OUTPUT 2>/dev/null");
	system("ip6tables -X HIPFW-FORWARD 2>/dev/null");
}


void firewall_exit(){
	HIP_DEBUG("Firewall exit\n");

	if (system_based_opp_mode)
		hip_fw_uninit_system_based_opp_mode();

	hip_fw_flush_iptables();

	/* rules have to be removed first, otherwise HIP packets won't pass through
	 * at this time any more */
	hip_fw_uninit_userspace_ipsec();
	hip_fw_uninit_esp_prot();
	hip_fw_uninit_esp_prot_conntrack();
	hip_fw_uninit_lsi_support();
	hip_fw_uninit_sava_router();

	hip_remove_lock_file(HIP_FIREWALL_LOCK_FILE);
}


/*-------------PACKET FILTERING FUNCTIONS------------------*/

int match_hit(struct in6_addr match_hit, struct in6_addr packet_hit, int boolean){
	int i= IN6_ARE_ADDR_EQUAL(&match_hit, &packet_hit);
	HIP_DEBUG("match_hit: hit1: %s hit2: %s bool: %d match: %d\n",
			addr_to_numeric(&match_hit), addr_to_numeric(&packet_hit), boolean, i);
	if (boolean)
		return i;
	else
		return !i;
}

#if 0
/**
 *inspects host identity by verifying sender signature
 * returns 1 if verified succesfully otherwise 0
 */
int match_hi(struct hip_host_id * hi, struct hip_common * packet){
	int value = 0;
	if (packet->type_hdr == HIP_I1)
	{
		_HIP_DEBUG("match_hi: I1\n");
		return 1;
	}
	// FIXME first check mapping: HI <-> HIT (cheaper operation)
	value = verify_packet_signature(hi, packet);
	if (value == 0)
		_HIP_DEBUG("match_hi: verify ok\n");
	else
		_HIP_DEBUG("match_hi: verify failed\n");
	if (value == 0)
		return 1;
	return 0;
}
#endif

int match_int(int match, int packet, int boolean){
	if (boolean)
		return match == packet;
	else
		return !(match == packet);
}


int match_string(const char * match, const char * packet, int boolean){
	if (boolean)
		return !strcmp(match, packet);
	else
		return strcmp(match, packet);
}

/*------------------------------------------------*/

static void die(struct ipq_handle *h){
	HIP_DEBUG("dying\n");
	ipq_perror("passer");
	ipq_destroy_handle(h);
	firewall_close(1);
}


/**
 * Returns the packet type of an IP packet.
 *
 * Currently supported types:				type
 * - plain HIP control packet				  1
 * - STUN packet				  			  1 (UDP encapsulated HIP control)
 * - ESP packet								  2
 * - TCP packet								  3 (for opportunistic TCP handshake)
 *
 * Unsupported types -> type 0
 *
 * @param  hdr        a pointer to a IP packet.
 * @param ipVersion	  the IP version for this packet
 * @return            One if @c hdr is a HIP packet, zero otherwise.
 */
int hip_fw_init_context(hip_fw_context_t *ctx, char *buf, int ip_version)
{
	int ip_hdr_len, err = 0;
	// length of packet starting at udp header
	uint16_t udp_len = 0;
	struct udphdr *udphdr = NULL;
	int udp_encap_zero_bytes = 0, stun_ret;

	// default assumption
	ctx->packet_type = OTHER_PACKET;

	// same context memory as for packets before -> re-init
	memset(ctx, 0, sizeof(hip_fw_context_t));

	// add whole packet to context and ip version
	ctx->ipq_packet = ipq_get_packet(buf);

	// check if packet is to big for the buffer
	if (ctx->ipq_packet->data_len > BUFSIZE)
	{
		HIP_ERROR("packet size greater than buffer\n");

		err = 1;
		goto end_init;
	}

	ctx->ip_version = ip_version;

	if(ctx->ip_version == 4){
		_HIP_DEBUG("IPv4 packet\n");

		struct ip *iphdr = (struct ip *) ctx->ipq_packet->payload;
		// add pointer to IPv4 header to context
		ctx->ip_hdr.ipv4 = iphdr;

		/* ip_hl is given in multiple of 4 bytes
		 *
		 * NOTE: not sizeof(struct ip) as we might have options */
		ip_hdr_len = (iphdr->ip_hl * 4);
		// needed for opportunistic TCP
		ctx->ip_hdr_len = ip_hdr_len;
		HIP_DEBUG("ip_hdr_len is: %d\n", ip_hdr_len);
		HIP_DEBUG("total length: %u\n", ntohs(iphdr->ip_len));
		HIP_DEBUG("ttl: %u\n", iphdr->ip_ttl);
		HIP_DEBUG("packet length (ipq): %u\n", ctx->ipq_packet->data_len);

		// add IPv4 addresses
		IPV4_TO_IPV6_MAP(&ctx->ip_hdr.ipv4->ip_src, &ctx->src);
		IPV4_TO_IPV6_MAP(&ctx->ip_hdr.ipv4->ip_dst, &ctx->dst);

		HIP_DEBUG_HIT("packet src: ", &ctx->src);
		HIP_DEBUG_HIT("packet dst: ", &ctx->dst);

		HIP_DEBUG("IPv4 next header protocol number is %d\n", iphdr->ip_p);

		// find out which transport layer protocol is used
		if(iphdr->ip_p == IPPROTO_HIP)
		{
			// we have found a plain HIP control packet
			HIP_DEBUG("plain HIP packet\n");

			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)iphdr) + ip_hdr_len);

			goto end_init;

		} else if (iphdr->ip_p == IPPROTO_ESP)
		{
			// this is an ESP packet
			HIP_DEBUG("plain ESP packet\n");

			ctx->packet_type = ESP_PACKET;
			ctx->transport_hdr.esp = (struct hip_esp *) (((char *)iphdr) + ip_hdr_len);

			goto end_init;

		} else if(iphdr->ip_p == IPPROTO_TCP)
		{
			// this might be a TCP packet for opportunistic mode
			HIP_DEBUG("plain TCP packet\n");

			ctx->packet_type = TCP_PACKET;
			ctx->transport_hdr.tcp = (struct tcphdr *) (((char *)iphdr) + ip_hdr_len);

			goto end_init;
		} else if (iphdr->ip_p != IPPROTO_UDP)
		{
			// if it's not UDP either, it's unsupported
			HIP_DEBUG("some other packet\n");

			goto end_init;
		}

		// need UDP header to look for encapsulated ESP or STUN
		udp_len = ntohs(iphdr->ip_len);
		udphdr = ((struct udphdr *) (((char *) iphdr) + ip_hdr_len));

		// add UDP header to context
		ctx->udp_encap_hdr = udphdr;

	} else if (ctx->ip_version == 6)
	{
		_HIP_DEBUG("IPv6 packet\n");

		struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ctx->ipq_packet->payload;
		// add pointer to IPv4 header to context
		ctx->ip_hdr.ipv6 = ip6_hdr;

		// Ipv6 has fixed header length
		ip_hdr_len = sizeof(struct ip6_hdr);
		// needed for opportunistic TCP
		ctx->ip_hdr_len = ip_hdr_len;
		HIP_DEBUG("ip_hdr_len is: %d\n", ip_hdr_len);
		HIP_DEBUG("payload length: %u\n", ntohs(ip6_hdr->ip6_plen));
		HIP_DEBUG("ttl: %u\n", ip6_hdr->ip6_hlim);
		HIP_DEBUG("packet length (ipq): %u\n", ctx->ipq_packet->data_len);

		// add IPv6 addresses
		ipv6_addr_copy(&ctx->src, &ip6_hdr->ip6_src);
		ipv6_addr_copy(&ctx->dst, &ip6_hdr->ip6_dst);

		HIP_DEBUG_HIT("packet src: ", &ctx->src);
		HIP_DEBUG_HIT("packet dst: ", &ctx->dst);

		HIP_DEBUG("IPv6 next header protocol number is %d\n",
			  ip6_hdr->ip6_nxt);

		// find out which transport layer protocol is used
		if(ip6_hdr->ip6_nxt == IPPROTO_HIP)
		{
			// we have found a plain HIP control packet
			HIP_DEBUG("plain HIP packet\n");

			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));

			goto end_init;

		} else if (ip6_hdr->ip6_nxt == IPPROTO_ESP)
		{
			// we have found a plain ESP packet
			HIP_DEBUG("plain ESP packet\n");

			ctx->packet_type = ESP_PACKET;
			ctx->transport_hdr.esp = (struct hip_esp *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));

			goto end_init;

		} else if(ip6_hdr->ip6_nxt == IPPROTO_TCP)
		{
			// this might be a TCP packet for opportunistic mode
			HIP_DEBUG("plain TCP packet\n");

			ctx->packet_type = TCP_PACKET;
			ctx->transport_hdr.tcp = (struct tcphdr *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));

			goto end_init;

		} else if (ip6_hdr->ip6_nxt != IPPROTO_UDP)
		{
			// if it's not UDP either, it's unsupported
			HIP_DEBUG("some other packet\n");

			goto end_init;
		}

		/* for now these calculations are not necessary as UDP encapsulation
		 * is only used for IPv4 at the moment
		 *
		 * we keep them anyway in order to ease UDP encapsulation handling
		 * with IPv6
		 *
		 * NOTE: the length will include optional extension headers
		 * -> handle this */
		udp_len = ntohs(ip6_hdr->ip6_plen);
		udphdr = ((struct udphdr *) (((char *) ip6_hdr) + ip_hdr_len));

		// add udp header to context
		ctx->udp_encap_hdr = udphdr;
	}

	HIP_DEBUG("UDP header size  is %d\n", sizeof(struct udphdr));

	/* only handle IPv4 right now
	 * -> however this is the place to handle UDP encapsulated IPv6 */
	if (ctx->ip_version == 4)
	{
		// we might have only received a UDP packet with headers only
		if (udp_len >= sizeof(struct ip) + sizeof(struct udphdr) + HIP_UDP_ZERO_BYTES_LEN)
		{
			uint32_t *zero_bytes = NULL;

			// we can distinguish UDP encapsulated control and data traffic with 32 zero bits
			// behind UDP header
			zero_bytes = (uint32_t *) (((char *)udphdr) + sizeof(struct udphdr));

			HIP_HEXDUMP("zero_bytes: ", zero_bytes, 4);

			/* check whether next 32 bits are zero or not */
			if (*zero_bytes == 0)
			{
				udp_encap_zero_bytes = 1;

				HIP_DEBUG("Zero SPI found\n");
			}

			zero_bytes = NULL;
		} else
		{
			// only UDP header + payload < 32 bit -> neither HIP nor ESP
			HIP_DEBUG("UDP packet with < 32 bit payload\n");

			goto end_init;
		}
	}

	_HIP_DEBUG("udp hdr len %d\n", ntohs(udphdr->len));
	_HIP_HEXDUMP("hexdump ",udphdr, 20);

	// HIP packets have zero bytes (IPv4 only right now)
	if(ctx->ip_version == 4 && udphdr
			&& ((udphdr->source == ntohs(hip_get_local_nat_udp_port())) ||
		        (udphdr->dest == ntohs(hip_get_peer_nat_udp_port())))
		    && udp_encap_zero_bytes)

	{
		/* check if zero byte hint is correct and we are processing a
		 * HIP control message */
		if (!hip_check_network_msg((struct hip_common *) (((char *)udphdr)
								     +
								  sizeof(struct udphdr)
								  +
								  HIP_UDP_ZERO_BYTES_LEN)))
		{
			// we found an UDP encapsulated HIP control packet
			HIP_DEBUG("UDP encapsulated HIP control packet\n");

			// add to context
			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)udphdr)
									+ sizeof(struct udphdr)
									+ HIP_UDP_ZERO_BYTES_LEN);

			goto end_init;
		}
		HIP_ERROR("communicating with BROKEN peer implementation of UDP encapsulation,"
				" found zero bytes when receiving HIP control message\n");
	}

	/* Santtu: XX FIXME: needs to be inside the following if */
	//else if (hip_is_stun_msg(udphdr) {
	else if (hip_stun && ((stun_ret = pj_stun_msg_check(udphdr+1,ntohs(udphdr->len) -
			sizeof(struct udphdr),PJ_STUN_IS_DATAGRAM))
			      == PJ_SUCCESS)){
		HIP_DEBUG("Found a UDP STUN\n");
		ctx->is_stun = 1;
	    goto end_init;
	}

	// ESP does not have zero bytes (IPv4 only right now)
	else if (ctx->ip_version == 4 && udphdr
		 && ((udphdr->source == ntohs(hip_get_local_nat_udp_port())) ||
		     (udphdr->dest == ntohs(hip_get_peer_nat_udp_port())))
		 && !udp_encap_zero_bytes)
	{

		_HIP_HEXDUMP("stun check failed in UDP",udphdr+1, 20);
		HIP_DEBUG("stun return is %d \n",stun_ret);
		HIP_DEBUG("stun len is %d \n",ntohs(udphdr->len) - sizeof(udphdr));
		/* from the ports and the non zero SPI we can tell that this
		 * is an ESP packet */
		HIP_DEBUG("UDP encapsulated ESP packet or STUN PACKET\n");
		HIP_DEBUG("Assuming ESP. Todo: verify SPI from database\n");

		// add to context
		ctx->packet_type = ESP_PACKET;
		ctx->transport_hdr.esp = (struct hip_esp *) (((char *)udphdr)
							     + sizeof(struct udphdr));

		goto end_init;
	} else if (ctx->is_stun && ctx->ip_version == 4 && udphdr &&
		   udphdr->dest == ntohs(HIP_NAT_TURN_PORT) &&
		   !udp_encap_zero_bytes) {
		ctx->packet_type = ESP_PACKET;
		ctx->transport_hdr.esp = (struct hip_esp *) (((char *)udphdr)
							     + sizeof(struct udphdr));
		ctx->is_turn = 1;
	}
	// normal UDP packet or UDP encapsulated IPv6
	else {
		HIP_DEBUG("normal UDP packet\n");
	}

end_init:
	return err;
}


/**
 * Allow a packet to pass
 *
 * @param handle	the handle for the packets.
 * @param packetId	the packet ID.
 * @return		nothing
 */
void allow_packet(struct ipq_handle *handle, unsigned long packetId){
	ipq_set_verdict(handle, packetId, NF_ACCEPT, 0, NULL);

	HIP_DEBUG("Packet accepted \n\n");
}


/**
 * Not allow a packet to pass
 *
 * @param handle	the handle for the packets.
 * @param packetId	the packet ID.
 * @return		nothing
 */
void drop_packet(struct ipq_handle *handle, unsigned long packetId){
	ipq_set_verdict(handle, packetId, NF_DROP, 0, NULL);

	HIP_DEBUG("Packet dropped \n\n");
}


/* We only match the esp packet with the state in the connection
  * tracking. There is no need to match the rule-set again as we
  * already filtered the HIP control packets. If we wanted to
  * disallow a connection, we should do it there! */
int filter_esp(hip_fw_context_t * ctx)
{
	// drop packet by default
	int verdict = 0;
	int use_escrow = 0;
	struct _DList * list = NULL;
	struct rule * rule = NULL;

	/* @todo: ESP access control have some issues ICE/STUN */
	if (hip_stun){
		verdict = 1;
		goto out_err;
	}
	// if key escrow is active we have to handle it here too
	if (escrow_active)
	{
		// there might be some rules in the rule-set which specify
		// HITs for which decryption should be done

		// list with all rules for hook (= IN / OUT / FORWARD)
		list = (struct _DList *) read_rules(ctx->ipq_packet->hook);
		rule = NULL;

		// match all rules
		while (list != NULL)
		{
			rule = (struct rule *) list->data;

			// FIXME this does only work if first rule with rule->state->decrypt_contents
			// has matching src or dst addresses
			if (rule->state)
			{
				// search the rule-set for a rule with escow set
				if (rule->state->decrypt_contents)
				{
					// check if rule has valid state specified for data transfer
					if((rule->state->int_opt.value == CONN_NEW && rule->state->int_opt.boolean) ||
							(rule->state->int_opt.value == CONN_ESTABLISHED && !rule->state->int_opt.boolean))
					{
						HIP_ERROR("INVALID rule: specified state incompatible with --decrypt_contents\n");

						continue;
					}
					else
					{
						use_escrow = 1;

						break;
					}
				}
			}
		}
	}

	//the entire rule is passed as argument as hits can only be
	//filtered with the state information

	if (filter_esp_state(ctx, rule, use_escrow) > 0)
	{
		verdict = 1;

		HIP_DEBUG("ESP packet successfully passed filtering\n");

	} else
	{
		verdict = 0;

		HIP_DEBUG("ESP packet NOT authed in ESP filtering\n");
	}

  out_err:
  	return verdict;
}

/* filter hip packet according to rules.
 * return verdict
 */

int filter_hip(const struct in6_addr * ip6_src,
               const struct in6_addr * ip6_dst,
               struct hip_common *buf,
               unsigned int hook,
               const char * in_if,
               const char * out_if)
{
	// complete rule list for hook (== IN / OUT / FORWARD)
  	struct _DList * list = (struct _DList *) read_rules(hook);
  	struct rule * rule = NULL;
  	// assume match for current rule
  	int match = 1;
  	// assume packet has not yet passed connection tracking
  	int conntracked = 0;
  	// block traffic by default
  	int verdict = 0;

	HIP_DEBUG("\n");

  	//if dynamically changing rules possible

  	if (!list) {
  		HIP_DEBUG("The list of rules is empty!!!???\n");
  	}

  	while (list != NULL) {
  		match = 1;
  		rule = (struct rule *) list->data;

  		HIP_DEBUG("HIP type number is %d\n", buf->type_hdr);

  		//print_rule(rule);
		if (buf->type_hdr == HIP_I1)
			HIP_DEBUG("packet type: I1\n");
		else if (buf->type_hdr == HIP_R1)
			HIP_DEBUG("packet type: R1\n");
		else if (buf->type_hdr == HIP_I2)
			HIP_DEBUG("packet type: I2\n");
		else if (buf->type_hdr == HIP_R2)
			HIP_DEBUG("packet type: R2\n");
		else if (buf->type_hdr == HIP_UPDATE)
			HIP_DEBUG("packet type: UPDATE\n");
		else if (buf->type_hdr == HIP_NOTIFY)
			HIP_DEBUG("packet type: NOTIFY\n");
		else if (buf->type_hdr == HIP_LUPDATE)
			HIP_DEBUG("packet type: LIGHT UPDATE\n");
		else
			HIP_DEBUG("packet type: UNKNOWN\n");

		HIP_DEBUG_HIT("src hit: ", &(buf->hits));
		HIP_DEBUG_HIT("dst hit: ", &(buf->hitr));

		// check src_hit if defined in rule
		if(match && rule->src_hit) {
			HIP_DEBUG("src_hit\n");

			if(!match_hit(rule->src_hit->value,
				      buf->hits,
				      rule->src_hit->boolean)) {
				match = 0;
			}
		}

		// check dst_hit if defined in rule
		if(match && rule->dst_hit) {
			HIP_DEBUG("dst_hit\n");

			if(!match_hit(rule->dst_hit->value,
				      buf->hitr,
				      rule->dst_hit->boolean)) {
				match = 0;
			}
	  	}

		// check the HIP packet type (I1, UPDATE, etc.)
		if(match && rule->type) {
			HIP_DEBUG("type\n");
			if(!match_int(rule->type->value,
				      buf->type_hdr,
				      rule->type->boolean)) {
				match = 0;
			}

			HIP_DEBUG("type rule: %d, packet: %d, boolean: %d, match: %d\n",
				  rule->type->value,
				  buf->type_hdr,
				  rule->type->boolean,
				  match);
	  	}

		/* this checks, if the the input interface of the packet
		   matches the one specified in the rule */
		if(match && rule->in_if) {
			if(!match_string(rule->in_if->value, in_if,
					 rule->in_if->boolean)) {
				match = 0;
			}

			HIP_DEBUG("in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
				  rule->in_if->value,
				  in_if, rule->in_if->boolean, match);
	  	}

		/* this checks, if the the output interface of the packet matches the
		 * one specified in the rule */
		if(match && rule->out_if) {
			if(!match_string(rule->out_if->value,
					 out_if,
					 rule->out_if->boolean))
			{
				match = 0;
			}

			HIP_DEBUG("out_if rule: %s, packet: %s, boolean: %d, match: %d \n",
				  rule->out_if->value, out_if, rule->out_if->boolean, match);
	  	}

/* NOTE: HI does not make sense as a filter criteria as filtering by HITs and matching to transmitted HI
 * 		 is supposed to provide a similar level of security. Furthermore, signature verification is done
 * 		 in conntracking.
 * 		 -- Rene
 * TODO think about removing this in firewall_control.conf as well
 */
#if 0
		// if HI defined in rule, verify signature now
		// - late as it's an expensive operation
		// - checks that the message src is the src defined in the _rule_
		if(match && rule->src_hi) {
			_HIP_DEBUG("src_hi\n");

			if(!match_hi(rule->src_hi, buf)) {
		  		match = 0;
			}
		}
#endif

		/* check if packet matches state from connection tracking
		   must be last, so not called if packet is going to be
		   dropped */
		if(match && rule->state)
	  	{
			/* we at least had some packet before -> check
			   this packet this will also check the signature of
			   the packet, if we already have a src_HI stored
			   for the _connection_ */
			if(!filter_state(ip6_src, ip6_dst, buf, rule->state, rule->accept)) {
				match = 0;
			} else
			{
				// if it is a valid packet, this also tracked the packet
				conntracked = 1;
			}

			HIP_DEBUG("state, rule %d, boolean %d, match %d\n",
				  rule->state->int_opt.value,
				  rule->state->int_opt.boolean,
				  match);
		}

		// if a match, no need to check further rules
		if(match)
		{
			HIP_DEBUG("match found\n");
			break;
 		}

		// else proceed with next rule
		list = list->next;
	}

  	// if we found a matching rule, use its verdict
  	if(rule && match)
	{
		HIP_DEBUG("packet matched rule, target %d\n", rule->accept);
		verdict = rule->accept;
	} else {
 		HIP_DEBUG("falling back to default HIP/ESP behavior, target %d\n",
			  accept_hip_esp_traffic_by_default);

 		verdict = accept_hip_esp_traffic_by_default;
 	}

  	//release rule list
  	read_rules_exit(0);

  	// if packet will be accepted and connection tracking is used
  	// but there is no state for the packet in the conntrack module
  	// yet -> show the packet to conntracking
  	if (statefulFiltering && verdict && !conntracked) {
		conntrack(ip6_src, ip6_dst, buf);
  	}

  	return verdict;
}


int hip_fw_handle_other_output(hip_fw_context_t *ctx){
	hip_lsi_t src_ip, dst_ip;
	struct sockaddr_in6 dst_hit;
	hip_lsi_t defaultLSI;

	struct hip_common * msg;
	struct ip      *iphdr;
	struct tcphdr  *tcphdr;
	char 	       *hdrBytes = NULL;
	int             err = 0;
	int verdict = accept_normal_traffic_by_default;

	HIP_DEBUG("\n");

	if (hip_opptcp) {
		/* For TCP option only */
		iphdr = (struct ip *)ctx->ip_hdr.ipv4;
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + ctx->ip_hdr_len));
		hdrBytes = ((char *) iphdr) + ctx->ip_hdr_len;
	}
	if (hip_sava_client &&
	    !hip_lsi_support &&
	    !hip_userspace_ipsec) {
		/* check if HA exists with the router then
		   encrypt source IP and reinject packet to
		   the network stack
		   else register with the sava router
		   to register first try to find if sava router IP present in configuration
		   if not try to broadcast SD HIP packets and wait for the response
		   upon registration repeat the procedure described above for sending
		   out the packet */

		HIP_DEBUG("Handling normal traffic in SAVA mode \n ");

		verdict = hip_sava_handle_output(ctx);

	} else if (ctx->ip_version == 6 && hip_userspace_ipsec) {
		hip_hit_t *def_hit = hip_fw_get_default_hit();
		HIP_DEBUG_HIT("destination hit: ", &ctx->dst);
		// XX TODO: hip_fw_get_default_hit() returns an unfreed value
		if (def_hit)
			HIP_DEBUG_HIT("default hit: ", def_hit);
		// check if this is a reinjected packet
		if (def_hit && IN6_ARE_ADDR_EQUAL(&ctx->dst, def_hit)) {
			// let the packet pass through directly
			verdict = 1;
		} else {
			verdict = !hip_fw_userspace_ipsec_output(ctx);
		}
	} else if(ctx->ip_version == 4) {
		hip_lsi_t src_lsi, dst_lsi;

		IPV6_TO_IPV4_MAP(&(ctx->src), &src_lsi);
		IPV6_TO_IPV4_MAP(&(ctx->dst), &dst_lsi);

		/* LSI HOOKS */
		if (IS_LSI32(dst_lsi.s_addr) && hip_lsi_support) {
			if (hip_is_packet_lsi_reinjection(&dst_lsi)) {
				verdict = 1;
			} else {
				hip_fw_handle_outgoing_lsi(ctx->ipq_packet,
							   &src_lsi, &dst_lsi);
				verdict = 0; /* Reject the packet */
			}
		} else if (hip_opptcp && (ctx->ip_hdr.ipv4)->ip_p == 6 &&
			   tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
				verdict = 1;
		} else if (system_based_opp_mode) {
			   verdict = hip_fw_handle_outgoing_system_based_opp(ctx);
		}
	}

	/* No need to check default rules as it is handled by the
	   iptables rules */
 out_err:

	return verdict;
}


int hip_fw_handle_hip_output(hip_fw_context_t *ctx){
        int err = 0;
	int verdict = accept_hip_esp_traffic_by_default;
	hip_common_t * buf = ctx->transport_hdr.hip;

	HIP_DEBUG("hip_fw_handle_hip_output \n");

	if (hip_userspace_ipsec)
		HIP_IFEL(hip_fw_userspace_ipsec_init_hipd(1), 0,
			 "Drop ESP packet until hipd is available\n");

	if (filter_traffic)
	{
#if 0
	  if (hip_sava_router) {
		  HIP_DEBUG("HIP packet type %d \n", buf->type_hdr);

		  hip_common_t * buf = ctx->transport_hdr.hip;

	    //add a check for flow direction this should be incomming
	    if (buf->type_hdr == HIP_I2){

	      HIP_DEBUG("CHECK IP IN THE HIP_I2 STATE \n");
	      if (hip_sava_ip_entry_find(&ctx->src) != NULL) {
		HIP_DEBUG("IP already apprears to present in the data base. Most likely retransmitting the I2 \n");
		verdict = ACCEPT;
		goto filter;
	      } else {
		HIP_DEBUG("IP  apprears to be new. Adding to DB \n");
	      }
	      {
		hip_sava_ip_entry_t * ip_entry = NULL;
		hip_sava_hit_entry_t * hit_entry = NULL;

		//TODO: check if the source IP belongs to
		//the same network as router's IP address
		// Drop the packet IP was not found in the data base
		HIP_DEBUG("Packet accepted! Adding source IP address to the DB \n");
		hip_sava_ip_entry_add(&ctx->src, NULL);
		hip_sava_hit_entry_add(&buf->hits, NULL);

		HIP_IFEL((ip_entry = hip_sava_ip_entry_find(&ctx->src)) == NULL, DROP,
			 "No entry was found for given IP address \n");
		HIP_IFEL((hit_entry = hip_sava_hit_entry_find(&buf->hits)) == NULL, DROP,
			 "No entry was found for given HIT \n");

		//Adding cross references
		ip_entry->link = hit_entry;
		hit_entry->link = ip_entry;
		//End adding cross references
	      }
	    }
	  } else if (hip_sava_client) {

	  }
#endif
	    /*
	      The simplest way to check is to hold a list of IP addresses that
	      already were discovered previously and have 2 checks:
	      1. Check if the IP address is on the same subnet as the router (since we
	      deal only with clients that should be on the same subnet as router)
	      2. Check if current IP does not present in the list previously seen IP addresses
	      Is there more secure and complecated way to do that???
	    */
	    /*
	       Add mechanism to verify the source IP
	       Also we need to check if this address was not
	       previously used and not present in the data base
	    */
	    //this should be incomming packet


	  //second check is to check HITs
	  //mandatory check for SAVA
	  //rules should present in the ACL otherwise the packets are dropped
	  verdict = filter_hip(&ctx->src,
			       &ctx->dst,
			       ctx->transport_hdr.hip,
			       ctx->ipq_packet->hook,
			       ctx->ipq_packet->indev_name,
			       ctx->ipq_packet->outdev_name);
	} else {
	  verdict = ACCEPT;
	}

 out_err:
	/* zero return value means that the packet should be dropped */
	return verdict;
}


int hip_fw_handle_esp_output(hip_fw_context_t *ctx){
	int verdict = accept_hip_esp_traffic_by_default;

	HIP_DEBUG("\n");

	if (filter_traffic)
	{
		verdict = filter_esp(ctx);
	} else
	{
		verdict = ACCEPT;
	}

	if (ctx->is_turn)
		verdict = hip_fw_handle_turn_esp_output(ctx);

	return verdict;
}


int hip_fw_handle_tcp_output(hip_fw_context_t *ctx){

	HIP_DEBUG("\n");

	return hip_fw_handle_other_output(ctx);
}


int hip_fw_handle_other_input(hip_fw_context_t *ctx){
	int verdict = accept_normal_traffic_by_default;
	int ip_hits = ipv6_addr_is_hit(&ctx->src) &&
		      ipv6_addr_is_hit(&ctx->dst);

	HIP_DEBUG("\n");

	if (ip_hits) {
		if (hip_proxy_status)
			verdict = handle_proxy_inbound_traffic(ctx->ipq_packet,
					&ctx->src);
	  	else if (hip_lsi_support || system_based_opp_mode) {
			verdict = hip_fw_handle_incoming_hit(ctx->ipq_packet,
							     &ctx->src,
							     &ctx->dst,
							     hip_lsi_support,
							     system_based_opp_mode);
	  	}
	} else if (hip_stun && ctx->is_stun == 1) {
		// Santtu FIXME
		verdict = hip_fw_handle_stun_packet(ctx);
		/* - verdict zero drops the original so that you can send a new one
		   - alloc new memory, copy the packet and add some zeroes (and hip header?)
		   - change ip and udp lengths and checksums accordingly
		   - check handle_proxy_inbound_traffic() for examples
		   - use raw_sock_v4 to send the packets */
	}

	/* No need to check default rules as it is handled by the
	   iptables rules */
 out_err:

	return verdict;
}


int hip_fw_handle_hip_input(hip_fw_context_t *ctx){

	HIP_DEBUG("hip_fw_handle_hip_input()\n");

	// for now input and output are handled symmetrically
	return hip_fw_handle_hip_output(ctx);
}


int hip_fw_handle_esp_input(hip_fw_context_t *ctx){
	int verdict = accept_hip_esp_traffic_by_default;

	HIP_DEBUG("\n");

	if (filter_traffic)
	{
		// first of all check if this belongs to one of our connections
		verdict = filter_esp(ctx);
	} else
	{
		verdict = ACCEPT;
	}

	if (verdict && hip_userspace_ipsec) {
		HIP_DEBUG("userspace ipsec input\n");
		// added by Tao Wan
		verdict = !hip_fw_userspace_ipsec_input(ctx);
	}

 out_err:
	return verdict;
}


int hip_fw_handle_tcp_input(hip_fw_context_t *ctx){
	int verdict = accept_normal_traffic_by_default;

	HIP_DEBUG("\n");

	// any incoming plain TCP packet might be an opportunistic I1
	HIP_DEBUG_HIT("hit src", &ctx->src);
	HIP_DEBUG_HIT("hit dst", &ctx->dst);

	if(hip_opptcp && !ipv6_addr_is_hit(&ctx->dst)){
		verdict = hip_fw_examine_incoming_tcp_packet(ctx->ip_hdr.ipv4,
							     ctx->ip_version,
							     ctx->ip_hdr_len);
	} else
	{
		// as we should never receive TCP with HITs, this will only apply
		// to IPv4 TCP
		verdict = hip_fw_handle_other_input(ctx);
	}

 out_err:

	return verdict;
}

int hip_fw_handle_other_forward(hip_fw_context_t *ctx){

	int verdict = accept_normal_traffic_by_default;

	HIP_DEBUG("hip_fw_handle_other_forward()\n");

	if (hip_proxy_status && !ipv6_addr_is_hit(&ctx->dst))
	{
		verdict = handle_proxy_outbound_traffic(ctx->ipq_packet,
							&ctx->src,
							&ctx->dst,
							ctx->ip_hdr_len,
							ctx->ip_version);
	} else if (hip_sava_router) {
	  HIP_DEBUG("hip_sava_router \n");
	  verdict = hip_sava_handle_router_forward(ctx);
	}

 out_err:
	return verdict;
}


int hip_fw_handle_hip_forward(hip_fw_context_t *ctx){

	HIP_DEBUG("\n");

	// for now forward and output are handled symmetrically
	return hip_fw_handle_hip_output(ctx);
}


int hip_fw_handle_esp_forward(hip_fw_context_t *ctx){
	int verdict = accept_hip_esp_traffic_by_default;

	HIP_DEBUG("\n");

	if (filter_traffic)
	{
		// check if this belongs to one of the connections pass through
		verdict = filter_esp(ctx);
	} else
	{
		verdict = ACCEPT;
	}

 out_err:
	return verdict;
}


int hip_fw_handle_tcp_forward(hip_fw_context_t *ctx){
	HIP_DEBUG("\n");

	return hip_fw_handle_other_forward(ctx);
}


/**
 * Analyzes packets.

 * @param *ptr	pointer to an integer that indicates
 * 		the type of traffic: 4 - ipv4; 6 - ipv6.
 * @return	nothing, this function loops forever,
 * 		until the firewall is stopped.
 */
int hip_fw_handle_packet(char *buf,
			 struct ipq_handle *hndl,
			 int ip_version,
			 hip_fw_context_t *ctx){
	// assume DROP
	int verdict = 0;

// @note unset for performance reasons
#if 0
	// same buffer memory as for packets before -> re-init
	memset(buf, 0, BUFSIZE);
#endif

	/* waits for queue messages to arrive from ip_queue and
	 * copies them into a supplied buffer */
	if (ipq_read(hndl, buf, BUFSIZE, 0) < 0)
	{
		HIP_PERROR("ipq_read failed: ");
		// TODO this error needs to be handled seperately -> die(hndl)?
		goto out_err;
	}

	/* queued messages may be a packet messages or an error messages */
	switch (ipq_message_type(buf))
	{
		case IPQM_PACKET:
			HIP_DEBUG("Received ipqm packet\n");
			// no goto -> go on with processing the message below
			break;
		case NLMSG_ERROR:
			HIP_ERROR("Received error message (%d): %s\n", ipq_get_msgerr(buf), ipq_errstr());
			goto out_err;
			break;
		default:
			HIP_DEBUG("Unsupported libipq packet\n");
			goto out_err;
			break;
	}

	// set up firewall context
	if (hip_fw_init_context(ctx, buf, ip_version))
		goto out_err;

	HIP_DEBUG("packet hook=%d, packet type=%d\n", ctx->ipq_packet->hook, ctx->packet_type);

	// match context with rules
	if (hip_fw_handler[ctx->ipq_packet->hook][ctx->packet_type]) {
		verdict = (hip_fw_handler[ctx->ipq_packet->hook][ctx->packet_type])(ctx);
	} else {
		HIP_DEBUG("Ignoring, no handler for hook (%d) with type (%d)\n");
	}

 out_err:
	if (verdict) {
		HIP_DEBUG("=== Verdict: allow packet ===\n");
		allow_packet(hndl, ctx->ipq_packet->packet_id);
	} else {
		HIP_DEBUG("=== Verdict: drop packet ===\n");
		drop_packet(hndl, ctx->ipq_packet->packet_id);
	}

	// nothing to clean up here as we re-use buf, hndl and ctx

	return 0;
}


void check_and_write_default_config(){
	struct stat status;
	FILE *fp= NULL;
	ssize_t items;
	char *file= HIP_FW_DEFAULT_RULE_FILE;
	int i = 0;

	_HIP_DEBUG("\n");

	/* Firewall depends on hipd to create /etc/hip */
	for (i=0; i<5; i++) {
        	if (stat(DEFAULT_CONFIG_DIR, &status) &&
			errno == ENOENT) {
			HIP_INFO("%s does not exist. Waiting for hipd to start...\n",
 					DEFAULT_CONFIG_DIR);
			sleep(2);
		} else {
			break;
		}
	}

	if (i == 5)
		HIP_DIE("Please start hipd or execute 'hipd -c'\n");

	rename("/etc/hip/firewall.conf", HIP_FW_DEFAULT_RULE_FILE);

	if (stat(file, &status) && errno == ENOENT)
	{
		errno = 0;
		fp = fopen(file, "w" /* mode */);
		if (!fp)
			HIP_PERROR("Failed to write config file\n");
		HIP_ASSERT(fp);
		items = fwrite(HIP_FW_CONFIG_FILE_EX,
		strlen(HIP_FW_CONFIG_FILE_EX), 1, fp);
		HIP_ASSERT(items > 0);
		fclose(fp);
	}
}

void hip_fw_wait_for_hipd() {
	int err = 0;
	char *msg = NULL;

	hip_fw_flush_iptables();

	/* Hipfw should be started before hipd to make sure
	   that nobody can bypass ACLs. However, some hipfw
	   extensions (e.g. userspace ipsec) work consistently
	   only when hipd is started first. To solve this
	   chicken-and-egg problem, we are blocking all hipd
	   messages until hipd is running and firewall is set up */
	system("iptables -N HIPFW-INPUT");
	system("iptables -N HIPFW-OUTPUT");
	system("iptables -N HIPFW-FORWARD");
	system("ip6tables -N HIPFW-INPUT");
	system("ip6tables -N HIPFW-OUTPUT");
	system("ip6tables -N HIPFW-FORWARD");

	system("iptables -I HIPFW-INPUT -p 139 -j DROP");
	system("iptables -I HIPFW-OUTPUT -p 139 -j DROP");
	system("iptables -I HIPFW-FORWARD -p 139 -j DROP");
	system("ip6tables -I HIPFW-INPUT -p 139 -j DROP");
	system("ip6tables -I HIPFW-OUTPUT -p 139 -j DROP");
	system("ip6tables -I HIPFW-FORWARD -p 139 -j DROP");

	system("iptables -I INPUT -j HIPFW-INPUT");
	system("iptables -I OUTPUT -j HIPFW-OUTPUT");
	system("iptables -I FORWARD -j HIPFW-FORWARD");
	system("ip6tables -I INPUT -j HIPFW-INPUT");
	system("ip6tables -I OUTPUT -j HIPFW-OUTPUT");
	system("ip6tables -I FORWARD -j HIPFW-FORWARD");

	//HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc\n");
	//HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_PING, 0), -1, "hdr\n")

	while (hip_fw_get_default_hit() == NULL) {
		HIP_DEBUG("Sleeping until hipd is running...\n");
		sleep(1);
	}

	/* Notice that firewall flushed the dropping rules later */
}

int main(int argc, char **argv){
	int err = 0, highest_descriptor, i;
	int status, n, len;
	long int hip_ha_timeout = 1;
	//unsigned char buf[BUFSIZE];
	struct ipq_handle *h4 = NULL, *h6 = NULL;
	struct rule * rule= NULL;
	struct _DList * temp_list= NULL;
	//struct hip_common * hip_common = NULL;
	//struct hip_esp * esp_data = NULL;
	//struct hip_esp_packet * esp = NULL;
	int escrow_active = 0;
	const int family4 = 4, family6 = 6;
	int ch, tmp;
	const char *default_rule_file= HIP_FW_DEFAULT_RULE_FILE;
	char *rule_file = (char *) default_rule_file;
	char *traffic;
	extern char *optarg;
	extern int optind, optopt;
	int errflg = 0, killold = 0;
	struct hip_common *msg = NULL;
	struct sockaddr_in6 sock_addr;
	socklen_t alen;
	fd_set read_fdset;
	struct timeval timeout;
	unsigned char buf[BUFSIZE];
	hip_fw_context_t ctx;
	int limit_capabilities = 0;
	int is_root = 0, access_ok = 0, msg_type = 0;//variables for accepting user messages only from hipd

	/* Make sure that root path is set up correcly (e.g. on Fedora 9).
	   Otherwise may get warnings from system() commands.
	   @todo: should append, not overwrite  */
	setenv("PATH", HIP_DEFAULT_EXEC_PATH, 1);

	if (geteuid() != 0) {
		HIP_ERROR("firewall must be run as root\n");
		exit(-1);
	}

	memset(&ha_cache, 0, sizeof(ha_cache));
	memset(&default_hit, 0, sizeof(default_hit));
	memset(&proxy_hit, 0, sizeof(default_hit));

	// only needed by hip proxy
	// XX TODO change proxy to use hip_fw_get_default_hit() instead of own variable
	if (hip_proxy_status)
	{
		hip_hit_t *def_hit = hip_fw_get_default_hit();
		if (!hip_query_default_local_hit_from_hipd() && def_hit) {
			ipv6_addr_copy(&proxy_hit, def_hit);
			HIP_DEBUG_HIT("Default hit is ",  &proxy_hit);
		}
	}

	hip_set_logdebug(LOGDEBUG_ALL);

	check_and_write_default_config();

	while ((ch = getopt(argc, argv, "f:t:vdFHAbkiIpehsolF")) != -1)
	{
		switch (ch)
		{
		case 'v':
			log_level = LOGDEBUG_MEDIUM;
			break;
		case 'd':
			log_level = LOGDEBUG_ALL;
			break;
		case 'H':
			accept_normal_traffic_by_default = 0;
			break;
		case 'A':
			accept_hip_esp_traffic_by_default = 1;
			restore_accept_hip_esp_traffic = 1;
			break;
		case 'f':
			rule_file = optarg;
			break;
		case 't':
			hip_ha_timeout = atol(optarg);
			break;
		case ':': /* -f or -p without operand */
			printf("Option -%c requires an operand\n", optopt);
			errflg++;
			break;
		case 'b':
			foreground = 0;
			break;
		case 'k':
			killold = 1;
			break;
		case 'l':
			hip_lsi_support = 1;
			break;
		case 'F':
			filter_traffic = 0;
			restore_filter_traffic = filter_traffic;
			break;
		case 'p':
			limit_capabilities = 1;
			break;
		case 'i':
			hip_userspace_ipsec = 1;
			hip_kernel_ipsec_fallback = 0;
			break;
		case 'I':
			hip_userspace_ipsec = 1;
			hip_kernel_ipsec_fallback = 1;
			break;
		case 'a':
		  //hip_sava_router = 1;
			break;
		case 'c':
		  //hip_sava_client = 1;
		        break;
		case 'e':
			hip_userspace_ipsec = 1;
			hip_esp_protection = 1;
			break;
		case 's':
			hip_stun = 1;
			break;
		case 'h':
			print_usage();
			exit(2);
			break;
		case 'o':
			system_based_opp_mode = 1;
			break;
		case '?':
			printf("Unrecognized option: -%c\n", optopt);
			errflg++;
		}
	}

	if (errflg)
	{
		print_usage();
		printf("Invalid argument. Closing. \n\n");
		exit(2);
	}

	if (!foreground)
	{
		hip_set_logtype(LOGTYPE_SYSLOG);
		HIP_DEBUG("Forking into background\n");
		if (fork() > 0)
			return 0;
	}

	HIP_IFEL(hip_create_lock_file(HIP_FIREWALL_LOCK_FILE, killold), -1,
			"Failed to obtain firewall lock.\n");

	/* Request-response socket with hipfw */
	hip_fw_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_fw_sock < 0), 1, "Could not create socket for firewall.\n");
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_FIREWALL_SYNC_PORT);
	sock_addr.sin6_addr = in6addr_loopback;

	for (i=0; i<2; i++) {
		err = bind(hip_fw_sock, (struct sockaddr *)& sock_addr,
			   sizeof(sock_addr));
		if (err == 0)
			break;
		else if (err && i == 0)
			sleep(2);
	}

	HIP_IFEL(err, -1, "Bind on firewall socket addr failed. Give -k option to kill old hipfw\n");
	HIP_IFEL(hip_daemon_connect(hip_fw_sock), -1,
		 "connecting socket failed\n");

	/* Only for receiving out-of-sync notifications from hipd  */
	hip_fw_async_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_fw_async_sock < 0), 1, "Could not create socket for firewall.\n");
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;
	HIP_IFEL(bind(hip_fw_async_sock, (struct sockaddr *)& sock_addr,
		      sizeof(sock_addr)), -1, "Bind on firewall socket addr failed. Give -k option to kill old hipfw\n");
	HIP_IFEL(hip_daemon_connect(hip_fw_async_sock), -1,
		 "connecting socket failed\n");

	/* Starting hipfw does not always work when hipfw starts first -miika */
	if (hip_userspace_ipsec || hip_sava_router || hip_lsi_support || hip_proxy_status || system_based_opp_mode)
		hip_fw_wait_for_hipd();

	HIP_INFO("firewall pid=%d starting\n", getpid());

	//use by default both ipv4 and ipv6
	HIP_DEBUG("Using ipv4 and ipv6\n");

	if (hip_stun) {
		// initialize TURN database
	}

	read_file(rule_file);
	HIP_DEBUG("Firewall rule table: \n");
	print_rule_tables();
	//running test functions for rule handling
	//  test_parse_copy();
	//  test_rule_management();

	HIP_DEBUG("starting up with rule_file: %s and connection timeout: %d\n",
			rule_file, timeout);

	firewall_increase_netlink_buffers();
#ifndef CONFIG_HIP_OPENWRT
	firewall_probe_kernel_modules();
#endif

	// create firewall queue handles for IPv4 traffic
	// FIXME died handle will still be used below
	h4 = ipq_create_handle(0, PF_INET);

	if (!h4)
		die(h4);

	HIP_DEBUG("IPv4 handle created\n");

	status = ipq_set_mode(h4, IPQ_COPY_PACKET, BUFSIZE);

	if (status < 0)
		die(h4);
	HIP_DEBUG("IPv4 handle mode COPY_PACKET set\n");
	// create firewall queue handles for IPv6 traffic
	// FIXME died handle will still be used below
	h6 = ipq_create_handle(0, PF_INET6);

	_HIP_DEBUG("IPQ error: %s \n", ipq_errstr());

	if (!h6)
		die(h6);
	HIP_DEBUG("IPv6 handle created\n");
	status = ipq_set_mode(h6, IPQ_COPY_PACKET, BUFSIZE);

	if (status < 0)
		die(h6);
	HIP_DEBUG("IPv6 handle mode COPY_PACKET set\n");
	// set up ip(6)tables rules
	HIP_IFEL(firewall_init_rules(), -1,
		 "Firewall init failed\n");
	//get default HIT
	//hip_get_local_hit_wrapper(&proxy_hit);

	/* Allocate message. */
	msg = hip_msg_alloc();
	if (!msg) {
		err = -1;
		return err;
	}

	HIP_IFEL(init_raw_sockets(), -1, "raw sockets");

#ifdef CONFIG_HIP_PRIVSEP
	if (limit_capabilities) {
		HIP_IFEL(hip_set_lowcapability(0), -1, "Failed to reduce priviledges");
	}
#endif
	//init_timeout_checking(timeout);

#ifdef CONFIG_HIP_HIPPROXY
	request_hipproxy_status(); //send hipproxy status request before the control thread running.
#endif /* CONFIG_HIP_HIPPROXY */
	if (!hip_sava_client)
	  request_savah_status(SO_HIP_SAVAH_SERVER_STATUS_REQUEST);
	if(!hip_sava_router)
	  request_savah_status(SO_HIP_SAVAH_CLIENT_STATUS_REQUEST);

	highest_descriptor = maxof(3, hip_fw_async_sock, h4->fd, h6->fd);

	// let's show that the firewall is running even with debug NONE
	HIP_DEBUG("firewall running. Entering select loop.\n");

	// firewall started up, now respect the selected log level
	hip_set_logdebug(log_level);

	// do all the work here
	while (1) {
		// set up file descriptors for select
		FD_ZERO(&read_fdset);
		FD_SET(hip_fw_async_sock, &read_fdset);
		FD_SET(h4->fd, &read_fdset);
		FD_SET(h6->fd, &read_fdset);

		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;

		_HIP_DEBUG("HIP fw select\n");

		// get handle with queued packet and process
		/* @todo: using HIPD_SELECT blocks hipfw with R1 */
		if ((err = select((highest_descriptor + 1), &read_fdset,
				       NULL, NULL, &timeout)) < 0) {
			HIP_PERROR("select error, ignoring\n");
			continue;
		}

		if (FD_ISSET(h4->fd, &read_fdset)) {
			HIP_DEBUG("received IPv4 packet from iptables queue\n");
			err = hip_fw_handle_packet(buf, h4, 4, &ctx);
		}

		if (FD_ISSET(h6->fd, &read_fdset)) {
			HIP_DEBUG("received IPv6 packet from iptables queue\n");
			err = hip_fw_handle_packet(buf, h6, 6, &ctx);
		}

		if (FD_ISSET(hip_fw_async_sock, &read_fdset)) {
			HIP_DEBUG("****** Received HIPD message ******\n");
			bzero(&sock_addr, sizeof(sock_addr));
			alen = sizeof(sock_addr);
			n = recvfrom(hip_fw_async_sock, msg, sizeof(struct hip_common), MSG_PEEK,
		             (struct sockaddr *)&sock_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Error receiving message header from daemon.\n");
				err = -1;
				continue;
			}


			/*making sure user messages are received from hipd*/
			//resetting vars to 0 because it is a loop
			is_root = 0, access_ok = 0, msg_type = 0;
			msg_type = hip_get_msg_type(msg);
			is_root = (ntohs(sock_addr.sin6_port) < 1024);
			if(is_root){
				access_ok = 1;
			}else if( !is_root &&
				  (msg_type >= HIP_SO_ANY_MIN &&
				   msg_type <= HIP_SO_ANY_MAX)    ){
				access_ok = 1;
			}
			if(!access_ok){
				HIP_ERROR("The sender of the message is not trusted.\n");
				err = -1;
				continue;
			}


			_HIP_DEBUG("Header received successfully\n");
			alen = sizeof(sock_addr);
			len = hip_get_msg_total_len(msg);

			HIP_DEBUG("Receiving message type %d (%d bytes)\n",
				  hip_get_msg_type(msg), len);
			n = recvfrom(hip_fw_async_sock, msg, len, 0,
		             (struct sockaddr *)&sock_addr, &alen);

			if (n < 0)
			{
				HIP_ERROR("Error receiving message parameters from daemon.\n");
				err = -1;
				continue;
			}

			HIP_ASSERT(n == len);

			if (ntohs(sock_addr.sin6_port) != HIP_DAEMON_LOCAL_PORT) {
			  	int type = hip_get_msg_type(msg);
			        if (type == SO_HIP_FW_BEX_DONE){
				  HIP_DEBUG("SO_HIP_FW_BEX_DONE\n");
				  HIP_DEBUG("%d == %d\n", ntohs(sock_addr.sin6_port), HIP_DAEMON_LOCAL_PORT);
				}
				HIP_DEBUG("Drop, message not from hipd\n");
				err = -1;
				continue;

			}

			err = handle_msg(msg, &sock_addr);
			if (err < 0){
				HIP_ERROR("Error handling message\n");
				continue;
				//goto out_err;
			}
		}
	}

 out_err:
	if (hip_fw_async_sock)
		close(hip_fw_async_sock);
	if (hip_fw_sock)
		close(hip_fw_sock);
	if (msg != NULL)
		HIP_FREE(msg);

	firewall_exit();
	return 0;
}


/**
 * Loads several modules that are neede by th firewall.
 *
 * @return	nothing.
 */
void firewall_probe_kernel_modules(){
	int count, err, status;
	char cmd[40];
	int mod_total;
	char *mod_name[] =
	{ "ip_queue", "ip6_queue", "iptable_filter", "ip6table_filter" };

	mod_total = sizeof(mod_name) / sizeof(char *);

	HIP_DEBUG("Probing for %d modules. When the modules are built-in, the errors can be ignored\n", mod_total);

	for (count = 0; count < mod_total; count++)
	{
		snprintf(cmd, sizeof(cmd), "%s %s", "/sbin/modprobe",
				mod_name[count]);
		HIP_DEBUG("%s\n", cmd);
		err = fork();
		if (err < 0)
			HIP_ERROR("Failed to fork() for modprobe!\n");
		else if (err == 0)
		{
			/* Redirect stderr, so few non fatal errors wont show up. */
			stderr = freopen("/dev/null", "w", stderr);
			execlp("/sbin/modprobe", "/sbin/modprobe",
					mod_name[count], (char *)NULL);
		}
		else
			waitpid(err, &status, 0);
	}
	HIP_DEBUG("Probing completed\n");
}


/**
 * Increases the netlink buffer capacity.
 *
 * The previous default values were:
 *
 * /proc/sys/net/core/rmem_default - 110592
 * /proc/sys/net/core/rmem_max     - 131071
 * /proc/sys/net/core/wmem_default - 110592
 * /proc/sys/net/core/wmem_max     - 131071
 *
 * The new value 1048576=1024*1024 was assigned to all of them
 *
 * @return	nothing.
 */
void firewall_increase_netlink_buffers(){
	HIP_DEBUG("Increasing the netlink buffers\n");

	system("echo 1048576 > /proc/sys/net/core/rmem_default");
	system("echo 1048576 > /proc/sys/net/core/rmem_max");
	system("echo 1048576 > /proc/sys/net/core/wmem_default");
	system("echo 1048576 > /proc/sys/net/core/wmem_max");
}


/* Get default HIT*/
int hip_query_default_local_hit_from_hipd(void)
{
	int err = 0;
	struct hip_common *msg = NULL;
	struct hip_tlv_common *param = NULL;
	hip_hit_t *hit  = NULL;

	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT,0),-1,
		 "Fail to get hits");
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1,
		 "send/recv daemon info\n");

	HIP_IFE(!(param = hip_get_param(msg, HIP_PARAM_HIT)), -1);
	hit = hip_get_param_contents_direct(param);
	ipv6_addr_copy(&default_hit, hit);

	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_LSI)), -1,
		 "Did not find LSI\n");
	memcpy(&local_lsi, hip_get_param_contents_direct(param),
	       sizeof(local_lsi));
out_err:
	if (msg)
		free(msg);

	return err;
}


/* TODO move this and next function where they belong
 *
 * @note located in user_ipsec_api before, but now also used for proxy
 */
hip_hit_t *hip_fw_get_default_hit(void)
{
	// only query for default hit if global variable is not set
	if (ipv6_addr_is_null(&default_hit))
	{
		_HIP_DEBUG("Querying hipd for default hit\n");
		if (hip_query_default_local_hit_from_hipd())
			return NULL;
	}

	return &default_hit;
}

int hip_fw_sys_opp_set_peer_hit(struct hip_common *msg) {
	int err = 0, state;
	hip_hit_t *local_hit, *peer_hit;
	struct in6_addr *local_addr, *peer_addr;

	local_hit = hip_get_param_contents(msg, HIP_PARAM_HIT_LOCAL);
	peer_hit = hip_get_param_contents(msg, HIP_PARAM_HIT_PEER);
	local_addr = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_LOCAL);
	peer_addr = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_PEER);

	if (peer_hit)
		state = FIREWALL_STATE_BEX_ESTABLISHED;
	else
		state = FIREWALL_STATE_BEX_NOT_SUPPORTED;

	firewall_update_entry(local_hit, peer_hit, local_addr,
			      peer_addr, state);

out_err:
	return err;
}

/**
 * Gets the state of the bex for a pair of ip addresses.
 * @param *src_ip	input for finding the correct entries
 * @param *dst_ip	input for finding the correct entries
 * @param *src_hit	output data of the correct entry
 * @param *dst_hit	output data of the correct entry
 * @param *src_lsi	output data of the correct entry
 * @param *dst_lsi	output data of the correct entry
 *
 * @return		the state of the bex if the entry is found
 *			otherwise returns -1
 */
int hip_get_bex_state_from_IPs(struct in6_addr *src_ip,
		      	       struct in6_addr *dst_ip,
			       struct in6_addr *src_hit,
			       struct in6_addr *dst_hit,
			       hip_lsi_t       *src_lsi,
			       hip_lsi_t       *dst_lsi){
	int err = 0, res = -1;
	struct hip_tlv_common *current_param = NULL;
	struct hip_common *msg = NULL;
	struct hip_hadb_user_info_state *ha;

	HIP_ASSERT(src_ip != NULL && dst_ip != NULL);

	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0),
			-1, "Building of daemon header failed\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1, "send recv daemon info\n");

	while((current_param = hip_get_next_param(msg, current_param)) != NULL) {
		ha = hip_get_param_contents_direct(current_param);

		if( (ipv6_addr_cmp(dst_ip, &ha->ip_our) == 0) &&
		    (ipv6_addr_cmp(src_ip, &ha->ip_peer) == 0) ){
			*src_hit = ha->hit_peer;
			*dst_hit = ha->hit_our;
			*src_lsi = ha->lsi_peer;
			*dst_lsi = ha->lsi_our;
			res = ha->state;
			break;
		}else if( (ipv6_addr_cmp(src_ip, &ha->ip_our) == 0) &&
		         (ipv6_addr_cmp(dst_ip, &ha->ip_peer) == 0) ){
			*src_hit = ha->hit_our;
			*dst_hit = ha->hit_peer;
			*src_lsi = ha->lsi_our;
			*dst_lsi = ha->lsi_peer;
			res = ha->state;
			break;
		}
	}

 out_err:
        if(msg)
                HIP_FREE(msg);
        return res;

}

/**
 * Checks whether a particular hit is one of the local ones.
 * Goes through all the local hits and compares with the given hit.
 *
 * @param *hit	the input src hit
 *
 * @return	1 if *hit is a local hit
 * 		0 otherwise
 */
int hit_is_local_hit(struct in6_addr *hit){
	struct hip_tlv_common *current_param = NULL;
	struct endpoint_hip   *endp = NULL;
	struct hip_common     *msg = NULL;
	hip_tlv_type_t         param_type = 0;
	int res = 0, err = 0;

	HIP_DEBUG("\n");

	/* Build a HIP message with socket option to get all HITs. */
	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
	hip_msg_init(msg);
	HIP_IFE(hip_build_user_hdr(msg, SO_HIP_GET_HITS, 0), -1);

	/* Send the message to the daemon.
	The daemon fills the message. */
	HIP_IFE(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -ECOMM);

	/* Loop through all the parameters in the message just filled. */
	while((current_param = hip_get_next_param(msg, current_param)) != NULL){

		param_type = hip_get_param_type(current_param);

		if(param_type == HIP_PARAM_EID_ENDPOINT){
			endp = (struct endpoint_hip *)
				hip_get_param_contents_direct(
					current_param);

			if(ipv6_addr_cmp(hit, &endp->id.hit) == 0)
				return 1;
		}
	}
 out_err:
	return res;
}

void hip_fw_add_non_hip_peer(hip_fw_context_t *ctx);

/**
 * Checks if the outgoing packet has already ESTABLISHED
 * the Base Exchange with the peer host. In case the BEX
 * is not done, it triggers it. Otherwise, it looks up
 * in the local database the necessary information for
 * doing the packet reinjection with HITs.
 *
 * @param *ctx	the contect of the packet
 * @return	the verdict for the packet
 */
int hip_fw_handle_outgoing_system_based_opp(hip_fw_context_t *ctx) {
	int err, msg_type, state_ha, fallback, reject, new_fw_entry_state;
	struct in6_addr src_lsi, dst_lsi;
	struct in6_addr src_hit, dst_hit;
	struct in6_addr src6_ip, dst6_ip;
	firewall_hl_t *entry_peer = NULL;
	struct sockaddr_in6 all_zero_hit;
	int verdict = accept_normal_traffic_by_default;

	HIP_DEBUG("\n");

	//get firewall db entry
	entry_peer = firewall_ip_db_match(&ctx->dst);
	if (entry_peer) {
		//if the firewall entry is still undefined
		//check whether the base exchange has been established
		if (entry_peer->bex_state == FIREWALL_STATE_BEX_DEFAULT) {
			//get current connection state from hipd
			state_ha = hip_get_bex_state_from_IPs(&ctx->src,
							      &ctx->dst,
							      &src_hit,
							      &dst_hit,
							      &src_lsi,
							      &dst_lsi);

			//find the correct state for the fw entry state
			if (state_ha == HIP_STATE_ESTABLISHED)
				new_fw_entry_state = FIREWALL_STATE_BEX_ESTABLISHED;
			else if ((state_ha == HIP_STATE_FAILED)  ||
				 (state_ha == HIP_STATE_CLOSING) ||
				 (state_ha == HIP_STATE_CLOSED)) {
				new_fw_entry_state = FIREWALL_STATE_BEX_NOT_SUPPORTED;

			} else
				new_fw_entry_state = FIREWALL_STATE_BEX_DEFAULT;

			HIP_DEBUG("New state %d\n", new_fw_entry_state);
			//update fw entry state accordingly
			firewall_update_entry(&src_hit, &dst_hit, &dst_lsi,
					      &ctx->dst, new_fw_entry_state);

			//reobtain the entry in case it has been updated
			entry_peer = firewall_ip_db_match(&ctx->dst);
		}

		//decide what to do with the packet
		if(entry_peer->bex_state == FIREWALL_STATE_BEX_DEFAULT)
			verdict = 0;
		else if (entry_peer->bex_state == FIREWALL_STATE_BEX_NOT_SUPPORTED) {
			hip_fw_add_non_hip_peer(ctx);
			verdict = accept_normal_traffic_by_default;
		} else if (entry_peer->bex_state == FIREWALL_STATE_BEX_ESTABLISHED){
			if( &entry_peer->hit_our                       &&
			    (ipv6_addr_cmp(hip_fw_get_default_hit(),
					   &entry_peer->hit_our) == 0)    ){
				reinject_packet(&entry_peer->hit_our,
						&entry_peer->hit_peer,
						ctx->ipq_packet, 4, 0);
				verdict = 0;
			} else {
				verdict = accept_normal_traffic_by_default;
			}
		}
	} else {
		/* add default entry in the firewall db */
		firewall_add_default_entry(&ctx->dst);

		/* get current connection state from hipd */
		state_ha = hip_get_bex_state_from_IPs(&ctx->src, &ctx->dst,
						      &src_hit, &dst_hit,
						      &src_lsi, &dst_lsi);
		if (state_ha == -1) {
			hip_hit_t *def_hit = hip_fw_get_default_hit();
			HIP_DEBUG("Initiate bex at firewall\n");
			memset(&all_zero_hit, 0, sizeof(struct sockaddr_in6));
			hip_request_peer_hit_from_hipd_at_firewall(
				&ctx->dst,
				&all_zero_hit.sin6_addr,
				(const struct in6_addr *) def_hit,
				(in_port_t *) &(ctx->transport_hdr.tcp)->source,
				(in_port_t *) &(ctx->transport_hdr.tcp)->dest,
				&fallback,
				&reject);
			verdict = 0;
		} else if (state_ha == HIP_STATE_ESTABLISHED) {
			if (hit_is_local_hit(&src_hit)) {
				HIP_DEBUG("is local hit\n");
				firewall_update_entry(&src_hit, &dst_hit,
						      &dst_lsi, &ctx->dst,
						      FIREWALL_STATE_BEX_ESTABLISHED);
				reinject_packet(&src_hit, &dst_hit,
						ctx->ipq_packet, 4, 0);
				verdict = 0;
			} else {
				verdict = accept_normal_traffic_by_default;
			}
		} else if ((state_ha == HIP_STATE_FAILED)  ||
			  (state_ha == HIP_STATE_CLOSING) ||
			   (state_ha == HIP_STATE_CLOSED)) {
			verdict = accept_normal_traffic_by_default;
		} else {
			verdict = 0;
		}
	}

out_err:
	return verdict;
}

void hip_fw_flush_system_based_opp_chains(void)
{
	system("iptables -F HIPFWOPP-INPUT");
	system("iptables -F HIPFWOPP-OUTPUT");
}

void hip_fw_add_non_hip_peer(hip_fw_context_t *ctx)
{
	char command[64];
	char addr_str[INET_ADDRSTRLEN];
	struct in_addr addr_v4;

	IPV6_TO_IPV4_MAP(&ctx->dst, &addr_v4);

	if (!inet_ntop(AF_INET, &addr_v4, addr_str,
				sizeof(struct sockaddr_in))) {
		HIP_ERROR("inet_ntop() failed\n");
		return;
	}

	HIP_DEBUG("Adding rule for non-hip-capable peer: %s\n", addr_str);

	snprintf(command, sizeof(command), "iptables -I HIPFWOPP-INPUT -s %s -j %s",
			addr_str, accept_normal_traffic_by_default ? "ACCEPT" : "DROP");
	system(command);
	snprintf(command, sizeof(command), "iptables -I HIPFWOPP-OUTPUT -d %s -j %s",
			addr_str, accept_normal_traffic_by_default ? "ACCEPT" : "DROP");
	system(command);
}

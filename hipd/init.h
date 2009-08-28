#ifndef _HIPD_INIT
#define _HIPD_INIT
#include <sys/types.h>
#include <sys/stat.h> 
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <linux/icmpv6.h>
#include "xfrmapi.h"
#include "hipconf.h"
#include "oppipdb.h"
#include "debug.h"
#include "hiprelay.h"
#include "escrow.h"
/* added by Tao Wan on 14.Jan.2008 */
#include "tcptimeout.h"
#include "hadb.h"
#include "hi3.h"
#include "nsupdate.h"

/*
 * HIP daemon initialization functions.
 *
 */

/**
 * HIP daemon lock file is used to prevent multiple instances
 * of the daemon to start and to record current daemon pid.
 */ 
#define HIP_DAEMON_LOCK_FILE	"/var/lock/hipd.lock"
#define USER_NOBODY "nobody"


/** ICMPV6_FILTER related stuff **/
#define BIT_CLEAR(nr, addr) do { ((__u32 *)(addr))[(nr) >> 5] &= ~(1U << ((nr) & 31)); } while(0)
#define BIT_SET(nr, addr) do { ((__u32 *)(addr))[(nr) >> 5] |= (1U << ((nr) & 31)); } while(0)
#define BIT_TEST(nr, addr) do { (__u32 *)(addr))[(nr) >> 5] & (1U << ((nr) & 31)); } while(0)

#ifndef ICMP6_FILTER_WILLPASS
#define ICMP6_FILTER_WILLPASS(type, filterp) \
        (BIT_TEST((type), filterp) == 0)

#define ICMP6_FILTER_WILLBLOCK(type, filterp) \
        BIT_TEST((type), filterp)

#define ICMP6_FILTER_SETPASS(type, filterp) \
        BIT_CLEAR((type), filterp)

#define ICMP6_FILTER_SETBLOCK(type, filterp) \
        BIT_SET((type), filterp)

#define ICMP6_FILTER_SETPASSALL(filterp) \
        memset(filterp, 0, sizeof(struct icmp6_filter));

#define ICMP6_FILTER_SETBLOCKALL(filterp) \
        memset(filterp, 0xFF, sizeof(struct icmp6_filter));
#endif
/** end ICMPV6_FILTER related stuff **/

#define USER_NOBODY "nobody"


/* the /etc/hip/dhtservers file*/
#define HIPD_DHTSERVERS_FILE     "/etc/hip/dhtservers"
#define HIPD_DHTSERVERS_FILE_EX \
"193.167.187.134 hipdht2.infrahip.net\n"


extern char *i3_config_file;
//extern char *hip_i3_config_file;
extern int hip_use_i3;
extern hip_ipsec_func_set_t default_ipsec_func_set;
extern int hip_firewall_sock_fd;
extern int hip_firewall_sock_lsi_fd;

int hip_associate_default_hit_lsi();

int hipd_init(int flush_ipsec, int killold);
int hip_init_host_ids();
int hip_init_raw_sock_v6(int *hip_raw_sock_v6);
/**
 * Creates a UDP socket for NAT traversal.
 *
 * @param  hip_nat_sock_udp	a pointer to the UDP socket.
 * @param  close_		the socket will be closed before recreation
 * 				if close_ is nonzero
 * 
 * @return zero on success, negative error value on error.
 */
int hip_create_nat_sock_udp(int *hip_nat_sock_udp, char close_);
int init_random_seed();
void hip_close(int signal);
void hip_exit(int signal);
void hip_probe_kernel_modules();
int hip_init_dht();
int hip_init_certs();
struct hip_host_id_entry * hip_return_first_rsa(void);
#endif /* _HIP_INIT */


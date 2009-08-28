#ifndef I3_CLIENT_H
#define I3_CLIENT_H

#if !defined(_WIN32)
    #include <unistd.h>
    #include <sys/time.h>
#else
    #include <time.h>
#endif
#include "../utils/netwrap.h"

#include "i3_client_params.h"
#include "i3server_list.h"
#include "i3_client_fd.h"
#include "../utils/event.h"

#define CL_CBK_TRIGGER_INSERTED       1        
#define CL_CBK_TRIGGER_REFRESH_FAILED 2        
#define CL_CBK_TRIGGER_NOT_FOUND      3
#define CL_CBK_RECEIVE_PACKET         4
#define CL_CBK_RECEIVE_PAYLOAD        5
#define CL_CBK_SERVER_DOWN            6
#define CL_CBK_TRIGGER_CONSTRAINT_FAILED 7
#define CL_CBK_ROUTE_BROKEN	      8
#define CL_CBK_RATELIMIT_EXCEEDED     9


#define CL_INTERNAL_HOOK_TRIGGER_ACK_TIMEOUT        100
#define CL_INTERNAL_HOOK_TRIGGER_REFRESH_TIMEOUT    101

#define CL_RET_OK                      0
#define CL_RET_TRIGGER_ALREADY_CREATED 1
#define CL_RET_TRIGGER_NOT_FOUND       2
#define CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD 3   
#define CL_RET_DUP_CONTEXT             4
#define CL_RET_NO_CONTEXT              5
#define CL_RET_NO_TRIGGER              6
#define CL_RET_TRIGGER_ALREADY_EXISTS 11
#define CL_RET_NO_AUTO_SERVER_SELECT  12
#define CL_RET_NOT_LOCAL_TRIGGER      13
#define CL_RET_INVALID_TRIGGER_TYPE   14
#define CL_RET_DUPLICATE_FD           15
#define CL_RET_INVALID_FD             16
#define CL_RET_INVALID_CFG_FILE       17
#define CL_RET_INVALID_FLAGS          18
#define CL_RET_INVALID_STACK_LEN      20
#define CL_RET_NET_ERROR	      21
#define CL_RET_MSG_SIZE		      22
#define CL_RET_NO_SERVERS	      23

#define CL_TRIGGER_STATUS_IDLE   0
#define CL_TRIGGER_STATUS_PENDING  1
#define CL_TRIGGER_STATUS_INSERTED 2

#define CL_TRIGGER_I3    0
#define CL_TRIGGER_LOCAL 1

#define CL_FD_TYPE_READ   1
#define CL_FD_TYPE_WRITE  2
#define CL_FD_TYPE_EXCEPT 3

/* flags associated with trigger creation */
#define CL_TRIGGER_CFLAG_R_CONSTRAINT 0x1
#define CL_TRIGGER_CFLAG_L_CONSTRAINT (0x1 << 1)
#define CL_TRIGGER_CFLAG_PUBLIC       (0x1 << 2)
#define CL_TRIGGER_CFLAG_PRIVATE       (0x1 << 3)

//#define CL_TRIGGER_CFLAG_UNCONSTRAINED (0x1 << 4)

/* flags associated to trigger insertion */
#define CL_IFLAGS_TRIGGER_ALLOW_SHORTCUT 0x1
#define CL_IFLAGS_TRIGGER_LOCAL          (0x1 << 1)

/* flags associated with sending a packet */
#define CL_PKT_FLAG_ALLOW_SHORTCUT     0x1

#define EOL          0xa
#define MAX_BUF_SIZE 2048

#define CL_HTABLE_SIZE 1024*64

#define UMILLION 1000000ULL

/****************************************************************************
 *  Macro definitions
 ****************************************************************************/

#define CL_HASH_ID(id) (((*(uint32_t *)&(id)->x[0])^(*(uint32_t *)&(id)->x[4]) ^ (*(uint32_t *)&(id)->x[8]) ^ (*(uint32_t *)&(id)->x[12]))% CL_HTABLE_SIZE)

#define CL_HASH_TRIG(id) (((*(uint32_t *)&(id)->x[0])^(*(uint32_t *)&(id)->x[4])^ (*(uint32_t *)&(id)->x[8]) ^ (*(uint32_t *)&(id)->x[12]))% CL_HTABLE_SIZE)

/* #define CL_HASH_TRIG(id) (((*(uint32_t *)&(id)->x[0])^(*(uint32_t *)&(id)->x[4])^ (*(uint32_t *)&(id)->x[8]) ^ (*(uint32_t *)&(id)->x[12]) ^ (*(uint32_t *)&(id)->x[16]) ^ (*(uint32_t *)&(id)->x[20]) ^ (*(uint32_t *)&(id)->x[24]) ^ (*(uint32_t *)&(id)->x[28]))% CL_HTABLE_SIZE) */


/****************************************************************************
 *  Data structures
 ****************************************************************************/

typedef struct buf_struct {
  unsigned short  len;
  char *p;
} buf_struct;


#ifndef CCURED
typedef struct cl_cbk {
  void (*fun)();  /* pointer to callback function */
  void *fun_ctx;     /* pointer to the function context information specified while registering the callback */
		     
} cl_cbk;
#else
#ifndef __RTTI
  #define __RTTI
#endif
typedef struct cl_cbk {
  void (*fun)(i3_trigger*, void * __RTTI);  /* pointer to callbcak function */
  void * __RTTI fun_ctx;     /* pointer to the function context information specified while registering the callback */
} cl_cbk;
#endif
		     

typedef struct cl_trigger {
  i3_trigger        *t;
  buf_struct         precomputed_pkt;
  char               type; /* specify whether the trigger is inserted only 
                            * locally (CL_TRIGGER_LOCAL) or is inserted in 
			    * i3 (CL_TRIGGER_I3) 
                            */
  char		     is_queued; /* true when it is inserted in PRIORITY QUEUE.
				 * the priority queue is used to efficiently
                                 * refresh triggers
                                 */
  uint16_t           status; /* possible status: CL_TRIGGER_STATUS_PENDING, 
			      * CL_TRIGGER_STATUS_INSERTED 
			      * CL_TRIGGER_STATUS_IDLE 
                              */
  int                retries_cnt;
  cl_cbk cbk_trigger_inserted; /* callback confirming that the trigger
				* has been inserted 
                                */
  cl_cbk cbk_trigger_refresh_failed;/* trigger cannot be inserted 
				     * or trigger couldn't be refreshed 
                                     */
  cl_cbk cbk_trigger_constraint_failed; /* constraint fails at server */
  cl_cbk cbk_receive_packet;    /* callback triggered when a packet 
				 * arrives to this trigger 
                                 */
  cl_cbk cbk_receive_payload;   /* callback triggered when a packet 
				 * arrives to this trigger
				 * NOTE 1: cbk_receive_packet has a higher
				 * precedence than cbk_receive_data; if both
				 * of these callbacks are specified, only 
				 * cbk_receive_data will called
				 * NOTE 2: the only difference between 
				 * cbk_receive_data and cbk_receive_packet
				 * is that cbk_receive_packet returns
                                 * the packet's header (hdr) in addition 
                                 */
  cl_cbk cbk_route_broken;	/* triggered when an i3_server 
				 * attempting to forward a packet
				 * along this trigger discovers that
				 * the i3_server corres to the next
				 * hop is down 
                                 */

  /** This is an internal hook which is triggered whenever a trigger ack timeout
    * needs to be set.  This is used only when an external select() statement
    * is used (as in the proxy).
    */
  cl_cbk internal_hook_ack_timeout;

  /** This is an internal hook which is triggered whenever a trigger refresh timeout
    * needs to be set.  This is used only when an external select() statement
    * is used (as in the proxy).
    */
  cl_cbk internal_hook_refresh_timeout;
  
  void  *ctx;                   /* trigger's context */
  void  *timer;                 /* pointer to the current timeout associated
                                 * to the trigger (e.g., timeout)
				 */
  struct cl_trigger *next;
  struct cl_trigger *prev;
} cl_trigger;


typedef struct cl_id {
  ID                 id;
  struct sockaddr_in cache_addr; /* address where packets with the
			          * the identifier "id" are sent;
                                  * data is stored in network format 
			          */
  struct sockaddr_in dest_addr;  /* destination address. Returned
                                  * by the I3_OPT_CACHE_DEST_ADDR and
				  * I3_OPT_CACHE_SHORTCUT_ADDR options
				  */
  int            retries_cnt;     
  struct timeval last_ack;  /* time when last request for ack 
			       has been sent */
  cl_cbk    cbk_no_trigger; /* callback invoked when no trigger
                             * matching the "id" filed was found 
                             */
#if NEWS_INSTRUMENT
  int		opt_log_pkt;
  int		opt_add_ts;
#endif
  struct cl_id *next;
  struct cl_id *prev;
} cl_id;


/* maintain the list of i3 servers read from the configuration file */
 #define MAX_NUM_SRV 20
typedef struct srv_address {
  struct in_addr addr;
  uint16_t port;
  ID id;
#define ID_EMPTY 0
#define ID_UP    1
#define ID_DOWN  2
  char     status;
} srv_address;

/* Maintain array of precomputed options */
#define MAX_OPTS_MASK_SIZE (1 << 3) + 1
#define REFRESH_MASK (1 << 0)
#define LOG_PKT_MASK (1 << 1)
#define APP_TS_MASK  (1 << 2)
#define REFRESH_SHORTCUT_MASK (1 << 3)

typedef struct {
  nw_skt_t                fd;    /* file descriptor for i3 packets */
  struct sockaddr_in local; /* local address, used to receive i3 traffic 
			     * (in network format)
			     */
  struct in_addr local_ip_addr; /* local IP address; this field is
				 * needed because the IP address in 
				 * "local" data structure is set to
				 * INADDR_ANY (host format)
				 */
  uint16_t        local_port; /* local port number (host format) */           
  struct timeval  now; /* updated every time cl_refresh_context 
			* is invoked */

  nw_skt_t	tcp_fd;		/* Filedes for TCP connection */
  char		is_tcp;		/* 1 if tcp connection is used */
  
  cl_cbk cbk_trigger_not_found;  /* callback invoked when there is no trigger
                                  * matching the ID of the transmitted 
                                  * packet */ 
  cl_cbk cbk_server_down;        /* callback invoked when an i3 server
				  * couldn't be contacted */ 
  /* following callbacks are called when the corresponding callbacks 
   * associated with the trigger are not defined */
  cl_cbk cbk_trigger_inserted; /* callback confirming that the trigger
				* has been inserted 
				*/
  cl_cbk cbk_trigger_refresh_failed;/* trigger cannot be inserted 
				     * or trigger couldn't be refreshed */
  cl_cbk cbk_trigger_constraint_failed; /* constraint fails at server */
    
  cl_cbk cbk_receive_packet;    /* callback triggered when a packet 
				 * arrives to this trigger */
  cl_cbk cbk_receive_payload;   /* callback triggered when a packet 
				 * arrives to this trigger
				 * NOTE 1: cbk_receive_packet has a higher
				 * precedence than cbk_receive_data; if both
				 * of these callbacks are specified, only 
				 * cbk_receive_data will called
				 * NOTE 2: the only difference between 
				 * cbk_receive_data and cbk_receive_packet
				 * is that cbk_receive_packet returns
                                 * the packet's header (hdr) in addition */
  cl_cbk cbk_route_broken;	/* triggered when an i3_server when
				   attempting to forward a packet
				   along this trigger discovers that
				   the i3_server corres to the next
				   hop is down */
  
  cl_cbk cbk_ratelimit_exceeded; /* callback invoked when the token-bucket
				  * constraints of trigger that matches the
				  * packet's ID are exceeded
				  */
  cl_trigger      *trigger_htable[CL_HTABLE_SIZE];
  cl_id           *id_htable[CL_HTABLE_SIZE];
  srv_address     *s_array;
  int		  num_servers;
  buf_struct	  precomputed_opt[MAX_OPTS_MASK_SIZE];
  I3ServerList	*list;
  EventHeap       timer_heap; /* heap managing timers */
#define MAX_FDS 1024
  i3_fds         *i3fds; /* list of file descriptors */
  uint64_t *ping_start_time;

  /** Is pinging being used to choose the best i3 server
   * 0 - no
   * 1 - true
   */
  unsigned short use_ping;

  /** TCP socket was successfully initialized if this flag is 1.
    * Else the flag is 0.
    */
  int init_tcp_ctx_flag;
  
} cl_context;


/* this data structure is used to send/receive data while eliminating 
 * an extra memory copy
 */
typedef struct cl_buf {
#define CL_PREFIX_LEN   512
  char *data;            /* pointer to the payload */
  unsigned int data_len; /* length of the payload */
  unsigned int max_len;  /* maximum length that can be used for payload */
  char *internal_buf;    /* pointer to the allocated buffer. the size of 
                          * this buffer is max_len + 2*CL_PREFIX_LEN.
			  * the "data" pointer is between (internal_buf + 
			  * CL_PREFIX_LEN) and (internal_buf + 2*CL_PREFIX_LEN)
			  */
} cl_buf;


#endif // I3_CLIENT_H

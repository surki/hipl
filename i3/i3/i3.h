/***************************************************************************
                          i3.h  -  description
                             -------------------
    begin                : Son Nov 17 2002
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef I3_H
#define I3_H 
 
#include <sys/types.h>
#ifdef _WIN32
    #include "../utils/fwint.h"
#endif
#include "../utils/netwrap.h"
#ifdef __APPLE__
#include <inttypes.h>  // Need uint8_t
#include <sys/time.h>  // Need timeval
#endif
#include <assert.h>

/* CLIENT_API_DEPRECIATED specifies whether the old client api is used */
//#define  CLIENT_API_DEPRECIATED

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif  

#define CHAR_BITS 8

// first byte in a packet sent to an i3 server
//   - normal i3 packet --> version number
//   - i3 ping packet --> I3_PING_PACKET

// note that i3 ping packets are not i3 packets; ping responses
// should be from a different process, but for fatesharing reasons
// implemented together 
#define I3_v01          0x10
#define I3_PING_PKT	0x01

#define I3_DATA         0x10
#define I3_OPTION_LIST  0x20
#define I3_FIRST_HOP    0x40

#define I3_ADDR_TYPE_STACK 0x10
#define I3_ADDR_TYPE_IPv4  0x20
#define I3_ADDR_TYPE_IPv6  0x30
#define I3_ADDR_TYPE_IPv4_NAT 0x40

#define I3_ID_TYPE_PUBLIC	0x10
#define I3_ID_TYPE_PRIVATE	0x20
//#define I3_ID_TYPE_UNCONSTRAINED 0x30
#define I3_ID_TYPE_UNKNOWN      0x40

#define I3_OPT_SENDER			0x01
#define I3_OPT_TRIGGER_INSERT		0x02
#define I3_OPT_TRIGGER_CHALLENGE	0x03
#define I3_OPT_TRIGGER_ACK		0x04
#define I3_OPT_TRIGGER_REMOVE		0x05
#define I3_OPT_TRIGGER_NOT_PRESENT	0x06
#define I3_OPT_REQUEST_FOR_CACHE	0x07
#define I3_OPT_CACHE_ADDR		0x08
#define I3_OPT_FORCE_CACHE_ADDR		0x09
#define I3_OPT_CONSTRAINT_FAILED	0x10
#define I3_OPT_ROUTE_BROKEN		0x11
#define I3_OPT_REQUEST_FOR_CACHE_SHORTCUT 0x12
#define I3_OPT_CACHE_SHORTCUT_ADDR      0x13
#define I3_OPT_CACHE_DEST_ADDR          0x14
#define I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR 0x15
#define I3_OPT_DESTINATION              0x20
#define I3_OPT_TRIGGER_RATELIMIT	0x30

/* flags associated to trigger */
#define I3_TRIGGER_FLAG_ALLOW_SHORTCUT  0x1
#define I3_TRIGGER_FLAG_RATE_LIMIT      0x2

#define I3_ERR_INVALID_VER       -1
#define I3_ERR_INVALID_FLAGS     -2
#define I3_ERR_PKT_LEN_TOO_SHORT -3
#define I3_ERR_INVALID_STACK     -4
#define I3_ERR_INVALID_ADDR      -5
#define I3_ERR_INVALID_OPTLIST   -6
#define I3_ERR_INVALID_OPTION    -7

#define L_CONSTRAINT 0
#define R_CONSTRAINT 1

#define NEWS_INSTRUMENT 1

#if NEWS_INSTRUMENT
// 2 options for instrumenting i3 servers
// maybe modified later for cleanliness
#define I3_OPT_LOG_PACKET		0x0A
#define I3_OPT_APPEND_TS		0x0B
#define MAX_NEWS_OPTS			2
#endif

#define OK              1
#define ERROR           0

#define INDENT_CONST    2 	/* just for printing data nice for debugging */
#define INDENT_BUF_LEN  100 	/* just for printing data nice for debugging */


/******************************
 ** Type of an i3-id         **
 ******************************/

#define ID_LEN         	32  /* in bytes */
#define ID_LEN_BITS    	256 /* in bits, i.e., ID_LEN_BITS = ID_LEN*8 */
#define MIN_PREFIX_LEN 	192 /* minimum prefix length that has to match */

#define PREFIX_LEN      8
#define KEY_LEN		16  /* length of key in bytes */

#define PREFIX_ID(id)	(id.x)
#define KEY_ID(id)	(id.x + PREFIX_LEN)
#define KEY_ID_PTR(id)	(id->x + PREFIX_LEN)
#define SUFFIX_ID(id)	(id.x + SUFFIX_LEN)
typedef struct 
{
  uint8_t x[ID_LEN];
} ID;

typedef struct
{
  uint8_t x[KEY_LEN];
} Key;

/******************************
 ** structure of an i3-stack **
 ******************************/
        
#define I3_MAX_STACK_LEN 15
typedef struct i3_stack {
  int len; /* # of IDs in the stack */
  ID *ids;
} i3_stack;


/********************************
 ** structure of an i3 address **
 ********************************/
#ifndef CCURED
 #define __SELECTEDWHEN(x)
 #define __SELECTOR(x)
 #define __RTTI
#endif
typedef struct i3_addr {
  char type;      
  union
  {
                      /* I3_ADDR_TYPE_STACK */
    i3_stack *stack        __SELECTEDWHEN("type" == I3_ADDR_TYPE_STACK);
    
    struct            /* I3_ADDR_TYPE_IPv4 */
    {
      struct in_addr	addr;
      uint16_t       	port;
    } v4                    __SELECTEDWHEN("type" == I3_ADDR_TYPE_IPv4);

    /* v4_nat is used to store all the information required to support
     * NAT hosts:
     *  - (host_addr, host_port) is the address of the host, which
     *    can be behind NAT
     *  - (nat_addr, nat_port) is the address assigned by the NAT to the host
     *  - (i3srv_addr, i3srv_port) is the address of the first i3 server
     *    to which the host sends packets
     */
    struct
    {
      struct in_addr host_addr;
      uint16_t       host_port;
      struct in_addr nat_addr;
      uint16_t       nat_port;
      struct in_addr i3srv_addr;
      uint16_t       i3srv_port;
      
    } v4_nat             __SELECTEDWHEN("type" == I3_ADDR_TYPE_IPv4_NAT);


#ifndef __CYGWIN__   
    struct            /* I3_ADDR_TYPE_IPv6 */
    {
      struct in6_addr	addr;
      uint16_t		port;
    } v6                     __SELECTEDWHEN("type" == I3_ADDR_TYPE_IPv6);
#endif
  } t;
} i3_addr;


typedef struct token_bucket {
#define TOKEN_BUCKET_PACKET 0
#define TOKEN_BUCKET_BYTE   1
  char type; /* specifies whether units are "packets" or "bytes" */
  uint32_t depth; /* token depth (bytes or packets) */
  uint32_t r; /* long term rate (Bps or pps) */
  uint32_t R; /* maximum rate (Bps or pps) */
  /* only the first three fields are packed in packet;
   * the following two fields are temporar variables
   * used to implement the token bucket functionality
   */
  uint32_t tokens; /* actual number of tokens in the bucket (bytes or packets)
		    * Note: "tokens" is never larger than "depth" 
		    */
  uint64_t last_time; /* time since the previous packet has been 
		       * received (usec) 
		       */
} token_bucket;

#define NONCE_LEN  16
typedef struct i3_trigger {
  ID		id;
  uint8_t       flags;  /* possible flags:I3_TRIGGER_FLAG_ALLOW_SHORTCUT (0x1)
			 * I3_TRIGGER_FLAG_RATE_LIMIT (0x2)
			 */
  uint16_t	prefix_len; /* packet ID should match trigID in the first
			     max(prefix_len, MIN_PREFIX_LEN) bits or more */
  char		nonce[NONCE_LEN];
  i3_addr	*to;    
  Key		key;
  token_bucket  *tb; /* this is set only if I3_TRIGGER_FLAG_RATE_LIMIT is set*/
} i3_trigger;


/************************************
 ** i3_option_entry data structure **
 ************************************/

typedef struct i3_option
{
  char type;      
  union
  {
    /* sender address where to send a reply (type = I3_OPT_SENDER)
     */
    i3_addr   *ret_addr  __SELECTEDWHEN("type" == I3_OPT_SENDER);
    
    /* sender address where to send a reply (type = I3_OPT_SENDER)
     */
    i3_addr   *dst_addr  __SELECTEDWHEN("type" == I3_OPT_DESTINATION);
    
    /* trigger insertion and challenge 
     * (type = I3_OPT_TRIGGER_INSERT, I3_OPT_TRIGGER_CHALLENGE,
     * I3_OPT_TRIGGER_ACK, I3_OPT_TRIGGER_REMOVE,
     * I3_OPT_CACHE_ADDR, I3_OPT_CACHE_SHORTCUT_ADDR,
     * I3_OPT_CACHE_DEST_ADDR,
     * I3_OPT_CONSTRAINT_FAILED, I3_OPT_ROUTE_BROKEN)
     *
     * When I3_OPT_CACHE_ADDR is used, trigger->to represents the 
     * the address suggested by the i3 server (e.g., its own address)
     * where client should send data and control messages addressed to
     * any identifier that shares MIN_PREFIX_LEN bits with trigger->id.
     * Thus, this option allows the client to cache the address of a server
     * responsible for a certain identifier.
     * When I3_OPT_CACHE_SHORTCUT_ADDR is used, trigger->to represents the 
     * the address of the end host. This option is sent directly to the 
     * receiver. The receiver can see whether the sender is behind a NAT
     * by comparing the IP source address of the packet and the IP address
     * in trigger->to.
     */
    i3_trigger *trigger __SELECTEDWHEN("type" == I3_OPT_TRIGGER_INSERT || \
                                       "type" == I3_OPT_TRIGGER_CHALLENGE || \
				       "type" == I3_OPT_TRIGGER_ACK || \
				       "type" == I3_OPT_TRIGGER_REMOVE || \
				       "type" == I3_OPT_CACHE_ADDR || \
				       "type" == I3_OPT_CACHE_DEST_ADDR || \
				       "type" == I3_OPT_CACHE_SHORTCUT_ADDR ||\
				       "type" == I3_OPT_CONSTRAINT_FAILED\
				       "type" == I3_OPT_ROUTE_BROKEN);

    /* id to which the reply refers to (type = I3_OPT_TRIGGER_NOT_PRESENT,
     * I3_OPT_REQUEST_FOR_CACHE, I3_OPT_TRIGGER_RATELIMIT)
     */
    ID         *id      __SELECTEDWHEN("type" == I3_OPT_TRIGGER_NOT_PRESENT ||\
				       "type" == I3_OPT_TRIGGER_RATELIMIT);
    
    /* the cache request is for the first ID in the stack 
     * (type = I3_OPT_REQUEST_FOR_CACHE, I3_OPT_REQUEST_FOR_CACHE_SHORTCUT)
     */ 
    void       *nothing  __SELECTEDWHEN("type" == I3_OPT_REQUEST_FOR_CACHE || \
                            "type" == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT || \
			    "type" == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR);
  } entry;
  struct i3_option *next;
} i3_option;
        

/*********************************
 ** structure of i3 option list **
 *********************************/
        
typedef struct i3_option_list
{
  i3_option *head;
  i3_option *tail;
} i3_option_list;


/****************************
 ** structure of i3-header **
 ****************************/

typedef struct i3_header
{
  uint8_t  ver; 		/* version */
  uint8_t  flags; 
  struct i3_stack *stack;       /* stack of IDs */
  i3_option_list  *option_list; /* option list */
} i3_header;

#define get_hdr_options(p) (p + ID_LEN*((p)[2] & 0xf) + 3*sizeof(char))
#define get_hdr_stack(p) ((p) + 3*sizeof(char))
#define get_flags(p) ((p)[1])
#define get_stack_len(p) ( (p)[2] & 0xf)
#define get_first_hop(p) ( get_flags(p) & I3_FIRST_HOP )
#define set_first_hop(p) ( (p)[1] = (p)[1] | I3_FIRST_HOP )
#define clear_first_hop(p) ( (p)[1] = (p)[1] & (~I3_FIRST_HOP) )


/*****************************************************************
 * 
 * i3_header:
 *
 *  7              0               
 *  ----------------
 * | version        |   
 *  ----------------
 * | flags          |
 *  ----------------
 * | stacklen       |   
 *  ----------------
 * |                |                
 * |    i3_stack    |
 * |   (var size)   |
 * |     ...        |               
 *  ----------------
 * | option_list_len|   
 * |                |   
 *  ----------------
 * |                |
 * | i3_option_list |
 * |   (var size)   |
 * |     ...        |                
 *  ----------------
 * 
 * 
 *    i3_stack: list of i3 IDs (number of IDs < 16)
 *    ----------------
 *   |    ID #1       |
 *   |                |                
 *    ----------------
 *   |      ...       |                
 *   |                |
 *    ----------------
 *   |     ID #n      |
 *   |                |                
 *    ----------------
 *
 *    i3_option_list: list of i3_option's
 *    ----------------
 *   |  option list   |
 *   |     size       |
 *   |  (in bytes)    |
 *   |                |                
 *    ----------------
 *   |   i3 option    |
 *   |   (var size)   |
 *   |                |                
 *    ----------------
 *   |                |                
 *   |      ...       |                
 *   |                |
 *    ----------------
 *   |   i3 option    |
 *   |   (var size)   |
 *   |                |                
 *    ----------------
 *
 *   i3 options:
 *
 *      return address
 *      ---------------
 *     | opt type      |
 *      ---------------
 *     | data type     |
 *      ---------------                 
 *     | i3 stack or   |
 *     | IPv4 addr or  |
 *     | IPv6 add      |
 *      ----------------
 *      
 *      trigger
 *      ---------------
 *     | opt type      |
 *      ---------------
 *     | flags         |                
 *      ---------------                 
 *     |               |
 *     | i3 id (32B)   |
 *     |    ...        |
 *      ---------------
 *     |prefix len (2B)|
 *      ---------------
 *     |               |
 *     | Nonce (16B)   |
 *     |    ...        |
 *      ---------------
 *     | i3 address    |
 *      ---------------
 *
 *         i3_addr
 *        ---------------
 *       |   type        |
 *        ---------------
 *       | IPv4 addr or  |
 *       | IPv6 addr or  |
 *       | i3_stack      |
 *       ----------------
 *
 *         IPv4 addr
 *          ---------------                 
 *         |               |
 *         |   IP address  |
 *         |               |
 *         |               |
 *          ---------------
 *         |   port #      |
 *         |               |
 *          ---------------
 *
 *         IPv6 addr
 *          ---------------                 
 *         |               |
 *         |   IPv6 addr   |
 *         |    (16 B)     |
 *         |     ...       |
 *          ---------------
 *         |   port #      |
 *         |               |
 *          ---------------
 *
 *         I3 id
 *          ---------------                 
 *         |               |
 *         |               |
 *         |    (32 B)     |
 *         |     ...       |
 *          ---------------
 *
 *****************************************************************/


#endif /* I3_H */

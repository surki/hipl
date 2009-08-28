#include <sys/types.h>
#include <netinet/in.h>
#ifdef __APPLE__
#include <inttypes.h>  // Need uint64_t
#endif
#include <stdio.h>
#include "debug.h"

#ifndef INCL_CHORD_H
#define INCL_CHORD_H

typedef struct Finger Finger;
typedef struct Node Node;
typedef struct Server Server;


#define NELEMS(a) (sizeof(a) / sizeof(a[0]))
#ifndef FALSE
#define FALSE 0
#define TRUE  1
#endif

/* whether a finger is passive or active */
#define F_PASSIVE 0
#define F_ACTIVE  1

//#define SIM_CHORD

#ifdef SIM_CHORD 
enum {
    NBITS        = 16,             /* # bits of an ID */         
    ID_LEN       = NBITS/8,        /* bytes per ID */
    NFINGERS     = NBITS,          /* # fingers per node */
    NSUCCESSORS  = 3,              /* # successors kept */
    NPREDECESSORS = 3,             /* # predecessors kep */
    BUFSIZE      = 65535,          /* buffer for packets */
    STABILIZE_PERIOD = 1*1000000,  /* in usec  */
    MAX_WELLKNOWN = 4,             /* maximum number of "seed" servers */
    MAX_SIMJOIN = 4,               /* maximum number of servers 
				    * contacted simultaneously when joining
				    */
    PING_THRESH = 3,               /* this many unanswered pings are allowed */
    DEF_TTL      = 64,             /* default TTL for multi-hop packets */
};
#else
enum {
    NBITS        = 160,            /* # bits per ID, same as SHA-1 output */
    ID_LEN       = NBITS/8,        /* bytes per ID */
    NFINGERS     = NBITS,          /* # fingers per node */
    NSUCCESSORS  = 8,              /* # successors kept */
    NPREDECESSORS = 3,             /* # predecessors kept */
    STABILIZE_PERIOD = 1*1000000,  /* in usec */
    BUFSIZE      = 65535,          /* buffer for packets */
    MAX_WELLKNOWN = 50,            /* maximum number of other known servers 
				    *  (read from configuration file)
				    */
    MAX_SIMJOIN = 4,               /* maximum number of servers 
				    * contacted simultaneously when joining
				    */
    PING_THRESH = 5,               /* this many unanswered pings are allowed */
    DEF_TTL      = 64,             /* default TTL for multi-hop packets */
};
#endif /* SIM_CHORD */

/* packet types */
enum {
    CHORD_ROUTE = 0,   /* data packet */
    CHORD_ROUTE_LAST,     
    CHORD_FS,          /* find_successor */
    CHORD_FS_REPL,     /* find_successor reply */
    CHORD_STAB,        /* get predecessor */
    CHORD_STAB_REPL,   /* ... response */
    CHORD_NOTIFY,      /* notify (predecessor) */
    CHORD_PING,        /* are you alive? */
    CHORD_PONG,        /* yes, I am */
    CHORD_FINGERS_GET, /* get your finger list */
    CHORD_FINGERS_REPL,/* .. here is my finger list */
    CHORD_TRACEROUTE,  /* traceroute */
    CHORD_TRACEROUTE_LAST,
    CHORD_TRACEROUTE_REPL,/* traceroute repl */
};

/* XXX: warning: portability bugs */
typedef uint8_t byte;
typedef unsigned char  uchar;
#ifdef __APPLE__
typedef u_long ulong;
#endif

typedef struct {
    byte x[ID_LEN];
} chordID;

#define KEY_LEN 20
typedef struct {
    char x[KEY_LEN];
} Key;

struct Node
{
    chordID id;
    in_addr_t addr;
    in_port_t port;
};

struct Finger
{
    Node node;          /* ID and address of finger */
    int  status;        /* specifies whether this finger has been 
			 * pinged; possible values: F_PASSIVE (the node
			 * has not been pinged) and F_ACTIVE (the node
			 * has been pinged) 
			 */
    int npings;         /* # of unanswered pings */
    long rtt_avg;       /* average rtt to finger (ms in simulator, 
			 * usec in the implementation)
			 */
    long rtt_dev;       /* rtt's mean deviation (ms in simulator, 
			 * usec in the implementation)
			 */
                         /* rtt_avg, rtt_dev can be used to implement 
                          * proximity routing or set up RTO for ping 
                          */
    struct Finger *next;
    struct Finger *prev;
};

/* Finger table contains NFINGERS fingers, then predecessor, then
   the successor list */

struct Server
{
    Node node;          /* addr and ID */
    Finger *head_flist; /* head and tail of finger  */
    Finger *tail_flist; /* table + pred + successors 
			 */
    int to_fix_finger;  /* next finger to be fixed */
    int to_fix_backup;  /* next successor/predecessor to be fixed */
    int to_ping;        /* next node in finger list to be refreshed */
    uint64_t next_stabilize_us;	/* value of wall_time() at next stabilize */

    int in_sock;      /* incoming socket */
    int out_sock;     /* outgoing socket */
};

#define PRED(srv)  (srv->tail_flist)
#define SUCC(srv)  (srv->head_flist)

/* GLOBALS */
extern Node well_known[MAX_WELLKNOWN];
extern int nknown;
#define MAX_KEY_NUM 20
/* the keys in KeyArray are read from file acclist.txt,
 * and are used to authenticate users sending control 
 * messages such as CHORD_FINGERS_GET.
 * This mechanism is intended to prevent trivial DDoS attacks.
 *
 * (For now the keyes are sent and stored in clear so
 *  the security provided by this mechanism is quite weak)
 */
#define ACCLIST_FILE "acclist.txt"
extern Key KeyArray[MAX_KEY_NUM];
extern int NumKeys;

/* chord.c */
extern void chord_main(char *conf_file, int parent_sock);
extern void initialize(Server *srv);
extern void handle_packet(int network);
extern int read_keys(char *file, Key *keyarray, int max_num_keys);

/* finger.c */
extern Finger *new_finger(Node *node);
extern Finger *succ_finger(Server *srv);
extern Finger *pred_finger(Server *srv);
extern Finger *closest_preceding_finger(Server *srv, chordID *id, int fall);
extern Node *closest_preceding_node(Server *srv, chordID *id, int fall);
extern void remove_finger(Server *srv, Finger *f);
extern Finger *get_finger(Server *srv, chordID *id);
extern Finger *insert_finger(Server *srv, chordID *id, 
			     in_addr_t addr, in_port_t port, int *fnew);
void free_finger_list(Finger *flist);

/* hosts.c */
extern in_addr_t get_addr(void); /* get_addr: get IP address of server */

/* join.c */
extern void join(Server *srv, FILE *fp);

/* pack.c */
extern int dispatch(Server *srv, int n, uchar *buf);

extern int pack(uchar *buf, char *fmt, ...);
extern int unpack(uchar *buf, char *fmt, ...);
extern int sizeof_fmt(char *fmt);

#ifdef CCURED
// These are the kinds of arguments that we pass to pack
struct pack_args {
  int f1;
  chordID * f2;
};
#pragma ccuredvararg("pack", sizeof(struct pack_args))
struct unpack_args {
  ushort * f1;
  uchar * f2;
  ulong * f3;
  chordID *id;
};
#pragma ccuredvararg("unpack", sizeof(struct unpack_args))
#endif

extern int pack_data(uchar *buf, uchar type, byte ttl, 
		     chordID *id, ushort len, uchar *data);
extern int unpack_data(Server *srv, int n, uchar *buf);
extern int pack_fs(uchar *buf, byte ttl, chordID *id, ulong addr, ushort port);
extern int unpack_fs(Server *srv, int n, uchar *buf);
extern int pack_fs_repl(uchar *buf, chordID *id, ulong addr, ushort port);
extern int unpack_fs_repl(Server *srv, int n, uchar *buf);
extern int pack_stab(uchar *buf, chordID *id, ulong addr, ushort port);
extern int unpack_stab(Server *srv, int n, uchar *buf);
extern int pack_stab_repl(uchar *buf, chordID *id, ulong addr, ushort port);
extern int unpack_stab_repl(Server *srv, int n, uchar *buf);
extern int pack_notify(uchar *buf, chordID *id, ulong addr, ushort port);
extern int unpack_notify(Server *srv, int n, uchar *buf);
int pack_ping(uchar *buf, chordID *id, ulong addr, ushort port, ulong time);
extern int unpack_ping(Server *srv, int n, uchar *buf);
extern int pack_pong(uchar *buf, chordID *id, 
		     ulong addr, ushort port, ulong time);
extern int unpack_pong(Server *srv, int n, uchar *buf);
extern int pack_fingers_get(uchar *buf, ulong addr, ushort port, Key *key);
extern int unpack_fingers_get(Server *srv, int n, uchar *buf);
extern int pack_fingers_repl(uchar *buf, Server *srv);
extern int unpack_fingers_repl(Server *null, int n, uchar *buf);

extern int pack_traceroute(uchar *buf, Server *srv, Finger *f, 
			   uchar type, byte ttl, byte hops);
extern int unpack_traceroute(Server *srv, int n, uchar *buf);
extern int pack_traceroute_repl(uchar *buf, Server *srv, byte ttl, byte hops,
				ulong *paddr, ushort *pport, int one_hop);
extern int unpack_traceroute_repl(Server *srv, int n, uchar *buf);

/* process.c */
extern int process_data(Server *srv, uchar type, byte ttl, chordID *id,  
			ushort len, uchar *data);
extern int process_fs(Server *srv, byte ttl, 
		      chordID *id, ulong addr, ushort port);
extern int process_fs_repl(Server *srv, chordID *id, ulong addr, ushort port);
extern int process_stab(Server *srv, chordID *id, ulong addr, ushort port);
extern int process_stab_repl(Server *srv, chordID *id, 
			     ulong addr, ushort port);
extern int process_notify(Server *srv, chordID *id, ulong addr, ushort port);
extern int process_ping(Server *srv, chordID *id,
			ulong addr, ushort port, ulong time);
extern int process_pong(Server *srv, chordID *id, 
			ulong addr, ushort port, ulong time);
extern int process_fingers_get(Server *srv, ulong addr, ushort port, Key *key);
extern int process_fingers_repl(Server *srv, uchar ret_code);
extern int process_traceroute(Server *srv, chordID *id, char *buf,
			      uchar type, byte ttl, byte hops);
extern int process_traceroute_repl(Server *srv, char *buf,
				   byte ttl, byte hops);

/* sendpkt.c */
extern void send_raw(Server *srv, in_addr_t addr, in_port_t port, 
		     int n, uchar *buf);
extern void send_data(Server *srv, uchar type, byte ttl, Node *np, 
		      chordID *id, ushort n, uchar *data);
extern void send_fs(Server *srv, byte ttl, ulong to_addr, ushort to_port,
		    chordID *id, ulong addr, ushort port);
extern void send_fs_repl(Server *srv, ulong to_addr, ushort to_port,
			 chordID *id, ulong addr, ushort port);
extern void send_stab(Server *srv, ulong to_addr, ushort to_port,
		      chordID *id, ulong addr, ushort port);
extern void send_stab_repl(Server *srv, ulong to_addr, ushort to_port,
			   chordID *id, ulong addr, ushort port);
extern void send_notify(Server *srv, ulong to_addr, ushort to_port,
			chordID *id, ulong addr, ushort port);
extern void send_ping(Server *srv, ulong to_addr, ushort to_port,
		      ulong addr, ushort port, ulong time);
extern void send_pong(Server *srv, ulong to_addr, ushort to_port, ulong time);
extern void send_fingers_get(Server *srv, ulong to_addr, ushort to_port,
			     ulong addr, ushort port, Key *key);
extern void send_fingers_repl(Server *srv, ulong to_addr, ushort to_port);
extern void send_traceroute(Server *srv, Finger *f, uchar *buf, 
			    uchar type, byte ttl, byte hops);
extern void send_traceroute_repl(Server *srv, uchar *buf, int ttl, 
				 int hops, int one_hop);

/* stabilize.c */
extern void stabilize(Server *srv);
extern void set_stabilize_timer(void);

/* api.c */
extern int chord_init(char *conf_file);
extern void chord_cleanup(int signum);
extern void chord_route(chordID *k, char *data, int len);
extern void chord_deliver(int n, uchar *data);
extern void chord_get_range(chordID *l, chordID *r);
void chord_update_range(chordID *l, chordID *r);
int chord_is_local(chordID *x);

/* util.c */
extern double f_rand(void);
extern double funif_rand(double a, double b);
extern int n_rand(int n);
extern int unif_rand(int a, int b);
extern uint64_t wall_time(void);
extern ulong get_current_time();
extern void update_rtt(long *rtt_avg, long *rtt_std, long new_rtt);
extern chordID rand_ID(void);
extern chordID successor(chordID id, int n);
extern chordID predecessor(chordID id, int n);
extern void add(chordID *a, chordID *b, chordID *res);
extern void subtract(chordID *a, chordID *b, chordID *res);
extern void random_between(chordID *a, chordID *b, chordID *res);
extern int msb(chordID *x);
extern int equals(chordID *a, chordID *b);
extern int equals_id_str(chordID *a, char *b);
extern int is_zero(chordID *x);
extern int is_between(chordID *x, chordID *a, chordID *b);
extern int copy_id( chordID *a, chordID *b);
extern void print_id(FILE *f, chordID *id);
extern chordID atoid(const char *str);
extern unsigned hash(chordID *id, unsigned n);
extern void print_chordID(chordID *id);
extern void print_two_chordIDs(char *preffix, chordID *id1, 
			       char *middle, chordID *id2, 
			       char *suffix);
extern void print_three_chordIDs(char *preffix, chordID *id1, 
				 char *middle1, chordID *id2, 
				 char *middle2, chordID *id3,
				 char *suffix);
extern void print_node(Node *node, char *prefix, char *suffix);
extern void print_finger(Finger *f, char *prefix, char *suffix);
extern void print_finger_list(Finger *fhead, char *prefix, char *suffix);
extern void print_server(Server *s, char *prefix, char *suffix);
extern void print_process(Server *srv, char *process_type, chordID *id,
			  ulong addr, ushort port);
extern void print_send(Server *srv, char *send_type, chordID *id,
		       ulong addr, ushort port);
extern void print_fun(Server *srv, char *fun_name, chordID *id);
void print_current_time(char *prefix, char *suffix);
extern int match_key(Key *key);

#ifdef SIM_CHORD
void sim_send_raw(Server *srv, 
		  in_addr_t addr, in_port_t port, int n, uchar *buf);
void sim_deliver_data(Server *srv, chordID *id, int n, uchar *data);
Server *get_random_server(int no_idx, int status);
int sim_chord_is_local(Server *srv, chordID *x);
double sim_get_time(void);
#endif

#include "eprintf.h"

#endif /* INCL_CHORD_H */

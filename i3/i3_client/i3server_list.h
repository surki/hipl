#ifndef _HOST_LIST_H
#define _HOST_LIST_H 

#if !defined(_WIN32) 
    #include <inttypes.h>
#else
    #include "../utils/fwint.h"
#endif
#include "../i3/i3.h"
#include "coordinates.h"

#define I3SERVERHASH		200
#define MAX_I3_SERVER_LIST_SIZE 200 
#define MAX_PING_LIST_SIZE 	8
#define NUM_TO_PURGE		2

#define I3SERVER_ALIVE 1
#define I3SERVER_DEAD  0

#define HISTORY_SIZE 10

typedef struct PingInfo {
    uint16_t seq;
    uint64_t rtt;
} PingInfo;


/* Maintain a list of i3 servers as (i) hash table (ii) circular ring */
typedef struct I3ServerListNode {
    uint32_t	addr;
    uint16_t	port;
    ID		id;
    int		status; // ideally, we should use an assoc array; this is shortcut
    
    Coordinates	coord;
    int		head, n;
    PingInfo	ping_info[HISTORY_SIZE];

    struct I3ServerListNode *next_hash;// next in the chained hash
    struct I3ServerListNode *next_list;// next in the list
} I3ServerListNode;

typedef struct I3ServerList {
    int			num_ping_list;
    I3ServerListNode	*hash[I3SERVERHASH];
    I3ServerListNode	*list;
    
    int			num_newservers;
    I3ServerListNode	*full_list; // new servers when getting server list
} I3ServerList;

/* External methods */
void init_i3server_list(I3ServerList *list);
I3ServerListNode *lookup_i3server(I3ServerList *list, uint32_t addr);
I3ServerListNode *update_i3server(I3ServerList *list, 
	uint32_t addr, uint16_t port, ID id, Coordinates coord);
I3ServerListNode *add_to_new_i3servers(I3ServerList *list,
	uint32_t addr, uint16_t port, ID id, Coordinates coord);
I3ServerListNode *create_i3server(I3ServerList *list,
	uint32_t addr, uint16_t port, ID id, Coordinates coord);
void change_ping_list(I3ServerList *list, 
	I3ServerListNode **next_ping, int closest_coordinate);
int is_empty_new_i3servers(I3ServerList *list);
void delete_dead_i3servers(I3ServerList *list);
int update_ping_information(I3ServerList *list, 
	uint32_t addr, uint16_t seq, uint64_t rtt);
void mark_i3servers_dead(I3ServerList *list);
void print_i3servers(I3ServerList *list);

int get_top_k(I3ServerList *list, int k,
	      uint32_t best_addr[], uint16_t best_port[], uint64_t best_rtt[]);
uint64_t get_rtt_node(I3ServerListNode *node);
uint64_t get_rtt(I3ServerList *list, uint32_t addr);
uint64_t get_rtt_id(I3ServerList *list, ID *id);
int get_top_k_id(I3ServerList *list, int k, ID best_id[], uint64_t best_rtt[]);

I3ServerListNode *find_next_alive_ping_list(I3ServerList *list, 
					I3ServerListNode *curr);

#endif

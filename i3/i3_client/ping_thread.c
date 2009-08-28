#include "ping_thread.h"
#include "ping.h"
#include "http.h"
#include "i3server_list.h"
#include "../utils/gen_utils.h"

#include "i3.h"
#include "i3_id.h"
#include "i3_debug.h"
#include "i3_ping.h"


#include <stdio.h>
    #include <errno.h>
#ifndef _WIN32
    #include <pthread.h>
#endif
#include "../utils/netwrap.h"

// #define ICMP_PING

#define START_TIME 		5 * 60 * 1000000ULL
#define PERIOD_PING_START 	10 * 1000000ULL
#define PERIOD_PING_STEADY 	50 * 1000000ULL
#define PERIOD_PICK_NEW_SERVER_START	20 * 1000000ULL
#define PERIOD_PICK_NEW_SERVER_STEADY	3 * 60 * 1000000ULL
#define PERIOD_SERVERLIST_WGET 	5 * 60 * 1000000ULL
#define PING_STEADY_TIME 	5 * 60 * 1000000ULL

uint64_t period_ping[2] = {PERIOD_PING_START, PERIOD_PING_STEADY};
uint64_t period_pick_new_server[2] = {
    PERIOD_PICK_NEW_SERVER_START, PERIOD_PICK_NEW_SERVER_STEADY};

/** The socket used to listen for ping (ICMP or UDP) replies */
nw_skt_t ping_sock = -1;

    
/********************************************************
 * Locking for status of ping process
 *******************************************************/
#ifndef _WIN32
pthread_mutex_t status_mutex = PTHREAD_MUTEX_INITIALIZER;
#else
HANDLE status_mutex = NULL;
#endif

int status_lock()
{
#ifndef _WIN32
    if (pthread_mutex_lock(&status_mutex)) {
	fprintf(stderr, "status_mutex: problem with locking mutex\n");
	return 1;
    }
#else
    WaitForSingleObject(status_mutex, INFINITE);
#endif
    return 0;
}
int status_unlock()
{
#ifndef _WIN32
    if (pthread_mutex_unlock(&status_mutex)) {
	fprintf(stderr, "status_mutex: problem with unlocking mutex\n");
	return 1;
    }
#else
    ReleaseMutex(status_mutex);
#endif
    return 0;
}

char is_valid(char type)
{
    if (PING_STATUS_STEADY == type || PING_STATUS_START == type)
	return 1;
    else
	return 0;
}

void set_status(uint64_t *ping_start_time, uint64_t curr_time)
{
    status_lock();
    if (ping_start_time != NULL)
	*ping_start_time = curr_time;
    status_unlock();
}

char get_status(uint64_t *ping_start_time, uint64_t curr_time)
{
    char ret = PING_STATUS_STEADY;
    status_lock();
    if (curr_time - *ping_start_time > PING_STEADY_TIME) {
	ret = PING_STATUS_STEADY;
    } else {
	ret = PING_STATUS_START;
    }
    status_unlock();
    return ret;
}

/* Send a set of pings to nodes in order */
void send_npings(nw_skt_t sock, I3ServerList *list, I3ServerListNode **node, int n)
{
    int i;
    static int seq = 1;
    struct in_addr ia;
    
    n = MIN(n, list->num_ping_list);
    for (i = 0; i < n; i++) {
	ia.s_addr = htonl((*node)->addr);
	I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_VERBOSE, 
		"Sending echo request to %s\n", inet_ntoa(ia));
#ifdef ICMP_PING
	send_echo_request(sock, (*node)->addr, seq);
#else
	i3_echo_request(sock, (*node)->addr, (*node)->port, seq);
#endif
	
	*node = (*node)->next_list;
	if (NULL == *node) {
	    *node = list->list;
	    seq++;
	}
    }
}

/********** Coordinate computation *******************/

#define NUM_LANDMARKS_COORDINATE 10
#define COORD_INIT_PING_WAIT_TIME 3*1000000ULL

/* To determine the coordinates of the local node initially
 * Ping a subset of nodes and determine coordinates */
void init_coordinates(I3ServerList *list)
{
    int n = MIN(NUM_LANDMARKS_COORDINATE, list->num_newservers + list->num_ping_list);
    I3ServerListNode *node = list->list, *temp_node;
    uint64_t start_time = wall_time();
    Coordinates_RTT coord_rtt[NUM_LANDMARKS_COORDINATE];
    int num_landmarks = 0; int started_full_list = 0;
    struct in_addr ia;
    nw_skt_t tmp_ping_sock;

#ifdef ICMP_PING
    if (init_icmp_socket(&tmp_ping_sock) == -1)
	abort();
#else
    if (init_udp_socket(&tmp_ping_sock) == -1)
	abort();
#endif

    // wait for responses and accumulate
    // cut and pasted from below
    while ((wall_time() - start_time < COORD_INIT_PING_WAIT_TIME) && 
	    (num_landmarks < n)) {
	fd_set rset;
	struct timeval to;
	int ret;

	FD_ZERO(&rset);

	if (!node && !started_full_list) {
	    node = list-> full_list;
	    started_full_list = 1;
	}
	
	if (node) {
	    ia.s_addr = htonl(node->addr);
	    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_VERBOSE,
		    "Sending ICMP echo request to %s\n", inet_ntoa(ia));
#ifdef ICMP_PING
	    send_echo_request(tmp_ping_sock, node->addr, 0);
#else
	    i3_echo_request(tmp_ping_sock, node->addr, node->port, 0);
#endif
	    node = node->next_list;
	}

	FD_SET(tmp_ping_sock, &rset);
        to.tv_sec = 0; to.tv_usec = 200000ULL;
        if ((ret = select(tmp_ping_sock+1, &rset, NULL, NULL, &to)) < 0) {
	    int err = nw_error();
            if (err == EINTR)
                continue;
            else {
                perror("select");
                abort();
            }
        }

	// message received on icmp socket
	if (FD_ISSET(tmp_ping_sock, &rset)) {
	    uint32_t addr; uint16_t port, seq; uint64_t rtt;
#ifdef ICMP_PING
	    if (recv_echo_reply(tmp_ping_sock, &addr, &seq, &rtt)) {
#else
	    if (recv_i3_echo_reply(tmp_ping_sock, &addr, &port, &seq, &rtt)) {
#endif
		temp_node = lookup_i3server(list, addr);
		assert(NULL != temp_node);

		coord_rtt[num_landmarks].coord = temp_node->coord;
		coord_rtt[num_landmarks].rtt = rtt;
		num_landmarks++;

		ia.s_addr = htonl(addr);
		I3_PRINT_DEBUG4(I3_DEBUG_LEVEL_VERBOSE,
			"Node: %s Coordinate: %.1f:%.1f RTT: %Ld\n",
			inet_ntoa(ia), temp_node->coord.latitude,
			temp_node->coord.longitude, rtt);
	    }
	}
    }
    nw_close(tmp_ping_sock);

    // compute own coordinate
    compute_coordinates(num_landmarks, coord_rtt);
}

/* Update the coordinates of a node using ping information */
void update_coordinate(I3ServerList *list, I3ServerListNode *next_to_ping)
{
    Coordinates_RTT coord_rtt[NUM_LANDMARKS_COORDINATE];
    int count, num_landmarks = 0;
    I3ServerListNode *node;

    // n1 and n2: number of landmarks from ping_list and rest in
    // proportion to the number of nodes in those lists
    int i, n = MIN(NUM_LANDMARKS_COORDINATE, 
	    list->num_newservers + list->num_ping_list);
    int n1 = ((float)list->num_ping_list/
	    (list->num_newservers + list->num_ping_list)) * n;
    int n2 = n-n1;

    // add from ping list
    count = 0;
    for (i = 0, node = list->list; 
	    i < list->num_ping_list, count < n1;
	    node = node->next_list, ++i) {
	if (node->n > 0) {
	    coord_rtt[count].rtt = get_rtt_node(node);
	    coord_rtt[count].coord = node->coord;
	    count++;
	}
    }
    num_landmarks = count;

    // add from rest
    count = 0;
    for (i = 0, node = list->full_list; 
	    i < list->num_newservers, count < n2; 
	    node = node->next_list, ++i) {
	if (node->n > 0) {
	    coord_rtt[num_landmarks + count].rtt = get_rtt_node(node);
	    coord_rtt[num_landmarks + count].coord = node->coord;
	    count++;
	}
    }
    num_landmarks += count;

    // recompute coordinates
    compute_coordinates(num_landmarks, coord_rtt);

    // repopulate ping list afresh
    change_ping_list(list, &next_to_ping, 1);
}

/** This function is called to close the ping socket
 */
void close_ping_socket() {

   if (ping_sock != -1) {
	nw_close (ping_sock);
   }
}

/*********************************************************
 * Main ping thread 
 ********************************************************/
#ifndef _WIN32
void *ping_thread_entry(void *data)
#else
unsigned int __stdcall ping_thread_entry(void *data)
#endif
{
    PingThreadData *pdata = (PingThreadData *)data;
    
    int maxfd, ret;
    fd_set all_rset, rset;
    struct timeval to;

    I3ServerList *list = pdata->list;
    char *url = pdata->url;
    uint64_t *ping_start_time = pdata->ping_start_time;
       
    int num_pings;
    I3ServerListNode *next_to_ping;
    uint64_t last_ping_time, curr_time;
    uint64_t last_add_new_i3servers, last_update_serverlist;
 
    FD_ZERO(&all_rset);
    FD_ZERO(&rset);

    /* socket init */
#ifdef ICMP_PING
    if (init_icmp_socket(&ping_sock) == -1)
	abort();
#else
    if (init_udp_socket(&ping_sock) == -1)
	abort();
#endif
    FD_SET(ping_sock, &all_rset);
    maxfd = ping_sock + 1;
    
    /* initial populate the list of i3 servers */
    update_i3_server_list(url, list, &next_to_ping);

    /* determine coordinates */
    init_coordinates(list);

    /* add some close-by servers from the list based on coordinates */
    change_ping_list(list, &next_to_ping, 1);
       
    /* eternal loop */
    last_ping_time = last_add_new_i3servers = last_update_serverlist = wall_time();
    set_status(ping_start_time, last_ping_time);
    for (;;) {
		rset = all_rset;
        to.tv_sec = 0; to.tv_usec = 10000;
        if ((ret = select(maxfd, &rset, NULL, NULL, &to)) < 0) {
            if (errno == EINTR)
                continue;
            else {
                perror("select");
                abort();
            }
        }

		/* message received on icmp socket */
		if (FD_ISSET(ping_sock, &rset)) {
			uint32_t addr; uint16_t port, seq; uint64_t rtt;
#ifdef ICMP_PING
			if (recv_echo_reply(ping_sock, &addr, &seq, &rtt)) {
#else
			if (recv_i3_echo_reply(ping_sock, &addr, &port, &seq, &rtt)) {
#endif
				update_ping_information(list, addr, seq, rtt);
			}
		}

		/* need to ping */
		curr_time = wall_time();
		if (list->num_ping_list > 0) {
			char status = get_status(ping_start_time, curr_time);
			num_pings = (curr_time - last_ping_time)/
				(period_ping[status]/list->num_ping_list);
			if (num_pings > 0) {
				if (NULL == next_to_ping) {
					I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, 
							"No servers to ping. Aborting\n");
				}
				send_npings(ping_sock, list, &next_to_ping, num_pings);
				last_ping_time = curr_time;
			}
		}
	
		/* change the list of i3 servers */
		if (curr_time - last_add_new_i3servers >
					period_pick_new_server[get_status(ping_start_time, curr_time)]) {
			/* testing just the best server */
			uint32_t best_addr; uint16_t best_port; uint64_t best_rtt;
			struct in_addr ia;
			int required_k = 1;
			int ret = get_top_k(list, required_k, &best_addr, &best_port, &best_rtt);
			
			if (ret != required_k) {
				// We couldn't find the request k top nodes.

				I3_PRINT_INFO0 (
						I3_INFO_LEVEL_WARNING,
						"I3 Ping Thread: Unable to obtain top k nodes.\n"
						);
				// Dilip: Feb 20, 2006.  I don't think the following works.
				// TODO: Start
				// We set the last_add_new_servers to fool the thread
				// to wait for some time before trying again to get
				// the top k nodes.
				//last_add_new_i3servers = curr_time;
				// TODO: End

				// Sleep for some time before trying again.
#				if defined (_WIN32)
					Sleep ( 25 ); // 25 milliseconds
#				else
					usleep(25 * 1000); // 25 milliseconds
#				endif				
				continue;
			}

			ia.s_addr = htonl(best_addr);
			I3_PRINT_DEBUG3(I3_INFO_LEVEL_MINIMAL,
					"Best node: %s:%d with RTT %Ld\n", 
					inet_ntoa(ia), best_port, best_rtt
					);
	    
			I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_VERBOSE, "Adding new servers to list\n");
			change_ping_list(list, &next_to_ping, 0);
			last_add_new_i3servers = curr_time;
		}
	
		/* update (wget) i3 server list */
		if (curr_time - last_update_serverlist > PERIOD_SERVERLIST_WGET) {
			I3_PRINT_DEBUG0(	I3_DEBUG_LEVEL_VERBOSE, 
								"Updating server list from server\n");
			update_i3_server_list(url, list, &next_to_ping);
			last_update_serverlist = curr_time;
		}
    }

#ifndef _WIN32
    pthread_exit(0);
#endif
    return 0;
}

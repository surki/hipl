#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "chord.h"

/* Global variable that is a pointer to srv in chord main */
Server *srv_ref;

/* local functions */
static void fix_fingers(Server *srv);
static void fix_succs_preds(Server *srv);
static void ping(Server *srv);
static void clean_finger_list(Server *srv);

/* stabilize: the following things are done periodically
 *  - stabilize successor by asking for its predecessor
 *  - fix one backup successor 
 *  - fix one proper finger 
 *  - ping one node in the finger list (the finger list includes 
 *    the backup successors, the proper fingers and the predecessor)
 *  - ping any node in the finger list that has not replied to the
 *    previous ping
 */

#define CHORD_CLEAN_PERIOD 60

void stabilize(Server *srv)
{
  static int idx = 0, i;
  Finger *succ, *pred;

  /* Hack to get around the fact that parameters
   * cannot be passed when setting signal timers 
   */
#ifndef SIM_CHORD
  srv = srv_ref;
  /* Set next stabilize time */
  do {
    srv->next_stabilize_us += STABILIZE_PERIOD;
  } while(srv->next_stabilize_us <= wall_time());
#endif

  /* While there is no successor, we fix that! */
  if (srv->head_flist == NULL) {
#ifndef SIM_CHORD
    for (i = 0; ((i < nknown) && (i < MAX_SIMJOIN)); i++) {
      send_fs(srv, DEF_TTL, well_known[i].addr, well_known[i].port,
	      &srv->node.id, srv->node.addr, srv->node.port);
      send_ping(srv, well_known[i].addr, well_known[i].port,
		srv->node.addr, srv->node.port, get_current_time());
    }
#else
    {
      Server *s;
#define SRV_PRESENT 2
      /* join by contacting two nodes, already in the system */
      for (i = 0; i < 2; i++) {
	s = get_random_server(srv->node.addr, SRV_PRESENT);
	if (s != NULL) {
	  send_fs(srv, DEF_TTL, s->node.addr, s->node.port,
		  &srv->node.id, srv->node.addr, srv->node.port);
	  send_ping(srv, s->node.addr, s->node.port,
		    srv->node.addr, srv->node.port, get_current_time());
	}
      }
    }
#endif
    return;
  }
  
  /* ping one node in the finger list; these nodes are 
   * pinged in a round robin fashion. 
   * In ddition, ping all nodes which have not replyed to previous pings
   */
  ping(srv);

  /* stabilize successor */
  if ((succ = succ_finger(srv)) == NULL)
    return;
  send_stab(srv, succ->node.addr, succ->node.port,
	    &srv->node.id, srv->node.addr, srv->node.port);

  /* ping predecessor. Normally we should hear from our
   * predecessor via the stabilize message. However, if we
   * cannot communicate with our true predecessor, our predecessor
   * will be another node, so we need to ping it...
   */
#define PERIOD_PING_PRED 5
  if (idx % PERIOD_PING_PRED == 0) {
    pred = pred_finger(srv);
    assert(pred);
    send_ping(srv, pred->node.addr, pred->node.port, 
	      srv->node.addr, srv->node.port, get_current_time());
  } 

  /* fix one backup successor and predessors in a round-robin fashion */
  fix_succs_preds(srv);

  /* fix one proper finger that is not a backup successor; 
   * backup successors are fixed in a round-robin fashion 
   */
  fix_fingers(srv);

  if ((idx++) % CHORD_CLEAN_PERIOD == 0) {
    /* remove all nodes in the finger list that are neither (1)
     * backup successors, nor (2) proper fingers, and nor (3) backup 
     * predecessors
     */
    clean_finger_list(srv);
  }
}


/**********************************************************************/

void fix_fingers(Server *srv)
{
  Finger *f, *succ = succ_finger(srv);
  chordID id = successor(srv->node.id, srv->to_fix_finger);
  chordID to_id = successor(srv->node.id, NFINGERS-1);

  CHORD_DEBUG(5, print_fun(srv, "fix_finger", &id));

  /* Only loop across most significant fingers */
  if (is_between(&id, &srv->node.id, &succ->node.id) ||
      (srv->to_fix_finger == 0)) {
    /* the problem we are trying to solve here is the one of
     * loopy graphs, i.e., graphs that are locally consistent
     * but globally inconsistent (see the Chord TR). Loopy
     * graphs are quite common in the Internet where the
     * communication is not necessary symmetric or transitive
     * (i.e., A can reach B and C, but B cannot reach C).
     * Loopy graphs cause in lookup failures, as two loops
     * that originate in different parts of the ring can reach
     * different targets.
     * To alleviate loopy graph we ask a random node to resolve 
     * a query to a random id between us and our successor. 
     */
    random_between(&srv->node.id, &succ->node.id, &id);
#ifdef SIM_CHORD
    Server *s;
    s = get_random_server(srv->node.addr, SRV_PRESENT);
    if (s) {
      send_fs(srv, DEF_TTL, s->node.addr, s->node.port,
	      &id, srv->node.addr, srv->node.port);
    } 
#else
    Node *n;
    n = &well_known[random() % nknown];
    if (nknown) 
      send_fs(srv, DEF_TTL, n->addr, n->port,
	      &id, srv->node.addr, srv->node.port);
#endif // SIM_CHORD
    srv->to_fix_finger = NFINGERS-1;
  } else
    srv->to_fix_finger--;

  /* ask one of our fingers to find the proper finger corresponding to id. 
   * preferable this is a far away finger, that share as little routing
   * information as possible with us
   */
  if ((f = closest_preceding_finger(srv, &to_id, FALSE)) == NULL) 
    /* settle for successor... */
    f = succ;
  if (f) {
    send_fs(srv, DEF_TTL, f->node.addr, f->node.port,
  	    &id, srv->node.addr, srv->node.port);

    /* once in a while try to get a better predecessor, as well */
    if (srv->to_fix_finger == NFINGERS-1) {
      if (PRED(srv)) {
	random_between(&(PRED(srv)->node.id), &srv->node.id, &id);
	send_fs(srv, DEF_TTL, f->node.addr, f->node.port,
		&id, srv->node.addr, srv->node.port);
      }
    }
  }   
}


/**********************************************************************/
/* fix backup successors and predecessors in a round-robin fashion    */
/**********************************************************************/

void fix_succs_preds(Server *srv)
{
  int k;
  Finger *f, *succ, *pred;
  chordID id;

  CHORD_DEBUG(5, print_fun(srv, "fix_successors", &f->node.id));

  if (succ_finger(srv) == NULL)
    return;

  /* find the next successor to be fixed... */
  for (f = succ_finger(srv), k = 0; 
       (k < srv->to_fix_backup) && f->next; 
       k++, f = f->next);
  /* ... no more successors to be fixed; restart */
  if (f->next == NULL) {
    srv->to_fix_backup = 0;
    return;
  }

  /* find f's successor */
  id = successor(f->node.id, 0);
  send_fs(srv, DEF_TTL, f->node.addr, f->node.port, 
	  &id, srv->node.addr, srv->node.port);
  succ = f;

  /* now fix predecessors; this is not part of the Chord protocol,
   * but in pactice having more than one predecessor is more robust
   *
   * use same index (to_fix_backup) to fix predecessor, as well. Note 
   * that here we assume that NPREDECESSORS <= NSUCCESSORS
   */
  for (f = pred_finger(srv), k = 0; (k < NPREDECESSORS) && f->prev; 
       k++, f = f->prev) {
    if (f->next == NULL)
      /* f is our known predecessor; if there is a node between our 
       * predecessor and us, we'll get it during the next stabilization 
       * round
       */
      continue;
    if (f == succ)
      /* f is both a successor and predecessor */
      break;
    if (k == srv->to_fix_backup) {
      /* fix predecessor */
      random_between(&f->node.id, &f->next->node.id, &id);
      send_fs(srv, DEF_TTL, f->node.addr, f->node.port, 
	      &id, srv->node.addr, srv->node.port);
      break;
    }
  }

  srv->to_fix_backup++;
  if (srv->to_fix_backup >= NSUCCESSORS)
    srv->to_fix_backup = 0;
}

/************************************************************************/

void ping(Server *srv)
{
  int i;
  struct in_addr ia;
  Finger *f, *f_next, *f_pinged = NULL;

  /* ping every finger who is still waiting for reply to a previous ping,
   * and the to_ping-th finger in the list 
   */
  for (f = srv->head_flist, i = 0; f; i++) {

    if (f->npings >= PING_THRESH) {
#define ADDR_STR_LEN	16
      char srv_addr[ADDR_STR_LEN+1];
      char dropped_addr[ADDR_STR_LEN+1];
      ia.s_addr = htonl(srv->node.addr);
      strncpy( srv_addr, inet_ntoa(ia), ADDR_STR_LEN );
      ia.s_addr = htonl(f->node.addr);
      strncpy( dropped_addr, inet_ntoa(ia), ADDR_STR_LEN );
      
#ifdef SIM_CHORD
      // print_fun(srv, "dropping finger", &f->node.id); 
#else
      weprintf("dropping finger[%d] %s:%d (at %s:%d)\n",
	       i, dropped_addr, f->node.port,
	       srv_addr, srv->node.port);
#endif
      f_next = f->next;
      remove_finger(srv, f);
    } else {
      if (f->npings || (srv->to_ping == i)) {
	f->npings++;
	send_ping(srv, f->node.addr, f->node.port, 
		  srv->node.addr, srv->node.port, get_current_time());
	if (srv->to_ping == i) 
	  f_pinged = f;
      }
      f_next = f->next;
    }
    f = f_next;
  }

  if (!f_pinged || !(f_pinged->next))
    srv->to_ping = 0;
  else
    srv->to_ping++;
}

/**********************************************************************
 * keep only (1) backup successors, (2) proper fingers, and (3) predecessor;
 * remove anything else from finger list
 ***********************************************************************/

void clean_finger_list(Server *srv)
{
  Finger *f, *f_lastsucc, *f_lastpred, *f_tmp;
  int     k;
  chordID id;

  /* skip successor list */
  for (f = srv->head_flist, k = 0; f && (k < NSUCCESSORS-1); f = f->next, k++);
  if (f == NULL || f->next == NULL)
    return;
  f_lastsucc = f;

  /* start from the tail and skip predecessors */
  for (f = srv->tail_flist, k = 0; k < NPREDECESSORS-1; f = f->prev, k++) {
    if (f == f_lastsucc)
      /* finger list contains only of backup successors and predecesor */
      return;
  }
  f_lastpred = f;
  f = f_lastpred->prev;	/* First disposable finger */

  /* keep only unique (proper) fingers */
  for (k = NFINGERS - 1; k >= 0; k--) {

    if (f == f_lastsucc)
      return;

    /* compute srv.id + 2^k */
    id = successor(srv->node.id, k);

    if (is_between(&id, &f_lastpred->node.id, &srv->node.id) ||
	equals(&id, &f_lastpred->node.id)) {
      /* proper finger for id is one of the (backup) predecessors */
      continue;
    }
    
    if (is_between(&id, &srv->node.id, &f_lastsucc->node.id) ||
	equals(&id, &srv->node.id))
      /* proper finger for id is one of the (backup) successors */
      break;

    if (is_between(&f->node.id, &srv->node.id, &id)) {
      /* f cannot be a proper finger for id, because it
       * is between current node and id; try next finger
       */
      continue;
    }
    
    /* f is a possible proper finger for id */
    while (1) {
      if (f->prev == NULL || f == f_lastsucc)
	return;
      if (is_between(&f->prev->node.id, &id, &f->node.id) ||
	  equals(&f->prev->node.id, &id)) {
	/* this is not a proper finger (i.e., f's predecessor
	 * is between id and f), so remove f 
	 */
	f_tmp = f;
	f = f->prev;
	remove_finger(srv, f_tmp);
      } else {
	/* f is a proper finger */
	f = f->prev;
	break;
      }
    }
  }
}
  


/**********************************************************************/
/* set_stabilize_timer: Set first stabilize time (to now).	      */
/**********************************************************************/

void set_stabilize_timer(void)
{
    /* do not use get_current_time(), because we need the 
     * resolution of uint64_t 
     */
    srv_ref->next_stabilize_us = wall_time();
}


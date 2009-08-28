#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "chord.h"

int process_data(Server *srv, uchar type, 
		 byte ttl, chordID *id, ushort len, uchar *data)
{
  Node   *np;
  Finger *pf, *sf;

  CHORD_DEBUG(5, print_process(srv, "process_data", id, -1, -1)); 
  
    /* handle request locally? */
#ifdef SIM_CHORD
    if (sim_chord_is_local(srv, id)) {
	/* Upcall goes here... */
        sim_deliver_data(srv, id, len, data);
#else
    if (chord_is_local(id)) {
	/* Upcall goes here... */
        chord_deliver(len, data);
#endif
	return 1;
    } 
    if ((type == CHORD_ROUTE_LAST) && ((pf = pred_finger(srv)) != NULL)) {
      /* the previous hop N believes we are responsible for id,
       * but we aren't. This means that our predecessor is
       * a better successor for N. Just pass the packet to our
       * predecessor. Note that ttl takes care of loops!
       */
      send_data(srv, CHORD_ROUTE_LAST, ttl, &pf->node, id, len, data);
      return 1;
    } 
    if ((sf = succ_finger(srv)) != NULL) {
      if (is_between(id, &srv->node.id, &sf->node.id) || 
	  equals(id, &sf->node.id)) {
	/* according to our info the successor should be responsible
         * for id; send the packet to the successor.
	 */
	send_data(srv, CHORD_ROUTE_LAST, ttl, &sf->node, id, len, data);
	return 1;
      }
    }
    /* send packet to the closest active predecessor (that we know about) */
    np = closest_preceding_node(srv, id, FALSE);
    send_data(srv, CHORD_ROUTE, ttl, np, id, len, data);
    return 1;
}

/**********************************************************************/

int process_fs(Server *srv, byte ttl, chordID *id, ulong addr, ushort port)
{
  Node *succ, *np;

  if (srv->node.addr == addr && srv->node.port == port)
    return 1;

  CHORD_DEBUG(5, print_process(srv, "process_fs", id, addr, port));

  if (succ_finger(srv) == NULL) {
    send_fs_repl(srv, addr, port, 
		 &srv->node.id, srv->node.addr, srv->node.port);
    return 0;
  }
  succ = &(succ_finger(srv)->node);
  if (is_between(id, &srv->node.id, &succ->id) || equals(id, &succ->id)) {
    send_fs_repl(srv, addr, port, &succ->id, succ->addr, succ->port);
  } else {
    np = closest_preceding_node(srv, id, FALSE);
    send_fs(srv, ttl, np->addr, np->port, id, addr, port);
  }
  return 1;
}

/**********************************************************************/

int process_fs_repl(Server *srv, chordID *id, ulong addr, ushort port)
{
  int fnew;

  if (srv->node.addr == addr && srv->node.port == port)
    return 1;

  CHORD_DEBUG(5, print_process(srv, "process_fs_repl", id, -1, -1));
  insert_finger(srv, id, addr, port, &fnew);
  if (fnew == TRUE) {
    send_ping(srv, addr, port, 
	      srv->node.addr, srv->node.port, get_current_time());
  }

  return 1;
}

/**********************************************************************/

int process_stab(Server *srv, chordID *id, ulong addr, ushort port)
{
  Finger *pred = pred_finger(srv);
  int     fnew;

  CHORD_DEBUG(5, print_process(srv, "process_stab", id, addr, port)); 

  insert_finger(srv, id, addr, port, &fnew);
  if (pred) {
    send_stab_repl(srv, addr, port, 
		   &pred->node.id, pred->node.addr, pred->node.port);
  }
  return 1;
}

/**********************************************************************/

int process_stab_repl(Server *srv, chordID *id, ulong addr, ushort port)
{
  Finger *succ;
  int     fnew;

  CHORD_DEBUG(5, print_process(srv, "process_stab_repl", id, -1, -1)); 

  if ((srv->node.addr == addr) && (srv->node.port == port))
    return 1;
  insert_finger(srv, id, addr, port, &fnew);
  succ = succ_finger(srv);
  send_notify(srv, succ->node.addr, succ->node.port,
	      &srv->node.id, srv->node.addr, srv->node.port);
  if (fnew == TRUE) {
    send_ping(srv, addr, port, 
	      srv->node.addr, srv->node.port, get_current_time());
  }
  return 1;
}

/**********************************************************************/

int process_notify(Server *srv, chordID *id, ulong addr, ushort port)
{
  int fnew;

  CHORD_DEBUG(5, print_process(srv, "process_notify", id, addr, port)); 
  insert_finger(srv, id, addr, port, &fnew);
  if (fnew == TRUE) {
    send_ping(srv, addr, port, 
	      srv->node.addr, srv->node.port, get_current_time());
  }
  return 1;
}

/**********************************************************************/

int process_ping(Server *srv, chordID *id, ulong addr, ushort port, ulong time)
{
  int fnew;
  Finger *pred;

  CHORD_DEBUG(5, print_process(srv, "process_ping", id, addr, port)); 
  insert_finger(srv, id, addr, port, &fnew);
  pred = pred_finger(srv);
  if (fnew == TRUE && ((pred == NULL) || 
		       (pred && is_between(id, &pred->node.id, 
					   &srv->node.id)))) {
    send_ping(srv, addr, port, 
	      srv->node.addr, srv->node.port, get_current_time());
  }

  send_pong(srv, addr, port, time);
  
  return 1;
}

/**********************************************************************/

int process_pong(Server *srv, chordID *id, ulong addr, ushort port, ulong time)
{
  Finger *f, *pred, *newpred;
  ulong   new_rtt;
  int     fnew;

  CHORD_DEBUG(5, print_process(srv, "process_pong", id, addr, port)); 
  f = insert_finger(srv, id, addr, port, &fnew);
  f->npings = 0;
  new_rtt = get_current_time() - time; /* takes care of overlow */
  update_rtt(&f->rtt_avg, &f->rtt_dev, (long)new_rtt); 

  pred = pred_finger(srv);
  f->status = F_ACTIVE; /* there is a two-way connectivity to this node */
  newpred = pred_finger(srv); /* check whether pred has changed, i.e.,
			       * f has became the new pred
			       */
  assert(newpred || (pred == newpred));

  if (pred != newpred)
    chord_update_range(&newpred->node.id, &srv->node.id);

  return 1;
}

/**********************************************************************/

int process_fingers_get(Server *srv, ulong addr, ushort port, Key *key)
{
  CHORD_DEBUG(5, print_process(srv, "process_fingers_get", NULL, addr, port));
  if (match_key(key) == 0) 
    print_server(srv, "[process_fingers_get: invalid key]", "");
  else 
    send_fingers_repl(srv, addr, port);

  return 1;
}

/**********************************************************************/

int process_fingers_repl(Server *srv, uchar ret_code)
{
  /* this process should be never invoked by the i3 server,
   * as CHORD_FINGERS_REPL is always sent to the client
   */
  CHORD_DEBUG(5, print_process(srv, "process_fingers_repl", NULL, 0, 0)); 
  return 1;
}

/**********************************************************************/

int process_traceroute(Server *srv, chordID *id, char *buf,
		       uchar type, byte ttl, byte hops)
{
    Finger *f;

    CHORD_DEBUG(5, print_process(srv, "process_traceroute", id, -1, -1)); 

    assert(ttl);
    ttl--;

    /* handle request locally? */
#ifdef SIM_CHORD
    if (sim_chord_is_local(srv, id) || (ttl == 0)) {
        send_traceroute_repl(srv, buf, ttl, hops, (hops ? FALSE : TRUE));
#else
    if (chord_is_local(id) || (ttl == 0)) {
        send_traceroute_repl(srv, buf, ttl, hops, (hops ? FALSE : TRUE));
#endif
	return 1;
    } 
    hops++;
    if ((type == CHORD_TRACEROUTE_LAST) && (f = pred_finger(srv))) {
      /* the previous hop N believes we are responsible for id,
       * but we aren't. This means that our predecessor is
       * a better successor for N. Just pass the packet to our
       * predecessor. Note that ttl takes care of loops.
       */
      send_traceroute(srv, f, buf, CHORD_TRACEROUTE_LAST, ttl, hops);
      return 1;
    } 
    if ((f = succ_finger(srv)) != NULL) {
        if (is_between(id, &srv->node.id, &f->node.id) || 
	    equals(id, &f->node.id)) {
	    send_traceroute(srv, f, buf, CHORD_TRACEROUTE_LAST, ttl, hops);
	    return 1;
	}    
    }
       
    /* send to the closest predecessor (that we know about) */
    f = closest_preceding_finger(srv, id, FALSE);
    send_traceroute(srv, f, buf, CHORD_TRACEROUTE, ttl, hops); 
    return 1;
}

/**********************************************************************/

int process_traceroute_repl(Server *srv, char *buf,
			    byte ttl, byte hops)
{
    CHORD_DEBUG(5, print_process(srv, "process_traceroute_repl", 
				 &srv->node.id, -1, -1)); 
    if (hops == 0)
        return -1;
    hops--;
    send_traceroute_repl(srv, buf, ttl, hops, FALSE);
    return 1;
}




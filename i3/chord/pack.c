#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include "chord.h"

/* pack: pack binary items into buf, return length */

int pack(uchar *buf, char *fmt, ...)
{
  va_list args;
  char *p;
  uchar *bp;
  chordID *id;
  ushort s;
  ulong l;

  bp = buf;
  va_start(args, fmt);
  for (p = fmt; *p != '\0'; p++) {
    switch (*p) {
    case 'c':   /* char */
      *bp++ = va_arg(args, int);
      break;
    case 's':   /* short */
      s = va_arg(args, int);
      s = htons(s);
      memmove(bp, (char *)&s, sizeof(ushort));
      bp += sizeof(ushort);
      break;
    case 'l':   /* long */
      l = va_arg(args, ulong);
      l = htonl(l);
      memmove(bp, (char *)&l, sizeof(ulong));
      bp += sizeof(ulong);
      break;
    case 'x':   /* id */
      id = va_arg(args, chordID *);
      memmove(bp, id->x, ID_LEN);
      bp += ID_LEN;
      break;
    default:   /* illegal type character */
      va_end(args);
      return -1;
    }
  }
  va_end(args);
  return bp - buf;
}

/**********************************************************************/

/* unpack: unpack binary items from buf, return length */
int unpack(uchar *buf, char *fmt, ...)
{
  va_list args;
  char *p;
  uchar *bp, *pc;
  chordID *id;
  ushort *ps;
  ulong *pl;
  
  bp = buf;  
  va_start(args, fmt);
  for (p = fmt; *p != '\0'; p++) {
    switch (*p) {
    case 'c':   /* char */
      pc = va_arg(args, uchar*);
      *pc = *bp++;
      break;
    case 's':   /* short */
      ps = va_arg(args, ushort*);
      *ps = ntohs(*(ushort*)bp);
      bp += sizeof(ushort);
      break;
    case 'l':   /* long */
      pl = va_arg(args, ulong*);
      *pl  = ntohl(*(ulong*)bp);
      bp += sizeof(ulong);
      break;
    case 'x':   /* id */
      id = va_arg(args, chordID *);
      memmove(id->x, bp, ID_LEN);
      bp += ID_LEN;
      break;
    default:   /* illegal type character */
      va_end(args);
      return -1;
    }
  }
  va_end(args);
  return bp - buf;
}

/**********************************************************************/

int sizeof_fmt(char *fmt)
{
  int len = 0;
  int i;

  for (i = 0; i < strlen(fmt); i++) {
    switch (fmt[i]) {
    case 'c':   /* char */
      len += sizeof(char);
      break;
    case 's':   /* short */
      len += sizeof(ushort);
      break;
    case 'l':   /* long */
      len += sizeof(ulong);
      break;
    case 'x':   /* id */
      len += ID_LEN;
      break;
    default:   /* illegal type character */
      eprintf("fmt_len: illegal type character.\n");
      return -1;
    }
  }
  return len;
}

/**********************************************************************/

static int (*unpackfn[])(Server *, int, uchar *) = {
  unpack_data,
  unpack_data,
  unpack_fs,
  unpack_fs_repl,
  unpack_stab,
  unpack_stab_repl,
  unpack_notify,
  unpack_ping,
  unpack_pong,
  unpack_fingers_get,
  unpack_fingers_repl,
  unpack_traceroute,
  unpack_traceroute,
  unpack_traceroute_repl,
};

/* dispatch: unpack and process packet */
int dispatch(Server *srv, int n, uchar *buf)
{
  uchar type;
  int res;

  type = buf[0];
  
  if (type >= NELEMS(unpackfn)) {
    printf("bad packet type 0x%x\n", type);
    return -1;
  }
  res = (*unpackfn[type])(srv, n, buf);
  if (res == -1) 
      printf("protocol error, type %x length %d\n", type, n);
  return res;
}

/**********************************************************************/

/* pack_data: pack data packet */
int pack_data(uchar *buf, uchar type, byte ttl, chordID *id, 
	      ushort len, uchar *data)
{
  int n;

  n = pack(buf, "ccxs", type, ttl, id, len);
  if (n >= 0) {
    memmove(buf + n, data, len);
    n += len;
  }
  return n;
}

/**********************************************************************/

/* unpack_data: unpack and process data packet */
int unpack_data(Server *srv, int n, uchar *buf)
{
  uchar type;
  byte  ttl;
  int len;
  chordID id;
  ushort pkt_len;

  len = unpack(buf, "ccxs", &type, &ttl, id.x, &pkt_len);
  if (len < 0 || len + pkt_len != n) 
    return -1;
  if (--ttl == 0) { 
    print_two_chordIDs("TTL expired: data packet ", &id, 
		       " dropped at node ", &srv->node.id, "\n");
    return -2;
  }
  assert(type == CHORD_ROUTE || type == CHORD_ROUTE_LAST);
  return process_data(srv, type, ttl, &id, pkt_len, buf + len);
}

/**********************************************************************/

/* pack_fs: pack find_successor packet */
int pack_fs(uchar *buf, byte ttl, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "ccxls", CHORD_FS, ttl, id, addr, port);
}

/**********************************************************************/

/* unpack_fs: unpack and process find_successor packet */
int unpack_fs(Server *srv, int n, uchar *buf)
{
  uchar type;
  byte  ttl;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "ccxls", &type, &ttl, &id, &addr, &port) != n)
    return -1;
  if (--ttl == 0) {
    print_two_chordIDs("TTL expired: fix_finger packet ", &id, 
		       " dropped at node ", &srv->node.id, "\n");
    return -2;
  }
  assert(type == CHORD_FS);
  return process_fs(srv, ttl, &id, addr, port);
}

/**********************************************************************/

/* pack_fs_repl: pack find_successor reply packet */
int pack_fs_repl(uchar *buf, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "cxls", CHORD_FS_REPL, id, addr, port);
}

/**********************************************************************/

/* unpack_fs_repl: unpack and process find_successor reply packet */
int unpack_fs_repl(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "cxls", &type, &id, &addr, &port) != n)
    return -1;
  assert(type == CHORD_FS_REPL);
  return process_fs_repl(srv, &id, addr, port);
}

/**********************************************************************/

/* pack_stab: pack stabilize packet */
int pack_stab(uchar *buf, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "cxls", CHORD_STAB, id, addr, port);
}

/**********************************************************************/

/* unpack_stab: unpack and process stabilize packet */
int unpack_stab(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "cxls", &type, &id, &addr, &port) != n)
    return -1;
  assert(type == CHORD_STAB);
  return process_stab(srv, &id, addr, port);
}

/**********************************************************************/

/* pack_stab_repl: pack stabilize reply packet */
int pack_stab_repl(uchar *buf, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "cxls", CHORD_STAB_REPL, id, addr, port);
}

/**********************************************************************/

/* unpack_stab_repl: unpack and process stabilize reply packet */
int unpack_stab_repl(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "cxls", &type, &id, &addr, &port) != n)
    return -1;
  assert(type == CHORD_STAB_REPL);
  return process_stab_repl(srv, &id, addr, port);
}

/**********************************************************************/

/* pack_notify: pack notify packet */
int pack_notify(uchar *buf, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "cxls", CHORD_NOTIFY, id, addr, port);
}

/**********************************************************************/

/* unpack_notify: unpack notify packet */
int unpack_notify(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "cxls", &type, &id, &addr, &port) != n)
    return -1;
  assert(type == CHORD_NOTIFY);
  return process_notify(srv, &id, addr, port);
}

/**********************************************************************/

/* pack_ping: pack ping packet */
int pack_ping(uchar *buf, chordID *id, ulong addr, ushort port, ulong time)
{
  return pack(buf, "cxlsl", CHORD_PING, id, addr, port, time);
}

/**********************************************************************/

/* unpack_ping: unpack and process ping packet */
int unpack_ping(Server *srv, int n, uchar *buf)
{
  uchar type;
  chordID id;
  ulong addr;
  ushort port;
  ulong time;

  if (unpack(buf, "cxlsl", &type, &id, &addr, &port, &time) != n)
    return -1;
  assert(type == CHORD_PING);
  return process_ping(srv, &id, addr, port, time);
}

/**********************************************************************/

/* pack_pong: pack pong packet */
int pack_pong(uchar *buf, chordID *id, ulong addr, ushort port, ulong time)
{
  return pack(buf, "cxlsl", CHORD_PONG, id, addr, port, time);
}

/**********************************************************************/

/* unpack_pong: unpack pong packet */
int unpack_pong(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;
  ulong   time;

  if (unpack(buf, "cxlsl", &type, &id, &addr, &port, &time) != n)
    return -1;
  assert(type == CHORD_PONG);
  return process_pong(srv, &id, addr, port, time);
}

/**********************************************************************/
/**********************************************************************/

/* pack_fingers_get: pack get fingers packet */
int pack_fingers_get(uchar *buf, ulong addr, ushort port, Key *key)
{
  return pack(buf, "cxls", CHORD_FINGERS_GET, key, addr, port);
}

/**********************************************************************/

/* unpack_fingers_get: unpack and process fingers_get packet */
int unpack_fingers_get(Server *srv, int n, uchar *buf)
{
  uchar type;
  Key   key;
  ulong addr;
  ushort port;

  if (unpack(buf, "cxls", &type, &key, &addr, &port) != n)
    return -1;
  assert(type == CHORD_FINGERS_GET);
  return process_fingers_get(srv, addr, port, &key);
}

#define INCOMPLETE_FINGER_LIST -1
#define END_FINGER_LIST 0

/* pack_fingers_repl: pack repl fingers packet */
int pack_fingers_repl(uchar *buf, Server *srv)
{
  Finger *f;
  int len, l;

  assert(srv);
  len = pack(buf, "cxls", CHORD_FINGERS_REPL, &srv->node.id, 
	     srv->node.addr, srv->node.port);

  /* pack fingers */
  for (f = srv->head_flist; f; f = f->next) {
    l = pack(buf + len, "xlslls",
             &f->node.id, f->node.addr, f->node.port,
	     f->rtt_avg, f->rtt_dev, (short)f->npings); 
    len += l;
    if (len + l + 1 > BUFSIZE) {
      len += pack(buf + len, "c", INCOMPLETE_FINGER_LIST);
      return len;
    }
  }
  len += pack(buf + len, "c", END_FINGER_LIST);
  return len;
}


/* unpack_fingers_repl: unpack and process fingers_repl packet */
int unpack_fingers_repl(Server *srv, int n, uchar *buf)
{
  /* this message is received by a client; 
   * it shouldn't be received by an i3 server 
   */
  return process_fingers_repl(srv, 0);
}


/**********************************************************************/

/* pack_traceroute: pack/update traceroute packet */
/* 
 * traceroute packet format:
 *    char pkt_type; 
 *    char ttl; time to live, decremented at every hop. 
 *              When ttl reaches 0, a traceroute_repl packet is returned.
 *    char hops; number of hops up to the current node (not including the
 *               client). hops is inceremented at every hop along the 
 *               forward path. hops should be initialized to 0 by the clients. 
 *    ID target_id;   target ID for traceroute.
 *    Node prev_node; previous node (ie., the node which forwarded the packet) 
 *    ulong rtt; rtt...
 *    ulong dev; ... and std dev frm previous node to this node (in usec)  
 *    Node crt_node; this node
 *    (list of addresses/ports of the nodes along the traceroute path 
 *     up to this node)
 *    ulong addr;  address...   
 *    ushort port; ... and port number of the client
 *    ....
 */
int pack_traceroute(uchar *buf, Server *srv, Finger *f, 
		    uchar type, byte ttl, byte hops)
{
  int   n = 0;

  /* pack type, ttl and hops fields */
  n = pack(buf+n, "ccc", type, ttl, hops);
  
  /* skip target ID field */
  n += sizeof_fmt("x");

  /* pack prev node (for the next node, this is the current node!) */
  n += pack(buf+n, "xlsll", &srv->node.id, srv->node.addr, srv->node.port,
	    f->rtt_avg, f->rtt_dev);

  /* pack this node field (for next node this is the node itself!) */
  n += pack(buf+n, "xls", &f->node.id, f->node.addr, f->node.port);

  /* skip current list of addresses .. */
  n += sizeof_fmt("ls")*hops;

  /* add current node to the list */
  n += pack(buf+n, "ls", srv->node.addr, srv->node.port);

  return n;
}

/**********************************************************************/

/* unpack_traceroute: unpack and process trace_route packet 
 * (see pack_traceroute for packet format)
 */
int unpack_traceroute(Server *srv, int n, uchar *buf)
{
  chordID id;
  byte    type;
  byte    ttl;
  byte    hops;

  /* unpack following fields: type, ttl, hops, and target id */
  if (unpack(buf, "cccx", &type, &ttl, &hops, &id) >= n)
    return -1;
  assert(type == CHORD_TRACEROUTE || type == CHORD_TRACEROUTE_LAST);
  return process_traceroute(srv, &id, buf, type, ttl, hops);
}

/**********************************************************************/

/* pack_traceroute_repl: pack/update traceroute packet */
/* 
 * traceroute packet_repl format:
 *    char pkt_type; 
 *    char ttl; time to live, incremented at every hop (remember, this message
 *              travls on the reverse path)
 *    char hops; number of hops from client, decremented at every
 *               hop along the forward path. When hops reaches 0,
 *               the packet is dropped.
 *    ID target_id;   target ID for traceroute.
 *    Node nl_node; next-to-last hop on traceroute path
 *    ulong rtt; rtt...
 *    ulong dev; ... and std dev from next-to-last hop to the last hop
 *    Node l_node; last node of traceroute path
 *    (list of addresses/ports of the nodes along the traceroute path 
 *     up to this node, starting with the client)
 *    ulong addr;  address...   
 *    ushort port; ... and port number of the client
 *    ....
 */
int pack_traceroute_repl(uchar *buf, Server *srv, byte ttl, byte hops,
			 ulong *paddr, ushort *pport, int one_hop)
{
  int   n = 0;

  /* pack ttl and hops fields */
  n += pack(buf+n, "ccc", CHORD_TRACEROUTE_REPL, (char)ttl, (char)hops);
  
  /* skip target ID field */
  n += sizeof_fmt("x");

  if (one_hop) {
    /* one hop path */
    n += pack(buf+n, "xls", &srv->node.id, srv->node.addr, srv->node.port);
    /* skip mean rtt, and std dev rtt fields */
    n += sizeof_fmt("ll");
  } else {
    /* skip next-to-last node field, and the mean and std dev. to last 
     * node fields
     */
    n += sizeof_fmt("xlsll");
  }

  /* skip last node field */
  n += sizeof_fmt("xls");

  /* compute source list size -- this is the number of hops plus client */
  n += sizeof_fmt("ls")*hops;

  /* get address and port number of previous node on reverse path
   * yes, it's ugly to unpack in a pack function, but... 
   */
  unpack(buf+n, "ls", paddr, pport);

  return n;
}

/**********************************************************************/

/*  unpack_traceroute: unpack and process trace_route packet 
 * (see pack_traceroute for packet format)
 */
int unpack_traceroute_repl(Server *srv, int n, uchar *buf)
{
  byte type;
  byte ttl;
  byte hops;

  /* unpack following fields: type, ttl, and hops */
  if (unpack(buf, "ccc", &type, &ttl, &hops) >= n)
    return -1;
  assert(type == CHORD_TRACEROUTE_REPL);

  return process_traceroute_repl(srv, buf, ttl, hops);
}


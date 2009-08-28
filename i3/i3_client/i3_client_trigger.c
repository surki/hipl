/***************************************************************************
                          i3_client_trigger.c  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu

    changes:
      Nov 10, 2004: added two functions (num_matched_bits and
                    cl_get_max_prefix_len_from_list) needed for 
                    handling anycast triggers inserted by the same node;
                    see the cl_context_select function in i3_client_context.c

      Nov 12, 2004: added the shortcut functionality 
 ***************************************************************************/

#include <stdlib.h>
#ifndef _WIN32
    #include <sys/time.h>
#endif

#include "i3.h"
#include "i3_fun.h"

#include "i3_client.h"
#include "i3_client_fun.h"
#include "i3_debug.h"

#include "../utils/gen_utils.h"

void trigger_set_timer(struct timeval *tv, void (*fun)(), cl_trigger *ctr);
void trigger_cancel_timer(cl_trigger *ctr);

/*********************************************************************
 * cl_create_trigger_gen - create a trigger entry and insert it in 
 *                         a hash data structure
 *  input:
 *    ctx - context
 *    addr_type    - trigger type
 *    id           - trigger's ID
 *    prefix_len   - length of the trigger's ID preffix
 *    ip_addr, port - address and port number of the receiver 
 *                    (addr_type == I3_ADDR_TYPE_IPv4)
 *    stack        - stack of ID (addr_type == I3_ADDR_TYPE_STACK)
 *    flags        - flags associated to the trigger (e.g., 
 *                   I3_TRIGGER_FLAG_ALLOW_SHORTCUT)
 *
 *  output:
 *    trigger entry, if allocation succesful; NULL, otherwise
 *********************************************************************/

cl_trigger *cl_create_trigger_gen(cl_context *ctx,
				  uint16_t addr_type, 
				  ID *id, uint16_t prefix_len,
				  struct in_addr ip_addr, uint16_t port,
				  i3_stack *stack, Key *key, uint16_t flags)
{
  i3_trigger *t;
  i3_addr    *a;
  cl_trigger *ctr;
  int idx = CL_HASH_TRIG(id);

  t = alloc_i3_trigger();
  a = alloc_i3_addr();

  switch (addr_type) {
  case I3_ADDR_TYPE_IPv4:
    init_i3_addr_ipv4(a, ip_addr, port);
    break;
  case I3_ADDR_TYPE_STACK:
    init_i3_addr_stack(a, stack);
    break;
  default:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, 
		"cl_create_trigger_gen: invalid address type\n");
  }

  init_i3_trigger(t, id, MAX(prefix_len, MIN_PREFIX_LEN), a, key, flags);

  if (cl_get_trigger_from_list(ctx->trigger_htable[idx], t) == NULL) {
    ctr = cl_alloc_trigger();
    ctr->t = t;
    ctr->status = CL_TRIGGER_STATUS_IDLE; 
    ctr->is_queued = FALSE;	/* Not yet inserted in PRIORITY QUEUE */
    ctr->retries_cnt = 0;
    ctr->ctx = ctx;
    ctr->timer = NULL;

    cl_add_trigger_to_list(&ctx->trigger_htable[idx], ctr);
    return ctr;
  } else {
    /* trigger already presented */
    free_i3_trigger(t);
    return NULL;
  }
}


/************************************************************************
 * cl_delete_trigger - delete a given trigger; remove it from
 *                     ctx->trigger_htable and free memory 
 *************************************************************************/

void cl_delete_trigger(cl_context *ctx, cl_trigger *ctr)
{
  int idx = CL_HASH_TRIG(&ctr->t->id);

  cl_remove_trigger_from_list(&ctx->trigger_htable[idx], ctr);
  cl_free_trigger(ctr);
}



/************************************************************************
 *  cl_insert_trigger_into_i3 - insert a given trigger 
 *
 *  input:
 *    ctx - context
 *    ctr - cl data structure of the trigger to be inserted
 *************************************************************************/

int cl_insert_trigger_into_i3(cl_context *ctx, cl_trigger *ctr)
{
  int refresh;

  assert(ctr);
  if (ctr->type == CL_TRIGGER_LOCAL) {
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, 
		"This trigger is local so it shouldn't be inserted in i3\n");
    return CL_RET_OK;
  }

  if (ctr->precomputed_pkt.p == NULL) 
    /* Beware of side effects! The precomputed packet can be 
     *changed in cl_ctx_trigger_ratelimit() and process_trigger_option()
     */
    cl_make_trigger_packet(ctx, ctr->t, 
			   I3_OPT_TRIGGER_INSERT, &ctr->precomputed_pkt);

  if (ctr->status == CL_TRIGGER_STATUS_INSERTED) {
    /* trigger already inserted; this is a redundant trigger insertion call */
    ;
  } else 
    ctr->status = CL_TRIGGER_STATUS_PENDING;

  /* insert trigger into i3;
   * "refresh" doesn't matter here as trigger inserts are always
   * acked with a control message (I3_OPT_TRIGGER_CHALLENGE or
   * I3_OPT_TRIGGER_ACK) that includes the option I3_OPT_CACHE_ADDR 
   */
  cl_sendto(ctx, ctr->precomputed_pkt.p, ctr->precomputed_pkt.len, 
	    cl_get_valid_id(ctx, &ctr->t->id, &refresh),
	    &ctr->t->id);

  return CL_RET_OK;
}


/************************************************************************
 *  cl_remove_trigger_from_i3 - remove given trigger 
 *
 *  input:
 *    ctx - context
 *    ctr - cl data structure of the trigger to be inserted
 *************************************************************************/

int cl_remove_trigger_from_i3(cl_context *ctx, cl_trigger *ctr)
{
  buf_struct b;
  int refresh;
  int idx = CL_HASH_TRIG(&ctr->t->id);;

  if (ctr->type == CL_TRIGGER_LOCAL) {
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, 
		"This trigger is local so it shouldn't be inserted in i3\n");
    return CL_RET_OK;
  }
   
  if ((ctr = cl_get_trigger_from_list(ctx->trigger_htable[idx], ctr->t))
      == NULL)
    return CL_RET_TRIGGER_NOT_FOUND;

  cl_make_trigger_packet(ctx, ctr->t, I3_OPT_TRIGGER_REMOVE, &b);

  cl_sendto(ctx, b.p, b.len, cl_get_valid_id(ctx, &ctr->t->id, &refresh),
	    &ctr->t->id);
  ctr->status = CL_TRIGGER_STATUS_IDLE;

  free(b.p); /* ... because b.p is allocated in cl_make_trigger_packet */

  /* cancel any timer associated to the trigger, if any */
  trigger_cancel_timer(ctr);

  return CL_RET_OK;
}

/* basic operations for manipulating triggers on the client side */
cl_trigger *cl_alloc_trigger()
{
  cl_trigger *ctr;

  if ((ctr = (cl_trigger *)calloc(1, sizeof(cl_trigger))) != NULL)
    return ctr;

  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, 
	      "cl_alloc_trigger: memory allocation error.\n");
  return NULL;
}

void cl_free_trigger(cl_trigger *ctr)
{
  /* cancel any timer associated to the trigger, if any */
  trigger_cancel_timer(ctr);

  free_i3_trigger(ctr->t);
  if (ctr->precomputed_pkt.p)
    free(ctr->precomputed_pkt.p);
  free(ctr);
}


void cl_free_trigger_list(cl_trigger *ctr_head)
{
  cl_trigger *ctr;

  assert(ctr_head);

  while (ctr_head) {
    ctr = ctr_head->next;
    cl_free_trigger(ctr_head);
    ctr_head = ctr;
  }
}

#define MAX_TRIG_PER_HASH 10000

cl_trigger *cl_get_trigger_from_list(cl_trigger *head, i3_trigger *t)
{
  cl_trigger *ctr;
  int count = 0;

  for (ctr = head; ctr; ctr = ctr->next) {
    count++;
    if (count > MAX_TRIG_PER_HASH)
        I3_PRINT_INFO1(I3_INFO_LEVEL_VERBOSE, 
		   "Too many triggers per entry! %d\n", count);
    if (trigger_equal(t, ctr->t)) {
      return ctr;
    } 
  }
  return NULL;
}

int does_id_match(ID *id1, ID *id2, int prefix_len)
{
  int d = prefix_len / 8; /* number of bytes */
  int r = prefix_len % 8; 
  char mask = 0;

  if (memcmp((char *)id1, (char *)id2, d))
    return FALSE;

  if (r == 0)
    return TRUE;

  mask = ~(0x7f >> (r - 1));

  if ((id1->x[d] & mask) == (id2->x[d] & mask))
    return TRUE;

  return FALSE;
}

cl_trigger *cl_get_trigger_by_id(cl_trigger *ctr_head, ID *id)
{
  cl_trigger *ctr;

  for (ctr = ctr_head; ctr; ctr = ctr->next) 
    if (does_id_match(&ctr->t->id, id, ctr->t->prefix_len) == TRUE)
      return ctr;

  return NULL;
}

/* get the common prefix length of x and y */
int num_matched_bits(ID *id1, ID *id2)
{
  int i, j;
  char mask = 0x80;
  
  for (i = 0; i < ID_LEN; i += sizeof(long)) {
    if (*(long *)&id1->x[i] != *(long *)&id2->x[i]) 
      break;
  }

  if (i == ID_LEN)
    return i*8;

  for (; i < ID_LEN; i++) {
    if (id1->x[i] != id2->x[i])
      break;
  }
  if (i == ID_LEN)
    return i*8;

  for (j = 0; j < 8; j++) {
    if ((id1->x[i] & mask) != (id2->x[i] & mask))
      break;
    mask = mask >> 1;
  }

  return i*8 + j;
}


int cl_get_max_prefix_len_from_list(cl_trigger *ctr_head, ID *id)
{
  cl_trigger *ctr;
  int max_prefix_len = 0, n;

  for (ctr = ctr_head; ctr; ctr = ctr->next) {
    n = num_matched_bits(&(ctr->t->id), id);
    if (n > max_prefix_len)
      max_prefix_len = n;
  }
  return max_prefix_len;
}


/* remove a given trigger from list; don't destroy it */ 
void cl_remove_trigger_from_list(cl_trigger **phead, cl_trigger *ctr)
{

  assert(ctr);
  
  if (*phead == ctr) {
    *phead = (*phead)->next;
    if (*phead)
      (*phead)->prev = NULL;
  } else {
    ctr->prev->next = ctr->next;
    if (ctr->next)
      ctr->next->prev = ctr->prev;
  }
}


/* insert at the head of the list */
void cl_add_trigger_to_list(cl_trigger **phead, cl_trigger *ctr)
{
  assert(ctr);

  ctr->next = *phead;
  if (*phead)
    (*phead)->prev = ctr;
  ctr->prev = NULL;
  *phead = ctr;
}

/* update (id,R) --> (id,R'). called when IP addr change is detected */
void cl_update_triggers(cl_context *ctx)
{
  int idx;	 
  cl_trigger *ctr;
  
  for (idx = 0; idx < CL_HTABLE_SIZE; idx++) {
    for (ctr = ctx->trigger_htable[idx]; ctr; ctr = ctr->next) {
      if (I3_ADDR_TYPE_IPv4 == ctr->t->to->type)
	{
	  /* (i) update addr */
	  ctr->t->to->t.v4.addr = ctx->local_ip_addr;
	  
	  /* (ii) invalidate */
	  ctr->is_queued = FALSE;
	  ctr->retries_cnt = 0;
	  free(ctr->precomputed_pkt.p);
	  ctr->precomputed_pkt.p = NULL;
	  
	  /* (iii) re-insert in i3 */
	  cl_insert_trigger_into_i3(ctx, ctr);
	}
    }
  }
}

void process_trigger_option(cl_context *ctx, i3_trigger *t, 
			    int opt_type, struct sockaddr_in *fromaddr)
{
  cl_trigger    *ctr;
  int            refresh;
  struct timeval tv;
  struct sockaddr_in *faddr = fromaddr;
  char tmpIdStr[100];
    
  assert(ctx != NULL);

  switch (opt_type) {
  case I3_OPT_TRIGGER_CHALLENGE:
    
    ctr = cl_get_trigger_from_list(
	    ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);
    
    if (NULL == ctr) {
    
      I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, 
		  "Ignoring reply to a removed trigger with id %s\n",
		  sprintf_i3_id (tmpIdStr, &(t->id)));
      break;
    }
    
    memcpy((char *)ctr->t->nonce, (char *)t->nonce, NONCE_LEN);
    
    /* check whether this trigger has been already precomputed */
    if (ctr->precomputed_pkt.p) 
      free(ctr->precomputed_pkt.p);
    
    cl_make_trigger_packet(ctx, ctr->t, I3_OPT_TRIGGER_INSERT, 
			   &ctr->precomputed_pkt);
    
    cl_sendto(ctx, ctr->precomputed_pkt.p, 
	      ctr->precomputed_pkt.len,
	      cl_get_valid_id(ctx, &t->id, &refresh), &t->id); 
    
    cl_trigger_callback(ctx, ctr, 
			CL_INTERNAL_HOOK_TRIGGER_ACK_TIMEOUT, NULL, NULL);
    /* set ack timeout */
    tv.tv_sec  = ACK_TIMEOUT;
    tv.tv_usec = random_sec();
    trigger_set_timer(&tv, timeout_ack_refresh, ctr);
    break;

    
  case I3_OPT_TRIGGER_ACK:
    ctr = cl_get_trigger_from_list(
      ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);
    if (NULL == ctr) {
      I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, 
		  "Ignoring reply to a removed trigger\n");
      break;
    }
    
    if (ctr->status == CL_TRIGGER_STATUS_PENDING || 
	ctr->status == CL_TRIGGER_STATUS_IDLE) {
      ctr->status = CL_TRIGGER_STATUS_INSERTED;
      ctr->retries_cnt = 0;
      cl_trigger_callback(ctx, ctr, CL_CBK_TRIGGER_INSERTED, NULL, NULL);
    }

    cl_trigger_callback(ctx, ctr, 
			CL_INTERNAL_HOOK_TRIGGER_REFRESH_TIMEOUT, NULL, NULL);

    /* set ack timeout */
    tv.tv_sec  = TRIGGER_REFRESH_PERIOD - ACK_TIMEOUT*MAX_NUM_TRIG_RETRIES;
    tv.tv_usec = random_sec();
    trigger_set_timer(&tv, timeout_ack_refresh, ctr);
    break;

  case I3_OPT_CONSTRAINT_FAILED:
    ctr = cl_get_trigger_from_list(
	    ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);
    cl_trigger_callback(ctx, ctr, 
            CL_CBK_TRIGGER_CONSTRAINT_FAILED, NULL, NULL);
    break;
    
  case I3_OPT_ROUTE_BROKEN:
    ctr = cl_get_trigger_from_list(
	  ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);
      cl_trigger_callback(ctx, ctr, CL_CBK_ROUTE_BROKEN, NULL, NULL);
      break;

  case I3_OPT_CACHE_ADDR:
  case I3_OPT_CACHE_SHORTCUT_ADDR:
  case I3_OPT_CACHE_DEST_ADDR:
    {
      cl_id *cid;

      if (t->to->type == I3_ADDR_TYPE_IPv4) {
	if ((cid = cl_update_id(ctx, &t->id, opt_type,
				&t->to->t.v4.addr, 
				t->to->t.v4.port, faddr)) == NULL)
	  cid = cl_create_id(ctx, &t->id, opt_type,
			     &t->to->t.v4.addr, t->to->t.v4.port, faddr);
      } else if (t->to->type == I3_ADDR_TYPE_IPv4_NAT) {
	if ((cid = cl_update_id(ctx, &t->id, opt_type,
				&t->to->t.v4_nat.nat_addr, 
				t->to->t.v4_nat.nat_port, faddr)) == NULL)
	  cid = cl_create_id(ctx, &t->id, opt_type,
			     &t->to->t.v4_nat.nat_addr, 
			     t->to->t.v4_nat.nat_port, faddr);
      }
      if (opt_type == I3_OPT_CACHE_DEST_ADDR) {
	/* ask for I3_OPT_REQUEST_FOR_SHORTCUT */
	cl_send_request_for_shortcut(ctx, cid, 1);
      }
    }
    break;
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR:
    ;
    
  default:
        I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, 
		    "process_trigger_option: unknown option %d\n", opt_type);
  }  
}


void cl_process_option_list(cl_context *ctx, i3_header *hdr,
			    struct sockaddr_in  *fromaddr)
{
  i3_option *option;
  cl_id     *cid;
  i3_addr    *ret_a = NULL; 
  i3_option_list *ol = hdr->option_list;

  /* When client reeives a i3_opt_force_cache_addr, 
   * it updates its cache, before processing other options in the message. 
   */
  for (option = ol->head; option; option = option->next) {
    i3_trigger *t;
    
    switch (option->type) {
    case I3_OPT_FORCE_CACHE_ADDR:
      t = option->entry.trigger;
      if (t->to->type == I3_ADDR_TYPE_IPv4)        
	cl_update_id(ctx, &t->id, I3_OPT_FORCE_CACHE_ADDR,
		     &t->to->t.v4.addr, t->to->t.v4.port, fromaddr);
      break;
    case I3_OPT_SENDER:
	/* this is the sender address, where replies are sent */
	ret_a = option->entry.ret_addr;
	break;
    default:
      break;
    }
  }
  for (option = ol->head; option; option = option->next) {
    switch (option->type) {
    case I3_OPT_TRIGGER_CHALLENGE:
    case I3_OPT_TRIGGER_ACK:
    case I3_OPT_CONSTRAINT_FAILED:
    case I3_OPT_CACHE_ADDR:
    case I3_OPT_CACHE_DEST_ADDR:
    case I3_OPT_CACHE_SHORTCUT_ADDR:
    case I3_OPT_ROUTE_BROKEN:
      process_trigger_option(ctx, option->entry.trigger, 
			     option->type, fromaddr);
      break;
    case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR:
      cl_send_opt_cache_address_indir(ctx, hdr->stack->ids, 
				      ID_LEN_BITS, ret_a);
      break;
    case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT:
      cl_send_opt_cache_address(ctx, hdr->stack->ids, ID_LEN_BITS, fromaddr);
      break;
    case I3_OPT_TRIGGER_NOT_PRESENT:
      /* trigger not present */
      cid = cl_get_id_from_list(ctx->id_htable[CL_HASH_ID(option->entry.id)],
				option->entry.id);
      cl_id_callback(ctx, CL_CBK_TRIGGER_NOT_FOUND, 
		     option->entry.id, NULL, NULL);
      break;
    case I3_OPT_TRIGGER_RATELIMIT:
      /* trigger not present */
      cid = cl_get_id_from_list(ctx->id_htable[CL_HASH_ID(option->entry.id)],
				option->entry.id);
      cl_id_callback(ctx, CL_CBK_RATELIMIT_EXCEEDED, 
		     option->entry.id, NULL, NULL);
      break;
    case I3_OPT_SENDER:
    case I3_OPT_FORCE_CACHE_ADDR:
      break;
    default:
      I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, 
		  "Invalid option_type = %d\n", option->type);
    }
  }
}


/* create trigger packet -- trigger is not freed here */
void cl_make_trigger_packet(cl_context *ctx, i3_trigger *t, 
			    char opt_type, buf_struct *buf)
{
  i3_addr *a;
  i3_option *o;
  i3_option_list *ol;
  i3_stack *s;
  i3_header *h;

  ol = alloc_i3_option_list();

  if (opt_type != I3_OPT_TRIGGER_REMOVE) {
    /* create ID_OPT_SENDER to tell the i3 server where to reply with 
     * an ack or challenge message 
     */
    a = alloc_i3_addr();
    init_i3_addr_ipv4(a, ctx->local_ip_addr, ctx->local_port);
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_SENDER, (void *)a);
    append_i3_option(ol, o);
  }

  /* create "insert trigger" option */ 
  o = alloc_i3_option();
  init_i3_option(o, opt_type, (void *)duplicate_i3_trigger(t));
  append_i3_option(ol, o);
  
  s = alloc_i3_stack();
  init_i3_stack(s, &t->id, 1 /* only one ID in the stack */);

  h = alloc_i3_header();
  init_i3_header(h, FALSE, s, ol);

  buf->len = get_i3_header_len(h);

  if ((buf->p = (char *)malloc(buf->len)) == NULL)
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, 
		"cl_make_trigger_packet: memory allocation error\n");
  
  pack_i3_header(buf->p, h, &buf->len);
  set_first_hop(buf->p);
  
  free_i3_header(h);
}


/********************************************************************
 * timeout associated with trigger insertion (i.e., chalenge message);
 * if timeout, reinsert the trigger 
 ********************************************************************/
void timeout_ack_insert(cl_trigger *ctr)
{
  int            refresh;
  struct timeval tv;
  cl_context     *ctx = ctr->ctx;

  if( ctx->init_tcp_ctx_flag ) {
	  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "Trigger still pending, reinsert it\n");
  
	  cl_sendto(ctx, ctr->precomputed_pkt.p, 
		    ctr->precomputed_pkt.len,
		    cl_get_valid_id(ctx, &ctr->t->id, &refresh),
		    &ctr->t->id); 
  }
  tv.tv_sec  = ACK_TIMEOUT;
  tv.tv_usec = random_sec();
  trigger_set_timer(&tv, timeout_ack_insert, ctr);
}


/********************************************************************
 * timeout associated with a trigger refresh message
 * if timeout, resend the refresh message
 ********************************************************************/
void timeout_ack_refresh(cl_trigger *ctr)
{
  struct timeval tv;
  cl_context    *ctx = ctr->ctx;
  int            refresh;

  assert(ctr);

  if (ctr->retries_cnt <= MAX_NUM_TRIG_RETRIES) {
    cl_sendto(ctx, ctr->precomputed_pkt.p, ctr->precomputed_pkt.len,
	      cl_get_valid_id(ctx, &ctr->t->id, &refresh), &ctr->t->id);
    ctr->retries_cnt++;
    tv.tv_sec  = ACK_TIMEOUT;
    tv.tv_usec = random_sec();

    cl_trigger_callback(ctx, ctr, 
			CL_INTERNAL_HOOK_TRIGGER_ACK_TIMEOUT, NULL, NULL);

  } else {
    /* refresh failed MAX_NUM_TRIG_RETRIES times; try again later */
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_VERBOSE, "Timeout exceeded, resending\n");
    ctr->retries_cnt = 0;
    tv.tv_sec  = TRIGGER_REFRESH_PERIOD - ACK_TIMEOUT*MAX_NUM_TRIG_RETRIES;
    tv.tv_usec = random_sec();
    
    cl_trigger_callback(ctx, ctr, 
			CL_INTERNAL_HOOK_TRIGGER_REFRESH_TIMEOUT, NULL, NULL);
  }
  trigger_set_timer(&tv, timeout_ack_refresh, ctr);
}


void trigger_set_timer(struct timeval *tv, void (*fun)(), cl_trigger *ctr)
{
  /* cancel timer associated to trigger, if any */
  if (ctr->timer) cl_cancel_timer(ctr->timer);
  ctr->timer = cl_set_timer(tv, fun, ctr);
}

void trigger_cancel_timer(cl_trigger *ctr)
{
  if (ctr->timer) cl_cancel_timer(ctr->timer);
  ctr->timer = NULL;
}

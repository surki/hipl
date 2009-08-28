/***************************************************************************
                          i3_client_id.c  -  description
                             -------------------
    begin                : Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include "i3.h"
#include "i3_fun.h"
#include "i3_client.h"
#include "i3_client_fun.h"
#include "i3_debug.h"
#include "../utils/netwrap.h"

cl_id *cl_alloc_id()
{
  cl_id *cid;

  if ((cid = (cl_id *)calloc(1, sizeof(cl_id))) != NULL)
    return cid;

  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_alloc_id: memory allocation error.\n");
  return NULL;
}

void cl_free_id(cl_id *cid)
{
  free(cid);
}


void cl_free_id_list(cl_id *cid_head)
{
  cl_id *cid;

  assert(cid_head);

  while (cid_head) {
    cid = cid_head->next;
    cl_free_id(cid_head);
    cid_head = cid;
  }
}


/* return a node whose id is on the same i3 server */
cl_id *cl_get_id_from_list(cl_id *head, ID *id)
{
  cl_id *cid;

  for (cid = head; cid; cid = cid->next)  
    if (!memcmp((char *)&cid->id, (char *)id, (MIN_PREFIX_LEN >> 3))) 
      return cid;
  return NULL;
}


/* remove a given identifier node from list; don't destroy it */ 
void cl_remove_id_from_list(cl_id **phead, cl_id *cid)
{

  assert(cid);

  if (*phead == cid) {
    *phead = (*phead)->next;
    if (*phead)
      (*phead)->prev = NULL;
  } else {
    cid->prev->next = cid->next;
    if (cid->next)
      cid->next->prev = cid->prev;
  }
}

/* add identifier at the head of the list */
void cl_add_id_to_list(cl_id **phead, cl_id *cid)
{
  assert(cid);

  cid->next = *phead;
  if (*phead)
    (*phead)->prev = cid;
  cid->prev = NULL;
  *phead = cid;
}

cl_id *cl_get_valid_id(cl_context *ctx, ID *id, int *refresh)
{
  cl_id *cid;
  int idx = CL_HASH_ID(id);
  srv_address *srv;
  struct in_addr ia;
  
  *refresh = TRUE;
  if ((cid = cl_get_id_from_list(ctx->id_htable[idx], id)) == NULL) 
    return NULL;
  if (cid->retries_cnt >= MAX_NUM_ID_RETRIES) {
    cl_remove_id_from_list(&ctx->id_htable[idx], cid);
    srv = set_i3_server_status(ctx->s_array, 
			       htonl(cid->cache_addr.sin_addr.s_addr),
			       htons(cid->cache_addr.sin_port), ID_DOWN);
    ia.s_addr = htonl(cid->cache_addr.sin_addr.s_addr);
    if (NULL == srv)
      return NULL;
    cl_id_callback(ctx, CL_CBK_SERVER_DOWN, id, &srv->addr, &srv->port); 
    cl_free_id(cid);
    return NULL;
  } else {
    if (ctx->now.tv_sec - cid->last_ack.tv_sec > 
       ID_REFRESH_PERIOD-ACK_TIMEOUT*(MAX_NUM_ID_RETRIES-cid->retries_cnt)) {
      cid->retries_cnt++;
      return cid;
    }
  }
  *refresh = FALSE;
  return cid;
}


/***********************************************************************
 * cl_create_id - associate an id with a cache address. This function
 *                is invoked upon receiving I3_OPT_CACHE_ADDR, 
 *                I3_OPT_CACHE_SHORTCUT_ADDR or I3_OPT_CACHE_DEST_ADDR
 *                options
 * input:
 *   ctx - context
 *   id  - identifier
 *   ip_addr, port - IP address and port numbers contained in the 
 *                   trigger associated to the option. In the case of
 *                   I3_OPT_CACHE_ADDR, (ip_addr, port) represents the 
 *                   i3 server responsible for id. Otherwise, (ip_addr,
 *                   port) represents the sender.  
 *   fromaddr      - contains the IP *routable* address and the port number 
 *                   of the sender. If the sender is behind a NAT, fromaddr
 *                   is different from (ip_addr, port) returned by the 
 *                   I3_OPT_CACHE_SHORTCUT_ADDR option. Otherwise the two
 *                   are equal.
 * return: identifier data structure
 *
 * Note: ip_addr and port number are in host format; fromaddr is in
 *       network format
 ***********************************************************************/
cl_id *cl_create_id(cl_context *ctx, ID *id, int opt_type,
		    struct in_addr *ip_addr, uint16_t port,
		    struct sockaddr_in *fromaddr)
{
  cl_id *cid;

  if ((cid = cl_get_id_from_list(ctx->id_htable[CL_HASH_ID(id)], id)) != NULL)
    return cid;

  cid = cl_alloc_id();
  memcpy((char *)&cid->id, id, ID_LEN);
  memset(&cid->cache_addr, 0, sizeof(struct sockaddr_in));
  cid->cache_addr.sin_family = AF_INET;
  cid->dest_addr.sin_family = AF_INET;
  cl_add_id_to_list(&ctx->id_htable[CL_HASH_ID(&cid->id)], cid);

  switch (opt_type) {
  case I3_OPT_CACHE_ADDR:
  case I3_OPT_FORCE_CACHE_ADDR:
    cid->cache_addr.sin_addr.s_addr = ntohl(ip_addr->s_addr);
    cid->cache_addr.sin_port = ntohs(port);
    cid->retries_cnt = 0;
    cid->last_ack = ctx->now;
    set_i3_server_status(ctx->s_array, ip_addr->s_addr, port, ID_UP);
    break;
  case I3_OPT_CACHE_SHORTCUT_ADDR:
    assert(fromaddr);
    /* no need to convert since fromaddr is already in network format */
    cid->cache_addr.sin_addr.s_addr = fromaddr->sin_addr.s_addr;
    cid->cache_addr.sin_port = fromaddr->sin_port;
    cid->retries_cnt = 0;
    cid->last_ack = ctx->now;
    set_i3_server_status(ctx->s_array, htonl(fromaddr->sin_addr.s_addr), 
			 htons(fromaddr->sin_port), ID_UP);
    break;
  case I3_OPT_CACHE_DEST_ADDR:
    cid->dest_addr.sin_addr.s_addr = ntohl(ip_addr->s_addr);
    cid->dest_addr.sin_port = ntohs(port);
    set_i3_server_status(ctx->s_array, 
			 ip_addr->s_addr, port, ID_UP);
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "cl_create_id: unknown option %d\n", opt_type);
  }
  return cid;
}

/* see cl_create_id */
cl_id *cl_update_id(cl_context *ctx, ID *id, int opt_type,
		    struct in_addr *ip_addr, uint16_t port,
		    struct sockaddr_in  *fromaddr)
{
  cl_id *cid;

  
  if ((cid = cl_get_id_from_list(ctx->id_htable[CL_HASH_ID(id)], id)) != NULL){
    switch (opt_type) {
    case I3_OPT_CACHE_ADDR:
    case I3_OPT_FORCE_CACHE_ADDR:
      assert(ip_addr->s_addr);
      cid->cache_addr.sin_addr.s_addr = ntohl(ip_addr->s_addr);
      cid->cache_addr.sin_port = ntohs(port);
      set_i3_server_status(ctx->s_array, ip_addr->s_addr, port, ID_UP);
      cid->retries_cnt = 0;
      cid->last_ack = ctx->now;
      break;
    case I3_OPT_CACHE_SHORTCUT_ADDR:
      assert(fromaddr);
      /* fromaddr already in network format; no need to convert */
      cid->cache_addr.sin_addr.s_addr = fromaddr->sin_addr.s_addr;
      cid->cache_addr.sin_port = fromaddr->sin_port;
      set_i3_server_status(ctx->s_array, htonl(fromaddr->sin_addr.s_addr), 
			   htons(fromaddr->sin_port), ID_UP);
      cid->retries_cnt = 0;
      cid->last_ack = ctx->now;
      break;
    case I3_OPT_CACHE_DEST_ADDR:
      cid->dest_addr.sin_addr.s_addr = ntohl(ip_addr->s_addr);
      cid->dest_addr.sin_port = ntohs(port);
      set_i3_server_status(ctx->s_array, 
			   ip_addr->s_addr, port, ID_UP);
      break;
    default:
      I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "cl_update_id: unknown option %d\n", opt_type);
    }
    return cid;
  } else 
    return NULL;
}


/* setting IDs as public_IDs */
void cl_set_public_id(ID *id)
{
    set_id_type(id, I3_ID_TYPE_PUBLIC);
}
void cl_set_private_id(ID *id)
{
    set_id_type(id, I3_ID_TYPE_PRIVATE);
}

/***************************************************************************
 * update_id_key - update a trigger ID according using key according to the
 *                 specified constraint
 *
 * input:
 *   id - trigger ID
 *   key 
 *   flags - flags associated to creating a trigger; possible values:
 *           CL_TRIGGER_CFLAG_R_CONSTRAINT - right constraint; id.key = h_l(key)
 *           CL_TRIGGER_CFLAG_L_CONSTRAINT - left constraint; id.key = h_r(key)
 *           CL_TRIGGER_CFLAG_PUBLIC - public ID; otherwise the ID
 *                                     is private. If the trigger is public
 *                                     then it has to be left constraint, 
 *                                     i.e., CL_TRIGGER_CFLAG_R_CONSTRAINT 
 *                                     and CL_TRIGGER_CFLAG_PUBLIC cannot be
 *
 * return value:
 *   error code; possible values
 *     CL_RET_INVALID_FLAGS
 *     CL_RET_OK
 ***************************************************************************/
int update_id_key(ID *id, Key *key, uint16_t flags)
{
    Key k;

    if ((flags & CL_TRIGGER_CFLAG_PUBLIC) && 
        (flags & CL_TRIGGER_CFLAG_R_CONSTRAINT)) {
        
        return CL_RET_INVALID_FLAGS;
    }

    if ((flags & CL_TRIGGER_CFLAG_R_CONSTRAINT) &&
        (flags & CL_TRIGGER_CFLAG_L_CONSTRAINT)) {
       
            return CL_RET_INVALID_FLAGS;
    }
  
    
    if (flags & CL_TRIGGER_CFLAG_PUBLIC) {
        cl_set_public_id(id);
    
    } else if (flags) {             // & CL_TRIGGER_CFLAG_PRIVATE) {
        cl_set_private_id(id);
   
    /*
    } else if (flags & CL_TRIGGER_CFLAG_UNCONSTRAINED) {
        set_id_type (id, I3_ID_TYPE_UNCONSTRAINED);

    */
    
    }
    

    if (flags & CL_TRIGGER_CFLAG_R_CONSTRAINT) {
        generate_constraint_id(id, key, R_CONSTRAINT);
    }
  
    if (flags & CL_TRIGGER_CFLAG_L_CONSTRAINT) {
        memcpy(&k.x, KEY_ID_PTR(id), KEY_LEN);
        generate_l_constraint_addr(key, &k);
        memcpy(KEY_ID_PTR(id), &k.x, KEY_LEN);
    }  
  return CL_RET_OK;
}


/***************************************************************************
 * update_id_id - constrain the trigger ID and the target ID
 *
 * input:
 *   id - trigger ID
 *   id_target - target ID 
 *   flags - flags associated to creating a trigger; possible values:
 *           CL_TRIGGER_CFLAG_R_CONSTRAINT - right constraint; 
 *                                           id.key = h_l(id_target)
 *           CL_TRIGGER_CFLAG_L_CONSTRAINT - left constraint; 
 *                                           id_target.key = h_r(id)
 *           CL_TRIGGER_CFLAG_PUBLIC - public ID; otherwise the ID
 *                                     is private. If the trigger is public
 *                                     then it has to be left constraint, 
 *                                     i.e., CL_TRIGGER_CFLAG_R_CONSTRAINT 
 *                                     and CL_TRIGGER_CFLAG_PUBLIC cannot be
 *
 * return value:
 *   error code; possible values
 *     CL_RET_INVALID_FLAGS
 *     CL_RET_OK
 ***************************************************************************/
int update_id_id(ID *id, ID *id_target, uint16_t flags)
{
  Key k;
  char tmpBuf[10000];

  //printf("\n\n\n------------------->update_id_id: original id = %s, flags=%d\n", sprintf_i3_id (tmpBuf,id), flags);
  //printf("\n\n\n------------------->update_id_id: constrained id = %s\n", sprintf_i3_id (tmpBuf,id_target));
  if ((flags & CL_TRIGGER_CFLAG_PUBLIC) && 
      (flags & CL_TRIGGER_CFLAG_R_CONSTRAINT))
    return CL_RET_INVALID_FLAGS;

  if ((flags & CL_TRIGGER_CFLAG_R_CONSTRAINT) &&
      (flags & CL_TRIGGER_CFLAG_L_CONSTRAINT))
    return CL_RET_INVALID_FLAGS;
  
  if (flags & CL_TRIGGER_CFLAG_PUBLIC)
    cl_set_public_id(id);
  else
    cl_set_private_id(id);

  if (flags & CL_TRIGGER_CFLAG_R_CONSTRAINT) {
    generate_constraint_id(id, &k, R_CONSTRAINT);
    memcpy(KEY_ID_PTR(id_target), &k.x, KEY_LEN);
  }

  //printf("------------------->update_id_id: constrained id = %s\n\n\n\n", sprintf_i3_id (tmpBuf,id_target));
  if (flags & CL_TRIGGER_CFLAG_L_CONSTRAINT) {
    generate_constraint_id(id_target, &k, L_CONSTRAINT);
    memcpy(KEY_ID_PTR(id), &k.x, KEY_LEN);
  }
  return CL_RET_OK;
}



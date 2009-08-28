/************************************************************************
 * cl_ctx_init - create and initialize a context data structure 
 * 
 *  input:
 *    cfg_file - xml file containing configuration parameters
 *               such as the servers to which the client can connect
 *    rc       - return error code; possible values
 *               CL_RET_OK
 *               CL_RET_INVALID_CFG_FILE
 *               CL_RE_NO_CONTEXT
 *               error code returned cl_init_ping
 *               
 *  return value:
 *   ctx - pointer to the context
 *
 *************************************************************************/

#include <errno.h>
#include <time.h>
#include <stdio.h> // printf()
#include <string.h> // strcasecmp()
#include <stdlib.h> // exit()
#ifdef _WIN32
    // stg: win does not have strcasecmp():
    #define strcasecmp _stricmp
#endif

#include "i3.h"
#include "i3_stack.h"
#include "i3_client_fun.h"
#include "i3_debug.h"
#include "i3_client.h"
#include "i3_client_api.h"
#include "i3_client_api_ctx.h"
#include "i3_ping.h"

#include "../utils/utils.h"
#include "../utils/gen_utils.h"

#include "token_bucket.h"
token_bucket *alloc_token_bucket();
void timeout_ack_insert(cl_trigger *ctr);


int cl_init_ping(cl_context* ctx, char *url);
void trigger_set_timer(struct timeval *tv, void (*fun)(), cl_trigger *ctr);


/**
  * @param i3_port_num The port on which i3 should listen.
  */
cl_context *cl_ctx_init(const char *cfg_file, int *rc, int i3_port_num)
{
  char usePingStr[50];
  char useTCPStr[50];
  
  cl_context *ctx;

  // Open the debug file to which all debug and info messages related to i3 are sent,
  // if it had not be previously opened.  
  // For eg: if the i3 client api is used as part of the i3OCD, the i3OCD
  // sets up i3DebugFD as soon as the i3OCD dll is loaded.
#ifdef _WIN32
  if (i3DebugFD == NULL) {
	i3DebugFD = fopen ("debug_i3.txt", "w");
  }
#endif
  if (0 != nw_init()) {
	  I3_PRINT_INFO0 (I3_INFO_LEVEL_FATAL_ERROR, "Unable to initialize the network.\n");
	  EXIT_ON_ERROR;
      return NULL;
  }

  if (!cfg_file) {
    *rc = CL_RET_INVALID_CFG_FILE;
    return NULL;
  }

  /* read configuration file */
  read_parameters(cfg_file);

  /* create context */
  ctx = cl_create_context(NULL, i3_port_num);
  if (ctx)
    *rc = CL_RET_OK;
  else {
    *rc = CL_RET_NO_CONTEXT;
    return ctx;
  }
  
  /* Should TCP be used to find the first hop i3 server? */
  read_string_attribute("//I3ServerDetails", "UseTCP", useTCPStr,0);
  if (strcasecmp(useTCPStr, "yes") == 0 || strcasecmp(useTCPStr, "true") == 0) {
     ctx->is_tcp = 1;
  } else {
     ctx->is_tcp = 0;
  }
   
  /* check whether ping is used to find a nearby server */
  read_string_attribute("//I3ServerDetails", "UsePing", usePingStr,0);
  if (strcasecmp(usePingStr, "yes") == 0 || strcasecmp(usePingStr, "true") == 0) {
     ctx->use_ping = 1;
  } else {
     ctx->use_ping = 0;
  }

  if (ctx->use_ping) {
#define STATUS_URL_LEN 1024
    char status_url[STATUS_URL_LEN];

    /* read the url containing the list of i3 serevers */
    read_string_attribute("//I3ServerDetails", "ServerListURL", status_url, 0);

    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_SUPER, "Using ping, server status url = %s\n\n", status_url);

    if (strlen(status_url) >= STATUS_URL_LEN) {
      I3_PRINT_INFO1(I3_INFO_LEVEL_WARNING, "cl_ctx_init: status_url file too long in %s\n", cfg_file);
      exit(-1);
    }
    if (strlen(status_url) == 0) {
      I3_PRINT_INFO1(I3_INFO_LEVEL_WARNING, "cl_ctx_init: no status_url file in %s\n", cfg_file);
      exit(-1);
    }
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_VERBOSE, "Starting ping thread\n");
    *rc = cl_init_ping(ctx, status_url);
  }
 
  // Don't read the configuration file after this point.
  release_params();
  
  if (ctx->num_servers < 1 && ! ctx->use_ping) {
      I3_PRINT_INFO0 (
              I3_INFO_LEVEL_FATAL_ERROR,
              "No i3 server details have been given and UsePing is turned off.\n"
              "There is no way to obtain i3 server details. Exiting.\n"
              );
      EXIT_ON_ERROR;
  }
              
  // This function intializes the TCP socket to be used to contact the first hop i3 server,
  // if UseTCP flag is set in the configuration file.
  // If UsePing is set, this function blocks till the details of at least
  // one i3 server is available.
  init_tcp_ctx(ctx);

  return ctx;
}


/************************************************************************
 * cl_ctx_exit - free all resources associated with the context (ctx)
 ***********************************************************************/
int cl_ctx_exit(cl_context *ctx)
{
  if (ctx == NULL)
    return CL_RET_NO_CONTEXT;
   
  cl_destroy_context(ctx);

  return CL_RET_OK;
}
 


int cl_ctx_loop(cl_context *ctx)
{
    fd_set rset;

    if (ctx == NULL) {
        return CL_RET_NO_CONTEXT; 
    }
  
    FD_ZERO(&rset);

    for (;;) {
#ifndef _WIN32
	FD_SET(0, &rset); /* just here, to be modified if application
		                * listens on other fds
		                */
#endif
        if (cl_select(0, &rset, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
	            continue;
            } else {
	            I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_FATAL, "select_error\n");
            }
        }
    }
  return errno;
}

/*************************************************************************
 * cl_ctx_create_trigger - create a trigger that points to the client, 
 *                         i.e., to the context's socket
 * 
 * input:
 *   ctx - context (only for cl_ctx_create_trigger)
 *   id, prefix_len  - trigger ID and prefix len
 *   key - key = h_l(id) if the trigger is left constrained, and
 *               h_r(id) if the trigger is right constrained, where h_l
 *               and h_r are two one-way hash functions
 *   flags - flags associated to trigger creation; possible values:
 *           CL_TRIGGER_CFLAG_R_CONSTRAINT - right constraint trigger
 *           CL_TRIGGER_CFLAG_L_CONSTRAINT - left constraint trigger
 *           CL_TRIGGER_CFLAG_PUBLIC - public trigger; otherwise the trigger
 *                                     is private. If the trigger is public
 *                                     then it has to be left constraint, 
 *                                     i.e., CL_TRIGGER_CFLAG_R_CONSTRAINT 
 *                                     and CL_TRIGGER_CFLAG_PUBLIC cannot be
 *                                     used simultaneously
 *   rc -  error code; possible values:
 *           CL_RET_NO_CONTEXT
 *           CL_RET_TRIGGER_ALREADY_EXISTS
 *           error code returned by update_id_key
 *   
 * return value:
 *   - pointer to the instantiated trigger
 *
 * Note:
 *   - the key field of the ID is upadted to h_l(key) or h_r(key)     
 *************************************************************************/
cl_trigger *cl_ctx_create_trigger(cl_context *ctx,
				  ID *id, uint16_t prefix_len, Key *key, 
				  uint16_t flags, int *rc)
{
  cl_trigger *ctr;

  //ADDED_DILIP
  *rc = CL_RET_OK; //default return code if nothing goes wrong
 
  if (!ctx) {
    *rc = CL_RET_NO_CONTEXT;
    return NULL;
  }
 
  *rc = update_id_key(id, key, flags);
  if (*rc != CL_RET_OK)
    return NULL;

  ctr = cl_create_trigger_gen(ctx,
			      I3_ADDR_TYPE_IPv4, id, prefix_len, 
			      ctx->local_ip_addr, ctx->local_port, 
			      NULL, key,
			      /* flags are initialized in 
			       * cl_ctx_insert_trigger
			       */
			      0);
  if (!ctr) {
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_ctx_create_trigger: duplicate trigger insertion.\n");
    ctr = cl_get_trigger_by_id(ctx->trigger_htable[CL_HASH_TRIG(id)], id);
    if (ctr)
      *rc = CL_RET_TRIGGER_ALREADY_EXISTS;
  }

  return ctr;
}
 

/*************************************************************************
 * cl_ctx_create_trigger_stack - same as
 *   cl_ctx_create_trigger/cl_create_trigger_addr but the trigger
 *   points to stack instead of the contex's socket
 *************************************************************************/
cl_trigger *cl_ctx_create_trigger_stack(cl_context *ctx,
					ID *id, uint16_t prefix_len, 
					ID *stack, int stack_len, 
					uint16_t flags, int *rc)
{
  cl_trigger *ctr;
  i3_stack   *s;

  struct in_addr nothing;
  nothing.s_addr = 0; // this line not necessary, but just here to avoid the warning.

  if (!ctx) {
    *rc = CL_RET_NO_CONTEXT;
    return NULL;
  }
  
  if (stack_len == 0 || stack_len >= I3_MAX_STACK_LEN) {
    *rc = CL_RET_INVALID_STACK_LEN;
    return NULL;
  }

  *rc = update_id_id(id, &stack[0], flags);

  if (*rc != CL_RET_OK)
    return NULL;

  s = alloc_i3_stack();
  init_i3_stack(s, stack, stack_len);

  ctr = cl_create_trigger_gen(ctx, I3_ADDR_TYPE_STACK, 
			      id, prefix_len, nothing, 0, s, 0, 0);

  if (!ctr) {
    free_i3_stack(s);
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, 
		"cl_ctx_create_trigger_stack: duplicate trigger insertion.\n");
    ctr = cl_get_trigger_by_id(ctx->trigger_htable[CL_HASH_TRIG(id)], id);
    if (ctr)
      *rc = CL_RET_TRIGGER_ALREADY_EXISTS;
  }

  return ctr;
}

/********************************************************************
 * cl_ctx_destroy_trigger - dealocate a trigger data structure
 *
 * input:
 *   ctx - context (only for cl_ctx_destroy_trigger)
 *   ctr - trigger to be destroyed
 *     
 * return value:
 *   - error code; possibe values 
 *       CL_RET_OK
 *       CL_RET_NO_TRIGGER
 *       CL_RET_NO_CONTEXT 
 *        
 * Note: if the trigger is not removed from the infrastructure, this
 *       function removes it
 *******************************************************************/
int cl_ctx_destroy_trigger(cl_context *ctx, cl_trigger *ctr)
{
  int rc;

  if (!ctx) 
    return CL_RET_NO_CONTEXT;
  
  if (!ctr) 
    return CL_RET_NO_TRIGGER;
   
  if (ctr->type == CL_TRIGGER_I3) {
    rc = cl_ctx_remove_trigger(ctx, ctr);
    if (rc != CL_RET_OK)
      return rc;
  }

  cl_delete_trigger(ctx, ctr);

  return CL_RET_OK;
}

/************************************************************************
 * cl_ctx_insert_trigger - insert a trigger into i3 
 *
 * input: 
 *   ctx - context (only for cl_ctx_insert_trigger)
 *   ctr - trigger
 *   flags - flags associated to trigger insertion; possible values
 *      
 ************************************************************************/
int cl_ctx_insert_trigger(cl_context *ctx, cl_trigger *ctr, uint16_t flags) 
{
  struct timeval tv;

  if (!ctr)
    return CL_RET_NO_TRIGGER;

  if (!ctx)
    return CL_RET_NO_CONTEXT;

  if (flags & CL_IFLAGS_TRIGGER_LOCAL) 
    ctr->type = CL_TRIGGER_LOCAL;
  else 
    ctr->type = CL_TRIGGER_I3;

  if (flags & CL_IFLAGS_TRIGGER_ALLOW_SHORTCUT)
    ctr->t->flags |= I3_TRIGGER_FLAG_ALLOW_SHORTCUT;

  if (ctr->type == CL_TRIGGER_I3) {
    cl_insert_trigger_into_i3(ctx, ctr);
    if (ctr->status == CL_TRIGGER_STATUS_INSERTED) {
      /* trigger already inserted; just update trigger info;
       * no need to set-up timeout_ack_timer 
       */
      ;
    } else {
      /* set challenge timeout  */
      tv.tv_sec  = ACK_TIMEOUT;
      tv.tv_usec = random_sec();
      trigger_set_timer(&tv, timeout_ack_insert, ctr);
    }
  } else {
    /* do nothing */ ;
  }
  
  //ADDED_DILIP
  return CL_RET_OK;

}


int cl_ctx_trigger_ratelimit(cl_context* ctx, cl_trigger *ctr, uint8_t type,
			     uint32_t depth, uint32_t r, uint32_t R)
{
  if (ctx == NULL)
    return CL_RET_NO_CONTEXT;
  
  if (!ctr) 
    return CL_RET_NO_TRIGGER;
 
  if (ctr->t->flags & I3_TRIGGER_FLAG_RATE_LIMIT) {
    assert(ctr->t->tb);
    /* trigger is already rate limited; just update the token buket */
    ctr->t->tb->type = type;
    ctr->t->tb->depth = depth;
    ctr->t->tb->r = r;
    ctr->t->tb->R = R;
    if (ctr->precomputed_pkt.p) {
      free(ctr->precomputed_pkt.p);
      /* need to precompute the packet after the change */
      cl_make_trigger_packet(ctx, ctr->t, 
			     I3_OPT_TRIGGER_INSERT, &ctr->precomputed_pkt);
    }
  } else {
    ctr->t->flags |= I3_TRIGGER_FLAG_RATE_LIMIT;
    ctr->t->tb = alloc_token_bucket();
    init_token_bucket(ctr->t->tb, type, depth, r, R);
  }
  if (ctr->status == CL_TRIGGER_STATUS_INSERTED) {
    /* update trigger token-bucket constraints */
    cl_insert_trigger_into_i3(ctx, ctr);
  }
  return CL_RET_OK;
}

//ADDED_DILIP
int cl_ctx_register_trigger_callback(cl_context* ctx, cl_trigger *ctr, uint16_t cbk_type, 
				 void (*fun)(cl_trigger*,void *data, void *fun_ctx), void *fun_ctx)
{
  if (ctx == NULL)
    return CL_RET_NO_CONTEXT;
  
  if (!ctr) 
    return CL_RET_NO_TRIGGER;
 
  return cl_register_trigger_callback1(ctr, cbk_type, fun, fun_ctx);
}

int cl_ctx_register_fd_callback(cl_context *ctx, int fd, 
				int type, void (*fun)(), void *data)
{
  fd_node *n;

  if (ctx == NULL)
    return CL_RET_NO_CONTEXT;

  switch (type) {
  case CL_FD_TYPE_READ:
    if (n = get_fd_node(ctx->i3fds->readfd_list, fd))
      return CL_RET_DUPLICATE_FD;
    if ((n = alloc_fd_node(fd, fun, data)) == NULL)
      /* just to please the compiler; alloc_fd_node will panic if it cannot
       * allocate memory
       */
      return CL_RET_OK;
    insert_fd_node_in_list(&ctx->i3fds->readfd_list, n);
    break;
  case CL_FD_TYPE_WRITE:
    if (n = get_fd_node(ctx->i3fds->writefd_list, fd))
      return CL_RET_DUPLICATE_FD;
    if ((n = alloc_fd_node(fd, fun, data)) == NULL)
      return CL_RET_OK;
    insert_fd_node_in_list(&ctx->i3fds->writefd_list, n);
    break;
  case CL_FD_TYPE_EXCEPT:
    if (n = get_fd_node(ctx->i3fds->exceptfd_list, fd))
      return CL_RET_DUPLICATE_FD;
    if ((n = alloc_fd_node(fd, fun, data)) == NULL)
      return CL_RET_OK;
    insert_fd_node_in_list(&ctx->i3fds->exceptfd_list, n);
    break;
  default:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_register_fd_callback: unknown file descriptor type\n");
  }

  ctx->i3fds->max_fd = MAX(ctx->i3fds->max_fd, fd);
  
  return CL_RET_OK;
}


/************************************************************************
 * cl_ctx_unregister_fd_callback - unregister a callback associated with a
 *                                 file descriptor fd
 * NOTE: this should be done once the file descriptor is closed
 ************************************************************************/
int cl_ctx_unregister_fd_callback(cl_context *ctx, int fd, int type)
{
  fd_node *n;

  if (ctx == NULL)
    return CL_RET_NO_CONTEXT;

  switch (type) {
  case CL_FD_TYPE_READ:
    n = get_fd_node(ctx->i3fds->readfd_list, fd);
    if (!n) 
      return CL_RET_INVALID_FD;
    remove_fd_node_from_list(&ctx->i3fds->readfd_list, n);
    break;
  case CL_FD_TYPE_WRITE:
    n = get_fd_node(ctx->i3fds->writefd_list, fd);
    if (!n) 
      return CL_RET_INVALID_FD;
    remove_fd_node_from_list(&ctx->i3fds->writefd_list, n);
    break;
  case CL_FD_TYPE_EXCEPT:
    n = get_fd_node(ctx->i3fds->exceptfd_list, fd);
    if (!n) 
      return CL_RET_INVALID_FD;
    remove_fd_node_from_list(&ctx->i3fds->exceptfd_list, n);
    break;
  default:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_register_fd_callback: unknown file descriptor type\n");
  }

  compute_max_i3_fds(ctx->i3fds);

  return CL_RET_OK;
}


/***********************************************************************
 *  cl_ctx_set_timer - set timer
 *
 *  input:
 *    ctx  - context
 *    tv   - timeout after which the timer expires
 *    fun  - function to be invoked when the timer expires
 *    data - application data passed back to the application when the
 *           callback is invoked
 *
 ************************************************************************/
cl_timer *cl_ctx_set_timer(cl_context *ctx, struct timeval *tv, 
			   void (*fun)(), void *data)
{
  uint64_t when;
  Event *ev;

  if (ctx == NULL)
    return NULL;

  when = wall_time();
  when = when + UMILLION*tv->tv_sec + tv->tv_usec;
  ev = newEvent(fun, data, when);

  insertEvent(&ctx->timer_heap, ev);

  return (cl_timer *)ev;
}

/**************************************************************************
 *  cl_ctx_send_stack - send packet to a stack of IDs
 *  
 *  input:
 *    ctx - context (only for cl_ctx_send)
 *    stack - stack, reppresented as an array of IDs; stack[0]
 *            represents the ID where the packet is sent next
 *    stack_len - number of IDs in the stack 
 *    clb - payload
 *    flags - flags associated to sending a packet; possible values:
 *             CL_PKT_FLAG_ALLOW_SHORTCUT - allow shortcuts  
 *        
 *  return value:
 *    - error code; possible values:
 *        CL_RET_OK
 *        CL_RET_NO_CONTEXT
 *        CL_RET_INVALID_STACK_LEN
 *	  CL_RET_MSG_SIZE
 *	  CL_RET_NO_SERVERS
 *	  CL_RET_NET_ERROR
 *************************************************************************/
int cl_ctx_send_stack(cl_context *ctx, ID *stack, int stack_len, 
		      cl_buf *clb, uint16_t flags)
{
  i3_stack *s;
  int err = 0;

  if (ctx == NULL)
    return CL_RET_NO_CONTEXT;
  
  if (stack_len == 0 || stack_len >= I3_MAX_STACK_LEN) 
    return CL_RET_INVALID_STACK_LEN;

 
  s = alloc_i3_stack();
  init_i3_stack(s, stack, stack_len);

  // for now, setting is_total_len to "0"
  err = cl_send_data_packet(ctx, s, clb, flags, 0);
  free_i3_stack(s);

  return err;
}



/************************************************************************
 * Returns RTT of given addr (in host format)
 ***********************************************************************/
int cl_ctx_get_rtt_server(cl_context* ctx, uint32_t addr, uint64_t *rtt)
{
    if (ctx == NULL || ctx->list == NULL)
	return CL_RET_NO_AUTO_SERVER_SELECT;

    *rtt = get_rtt(ctx->list, addr);
    
    return CL_RET_OK;
}

int cl_ctx_get_rtt_id(cl_context* ctx, ID *id, uint64_t *rtt)
{
    if (ctx == NULL || ctx->list == NULL)
	return CL_RET_NO_AUTO_SERVER_SELECT;

    *rtt = get_rtt_id(ctx->list, id);
    
    return CL_RET_OK;
}

/************************************************************************
 * Returns top k servers sorted by RTT.
 *
 * At return, "k" would contain the actual number of servers that are
 * returned (may be smaller than requested)
 ***********************************************************************/
int cl_ctx_get_top_k_servers(cl_context* ctx, int *k, uint32_t best_addr[],
    		uint16_t best_port[], uint64_t	best_rtt[])
{ 
    if (ctx == NULL || ctx->list == NULL) 
	return CL_RET_NO_AUTO_SERVER_SELECT;
    
    *k = get_top_k(ctx->list, *k, best_addr, best_port, best_rtt);
   
   //printf("in cl_get_top_k_servers, k returned = %d\n", *k); 
    return CL_RET_OK;
}

int cl_ctx_get_top_k_ids(cl_context* ctx,int *k, ID best_id[], uint64_t best_rtt[])
{
    if (ctx == NULL || ctx->list == NULL)
	return CL_RET_NO_AUTO_SERVER_SELECT;

    *k = get_top_k_id(ctx->list, *k, best_id, best_rtt);
    
    return CL_RET_OK;
}

/** Close all the open sockets, including the ping socket 
 */
void i3_close_all_sockets (cl_context* ctx) {
	
	if (ctx->fd != -1) {
		nw_close (ctx->fd);
	}
	if (ctx->is_tcp && ctx->tcp_fd != -1) {
		nw_close (ctx->tcp_fd);
	}
	//close_ping_socket();
}

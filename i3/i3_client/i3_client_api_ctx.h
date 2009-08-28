/***************************************************************************
                          i3_client_api_ctx.h  -  description
                             -------------------
    begin                : Aug 20 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_API_CTX_H
#define I3_CLIENT_API_CTX_H

#include "i3_client.h"
#include "i3_client_api.h"
#include "../i3/i3_config.h"

/* create and initialize the context */
cl_context *cl_ctx_init(const char *cfg_file, int *rc, int i3_port_num);

/* destroy context */
int cl_ctx_exit(cl_context *ctx);

/*
 * cl_ctx_select - function that replaces the select() function 
 *             (sys/select.h) Either this function or cl_loop() should be 
 *             invoked at the end of every client program since 
 *             cl_select()/cl_loop() are responsibe with the trigger 
 *             refreshing and processing the options of the received packets.
 */
#define cl_ctx_select(ctx, n, readfds, writefds, exceptfds, cl_to) \
  cl_context_select(ctx, n, readfds, writefds, exceptfds, cl_to)
int cl_ctx_loop(cl_context *ctx);


/* create a trigger pointing to the creator
 * Possible flags:
 *   CL_TRIGGER_CFLAG_R_CONSTRAINT - right constraint trigger
 *   CL_TRIGGER_CFLAG_L_CONSTRAINT - left constraint trigger
 *   CL_TRIGGER_CFLAG_PUBLIC - public trigger; otherwise the trigger
 *                             is private. If the trigger is public
 *                             then it has to be left constraint, 
 *                             i.e., CL_TRIGGER_CFLAG_R_CONSTRAINT 
 *                             and CL_TRIGGER_CFLAG_PUBLIC cannot be
 *                             used simultaneously
 */
cl_trigger *cl_ctx_create_trigger(cl_context *ctx,
				  ID *id, uint16_t prefix_len, Key *key, 
				  uint16_t flags, int *rc);
/* create a trigger pointing to a stack */
cl_trigger *cl_ctx_create_trigger_stack(cl_context *ctx,
					ID *id, uint16_t prefix_len, 
					ID *stack, int stack_len, 
					uint16_t flags, int *rc);
/* destroy trigger */
int cl_ctx_destroy_trigger(cl_context *ctx, cl_trigger *ctr);
/* insert trigger into i3
 * Possible flags: 
 *   CL_IFLAGS_TRIGGER_LOCAL - trigger is only local, i.e., it is not inserted
 *                             into i3
 *   CL_IFLAGS_TRIGGER_ALLOW_SHORTCUT - allow shortcut
 */
int cl_ctx_insert_trigger(cl_context *ctx, cl_trigger *ctr, uint16_t flags);

#define cl_ctx_remove_trigger(ctx, ctr) cl_remove_trigger_from_i3(ctx, ctr)

int cl_ctx_trigger_ratelimit(cl_context* ctx, cl_trigger *ctr, uint8_t type,
			     uint32_t depth, uint32_t r, uint32_t R);

/* send functions */
int cl_ctx_send_stack(cl_context *ctx, ID *stack, int stack_len, 
		      cl_buf *clb, uint16_t flags);
#define cl_ctx_send(ctx, id, clb, flags) \
  cl_ctx_send_to_stack(ctx, id, 1, clb, flags)


/* register callback functions and timers */
#define cl_ctx_register_callback(g_ctx, cbk_type, fun, fun_ctx) \
 cl_register_context_callback(g_ctx, cbk_type, fun, fun_ctx)

//ADDED_DILIP
int cl_ctx_register_trigger_callback(cl_context *ctx, cl_trigger *ctr, uint16_t cbk_type, 
				 void (*fun)(cl_trigger* ctr, void* data, void* fun_ctx), void *fun_ctx); //DILIP


int cl_ctx_unregister_fd_callback(cl_context *ctx, int fd, int type);
int cl_ctx_register_fd_callback(cl_context *ctx, int fd, 
				int type, void (*fun)(), void *data);
int cl_ctx_unregister_fd_callback(cl_context *ctx, int fd, int type);
cl_timer *cl_ctx_set_timer(cl_context *ctx, struct timeval *tv, 
			   void (*fun)(), void *data);

/* 
 * Get close servers from a list of servers 
 *   - currently uses a combination of latitude-longitude + pings
 */
int cl_ctx_get_rtt_server(cl_context *ctx, uint32_t addr, uint64_t *rtt);
int cl_ctx_get_rtt_id(cl_context *ctx, ID *id, uint64_t *rtt);
int cl_ctx_get_top_k_servers(cl_context* ctx, int *k, uint32_t best_addr[], uint16_t best_port[], uint64_t best_rtt[]);
int cl_ctx_get_top_k_ids(cl_context* ctx, int *k, ID best_id[], uint64_t best_rtt[]);


void i3_close_all_sockets (cl_context* ctx);

#endif // I3_CLIENT_API_CTX_H


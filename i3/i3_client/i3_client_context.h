/***************************************************************************
                          i3_client_context.h  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_CONTEXT_H
#define I3_CLIENT_CONTEXT_H

#include "i3_client.h"

#define CL_CONTINUE 100
#define CL_NO_CONTINUE 200
#define CL_RECV_ERROR -100

cl_context *cl_create_context(struct in_addr *ip_addr,
			      uint16_t local_port
			      );
void cl_destroy_context(cl_context *ctx);

void init_tcp_ctx(cl_context* ctx);

//TODO: remove duplicate declaration in i3_client_callbacks.h
int cl_register_context_callback(cl_context *ctx, uint16_t cbk_type, 
				 void (*fun)(void* ctx_data, void* data, void* fun_ctx), 
                 void *fun_ctx);


int cl_context_select(cl_context *ctx, int n, 
		      fd_set *readfds, fd_set *writefds, fd_set *exceptfds, 
		      struct timeval *cl_to);

void read_srv_list(cl_context *ctx);
void update_srv_list(cl_context *ctx);
srv_address *set_i3_server_status(srv_address *s_array, 
				  uint32_t ip_addr, uint16_t port,
				  int status);
int get_i3_server(int num_servers, srv_address *s_array);

int cl_process_recd_i3_pkt(cl_context*, cl_buf*);

void timeout_address_change(cl_context *ctx);
void timeout_server_update(cl_context *ctx);
#endif

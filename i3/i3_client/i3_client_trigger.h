/***************************************************************************
                          i3_client_trigger.h  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_TRIGGER_H
#define I3_CLIENT_TRIGGER_H

 
/* functions implemented in i3_client_trigger.c */
int cl_insert_trigger_into_i3(cl_context *ctx, cl_trigger *ctr);
int cl_remove_trigger_from_i3(cl_context *ctx, cl_trigger *ctr);
cl_trigger *cl_alloc_trigger();
void cl_free_trigger(cl_trigger *ctr);
cl_trigger *cl_get_trigger_from_list(cl_trigger *head, i3_trigger *t);
cl_trigger *cl_get_trigger_by_id(cl_trigger *ctl_head, ID *id);
int cl_get_max_prefix_len_from_list(cl_trigger *ctr_head, ID *id);
void cl_free_trigger_list(cl_trigger *ctr_head);
void cl_remove_trigger_from_list(cl_trigger **phead, cl_trigger *ctr);
void cl_add_trigger_to_list(cl_trigger **phead, cl_trigger *ctr);
void cl_update_triggers(cl_context *ctx);
void cl_delete_trigger(cl_context *ctx, cl_trigger *ctr);

cl_trigger *cl_create_trigger_gen(cl_context *ctx, 
				  uint16_t addr_type, 
				  ID *id, uint16_t prefix_len,
				  struct in_addr ip_addr, uint16_t port,
				  i3_stack *stack, Key *key, uint16_t);
void process_trigger_option(cl_context *ctx, i3_trigger *t, 
			    int opt_type, struct sockaddr_in *fromaddr);
void cl_process_option_list(cl_context *ctx, i3_header *hdr,
			    struct sockaddr_in *fromaddr);
void cl_make_trigger_packet(cl_context *ctx, i3_trigger *t, 
			    char opt_type, buf_struct *buf);


void timeout_ack_insert(cl_trigger *ctr);
void timeout_ack_refresh(cl_trigger *ctr);
#endif

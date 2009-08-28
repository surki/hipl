/***************************************************************************
                          i3_client_api.h  -  description
                             -------------------
    begin                : Aug 20 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_API_H
#define I3_CLIENT_API_H

#include "i3_client.h"
#include "../i3/i3_config.h"

#define cl_timer Event

/** 
  * cbk_packet stands for "Callback Packet".
  * This structure encapsulates the contents
  * of a packet and the stack of IDs and stack len associated with 
  * its header.  It is used in the data arguments of callbacks of type
  * CL_CBK_RECEIVE_PACKET.
  */
typedef struct cbk_packet {
  ID *ids;      /** Stack of IDs associated with the packet. */
  int stack_len;      /** Number of IDs in the stack */
  cl_buf* clb;  /** The contents of the packet */
} cbk_packet;


int cl_init(char *cfg_file);
int cl_exit();

int cl_select(int n, fd_set *readfds, fd_set *writefds, 
	      fd_set *exceptfds, struct timeval *cl_to);
int cl_loop();


cl_trigger *cl_create_trigger(ID *id, uint16_t prefix_len, Key *key, 
			      uint16_t flags);

cl_trigger *cl_create_trigger_stack(ID *id, uint16_t prefix_len, 
				    ID *stack, int stack_len, 
				    uint16_t flags);


/** This function forces the specified id to be public
  * It sets/unsets the appropriate bit in the id.
  * Note that id changes; please remember this when you try to use
  * the 'same' id for sending packets.
  */
void cl_set_public_id(ID *id);

/** This function forces the specified id to be private.
  * It sets/unsets the appropriate bit in the id.
  * Note that id changes; please remember this when you try to use
  * the 'same' id for sending packets.
  */
void cl_set_private_id(ID *id);


/**
 * This function is used to create a trigger which points to an i3 id.
 * Please note that this function does not insert the trigger into the i3 infrastructure.
 * <code>cl_insert_trigger</code> is used to insert the trigger into the i3 infrastructure.
 * 
 * @param id The i3 Id of the trigger to be created.
 * 
 * @param prefix_len The length of the prefix of the id to be used for matching.
 * 
 * @param id_target The i3 Id to which this trigger points.
 *
 * @param flags Flags are used to specify the properties of the trigger being created.
 * The following flags can be used individually or ORed together.
 * <ul>
 *	<li><code>CL_TRIGGER_CFLAG_R_CONSTRAINT</code> - Make the trigger right constrained.
 *      <li><code>CL_TRIGGER_CFLAG_L_CONSTRAINT</code> - Make the trigger left constrained.
 *      <li><code>CL_TRIGGER_CFLAG_PUBLIC</code> - Make this a public trigger.  If this is flag is 
 *      not used, the trigger is private by default.  Please note that a public trigger must be left constrained.
 *      This means that you cannot use the flags <code>CL_TRIGGER_CFLAG_R_CONSTRAINT</code> and
 *      CL_TRIGGER_CFLAG_PUBLIC together.
 * </ul>
 *
 * @return A pointer to the created trigger.
 */
#define cl_create_trigger_id(id, prefix_len, id_target, flags) \
  cl_create_trigger_stack(id, prefix_len, id_target, 1, flags)

int cl_destroy_trigger(cl_trigger *ctr);

int cl_insert_trigger(cl_trigger *ctr, uint16_t flags);

int cl_remove_trigger(cl_trigger *ctr);

int cl_send_stack(ID *stack, int stack_len, cl_buf *clb, uint16_t flags);


/*
 * This function is used to send a packet addressed to an i3 Id.
 *  
 * @param id The i3 id to which this packet is addressed 
 * @param clb The packet payload
 * @param flags The flags associated with sending a packet. It can take on the
 * following values:
 *
 *  <ul>
 *	<li><code>CL_PKT_FLAG_ALLOW_SHORTCUT</code> All this packet to be shortcutted.  
 *  </ul>
 *
 *  @return One of the following codes is returned.
 *
 *	<ul>
 *	    <li><code>CL_RET_OK</code> - Packet was successfully sent.
 *	    <li><code>CL_RET_NO_CONTEXT</code> - No i3 context was found.  
 *	    Probably cl_init() was omitted initially.
 *	    <li><code>CL_RET_MSG_SIZE</code> - the packet payload is
 *	    too large to be transferred.
 *	    <li><code>CL_RET_NO_SERVERS</code> - no i3 servers are
 *	    known or reachable.
 *	    <li><code>CL_RET_NET_ERROR</code> - the packet was not
 *	    sent due to a low-level network or socket error.
 *	</ul>
 */	
#define cl_send(id, clb, flags) cl_send_stack(id, 1, clb, flags)


int cl_register_trigger_callback(cl_trigger *ctr, uint16_t cbk_type, 
				 void (*fun)(cl_trigger*, void* data, void* fun_ctx), void *fun_ctx);

int cl_register_callback(
            uint16_t cbk_type, 
            void (*fun)(void *ctx_data, void *data, void *fun_ctx), 
            void *fun_ctx);

int cl_register_fd_callback(int fd, int type, void (*fun)(), void *data);
int cl_unregister_fd_callback(int fd, int type);

cl_timer *cl_set_timer(struct timeval *tv, void (*fun)(), void *data);
void cl_cancel_timer(cl_timer *ct);

/* 
 * Create a cl_bug data structure which is used for sending and receiving packets.
 * @param len The size of the buffer to be created.
 */
cl_buf *cl_alloc_buf(unsigned int len);

/*
 * Free the memory of the specified cl_buffer
 * @param clb Pointer to the buffer to be deallocated.
 */
void cl_free_buf(cl_buf *clb);

/* 
 * Get close servers from a list of servers 
 *   - currently uses a combination of latitude-longitude + pings
 */
int cl_get_rtt_server(uint32_t addr, uint64_t *rtt);
int cl_get_rtt_id(ID *id, uint64_t *rtt);
int cl_get_top_k_servers(int *k, uint32_t best_addr[], uint16_t best_port[], uint64_t best_rtt[]);
int cl_get_top_k_ids(int *k, ID best_id[], uint64_t best_rtt[]);


#endif // I3_CLIENT_API_H

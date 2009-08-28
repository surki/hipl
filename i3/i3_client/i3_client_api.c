/***************************************************************************
                          i3_client_api.c  -  description
                             -------------------
    begin                : Aug 20 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/


#include <errno.h>
#include <time.h>
#ifndef _WIN32
    #include <unistd.h>
#endif
#include "../utils/netwrap.h"

#include "i3.h"
#include "i3_client_fun.h"
#include "i3_debug.h"
#include "i3_client.h"
#include "i3_client_api.h"
#include "i3_client_api_ctx.h"
#include "i3server_list.h"
#include "gen_utils.h"

/**
 * This structure stores all i3 specific information.
 * By default, all API functions use g_ctx.  Moreover, you can have only one g_ctx
 * structure in a program as it is static.
 * 
 * If you wish to use a different instance of the context, rather
 * than the one defined here, the functions in i3_client_api_ctx will be 
 * helpful.  Those function explicitly take a cl_context structure as one
 * of their inputs.
 */ 
static cl_context *g_ctx = NULL; /* context associated with the process */

/************************************************************************
 * cl_init - same as cl_ctx_init but initialize a global context (g_ctx)
 *           which is later refered by the cl_* functions
 *************************************************************************/
/**
 * This function initializes the i3 data structures.  It must be called before
 * calling any other I3 API functions.
 *
 * @param cfg_file The i3 configuration file from which parameters are read.
 * 
 * @return One of the following error codes is returned.
 *	    <ul>
 *               <li><code>CL_RET_OK</code> - Initialization was completed successfully.
 *               <li><code>CL_RET_INVALID_CFG_FILE</code> - There was an error in the supplied configuration file.
 *               <li><code>CL_RE_NO_CONTEXT</code> - Unable to initialize the context.
 *               <li><code>CL_RET_DUP_CONTEXT</code> - I3 was already initialized previously.
 *		 <li><code>CL_RET_NET_ERROR</code> - networking subsystem could not be initialized.
 *				    You shouldn't call this function multiple times.
 *	    </ul>
 */
int cl_init(char *cfg_file)
{
  int rc;

  init_rand();

  if (0 != nw_init())
      return CL_RET_NET_ERROR;

  if (g_ctx != NULL)
    return CL_RET_DUP_CONTEXT;
  
  g_ctx = cl_ctx_init(cfg_file, &rc, 0);

  return rc;
}


/**
 * This function is called to free all resources allocated by
 * cl_init().  This function is usually called when you are exiting the program.
 * 
 * @return One of the following error codes is returned.
 *	    <ul>
 *		<li><code>CL_RET_OK</code> - All resources were successfully freed.
 *		<li><code>CL_RET_NO_CONTEXT</code> - There was no i3 context to free.  
 *		This error usually occurs when a cl_init() was initially omitted.
 *	    </ul>
 */
int cl_exit()
{
  int rc;

  rc = cl_ctx_exit(g_ctx);
  g_ctx = NULL;
  return rc;
}


/************************************************************************
 * cl_selct - function that replaces the select() function 
 *            (sys/select.h) Either this function or cl_loop() should be 
 *            invoked at the end of every client program since 
 *            cl_select()/cl_loop() are responsibe with the trigger 
 *            refreshing and processing the options of the received packets.
 ***********************************************************************/
/**
 * This function should be called in the client program after all initialization
 * has been completed.
 * This function loops indefinitely and does not return unless there is an 
 * error.  It listens for packets on the i3 socket and other sockets added 
 * using cl_register_fd_callback(). 
 */
int cl_select(int n, fd_set *readfds, fd_set *writefds, 
	      fd_set *exceptfds, struct timeval *cl_to)
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT; 
  return cl_ctx_select(g_ctx, n, readfds, writefds, exceptfds, cl_to); /*xxx */
}


int cl_loop(void)
{
  return cl_ctx_loop(g_ctx);
}


/**
 * This function is used to create a trigger which points to the client,
 * i.e. the machine on which this function is executed.  
 * Please note that this function does not insert the trigger into the i3 infrastructure.
 * <code>cl_insert_trigger</code> is used to insert the trigger into the i3 infrastructure.
 * 
 * @param id The i3 Id of the trigger to be created.
 * 
 * @param prefix_len The length of the prefix of the id to be used for matching.
 * 
 * @param key The key for this trigger. <br>
 *		 The key is equal to h_l(id) if the trigger is left constrained, and<br>
 *               h_r(id) if the trigger is right constrained, <br>
 *               where h_l and h_r are two one-way hash functions.
 *	         The key field of the ID is upadted to h_l(key) or h_r(key).
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
 *      Please note that trigger id might be changed by this step.  For example, if the CL_TRIGGER_CFLAG_PUBLIC
 *      is specified and the public bit of the id is not set, it will be set when you call this function.
 *      Please remember this fact when you try to use this id to contact the host - you will might have the change
 *      the id by calling set_public_id before using it.  The same applies to CL_TRIGGER_CFLAG_PRIVATE too (Note
 *      that CL_TRIGGER_CFLAG_PRIVATE is assumed by default unless CL_TRIGGER_CLFAG_PUBLIC is specified.)
 * </ul>
 * 
 * @return A pointer to the created trigger.
 */
cl_trigger *cl_create_trigger(ID *id, uint16_t prefix_len, Key *key, 
			      uint16_t flags)
{
  int rc;
  return cl_ctx_create_trigger(g_ctx, id, prefix_len, key, flags, &rc);
}


/**
 * This function is similar to cl_create_trigger except that the created
 * trigger points to the specificed stack of i3 IDs instead of the 
 * client machine.
 *
 * Please note that this function does not insert the trigger into the i3 infrastructure.
 * <code>cl_insert_trigger</code> is used to insert the trigger into the i3 infrastructure.
 *
 * @param id The i3 Id of the trigger to be created.
 * 
 * @param prefix_len The length of the prefix of the id to be used for matching.
 * 
 * @param stack	The stack of i3 ids to which this trigger points
 * @param stack_len The number of i3 ids in the stack.
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
cl_trigger *cl_create_trigger_stack(ID *id, uint16_t prefix_len, 
				    ID *stack, int stack_len, 
				    uint16_t flags)
{
  int rc;
  return cl_ctx_create_trigger_stack(g_ctx, id, prefix_len, stack, 
				     stack_len, flags, &rc);
}


/**
 * This function is used to deallocate a trigger created by
 * <code>cl_create_trigger.  This function not only frees up 
 * the memory used by the trigger in the local system, but also
 * removes it from the i3 infrastructure.
 *
 * @param ctr Pointer to the trigger to be destroyed.
 *
 * @return One of the following codes is returned.
 *	<ul>
 *	    <li><code>CL_RET_OK</code> - The trigger was successfully destroyed.
 *	    <li><code>CL_RET_NO_CONTEXT</code> - No i3 context was available or
 *	    invalid context. Probably cl_init() was not called initially.
 *	</ul>
 */
int cl_destroy_trigger(cl_trigger *ctr)
{
  return cl_ctx_destroy_trigger(g_ctx, ctr);
}


/**
 * This function inserts the specified trigger into the i3 
 * infrastructure.
 *
 * @param ctr Pointer to the trigger to be inserted.
 * @param flags The following flags can be specified at trigger insertion.
 *	<ul>
 *	    <li><code>CL_IFLAGS_TRIGGER_LOCAL</code> - This trigger should be inserted locally, i.e. not
 *	    in the i3 infrastructure.
 *	    <li><code>CL_IFLAGS_TRIGGER_ALLOW_SHORTCUT</code> - This trigger allows shortcuts.
 *	</ul>
 * @return One of the following codes is returned.
 *	<ul>
 *	    <li><code>CL_RET_OK</code> - The trigger was successfully submitted for insertion.
 *	    The trigger insertion callbacks (if any were registered) will be executed when 
 *	    a confirmation message for trigger insertion is received from the infrastructure.
 *	    
 *	    <li><code>CL_RET_NO_CONTEXT</code> - No i3 context was available or
 *	    invalid context. Probably cl_init() was not called initially.
 *
 *	    <li><code>CL_RET_NO_TRIGGER</code> - The trigger to be inserted is NULL.
 *	</ul>
 */
int cl_insert_trigger(cl_trigger *ctr, uint16_t flags) 
{
  return cl_ctx_insert_trigger(g_ctx, ctr, flags);
}

/**
 * This function removes the specified trigger from the i3 infrastructure.
 * However, it is not destroyed from the local system, i.e. its data structures
 * are not deallocated.  It can be reinserted at a later point using 
 * <code>cl_insert_trigger</code>.
 *
 * @param ctr The trigger to be removed.
 *
 * @return One of the following codes is returned.
 *	<ul>
 *	    <li><code>CL_RET_OK</code> - The trigger was successfully submitted for removal.
 *	    
 *	    <li><code>CL_RET_NO_CONTEXT</code> - No i3 context was available or
 *	    invalid context. Probably cl_init() was not called initially.
 *
 *	    <li><code>CL_RET_NO_TRIGGER</code> - The trigger to be removed is NULL.
 *	</ul>
 */
int cl_remove_trigger(cl_trigger *ctr)
{
  return cl_ctx_remove_trigger(g_ctx, ctr);
}


/**
 * This function limits the traffic forwarded by a trigger using 
 * token-bucket constraints. 
 *
 * Note 1: This function takes action only if/when the trigger
 * is inserted in the i3 infrastructure. If the trigger is local 
 * (i.e. it was inserted using the 
 * <li><code>CL_IFLAGS_TRIGGER_LOCAL</code></li> flag) this function
 * has no effect.
 *
 * Note 2: This function uses an unreliable message to update
 * the trigger data structure at the i3 node. If this message is lost
 * it may take one full refresh interval until this function
 * takes effect.
 *
 * @param ctr The trigger to be rate limited using a token bucket.
 *
 * @param type The type of token bucket, specifying data units. 
               Possible values are  TOKEN_BUKET_PACKET and  
               TOKEN_BUKET_BYTE, respectively.
 *
 * @param depth Token bucket depth (bytes or packets, depending on "type")
 *
 * @param r Token bucket average rate (Bps or pps)
 *
 * @param R Token bucket peek rate (Bps or pps)
 *
 * @return One of the following codes is returned.
 *	<ul>
 *	    <li><code>CL_RET_OK</code> - The trigger was successfully submitted for removal.
 *	    
 *	    <li><code>CL_RET_NO_CONTEXT</code> - No i3 context was available or
 *	    invalid context. Probably cl_init() was not called initially.
 *
 *	    <li><code>CL_RET_NO_TRIGGER</code> - The trigger does not exist.
 *	</ul>
 */
int cl_trigger_ratelimit(cl_trigger *ctr, uint8_t type,
			  uint32_t depth, uint32_t r, uint32_t R)
{
  return cl_ctx_trigger_ratelimit(g_ctx, ctr, type, depth, r, R);
}

/**
    This function is used to register a callback associated with the current context.  This
    is more general than associating a callback with a particular trigger. 
 
    @param cbk_type The callback type.  It should be equal to one of the following values:
    <ol>
    
        <li><b>CL_CBK_TRIGGER_INSERTED</b> : This callback is invoked when the client receives the first ack as a result of a trigger insertion. 
        
        <li><b>CL_CBK_TRIGGER_REFRESH_FAILED</b> : This callback is invoked when the refreshing of a trigger fails. A refreshing failure occurs when none of the client's refreshing messages is acked during a refresh period which has a duration of TRIGGER_REFRESH_PERIOD sec. The client refreshes a trigger by sending a refreshing message MAX_NUM_TRIG_RETRIES*ACK_TIMEOUT before the refreshing period expires. If the first refresh message is not acked, the client resends the refresh message approximately every ACK_TIMEOUT sec.  A typical response of the client to this callback is to reinsert the trigger.
    
        <li><b>CL_CBK_TRIGGER_NOT_FOUND</b> : This callback is invoked when the client sends packets to an ID id, and there is no trigger in the network matching this id.

        <li><b>CL_CBK_RATELIMIT_EXCEEDED</b> : This callback is invoked when the client packet (sent to an ID id) is dropped due to the violation of the token-bucket traffic constraints (associated with the trigger whose ID is id). 

 is no trigger in the network matching this id.

        <li><b>CL_CBK_TRIGGER_CONSTRAINT_FAILED</b> : This callback invoked when an unconstrained trigger insertion is attempted.

        <li><b>CL_CBK_RECEIVE_PACKET</b> : This callback is invoked on receiving an i3 packet.

        <li><b>CL_CBK_RECEIVE_PAYLOAD</b> : This callback is invoked upon receiving a data packet. This callback is suppressed by the CL_CBK_RECEIVE_PACKET callback.
        
        <li><b>CL_CBK_SERVER_DOWN</b> : This callback is invoked when  the client concludes than an i3 server is down. This happens when the client either receives no acks (in the form of I3_OPT_CACHE_ADDR replies) to sending packets to that server during a refresh period of ID_REFRESH_PERIOD sec, or when the client receives no acks to three consecutive I3_OPT_REQUEST_FOR_CACHE queries.
       
        <li><b>CL_CBK_ROUTE_BROKEN</b> : This callback is invoked when server indicates that the i3server corresponding to the next hop is dead, and some action is needed to recover.
    </ol> 
    
    @param fun   The pointer to the function to be executed when the callback is invoked.
    This function pointer should point to a function with following signature:<br>
    
    <center><code>void funName (void *ctx_data, void *data, void *fun_ctx)</code></center>
    
    The parameters to the callback function are used as follows:
  
    <ul>
    
        <li><b>ctx_data</b>: This is parameter is used to pass some context info when the callback is invoked.  For example, for a callback of type CL_CBK_TRIGGER_INSERTED, the pointer to the <code>cl_trigger</code> which was inserted is passed via this argument.  Please note that the function signature must assign the type <code>void *</code> to this argument.  The argument must be appropriately cast before use inside the function body.

        <li><b>data</b>: This parameter is used to pass back some data which is generated at the time of callback invocation.
        For example, in the callback of type CL_CBK_RECEIVE_PAYLOAD, the payload of the packet received is passed through this argument.

        <li><b>fun_ctx</b>:  This parameter is used to pass back data which was stored at the time of callback registration.

    </ul>
 
    We now describe the values passed via the arguments of the callback function for the different callback types in the following table.

    <table>
        <tr>
            <td>CALLBACK TYPE</td>
            <td>ctx_data</td>
            <td>data</td>
            <td>fun_ctx</td>
        </tr>
        
        <tr>
            <td>CL_CBK_TRIGGER_INSERTED</td>
            <td><code>cl_trigger* t</code>, where t represents the inserted trigger</td>
            <td><code>NULL</code>
            <td>function context passed at callback registration</td>
        </tr>
 
        <tr>
            <td>CL_CBK_TRIGGER_REFRESH_FAILED</td>
            <td><code>cl_trigger* t</code>, where t represents the trigger whose refresh failed</td>
            <td><code>NULL</code>
            <td>function context passed at callback registration</td>
        </tr>
    
        <tr>
            <td>CL_CBK_TRIGGER_NOT_FOUND</td>
            <td><code>ID *id</code>, the id for which no matching trigger was found.</td>
            <td><code>NULL</code></td>
            <td>function context passed at callback registration</td>
        </tr>
        
        <tr>
            <td>CL_CBK_RATELIMIT_EXCEEDED</td>
            <td><code>ID *id</code>, the id whose token-bucket traffic constraints were violated.</td>
            <td><code>NULL</code></td>
            <td>function context passed at callback registration</td>
        </tr>
        
        <tr>
            <td>CL_CBK_TRIGGER_CONSTRAINT_FAILED</td>
            <td><code>ID *id</code>, the id for which trigger constraint failed.</td>
            <td><code>NULL</code></td>
            <td>function context passed at callback registration</td>
        </tr>
        
        <tr>
            <td>CL_CBK_RECEIVE_PACKET</td>
            <td><code>cl_trigger* t</code>, the trigger matching the packet's ID</td>
            <td><code>cbk_packet* pkt</code> encapsulates the header and payload of the received packet.
                Please note that the callback function should deallocate the memory pointed to by pkt after
                it is no longer needed by using <code>free(pkt)</code>.  This frees up only the temporary encapsulating
                cbk_packet and not the actual contents of the packet.</td>
            <td>function context passed at callback registration</td>
        </tr>
        
        <tr>
            <td>CL_CBK_RECEIVE_PAYLOAD</td>
            <td><code>cl_trigger* t</code>, the trigger matching the packet's ID</td>
            <td><code>cl_buf *b</code>, the payload of the data packet received</td>
            <td>function context passed at callback registration</td>
        </tr>
 
        <tr>
            <td>CL_CBK_SERVER_DOWN</td>
            <td><code>struct in_addr *ip_addr</code>, the IP address of the server which is down</td>
            <td><code>uint16_t *portNum</code>, the port on which i3 was supposed to have been running on the down server (TODO: It will better to aggregate the IP address and port info into a single structure as part of the first param.)</td>
            <td>function context passed at callback registration</td>
        </tr>
 
        <tr>
            <td>CL_CBK_ROUTE_BROKEN</td>
            <td><code>cl_trigger *t</code>, the trigger whose route has been broken [[VERIFY: unclear]]</td>
            <td><code>NULL</code></td>
            <td>function context passed at callback registration</td>
        </tr>
    </table>
 
  @return One of the following codes is returned.
 	<ul>
 	    <li><code>CL_RET_OK</code> 
 	    
 	    <li><code>CL_RET_NO_CONTEXT</code> - No i3 context was available or
 	    invalid context. Probably cl_init() was not called initially.
 
	</ul>
 */
int cl_register_callback(
            uint16_t cbk_type, 
            void (*fun)(void *ctx_data, void *data, void *fun_ctx), 
            void *fun_ctx) 
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;

  return cl_ctx_register_callback(g_ctx, cbk_type, fun, fun_ctx);
}

/*
 * This function is used to register a callback associated with a 
 * particular trigger. These callbacks are similar to the callbacks 
 * asssociated with the context (see cl_register_callback).
 * A callback associated with a trigger has strict priority over the same 
 * callback associated with the context.
 *
 * @param  t  The trigger with which the callback is associated.
 * @param cbk_type The callback type should be one of the following:
 *	<ol>
 *	    <li><code>CL_CBK_TRIGGER_INSERTED<code>
 *	    This callback is invoked when  the client receives the first ack
 *          as a result of a trigger insertion. 
 *
 *	    <li><code>CL_CBK_TRIGGER_REFRESH_FAILED</code>
 *	    This callback is invoked when the refreshing of a trigger fails. 
 *	    A refreshing failure occurs when none of the client's refreshing messages
 *          is acked during a refresh period which has a duration of 
 *          <code>TRIGGER_REFRESH_PERIOD</code> sec. The client refreshes a trigger by 
 *	    sending a refreshing message <code>MAX_NUM_TRIG_RETRIES * ACK_TIMEOUT</code> sec
 *	    before the refreshing period expires. If the first refresh message is not
 *          acked, the client resends the refresh message approximately every 
 *          <code>ACK_TIMEOUT</code> sec.
 *
 *          A typical response of the client to this callback is to reinsert the trigger
 *          using the cl_reinsert_trigger function.
 *                                  
 *	    <li><code>CL_CBK_RECEIVE_PACKET</code>
 *	    This callback is invoked upon receiving an i3 packet.
 *
 *                            The callback function has the following 
 *                            arguments: 
 *                                 fun(i3_trigger *t, i3_header *hdr,
 *                                     cl_buf *b, void *data), where "t" 
 *                               represents the trigger matching the
 *                               the packet's ID, "hdr" represents the 
 *                               packet's header, "b" contains the 
 *                               packet's payload, and "data" represents
 *                               the client's data.
 *
 *	    <li><code>CL_CBK_RECEIVE_PAYLOAD</code>
 *	    This callback is invoked upon receiving a data packet. 
 *	    This callback is suppressed by the <code>CL_CBK_RECEIVE_PACKET</code> callback.
 *
 *
 *   @param fun   The pointer to the function to be executed when the callback is invoked.
 *   This function pointer should point to a function with following signature:<br>
 *   
 *   <center><code>void funName (cl_trigger *ctr, void *data, void *fun_ctx)</code></center>
 *   
 *   The parameters to the callback function are used as follows:
 * 
 *   <ul>
 *   
 *       <li><b>ctr</b>: This parameter is used to pass a pointer to the trigger on which this
 *       callback was registered.
 *      
 *       <li><b>data</b>: This parameter is used to pass back some data which is generated
 *        at the time of callback invocation.  For example, in the callback of type 
 *        <code>CL_CBK_RECEIVE_PAYLOAD</code>, the payload of the packet received is passed 
 *        via this argument.
 *
 *       <li><b>fun_ctx</b>:  This parameter is used to pass back data which was stored i
 *       at the time of callback registration.
 *
 *  </ul>
 *
 *   We now describe the values passed via the arguments of the callback function for the 
 *   different callback types in the following table.
 *
 *   <table>
 *       <tr>
 *           <td>CALLBACK TYPE</td>
 *           <td>ctr</td>
 *           <td>data</td>
 *           <td>fun_ctx</td>
 *       </tr>
 *       
 *       <tr>
 *           <td>CL_CBK_TRIGGER_INSERTED</td>
 *           <td>ctr is a pointer to the inserted trigger</td>
 *           <td><code>NULL</code>
 *           <td>function context passed at callback registration</td>
 *       </tr>
 * 
 *       <tr>
 *           <td>CL_CBK_TRIGGER_REFRESH_FAILED</td>
 *           <td>ctr is a pointer to the trigger whose refresh failed</td>
 *           <td><code>NULL</code>
 *           <td>function context passed at callback registration</td>
 *       </tr>
 *   
 *       <tr>
 *           <td>CL_CBK_RECEIVE_PAYLOAD</td>
 *           <td>ctr is a pointer to the trigger matching the packet's ID</td>
 *           <td><code>cl_buf *b</code>, the payload of the data packet received</td>
 *           <td>function context passed at callback registration</td>
 *       </tr>
 *   </table>
 * @return One of the following codes is returned.
 *	<ul>
 *	    <li><code>CL_RET_OK</code> - 
 *	    
 *	    <li><code>CL_RET_NO_CONTEXT</code> - No i3 context was available or
 *	    invalid context. Probably cl_init() was not called initially.
 *
 *	    <li><code>CL_RET_NO_TRIGGER</code> - The trigger on which the callback
 *	    is to be registered is NULL.
 *	</ul>
 */
int cl_register_trigger_callback(cl_trigger *ctr, uint16_t cbk_type, 
				 void (*fun)(cl_trigger*,void* data, void* fun_ctx), void *fun_ctx) //DILIP
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;
  
  if (!ctr) 
    return CL_RET_NO_TRIGGER;
 
  return cl_register_trigger_callback1(ctr, cbk_type, fun, fun_ctx);
}

/*
 * This function is used to register a call back on a file descriptor open 
 * for reading (e.g., a socket file descriptor).  The callback function is
 * executed whenever there is data available to be read on the file descriptor.
 * This callback does NOT read the data from fd on application's behalf; 
 * the application has to explicitly read data from fd.
 * The application is also responsible for opening and closing the associated file/socket.
 *
 * @param fd The file descriptor on which the callback is to be registered.
 * @param type The type of the file descriptor can be one of the following:
 *  <ul>
 *	<li><code>CL_FD_TYPE_READ</code>
 *	<li><code>CL_FD_TYPE_WRITE</code>
 *	<li><code>CL_FD_TYPE_EXCEPT</code>
 *  </ul>
 *
 * @param fun The function to be called back.  The function should have the
 * following signature:<br>
 * <center><code>void funName(int fd, void *data)</code></center>
 * I
 * @param data Application data to be passed when the callback is invoked 
 */
int cl_register_fd_callback(int fd, int type, void (*fun)(), void *data)
{
  return cl_ctx_register_fd_callback(g_ctx, fd, type, fun, data);
}


/**
 * This function unregisters the callback associated with the specified file
 * descriptor.  This should be done once the file descriptor is closed.
 * @param fd The file descriptor whose callback is to be removed.
 * @param type The type of the file descriptor can be one of the following:
 *  <ul>
 *	<li><code>CL_FD_TYPE_READ</code>
 *	<li><code>CL_FD_TYPE_WRITE</code>
 *	<li><code>CL_FD_TYPE_EXCEPT</code>
 *  </ul>
 *
 */
int cl_unregister_fd_callback(int fd, int type)
{
  return cl_ctx_unregister_fd_callback(g_ctx, fd, type);
}

/**
 * Set a timer.  The specified callback is invoked when the timer
 * expires.
 * @param tv The time value after which the timer expires.
 * @param fun The function to be invoked when the timer expires.
 * @param data Application data passed back to the application when the
 *           callback is invoked.
 *
 * @return A pointer to the created timer.  
 */
cl_timer *cl_set_timer(struct timeval *tv, void (*fun)(), void *data)
{
  return cl_ctx_set_timer(g_ctx, tv, fun, data);
}


/** 
 * This function is used to cancel an existing timer.
 * @param ct The timer data structure of the timer to be cancelled.
 * This data structure is returned by <code>cl_set_timer</code>.
 */
void cl_cancel_timer(cl_timer *ct)
{
  ct->cancel = TRUE;
}

/*
 * This function is used to send a packet addressed to a stack 
 * of i3 ids.
 *  
 * @param stack The stack of i3 ids to which the packet is to be sent.
 * The stack is represented as an array of IDs; stack[0]
 * represents the ID where the packet is sent next
 * 
 * @param stack_len The number of IDs in the stack 
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
 *	    <li><code>CL_RET_INVALID_STACK_LEN</code> - The length of the stack is incorrect.
 *	    <li><code>CL_RET_MSG_SIZE</code> - the packet payload is
 *	    too large to be transferred.
 *	    <li><code>CL_RET_NO_SERVERS</code> - no i3 servers are
 *	    known or reachable.
 *	    <li><code>CL_RET_NET_ERROR</code> - the packet was not
 *	    sent due to a low-level network or socket error.
 *	</ul>
 */	
int cl_send_stack(ID *stack, int stack_len, 
		  cl_buf *clb, uint16_t flags)
{
  return cl_ctx_send_stack(g_ctx, stack, stack_len, clb, flags);
}
/************************************************************************
 * Returns RTT of given addr (in host format)
 ***********************************************************************/
int cl_get_rtt_server(uint32_t addr, uint64_t *rtt)
{
    return cl_ctx_get_rtt_server (g_ctx, addr, rtt);
}

int cl_get_rtt_id(ID *id, uint64_t *rtt)
{ 
    return cl_ctx_get_rtt_id (g_ctx, id, rtt);
}

/************************************************************************
 * Returns top k servers sorted by RTT.
 *
 * At return, "k" would contain the actual number of servers that are
 * returned (may be smaller than requested)
 ***********************************************************************/
int cl_get_top_k_servers(int *k, uint32_t best_addr[],
    		uint16_t best_port[], uint64_t	best_rtt[])
{ 
    return cl_ctx_get_top_k_servers(g_ctx, k, best_addr, best_port, best_rtt);
}

int cl_get_top_k_ids(int *k, ID best_id[], uint64_t best_rtt[])
{
    return cl_ctx_get_top_k_ids (g_ctx, k, best_id, best_rtt);
}


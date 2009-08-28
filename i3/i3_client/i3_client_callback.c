/***************************************************************************
                          i3_client_callback.c  -  description
                          -------------------
    begin                : Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include "i3.h"
#include "i3_fun.h"
#include "i3_client.h"
#include "i3_client_fun.h"
#include "i3_debug.h"


//#define PRINT_DEF_CBK 

#ifdef CLIENT_API_DEPRECIATED
#define TRG(x) (x->t)
#else
#define TRG(x) (x)
#endif

printf_def_cbk(char *str, ID *id, int intend) 
{
#ifdef PRINT_DEF_CBK
  I3_PRINT_DEBUG1(DEBUG_LEVEL_MINIMAL, "Default callback: %s\n", str);
  printf_i3_id(id, intend);
#endif
}


/***********************************************************************
 *  cl_trigger_callback - invoke a callback associated with a trigger
 *
 *  input:
 *    ctx - context
 *    ctr - pointer to the trigger data structure on which this callback
 *          is invoked
 *    hdr - packet header; used only when CL_CBK_RECEIVE_PACKET is invoked
 *    payload, payload_len - pointer to the payload and its lengths; used
 *                           either when  CL_CBK_RECEIVE_PACKET and
 *                           CL_CBK_RECEIVE_PAYLOAD are invoked
 *
 ************************************************************************/

void cl_trigger_callback(cl_context *ctx, cl_trigger *ctr, int cbk_type, 
			 i3_header *hdr, cl_buf *cbl) 
{
  switch (cbk_type) {
  case CL_CBK_TRIGGER_INSERTED:
    // printf("In Callback: trigger with following ID inserted\n");
    // printf_i3_id(&(ctr->t->id), 2); 
    if (ctr->cbk_trigger_inserted.fun) {
      ctr->cbk_trigger_inserted.fun(TRG(ctr), 
              NULL, ctr->cbk_trigger_inserted.fun_ctx);
    } else if (ctx->cbk_trigger_inserted.fun) {
      ctx->cbk_trigger_inserted.fun(TRG(ctr), 
              NULL, ctx->cbk_trigger_inserted.fun_ctx);
    } else {
      printf_def_cbk("trigger with following ID inserted",
		     &(ctr->t->id), 2); 
    }
    break;
  case CL_CBK_TRIGGER_REFRESH_FAILED:
    if (ctr->cbk_trigger_refresh_failed.fun) 
      ctr->cbk_trigger_refresh_failed.fun(TRG(ctr), 
					  NULL, ctr->cbk_trigger_refresh_failed.fun_ctx);
    else if (ctx->cbk_trigger_refresh_failed.fun)
      ctx->cbk_trigger_refresh_failed.fun(TRG(ctr), 
					  NULL, ctx->cbk_trigger_refresh_failed.fun_ctx);
    else {
      printf_def_cbk("trigger with following ID couldn't be inserted/refreshed", 
		     &(ctr->t->id), 2); 
    }
    break;

  case CL_CBK_TRIGGER_CONSTRAINT_FAILED:
        if (ctr->cbk_trigger_constraint_failed.fun)
	        ctr->cbk_trigger_constraint_failed.fun(TRG(ctr),
		            NULL, ctr->cbk_trigger_constraint_failed.fun_ctx);
        else if (ctx->cbk_trigger_constraint_failed.fun)
	        ctx->cbk_trigger_constraint_failed.fun(TRG(ctr),
		            NULL, ctx->cbk_trigger_constraint_failed.fun_ctx);
    else {
      printf_def_cbk("trigger with following ID didn't satisfy constraints",
		     &(ctr->t->id), 2);
    }
    break;

    case CL_CBK_RECEIVE_PACKET:
        {
            // The packet and its header to be passed to the callback function
            // The callback function is responsible for freeing this memory.
            static cbk_packet *tmp_cbk_pkt = NULL;
            if (tmp_cbk_pkt == NULL) {
                tmp_cbk_pkt = malloc(sizeof(cbk_packet));
            }
            tmp_cbk_pkt->ids = &(hdr->stack->ids[1]);
            tmp_cbk_pkt->stack_len = hdr->stack->len - 1;
            tmp_cbk_pkt->clb = cbl;
  
            if (hdr->stack->len <= 0) {
                tmp_cbk_pkt->ids = NULL;
            }


            if (ctr->cbk_receive_packet.fun) 
	            ctr->cbk_receive_packet.fun(TRG(ctr), tmp_cbk_pkt, 
				    ctr->cbk_receive_packet.fun_ctx);
      
            else if (ctx->cbk_receive_packet.fun)
	            ctx->cbk_receive_packet.fun(TRG(ctr), tmp_cbk_pkt,
				    ctx->cbk_receive_packet.fun_ctx);
            else {
	            printf_def_cbk("received packet matching following ID",
		            &(ctr->t->id), 2); 
            }
        }
    break;
  
    case CL_CBK_RECEIVE_PAYLOAD:
        if (ctr->cbk_receive_packet.fun)
            break;
        
        else if (ctr->cbk_receive_payload.fun)
            ctr->cbk_receive_payload.fun(TRG(ctr), cbl,
				   ctr->cbk_receive_payload.fun_ctx);
    
        else if (ctx->cbk_receive_packet.fun)
            break;
        
        else if (ctx->cbk_receive_payload.fun)
            
            ctx->cbk_receive_payload.fun(TRG(ctr), cbl,ctx->cbk_receive_payload.fun_ctx);
        
        else {
            printf_def_cbk("received data matching following ID", 
		         &(ctr->t->id), 2); 
        }
    break;
    
    case CL_CBK_ROUTE_BROKEN:
        if (ctr->cbk_route_broken.fun) 
            ctr->cbk_route_broken.fun(TRG(ctr), NULL, ctr->cbk_route_broken.fun_ctx);
        else if (ctx->cbk_route_broken.fun)
            ctx->cbk_route_broken.fun(TRG(ctr), NULL, ctx->cbk_route_broken.fun_ctx);
        else {
#ifdef PRINT_DEF_CBK
            I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "Default callback: route broken while at the following trigger\n");
            printf_i3_trigger(ctr->t, 2); 
#endif // PRINT_DEF_CBK
     }
    break;

    case CL_INTERNAL_HOOK_TRIGGER_ACK_TIMEOUT:
        if (ctr->internal_hook_ack_timeout.fun)  {
            ctr->internal_hook_ack_timeout.fun(TRG(ctr), 
					  NULL, ctr->internal_hook_ack_timeout.fun_ctx);

        }
    break;

    case CL_INTERNAL_HOOK_TRIGGER_REFRESH_TIMEOUT:
        if (ctr->internal_hook_refresh_timeout.fun)  {
            ctr->internal_hook_refresh_timeout.fun(TRG(ctr), 
					  NULL, ctr->internal_hook_refresh_timeout.fun_ctx);
        }
    break;



  default:
        I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_trigger_callback: invalid callback type!\n");
  }
}

/***********************************************************************
 *  cl_id_callback - invoke a callback associated with an ID
 *
 *  input:
 *    ctx - context
 *    id - ID with which the callback is associated
 *
 ************************************************************************/

void cl_id_callback(cl_context *ctx, int cbk_type, ID *id,
		    struct in_addr *ip_addr, uint16_t *port)
{
    switch (cbk_type) {
        case CL_CBK_TRIGGER_NOT_FOUND:
            if (ctx->cbk_trigger_not_found.fun)
                ctx->cbk_trigger_not_found.fun(id, NULL, 
				     ctx->cbk_trigger_not_found.fun_ctx);
            else {
                printf_def_cbk("there is no trigger matching following ID", 
			       id, 2); 
            }
        break;
  
        case CL_CBK_RATELIMIT_EXCEEDED:
            if (ctx->cbk_ratelimit_exceeded.fun)
                ctx->cbk_ratelimit_exceeded.fun(id, NULL, 
				     ctx->cbk_ratelimit_exceeded.fun_ctx);
            else {
                printf_def_cbk("token-bucket constraints violated for ID", 
			       id, 2); 
            }
        break;
  
        case CL_CBK_SERVER_DOWN:
            if (ctx->cbk_server_down.fun) {
                ctx->cbk_server_down.fun(ip_addr, port, ctx->cbk_server_down.fun_ctx);
            } else {
      
#ifdef PRINT_DEF_CBK
                ip_addr->s_addr = htonl(ip_addr->s_addr);
                I3_PRINT_DEBUG2(I3_DEBUG_LEVEL_MINIMAL, "Default callback: server couldn't be contacted (%s, %d)\n", 
	                    inet_ntoa(*ip_addr), *port);
                ip_addr->s_addr = ntohl(ip_addr->s_addr);
#endif
            }
        break;
  
        default:
            I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_callback: invalid callback type!\n");
    }
}


/************************************************************************
 *  cl_register_trigger_callback1 - associate a callback with a trigger 
 *
 *  input:
 *    ctr - trigger
 *    cbk_type - callback type
 *    fun - callback function
 *    data - pointer to a user data associated with the callback
 *************************************************************************/

int cl_register_trigger_callback1(cl_trigger *ctr, uint16_t cbk_type,
			void (*fun)(cl_trigger*, void* data, void *fun_ctx), 
            void *fun_ctx)
{
  
    switch (cbk_type) {
        case CL_CBK_TRIGGER_INSERTED:
            if (ctr->type == CL_TRIGGER_LOCAL) {
                // local triggers are not inserted in i3
                return CL_RET_INVALID_TRIGGER_TYPE;
            }
            ctr->cbk_trigger_inserted.fun = fun;
            ctr->cbk_trigger_inserted.fun_ctx = fun_ctx;
        break;
  
        case CL_CBK_TRIGGER_REFRESH_FAILED:
            if (ctr->type == CL_TRIGGER_LOCAL) {
                // local triggers are not inserted in i3
                return CL_RET_INVALID_TRIGGER_TYPE;
            }
    
            ctr->cbk_trigger_refresh_failed.fun = fun;
            ctr->cbk_trigger_refresh_failed.fun_ctx = fun_ctx;
        break;
  
        case CL_CBK_TRIGGER_CONSTRAINT_FAILED:
            if (ctr->type == CL_TRIGGER_LOCAL) {
                // local triggers are not inserted in i3
                return CL_RET_INVALID_TRIGGER_TYPE;
            }
    
            ctr->cbk_trigger_constraint_failed.fun = fun;
            ctr->cbk_trigger_constraint_failed.fun_ctx = fun_ctx;
        break;
  
        case CL_CBK_RECEIVE_PACKET:
            ctr->cbk_receive_packet.fun = fun;
            ctr->cbk_receive_packet.fun_ctx = fun_ctx;
            /* this callback takes precedence over 
            * CL_CBK_RECEIVE_PAYLOAD callback */
            if (ctr->cbk_receive_payload.fun) {
                return CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD;
            }
        break;
  
        case CL_CBK_RECEIVE_PAYLOAD:
            ctr->cbk_receive_payload.fun = fun;
            ctr->cbk_receive_payload.fun_ctx = fun_ctx;
            /* this callback is ignored if CL_CBK_RECEIVE_PACKET is already defined */
            if (ctr->cbk_receive_packet.fun) {
                return CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD;
            }
        break;
  
        case CL_CBK_ROUTE_BROKEN:
            ctr->cbk_route_broken.fun = fun;
            ctr->cbk_route_broken.fun_ctx = fun_ctx;
        break;

        case CL_INTERNAL_HOOK_TRIGGER_ACK_TIMEOUT:
            ctr->internal_hook_ack_timeout.fun = fun;
            ctr->internal_hook_ack_timeout.fun_ctx = fun_ctx;
        break;
        
        case CL_INTERNAL_HOOK_TRIGGER_REFRESH_TIMEOUT:
            ctr->internal_hook_refresh_timeout.fun = fun;
            ctr->internal_hook_refresh_timeout.fun_ctx = fun_ctx;
        break;
        
        default:
            panic("cl_cbk_register_trigger_callback: invalid callback type!\n");
    }
    
    return CL_RET_OK;
}


/************************************************************************
 *  cl_register_context_callback - associate a callback with a context 
 *
 *  input:
 *    ctr - trigger
 *    cbk_type - callback type
 *    fun - callback function
 *    data - pointer to a user data associated with the callback
 *************************************************************************/

int cl_register_context_callback(cl_context *ctx, uint16_t cbk_type,
		void (*fun)(void *ctx_data, void *data, void* fun_ctx),
        void * fun_ctx)
{
  
    switch (cbk_type) {
        case CL_CBK_TRIGGER_NOT_FOUND:
            ctx->cbk_trigger_not_found.fun = fun;
            ctx->cbk_trigger_not_found.fun_ctx = fun_ctx;
	    break;
        
        case CL_CBK_TRIGGER_INSERTED:
            ctx->cbk_trigger_inserted.fun = fun;
            ctx->cbk_trigger_inserted.fun_ctx = fun_ctx;
	    break;
    
        case CL_CBK_TRIGGER_REFRESH_FAILED:
            ctx->cbk_trigger_refresh_failed.fun = fun;
            ctx->cbk_trigger_refresh_failed.fun_ctx = fun_ctx;
	    break;
    
        case CL_CBK_TRIGGER_CONSTRAINT_FAILED:
            ctx->cbk_trigger_constraint_failed.fun = fun;
            ctx->cbk_trigger_constraint_failed.fun_ctx = fun_ctx;
	    break;
    
        case CL_CBK_RECEIVE_PACKET:
            ctx->cbk_receive_packet.fun = fun;
            ctx->cbk_receive_packet.fun_ctx = fun_ctx;
            /* this callback takes precedence over 
            * CL_CBK_RECEIVE_PAYLOAD callback 
            */
    
            if (ctx->cbk_receive_payload.fun) {
                return CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD;
            }
	    break;
  
        case CL_CBK_RECEIVE_PAYLOAD:
            ctx->cbk_receive_payload.fun = fun;
            ctx->cbk_receive_payload.fun_ctx = fun_ctx;
            /* this callback is ignored if CL_CBK_RECEIVE_PACKET is already defined */
            if (ctx->cbk_receive_packet.fun) {
                return CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD;
            }
	    break;
  
        case CL_CBK_ROUTE_BROKEN:
            ctx->cbk_route_broken.fun = fun;
            ctx->cbk_route_broken.fun_ctx = fun_ctx;
	    break;
    
        case CL_CBK_SERVER_DOWN:
            ctx->cbk_server_down.fun = fun; 
            ctx->cbk_server_down.fun_ctx = fun_ctx;
	    break;
    
        case CL_CBK_RATELIMIT_EXCEEDED:
            ctx->cbk_ratelimit_exceeded.fun = fun;
            ctx->cbk_ratelimit_exceeded.fun_ctx = fun_ctx;
	    break;
        
        default:
            I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_register_context_callback: invalid callback type!\n");
  }
  return CL_RET_OK;
}



/***************************************************************************
                          i3_client_pkt.h  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>   /* basic system data types */
#include <time.h>        /* timespec{} for pselect() */
#ifndef _WIN32
    #include <sys/time.h>    /* timeval{} for select() */
    #include <sys/errno.h>    
#endif
#include "../utils/netwrap.h"

#include "i3.h"
#include "i3_fun.h"
#include "i3_debug.h"

#include "i3_client.h"
#include "i3_client_fun.h"
#include "i3_tcp_fns.h"


void fast_pack_i3_header(char *p, char  data, 
			 i3_stack *s, char *packed_ol, 
			 unsigned short packed_ol_len); 
void make_opt_cache_address_pkt(cl_context *ctx, ID *id, int prefix_len,
				char *buf, unsigned short *buf_len);

cl_buf *cl_alloc_buf(unsigned int len) {
  
  	cl_buf *clb;
	int tmp_internal_buf_len = 0;

  	if ((clb = (cl_buf *)malloc(sizeof(cl_buf))) == NULL) {
    	I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_alloc_buf(1): memory allocation error\n");
	} else {
		memset (clb, 0, sizeof (cl_buf));
	}
  
  	tmp_internal_buf_len = len + 2 * CL_PREFIX_LEN;
  	if ((clb->internal_buf = (char *)malloc(tmp_internal_buf_len)) == NULL) {
	    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_alloc_buf(2): memory allocation error\n");
	} else {
		memset (clb->internal_buf, 0, tmp_internal_buf_len);
	}
  
  	clb->data = clb->internal_buf + CL_PREFIX_LEN;
  	clb->max_len = len;

  	return clb;
}


void cl_free_buf(cl_buf *clb)
{
  if (clb) {
    if (clb->internal_buf) 
      free(clb->internal_buf);
    free(clb);
  }
}



int cl_send_data_packet(cl_context *ctx, i3_stack *stack,
			cl_buf *clb, uint16_t flags, char is_total_len)
{
  unsigned short len;
  cl_id *cid;
  int refresh, total_len = 0, err = 0;
  uint8_t opts_mask = 0;

  /* is stack->ids[0] cached ? */
  cid = cl_get_valid_id(ctx, &stack->ids[0], &refresh);

  /* form the complete mask using refresh also */
  if (flags & CL_PKT_FLAG_ALLOW_SHORTCUT)
    opts_mask |= (refresh != 0) ? REFRESH_SHORTCUT_MASK : 0;
  else 
    opts_mask |= (refresh != 0) ? REFRESH_MASK : 0; 

  assert(opts_mask < MAX_OPTS_MASK_SIZE);

  /* use appropriate precomputed option */
  len = 2 * sizeof(char) + get_i3_stack_len(stack) + 
    ctx->precomputed_opt[opts_mask].len;
  assert(len <= CL_PREFIX_LEN);

  /* check whether header and payload exceed maximum packet size of
     transport protocol */
  total_len = clb->data_len;
  if (!is_total_len) {
      total_len += len;
  }
  if (total_len > ((1 << 16) - 8)) {
      return CL_RET_MSG_SIZE;
  }
  
  fast_pack_i3_header(clb->data - len, TRUE, stack,
		      ctx->precomputed_opt[opts_mask].p,
		      ctx->precomputed_opt[opts_mask].len);
  /* set first flag */
  set_first_hop(clb->data - len);

  if (!is_total_len)  {
    err = cl_sendto(ctx, clb->data - len, clb->data_len + len,
		    cid, &stack->ids[0]);
  } else {
    err = cl_sendto(ctx, clb->data - len, clb->data_len, cid, &stack->ids[0]);
  }

  return err;
}


int cl_send_packet(cl_context *ctx, i3_header *hdr,
		   cl_buf *clb, uint8_t opts_mask)
// TODO XXX -- opts mask is unimplemented in this case
{
  char *pkt;
  unsigned short len;
  cl_id *cid;
  int refresh, err = 0;
    
  /* is there a cache entry for the first identifier in the stack ? */
  cid = cl_get_valid_id(ctx, &hdr->stack->ids[0], &refresh);
  if (refresh) {
    /* cache entry doesn't exist or needs to be refreshed */
    i3_option *o;
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_REQUEST_FOR_CACHE, NULL); 
    append_i3_option(hdr->option_list, o);
  }

  /* get header length */
  len = get_i3_header_len(hdr);
  
  /* check whether we have enough room to prepend header */
  assert (len <= clb->data - clb->internal_buf); 
  pkt = clb->data - len;
  /* copy header in front of payload */
  pack_i3_header(pkt, hdr, &len);
  set_first_hop(pkt);
  err = cl_sendto(ctx, pkt, len + clb->data_len, cid, &hdr->stack->ids[0]);

  free_i3_header(hdr);

  return err;
}



/* return the header and the payload of an i3 packet;
 * hdr is allocated and needs to be freed in the calling function
 * pkt ix expected to be allocated by the calling function
 */

int cl_receive_packet_from(cl_context *ctx, i3_header **phdr, cl_buf *clb,
			    struct sockaddr_in *fromaddr)
{
  int n;
  int     len, errcode;
  unsigned short hdr_len;

  *phdr = NULL;
  len = sizeof(struct sockaddr_in);
  /* leave enough room to allow caller to invoke a cl_send operation
   * using the same buffer
   */
  clb->data = clb->internal_buf + CL_PREFIX_LEN; 
  /* recall that total length of the allocated buffer in the clb structure is
   * clb->max_len + CL_PREFIX_LEN */
  if (ctx->is_tcp && ctx->init_tcp_ctx_flag) {
    if ((n = recv_tcp(clb->data, clb->max_len + CL_PREFIX_LEN, 
		      ctx->tcp_fd)) < 0) {
      I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "tcp recvfrom error");      
      perror ("recvfrom tcp");
      return 0;    
    }
    if (n == 0) {
      I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_VERBOSE, 
		  "Connection closed by server, exiting...\n");
      exit(0);
    }
  } else
    if ((n = recvfrom(ctx->fd, clb->data, clb->max_len + CL_PREFIX_LEN, 0, 
		      (struct sockaddr *)fromaddr, &len)) < 0) {
				  
	I3_PRINT_DEBUG1 (I3_DEBUG_LEVEL_WARNING, "Error while receiving packet: %s.\n",
					  strerror (errno)
					  );
      perror("recvfrom udp");
      return 0;
    }

  
  if (clb->data[0] == I3_v01) {
    /* check whether the packet is wellformed */
    errcode = check_i3_header(clb->data, n);
    if (errcode) {
      I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_SUPER, "invalid i3 header, errcode=%d", 
		  errcode);      
      return 0;
    }
    *phdr = unpack_i3_header(clb->data, &hdr_len);
    clb->data += hdr_len; /* this where the payload starts... */
    clb->data_len = n - hdr_len; /* ... and this is the payload length */
  }

  return 1;
}

void cl_receive_packet(cl_context *ctx, i3_header **phdr, cl_buf *clb)
{
  struct sockaddr_in fromaddr;
  cl_receive_packet_from(ctx, phdr, clb, &fromaddr);
}


int cl_sendto(cl_context *ctx, char *pkt, 
	      uint16_t pkt_len, cl_id *cid, ID *id) 

{
  if (cid == NULL) {
    int idx = get_i3_server(ctx->num_servers, ctx->s_array);
    if (-1 == idx) {
      fprintf(stderr, "cl_sendto: cannot get i3_servers\n");
      return CL_RET_NO_SERVERS;
    }
    
    
    cid = cl_create_id(ctx, id, I3_OPT_CACHE_ADDR, &ctx->s_array[idx].addr, 
		       ctx->s_array[idx].port, NULL);
  }
  assert(cid); 
  
  I3_PRINT_DEBUG2(I3_DEBUG_LEVEL_VERBOSE,
	      "in cl_sendto: using server %s:%u\n", 
	      inet_ntoa(cid->cache_addr.sin_addr), 
	      ntohs(cid->cache_addr.sin_port)
	      );
  
  if (ctx->is_tcp) {
    if (!ctx->init_tcp_ctx_flag) {
      // TCP connection had not been earlier established.
      // Try again
      init_tcp_ctx(ctx);
      
      if (!ctx->init_tcp_ctx_flag) {
	//failed again
	I3_PRINT_DEBUG0 (I3_DEBUG_LEVEL_MINIMAL,
		     "send failed as tcp connection could not be established.\n"
		     );
	return CL_RET_NET_ERROR;
      }
    }
    
    if (ctx->is_tcp && ctx->init_tcp_ctx_flag)
      if (send_tcp(pkt, pkt_len, ctx->tcp_fd) < 0)
        return CL_RET_NET_ERROR;
    
  } else {
    int numSent = 0;
    if ((numSent = sendto(ctx->fd, pkt, pkt_len, 0, 
			  (struct sockaddr *)&cid->cache_addr, 
			  sizeof(cid->cache_addr))) < 0) {
      perror("cl_sendto");
      if (errno == ENETUNREACH) {
	if (cid->retries_cnt > 0) {
	  cid->retries_cnt--;
	}
      } else {
	return CL_RET_NET_ERROR;
      }
    }
  }

  return CL_RET_OK;
}


void make_data_opt(cl_context *ctx, uint8_t opt_mask, buf_struct *b)
{
  unsigned short len;
  i3_addr *a;
  i3_option *o;
  i3_option_list *ol;
  
  ol = alloc_i3_option_list();

  /* create ID_OPT_SENDER to tell the i3 server where to reply if 
   * trigger not present
   */
  a = alloc_i3_addr();
  init_i3_addr_ipv4(a, ctx->local_ip_addr, ctx->local_port);
  o = alloc_i3_option();
  init_i3_option(o, I3_OPT_SENDER, (void *)a);
  append_i3_option(ol, o);
  
  // Code_Clean: make this 3 ifs into a loop
  if (opt_mask & REFRESH_MASK) {
    /* add "request for cache" option if needed */
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_REQUEST_FOR_CACHE, NULL); 
    append_i3_option(ol, o);
  }

  if (opt_mask & REFRESH_SHORTCUT_MASK) {
    /* add "request for cache" option if needed */
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_REQUEST_FOR_CACHE_SHORTCUT, NULL); 
    append_i3_option(ol, o);
  }

#if NEWS_INSTRUMENT
  if (opt_mask & LOG_PKT_MASK) {
    /* add "log packet" option if needed */
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_LOG_PACKET, NULL); 
    append_i3_option(ol, o);
  }

  if (opt_mask & APP_TS_MASK) {
    /* add "append ts" option if needed */
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_APPEND_TS, NULL); 
    append_i3_option(ol, o);
  }
#endif
  
  /* get option length ... */
  len = get_i3_option_list_len(ol);

  /* ... allocate memory ... */ 
  if ((b->p = (char *)malloc(len)) == NULL)
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "make_data_hdr: memory allocation error\n");
  
  /* ... and pack the option list */
  pack_i3_option_list(b->p, ol, &len);
  b->len = len;

  free_i3_option_list(ol);
}

void fast_pack_i3_header(char *p, char data, i3_stack *stack, 
			 char *packed_ol, unsigned short packed_ol_len) 
{
  unsigned short len = 0;

  *p = I3_v01;
  p += sizeof(char); 
  //len = sizeof(char); 
  *p = (data ? I3_DATA : 0);
  if (!packed_ol)
    *p = *p & (~I3_OPTION_LIST); 
  else
    *p = *p | I3_OPTION_LIST;
  p++; //len += sizeof(char); 
  *p=0;
  if (stack) {
    pack_i3_stack(p, stack, &len);
    p += len;
  }

  memcpy(p, packed_ol, packed_ol_len);
}


void make_opt_cache_address_pkt(cl_context *ctx, ID *id, int prefix_len,
				char *buf, unsigned short *buf_len)
{
  i3_header *h;
  i3_option *o;
  i3_option_list *ol;
  i3_trigger *t;
  i3_addr    *a;
  static Key null_key;

  ol = alloc_i3_option_list();
  o = alloc_i3_option();
  t = alloc_i3_trigger();
  a = alloc_i3_addr();
  init_i3_addr_ipv4(a, ctx->local_ip_addr, ntohs(ctx->local.sin_port));
  init_i3_trigger(t, id, prefix_len, a, &null_key, 0);
  init_i3_option(o, I3_OPT_CACHE_SHORTCUT_ADDR, t);
  append_i3_option(ol, o);

  /* finish create the header */
  h = alloc_i3_header();
  init_i3_header(h, FALSE, NULL, ol);
  pack_i3_header(buf, h, buf_len);
  free_i3_header(h);
}  

/* send cache reply to the sender; used when shortcut is enabled */
void cl_send_opt_cache_address_indir(cl_context *ctx, ID *id, int prefix_len, 
				     i3_addr *to)
{
#define MAX_PKT_SIZE 1024
  char pkt[MAX_PKT_SIZE];
  unsigned short len;

  assert(to->type != I3_ADDR_TYPE_STACK);

  make_opt_cache_address_pkt(ctx, id, prefix_len, pkt, &len);

  /* send packet */
  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "send back cache address\n");
  switch(to->type) {
  case I3_ADDR_TYPE_IPv4:
    send_packet_ipv4(pkt, len, &to->t.v4.addr, to->t.v4.port, ctx->fd);
    break;
  case I3_ADDR_TYPE_IPv4_NAT:
    send_packet_ipv4(pkt, len, &to->t.v4_nat.nat_addr, 
		     to->t.v4_nat.nat_port, ctx->fd);
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "cl_send_opt_cache_address: invalid addr type: %d\n",
	   to->type);
  }
}


/* send cache reply to the sender; used when shortcut is enabled */
void cl_send_opt_cache_address(cl_context *ctx, ID *id, int prefix_len, 
			       struct sockaddr_in  *fromaddr)
{
#define MAX_PKT_SIZE 1024
  char pkt[MAX_PKT_SIZE];
  unsigned short len;

  make_opt_cache_address_pkt(ctx, id, prefix_len, pkt, &len);

  /* send packet */
  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "send back cache address\n");

  if (sendto(ctx->fd, pkt, len, 0, 
	     (struct sockaddr *)fromaddr, sizeof(*fromaddr)) < 0)
        I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL," cl_send_opt_cache_address: sendto error\n");
}


void cl_send_request_for_shortcut(cl_context *ctx, cl_id *cid, int refresh)
{
  uint8_t   opts_mask; 
  char      pkt[CL_PREFIX_LEN];
  i3_stack *s;
  unsigned short len;

  opts_mask = REFRESH_SHORTCUT_MASK;

  /* create I3_OPT_REQUEST_FOR_CACHE_SHORTCUT packet and send it 
   * directly to destination 
   */
  /* pack ID */
  s = alloc_i3_stack();
  init_i3_stack(s,  &cid->id, 1);
  
  /* compute packet length */
  len = 2 * sizeof(char) + get_i3_stack_len(s) + 
    ctx->precomputed_opt[opts_mask].len;
  assert(len <= CL_PREFIX_LEN);
  
  fast_pack_i3_header(pkt, FALSE, s,
		      ctx->precomputed_opt[opts_mask].p,
		      ctx->precomputed_opt[opts_mask].len);
  free_i3_stack(s);
  assert(len < CL_PREFIX_LEN);

  if (sendto(ctx->fd, pkt, len, 0, 
	     (struct sockaddr *)&cid->dest_addr, sizeof(cid->dest_addr)) < 0) {
    perror("cl_sendto");
  }
}

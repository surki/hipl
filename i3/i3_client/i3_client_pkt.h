/***************************************************************************
                          i3_client_pkt.h  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_PKT_H
#define I3_CLIENT_PKT_H
 
/* functions implemented in i3_client_pkt.c */
int cl_send_data_packet(cl_context *ctx, i3_stack *stack,
			cl_buf *clb, uint16_t flags, char is_total_len);
int cl_send_packet(cl_context *ctx, i3_header *header,
		   cl_buf *clb, uint8_t opts);
int cl_sendto(cl_context *ctx, char *pkt, uint16_t pkt_len,
	      cl_id *cid, ID *id);
int cl_receive_packet_from(cl_context *ctx, i3_header **phdr, cl_buf *clb,
			    struct sockaddr_in *fromaddr);
void cl_receive_packet(cl_context *ctx, i3_header **phdr, cl_buf *clb);
void make_data_opt(cl_context *ctx, uint8_t opts_mask, buf_struct *b);
void cl_send_opt_cache_address_indir(cl_context *ctx, ID *id, int prefix_len, 
				     i3_addr *to);
void cl_send_opt_cache_address(cl_context *ctx, ID *id, int prefix_len, 
			       struct sockaddr_in  *fromaddr);
void cl_send_request_for_shortcut(cl_context *ctx, cl_id *cid, int refresh);
#endif

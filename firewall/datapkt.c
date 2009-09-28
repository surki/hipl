#include "datapkt.h"

extern int raw_sock_v6;

//Prabhu enable datapacket mode input
int hip_fw_userspace_datapacket_input(hip_fw_context_t *ctx)
{
        int err = 0;
	/* the routable addresses as used in HIPL */
	struct in6_addr preferred_local_addr ;
	struct in6_addr preferred_peer_addr;
	struct sockaddr_storage local_sockaddr;
        int out_ip_version;
	uint16_t data_packet_len = 0;
	unsigned char *hip_data_packet_input = NULL;
        
        HIP_DEBUG("HIP DATA MODE INPUT\n");
       
	HIP_ASSERT(ctx->packet_type == HIP_PACKET);
        HIP_IFE(!(hip_data_packet_input = (unsigned char *)malloc(ESP_PACKET_SIZE) ), -1);
	

	HIP_IFEL(hip_data_packet_mode_input(ctx, hip_data_packet_input, &data_packet_len, &preferred_local_addr, &preferred_peer_addr), 1,"failed to recreate original packet\n");

	HIP_HEXDUMP("restored original packet: ", hip_data_packet_input, data_packet_len);
	struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)hip_data_packet_input;
	HIP_DEBUG("ip6_hdr->ip6_vfc: 0x%x \n", ip6_hdr->ip6_vfc);
	HIP_DEBUG("ip6_hdr->ip6_plen: %u \n", ip6_hdr->ip6_plen);
	HIP_DEBUG("ip6_hdr->ip6_nxt: %u \n", ip6_hdr->ip6_nxt);
	HIP_DEBUG("ip6_hdr->ip6_hlim: %u \n", ip6_hdr->ip6_hlim);

	// create sockaddr for sendto
	hip_addr_to_sockaddr(&preferred_local_addr, &local_sockaddr);

	// re-insert the original HIT-based (-> IPv6) packet into the network stack
	err = sendto(raw_sock_v6, hip_data_packet_input, data_packet_len, 0,
					(struct sockaddr *)&local_sockaddr,
					hip_sockaddr_len(&local_sockaddr));

	if (err < 0) 
		HIP_DEBUG("sendto() failed\n");
        else
                HIP_DEBUG(" SUCCESSFULLY RECEIVED THE PACKET " );

out_err:
	
	if (hip_data_packet_input)
		free(hip_data_packet_input);

	return err;

}

int hip_data_packet_mode_output(hip_fw_context_t *ctx, 
		                struct in6_addr *preferred_local_addr, struct in6_addr *preferred_peer_addr,
		                unsigned char *hip_data_packet, uint16_t *hip_packet_len)
{
	struct ip *out_ip_hdr = NULL;
	struct ip6_hdr *out_ip6_hdr = NULL;
	unsigned char *in_transport_hdr = NULL;
	uint8_t in_transport_type = 0;
        int in_transport_len = 0;
	int next_hdr_offset = 0;
	int err = 0;
        struct hip_common *data_header = 0;
	int data_header_len = 0;
       
	/* For time being we are just encapsulating the received IPv6 packet
	   containing HITS with another IPv4/v6 header and send it back */

        data_header = hip_msg_alloc();
        if (!data_header) {
            err = -ENOMEM;
            goto out_err;
         }
        HIP_DEBUG("original packet length: %i \n", ctx->ipq_packet->data_len);

	/* distinguish between IPv4 and IPv6 output */
	if (IN6_IS_ADDR_V4MAPPED(preferred_peer_addr)) {
		/* NOTE: this does _not_ include IPv4 options for the original packet */
		/* calculate offset at which esp data should be located */
	        out_ip_hdr = (struct ip *)hip_data_packet;
		next_hdr_offset = sizeof(struct ip);

		/* NOTE: we are only dealing with HIT-based (-> IPv6) data traffic */

                in_transport_hdr = ((unsigned char *) ctx->ipq_packet->payload) + sizeof(struct ip6_hdr);
                in_transport_type = ((struct ip6_hdr *) ctx->ipq_packet->payload)->ip6_nxt; 
                in_transport_len = ctx->ipq_packet->data_len  - sizeof(struct ip6_hdr) ;
                
                err = hip_get_data_packet_header(&ctx->src, &ctx->dst,in_transport_type,data_header);
                if( err )
			goto out_err;
                data_header_len = hip_get_msg_total_len(data_header);
                HIP_DEBUG("\n HIP Header Length in Bytes = %d ", data_header_len);
                
                *hip_packet_len = next_hdr_offset + data_header_len + in_transport_len ;
                HIP_DEBUG("   Transport len = %d, type =%d, data_header_payload_type =%d, data_header_len = %d  Total_hip_packet_len = %d ", 
                              in_transport_len, in_transport_type,data_header->payload_proto, data_header_len, *hip_packet_len);

                memcpy(hip_data_packet + next_hdr_offset, data_header, data_header_len );
                memcpy(hip_data_packet + next_hdr_offset+data_header_len , in_transport_hdr, in_transport_len );
                 
		HIP_DEBUG("Just Checking if we have copied the data correctly ... original packets next header in encapsulated packed = %d", in_transport_type);
 
		//TESTING WITH ESP PROTO  NEED TO ADD OUR OWN PROTOCOL FIELD

		add_ipv4_header(out_ip_hdr, preferred_local_addr, preferred_peer_addr,
							*hip_packet_len, IPPROTO_HIP);
                HIP_DEBUG("HIP is SENIND DATA PACKET OF TOTAL LENGTH %d ",*hip_packet_len);
           
           }
         else{

              HIP_DEBUG("We have  <other THAN IN6 V4 MAPPED ");
        } 
out_err:
	if (data_header)
		free(data_header);

	return err;
}

int hip_data_packet_mode_input(hip_fw_context_t *ctx, unsigned char *hip_packet, uint16_t *hip_data_len,
			       struct in6_addr *preferred_local_addr, struct in6_addr *preferred_peer_addr)
{
	int next_hdr_offset = 0;
        int transport_data_len = 0;
	unsigned char *in_transport_hdr = NULL;
        int err = 0;
        struct hip_common *data_header = 0;
	uint8_t next_hdr = 0;
        int data_header_len = hip_get_msg_total_len((ctx->transport_hdr.hip));
        int packet_length   = ctx->ipq_packet->data_len ;

        HIP_DEBUG("Total Packet length = %d   HIP Header has the total length = %d ", packet_length,  data_header_len);

        /* the  extraxted data  will be placed behind the HIT-based IPv6 header */
	next_hdr_offset = sizeof(struct ip6_hdr);
        HIP_DEBUG("Next Header Offset : %d ", next_hdr_offset);
        
	/* below we need correctly deduct the siez of hip header */

        if(ctx->ip_version == 4 ){
             transport_data_len= packet_length  - sizeof( struct ip) - data_header_len;
             in_transport_hdr = ((unsigned char *) ctx->ipq_packet->payload) + sizeof(struct ip) + data_header_len;
             next_hdr= (ctx->transport_hdr.hip)->payload_proto;
             memcpy(preferred_local_addr, &(ctx->transport_hdr.hip->hitr), sizeof(struct in6_addr)) ;
             memcpy(preferred_peer_addr,&(ctx->transport_hdr.hip->hits),sizeof( struct in6_addr)) ;
             memcpy(hip_packet+next_hdr_offset,  in_transport_hdr , transport_data_len);
             
             HIP_DEBUG( "COPIED THE CONTENTS AND PAYLOAD FROM INCOMING HIP DATA PACKET,transport len = %d, next_hdr=%d", transport_data_len, next_hdr);               
            
        }

        *hip_data_len = next_hdr_offset + transport_data_len;

        HIP_DEBUG("Total Recovered packet size should be %d  ", *hip_data_len);

	/* now we know the next_hdr and can set up the IPv6 header */
	add_ipv6_header((struct ip6_hdr *)hip_packet, preferred_peer_addr ,
			preferred_local_addr, *hip_data_len, next_hdr);

	HIP_DEBUG("original packet length: %i \n", *hip_data_len);

  out_err:
  	return err;


}

int handle_hip_data(struct hip_common * common)
{
	struct in6_addr hit;
	struct hip_host_id * host_id = NULL;
	int sig_alg = 0;
	// assume correct packet
	int err = 0;
	hip_tlv_len_t len = 0;
        int orig_payload_proto = common->payload_proto ;


        HIP_DUMP_MSG(common);
	HIP_DEBUG("verifying hi -> hit mapping...\n");

	// handling HOST_ID param
	HIP_IFEL(!(host_id = (struct hip_host_id *)hip_get_param(common,
			HIP_PARAM_HOST_ID)),
			-1, "No HOST_ID found in control message\n");

	len = hip_get_param_total_len(host_id);

	// verify HI->HIT mapping
	HIP_IFEL(hip_host_id_to_hit(host_id, &hit, HIP_HIT_TYPE_HASH100) ||
		 ipv6_addr_cmp(&hit, &common->hits),
		 -1, "Unable to verify HOST_ID mapping to src HIT\n");

       /* Fix Prabhu..Due to some message.c constraints,
	  common->type_hdr was set to 1 when signing the data.. 
	  So set it to 1 when verifying and then reset it back */
       common->payload_proto = 1;
       
       HIP_IFEL(hip_verify_packet_signature(common, host_id),
		-EINVAL, "Verification of signature failed");

	HIP_DEBUG("verified HIP DATA signature\n");


  out_err:

       /* Reset the payload_proto field */ 
        common->payload_proto = orig_payload_proto;

	return err;
}

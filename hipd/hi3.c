#include "hi3.h"
//#include "output.h"

#define HI3_TRIGGER_MAX 10

cl_trigger* hi3_pri_tr[HI3_TRIGGER_MAX];
cl_trigger* hi3_pub_tr[HI3_TRIGGER_MAX];

ID hi3_pri_id[HI3_TRIGGER_MAX];
ID hi3_pub_id[HI3_TRIGGER_MAX];
int hi3_pub_tr_count = 0;
cl_trigger* cl_pub_tr_set = NULL;


/**
 * The callback for i3 "no matching id" callback.
 * 
 * @param ctx_data a pointer to...
 * @param data     a pointer to...
 * @param fun_ctx  a pointer to...
 * @todo           tkoponen: should this somehow trigger the timeout for waiting
 *                 outbound traffic (state machine)?
 */
static void no_matching_trigger(void *ctx_data, void *data, void *fun_ctx){
	char id[100];
	sprintf_i3_id(id, (ID *)ctx_data);
	
	HIP_ERROR("Following ID not found: %s\n", id);
}


int hip_i3_init(){
	if( cl_init(HIPD_HI3_FILE)!= CL_RET_OK){
		HIP_ERROR("hi3: error creating context!\n");
		exit(-1);
	}
	
	cl_register_callback(CL_CBK_TRIGGER_NOT_FOUND, no_matching_trigger, NULL);

	hip_hi3_insert_trigger();


	return 0;
}


int hip_hi3_add_pub_trigger_id(struct hip_host_id_entry *entry, void* count){
	int i = *(int*)count;
	if( i > HI3_TRIGGER_MAX ){
		HIP_ERROR("Trigger number exceeded");
		return 0;
	}

	bzero(&hi3_pub_id[i], ID_LEN);
	memcpy(&hi3_pub_id[i], &entry->lhi.hit, sizeof(hip_hit_t));
	(*((int*)count))++;

	return 0;
}


int hip_addr_parse(char *buf, struct sockaddr_in6 *in6, int len, int *res) {
	struct hi3_ipv4_addr *h4 = (struct hi3_ipv4_addr *)buf;
	if(len < (h4->sin_family == AF_INET ? sizeof(struct hi3_ipv4_addr) : 
		   sizeof(struct hi3_ipv6_addr))){
		HIP_ERROR("Received packet too small. Dropping\n");
		*res = 0;
		return 0;
	}

	if(h4->sin_family == AF_INET){
		((struct sockaddr_in *)in6)->sin_addr = h4->sin_addr;
		((struct sockaddr_in *)in6)->sin_family = AF_INET;
		*res = AF_INET;
		return sizeof(struct hi3_ipv4_addr);

	} else if(h4->sin_family == AF_INET6){
		in6->sin6_addr = ((struct hi3_ipv6_addr *)buf)->sin6_addr;
		in6->sin6_family = AF_INET6;
		*res = AF_INET6;
		return sizeof(struct hi3_ipv6_addr);
	} 

	HIP_ERROR("Illegal family. Dropping\n");
	return 0;
}


/**
 * This is the i3 callback to process received data.
 */
void hip_hi3_receive_payload(cl_trigger *t, void* data, void *fun_ctx) 
{ 
	struct hip_common *hip_common;
	//	struct hip_work_order *hwo;
	//	struct sockaddr_in6 src, dst;
	//	struct hi3_ipv4_addr *h4;
	//	struct hi3_ipv6_addr *h6;
	//	int family, l, type;
	cl_buf* clb = (cl_buf *)data;
	char *buf = clb->data;
	int len = clb->data_len;
	hip_portpair_t msg_info;

	/* See if there is at least the HIP header in the packet */
        if(len < sizeof(struct hip_common)){
		HIP_ERROR("Received packet too small. Dropping\n");
		goto out_err;
	}
	
	hip_common = (struct hip_common*)buf;
	HIP_DEBUG("Received HIP packet type %d\n", hip_common->type_hdr);
	_HIP_HEXDUMP("HIP PACKET", hip_common,
		     hip_get_msg_total_len(hip_common));

	/*        if (hip_verify_network_header(hip_common, 
				      (struct sockaddr *)&src, 
				      (struct sockaddr *)&dst,
				      len)) {
		HIP_ERROR("Verifying of the network header failed\n");
		goto out_err;
		}*/

	if(hip_check_network_msg(hip_common)){
		HIP_ERROR("HIP packet is invalid\n");
		goto out_err;
	}
	
	memset(&msg_info, 0, sizeof(msg_info));
	msg_info.hi3_in_use = 1;

	struct in6_addr lpback1 = IN6ADDR_LOOPBACK_INIT;
	struct in6_addr lpback2 = IN6ADDR_LOOPBACK_INIT;

	if(hip_receive_control_packet(hip_common, &lpback1 , &lpback2, //hip_cast_sa_addr(&src), hip_cast_sa_addr(&dst),
				       &msg_info, 0)){
		HIP_ERROR("HIP packet processsing failed\n");
		goto out_err;
	}

 out_err:
	//cl_free_buf(clb);
	;
}


/* 
 * i3 callbacks for trigger management
 */
void hip_hi3_constraint_failed(cl_trigger *t, void *data, void *fun_ctx){
	/* This should never occur if the infrastructure works */
	HIP_ERROR("Trigger constraint failed\n");
}


void hip_hi3_trigger_inserted(cl_trigger *t, void *data, void *fun_ctx){	
	char id[100];
	sprintf_i3_id(id, &t->t->id);
	
	HIP_ERROR("Trigger inserted: %s\n", id);
}


void hip_hi3_trigger_failure(cl_trigger *t, void *data, void *fun_ctx) {
	/* FIXME: A small delay before trying again? */
	HIP_ERROR("Trigger failed, reinserting...\n");
	
	/* Reinsert trigger */
	cl_insert_trigger(t, 0);
}


int hip_hi3_insert_trigger(){
	Key key[HI3_TRIGGER_MAX];
	int i;
	hip_hit_t peer_hit;

	//	hip_get_default_hit(&peer_hit);
	//	hip_i3_init(/*&peer_hit*/);
	//	hi3_pub_tr_count = 1;
	//	memcpy(&hi3_pub_id[0], &peer_hit, sizeof(hip_hit_t));
	hip_for_each_hi(hip_hi3_add_pub_trigger_id, &hi3_pub_tr_count );

	for( i=0; i<hi3_pub_tr_count; i++ ){
		get_random_bytes(hi3_pri_id[i].x, ID_LEN);	
//	        get_random_bytes(key.x, KEY_LEN);

		hi3_pub_tr[i] = cl_create_trigger_id(&hi3_pub_id[i], ID_LEN_BITS, &hi3_pri_id[i],
						  CL_TRIGGER_CFLAG_R_CONSTRAINT);
//				CL_TRIGGER_CFLAG_L_CONSTRAINT |
//				CL_TRIGGER_CFLAG_PUBLIC);

		cl_register_trigger_callback(hi3_pub_tr[i], CL_CBK_TRIGGER_CONSTRAINT_FAILED,
					     hip_hi3_constraint_failed, NULL);
		cl_register_trigger_callback(hi3_pub_tr[i], CL_CBK_RECEIVE_PAYLOAD,
					     hip_hi3_receive_payload, NULL);
		cl_register_trigger_callback(hi3_pub_tr[i], CL_CBK_TRIGGER_INSERTED,
					     hip_hi3_trigger_inserted, NULL);
		cl_register_trigger_callback(hi3_pub_tr[i], CL_CBK_TRIGGER_REFRESH_FAILED,
					     hip_hi3_trigger_failure, NULL);


		hi3_pri_tr[i]  = cl_create_trigger(&hi3_pri_id[i], ID_LEN_BITS, &key[i],
						CL_TRIGGER_CFLAG_R_CONSTRAINT);


		/* associate callbacks with the inserted trigger */
		cl_register_trigger_callback(hi3_pri_tr[i], CL_CBK_TRIGGER_CONSTRAINT_FAILED,
					     hip_hi3_constraint_failed, NULL);
		cl_register_trigger_callback(hi3_pri_tr[i], CL_CBK_RECEIVE_PAYLOAD,
					     hip_hi3_receive_payload, NULL);
		cl_register_trigger_callback(hi3_pri_tr[i], CL_CBK_TRIGGER_INSERTED,
					     hip_hi3_trigger_inserted, NULL);
		cl_register_trigger_callback(hi3_pri_tr[i], CL_CBK_TRIGGER_REFRESH_FAILED,
					     hip_hi3_trigger_failure, NULL);
	}
	/* Insert triggers */
	for(i=0; i<hi3_pub_tr_count; i++){
		cl_insert_trigger(hi3_pri_tr[i], 0);
		cl_insert_trigger(hi3_pub_tr[i], 0);
	}

}


int hip_hi3_clean(){
	int i=0;
	for(i=0; i<hi3_pub_tr_count; i++){
		cl_destroy_trigger(hi3_pub_tr[i]);
		cl_destroy_trigger(hi3_pri_tr[i]);
	}
	hi3_pub_tr_count = 0;

	cl_exit();
}


int hip_do_i3_stuff_for_i2(struct hip_locator *locator, hip_portpair_t *i2_info,
			   in6_addr_t *i2_saddr, in6_addr_t *i2_daddr){
	int n_addrs = 0, ii = 0, use_ip4 = 1;
	struct hip_locator_info_addr_item *first = NULL;
	struct netdev_address *n = NULL;
	hip_list_t *item = NULL, *tmp = NULL;

	if(locator == NULL){
		return 0;
	}
	
        if(locator){
		n_addrs = hip_get_locator_addr_item_count(locator);
		
		if(i2_info->hi3_in_use && n_addrs > 0){
			
                        first = (struct hip_locator_info_addr_item *)locator + sizeof(struct hip_locator);
                        memcpy(i2_saddr, &first->address,
			       sizeof(struct in6_addr));
			
                        list_for_each_safe(item, tmp, addresses, ii){
				n = list_entry(item);
				
				if(ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr))){
					continue;
				}
				if(!hip_sockaddr_is_v6_mapped((struct sockaddr *)&n->addr)){
					memcpy(i2_daddr, hip_cast_sa_addr(&n->addr),
					       hip_sa_addr_len(&n->addr));
					ii = -1;
					use_ip4 = 0;
					break;
				}
			}
                        if(use_ip4){
                                list_for_each_safe(item, tmp, addresses, ii){
					n = list_entry(item);
					
					if(ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr))){
						continue;
					}
					if(hip_sockaddr_is_v6_mapped((struct sockaddr *)&n->addr)){
						memcpy(i2_daddr, hip_cast_sa_addr(&n->addr),
						       hip_sa_addr_len(&n->addr));
						ii = -1;
						break;
					}
				}
                        }
		}
	}
}

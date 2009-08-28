#include "conndb.h"

/*
 * HIP proxy connection tracking
 */

/** A callback wrapper of the prototype required by @c lh_new(). */
//static IMPLEMENT_LHASH_HASH_FN(hip_hash_proxy_db, const hip_proxy_t *)
/** A callback wrapper of the prototype required by @c lh_new(). */
//static IMPLEMENT_LHASH_COMP_FN(hip_compare_conn_db, const hip_conn_t *)

/**
 * Maps function @c func to every HA in HIT hash table. The hash table is
 * LOCKED while we process all the entries. This means that the mapper function
 * MUST be very short and _NOT_ do any operations that might sleep!
 *
 * @param func a mapper function.
 * @param opaque opaque data for the mapper function.
 * @return       negative if an error occurs. If an error occurs during
 *               traversal of a the HIT hash table, then the traversal is
 *               stopped and function returns. Returns the last return value of
 *               applying the mapper function to the last element in the hash
 *               table.
 */
int hip_for_each_conn_db(int (*func)(hip_conn_t *entry, void *opaq), void *opaque)
{
	int i = 0, fail = 0;
	hip_conn_t *this;
	hip_list_t *item, *tmp;

	if (!func)
		return -EINVAL;

	HIP_LOCK_HT(&hip_conn_db);
	list_for_each_safe(item, tmp, hip_conn_db, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("list_for_each_safe\n");
		hip_hold_ha(this);
		fail = func(this, opaque);
		hip_db_put_ha(this, hip_hadb_delete_state);
		if (fail)
			goto out_err;
	}

	out_err:	
	HIP_UNLOCK_HT(&hip_conn_db);
	return fail;
}

unsigned long hip_hash_conn_db(const hip_conn_t *p)
{
	struct in6_addr *addr_src;
	uint8_t hash[HIP_AH_SHA_LEN];

	if(p == NULL)
	{
		return 0;
	}
	
	hip_build_digest(HIP_DIGEST_SHA1, (void *)p, sizeof(struct hip_conn_key), hash);
	return *((unsigned long *)hash);
}

int hip_compare_conn_db(const hip_conn_t *ha1, const hip_conn_t *ha2)
{
	if(ha1 == NULL || &(ha1->key) == NULL || &(ha1->addr_client) == NULL || &(ha1->addr_peer) == NULL ||
			ha2 == NULL ||  &(ha2->key) == NULL || &(ha2->addr_client) == NULL ||&(ha2->addr_peer) == NULL )
	{
		return 1;
	}

	return (hip_hash_conn_db(ha1) != hip_hash_conn_db(ha2));
}

void hip_init_conn_db(void)
{
	/** @todo Check for errors. */

	/* The next line initializes the hash table for host associations. Note
	that we are using callback wrappers IMPLEMENT_LHASH_HASH_FN and
	IMPLEMENT_LHASH_COMP_FN defined in the beginning of this file. These
	provide automagic variable casts, so that all elements stored in the
	hash table are cast to hip_ha_t. Lauri 09.10.2007 16:58. */
	//hip_conn_db = hip_ht_init(LHASH_HASH_FN(hip_hash_conn_db),
	//			   LHASH_COMP_FN(hip_compare_conn_db));

	hip_conn_db = hip_ht_init(hip_hash_conn_db, hip_compare_conn_db);	
}



void hip_uninit_conn_db()
{
	int i = 0;
	hip_list_t *item, *tmp;
	hip_conn_t *entry;

	list_for_each_safe(item, tmp, hip_conn_db, i)
	{
		entry = list_entry(item);
		hip_ht_delete(hip_conn_db, entry);
	}  

}

int hip_conn_add_entry(struct in6_addr *addr_client, 
		       struct in6_addr *addr_peer,
		       struct in6_addr *hit_proxy, 
		       struct in6_addr *hit_peer, 
		       int protocol, 
		       int port_client, 
		       int port_peer,  
		       int state)
{
	hip_conn_t *tmp = NULL, *new_item = NULL;
	int err = 0;

	new_item = (hip_conn_t *)malloc(sizeof(hip_conn_t));
	if (!new_item)
	{
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}

	memset(new_item, 0, sizeof(hip_conn_t));
	ipv6_addr_copy(&new_item->addr_client, addr_client);
	ipv6_addr_copy(&new_item->addr_peer, addr_peer);
	ipv6_addr_copy(&new_item->key.hit_proxy, hit_proxy);
	ipv6_addr_copy(&new_item->key.hit_peer, hit_peer);
	new_item->key.protocol = protocol;
	new_item->key.port_client = port_client;
	new_item->key.port_peer = port_peer;
	//new_item->key.hit_proxy = *hit_proxy;
	//new_item->key.hit_peer = *hit_peer;
	new_item->state = state;
	err = hip_ht_add(hip_conn_db, new_item);
	HIP_DEBUG("conn adds connection state successfully!\n");
	HIP_DEBUG_IN6ADDR("source ip addr",&new_item->addr_client);
	HIP_DEBUG_IN6ADDR("destination ip addr",&new_item->addr_peer);
	HIP_DEBUG("port_client=%d port_peer=%d protocol=%d\n", port_client, port_peer, protocol);

	return err;
}


hip_conn_t *hip_conn_find_by_portinfo(struct in6_addr *hit_proxy,
				      struct in6_addr *hit_peer,
				      int protocol,
				      int port_client,
				      int port_peer)
{
	hip_conn_t p, *ret;
	memcpy(&p.key.hit_proxy, hit_proxy, sizeof(struct in6_addr));
	memcpy(&p.key.hit_peer, hit_peer, sizeof(struct in6_addr));
	p.key.protocol = protocol;
	p.key.port_client = port_client;
	p.key.port_peer = port_peer;
	return hip_ht_find(hip_conn_db, &p);
}

/*
int hip_conn_update_state(struct in6_addr *src_addr,
		struct in6_addr *dst_addr, struct in6_addr* peer_hit,
		int state)
{
	hip_conn_t *p;

	_HIP_DEBUG_IN6ADDR("src_addr", src_addr);
	_HIP_DEBUG_IN6ADDR("dst_addr", dst_addr);

	p = hip_conn_find_by_addr(src_addr, dst_addr);
	if(p)
	{
		if(peer_hit)
			p->hit_peer = *peer_hit;
		p->state = state;
	
		HIP_DEBUG("Update connection state successfully!\n");
		//		memcpy(&p->hit_our, src_hit, sizeof(struct in6_addr));
		//		memcpy(&p->hit_peer, dst_hit, sizeof(struct in6_aadr));
		//		ipv6_addr_copy(&p->hit_our, addr_our);
		//		ipv6_addr_copy(&p->hit_peer, addr_peer);				
		return 0;
	}
	else
	{
		HIP_DEBUG("Can not update connection state!\n");
		return 1;
	}
}
*/


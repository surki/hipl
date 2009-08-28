/** @file 
 * oppipdb.c:
 * This file defines handling functions for opportunistic mode to remember
 * IP's which are not HIP capable. This means faster communication in second
 * connection attempts to these hosts. Otherwise it would always take the same
 * fallback timeout (about 5 secs) to make new connection to hosts which don't
 * support HIP.
 * 
 * @author  Antti Partanen
 * @author  Alberto Garcia
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */


#ifdef CONFIG_HIP_OPPORTUNISTIC

#include "oppipdb.h"

HIP_HASHTABLE *oppipdb;
extern unsigned int opportunistic_mode;

/**
 * hip_oppipdb_hash_ip:
 * Generates the hash information that is used to index the table
 *
 * @param ptr: pointer to the ip address used to make the hash
 *
 * @return hash information
 */
unsigned long hip_oppipdb_hash_ip(const void *ptr)
{
	hip_oppip_t *entry = (hip_oppip_t *)ptr;
	uint8_t hash[HIP_AH_SHA_LEN];

	hip_build_digest(HIP_DIGEST_SHA1, entry, sizeof(hip_oppip_t), hash);

	return *((unsigned long *)hash);
}

/**
 * hip_oppipdb_match_ip:
 * Compares two ip addresses using their hashes
 *
 * @param ptr1: pointer to the first ip address to compare
 * @param ptr2: pointer to the second ip address to compare
 *
 * @return 0 if the ip hashes are identical, 1 if they are different
 */
int hip_oppipdb_match_ip(const void *ptr1, const void *ptr2)
{
	return (hip_oppipdb_hash_ip(ptr1) != hip_oppipdb_hash_ip(ptr2));
}


/**
 * hip_for_each_oppip:
 * Map function @func to every entry in the oppipdb hash table
 *
 * @param func: mapper function to apply to all entries
 * @param opaque: opaque data for the mapper function
 *
 * @return negative value if an error occurs. If an error occurs during traversal of
 * the oppipdb hash table, then the traversal is stopped and function returns.
 * Returns the last return value of applying the mapper function to the last
 * element in the hash table.
 */
int hip_for_each_oppip(int (*func)(hip_oppip_t *entry, void *opaq), void *opaque)
{
	int i = 0, fail = 0;
	hip_oppip_t *this;
	hip_list_t *item, *tmp;
	
	if (!func) return -EINVAL;
	
	HIP_LOCK_HT(&oppipdb);
	list_for_each_safe(item, tmp, oppipdb, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("List_for_each_entry_safe\n");
		//hip_hold_ha(this);
		fail = func(this, opaque);
		//hip_db_put_ha(this, hip_oppdb_del_entry_by_entry);
		if (fail)
			goto out_err;
	}
 out_err:
	HIP_UNLOCK_HT(&oppipdb);
	return fail;
}

/**
 * hip_oppipdb_del_entry_by_entry:
 * Deletes an entry that is present in oppipdb hash table
 *
 * @param entry: pointer to the entry to delete
 */
void hip_oppipdb_del_entry_by_entry(hip_oppip_t *entry)
{

	HIP_LOCK_OPPIP(entry);
	hip_ht_delete(oppipdb, entry);
	HIP_UNLOCK_OPPIP(entry);

}

/**
 * hip_oppipdb_uninit_wrap:
 * Wrap function for hip_oppipdb_del_entry_by_entry()
 *
 * @param entry: pointer to the entry to delete
 * @param void: unused pointer
 *
 * @return 0 on success
 */
int hip_oppipdb_uninit_wrap(hip_oppip_t *entry, void *unused)
{
	hip_oppipdb_del_entry_by_entry(entry);
	return 0;
}

/**
 * hip_oppipdb_uninit:
 * Deletes the whole oppipdb hash table
 */
void hip_oppipdb_uninit(void)
{
	hip_for_each_oppip(hip_oppipdb_uninit_wrap, NULL);
}

/**
 * hip_create_oppip_entry:
 * Allocates and initilizes the node to store the information 
 * in the oppipdb hash table
 *
 * @return pointer to the allocated structure
 */
hip_oppip_t *hip_create_oppip_entry(void)
{
	hip_oppip_t * entry = NULL;

	entry = (hip_oppip_t *)malloc(sizeof(hip_oppip_t));
	if (!entry){
		HIP_ERROR("hip_oppip_t memory allocation failed.\n");
		return NULL;
	}
  
	memset(entry, 0, sizeof(*entry));

 out_err:
        return entry;
}

/**
 * hip_oppipdb_add_entry:
 * Adds a new entry to the oppipdb hash table. 
 * This table stores the ip addresses of the hosts that are not HIP capable.
 *
 * @param ip_peer: pointer to the ip of the non-HIP capable host
 *                 to be added to the table
 * @return 0 or the value being added on success; -ENOMEM on malloc failure
 */
int hip_oppipdb_add_entry(const struct in6_addr *ip_peer)
{
	int err = 0;
	hip_oppip_t *tmp = NULL;
	hip_oppip_t *new_item = NULL;
	
	new_item = hip_create_oppip_entry();
	if (!new_item) {
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}

	//HIP_IFEL(!ipv6_addr_copy(new_item, ip_peer), -1,
	//	 "Copy non-HIP host failed\n");
	ipv6_addr_copy(new_item, ip_peer);

	err = hip_ht_add(oppipdb, new_item);
	//hip_oppipdb_dump();
	
 out_err:
	return err;
}

/**
 * hip_init_oppip_db:
 * Creates and initializes the oppipdb hash table
 *
 * @return 0 on success
 */
int hip_init_oppip_db(void)
{
	oppipdb = hip_ht_init(hip_oppipdb_hash_ip, hip_oppipdb_match_ip);
	return 0;
}

/**
 * hip_oppipdb_dump:
 * Dumps the whole oppipdb hash table for monitoring purposes
 */
void hip_oppipdb_dump(void)
{
	int i;
	hip_oppip_t *this;
	hip_list_t *item, *tmp;
	
	HIP_DEBUG("Start oppipdb dump. Non-HIP peers are:\n");
	HIP_LOCK_HT(&oppipdb);

	list_for_each_safe(item, tmp, oppipdb, i)
	{
		this = list_entry(item);
		HIP_DEBUG_IN6ADDR("", this);
	}

	HIP_UNLOCK_HT(&oppipdb);
	HIP_DEBUG("end oppipdb dump\n");
}

/**
 * hip_oppipdb_find_byip:
 * Seeks an ip within the oppipdb hash table.
 * If the ip is found in the table, that host is not HIP capable.
 *
 * @param ip_peer: pointer to the ip of the host to check whether 
 *                 it is HIP capable
 * @return pointer to the entry if the ip is found in the table; NULL otherwise
 */
hip_oppip_t *hip_oppipdb_find_byip(const struct in6_addr *ip_peer)
{
	hip_oppip_t *ret = NULL;

	//hip_oppipdb_dump();
	_HIP_DEBUG_IN6ADDR("Searching in oppipdb for ip:", ip_peer);
	ret = hip_ht_find(oppipdb, (void *)ip_peer);
	if (!ret)
		HIP_DEBUG("The ip was not present in oppipdb. Peer HIP capable.\n");
	else
	        HIP_DEBUG("The ip was found in oppipdb. Peer non-HIP capable.\n");

	return ret;
}

/**
 * hip_oppipdb_delentry:
 * This function should be called after receiving an R1 from the peer and after
 * a successful base exchange in the opportunistic mode. It checks whether an
 * address of a HIP capable host is found from database. If the address is 
 * found, it is deleted from the database; since the host is actually HIP capable.
 *
 * @param ip_peer: pointer to the ip of the HIP-capable host
 */
void hip_oppipdb_delentry(const struct in6_addr *ip_peer)
{
	int i;
	hip_oppip_t *ret;
	_HIP_DEBUG("beginning of hip_oppipdb_delentry\n");
	
	if (ret = hip_oppipdb_find_byip(ip_peer)){
	      HIP_DEBUG_IN6ADDR("HIP capable host found in oppipbd (non-HIP hosts database). Deleting it from oppipdb.", ip_peer);
	      hip_oppipdb_del_entry_by_entry(ret);
	}
	
}


#endif /* CONFIG_HIP_OPPORTUNISTIC */



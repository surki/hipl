/*
 * libinet6 wrap_db.c
 *
 * Licence: GNU/GPL
 * Authors: 
 * - Bing Zhou <bingzhou@cc.hut.fi>
 *
 */
#ifdef CONFIG_HIP_OPPORTUNISTIC
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <pthread.h>

#include "hashtable.h"
#include "hadb.h"
#include "wrap_db.h"

HIP_HASHTABLE *socketdb;

int hip_exists_translation(int pid, int socket, pthread_t tid)
{
	hip_opp_socket_t *entry = NULL;

	entry = hip_socketdb_find_entry(pid, socket, tid);

	if(entry) {
		if(entry->pid == pid && entry->orig_socket == socket &&
		   entry->tid == tid)
			return 1;
		else
			return 0;
	} else
		return 0;
}

unsigned long hip_hash_pid_socket(const void *ptr)
{
	hip_opp_socket_t *entry = (hip_opp_socket_t *)ptr;
	uint8_t hash[HIP_AH_SHA_LEN];

	/* 
	   The hash table is indexed with three fields: 
	   pid, original socket, tid (thread id)
	 */
	hip_build_digest(HIP_DIGEST_SHA1, entry, sizeof(pid_t)+sizeof(int)+sizeof(pthread_t), hash);

	return *((unsigned long *)hash);

}

int hip_socketdb_match(const void *ptr1, const void *ptr2)
{
	unsigned long key1, key2;
	
	key1 = hip_hash_pid_socket(ptr1);
	key2 = hip_hash_pid_socket(ptr2);
	_HIP_DEBUG("key1=0x%x key2=0x%x\n", key1, key2);
	return (key1 != key2);
}

void hip_init_socket_db()
{
	socketdb = hip_ht_init(hip_hash_pid_socket, hip_socketdb_match);
	if (!socketdb) HIP_ERROR("hip_init_socket_db() error!\n");
}

//void hip_hadb_delete_hs(struct hip_hit_spi *hs)
void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry)
{
	_HIP_DEBUG("entry=0x%p pid=%d, orig_socket=%d\n", entry,
		  entry->pid, entry->orig_socket);
	if (!hip_ht_delete(socketdb, entry))
	  HIP_DEBUG("No entry was found to delete.\n");
}
void hip_uninit_socket_db()
{
	int i = 0;
	hip_list_t *item, *tmp;
	hip_opp_socket_t *entry;
	
	_HIP_DEBUG("DEBUG: DUMP SOCKETDB LISTS\n");
	//hip_socketdb_dump();
	
	_HIP_DEBUG("DELETING\n");
	//  hip_ht_uninit();
	list_for_each_safe(item, tmp, socketdb, i)
	{
//		if (atomic_read(&item->refcnt) > 2)
//			HIP_ERROR("socketdb: %p, in use while removing it from socketdb\n", item);
		entry = list_entry(item);
		hip_socketdb_del_entry_by_entry(entry);
	}  

}

/**
 * This function searches for a hip_opp_socket_t entry from the socketdb
 * by pid and orig_socket.
 */
//hip_ha_t *hip_hadb_find_byhits(hip_hit_t *hit, hip_hit_t *hit2)
hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket, pthread_t tid)
{
	hip_opp_socket_t opp, *ret;

	opp.pid = pid;
	opp.orig_socket = socket;
	opp.tid = tid;
	_HIP_DEBUG("pid %d socket %d computed key\n", pid, socket);
	
	ret = (hip_opp_socket_t *)hip_ht_find(socketdb, (void *)&opp);

	return ret;
}

void hip_socketdb_dump()
{
	int i;
	char src_ip[INET6_ADDRSTRLEN] = "\0";
	char dst_ip[INET6_ADDRSTRLEN] = "\0";
	char src_hit[INET6_ADDRSTRLEN] = "\0";
	char dst_hit[INET6_ADDRSTRLEN] = "\0";
	hip_list_t *item, *tmp;
	hip_opp_socket_t *entry;

	HIP_DEBUG("start socketdb dump\n");

	//HIP_LOCK_HT(&socketdb);
	
	list_for_each_safe(item, tmp, socketdb, i)
	{
		entry = list_entry(item);
	/*	hip_in6_ntop(hip_cast_sa_addr(&entry->orig_local_id), src_ip);
		hip_in6_ntop(hip_cast_sa_addr(&entry->orig_peer_id), dst_ip);
		hip_in6_ntop(hip_cast_sa_addr(&entry->translated_local_id), src_hit);
		hip_in6_ntop(hip_cast_sa_addr(&entry->translated_peer_id), dst_hit);


		HIP_DEBUG("pid=%d orig_socket=%d new_socket=%d"
		          " domain=%d type=%d protocol=%d"
		          " src_ip=%s dst_ip=%s src_hit=%s"
		          " dst_hit=%s\n",
		          entry->pid, entry->orig_socket,
		          entry->translated_socket,
		          entry->domain,
		          entry->type, entry->protocol,
		          src_ip, dst_ip, src_hit, dst_hit);
	*/

		HIP_DEBUG("pid=%d orig_socket=%d tid=%d new_socket=%d domain=%d\n",
			  entry->pid, entry->orig_socket, entry->tid,
		          entry->translated_socket,
		          entry->domain);

	}
	
	//HIP_UNLOCK_HT(&socketdb);
	HIP_DEBUG("end socketdb dump\n");
}

hip_opp_socket_t *hip_create_opp_entry() 
{
	hip_opp_socket_t * entry = NULL;
	
	entry = (hip_opp_socket_t *)malloc(sizeof(hip_opp_socket_t));
	if (!entry){
		HIP_ERROR("hip_opp_socket_t memory allocation failed.\n");
		return NULL;
	}
	
	memset(entry, 0, sizeof(*entry));
	
// 	INIT_LIST_HEAD(&entry->next_entry);
	
	//HIP_LOCK_SOCKET_INIT(entry);
	//atomic_set(&entry->refcnt, 0);
	//HIP_UNLOCK_SOCKET_INIT(entry);
 out_err:
	return entry;
}


//int hip_hadb_add_peer_info(hip_hit_t *peer_hit, struct in6_addr *peer_addr)
int hip_socketdb_add_entry(int pid, int socket, pthread_t tid)
{
	hip_opp_socket_t *tmp = NULL, *new_item = NULL;
	int err = 0;
	
	new_item = (hip_opp_socket_t *)malloc(sizeof(hip_opp_socket_t));
	if (!new_item)
	{
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}
	
	memset(new_item, 0, sizeof(hip_opp_socket_t));
	
	new_item->pid = pid;
	new_item->orig_socket = socket;
	new_item->tid = tid;
	err = hip_ht_add(socketdb, new_item);
	_HIP_DEBUG("pid %d, orig_sock %d, tid %d are added to HT socketdb, entry=%p\n",
		  new_item->pid, new_item->orig_socket, new_item->tid, new_item); 
	//hip_socketdb_dump();

	return err;
}

int hip_socketdb_del_entry(int pid, int socket, pthread_t tid)
{
	hip_opp_socket_t *entry = NULL;

	entry = hip_socketdb_find_entry(pid, socket, tid);
	if (!entry) {
		return -ENOENT;
	}
	hip_socketdb_del_entry_by_entry(entry);

	return 0;
}

#endif // CONFIG_HIP_OPPORTUNISTIC


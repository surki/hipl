
/*
*  HIP socket handler loadable kernel module
*  for kernel 2.6
*
* Description:
* 
*
* Authors: 
*   - Tobias Heer <heer@tobobox.de> 2006
*   - Miika Komu <miika@iki.fi>
*   - Laura Takkinen <laura.takkinen@hut.fi>
* Licence: GNU/GPL
*
*/

#include "eid_db.h"

//HIP_INIT_DB(hip_local_eid_db, "local_eid");
//HIP_INIT_DB(hip_peer_eid_db, "peer_eid");
struct hip_db_struct hip_local_eid_db;
struct hip_db_struct hip_peer_eid_db;

/*
 * The eid db lock (local or peer) must be obtained before accessing these
 * variables.
 */
static sa_eid_t hip_local_eid_count = 1;
static sa_eid_t hip_peer_eid_count  = 1;

sa_eid_t hip_create_unique_local_eid(void)
{
        // XX CHECK OVERFLOWS
        return hip_local_eid_count++;
}

sa_eid_t hip_create_unique_peer_eid(void)
{
        // XX CHECK OVERFLOWS
        return hip_peer_eid_count++;
}

struct hip_eid_db_entry *hip_db_find_eid_entry_by_hit_no_lock(struct hip_db_struct *db,
                                                     const struct hip_lhi *lhi)
{
        struct hip_eid_db_entry *entry;

        HIP_DEBUG("\n");

        list_for_each_entry(entry, &db->db_head, next) {
                /*! \todo Skip the anonymous bit. Is it ok? */
                if (!ipv6_addr_cmp(&entry->lhi.hit,
                                   (struct in6_addr *) &lhi->hit))
                        return entry;
        }

        return NULL;
}

struct hip_eid_db_entry *hip_db_find_eid_entry_by_eid_no_lock(struct hip_db_struct *db,
                                                const struct sockaddr_eid *eid)
{
        struct hip_eid_db_entry *entry;

        list_for_each_entry(entry, &db->db_head, next) {
                HIP_DEBUG("comparing %d with %d\n",
                          ntohs(entry->eid.eid_val), ntohs(eid->eid_val));
                if (entry->eid.eid_val == eid->eid_val)
                            return entry;
        }

        return NULL;
}

int hip_db_set_eid(struct sockaddr_eid *eid,
                   const struct hip_lhi *lhi,
                   const struct hip_eid_owner_info *owner_info,
                   int is_local)
{
        struct hip_db_struct *db;
        int err = 0;
        struct hip_eid_db_entry *entry = NULL;

        HIP_DEBUG("Accessing %s eid db\n", ((is_local) ? "local" : "peer"));

        db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;

        HIP_WRITE_LOCK_DB(db);

        entry = hip_db_find_eid_entry_by_hit_no_lock(db, lhi);
        if (!entry) {
                entry = HIP_MALLOC(sizeof(struct hip_eid_db_entry),
                                   GFP_KERNEL);
                if (!entry) {
                        err = -ENOMEM;
                        goto out_err;
                }

                entry->eid.eid_val = ((is_local) ?
                        htons(hip_create_unique_local_eid()) :
                        htons(hip_create_unique_peer_eid()));
                entry->eid.eid_family = PF_HIP;
                memcpy(eid, &entry->eid, sizeof(struct sockaddr_eid));

                HIP_DEBUG("Generated eid val %d\n", entry->eid.eid_val);

                memcpy(&entry->lhi, lhi, sizeof(struct hip_lhi));
                memcpy(&entry->owner_info, owner_info,
                       sizeof(struct hip_eid_owner_info));

                /* Finished. Add the entry to the list. */
                list_add(&entry->next, &db->db_head);
        } else {
                /*! \todo Ownership is not changed here; should it? */
                memcpy(eid, &entry->eid, sizeof(struct sockaddr_eid));
        }

 out_err:
        HIP_WRITE_UNLOCK_DB(db);

        return err;
}

int hip_db_set_my_eid(struct sockaddr_eid *eid,
                      const struct hip_lhi *lhi,
                      const struct hip_eid_owner_info *owner_info)
{
        return hip_db_set_eid(eid, lhi, owner_info, 1);
}

int hip_db_set_peer_eid(struct sockaddr_eid *eid,
                        const struct hip_lhi *lhi,
                        const struct hip_eid_owner_info *owner_info)
{
        return hip_db_set_eid(eid, lhi, owner_info, 0);
}


/*
 * This function is similar to hip_socket_handle_add_local_hi but there are
 * three major differences:
 * - this function is used by native HIP sockets (not hipconf)
 * - HIP sockets require EID handling which is done here
 * - this function DOES NOT call hip_precreate_r1, so you need launch
 */
int hip_socket_handle_set_my_eid(struct hip_common *msg)
{
        int err = 0;
        struct sockaddr_eid eid;
        struct hip_tlv_common *param = NULL;
        struct hip_eid_iface *iface;
        struct hip_eid_endpoint *eid_endpoint;
        struct hip_lhi lhi;
        struct hip_eid_owner_info owner_info;
        struct hip_host_id *host_id;
	hip_hit_t *hit = NULL;
        
        HIP_DEBUG("\n");
        
        /* Extra consistency test */
        if (hip_get_msg_type(msg) != SO_HIP_SET_MY_EID) {
                err = -EINVAL;
                HIP_ERROR("Bad message type\n");
                goto out_err;
        }
        
	eid_endpoint = hip_get_param(msg, HIP_PARAM_EID_ENDPOINT);
        if (!eid_endpoint) {
                err = -ENOENT;
                HIP_ERROR("Could not find eid endpoint\n");
                goto out_err;
        }

        HIP_DEBUG("hi len %d\n",
                  ntohs((eid_endpoint->endpoint.id.host_id.hi_length)));

        HIP_HEXDUMP("eid endpoint", eid_endpoint,
                    hip_get_param_total_len(eid_endpoint));

        host_id = &eid_endpoint->endpoint.id.host_id;

	owner_info.uid = current->uid;
        owner_info.gid = current->gid;
        owner_info.pid = current->pid;
        owner_info.flags = eid_endpoint->endpoint.flags;
        
        lhi.anonymous =
                (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_ANON) ?
                1 : 0;
	
	/*Laura***************************************************
	  The message should contain at least a HIT.Store it to &lhi.hit. 
	  Also, if there is public key, send to the hipd. 
	*/
 
	hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
	
	if(hit){
	  lhi.hit = *hit;
	}
	else{
	  HIP_ERROR("HIT was not found from the message\n");
	  goto out_err;
	}
	
	 HIP_DEBUG_HIT("Following local HIT was found from the message: HIT=\n", &lhi.hit);
        /*Laura*******************************************************/

               
        /* Iterate through the interfaces */
        while((param = hip_get_next_param(msg, param)) != NULL) {
                /* Skip other parameters (only the endpoint should
                   really be there). */
                if (hip_get_param_type(param) != HIP_PARAM_EID_IFACE)
                        continue;
                iface = (struct hip_eid_iface *) param;
                /*! \todo convert and store the iface somewhere?? */
                /*! \todo check also the UID permissions for storing
                   the ifaces before actually storing them */
        }
        
        /* The eid port information will be filled by the resolver. It is not
           really meaningful in the eid db. */
        eid.eid_port = htons(0);
        
        lhi.anonymous =
           (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_ANON) ?
                1 : 0;
        
        /*! \todo check UID/GID permissions before adding ? */
        err = hip_db_set_my_eid(&eid, &lhi, &owner_info);
        if (err) {
                HIP_ERROR("Could not set my eid into the db\n");
                goto out_err;
        }

        HIP_DEBUG("EID value was set to %d\n", ntohs(eid.eid_val));

        /* Clear the msg and reuse it for the result */
        
        hip_msg_init(msg);
        hip_build_user_hdr(msg, SO_HIP_SET_MY_EID, err);
        err = hip_build_param_eid_sockaddr(msg, (struct sockaddr *) &eid,
                                           sizeof(struct sockaddr_eid));
        if (err) {
                HIP_ERROR("Could not build eid sockaddr\n");
                goto out_err;
        }
        
 out_err:
        return err;
}

int hip_socket_handle_set_peer_eid(struct hip_common *msg)
{
        int err = 0;
        struct sockaddr_eid eid;
        struct hip_eid_endpoint *eid_endpoint;
        struct hip_lhi lhi;
        struct hip_eid_owner_info owner_info;

        HIP_DEBUG("\n");
        
        /* Extra consistency test */
        if (hip_get_msg_type(msg) != SO_HIP_SET_PEER_EID) {
                err = -EINVAL;
                HIP_ERROR("Bad message type\n");
                goto out_err;
        }
        
        eid_endpoint = hip_get_param(msg, HIP_PARAM_EID_ENDPOINT);
        if (!eid_endpoint) {
                err = -ENOENT;
                HIP_ERROR("Could not find eid endpoint\n");
                goto out_err;
        }
        
        if (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_HIT) {
                memcpy(&lhi.hit, &eid_endpoint->endpoint.id.hit,
                       sizeof(struct in6_addr));
                HIP_DEBUG_HIT("Peer HIT: ", &lhi.hit);
        } else {
		err = -1;
		HIP_ERROR("Public keys are not supported\n");
		goto out_err;
        }
        lhi.anonymous =
               (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_ANON) ? 1 : 0;

        /* Fill eid owner information in and assign a peer EID */

        owner_info.uid = current->uid;
        owner_info.gid = current->gid;
        
        /* The eid port information will be filled by the resolver. It is not
           really meaningful in the eid db. */
        eid.eid_port = htons(0);

        err = hip_db_set_peer_eid(&eid, &lhi, &owner_info);
        if (err) {
                HIP_ERROR("Could not set my eid into the db\n");
                goto out_err;
        }
        
        /* Write a return message with the EID (reuse the msg for
           result). */

        hip_msg_init(msg);
        hip_build_user_hdr(msg, SO_HIP_SET_PEER_EID, -err);
        err = hip_build_param_eid_sockaddr(msg,
                                           (struct sockaddr *) &eid,
                                           sizeof(eid));
        if (err) {
                HIP_ERROR("Could not build eid sockaddr\n");
                goto out_err;
        }

 out_err:
        /* XX FIXME: if there were errors, remove eid and hit-ip mappings
           if necessary */

        return err;
}

/*
 * Decreases the use_cnt entry in the hip_eid_db_entry struct and deletes
 * the entry for the given eid_val if use_cnt drops below one.
 */
void hip_db_dec_eid_use_cnt_by_eid_val(struct hip_db_struct *db, 
                                        sa_eid_t eid_val) 
{       

        struct hip_eid_db_entry *tmp;
        struct list_head *curr, *iter;

        HIP_WRITE_LOCK_DB(db);
        
        list_for_each_safe(curr, iter, &db->db_head){
                tmp = list_entry(curr ,struct hip_eid_db_entry, next);
                HIP_DEBUG("comparing %d with %d\n",
                          ntohs(tmp->eid.eid_val), eid_val);
                if (ntohs(tmp->eid.eid_val) == eid_val) {
                        tmp->use_cnt--;
                        if(tmp->use_cnt < 1) {
                                kfree(tmp);
                                list_del(curr);
                        }
                        HIP_WRITE_UNLOCK_DB(db);
                        return;
                }
        }
        HIP_WRITE_UNLOCK_DB(db);
}

void hip_db_dec_eid_use_cnt(sa_eid_t eid_val, int is_local) 
{
        struct hip_db_struct *db;
        
        if(eid_val == 0) return;
        
        db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;
        hip_db_dec_eid_use_cnt_by_eid_val(db, eid_val);
}

int hip_db_get_lhi_by_eid(const struct sockaddr_eid *eid,
                          struct hip_lhi *lhi,
                          struct hip_eid_owner_info *owner_info,
                          int is_local)
{
        struct hip_db_struct *db;
        int err = 0;
        struct hip_eid_db_entry *entry = NULL;

        HIP_DEBUG("Accessing %s eid db\n", ((is_local) ? "local" : "peer"));

        db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;

        HIP_READ_LOCK_DB(db);

        entry = hip_db_find_eid_entry_by_eid_no_lock(db, eid);
        if (!entry) {
                err = -ENOENT;
                goto out_err;
        }

        memcpy(lhi, &entry->lhi, sizeof(struct hip_lhi));
        memcpy(owner_info, &entry->owner_info,
               sizeof(struct hip_eid_owner_info));

 out_err:
        HIP_READ_UNLOCK_DB(db);

        return err;
}

int hip_db_get_peer_lhi_by_eid(const struct sockaddr_eid *eid,
                          struct hip_lhi *lhi,
                          struct hip_eid_owner_info *owner_info)
{
        return hip_db_get_lhi_by_eid(eid, lhi, owner_info, 0);
}

int hip_db_get_my_lhi_by_eid(const struct sockaddr_eid *eid,
                             struct hip_lhi *lhi,
                             struct hip_eid_owner_info *owner_info)
{
        return hip_db_get_lhi_by_eid(eid, lhi, owner_info, 1);
}


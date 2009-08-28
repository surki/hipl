/* 
 * Implements interfaces used to set IpSec SA/SP through PFKEY API's
 *
 * Authors:
 * - Diego Beltrami <diego.beltrami@gmail.com>
 */

#include "xfrmapi.h"
#ifdef CONFIG_HIP_PFKEY
#include </usr/include/linux/pfkeyv2.h>
#include </usr/include/linux/ipsec.h>

// FIXME: This must be turned to BEET when BEET will be supported by pfkey as well
#define HIP_IPSEC_DEFAULT_MODE IPSEC_MODE_BEET

static __inline u_int8_t
sysdep_sa_len (const struct sockaddr *sa)
{
#ifdef __linux__
  switch (sa->sa_family)
    {
    case AF_INET:
      return sizeof (struct sockaddr_in);
    case AF_INET6:
      return sizeof (struct sockaddr_in6);
    }
  // log_print ("sysdep_sa_len: unknown sa family %d", sa->sa_family);
  return sizeof (struct sockaddr_in);
#else
  return sa->sa_len;
#endif
}

// Given an in6_addr, this function correctly fills in a sock_addr (needs to be already allocated!)
void get_sock_addr_from_in6(struct sockaddr* s_addr, struct in6_addr *addr)
{
	memset(s_addr, 0, sizeof(struct sockaddr_storage));

	if(IN6_IS_ADDR_V4MAPPED(addr)) {	
		s_addr->sa_family = AF_INET;
		memcpy(hip_cast_sa_addr(s_addr), &addr->s6_addr32[3], hip_sa_addr_len(s_addr));
	} else {
		s_addr->sa_family = AF_INET6;
		memcpy(hip_cast_sa_addr(s_addr), addr, hip_sa_addr_len(s_addr));
 	}
}

int hip_flush_all_policy()
{
	int so, len, err = 0;
	HIP_DEBUG("\n");
	HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

	HIP_DEBUG("FLushing all SP's\n");
	HIP_IFEBL(((len = pfkey_send_spdflush(so))<0), -1, 
		  pfkey_close(so), "ERROR in flushing policies %s\n", ipsec_strerror());
	HIP_DEBUG("FLushing all SP's was successful\n");
	return len;
out_err:
	HIP_ERROR("FLushing all SP's\n");
	return err;
}

int hip_flush_all_sa()
{
	int so, len, err = 0;
	HIP_DEBUG("\n");
	HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

	HIP_DEBUG("Flushing all SA's\n");
	HIP_IFEBL(((len = pfkey_send_flush(so, SADB_SATYPE_ESP))<0), -1,
		   pfkey_close(so), "ERROR in flushing policies %s\n", ipsec_strerror());
	return len;
out_err:
	return err;
}

void hip_delete_sa(u32 spi, struct in6_addr *peer_addr, struct in6_addr *dst_addr,
		   int direction, hip_ha_t *entry)
{
	int so, len, err = 0;
	struct sockaddr_storage ss_addr, dd_addr;
	struct sockaddr *saddr;
	struct sockaddr *daddr;
	in_port_t sport, dport;

	/* @todo: sport and dport should be used! */

	if (direction == HIP_SPI_DIRECTION_OUT)
	{
		sport = entry->local_udp_port;
		dport = entry->peer_udp_port;
		entry->outbound_sa_count--;
		if (entry->outbound_sa_count < 0) {
			HIP_ERROR("Warning: out sa count negative\n");
			entry->outbound_sa_count = 0;
		}
	}
	else
	{
		sport = entry->peer_udp_port;
		dport = entry->local_udp_port;
		entry->inbound_sa_count--;
		if (entry->inbound_sa_count < 0) {
			HIP_ERROR("Warning: in sa count negative\n");
			entry->inbound_sa_count = 0;
		}
	}

	saddr = (struct sockaddr*) &ss_addr;
	daddr = (struct sockaddr*) &dd_addr;

	HIP_DEBUG("\n");
	HIP_DEBUG("spi=0x%x\n", spi);
	HIP_DEBUG_IN6ADDR("peer_addr", peer_addr);
	HIP_DEBUG_IN6ADDR("dst_addr", dst_addr);
	// Sanity check
	HIP_IFEL((!peer_addr || !dst_addr), -1, "Addresses not valid when deleting SA's\n");

	HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

	get_sock_addr_from_in6(saddr, peer_addr);
	get_sock_addr_from_in6(daddr, dst_addr);

	HIP_IFEBL(((len = pfkey_send_delete(so, SADB_SATYPE_ESP,  HIP_IPSEC_DEFAULT_MODE, saddr, daddr, spi))<0), -1,
		  pfkey_close(so), "ERROR in deleting sa %s", ipsec_strerror());
out_err:
	return;
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit)
{

	uint32_t spi;
	get_random_bytes(&spi, sizeof(uint32_t));
	return spi;
}

/* Security associations in the kernel with BEET are bounded to the outer
 * address, meaning IP addresses. As a result the parameters to be given
 * should be such an addresses and not the HITs.
 */
uint32_t hip_add_sa(struct in6_addr *saddr, struct in6_addr *daddr,
		    struct in6_addr *src_hit, struct in6_addr *dst_hit,
		    uint32_t spi, int ealg, struct hip_crypto_key *enckey,
		    struct hip_crypto_key *authkey,
		    int already_acquired, int direction, int update,
		    hip_ha_t *entry)
{

	int so, len, err = 0, e_keylen, a_keylen;
	int aalg = ealg;
	u_int wsize = 4;  /* XXX static size of window */
	struct sockaddr_storage ss_addr, dd_addr;
	struct sockaddr *s_saddr;
	struct sockaddr *d_saddr;
	uint32_t reqid = 0;
	u_int32_t seq = 0;
	u_int flags = 0; // always zero
	u_int64_t lifebyte = 0, lifetime = 0;
	//u_int8_t l_natt_type = HIP_UDP_ENCAP_ESPINUDP_NON_IKE;
	u_int8_t l_natt_type = HIP_UDP_ENCAP_ESPINUDP;
	// FIXME: this parameter maybe should be related to some esp parameters (according to racoon source code)
	u_int16_t l_natt_frag = 0;
	/* Mappings from HIP to PFKEY algo names */
	u_int e_types[] = {SADB_EALG_NULL, SADB_X_EALG_AESCBC, SADB_EALG_3DESCBC, SADB_EALG_3DESCBC,
			   SADB_X_EALG_BLOWFISHCBC, SADB_EALG_NULL, SADB_EALG_NULL};
	u_int a_algos[] = {SADB_AALG_NONE, SADB_AALG_SHA1HMAC, SADB_AALG_SHA1HMAC, SADB_AALG_MD5HMAC,
			   SADB_AALG_SHA1HMAC, SADB_AALG_SHA1HMAC, SADB_AALG_MD5HMAC};
	u_int e_type = e_types[ealg];
	u_int a_type = a_algos[aalg];
	in_port_t sport = entry->local_udp_port;
	in_port_t dport = entry->peer_udp_port;

	a_keylen = hip_auth_key_length_esp(ealg);
	e_keylen = hip_enc_key_length(ealg);

	get_random_bytes(&reqid, sizeof(uint32_t));
	get_random_bytes(&seq, sizeof(uint32_t));

	HIP_DEBUG("\n");
	HIP_DEBUG_HIT("src_hit", src_hit);
	HIP_DEBUG_HIT("dst_hit", dst_hit);
	HIP_DEBUG_IN6ADDR("saddr", saddr);
	HIP_DEBUG_IN6ADDR("daddr", daddr);
	HIP_IFEL((!saddr || !daddr), 1, "Addresses not valid when adding SA's\n");

	HIP_IFEL(((so = pfkey_open()) < 0), 1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

	s_saddr = (struct sockaddr*) &ss_addr;
	d_saddr = (struct sockaddr*) &dd_addr;
	get_sock_addr_from_in6(s_saddr, saddr);
	get_sock_addr_from_in6(d_saddr, daddr);

	if (direction == HIP_SPI_DIRECTION_OUT)
	{
		entry->outbound_sa_count++;
	}
	else
	{
		entry->inbound_sa_count++;
	}


	// NOTE: port numbers remains in host representation
	if (update) {
		if (sport) {
			// pfkey_send_update_nat when update = 1 and sport != 0
			HIP_IFEBL(((len = pfkey_send_update_nat(so, SADB_SATYPE_ESP, HIP_IPSEC_DEFAULT_MODE, 
								s_saddr, d_saddr, spi, reqid, wsize,
								(void*) enckey, e_type, e_keylen, 
								a_type, a_keylen, flags,
								0, lifebyte, lifetime, 0, seq,
								l_natt_type, sport, dport, NULL,
								l_natt_frag)) < 0),
				  1, pfkey_close(so), "ERROR in updating sa for nat: %s\n", ipsec_strerror());
		} else {
			// pfkey_send_update when update = 1 and sport == 0
			HIP_IFEBL(((len = pfkey_send_update(so, SADB_SATYPE_ESP, HIP_IPSEC_DEFAULT_MODE,
							    s_saddr, d_saddr, spi, reqid, wsize,
							    (void*) enckey, e_type, e_keylen,
							    a_type, a_keylen, flags,
							    0, lifebyte, lifetime, 0, seq)) < 0),
				  1, pfkey_close(so), "ERROR in updating sa: %s\n", ipsec_strerror());
		}
	} else {
		if (sport) {
			// pfkey_send_add_nat when update = 0 and sport != 0 	
			HIP_IFEBL(((len = pfkey_send_add_nat(so, SADB_SATYPE_ESP, HIP_IPSEC_DEFAULT_MODE,
							     s_saddr, d_saddr, spi, reqid, wsize,
							     (void*) enckey, e_type, e_keylen, 
							     a_type, a_keylen, flags,
							     0, lifebyte, lifetime, 0, seq,
							     l_natt_type, sport, dport, NULL,
							     l_natt_frag)) < 0),
				  1, pfkey_close(so), "ERROR in adding sa for nat: %s\n", ipsec_strerror());
		} else {
			// pfkey_send_add when update = 0 and sport == 0
			HIP_IFEBL(((len = pfkey_send_add(so, SADB_SATYPE_ESP, HIP_IPSEC_DEFAULT_MODE,
							 s_saddr, d_saddr, spi, reqid, wsize,
							 (void*) enckey, e_type, e_keylen,
							 a_type, a_keylen, flags,
							 0, lifebyte, lifetime, 0, seq)) < 0),
				  1, pfkey_close(so), "ERROR in adding sa: %s\n", ipsec_strerror());
		}
	}

	return 0;

out_err:
	return err;
}

// This function fills in policy0 and policylen0 according to the given parameters
// The full implementation can be found in racoon
// direction IPSEC_DIR_INBOUND | IPSEC_DIR_OUTBOUND
int getsadbpolicy(caddr_t *policy0, int *policylen0, int direction,
		  struct sockaddr *src, struct sockaddr *dst, u_int mode, int cmd)
{
	struct sadb_x_policy *xpl;
	struct sadb_x_ipsecrequest *xisr;
	struct saproto *pr;
	caddr_t policy, p;
	int policylen;
	int xisrlen, src_len, dst_len;
	u_int satype;
	HIP_DEBUG("\n");
	/* get policy buffer size */
	policylen = sizeof(struct sadb_x_policy);
	if (cmd != SADB_X_SPDDELETE) {
		xisrlen = sizeof(*xisr);
		xisrlen += (sysdep_sa_len(src) + sysdep_sa_len(dst));
		policylen += PFKEY_ALIGN8(xisrlen);
	}

	/* make policy structure */
	policy = malloc(policylen);
	if (!policy) {
		HIP_ERROR("Cannot allocate memory for policy\n");
		return -ENOMEM;
	}

	xpl = (struct sadb_x_policy *)policy;
	xpl->sadb_x_policy_len = PFKEY_UNIT64(policylen);
	xpl->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
	xpl->sadb_x_policy_dir = direction;
	xpl->sadb_x_policy_id = 0;

	//xpl->sadb_x_policy_priority = PRIORITY_DEFAULT;

	if (cmd == SADB_X_SPDDELETE)
		goto end;

	xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);

	xisr->sadb_x_ipsecrequest_proto = SADB_SATYPE_ESP;
	xisr->sadb_x_ipsecrequest_mode = mode;
	xisr->sadb_x_ipsecrequest_level = IPSEC_LEVEL_REQUIRE;
	xisr->sadb_x_ipsecrequest_reqid = 0;
	p = (caddr_t)(xisr + 1);

	xisrlen = sizeof(*xisr);

	src_len = sysdep_sa_len(src);
	dst_len = sysdep_sa_len(dst);
	xisrlen += src_len + dst_len;

	memcpy(p, src, src_len);
	p += src_len;

	memcpy(p, dst, dst_len);
	p += dst_len;

	xisr->sadb_x_ipsecrequest_len = PFKEY_ALIGN8(xisrlen);
end:
	*policy0 = policy;
	*policylen0 = policylen;
	return 0;
}

int hip_pfkey_policy_modify(int so, hip_hit_t *src_hit, u_int prefs, 
			    hip_hit_t *dst_hit, u_int prefd,
			    struct in6_addr *src_addr, struct in6_addr *dst_addr,
			    u8 proto, int cmd, int direction)
{
	int err = 0;
	struct sockaddr_storage ss_addr, dd_addr, ss_hit, dd_hit;
	struct sockaddr *s_saddr, *s_shit;
	struct sockaddr *d_saddr, *d_shit;
	caddr_t policy = NULL;
	int policylen = 0;
	int len = 0;
	u_int mode;
	HIP_DEBUG("\n");
	// Sanity check
	HIP_IFEL((src_hit == NULL || dst_hit == NULL), -1, "Invalid hit's\n");

	if (src_addr) { // could happen with the delete
		s_saddr = (struct sockaddr*) &ss_addr;
		get_sock_addr_from_in6(s_saddr, src_addr);
	}

	if (dst_addr) { // could happen with the delete
		d_saddr = (struct sockaddr*) &dd_addr;
		get_sock_addr_from_in6(d_saddr, dst_addr);
	}

	s_shit = (struct sockaddr*) &ss_hit;
	get_sock_addr_from_in6(s_shit, src_hit);
	d_shit = (struct sockaddr*) &dd_hit;
	get_sock_addr_from_in6(d_shit, dst_hit);
	if (proto)
		mode = HIP_IPSEC_DEFAULT_MODE;
	else
		mode = IPSEC_MODE_TRANSPORT;

	HIP_IFEL((getsadbpolicy(&policy, &policylen, direction, s_saddr, d_saddr, mode, cmd)<0),
		 -1, "Error in building the policy\n");

	if (cmd == SADB_X_SPDUPDATE) {
		HIP_IFEL((len = pfkey_send_spdupdate(so, s_shit, prefs, d_shit, prefd,
						  proto, policy, policylen, 0)<0), -1,
			 "libipsec failed send_x4 (%s)\n", ipsec_strerror());
	} else if (cmd == SADB_X_SPDADD) {
		HIP_IFEL((len = pfkey_send_spdadd(so, s_shit, prefs, d_shit, prefd,
						  proto, policy, policylen, 0)<0), -1,
			 "libipsec failed send_x4 (%s)\n", ipsec_strerror());
	} else {  // SADB_X_SPDDELETE
		HIP_IFEL((len = pfkey_send_spddelete(so, s_shit, prefs, d_shit, prefd,
						  proto, policy, policylen, 0)<0), -1,
			 "libipsec failed send_x4 (%s)\n", ipsec_strerror());
	}

	return len;
out_err:
	return err;
}

int hip_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
			  struct in6_addr *src_addr,
			  struct in6_addr *dst_addr, u8 proto,
			  int use_full_prefix, int update)
{
	int so, len, err = 0;
	u_int prefs, prefd;
	u8 prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;
	int cmd = update ? SADB_X_SPDUPDATE : SADB_X_SPDADD;

	HIP_DEBUG("\n");
	HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

	HIP_DEBUG("Adding a pair of SP\n");

	HIP_IFEBL((hip_pfkey_policy_modify(so, dst_hit, prefix, src_hit, 
					   prefix, src_addr, dst_addr, 
					   proto, cmd, IPSEC_DIR_INBOUND)<0),
		  -1, pfkey_close(so), "ERROR in %s the inbound policy\n", update ? "updating" : "adding");

	HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

	HIP_IFEBL((hip_pfkey_policy_modify(so, src_hit, prefix, dst_hit, 
					   prefix, dst_addr, src_addr,
					   proto, cmd, IPSEC_DIR_OUTBOUND)<0),
		  -1, pfkey_close(so), "ERROR in %s the outbound policy\n", update ? "updating" : "adding");
	return 0;
out_err:
	return err;
}

void hip_delete_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
			    int use_full_prefix)
{
	int so, len, err = 0;
	u8 prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;

	HIP_DEBUG("\n");
	HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

	HIP_IFEBL((hip_pfkey_policy_modify(so, dst_hit, prefix, src_hit, 
					   prefix, NULL, NULL, 
					   proto, SADB_X_SPDDELETE, IPSEC_DIR_INBOUND)<0),
		  -1, pfkey_close(so), "ERROR in deleting the inbound policy\n");

	HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

	HIP_IFEBL((hip_pfkey_policy_modify(so, src_hit, prefix, dst_hit, 
					   prefix, NULL, NULL,
					   proto, SADB_X_SPDDELETE, IPSEC_DIR_OUTBOUND)<0),
		  -1, pfkey_close(so), "ERROR in deleting the outbound policy\n");
out_err:
	return;
}

void hip_delete_default_prefix_sp_pair()
{
	// Currently unused
	HIP_DEBUG("\n");
}

int hip_setup_default_sp_prefix_pair()
{
	// currently this function is not needed
	HIP_DEBUG("\n");
	return 0;
}

#endif /* CONFIG_HIP_PFKEY */

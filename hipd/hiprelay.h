/** @file
 * A header file for hiprelay.c.
 *
 * The HIP relay combines the functionalites of an rendezvous server (RVS) and
 * a HIP UDP relay. The HIP relay consists of a hashtable for storing IP address
 * to HIT mappings and of functions that do the actual relaying action. The
 * hashtable is based on lhash library and its functionalites are the same
 * except that the HIP relay stores data (allocated memory for relay records)
 * instead of pointers.
 *
 * A few simple rules apply:
 * <ul>
 * <li>Allocate memory for relay records that are to be put into the hashtable
 * only with hip_relrec_alloc().</li>
 * <li>Once a relay record is <b>successfully</b> put into the hashtable, the
 * only way delete it is to call hip_relht_rec_free(). This will remove the
 * entry from the hashtable and free the memory allocated for the relay record.
 * </li>
 * </ul>
 *
 * Usage:
 * <ul>
 * <li>Inserting a new relay record:
 * <pre>
 * hip_relrec_t rr = hip_relrec_alloc(...);
 * hip_relht_put(rr);
 * if(hip_relht_get(rr) == NULL) // The put was unsuccessful.
 * {
 *   if(rr != NULL)
 *     free(rr);
 * }
 * </pre>
 * </li>
 * <li>Fetching a relay record. We do not need (but can use) a fully populated
 * relay record as a search key. A dummy record with hit_r field populated
 * is sufficient. Note that there is no need to re-put the relay record into the
 * hashtable once it has been succesfully inserted into the hashtable - except
 * if we change the hit_r field of the relay record. If a relay record with same
 * HIT is put into the hashtable, the existing element is deleted.
 *
 * <pre>
 * hip_relrec_t dummy, *fetch_record = NULL;
 * memcpy(&(dummy.hit_r), hit, sizeof(hit));
 * fetch_record = hip_relht_get(&dummy);
 * if(fetch_record != NULL)
 * {
 * // Do something with the record.
 * }
 * </pre>
 * </li>
 * <li>Deleting a relay record. A dummy record can be used:
 * <pre>
 * hip_relrec_t dummy;
 * memcpy(&(dummy.hit_r), hit, sizeof(hit));
 * hip_relht_rec_free(&dummy);
 * </pre>
 * </li>
 * </ul>
 * 
 * @author  Lauri Silvennoinen
 * @version 1.1
 * @date    31.03.2008
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5204.txt">
 *          Host Identity Protocol (HIP) Rendezvous Extension</a>
 * @note    Related draft:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-nat-traversal-03.txt">
 *          draft-ietf-hip-nat-traversal-03</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_HIPRELAY_H
#define HIP_HIPRELAY_H

#include <time.h> /* For timing. */
#include <openssl/lhash.h> /* For LHASH. */
#include <netinet/in.h> /* For IPv6 addresses etc. */
#include <arpa/inet.h> /* For nthos() */
#include <math.h> /* For pow() */
#include "misc.h" /* For debuging macros. */
#include "registration.h" /* For lifetime conversions. */
#include "configfilereader.h"
#include "state.h"

/**
 * The minimum lifetime the relay / RVS client is granted the service. This
 * value is used as a 8-bit integer value. The lifetime value in seconds is
 * calculated using the formula given in RFC 5203.
 * @note this is a fallback value if we are not able to read the configuration
 *       file.
 */
#define HIP_RELREC_MIN_LIFETIME 112 // Equals 64 seconds.
/**
 * The maximum lifetime the relay / RVS client is granted the service. This
 * value is used as a 8-bit integer value. The lifetime value in seconds is
 * calculated using the formula given in RFC 5203.
 * @note this is a fallback value if we are not able to read the configuration
 *       file.
 */
#define HIP_RELREC_MAX_LIFETIME 159 // Equals 3756 seconds.
/** HIP relay config file name and path. */
#ifdef ANDROID_CHANGES
#define HIP_RELAY_CONFIG_FILE  "/data/hip/relay_config"
#else
#define HIP_RELAY_CONFIG_FILE  "/etc/hip/relay_config"
#endif
/** HIP relay config file default content. If the file @c HIP_RELAY_CONFIG_FILE
 *  cannot be opened for reading, we write a new config file from scratch using
 *  this content.
 *  @note @c HIP_RC_FILE_FORMAT_STRING must match the printf format of this
 *        string.
 */
#define HIP_RC_FILE_CONTENT \
"# HIP relay / RVS configuration file.\n"\
"#\n"\
"# This file consists of stanzas of the following form:\n"\
"# \n"\
"# parametername = \"value1\", \"value2\", ... \"valueN\"\n"\
"#\n"\
"# where there can be as many values as needed per line with the limitation of\n"\
"# total line length of ",HIP_RELAY_MAX_LINE_LEN," characters. The 'parametername' is at most ",HIP_RELAY_MAX_PAR_LEN,"\n"\
"# characters long and 'values' are at most ",HIP_RELAY_MAX_VAL_LEN," characters long. A value itself\n"\
"# may not contain a '",HIP_RELAY_VAL_SEP,"' character.\n"\
"#\n"\
"# The '",HIP_RELAY_COMMENT,"' character is used for comments. End of line comments are not allowed.\n"\
"\n"\
"# Relay whitelist status. When this is set to 'yes', only clients whose HIT is\n"\
"# listed on the whitelist are allowed to register to the relay / RVS service.\n"\
"# When this is set to 'no', any client is allowed to register. This defaults as\n"\
"# 'yes' when no value is given.\n"\
"whitelist_enabled = \"yes\"\n"\
"\n"\
"# Relay whitelist. The HITs of the clients that are allowed to register to\n"\
"# the relay / RVS service. You may use multiple stanzas of the same name.\n"\
"whitelist = \"\"\n"\
"\n"\
"# The minimum number of seconds the relay / RVS client is granted the service.\n"\
"# If the service request defines a value smaller than this value, this value is\n"\
"# used.\n"\
"minimum_lifetime = \"60\"\n"\
"\n"\
"# The maximum number of seconds the relay / RVS client is granted the service.\n"\
"# If the service request defines a value bigger than this value, this value is\n"\
"# used.\n"\
"maximum_lifetime = \"3600\"\n"
/** The printf format string of @c HIP_RC_FILE_CONTENT. */
#define HIP_RC_FILE_FORMAT_STRING "%s%d%s%d%s%d%s%c%s%c%s"

/** HIP Relay record. These records are stored in the HIP Relay hashtable. */
typedef struct{
	/** The type of this relay record (full relay or rvs) */
	uint8_t type;
	/** The lifetime of this record, seconds. */
        time_t lifetime;
	/** Time when this record was created, seconds since epoch. */
	time_t created;
	/** Time when this record was last used, seconds since epoch. */
	time_t last_contact;
	/** HIT of Responder (Relay Client) */
	hip_hit_t hit_r;
	/** IP address of Responder (Relay Client) */
	in6_addr_t ip_r;
	/** Client UDP port received in I2 packet of registration. */
	in_port_t udp_port_r;
	/** Integrity key established while registration occurred. */
	hip_crypto_key_t hmac_relay;
	/** Function pointer to send function (raw or udp). */
	hip_xmit_func_t send_fn;
}hip_relrec_t;

/** 
 * Relay record encapsulation modes used in a relay record. This mode is between
 * the Relay and the Responder.
 */
typedef enum{HIP_FULLRELAY = HIP_SERVICE_RELAY,
		     HIP_RVSRELAY = HIP_SERVICE_RENDEZVOUS}hip_relrec_type_t;
/** Possible states of the RVS / relay. */
typedef enum{HIP_RELAY_OFF = 0, HIP_RELAY_ON = 1}hip_relay_status_t;
/** Possible states of the whitelist. */
typedef enum{HIP_RELAY_WL_OFF = 0, HIP_RELAY_WL_ON = 1}hip_relay_wl_status_t;

/** 
 * Returns relay status.
 * 
 * @return HIP_RELAY_ON if the RVS / relay is "on", HIP_RELAY_OFF otherwise.
 */
hip_relay_status_t hip_relay_get_status();

/**
 * Sets the status of the RVS / relay. Sets the relay "on" or "off".
 *
 * @param status zero if the relay is to be disabled, anything else to enable
 *               the relay.
 */ 
void hip_relay_set_status(hip_relay_status_t status);

/**
 * Returns a hash calculated over a HIT.
 *
 * @param  hit a HIT value over which the hash is calculated.
 * @return a hash value.
 */
static inline unsigned long hip_hash_func(const hip_hit_t *hit)
{
	uint32_t bits_1st = 0;
	unsigned long hash = 0;

	/* HITs are of the form: 2001:001x:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
	   We have four groups of 32 bit sequences here, but the first 28 bits
	   are constant and have no hash value. Therefore, we create a new
	   replacement sequence for first 32 bit sequence. */
	   
	bits_1st = (~hit->s6_addr[3]) << 28;
	bits_1st |= hit->s6_addr[3] << 24;
	bits_1st |= hit->s6_addr[7] << 16;
	bits_1st |= hit->s6_addr[11] << 8;
	bits_1st |= hit->s6_addr[15];
		
	/* We calculate the hash by avalanching the bits. The avalanching
	   ensures that we make use of all bits when dealing with 64 bits
	   architectures. */
	hash =  (bits_1st ^ hit->s6_addr32[1]);
	hash ^= hash << 3;
	hash ^= (hit->s6_addr32[2] ^ hit->s6_addr32[3]);
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;
	
	return hash;
}

/**
 * Initializes the HIP relay / RVS. Initializes the HIP relay hashtable and
 * whitelist.
 */ 
int hip_relay_init();

/**
 * Uninitializes the HIP relay / RVS. Uninitializes the HIP relay hashtable and
 * whitelist.
 */ 
void hip_relay_uninit();

/**
 * Reinitializes the HIP relay / RVS. Deletes the old values from the relay
 * whitelist and reads new values from the configuration file
 * @c HIP_RELAY_CONFIG_FILE. Besides the whitelist values also every other
 * value read from the configuration file is reinitialized. These include the
 * lifetime values etc. However, the existing relay records are left as they
 * were. This means that the relay / RVS clients that have already registered
 * continue to be served as before - even if their HIT nomore exists in the
 * whitelist.
 *
 * @return zero if the configuration file was read succesfully, -1 otherwise.
 */
int hip_relay_reinit();

/**
 * Initializes the global HIP relay hashtable. Allocates memory for
 * @c hiprelay_ht.
 *
 * @return zero on success, -1 otherwise.
 * @note   do not call this function directly, instead call hip_relay_init().
 */ 
int hip_relht_init();

/** 
 * Uninitializes the HIP relay record hashtable @c hiprelay_ht. Frees the memory
 * allocated for the hashtable and for the relay records. Thus, after calling
 * this function, all memory allocated from the heap related to the relay record
 * hashtable is free.
 *
 * @note do not call this function directly, instead call hip_relay_uninit().
 */
void hip_relht_uninit();

/**
 * The hash function of the @c hiprelay_ht hashtable. Calculates a hash from
 * parameter relay record HIT.
 * 
 * @param rec a pointer to a relay record.
 * @return    the calculated hash or zero if @c rec or hit_r is NULL.
 */
unsigned long hip_relht_hash(const hip_relrec_t *rec);

/**
 * The compare function of the @c hiprelay_ht hashtable. Compares the hash
 * values calculated from parameters @c rec1 and @c rec2.
 * 
 * @param rec1 a pointer to a HIT.
 * @param rec2 a pointer to a HIT.
 * @return     0 if keys are equal and neither is NULL, non-zero otherwise.
 */
int hip_relht_compare(const hip_relrec_t *rec1, const hip_relrec_t *rec2);

/**
 * Puts a relay record into the hashtable. Puts the relay record pointed by
 * @c rec into the hashtable @c hiprelay_ht. If there already is an entry with
 * the same key the old value is replaced, and <b>the memory allocated for the
 * existing element is freed</b>. Note that we store pointers here, the data are
 * not copied. There should be no need to put a relay record more than once into
 * the hashtable. If the fields of an individual relay record need to be
 * changed, just retrieve the record with @c hip_relht_get() and alter the
 * fields of it, but do not re-put it into the hashtable.
 *
 * @param rec a pointer to a relay record to be inserted into the hashtable.
 * @return    -1 if there was a hash collision i.e. an entry with duplicate HIT
 *            is inserted, zero otherwise.
 * @note      <b style="color: #f00;">Do not put records allocated from stack
 *            into the hashtable.</b> Instead put only records created with
 *            hip_relrec_alloc().
 * @note      In case of a hash collision, the existing relay record is freed.
 *            If you store references to relay records that are in the hashtable
 *            elsewhere outside the hashtable, NULL pointers can result.
 */
int hip_relht_put(hip_relrec_t *rec);

/**
 * Retrieves a relay record from the hashtable @c hiprelay_ht. The parameter
 * record @c rec only needs to have field @c hit_r populated.
 *
 * @param rec a pointer to a relay record.
 * @return    a pointer to a fully populated relay record if found, NULL
 *            otherwise.
 */
hip_relrec_t *hip_relht_get(const hip_relrec_t *rec);

/**
 * Deletes a single entry from the relay record hashtable and frees the memory
 * allocated for the element. The deletion is based on the hash calculated from
 * the relay fecord @c hit_r field, and therefore the parameter record does not
 * need to be fully populated. If the parameter relay record is the same record
 * that is being deleted (i.e. is located in the same memory location) then
 * the parameter @c rec itself is freed. If a dummy record is used (i.e. is
 * located in a different memory location thatn the hashtable entry), then
 * @c rec is left untouched.
 *
 * @param rec a pointer to a relay record. 
 */
void hip_relht_rec_free(hip_relrec_t *rec);

/**
 * Deletes a single entry from the relay record hashtable and frees the memory
 * allocated for the record, if the record has expired. The relay record is
 * deleted if it has been last contacted more than @c hiprelay_lifetime seconds
 * ago. If the parameter relay record is the same record that is being deleted
 * (i.e. is located in the same memory location) then the parameter @c rec
 * itself is freed. If a dummy record is used (i.e. is located in a different
 * memory location thatn the hashtable entry), then @c rec is left untouched.
 *
 * @param rec a pointer to a relay record.
 */
void hip_relht_rec_free_expired(hip_relrec_t *rec);

/**
 * Deletes a single entry from the relay record hashtable and frees the memory
 * allocated for the element if the matching element's type is of @c type. The
 * deletion is based on the hash calculated from the relay fecord
 * @c hit_r field, and therefore the parameter record does not need to be fully
 * populated. If the parameter relay record is the same record that is being
 * deleted (i.e. is located in the same memory location) then the parameter
 * @c rec itself is freed. If a dummy record is used (i.e. is located in a
 * different memory location thatn the hashtable entry), then @c rec is left
 * untouched.
 *
 * @param rec a pointer to a relay record. 
 */ 
void hip_relht_rec_free_type(hip_relrec_t *rec, const hip_relrec_type_t *type);

/**
 * Returns the number of relay records in the hashtable @c hiprelay_ht.
 * 
 * @return  number of relay records in the hashtable.
 */
unsigned long hip_relht_size();

/**
 * Periodic maintenance function of the hip relay. This function should be
 * called once in every maintenance cycle of the hip daemon. It clears the
 * expired relay records by calling @c hip_relht_rec_free_expired() for every
 * element in the hashtable.
 * @todo a REG_RESPONSE with zero lifetime should be sent to each client whose
 *       registration is cancelled.
 */
void hip_relht_maintenance();

/**
 * Allocates a new relay record.
 * 
 * @param type     the type of this relay record (HIP_FULLRELAY or
 *                 HIP_RVSRELAY).
 * @param lifetime the lifetime of this relayrecord as defined in registration
 *                 draft.
 * @param hit_r    a pointer to Responder (relay client) HIT.
 * @param ip_r     a pointer to Responder (relay client) IP address.
 * @param port     responder's UDP port.
 * @return         a pointer to a new relay record, or NULL if failed to
 *                 allocate.
 * @note           All records to be put in the hashtable should be created with
 *                 this function.
 */
hip_relrec_t *hip_relrec_alloc(const hip_relrec_type_t type,
			       const uint8_t lifetime,
			       const in6_addr_t *hit_r, const hip_hit_t *ip_r,
			       const in_port_t port,
			       const hip_crypto_key_t *hmac,
			       const hip_xmit_func_t func);

/**
 * Deletes all entries of @c type from the relay record hashtable and frees the
 * memory allocated for the deleted elements.
 *
 * @param type the type of the records to be deleted.
 */
void hip_relht_free_all_of_type(const hip_relrec_type_t type);

/**
 * Sets the mode of a relay record. This function sets the @c flags field of a
 * relay record.
 * 
 * @param rec  a pointer to a relay record. 
 * @param mode the mode to be set for the parameter record. One of the following:
 *             <ul>
 *             <li>HIP_REL_NONE</li>
 *             <li>HIP_REL_UDP</li>
 *             <li>HIP_REL_TCP</li>
 *             </ul>
 * @see        hip_relrec_t for a bitmap.
 */
void hip_relrec_set_mode(hip_relrec_t *rec, const hip_relrec_type_t type);

/**
 * Sets the lifetime of a relay record.
 * The service lifetime is set to 2^((lifetime - 64)/8) seconds.
 * 
 * @param rec      a pointer to a relay record. 
 * @param lifetime the lifetime of the above formula. 
 */
void hip_relrec_set_lifetime(hip_relrec_t *rec, const uint8_t lifetime);

/**
 * Sets the UDP port number of a relay record. 
 * 
 * @param rec  a pointer to a relay record. 
 * @param port UDP port number. 
 */
void hip_relrec_set_udpport(hip_relrec_t *rec, const in_port_t port);

/**
 * Prints info of the parameter relay record using @c HIP_INFO() macro.
 * 
 * @param rec a pointer to a relay record.
 */
void hip_relrec_info(const hip_relrec_t *rec);

/**
 * Initializes the global HIP relay whitelist. Allocates memory for
 * @c hiprelay_wl.
 *
 * @return zero on success, -1 otherwise.
 * @note   do not call this function directly, instead call hip_relay_init().
 */ 
int hip_relwl_init();

/** 
 * Uninitializes the HIP relay whitelist hashtable @c hiprelay_wl. Frees the
 * memory allocated for the hashtable and for the HITs. Thus, after calling
 * this function, all memory allocated from the heap related to the whitelist
 * is free.
 *
 * @note do not call this function directly, instead call hip_relay_uninit().
 */
void hip_relwl_uninit();

/**
 * The hash function of the @c hiprelay_wl hashtable. Calculates a hash from
 * parameter HIT.
 * 
 * @param hit a pointer to a HIT.
 * @return    the calculated hash or zero if @c hit is NULL.
 */
unsigned long hip_relwl_hash(const hip_hit_t *hit);

/**
 * The compare function of the @c hiprelay_wl hashtable. Compares the hash
 * values calculated from parameter @c hit1 and @c hit2.
 * 
 * @param hit1 a pointer to a HIT.
 * @param hit2 a pointer to a HIT.
 * @return     0 if keys are equal and neither is NULL, non-zero otherwise.
 */
int hip_relwl_compare(const hip_hit_t *hit1, const hip_hit_t *hit2);

/**
 * Puts a HIT into the whitelist. Puts the HIT pointed by @c hit into the
 * whitelist hashtable @c hiprelay_wl. If there already is an entry with the
 * same HIT, the old value is replaced, and <b>the memory allocated for the
 * existing element is freed</b>. Note that we store pointers here, the data are
 * not copied.
 *
 * @param hit a pointer to a HIT to be inserted into the whitelist.
 * @return    -1 if there was a hash collision i.e. a duplicate HIT is inserted,
 *            zero otherwise.
 * @note      <b style="color: #f00;">Do not put HITs allocated from the stack
 *            into the whitelist.</b> Instead put only HITs created with
 *            malloc().
 * @note      In case of a hash collision, the existing HIT is freed. If you
 *            store references to HITs that are in the whitelist elsewhere
 *            outside the whitelist, NULL pointers can result.
 */
int hip_relwl_put(hip_hit_t *hit);

/**
 * Retrieves a HIT from the hashtable @c hiprelay_wl.
 *
 * @param hit a pointer to a HIT.
 * @return    a pointer to a matching HIT, NULL otherwise.
 */
hip_hit_t *hip_relwl_get(const hip_hit_t *hit);

/**
 * Returns the number of HITs in the hashtable @c hiprelay_wl.
 * 
 * @return  number of HITs in the hashtable.
 */
unsigned long hip_relwl_size();

/**
 * Deletes a single entry from the whitelist hashtable and frees the memory
 * allocated for the element. The parameter HIT is itself left untouched, it is
 * only used as an search key.
 *
 * @param hit a pointer to a HIT. 
 */
void hip_relwl_hit_free(hip_hit_t *hit);

/**
 * Returns the whitelist status.
 *
 * @return HIP_RELAY_ON if the RVS / relay whitelist is "on", HIP_RELAY_OFF
 *         otherwise.
 */ 
hip_relay_wl_status_t hip_relwl_get_status();

/**
 * Validates a requested RVS service lifetime. If
 * @c requested_lifetime is smaller than @c hiprelay_min_lifetime then
 * @c granted_lifetime is set to @c hiprelay_min_lifetime. If
 * @c requested_lifetime is greater than @c hiprelay_max_lifetime then
 * @c granted_lifetime is set to @c hiprelay_max_lifetime. Else
 * @c granted_lifetime is set to @c requested_lifetime.
 *
 * @param  requested_lifetime the lifetime that is to be validated.
 * @param  granted_lifetime   a target buffer for the validated lifetime.
 * @return                    -1 if @c requested_lifetime is outside boundaries,
 *                            i.e. is smaller than @c hiprelay_min_lifetime or
 *                            is greater than @c hiprelay_max_lifetime. Zero
 *                            otherwise.
 */ 
int hip_rvs_validate_lifetime(uint8_t requested_lifetime,
			      uint8_t *granted_lifetime);

/**
 * Validates a requested HIP relay service lifetime. If
 * @c requested_lifetime is smaller than @c hiprelay_min_lifetime then
 * @c granted_lifetime is set to @c hiprelay_min_lifetime. If
 * @c requested_lifetime is greater than @c hiprelay_max_lifetime then
 * @c granted_lifetime is set to @c hiprelay_max_lifetime. Else
 * @c granted_lifetime is set to @c requested_lifetime.
 *
 * @param  requested_lifetime the lifetime that is to be validated.
 * @param  granted_lifetime   a target buffer for the validated lifetime.
 * @return                    -1 if @c requested_lifetime is outside boundaries,
 *                            i.e. is smaller than @c hiprelay_min_lifetime or
 *                            is greater than @c hiprelay_max_lifetime. Zero
 *                            otherwise.
 * @note                      Currently this is just a call back wrapper for
 *                            hip_rvs_validate_lifetime() because RVS and relay
 *                            services share the same lifetimes. 
 */
static inline int hip_relay_validate_lifetime(uint8_t requested_lifetime,
					      uint8_t *granted_lifetime)
{
	return hip_rvs_validate_lifetime(requested_lifetime,
					 granted_lifetime);
}

/**
 * Relays an incoming I1 packet.
 *
 * This function relays an incoming I1 packet to the next node on path
 * to receiver and inserts a @c FROM parameter encapsulating the source IP
 * address. In case there is a NAT between the sender (the initiator or previous
 * RVS) of the I1 packet, a @c RELAY_FROM parameter is inserted instead of a
 * @c FROM parameter. Next node on path is typically the responder, but if the
 * message is to travel multiple rendezvous servers en route to responder, next
 * node can also be another rendezvous server. In this case the @c FROM
 * (@c RELAY_FROM) parameter is appended after the existing ones. Thus current RVS
 * appends the address of previous RVS and the final RVS (n) in the RVS chain
 * sends @c FROM:I, @c FROM:RVS1, ... , <code>FROM:RVS(n-1)</code>. If initiator
 * is located behind a NAT, the first @c FROM parameter is replaced with a
 * @c RELAY_FROM parameter.
 * 
 * @param i1       a pointer to the I1 HIP packet common header with source and
 *                 destination HITs.
 * @param i1_saddr a pointer to the source address from where the I1 packet was
 *                 received.
 * @param i1_daddr a pointer to the destination address where the I1 packet was
 *                 sent to (own address).
 * @param rec      a pointer to a relay record matching the HIT of Responder.
 * @param i1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @note           This code has not been tested thoroughly with multiple RVSes.
 * @note           This function is a copy-paste from the previous RVS
 *                 implementation
 */
int hip_relay_rvs(const hip_common_t *i1,
		  const in6_addr_t *i1_saddr,
		  const in6_addr_t *i1_daddr, hip_relrec_t *rec,
		  const hip_portpair_t *i1_info);

/**
 * Handles a FROM/RELAY_FROM parameter.
 *
 * Checks if the parameter @c source_msg message has a FROM/RELAY_FROM
 * parameter. If a parameter is found, the values are copied to target buffers
 * @c dest_ip and @c dest_port. Next the hmac in RVS_HMAC is verified using
 * the host association created during registration. This host association
 * is searched using hitr from @c source_msg and @c rvs_ip as search keys. 
 *
 * @param  source_msg a pointer to the I1 HIP packet common header with source
 *                    and destination HITs.
 * @param rvs_ip      a pointer to the source address from where the I1 packet
 *                    was received.
 * @param dest_ip     a target buffer for the IP address in the FROM/RELAY_FROM
 *                    parameter.
 * @param dest_port   a target buffer for the port number in RELAY_FROM
 *                    parameter.
 * @return            zero 
 */ 

int hip_relay_handle_from(hip_common_t *source_msg,
			  in6_addr_t *rvs_ip,
			  in6_addr_t *dest_ip, in_port_t *dest_port);


/**
 * Reads RVS / HIP Relay configuration from a file. Reads configuration
 * information from @c HIP_RELAY_CONFIG_FILE. 
 *
 * @return zero on success, -ENOENT if the file could not be opened for reading.
 * @note   The white list @c hiprelay_wl must be initialized before this
 *         function is called.
 */ 
int hip_relay_read_config();

/**
 * Writes RVS / HIP Relay configuration file with default content. Writes a RVS
 * / HIP Relay configuration file to @c HIP_RELAY_CONFIG_FILE. The file is
 * opened with "w" argument mode, which means that a possibly existing file is
 * truncated to zero length.
 *
 * @return zero on success, -ENOENT if the file could not be opened for writing.
 * @note   Truncates existing file to zero length.
 */ 
int hip_relay_write_config();

/**
 * function for full relay service. from I to R
 *
 */
int hip_relay_forward_I(const hip_common_t *i1,
			const in6_addr_t *i1_saddr,
			const in6_addr_t *i1_daddr, hip_relrec_t *rec,
			const hip_portpair_t *i1_info,
			const uint8_t);

int hip_relay_forward_response(const hip_common_t *r,
			       const uint8_t type_hdr, 
			       const in6_addr_t *r_saddr,
			       const in6_addr_t *r_daddr , 
			       const hip_portpair_t *r_info , 
			       const in6_addr_t *relay_to_addr,
			       const in_port_t relay_to_port);

#endif /* HIP_HIPRELAY_H */

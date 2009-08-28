/** @file
 * A header file for update.c.
 *
 * @author  Mika Kousa <mkousa#iki.fi>
 * @author  Tobias Heer <tobi#tobibox.de>
 * @author  Abhijit Bagri <abagri#gmail.com>
 * @author  Miika Komu <miika#iki.fi>
 * @version 1.0
 * @date    08.01.2008
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note    Based on
 *          <a href="http://www1.ietf.org/mail-archive/web/hipsec/current/msg01745.html">Simplified state machine</a>
 */
#ifndef HIP_UPDATE_H
#define HIP_UPDATE_H

#include "builder.h"
#include "hadb.h"
#include "escrow.h"
#include "esp_prot_hipd_msg.h"

/* FIXME: where to include these from in userspace? */
#define IPV6_ADDR_ANY           0x0000U
#define IPV6_ADDR_UNICAST       0x0001U
#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U

/** The NAT status of the HIP daemon. I.e. Do we send packets on UPD or not. */
extern hip_transform_suite_t hip_nat_status;
/** @todo describe this variable. */
extern int is_active_handover;

/** A Really ugly hack ripped from rea.c, must convert to list_head asap. */
struct hip_update_kludge {
	hip_ha_t **array;
	int count;
	int length;
};

void empty_oppipdb();

/**
 * Iterate a list of locators using a function. The list handling is interrupted
 * if the give function returns an error.
 *
 * @param func    a function pointer to ...
 * @param entry   a pointer to a host association.
 * @param locator a pointer to ...
 * @param opaque  a pointer to ...
 * @return        zero on success or non-zero on error.
 */
int hip_for_each_locator_addr_item(int (*func)
				   (hip_ha_t *entry,
				    struct hip_locator_info_addr_item *i,
				    void *opaq), hip_ha_t *entry,
                                   struct hip_locator *locator, void *opaque);
/**
 * Function Doxygen comments missing.
 *
 * @param func    a function pointer to ...
 * @param entry   a pointer to a host association.
 * @param spi_out a pointer to ...
 * @param opaque  a pointer to ...
 * @return        zero on success or non-zero on error.
 */
int hip_update_for_each_peer_addr(int (*func)
				  (hip_ha_t *entry,
				   struct hip_peer_addr_list_item *list_item,
				   struct hip_spi_out_item *spi_out,
				   void *opaq), hip_ha_t *entry,
                                  struct hip_spi_out_item *spi_out, void *opaq);
/**
 * Function Doxygen comments missing.
 *
 * @param func   a function pointer to ...
 * @param entry  a pointer to a host association.
 * @param spi_in a pointer to ...
 * @param opaque a pointer to ...
 * @return       zero on success or non-zero on error.
 */
int hip_update_for_each_local_addr(int (*func)
				   (hip_ha_t *entry,
				    struct hip_spi_in_item *spi_in,
				    void *opaq), hip_ha_t *entry,
                                   void *opaq);
/**
 * Gets the keys needed by UPDATE.
 *
 * On success, all encryption and integrity keys are successfully stored and
 * @c keymat_offset_new, @c calc_index_new, and @c Kn_out will contain
 * updated values.
 *
 * @param entry             corresponding hadb entry of the peer.
 * @param keymat_offset_new value-result parameter for keymat index used.
 * @param calc_index_new    value-result parameter for the one byte index used.
 * @param Kn_out            value-result parameter for keymat.
 * @param espkey_gl         HIP-gl encryption key.
 * @param authkey_gl        HIP-gl integrity (HMAC).
 * @param espkey_lg         HIP-lg encryption key.
 * @param authkey_lg        HIP-lg integrity (HMAC).
 * @return                  0 on success and < 0 on error.
 */
int hip_update_get_sa_keys(hip_ha_t *entry, uint16_t *keymat_offset_new,
			   uint8_t *calc_index_new, uint8_t *Kn_out,
			   struct hip_crypto_key *espkey_gl,
			   struct hip_crypto_key *authkey_gl,
			   struct hip_crypto_key *espkey_lg,
			   struct hip_crypto_key *authkey_lg);
/**
 * Tests if IPv6 address is to be added into locator.
 *
 * Currently the following address types are ignored: unspecified (any),
 * loopback, link local, site local, and other not unicast addresses.
 *
 * @param addr the IPv6 address to be tested.
 * @return     1 if address is ok to be used as a peer address, otherwise 0.
 */
int hip_update_test_locator_addr(in6_addr_t *addr);

/**
 * Function Doxygen comments missing.
 *
 * @param entry a pointer to a host association.
 * @param locator_address_item a pointer to ...
 * @param _spi a pointer to ...
 * @return ...
 */
int hip_update_add_peer_addr_item(hip_ha_t *entry,
				  struct hip_locator_info_addr_item *locator_address_item,
				  void *_spi);

/**
 * Compares two locators for equality.
 *
 * @param unused a pointer to ...
 * @param item1  a pointer to the first item to compare.
 * @param item2  a pointer to the second item to compare.
 * @return       non-zero when address are equal, otherwise zero.
 */
int hip_update_locator_match(hip_ha_t *unused,
			     struct hip_locator_info_addr_item *item1,
			     void *_item2);

/**
 * Compares a locator and an addr list item for equality.
 *
 * @param unused a pointer to ...
 * @param item1  a pointer to the first item to compare.
 * @param item2  a pointer to the second item to compare.
 * @return       non-zero when address are equal, otherwise zero.
 */
int hip_update_locator_item_match(hip_ha_t *unused,
				  struct hip_locator_info_addr_item *item1,
				  void *_item2);

/**
 * Checks if a locator list contains a given locator.
 *
 * @param locator a pointer to a HIP LOCATOR.
 * @param item    a pointer to an item to search for.
 * @return        zero if the locator was found, otherwise non-zero.
 */
int hip_update_locator_contains_item(struct hip_locator *locator,
				     struct hip_peer_addr_list_item *item);

/**
 * Function Doxygen comments missing.
 *
 * @param entry     a pointer to a host association.
 * @param list_item a pointer to ...
 * @param spi_out   a pointer to ...
 * @param locator   a pointer to a HIP LOCATOR.
 * @return          zero if the locator was found, otherwise non-zero.
 */
int hip_update_deprecate_unlisted(hip_ha_t *entry,
				  struct hip_peer_addr_list_item *list_item,
				  struct hip_spi_out_item *spi_out,
				  void *_locator);

/**
 * Function Doxygen comments missing.
 *
 * @param entry     a pointer to a host association.
 * @param list_item a pointer to ...
 * @param spi_out   a pointer to ...
 * @param pref      a pointer to ...
 * @return          ...
 */
int hip_update_set_preferred(hip_ha_t *entry,
			     struct hip_peer_addr_list_item *list_item,
			     struct hip_spi_out_item *spi_out,
			     void *pref);

/**
 * Processes locator parameters in the UPDATE message.
 *
 * @param entry    a pointer to corresponding hadb entry of the peer.
 * @param locator  a pointer to the locator parameter in the packet.
 * @param esp_info a pointer to ...
 *
 * @note   @c entry must be is locked when this function is called.
 * @return 0 if the locator parameter was processed successfully, otherwise < 0.
 */
int hip_update_handle_locator_parameter(hip_ha_t *entry,
					struct hip_locator *locator,
					struct hip_esp_info *esp_info);

/**
 * @brief Handles an incoming UPDATE packet received in ESTABLISHED state.
 *
 * This function handles case 7 in section 8.11 Processing UPDATE packets in
 * state ESTABLISHED of the base draft.
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to a HIP packet.
 * @param src_ip source IPv6 address from where the UPDATE was sent.
 * @param dst_ip destination IPv6 address to which the UPDATE was sent.
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_handle_update_established(hip_ha_t *entry, hip_common_t *msg,
				  in6_addr_t *src_ip, in6_addr_t *dst_ip,
				  hip_portpair_t *update_info);

/**
 * Finishes the handling of REKEYING state.
 *
 * Performs items described in 8.11.3 Leaving REKEYING state of he base
 * draft-01. Parameters in @c esp_info are host byte order. On success new IPsec
 * SAs are created. Old SAs are deleted if the UPDATE was not the multihoming
 * case.
 *
 * @param  msg      a pointer to the HIP packet.
 * @param  entry    a pointer to an hadb entry corresponding to the peer.
 * @param  esp_info the ESP_INFO param to be handled in the received UPDATE.
 * @return          0 if successful, otherwise <0.
 * @note            @c entry must be is locked when this function is called.
 */
int hip_update_finish_rekeying(hip_common_t *msg, hip_ha_t *entry,
			       struct hip_esp_info *esp_info);

/**
 * Function Doxygen comments missing.
 *
 * @param  entry a pointer to an hadb entry corresponding to the peer.
 * @param  item  a pointer to ...
 * @param  msg   a pointer to ...
 * @return       ...
 */
int hip_update_do_finish_rekey(hip_ha_t *entry,
			       struct hip_spi_in_item *item,
			       void *_msg);

/**
 * Handles an incoming UPDATE packet received in REKEYING state.
 *
 * This function handles case 8 in section 8.11 Processing UPDATE
 * packets of the base draft.
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to a the HIP packet.
 * @param src_ip a pointer to the source IPv6 address from where the UPDATE
 *               was sent.
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_handle_update_rekeying(hip_ha_t *entry, hip_common_t *msg,
			       in6_addr_t *src_ip);

/**
 * Builds a verification packet.
 *
 * @param entry a pointer to a hadb entry.
 * @param msg   a pointer to a HIP UPDATE packet to be build.
 * @param addr  a pointer to ...
 * @param hits  a pointer to source HIT.
 * @param hits  a pointer to destination HIT.
 * @return      ...
 */
int hip_build_verification_pkt(hip_ha_t *entry, hip_common_t *update_packet,
			       struct hip_peer_addr_list_item *addr,
			       in6_addr_t *hits, in6_addr_t *hitr);

/**
 * Function Doxygen comments missing.
 *
 * @param entry   a pointer to a hadb entry.
 * @param addr    a pointer to ...
 * @param spi_out a pointer to ...
 * @param saddr   a pointer to ...
 * @return      ...
 */
int hip_update_send_addr_verify_packet(hip_ha_t *entry,
				       struct hip_peer_addr_list_item *addr,
				       struct hip_spi_out_item *spi_out,
				       void *saddr);
/**
 * Function Doxygen comments missing.
 *
 * @param entry                   a pointer to a hadb entry.
 * @param addr                    a pointer to ...
 * @param spi_out                 a pointer to ...
 * @param src_ip                  a pointer to ...
 * @param verify_active_addresses ...
 * @return      ...
 */
int hip_update_send_addr_verify_packet_all(hip_ha_t *entry,
					   struct hip_peer_addr_list_item *addr,
					   struct hip_spi_out_item *spi_out,
					   in6_addr_t *src_ip,
					   int verify_active_addresses);

/**
 * Sends address verification UPDATE.
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to the HIP packet.
 * @param src_ip source IPv6 address to use in the UPDATE to be sent out
 * @param spi    outbound SPI in host byte order
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_update_send_addr_verify(hip_ha_t *entry, hip_common_t *msg,
				in6_addr_t *src_ip, uint32_t spi);

/**
 * Function Doxygen comments missing.
 *
 * @param entry  a pointer to a hadb.
 * @param item   a pointer to ...
 * @param opaque a pointer to ...
 * @return       ...
 */
int hip_update_find_address_match(hip_ha_t *entry,
				  struct hip_locator_info_addr_item *item,
				  void *opaque);
/**
 * Function Doxygen comments missing.
 *
 * @param peer_ip a pointer to ...
 * @param locator a pointer to ...
 * @return        ...
 */
int hip_update_check_simple_nat(in6_addr_t *peer_ip,
				struct hip_locator *locator);
/**
 * Handles UPDATE(LOCATOR, SEQ).
 *
 * For each address in the LOCATOR, we reply with ACK and
 * UPDATE(SPI, SEQ, ACK, ECHO_REQUEST).
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to the HIP packet.
 * @param src_ip a pointer to the source IPv6 address to use in the UPDATE to be
 *               sent out.
 * @param dst_ip a pointer to the destination IPv6 address to use in the UPDATE
 *               to be sent out.
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_handle_update_plain_locator(hip_ha_t *entry, hip_common_t *msg,
				    in6_addr_t *src_ip, in6_addr_t *dst_ip,
				    struct hip_esp_info *esp_info,
				    struct hip_seq *seq);
/**
 * Function Doxygen comments missing.
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param src_ip source IPv6 address to use in the UPDATE to be sent out
 * @return       ...
 */
int set_address_state(hip_ha_t *entry, in6_addr_t *src_ip);

/**
 * Handles address verification UPDATE.
 *
 * Handles UPDATE(SPI, SEQ, ACK, ECHO_REQUEST) or UPDATE(SPI, SEQ,
 * ECHO_REQUEST).
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to a the HIP packet.
 * @param src_ip a pointer to a source IPv6 address to use in the UPDATE to be
 *               sent out.
 * @param dst_ip a pointer to a destination IPv6 address to use in the UPDATE
 *               to be sent out.
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_handle_update_addr_verify(hip_ha_t *entry, hip_common_t *msg,
				  in6_addr_t *src_ip, in6_addr_t *dst_ip);

/**
 * Function Doxygen comments missing.
 *
 * @param entry a pointer to a hadb entry.
 * @param msg   a pointer to a HIP message.
 * @return       ...
 */
int hip_handle_update_seq(hip_ha_t *entry, hip_common_t *msg);

/**
 * Function Doxygen comments missing.
 *
 * @param entry    a pointer to a hadb entry.
 * @param esp_info a pointer to ...
 * @return         ...
 */
int hip_set_rekeying_state(hip_ha_t *entry,
			   struct hip_esp_info *esp_info);

/**
 * Function Doxygen comments missing.
 *
 * @param msg   a pointer to a HIP message.
 * @param entry a pointer to a hadb entry.
 * @return      ...
 */
int hip_handle_esp_info(hip_common_t *msg, hip_ha_t *entry);

#ifdef CONFIG_HIP_ESCROW
/**
 * Function Doxygen comments missing.
 *
 * @param entry a pointer to a hadb entry.
 * @param keys  a pointer to ...
 * @return      ...
 */
int hip_handle_escrow_parameter(hip_ha_t * entry, struct hip_keys * keys);
#endif //CONFIG_HIP_ESCROW

/**
 * Function Doxygen comments missing.
 *
 * @param entry a pointer to a hadb entry.
 * @param enc   a pointer to ...
 * @return      ...
 */
int hip_handle_encrypted(hip_ha_t *entry, struct hip_tlv_common *enc);

/**
 * Function Doxygen comments missing.
 *
 * @param entry  a pointer to a hadb entry.
 * @param addr   a pointer to ...
 * @param spi_in a pointer to ...
 * @return       ...
 */
int hip_update_peer_preferred_address(hip_ha_t *entry,
				      struct hip_peer_addr_list_item *addr,
				      uint32_t spi_in);

/**
 * Function Doxygen comments missing.
 *
 * @param entry     a pointer to a hadb entry.
 * @param echo_resp a pointer to ...
 * @param src_ip    a pointer to ...
 * @return          ...
 */
int hip_update_handle_echo_response(hip_ha_t *entry,
				    struct hip_echo_response *echo_resp,
                                    in6_addr_t *src_ip);

/**
 * @addtogroup receive_functions
 * @{
 */
/**
 * @brief Receives an UPDATE packet.
 *
 * This is the initial function which is called when an UPDATE packet is
 * received. The UPDATE packet is only processed when the HIP state machine is
 * in state ESTABLISHED (see section 6.12. Receiving UPDATE Packets of RFC
 * 5201). However, if the state machine is in state R2-SENT and an UPDATE is
 * received, the state machine should move to state ESTABLISHED (see table 5
 * under section 4.4.2. HIP State Processes). Therefore this function processes
 * the received UPDATE packet in both of the states, R2-sent and ESTABLISHED.
 * When received in state R2-SENT, we move to state ESTABLISHED as instructed in
 * RFC 5201.
 *
 * If there is no corresponding HIP association (@c entry is NULL) or if the
 * state machine is in any other state than R2-SENT or ESTABLISHED the packet is
 * not processed and -1 is returned.
 *
 * The validity of the packet is checked and then this function acts
 * according to whether this packet is a reply or not.
 *
 * @param msg          a pointer to a HIP packet.
 * @param update_saddr a pointer to the UPDATE packet source IP address.
 * @param update_daddr a pointer to the UPDATE packet destination IP address.
 * @param entry        a pointer to a hadb entry.
 * @param sinfo        a pointer to a structure containing the UPDATE packet
 *                     source and destination ports.
 * @return             0 if successful (HMAC and signature (if needed) are
 *                     validated, and the rest of the packet is handled if
 *                     current state allows it), otherwise < 0.
 */
int hip_receive_update(hip_common_t *msg, in6_addr_t *update_saddr,
		       in6_addr_t *update_daddr, hip_ha_t *entry,
		       hip_portpair_t *sinfo);
/* @} */

/**
 * Copies addresses to the inbound SPI.
 *
 * A simple helper function to copy interface addresses to the inbound SPI of.
 * Caller must kfree the allocated memory.
 *
 * @param src    A pointer to an address list.
 * @param spi_in A pointer to the inbound SPI the addresses are copied to.
 * @param count  The number of addresses in @c src.
 * @return       0 on success, < 0 otherwise.
 */
int hip_copy_spi_in_addresses(struct hip_locator_info_addr_item *src,
			      struct hip_spi_in_item *spi_in, int count);

/**
 * Changes the preferred address advertised to the peer for this connection.
 *
 * @param entry         a pointer to a hadb entry corresponding to the peer.
 * @param new_pref_addr a pointer to the new prefferred address.
 * @param daddr         a pointer to destination address.
 * @param _spi_in       a pointer to ...
 * @return              ...
 */
int hip_update_preferred_address(struct hip_hadb_state *entry,
				 in6_addr_t *new_pref_addr, in6_addr_t *daddr,
				 uint32_t *_spi_in);

/**
 * Updates the source address list.
 *
 * @param entry            a pointer to a hadb entry.
 * @param addr_list        a pointer to ...
 * @param daddr            a pointer to ...
 * @param addr_count       address count.
 * @param esp_info_old_spi ...
 * @param is_add           ...
 * @param addr             ...
 * @return                 ...
 */
int hip_update_src_address_list(struct hip_hadb_state *entry,
				struct hip_locator_info_addr_item *addr_list,
				in6_addr_t *daddr, int addr_count,
				int esp_info_old_spi, int is_add,
				struct sockaddr* addr);

/**
 * Sends an initial UPDATE packet to the peer.
 *
 * @param entry      a pointer to a hadb entry corresponding to the peer.
 * @param addr_list  a pointer to an address list. if non-NULL, LOCATOR
 *                   parameter is added to the UPDATE.
 * @param addr_count number of addresses in @c addr_list.
 * @param ifindex    interface number. If non-zero, the ifindex value of the
 *                   interface which caused the event.
 * @param flags      ...
 * @param is_add     ...
 * @param addr       a pointer to ...
 * @return           0 if UPDATE was sent, otherwise < 0.
 */
int hip_send_update(struct hip_hadb_state *entry,
		    struct hip_locator_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags, int is_add,
		    struct sockaddr* addr);

/**
 * Internal function copied originally from rea.c.
 *
 * @param entry a pointer to a hadb entry.
 * @param addr  op
 * @return      ...
 */
static int hip_update_get_all_valid(hip_ha_t *entry, void *op);

/**
 * Sends UPDATE packet to every peer.
 *
 * UPDATE is sent to the peer only if the peer is in established state. Add
 * LOCATOR parameter if @c addr_list is non-null. @c ifindex tells which device
 * caused the network device event.
 *
 * @param addr_list  if non-NULL, LOCATOR parameter is added to the UPDATE.
 * @param addr_count number of addresses in @c addr_list.
 * @param ifindex    if non-zero, the ifindex value of the interface which
 *                   caused the event.
 * @param flags      flags passed to @c hip_send_update.
 */
void hip_send_update_all(struct hip_locator_info_addr_item *addr_list,
			 int addr_count, int ifindex,  int flags, int is_add,
			 struct sockaddr* addr);

/**
 * Handles UPDATE acknowledgement.
 *
 * @param entry    a pointer to a hadb entry corresponding to the peer.
 * @param ack      a pointer to ...
 * @param have_nes ...
 */
void hip_update_handle_ack(hip_ha_t *entry, struct hip_ack *ack, int have_nes);

/**
 * Sends an UPDATE acknowledgement.
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to a hip UPDATE message.
 * @param src_ip a pointer to source IP address.
 * @param dst_ip a pointer to destination IP address.
 * @return       zero on success, non-zero otherwise.
 */
int hip_update_send_ack(hip_ha_t *entry, hip_common_t *msg,
			in6_addr_t *src_ip, in6_addr_t *dst_ip);

/**
 * This function checks if the address in the ECHO_REQUEST is in the
 * SPIs peer_addr_list. If not found it adds it into the list
 *
 * @param esp_info  Structure pointer telling the SPI to use when adding.
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param src_ip a pointer to source IP address.
 *
 * @return       zero on success, non-zero otherwise.
 */
int hip_peer_learning(struct hip_esp_info * esp_info, hip_ha_t *entry, in6_addr_t * src_ip);

int hip_update_handle_stun(void* pkg, int len, 
			   in6_addr_t *src_addr, in6_addr_t * dst_addr,
			   hip_ha_t *entry,
			   hip_portpair_t *sinfo);

int hip_build_locators(struct hip_common *, uint32_t spi, hip_transform_suite_t  ice);

#endif /* HIP_UPDATE_H */

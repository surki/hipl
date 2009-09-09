/** @file
 * This file defines building and parsing functions for Host Identity Protocol
 * (HIP) kernel module and user messages.
 *
 * These functions work both in the userspace and in the kernel.
 *
 * Keep in mind the following things when using the builder:
 * <ul>
 * <li>Never access members of @c hip_common and @c hip_tlv_common directly. Use
 * the accessor functions to hide byte ordering and length manipulation.</li>
 * <li>Remember always to use <code>__attribute__ ((packed))</code> (see hip.h)
 * with builder because compiler adds padding into the structures.</li>
 * <li>This file is shared between userspace and kernel: do not put any memory
 * allocations or other kernel/userspace specific stuff into here.</li>
 * <li>If you build more functions like build_signature2_contents(), remember
 * to use hip_build_generic_param() in them.</li>
 * </ul>
 *
 * Usage examples:
 * <ul>
 * <li>sender of "add mapping", i.e. the hip module in kernel</li>
 * <ul>
 * <li>struct hip_common *msg = malloc(HIP_MAX_PACKET);</li>
 * <li>hip_msg_init(msg);</li>
 * <li>err = hip_build_user_hdr(msg, SO_HIP_ADD_MAP_HIT_IP, 0);</li>
 * <li>err = hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
 * sizeof(struct in6_addr));</li>
 * <li>err = hip_build_param_contents(msg, &ip, HIP_PARAM_IPV6_ADDR,
 * sizeof(struct in6_addr));</li>
 * <li>send the message to user space.</li>
 * </ul>
 * <li>receiver of "add mapping", i.e. the daemon</li>
 * <ul>
 * <li>struct hip_common *msg = malloc(HIP_MAX_PACKET);</li>
 * <li>receive the message from kernel.</li>
 * <li>if (msg->err) goto_error_handler;</li>
 * <li>hit = (struct in6addr *) hip_get_param_contents(msg, HIP_PARAM_HIT);</li>
 * <li>note: hit can be null, if the param was not found.</li>
 * <li>ip = (struct in6addr *) hip_get_param_object(msg, HIP_PARAM_IPV6ADDR);
 * </li>
 * <li>note: hit can be null.</li>
 * </ul>
 * </ul>
 * @author Miika Komu
 * @author Mika Kousa
 * @author Tobias Heer
 * @note   In network packets @c hip_build_network_hdr() should be used instead
 *         of @c hip_build_user_hdr().
 * @todo Macros for doing @c ntohs() and @c htons() conversion? Currently they are
 * used in a platform dependent way.
 * @todo Why does build network header return void whereas build daemon does
 *       not?
 * @todo There is a small TODO list in @c hip_build_network_hdr()
 * @todo <span style="color:#f00">Update the comments of this file.</span>
 */
#include "builder.h"
//#include "registration.h"
//#include "esp_prot_common.h"

static enum select_dh_key_t select_dh_key = STRONGER_KEY;

#ifdef __KERNEL__
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
#endif /* __KERNEL__ */

/**
 * hip_msg_init - initialize a network/daemon message
 * @param msg the message to be initialized
 *
 * Initialize a message to be sent to the daemon or into the network.
 * Initialization must be done before any parameters are build into
 * the message. Otherwise the writing of the parameters will result in bizarre
 * behaviour.
 *
 */
void hip_msg_init(struct hip_common *msg) {
	/* note: this is used both for daemon and network messages */
	memset(msg, 0, HIP_MAX_PACKET);
}

/**
 * hip_msg_alloc - allocate and initialize a HIP packet
 *
 * Return: initialized HIP packet if successful, NULL on error.
 */
struct hip_common *hip_msg_alloc(void)
{
        struct hip_common *ptr;

	ptr = HIP_MALLOC(HIP_MAX_PACKET, GFP_ATOMIC);
        if (ptr)
		hip_msg_init(ptr);
        return ptr;
}

/**
 * hip_msg_free - deallocate a HIP packet
 * @param msg the packet to be deallocated
 */
void hip_msg_free(struct hip_common *msg)
{
	HIP_FREE(msg);
}

/**
 * hip_convert_msg_total_len_to_bytes - convert message total length to bytes
 * @param len the length of the HIP header as it is in the header
 *       (in host byte order)
 *
 * @return the real size of HIP header in bytes (host byte order)
 */
uint16_t hip_convert_msg_total_len_to_bytes(hip_hdr_len_t len) {
	return (len == 0) ? 0 : ((len + 1) << 3);
}

/**
 * hip_get_msg_total_len - get the real, total size of the header in bytes
 * @param msg pointer to the beginning of the message header
 *
 * @return the real, total size of the message in bytes (host byte order).
 */
uint16_t hip_get_msg_total_len(const struct hip_common *msg) {
	return hip_convert_msg_total_len_to_bytes(msg->payload_len);
}

/**
 * hip_get_msg_contents_len - get message size excluding type and length
 * @param msg pointer to the beginning of the message header
 *
 * @return the real, total size of the message in bytes (host byte order)
 *          excluding the the length of the type and length fields
 */
uint16_t hip_get_msg_contents_len(const struct hip_common *msg) {
	HIP_ASSERT(hip_get_msg_total_len(msg) >=
		   sizeof(struct hip_common));
	return hip_get_msg_total_len(msg) - sizeof(struct hip_common);
}

/**
 * hip_set_msg_total_len - set the total message length in bytes
 * @param msg pointer to the beginning of the message header
 * @param len the total size of the message in bytes (host byte order)
 */
void hip_set_msg_total_len(struct hip_common *msg, uint16_t len) {
	/* assert len % 8 == 0 ? */
	msg->payload_len = (len < 8) ? 0 : ((len >> 3) - 1);
}

/**
 * hip_get_msg_type - get the type of the message in host byte order
 * @param msg pointer to the beginning of the message header
 *
 * @return the type of the message (in host byte order)
 *
 */
hip_hdr_type_t hip_get_msg_type(const struct hip_common *msg) {
	return msg->type_hdr;
}

/**
 * hip_set_msg_type - set the type of the message
 * @param msg pointer to the beginning of the message header
 * @param type the type of the message (in host byte order)
 *
 */
void hip_set_msg_type(struct hip_common *msg, hip_hdr_type_t type) {
	msg->type_hdr = type;
}

/**
 * hip_get_msg_err - get the error values from daemon message header
 * @param msg pointer to the beginning of the message header
 *
 * @return the error value from the message (in host byte order)
 *
 */
hip_hdr_err_t hip_get_msg_err(const struct hip_common *msg) {
	/* Note: error value is stored in checksum field for daemon messages.
	   This should be fixed later on by defining an own header for
	   daemon messages. This function should then input void* as
	   the message argument and cast it to the daemon message header
	   structure. */
	return msg->checksum; /* 1 byte, no ntohs() */
}

/**
 * hip_set_msg_err - set the error value of the daemon message
 * @param msg pointer to the beginning of the message header
 * @param err the error value
 */
void hip_set_msg_err(struct hip_common *msg, hip_hdr_err_t err) {
	/* note: error value is stored in checksum field for daemon messages */
	msg->checksum = err;
}

uint16_t hip_get_msg_checksum(struct hip_common *msg)
{
     return msg->checksum; /* one byte, no ntohs() */
}

/**
 * Get the HIP message @c Controls field value from the packet common header.
 *
 * @param msg a pointer to a HIP packet header
 * @return    the HIP controls
 */
hip_controls_t hip_get_msg_controls(struct hip_common *msg)
{
     return msg->control; /* one byte, no ntohs() */
}

/**
 * hip_zero_msg_checksum - zero message checksum
 */
void hip_zero_msg_checksum(struct hip_common *msg) {
	msg->checksum = 0; /* one byte, no ntohs() */
}

void hip_set_msg_checksum(struct hip_common *msg, u8 checksum) {
	msg->checksum = checksum; /* one byte, no ntohs() */
}

/**
 * hip_get_param_total_len - get total size of message parameter
 * @param tlv_common pointer to the parameter
 *
 * @return the total length of the parameter in bytes (host byte
 * order), including the padding.
 */
hip_tlv_len_t hip_get_param_total_len(const void *tlv_common) {
	return HIP_LEN_PAD(sizeof(struct hip_tlv_common) +
			   ntohs(((const struct hip_tlv_common *)
				  tlv_common)->length));
}

/**
 * hip_get_param_contents_len - get the size of the parameter contents
 * @param tlv_common pointer to the parameter
 *
 * @return the length of the parameter in bytes (in host byte order),
 *          excluding padding and the length of "type" and "length" fields
 */
hip_tlv_len_t hip_get_param_contents_len(const void *tlv_common) {
	return ntohs(((const struct hip_tlv_common *)tlv_common)->length);
}

/**
 * hip_set_param_contents_len - set parameter length
 * @param tlv_common pointer to the parameter
 * @param len the length of the parameter in bytes (in host byte order),
 *              excluding padding and the length of "type" and "length" fields
 */
void hip_set_param_contents_len(void *tlv_common,
				hip_tlv_len_t len) {
	((struct hip_tlv_common *)tlv_common)->length = htons(len);
}

/**
 * @brief Gets the type of a HIP parameter
 *
 * @param tlv_common pointer to the parameter
 * @return           the type of the parameter (in host byte order)
 */
hip_tlv_type_t hip_get_param_type(const void *tlv_common) {
	return ntohs(((const struct hip_tlv_common *)tlv_common)->type);
}

/**
 * hip_set_param_type - set parameter type
 * @param tlv_common pointer to the parameter
 * @param type type of the parameter (in host byte order)
 */
void hip_set_param_type(void *tlv_common, hip_tlv_type_t type) {
	((struct hip_tlv_common *)tlv_common)->type = htons(type);
}

/**
 * hip_get_diffie_hellman_param_public_value_contents - get dh public value contents
 * @param tlv_common pointer to the dh parameter
 *
 * @return pointer to the public value of Diffie-Hellman parameter
 */
void *hip_get_diffie_hellman_param_public_value_contents(const void *tlv_common) {
	return (void *) tlv_common + sizeof(struct hip_diffie_hellman);
}

/**
 * hip_get_diffie_hellman_param_public_value_len - get dh public value real length
 * @param dh pointer to the Diffie-Hellman parameter
 *
 * @return the length of the public value Diffie-Hellman parameter in bytes
 *          (in host byte order).
 */
hip_tlv_len_t hip_get_diffie_hellman_param_public_value_len(const struct hip_diffie_hellman *dh)
{
	return hip_get_param_contents_len(dh) - sizeof(uint8_t) - sizeof(uint16_t);
}


/**
 * hip_dh_select_key - Selects the stronger DH key according to Moskowitz, R.
 * et al. "Host Identity Protocol"  draft-ietf-hip-base-07.txt, section 5.2.6:
 *
 *  "The sender can include at most two different Diffie-Hellman public
 *  values in the DIFFIE_HELLMAN parameter.  This gives the possibility
 *  e.g. for a server to provide a weaker encryption possibility for a
 *  PDA host that is not powerful enough.  It is RECOMMENDED that the
 *  Initiator, receiving more than one public values selects the stronger
 *  one, if it supports it."
 *
 * @param dhf: pointer to the Diffie-Hellman parameter with two DH keys.
 *
 * @return dhf: pointer to the new Diffie-Hellman parameter, that includes
 *         only one DH key.
 */
struct hip_dh_public_value *hip_dh_select_key(const struct hip_diffie_hellman *dhf)
{
        struct hip_dh_public_value *dhpv1 = NULL, *dhpv2 = NULL, *err = NULL;

	if ( ntohs(dhf->pub_val.pub_len) ==
	     hip_get_diffie_hellman_param_public_value_len(dhf) ){
	         HIP_DEBUG("Single DHF public value received\n");
		 return (struct hip_dh_public_value *)&dhf->pub_val.group_id;
	} else {

		 dhpv1 = (struct hip_dh_public_value *)&dhf->pub_val.group_id;
		 dhpv2 = (struct hip_dh_public_value *)
		   (dhf->pub_val.public_value + ntohs(dhf->pub_val.pub_len));

		 HIP_IFEL (hip_get_diffie_hellman_param_public_value_len(dhf) !=
			   ntohs(dhpv1->pub_len) + sizeof(uint8_t) + sizeof(uint16_t)
			   + ntohs(dhpv2->pub_len), dhpv1, "Malformed DHF parameter\n");

		 HIP_DEBUG("Multiple DHF public values received\n");

		 _HIP_DEBUG("dhpv1->group_id= %d   dhpv2->group_id= %d\n",
			    dhpv1->group_id, dhpv2->group_id);
		 _HIP_DEBUG("dhpv1->pub_len= %d   dhpv2->pub_len= %d\n",
			    dhpv1->pub_len, dhpv2->pub_len);
		 _HIP_DEBUG("ntohs(dhpv1->pub_len)= %d   ntohs(dhpv2->pub_len)= %d\n",
			    ntohs(dhpv1->pub_len), ntohs(dhpv2->pub_len));



		 /* Selection of a DH key depending on select_dh_key */
		 if ( (select_dh_key == STRONGER_KEY &&
		       dhpv1->group_id >= dhpv2->group_id) ||
		      (select_dh_key == WEAKER_KEY &&
		       dhpv1->group_id <= dhpv2->group_id) )
		        return dhpv1;
		 else
		        return dhpv2;
	}
 out_err:
	return err;
}


#if 0
/**
 * hip_set_param_spi_value - set the spi value in spi_lsi parameter
 * @param spi_lsi the spi_lsi parameter
 * @param spi the value of the spi in the spi_lsi value in host byte order
 *
 */
void hip_set_param_spi_value(struct hip_esp_info *esp_info, uint32_t spi)
{
	esp_info->spi = htonl(spi);
}

/**
 * hip_get_param_spi_value - get the spi value from spi_lsi parameter
 * @param spi_lsi the spi_lsi parameter
 *
 * @return the spi value in host byte order
 */
uint32_t hip_get_param_spi_value(const struct hip_esp_info *esp_info)
{
	return ntohl(esp_info->spi);
}
#endif

/**
 * hip_get_unit_test_suite_param_id - get suite id from unit test parameter
 * @param test pointer to the unit test parameter
 *
 * @return the id of the test suite (in host byte order) of the unit test
 *          parameter
 */
uint16_t hip_get_unit_test_suite_param_id(const struct hip_unit_test *test)
{
	return ntohs(test->suiteid);
}

/**
 * hip_get_unit_test_case_param_id - get test case id from unit test parameter
 * @param test pointer to the unit test parameter
 *
 * @return the id of the test case (in host byte order) of the unit test
 *          parameter
 */
uint16_t hip_get_unit_test_case_param_id(const struct hip_unit_test *test)
{
	return ntohs(test->caseid);
}

uint8_t hip_get_host_id_algo(const struct hip_host_id *host_id) {
	return host_id->rdata.algorithm; /* 8 bits, no ntons() */
}

struct hip_locator_info_addr_item *hip_get_locator_first_addr_item(struct hip_locator *locator) {
	return (struct hip_locator_info_addr_item *) (locator + 1);
}
/* remove by santtu, since the item have type2
int hip_get_locator_addr_item_count(struct hip_locator *locator) {
	return (hip_get_param_contents_len(locator) -
		(sizeof(struct hip_locator) -
		 sizeof(struct hip_tlv_common))) /
		sizeof(struct hip_locator_info_addr_item);
}
*/
#ifndef __KERNEL__
int hip_get_lifetime_value(time_t seconds, uint8_t *lifetime)
{
	/* Check that we get a lifetime value between 1 and 255. The minimum
	   lifetime according to the registration draft is 0.004 seconds, but
	   the reverse formula gives zero for that. 15384774.906 seconds is the
	   maximum value. The boundary checks done here are just curiosities
	   since services are usually granted for minutes to a couple of days,
	   but not for milliseconds and days. However, log() gives a range error
	   if "seconds" is zero. */
	if(seconds == 0) {
		*lifetime = 0;
		return -1;
	}else if(seconds > 15384774) {
		*lifetime = 255;
		return -1;
	}else {
		*lifetime = (8 * (log(seconds) / log(2))) + 64;
		return 0;
	}
}

int hip_get_lifetime_seconds(uint8_t lifetime, time_t *seconds){
	if(lifetime == 0) {
		*seconds = 0;
		return -1;
	}
	/* All values between from 1 to 63 give just fractions of a second. */
	else if(lifetime < 64) {
		*seconds = 1;
		return 0;
	} else {
		*seconds = pow(2, ((double)((lifetime)-64)/8));
		return 0;
	}
}
#endif
/**
 * hip_check_user_msg_len - check validity of user message length
 * @param msg pointer to the message
 *
 * @return 1 if the message length is valid, or 0 if the message length is
 *          invalid
 */
int hip_check_user_msg_len(const struct hip_common *msg) {
	uint16_t len;

	HIP_ASSERT(msg);
	len = hip_get_msg_total_len(msg);

	if (len < sizeof(struct hip_common) || len > HIP_MAX_PACKET) {
		return 0;
	} else {
		return 1;
	}
}


/**
 * hip_check_network_msg_len - check validity of network message length
 * @param msg pointer to the message
 *
 * @return 1 if the message length is valid, or 0 if the message length is
 *          invalid
 */
int hip_check_network_msg_len(const struct hip_common *msg) {
	uint16_t len;

	HIP_ASSERT(msg);
	len = hip_get_msg_total_len(msg);

	if (len < sizeof(struct hip_common) || len > HIP_MAX_NETWORK_PACKET) {
		return 0;
	} else {
		return 1;
	}
}



/**
 * hip_check_network_msg_type - check the type of the network message
 * @param msg pointer to the message
 *
 * @return 1 if the message type is valid, or 0 if the message type is
 *          invalid
 */
int hip_check_network_msg_type(const struct hip_common *msg) {
	int ok = 0;
	hip_hdr_type_t supported[] =
		{
			HIP_I1,
			HIP_R1,
			HIP_I2,
			HIP_R2,
			HIP_UPDATE,
			HIP_NOTIFY,
			HIP_BOS,
			HIP_CLOSE,
			HIP_CLOSE_ACK,
			HIP_LUPDATE
		};
	hip_hdr_type_t i;
	hip_hdr_type_t type = hip_get_msg_type(msg);

	for (i = 0; i < sizeof(supported) / sizeof(hip_hdr_type_t); i++) {
		if (type == supported[i]) {
			ok = 1;
			break;
		}
	}

	return ok;
}

/**
 * hip_check_userspace_param_type - check the userspace parameter type
 * @param param pointer to the parameter
 *
 * @return 1 if parameter type is valid, or 0 if parameter type is invalid
 */
int hip_check_userspace_param_type(const struct hip_tlv_common *param)
{
	return 1;
}

/**
 * Checks the network parameter type.
 *
 * Optional parameters are not checked, because the code just does not
 * use them if they are not supported.
 *
 * @param param the network parameter
 * @return 1 if parameter type is valid, or 0 if parameter type
 * is not valid. "Valid" means all optional and non-optional parameters
 * in the HIP draft.
 * @todo Clarify the functionality and explanation of this function. Should
 *       new parameters be added to the checked parameters list as they are
 *       introduced in extensions drafts (RVS, NAT, Registration...), or should
 *       here only be the parameters listed in Sections 5.2.3 through Section
 *       5.2.18 of the draft-ietf-hip-base-06?
 */
int hip_check_network_param_type(const struct hip_tlv_common *param)
{
	int ok = 0;
	hip_tlv_type_t i;
	hip_tlv_type_t valid[] =
		{
			HIP_PARAM_ACK,
			HIP_PARAM_BLIND_NONCE,
                        HIP_PARAM_CERT,
                        HIP_PARAM_DIFFIE_HELLMAN,
                        HIP_PARAM_ECHO_REQUEST,
                        HIP_PARAM_ECHO_REQUEST_SIGN,
                        HIP_PARAM_ECHO_RESPONSE,
                        HIP_PARAM_ECHO_RESPONSE_SIGN,
                        HIP_PARAM_ENCRYPTED,
                        HIP_PARAM_ESP_INFO,
                        HIP_PARAM_ESP_INFO,
                        HIP_PARAM_ESP_TRANSFORM,
                        HIP_PARAM_FROM,
			HIP_PARAM_RELAY_FROM,
			//add by santtu
			HIP_PARAM_RELAY_HMAC,
			//end add
                        HIP_PARAM_HIP_SIGNATURE,
                        HIP_PARAM_HIP_SIGNATURE2,
                        HIP_PARAM_HIP_TRANSFORM,
                        HIP_PARAM_HMAC,
                        HIP_PARAM_HMAC,
                        HIP_PARAM_HMAC2,
			HIP_PARAM_RVS_HMAC,
                        HIP_PARAM_HOST_ID,
                        HIP_PARAM_LOCATOR,
			//add by santtu
			HIP_PARAM_NAT_TRANSFORM,
			HIP_PARAM_NAT_PACING,
			HIP_PARAM_STUN,
			//end add
                        HIP_PARAM_NOTIFICATION,
                        HIP_PARAM_PUZZLE,
                        HIP_PARAM_R1_COUNTER,
                        HIP_PARAM_REG_FAILED,
                        HIP_PARAM_REG_INFO,
                        HIP_PARAM_REG_REQUEST,
                        HIP_PARAM_REG_RESPONSE,
                        HIP_PARAM_SEQ,
                        HIP_PARAM_SOLUTION,
                        HIP_PARAM_VIA_RVS,
			HIP_PARAM_RELAY_TO,
			//add by santtu
			HIP_PARAM_REG_FROM,
			//end add
			HIP_PARAM_ESP_PROT_TRANSFORMS,
			HIP_PARAM_ESP_PROT_ANCHOR,
			HIP_PARAM_ESP_PROT_BRANCH,
			HIP_PARAM_ESP_PROT_SECRET,
			HIP_PARAM_ESP_PROT_ROOT
		};
	hip_tlv_type_t type = hip_get_param_type(param);

	/** @todo check the lengths of the parameters */

	for (i = 0; i < ARRAY_SIZE(valid); i++) {
		if (!(type & 0x0001)) {
			_HIP_DEBUG("Optional param, skip\n");
			ok = 1;
			break;
		} else if (type == valid[i]) {
			ok = 1;
			break;
		}
	}

	return ok;
}

/**
 * Checks the validity of parameter contents length.
 *
 * The msg is passed also in to check to the parameter will not cause buffer
 * overflows.
 *
 * @param msg   a pointer to the beginning of the message
 * @param param a pointer to the parameter to be checked for contents length
 * @return      1 if the length of the parameter contents length was valid
 *              (the length was not too small or too large to fit into the
 *              message). Zero is returned on invalid contents length.
 */
int hip_check_param_contents_len(const struct hip_common *msg,
				 const struct hip_tlv_common *param) {
	int ok = 0;
	int param_len = hip_get_param_total_len(param);
	void *pos = (void *) param;

	/* Note: the lower limit is not checked, because there really is no
	   lower limit. */

	if (pos == ((void *)msg)) {
		HIP_ERROR("use hip_check_msg_len()\n");
	} else if (pos + param_len > ((void *) msg) + HIP_MAX_PACKET) {
		HIP_DEBUG("param far too long (%d)\n", param_len);
	} else if (param_len > hip_get_msg_total_len(msg)) {
		HIP_DEBUG("param too long (%d)\n", param_len);
	} else {
		_HIP_DEBUG("param length ok (%d)\n", param_len);
		ok = 1;
	}
	return ok;
}

/**
 * Iterates to the next parameter.
 *
 * @param msg           a pointer to the beginning of the message header
 * @param current_param a pointer to the current parameter, or NULL if the msg
 *                      is to be searched from the beginning.
 * @return              the next parameter after the current_param in @c msg, or
 *                      NULL if no parameters were found.
 */
struct hip_tlv_common *hip_get_next_param(const struct hip_common *msg,
					  const struct hip_tlv_common *current_param)
{
	struct hip_tlv_common *next_param = NULL;
	void *pos = (void *) current_param;

	if (!msg) {
		HIP_ERROR("msg null\n");
		goto out;
	}

	if (current_param == NULL) {
		pos = (void *) msg;
	}

	if (pos == msg)
		pos += sizeof(struct hip_common);
	else
		pos += hip_get_param_total_len(current_param);

	next_param = (struct hip_tlv_common *) pos;

	/* check that the next parameter does not point
	   a) outside of the message
	   b) out of the buffer with check_param_contents_len()
	   c) to an empty slot in the message */
	if (((char *) next_param) - ((char *) msg) >=
	    hip_get_msg_total_len(msg) || /* a */
	    !hip_check_param_contents_len(msg, next_param) || /* b */
	    hip_get_param_contents_len(next_param) == 0) {    /* c */
		_HIP_DEBUG("no more parameters found\n");
		next_param = NULL;
	} else {
		/* next parameter successfully found  */
		_HIP_DEBUG("next param: type=%d, len=%d\n",
			  hip_get_param_type(next_param),
			  hip_get_param_contents_len(next_param));
	}

 out:
	return next_param;


}

/**
 * Gets  the first parameter of the given type.
 *
 * If there are multiple parameters of the same type, one should use
 * hip_get_next_param() after calling this function to iterate through
 * them all.

 * @param msg        a pointer to the beginning of the message header.
 * @param param_type the type of the parameter to be searched from msg
 *                   (in host byte order)
 * @return           a pointer to the first parameter of the type param_type,
 *                   or NULL if no parameters of the type param_type were not
 *                   found.
 */
void *hip_get_param(const struct hip_common *msg, hip_tlv_type_t param_type)
{
	void *matched = NULL;
	struct hip_tlv_common *current_param = NULL;

	_HIP_DEBUG("searching for type %d\n", param_type);

       /** @todo Optimize: stop when next parameter's type is greater than the
	   searched one. */

	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		_HIP_DEBUG("current param %d\n",
			   hip_get_param_type(current_param));
		if (hip_get_param_type(current_param) == param_type) {
			matched = current_param;
			break;
		}
	}

	return matched;
}

/**
 * Get contents of the first parameter of the given type. If there are multiple
 * parameters of the same type, one should use @c hip_get_next_param() after
 * calling this function to iterate through them all.
 *
 * @param msg         a pointer to the beginning of the message header
 * @param param_type the type of the parameter to be searched from msg
 *                   (in host byte order)
 * @return           a pointer to the contents of the first parameter of the
 *                   type @c param_type, or NULL if no parameters of type
 *                   @c param_type were found.
 */
void *hip_get_param_contents(const struct hip_common *msg,
			     hip_tlv_type_t param_type)
{

	void *contents = hip_get_param(msg,param_type);
	if (contents)
		contents += sizeof(struct hip_tlv_common);
	return contents;
}

/**
 * hip_get_param_contents_direct - get parameter contents direct from TLV
 * @param tlv_common pointer to a parameter
 *
 * @return pointer to the contents of the tlv_common (just after the
 *          the type and length fields)
 */
void *hip_get_param_contents_direct(const void *tlv_common)
{
	return ((void *)tlv_common) + sizeof(struct hip_tlv_common);
}


/* hip_get_nth_param - get nth parameter of given type from the message
 * @param msg pointer to the beginning of the message header
 * @param param_type the type of the parameter to be searched from msg
 *              (in host byte order)
 * @param n index number to be get
 *
 * @return the nth parameter from the message if found, else %NULL.
 */
void *hip_get_nth_param(const struct hip_common *msg,
			hip_tlv_type_t param_type, int n)
{
	struct hip_tlv_common *param = NULL;
	int i = 0;

	if (n < 1) {
		HIP_ERROR("n < 1 (n=%d)\n", n);
		return NULL;
	}

	while((param = hip_get_next_param(msg, param))) {
		if (hip_get_param_type(param) == param_type) {
			i++;
			if (i == n)
				return param;
		}
	}
	return NULL;
}

/**
 * @brief Finds the first free parameter position in message.
 *
 * This function does not check whether the new parameter to be appended
 * would overflow the @c msg buffer. It is the responsibilty of the caller
 * to check such circumstances because this function does not know
 * the length of the object to be appended in the message. Still, this
 * function checks the special situation where the buffer is completely
 * full and returns NULL in such a case.
 *
 * @param msg a pointer to the beginning of the message header
 * @return    a pointer to the first free (padded) position, or NULL if
 *            the message was completely full
 * @todo      Should this function should return hip_tlv_common?
 */
void *hip_find_free_param(const struct hip_common *msg)
{
	struct hip_tlv_common *current_param = NULL;
	struct hip_tlv_common *last_used_pos = NULL;
	void *free_pos = NULL;
	void *first_pos = ((void *) msg) + sizeof(struct hip_common);

	/* Check for no parameters: this has to be checked separately because
	   we cannot tell from the return value of get_next_param() whether
	   the message was completely full or there just were no parameters.
	   The length is used for checking the existance of parameter, because
	   type field may be zero (SPI_LSI = 0) and therefore it cannot be
	   used for checking the existance. */
	if (hip_get_param_contents_len((struct hip_tlv_common *) first_pos)
	    == 0) {
		_HIP_DEBUG("no parameters\n");
		free_pos = first_pos;
		goto out;
	}

	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		last_used_pos = current_param;
		_HIP_DEBUG("not free: type=%d, contents_len=%d\n",
			  hip_get_param_type(current_param),
			  hip_get_param_contents_len(current_param));
	}

	if (last_used_pos == NULL) {
		free_pos = NULL; /* the message was full */
	} else {
		free_pos = ((void *) last_used_pos) +
			hip_get_param_total_len(last_used_pos);
	}

 out:
	return free_pos;
}


/**
 * @brief Updates messsage header length
  *
 * This function is called always when a parameter has been added or the
 * daemon/network header was written. This function writes the new
 * header length directly into the message.
 *
 * @param msg a pointer to the beginning of the message header
 */
void hip_calc_hdr_len(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	void *pos = (void *) msg;

	/* We cannot call get_next() or get_free() because they need a valid
	   header length which is to be (possibly) calculated now. So, the
	   header length must be calculated manually here. */

	if (hip_get_msg_total_len(msg) == 0) {
		/* msg len is zero when
		   1) calling build_param() for the first time
		   2) calling just the build_hdr() without building
		      any parameters, e.g. in plain error messages */
		_HIP_DEBUG("case 1,2\n");
		hip_set_msg_total_len(msg, sizeof(struct hip_common));
	} else {
		/* 3) do nothing, build_param()+ */
		/* 4) do nothing, build_param()+ and build_hdr() */
		_HIP_DEBUG("case 3,4\n");
	}

	pos += hip_get_msg_total_len(msg);
	param = (struct hip_tlv_common *) pos;
	if (hip_get_param_contents_len(param) != 0) {
		/* Case 1 and 3: a new parameter (with a valid length) has
		   been added and the message length has not been updated. */
		_HIP_DEBUG("case 1,3\n");
		hip_set_msg_total_len(msg, hip_get_msg_total_len(msg) +
				      hip_get_param_total_len(param));
		/* XX assert: new pos must be of type 0 (assume only one
		   header has been added) */
	} else {
		/* case 2 and 4: the message length does not need to be
		   updated */
		_HIP_DEBUG("case 2,4\n");
	}

	_HIP_DEBUG("msg len %d\n", hip_get_msg_total_len(msg));
}

/**
 * Calculates and writes the length of any HIP packet parameter
 *
 * This function can be used for semi-automatic calculation of parameter
 * length field. This function should always be used instead of manual
 * calculation of parameter lengths. The tlv_size is usually just
 * sizeof(struct hip_tlv_common), but it can include other fields than
 * just the type and length. For example, DIFFIE_HELLMAN parameter includes
 * the group field as in hip_build_param_diffie_hellman_contents().
 *
 * @param tlv_common pointer to the beginning of the parameter
 * @param tlv_size size of the TLV header  (in host byte order)
 * @param contents_size size of the contents after the TLV header
 *                 (in host byte order)
 */
void hip_calc_generic_param_len(void *tlv_common,
			      hip_tlv_len_t tlv_size,
			      hip_tlv_len_t contents_size)
{
	hip_set_param_contents_len(tlv_common,
				   tlv_size + contents_size -
				   sizeof(struct hip_tlv_common));
}

/**
 * hip_calc_param_len - calculate the length of a "normal" TLV structure
 * @param tlv_common pointer to the beginning of the TLV structure
 * @param contents_size size of the contents after type and length fields
 *                 (in host byte order)
 *
 * This function calculates and writes the length of TLV structure field.
 * This function is different from hip_calc_generic_param_len() because
 * it assumes that the length of the header of the TLV is just
 * sizeof(struct hip_tlv_common).
 */
void hip_calc_param_len(void *tlv_common, hip_tlv_len_t contents_size)
{
	hip_calc_generic_param_len(tlv_common, sizeof(struct hip_tlv_common),
				   contents_size);
}

/**
 * Prints HIP message contents using HIP debug interface.
 *
 * @param msg a pointer to the message to be printed.
 * @note      Do not call this function directly, use the HIP_DUMP_MSG() macro
 *            instead.
 */
void hip_dump_msg(const struct hip_common *msg)
{
     struct hip_tlv_common *current_param = NULL;
     void *contents = NULL;
     /* The value of the "Length"-field in current parameter. */
     hip_tlv_len_t len = 0;
     /* Total length of the parameter (type+length+value+padding), and the
	length of padding. */
     size_t total_len = 0, pad_len = 0;
     HIP_DEBUG("--------------- MSG START ------------------\n");

     HIP_DEBUG("Msg type :      %s (%d)\n",
	       hip_message_type_name(hip_get_msg_type(msg)),
	       hip_get_msg_type(msg));
     HIP_DEBUG("Msg length:     %d\n", hip_get_msg_total_len(msg));
     HIP_DEBUG("Msg err:        %d\n", hip_get_msg_err(msg));
     HIP_DEBUG("Msg controls:   0x%04x\n", msg->control);

     _HIP_DEBUG_HIT("Msg hits:       ", &msg->hits );
     _HIP_DEBUG_HIT("Msg hitr:       ", &msg->hitr );

     while((current_param = hip_get_next_param(msg, current_param)) != NULL)
     {
	  len = hip_get_param_contents_len(current_param);
	  /* Formula from base draft section 5.2.1. */
	  total_len = 11 + len - (len +3) % 8;
	  pad_len = total_len - len - sizeof(hip_tlv_type_t)
	       - sizeof(hip_tlv_len_t);
	  contents = hip_get_param_contents_direct(current_param);
	  HIP_DEBUG("Parameter type:%s (%d). Total length: %d (4 type+"\
		    "length, %d content, %d padding).\n",
		    hip_param_type_name(hip_get_param_type(current_param)),
		    hip_get_param_type(current_param),
		    total_len,
		    len,
		    pad_len);
	  HIP_HEXDUMP("Contents:", contents, len);
	  HIP_HEXDUMP("Padding:", contents + len , pad_len);
     }
     HIP_DEBUG("---------------- MSG END --------------------\n");
}

/**
 * Returns a string for a given parameter type number.
 * The returned string should be just the same as its type constant name.
 *
 * @note If you added a SO_HIP_NEWMODE in libinet6/icomm.h, you also need to
 *       add a case block for your SO_HIP_NEWMODE constant in the
 *       switch(msg_type) block in this function.
 * @param msg_type message type number
 * @return         name of the message type
 **/
char* hip_message_type_name(const uint8_t msg_type){
	switch (msg_type) {
	case HIP_I1:		return "HIP_I1";
	case HIP_R1:		return "HIP_R1";
	case HIP_I2:		return "HIP_I2";
	case HIP_R2:		return "HIP_R2";
	case HIP_UPDATE:	return "HIP_UPDATE";
	case HIP_NOTIFY:	return "HIP_NOTIFY";
	case HIP_CLOSE:		return "HIP_CLOSE";
	case HIP_CLOSE_ACK:	return "HIP_CLOSE_ACK";
	case HIP_CER:		return "HIP_CER";
	case HIP_PAYLOAD:	return "HIP_PAYLOAD";
	case HIP_PSIG:		return "HIP_PSIG";
	case HIP_TRIG:		return "HIP_TRIG";

	case SO_HIP_ADD_LOCAL_HI:	return "SO_HIP_ADD_LOCAL_HI";
	case SO_HIP_DEL_LOCAL_HI:	return "SO_HIP_DEL_LOCAL_HI";
	case SO_HIP_RUN_UNIT_TEST:	return "SO_HIP_RUN_UNIT_TEST";
	case SO_HIP_RST:		return "SO_HIP_RST";
	case SO_HIP_UNIT_TEST:		return "SO_HIP_UNIT_TEST";
	case SO_HIP_BOS:		return "SO_HIP_BOS";
	case SO_HIP_NETLINK_DUMMY:	return "SO_HIP_NETLINK_DUMMY";
	case SO_HIP_CONF_PUZZLE_NEW:	return "SO_HIP_CONF_PUZZLE_NEW";
	case SO_HIP_CONF_PUZZLE_GET:	return "SO_HIP_CONF_PUZZLE_GET";
	case SO_HIP_CONF_PUZZLE_SET:	return "SO_HIP_CONF_PUZZLE_SET";
	case SO_HIP_CONF_PUZZLE_INC:	return "SO_HIP_CONF_PUZZLE_INC";
	case SO_HIP_CONF_PUZZLE_DEC:	return "SO_HIP_CONF_PUZZLE_DEC";
	case SO_HIP_SET_OPPORTUNISTIC_MODE: return "SO_HIP_SET_OPPORTUNISTIC_MODE";
	case SO_HIP_SET_BLIND_ON:	return "SO_HIP_SET_BLIND_ON";
	case SO_HIP_SET_BLIND_OFF:	return "SO_HIP_SET_BLIND_OFF";
	case SO_HIP_DHT_GW:		return "SO_HIP_DHT_GW";
	case SO_HIP_SET_DEBUG_ALL:	return "SO_HIP_SET_DEBUG_ALL";
	case SO_HIP_SET_DEBUG_MEDIUM:	return "SO_HIP_SET_DEBUG_MEDIUM";
	case SO_HIP_SET_DEBUG_NONE:	return "SO_HIP_SET_DEBUG_NONE";
	case SO_HIP_HANDOFF_ACTIVE:	return "SO_HIP_HANDOFF_ACTIVE";
	case SO_HIP_HANDOFF_LAZY:	return "SO_HIP_HANDOFF_LAZY";
	case SO_HIP_RESTART:		return "SO_HIP_RESTART";
	case SO_HIP_SET_LOCATOR_ON:	return "SO_HIP_SET_LOCATOR_ON";
	case SO_HIP_SET_LOCATOR_OFF:	return "SO_HIP_SET_LOCATOR_OFF";
	case SO_HIP_DHT_SET:		return "SO_HIP_DHT_SET";
	case SO_HIP_DHT_ON:		return "SO_HIP_DHT_ON";
	case SO_HIP_DHT_OFF:		return "SO_HIP_DHT_OFF";
	case SO_HIP_HIT_TO_IP_ON:	return "SO_HIP_HIT_TO_IP_ON";
	case SO_HIP_HIT_TO_IP_OFF:	return "SO_HIP_HIT_TO_IP_OFF";
	case SO_HIP_HIT_TO_IP_SET:	return "SO_HIP_HIT_TO_IP_SET";
	case SO_HIP_SET_OPPTCP_ON:	return "SO_HIP_SET_OPPTCP_ON";
	case SO_HIP_SET_OPPTCP_OFF:	return "SO_HIP_SET_OPPTCP_OFF";
	case SO_HIP_OPPTCP_SEND_TCP_PACKET: return "SO_HIP_OPPTCP_SEND_TCP_PACKET";
	case SO_HIP_TRANSFORM_ORDER:	return "SO_HIP_TRANSFORM_ORDER";
	case SO_HIP_OFFER_RVS:		return "SO_HIP_OFFER_RVS";
	case SO_HIP_CANCEL_RVS:		return "SO_HIP_CANCEL_RVS";
	case SO_HIP_REINIT_RVS:		return "SO_HIP_REINIT_RVS";
	case SO_HIP_ADD_DEL_SERVER:	return "SO_HIP_ADD_DEL_SERVER";
	case SO_HIP_OFFER_HIPRELAY:	return "SO_HIP_OFFER_HIPRELAY";
	case SO_HIP_CANCEL_HIPRELAY:	return "SO_HIP_CANCEL_HIPRELAY";
	case SO_HIP_REINIT_RELAY:	return "SO_HIP_REINIT_RELAY";
	case SO_HIP_OFFER_ESCROW:	return "SO_HIP_OFFER_ESCROW";
	case SO_HIP_CANCEL_ESCROW:	return "SO_HIP_CANCEL_ESCROW";
	case SO_HIP_ADD_DB_HI:		return "SO_HIP_ADD_DB_HI";
	case SO_HIP_ADD_ESCROW_DATA:	return "SO_HIP_ADD_ESCROW_DATA";
	case SO_HIP_DELETE_ESCROW_DATA:	return "SO_HIP_DELETE_ESCROW_DATA";
	case SO_HIP_SET_ESCROW_ACTIVE:	return "SO_HIP_SET_ESCROW_ACTIVE";
	case SO_HIP_SET_ESCROW_INACTIVE: return "SO_HIP_SET_ESCROW_INACTIVE";
	case SO_HIP_FIREWALL_PING:	return "SO_HIP_FIREWALL_PING";
	case SO_HIP_FIREWALL_PING_REPLY: return "SO_HIP_FIREWALL_PING_REPLY";
	case SO_HIP_FIREWALL_QUIT:	return "SO_HIP_FIREWALL_QUIT";
	case SO_HIP_AGENT_PING:		return "SO_HIP_AGENT_PING";
	case SO_HIP_AGENT_PING_REPLY:	return "SO_HIP_AGENT_PING_REPLY";
	case SO_HIP_AGENT_QUIT:		return "SO_HIP_AGENT_QUIT";
	case SO_HIP_DAEMON_QUIT:	return "SO_HIP_DAEMON_QUIT";
	case SO_HIP_I1_REJECT:		return "SO_HIP_I1_REJECT";
	case SO_HIP_UPDATE_HIU:		return "SO_HIP_UPDATE_HIU";
	case SO_HIP_SET_NAT_PLAIN_UDP:	return "SO_HIP_SET_NAT_PLAIN_UDP";
	case SO_HIP_SET_NAT_NONE:	return "SO_HIP_SET_NAT_NONE";
	case SO_HIP_SET_HIPPROXY_ON:	return "SO_HIP_SET_HIPPROXY_ON";
	case SO_HIP_SET_HIPPROXY_OFF:	return "SO_HIP_SET_HIPPROXY_OFF";
	case SO_HIP_GET_PROXY_LOCAL_ADDRESS: return "SO_HIP_GET_PROXY_LOCAL_ADDRESS";
	case SO_HIP_HIPPROXY_STATUS_REQUEST: return "SO_HIP_HIPPROXY_STATUS_REQUEST";
	case SO_HIP_OPPTCP_UNBLOCK_AND_BLACKLIST: return "SO_HIP_OPPTCP_UNBLOCK_AND_BLACKLIST";
	case SO_HIP_FW_BEX_DONE:	return "SO_HIP_FW_BEX_DONE";
	case SO_HIP_SET_TCPTIMEOUT_ON:	return "SO_HIP_SET_TCPTIMEOUT_ON";
	case SO_HIP_SET_TCPTIMEOUT_OFF:	return "SO_HIP_SET_TCPTIMEOUT_OFF";
	case SO_HIP_SET_NAT_ICE_UDP:	return "SO_HIP_SET_NAT_ICE_UDP";
	case SO_HIP_IPSEC_ADD_SA:	return "SO_HIP_IPSEC_ADD_SA";
	case SO_HIP_USERSPACE_IPSEC:	return "SO_HIP_USERSPACE_IPSEC";
	case SO_HIP_ESP_PROT_TFM:	return "SO_HIP_ESP_PROT_TFM";
	case SO_HIP_BEX_STORE_UPDATE:	return "SO_HIP_BEX_STORE_UPDATE";
	case SO_HIP_TRIGGER_UPDATE:	return "SO_HIP_TRIGGER_UPDATE";
	case SO_HIP_ANCHOR_CHANGE:	return "SO_HIP_ANCHOR_CHANGE";
	case SO_HIP_TRIGGER_BEX:	return "SO_HIP_TRIGGER_BEX";
	  //case SO_HIP_IS_OUR_LSI: return "SO_HIP_IS_OUR_LSI";
	case SO_HIP_GET_PEER_HIT:	return "SO_HIP_GET_PEER_HIT";
	case SO_HIP_REGISTER_SAVAHR: return "SO_HIP_REGISTER_SAVAHR";
	case SO_HIP_GET_SAVAHR_IN_KEYS: return "SO_HIP_GET_SAVAHR_IN_KEYS";
	case SO_HIP_GET_SAVAHR_OUT_KEYS: return "SO_HIP_GET_SAVAHR_OUT_KEYS";
	  //case SO_HIP_GET_PEER_HIT_BY_LSIS: return "SO_HIP_GET_PEER_HIT_BY_LSIS";
	case SO_HIP_NSUPDATE_ON:	return "SO_HIP_NSUPDATE_ON";
	case SO_HIP_NSUPDATE_OFF:	return "SO_HIP_NSUPDATE_OFF";
	case SO_HIP_SET_HI3_ON:		return "SO_HIP_SET_HI3_ON";
	case SO_HIP_SET_HI3_OFF:	return "SO_HIP_SET_HI3_OFF";
	case SO_HIP_HEARTBEAT: 		return "SO_HIP_HEARTBEAT";
	case SO_HIP_DHT_SERVING_GW: 	return "SO_HIP_DHT_SERVING_GW";
	case SO_HIP_SET_NAT_PORT:	return "SO_HIP_SET_NAT_PORT";
	default:
		return "UNDEFINED";
	}
}

/**
 * Returns a string for a given parameter type number.
 *
 * @param param_type parameter type number
 * @return      name of the message type
 **/
char* hip_param_type_name(const hip_tlv_type_t param_type){
	switch (param_type) {
	case HIP_PARAM_ACK:		return "HIP_PARAM_ACK";
	case HIP_PARAM_AGENT_REJECT:	return "HIP_PARAM_AGENT_REJECT";
	case HIP_PARAM_BLIND_NONCE:	return "HIP_PARAM_BLIND_NONCE";
	case HIP_PARAM_CERT:		return "HIP_PARAM_CERT";
	case HIP_PARAM_DH_SHARED_KEY:	return "HIP_PARAM_DH_SHARED_KEY";
	case HIP_PARAM_DIFFIE_HELLMAN:	return "HIP_PARAM_DIFFIE_HELLMAN";
	case HIP_PARAM_DSA_SIGN_DATA:	return "HIP_PARAM_DSA_SIGN_DATA";
	case HIP_PARAM_DST_ADDR:	return "HIP_PARAM_DST_ADDR";
	case HIP_PARAM_ECHO_REQUEST:	return "HIP_PARAM_ECHO_REQUEST";
	case HIP_PARAM_ECHO_REQUEST_SIGN: return "HIP_PARAM_ECHO_REQUEST_SIGN";
	case HIP_PARAM_ECHO_RESPONSE:	return "HIP_PARAM_ECHO_RESPONSE";
	case HIP_PARAM_ECHO_RESPONSE_SIGN: return "HIP_PARAM_ECHO_RESPONSE_SIGN";
	case HIP_PARAM_EID_ADDR:	return "HIP_PARAM_EID_ADDR";
	case HIP_PARAM_EID_ENDPOINT:	return "HIP_PARAM_EID_ENDPOINT";
	case HIP_PARAM_EID_IFACE:	return "HIP_PARAM_EID_IFACE";
	case HIP_PARAM_EID_SOCKADDR:	return "HIP_PARAM_EID_SOCKADDR";
	case HIP_PARAM_ENCAPS_MSG:	return "HIP_PARAM_ENCAPS_MSG";
	case HIP_PARAM_ENCRYPTED:	return "HIP_PARAM_ENCRYPTED";
	case HIP_PARAM_ESP_INFO:	return "HIP_PARAM_ESP_INFO";
	case HIP_PARAM_ESP_TRANSFORM:	return "HIP_PARAM_ESP_TRANSFORM";
	case HIP_PARAM_FROM_PEER:	return "HIP_PARAM_FROM_PEER";
	case HIP_PARAM_FROM:		return "HIP_PARAM_FROM";
	case HIP_PARAM_HA_INFO:		return "HIP_PARAM_HA_INFO";
	case HIP_PARAM_HASH_CHAIN_ANCHORS: return "HIP_PARAM_HASH_CHAIN_ANCHORS";
	case HIP_PARAM_HASH_CHAIN_PSIG:	return "HIP_PARAM_HASH_CHAIN_PSIG";
	case HIP_PARAM_HASH_CHAIN_VALUE: return "HIP_PARAM_HASH_CHAIN_VALUE";
	case HIP_PARAM_HIP_SIGNATURE2:	return "HIP_PARAM_HIP_SIGNATURE2";
	case HIP_PARAM_HIP_SIGNATURE:	return "HIP_PARAM_HIP_SIGNATURE";
	case HIP_PARAM_HIP_TRANSFORM:	return "HIP_PARAM_HIP_TRANSFORM";
	case HIP_PARAM_HI:		return "HIP_PARAM_HI";
	case HIP_PARAM_HIT:		return "HIP_PARAM_HIT";
	case HIP_PARAM_HIT_LOCAL:	return "HIP_PARAM_HIT_LOCAL";
	case HIP_PARAM_HIT_PEER:	return "HIP_PARAM_HIT_PEER";
	case HIP_PARAM_HMAC2:		return "HIP_PARAM_HMAC2";
	case HIP_PARAM_HMAC:		return "HIP_PARAM_HMAC";
	case HIP_PARAM_HOST_ID:		return "HIP_PARAM_HOST_ID";
	case HIP_PARAM_INT:		return "HIP_PARAM_INT";
	case HIP_PARAM_IPV6_ADDR:	return "HIP_PARAM_IPV6_ADDR";
	case HIP_PARAM_IPV6_ADDR_LOCAL: return "HIP_PARAM_IPV6_ADDR_LOCAL";
	case HIP_PARAM_IPV6_ADDR_PEER:	return "HIP_PARAM_IPV6_ADDR_PEER";
	case HIP_PARAM_KEYS:		return "HIP_PARAM_KEYS";
	case HIP_PARAM_LOCATOR:		return "HIP_PARAM_LOCATOR";
	case HIP_PARAM_NOTIFICATION:	return "HIP_PARAM_NOTIFICATION";
	case HIP_PARAM_OPENDHT_GW_INFO: return "HIP_PARAM_OPENDHT_GW_INFO";
	case HIP_PARAM_OPENDHT_SET:	return "HIP_PARAM_OPENDHT_SET";
	case HIP_PARAM_PORTPAIR:	return "HIP_PARAM_PORTPAIR";
	case HIP_PARAM_PUZZLE:		return "HIP_PARAM_PUZZLE";
	case HIP_PARAM_R1_COUNTER:	return "HIP_PARAM_R1_COUNTER";
	case HIP_PARAM_REG_FAILED:	return "HIP_PARAM_REG_FAILED";
	case HIP_PARAM_REG_FROM:	return "HIP_PARAM_REG_FROM";
	case HIP_PARAM_REG_INFO:	return "HIP_PARAM_REG_INFO";
	case HIP_PARAM_REG_REQUEST:	return "HIP_PARAM_REG_REQUEST";
	case HIP_PARAM_REG_RESPONSE:	return "HIP_PARAM_REG_RESPONSE";
	case HIP_PARAM_RELAY_FROM:	return "HIP_PARAM_RELAY_FROM";
	case HIP_PARAM_RELAY_HMAC:	return "HIP_PARAM_RELAY_HMAC";
	case HIP_PARAM_RELAY_TO:	return "HIP_PARAM_RELAY_TO";
	case HIP_PARAM_RVS_HMAC:	return "HIP_PARAM_RVS_HMAC";
	case HIP_PARAM_SEQ:		return "HIP_PARAM_SEQ";
	case HIP_PARAM_SOLUTION:	return "HIP_PARAM_SOLUTION";
	case HIP_PARAM_SRC_ADDR:	return "HIP_PARAM_SRC_ADDR";
	case HIP_PARAM_TO_PEER:		return "HIP_PARAM_TO_PEER";
	case HIP_PARAM_UINT:		return "HIP_PARAM_UINT";
	case HIP_PARAM_UNIT_TEST:	return "HIP_PARAM_UNIT_TEST";
	case HIP_PARAM_VIA_RVS:		return "HIP_PARAM_VIA_RVS";
	case HIP_PARAM_PSEUDO_HIT:	return "HIP_PARAM_PSEUDO_HIT";
	case HIP_PARAM_HCHAIN_ANCHOR:	return "HIP_PARAM_HCHAIN_ANCHOR";
	case HIP_PARAM_ESP_PROT_TRANSFORMS: return "HIP_PARAM_ESP_PROT_TRANSFORMS";
	case HIP_PARAM_ESP_PROT_ANCHOR: return "HIP_PARAM_ESP_PROT_ANCHOR";
	case HIP_PARAM_ESP_PROT_BRANCH: return "HIP_PARAM_ESP_PROT_BRANCH";
	case HIP_PARAM_ESP_PROT_SECRET: return "HIP_PARAM_ESP_PROT_SECRET";
	case HIP_PARAM_ESP_PROT_ROOT: return "HIP_PARAM_ESP_PROT_ROOT";
	//add by santtu
	case HIP_PARAM_NAT_TRANSFORM:	return "HIP_PARAM_NAT_TRANSFORM";
	case HIP_PARAM_NAT_PACING:	return "HIP_PARAM_NAT_PACING";
	//end add
	case HIP_PARAM_LSI:		return "HIP_PARAM_LSI";
	case HIP_PARAM_SRC_TCP_PORT:	return "HIP_PARAM_SRC_TCP_PORT";
	case HIP_PARAM_DST_TCP_PORT:	return "HIP_PARAM_DST_TCP_PORT";
	case HIP_PARAM_STUN:		return "HIP_PARAM_STUN";
	case HIP_PARAM_HOSTNAME:	return "HIP_PARAM_HOSTNAME";
	//end add
	}
	return "UNDEFINED";
}


/**
 * hip_check_userspace msg - check userspace message for integrity
 * @param msg the message to be verified for integrity
 *
 * @return zero if the message was ok, or negative error value on error.
 */
int hip_check_userspace_msg(const struct hip_common *msg) {
	struct hip_tlv_common *current_param = NULL;
	int err = 0;

	if (!hip_check_user_msg_len(msg)) {
		err = -EMSGSIZE;
		HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
		goto out;
	}

	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		if(!hip_check_param_contents_len(msg, current_param)) {
			err = -EMSGSIZE;
			HIP_ERROR("bad param len\n");
			break;
		} else if (!hip_check_userspace_param_type(current_param)) {
			err = -EINVAL;
			HIP_ERROR("bad param type\n");
			break;
		}
	}

 out:
	return err;
}

/**
 * hip_check_network_param_attributes - check parameter attributes
 * @param param the parameter to checked
 *
 * This is the function where one can test special attributes such as algo,
 * groupid, suiteid, etc of a HIP parameter. If the parameter does not require
 * other than just the validation of length and type fields, one should not
 * add any checks for that parameter here.
 *
 * @return zero if the message was ok, or negative error value on error.
 *
 * XX TODO: this function may be unneccessary because the input handlers
 * already do some checking. Currently they are double checked..
 */
int hip_check_network_param_attributes(const struct hip_tlv_common *param)
{
	hip_tlv_type_t type = hip_get_param_type(param);
	int err = 0;

	_HIP_DEBUG("type=%u\n", type);

	switch(type) {
	case HIP_PARAM_HIP_TRANSFORM:
	case HIP_PARAM_ESP_TRANSFORM:
	{
		/* Search for one supported transform */
		hip_transform_suite_t suite;

 		_HIP_DEBUG("Checking %s transform\n",
			   type == HIP_PARAM_HIP_TRANSFORM ? "HIP" : "ESP");
		suite = hip_get_param_transform_suite_id(param, 0);
		if (suite == 0) {
			HIP_ERROR("Could not find suitable %s transform\n",
				  type == HIP_PARAM_HIP_TRANSFORM ? "HIP" : "ESP");
			err = -EPROTONOSUPPORT;
		}
		break;
	}
	case HIP_PARAM_HOST_ID:
	{
		uint8_t algo =
			hip_get_host_id_algo((struct hip_host_id *) param);
		if (algo != HIP_HI_DSA && algo != HIP_HI_RSA) {
			err = -EPROTONOSUPPORT;
			HIP_ERROR("Host id algo %d not supported\n", algo);
		}
		break;
	}
	}
	_HIP_DEBUG("err=%d\n", err);
	return err;
}

/**
 * hip_check_network_msg - check network message for integrity
 * @param msg the message to be verified for integrity
 *
 * @return zero if the message was ok, or negative error value on error.
 */
int hip_check_network_msg(const struct hip_common *msg)
{
	struct hip_tlv_common *current_param = NULL;
	hip_tlv_type_t current_param_type = 0, prev_param_type = 0;
	int err = 0;

	/* Checksum of the message header is verified in input.c */

	if (!hip_check_network_msg_type(msg)) {
		err = -EINVAL;
		HIP_ERROR("bad msg type (%d)\n", hip_get_msg_type(msg));
		goto out;
	}

	//check msg length
	if (!hip_check_network_msg_len(msg)) {
		err = -EMSGSIZE;
		HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
		goto out;
	}

	/* Checking of param types, lengths and ordering. */
	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		current_param_type = hip_get_param_type(current_param);
		if(!hip_check_param_contents_len(msg, current_param)) {
			err = -EMSGSIZE;
			HIP_ERROR("bad param len\n");
			break;
		} else if (!hip_check_network_param_type(current_param)) {
			err = -EINVAL;
			HIP_ERROR("bad param type, current param=%u\n",
				  hip_get_param_type(current_param));
			break;
		} else if (current_param_type < prev_param_type &&
			   ((current_param_type < HIP_LOWER_TRANSFORM_TYPE ||
			    current_param_type > HIP_UPPER_TRANSFORM_TYPE) &&
			    (prev_param_type < HIP_LOWER_TRANSFORM_TYPE ||
			     prev_param_type > HIP_UPPER_TRANSFORM_TYPE))) {
			/* According to draft-ietf-hip-base-03 parameter type order
			 * strictly enforced, except for
			 * HIP_LOWER_TRANSFORM_TYPE - HIP_UPPER_TRANSFORM_TYPE
			 */
			err = -ENOMSG;
			HIP_ERROR("Wrong order of parameters (%d, %d)\n",
				  prev_param_type, current_param_type);
			break;
		} else if (hip_check_network_param_attributes(current_param)) {
			HIP_ERROR("bad param attributes\n");
			err = -EINVAL;
			break;
		}
		prev_param_type = current_param_type;
	}

 out:
	return err;
}

/**
 * Builds and inserts a parameter into the message.
 *
 * This is the root function of all parameter building functions.
 * hip_build_param() and hip_build_param_contents() both  use this function to
 * append the parameter into the HIP message. This function updates the message
 * header length to keep the next free parameter slot quickly accessible for
 * faster writing of the parameters. This function also automagically adds zero
 * filled padding to the parameter, to keep its total length in multiple of 8
 * bytes. Parameter contents are copied from the function parameter @c contents,
 * thus the contents can and should be allocated from the stack instead of the
 * heap (i.e. allocated with malloc()).
 *
 * @param msg            the message where the parameter is to be appended
 * @param parameter_hdr  pointer to the header of the parameter
 * @param param_hdr_size size of parameter_hdr structure (in host byte order)
 * @param contents       the contents of the parameter; the data to be inserted
 *                       after the parameter_hdr (in host byte order)
 * @return               zero on success, or negative on error
 * @see                  hip_build_param().
 * @see                  hip_build_param_contents().
 */
int hip_build_generic_param(struct hip_common *msg, const void *parameter_hdr,
			    hip_tlv_len_t param_hdr_size, const void *contents)
{
	const struct hip_tlv_common *param =
		(struct hip_tlv_common *) parameter_hdr;
	void *src = NULL, *dst = NULL;
	int err = 0, size = 0;
	void *max_dst = ((void *) msg) + HIP_MAX_PACKET;

	_HIP_DEBUG("\n");

	if (msg == NULL) {
		HIP_ERROR("Message is NULL.\n");
		err = -EFAULT;
		goto out;
	}

	if (contents == NULL) {
		HIP_ERROR("Parameter contents to build is NULL.\n");
		err = -EFAULT;
		goto out;
	}

	if (param_hdr_size < sizeof(struct hip_tlv_common)) {
		HIP_ERROR("Size of the parameter build is too small.\n");
		err = -EMSGSIZE;
		goto out;
	}

	dst = hip_find_free_param(msg);
	if (dst == NULL) {
		err = -EMSGSIZE;
		HIP_ERROR("The message has no room for new parameters.\n");
		goto out;
	}

	_HIP_DEBUG("found free: %d\n", dst - ((void *)msg));

	if (dst + hip_get_param_total_len(param) > max_dst) {
		err = -EMSGSIZE;
		_HIP_DEBUG("dst == %d\n",dst);
		HIP_ERROR("The parameter to build does not fit in the message "\
			  "because if the parameter would be appended to "\
			  "the message, maximum HIP packet length would be "\
			  "exceeded.\n",
			  hip_get_param_contents_len(param));
		goto out;
	}

	/* copy header */
	src = (void *) param;
	size = param_hdr_size;
	memcpy(dst, src, size);

	/* copy contents  */
	dst += param_hdr_size;
	src = (void *) contents;
	/* Copy the right amount of contents, see jokela draft for TLV
	   format. For example, this skips the algo in struct hip_sig2
           (which is included in the length), see the
	   build_param_signature2_contents() function below. */
	size = hip_get_param_contents_len(param) -
		(param_hdr_size - sizeof(struct hip_tlv_common));
	memcpy(dst, src, size);

	_HIP_DEBUG("contents copied %d bytes\n", size);

	/* we have to update header length or otherwise hip_find_free_param
	   will fail when it checks the header length */
	hip_calc_hdr_len(msg);
	if (hip_get_msg_total_len(msg) == 0) {
		HIP_ERROR("Could not calculate temporary header length.\n");
		err = -EFAULT;
	}

	_HIP_DEBUG("dumping msg, len = %d\n", hip_get_msg_total_len(msg));
	_HIP_HEXDUMP("build msg: ", (void *) msg,
		     hip_get_msg_total_len(msg));
 out:

	return err;
}

/**
 * Builds and appends parameter contents into message
 *
 * This function differs from hip_build_generic_param only because it
 * assumes that the parameter header is just sizeof(struct hip_tlv_common).
 * This function updates the message header length to keep the next free
 * parameter slot quickly accessible for faster writing of the parameters.
 * This function automagically adds zero filled paddign to the parameter,
 * to keep its total length in multiple of 8 bytes.
 *
 * @param msg           the message where the parameter will be appended.
 * @param contents      the data after the type and length fields.
 * @param param_type    the type of the parameter (in host byte order).
 * @param contents_size the size of contents (in host byte order).
 * @return              zero on success, or negative on error.
 * @see                 hip_build_generic_param().
 * @see                 hip_build_param().
 */
int hip_build_param_contents(struct hip_common *msg,
			     const void *contents,
			     hip_tlv_type_t param_type,
			     hip_tlv_len_t contents_size)
{
	struct hip_tlv_common param;
	hip_set_param_type(&param, param_type);
	hip_set_param_contents_len(&param, contents_size);
	return hip_build_generic_param(msg, &param,
				       sizeof(struct hip_tlv_common),
				       contents);
}


/**
 * Appends a complete parameter into a HIP message.
 *
 * Appends a complete network byte ordered parameter @c tlv_common into a HIP
 * message @c msg. This function differs from hip_build_param_contents() and
 * hip_build_generic_param() because it takes a complete network byte ordered
 * parameter as its input. It means that this function can be used for e.g.
 * copying a parameter from a message to another.
 *
 * This function updates the message header length to keep the next free
 * parameter slot quickly accessible for faster writing of the parameters. This
 * function automagically adds zero filled paddign to the parameter, to keep its
 * total length in multiple of 8 bytes.
 *
 * @param msg        a pointer to a message where the parameter will be
 *                   appended.
 * @param tlv_common a pointer to the network byte ordered parameter that will
 *                   be appended into the message.
 * @return           zero on success, or negative error value on error.
 * @see              hip_build_generic_param().
 * @see              hip_build_param_contents().
 */
int hip_build_param(struct hip_common *msg, const void *tlv_common)
{
	int err = 0;
	void *contents = ((void *) tlv_common) + sizeof(struct hip_tlv_common);

	if (tlv_common == NULL) {
		err = -EFAULT;
		HIP_ERROR("param null\n");
		goto out;
	}

	err = hip_build_param_contents(msg, contents,
		       hip_get_param_type(tlv_common),
				       hip_get_param_contents_len(tlv_common));
        _HIP_DEBUG("tlv_common len %d\n", ((struct hip_tlv_common *)tlv_common)->length);
	if (err) {
		HIP_ERROR("could not build contents (%d)\n", err);
	}

 out:
	return err;
}

/**
 * @brief request for a response from user message or not
 *
 * @param msg user message
 * @param on 1 if requesting for a response, otherwise 0
 */
void hip_set_msg_response(struct hip_common *msg, uint8_t on) {
	msg->payload_proto = on;
}

/**
 * @brief check if the user message requires response
 *
 * @param msg user message
 * @return 1 if message requires response, other 0
 */
uint8_t hip_get_msg_response(struct hip_common *msg) {
	return msg->payload_proto;
}

/**
 * @brief Builds a header for userspace-kernel communication.
 *
 * This function builds the header that can be used for HIP kernel-userspace
 * communication. It is commonly used by the daemon, hipconf, resolver or
 * the kernel module itself. This function can be called before or after
 * building the parameters for the message.
 *
 * This function does not write the header length into the message. It should
 * be written by the build_param_functions.
 *
 * @param msg       the message where the userspace header is to be written.
 * @param base_type the type of the message.
 * @param err_val   a positive error value to be communicated for the receiver
 *                  (usually just zero for no errors).
 * @return          zero on success, or negative on error.
 */
int hip_build_user_hdr(struct hip_common *msg, hip_hdr_type_t base_type,
		       hip_hdr_err_t err_val)
{
	int err = 0;

	_HIP_DEBUG("\n");

	/* notice that msg->payload_proto is reserved for
	   hip_set_msg_response() */

	hip_set_msg_type(msg, base_type);
	hip_set_msg_err(msg, err_val);
	/* Note: final header length is usually calculated by the
	   last call to build_param() but it is possible to build a
	   msg with just the header, so we have to calculate the
	   header length anyway. */
	hip_calc_hdr_len(msg);
	if (hip_get_msg_total_len(msg) == 0) {
		err = -EMSGSIZE;
		goto out;
	}

	/* some error checking on types and for null values */

	if (!msg) {
		err = -EINVAL;
		HIP_ERROR("msg null\n");
		goto out;
	}
	if (hip_get_msg_total_len(msg) == 0) {
		HIP_ERROR("hipd build hdr: could not calc size\n");
		err = -EMSGSIZE;
		goto out;
	}

	if (!hip_check_user_msg_len(msg)) {
		HIP_ERROR("hipd build hdr: msg len (%d) invalid\n",
			  hip_get_msg_total_len(msg));
		err = -EMSGSIZE;
		goto out;
	}

 out:
	return err;
}

/**
 * Writes a network header into a message.
 *
 * This function does not write the header length into the message. It should
 * be written by the build_param_functions. The checksum field is not written
 * either because it is done in hip_send_raw() and hip_send_udp().
 *
 * @param msg          the message where the HIP network should be written
 * @param type_hdr     the type of the HIP header as specified in the drafts
 * @param control      HIP control bits in host byte order
 * @param hit_sender   source HIT in network byte order
 * @param hit_receiver destination HIT in network byte order
 * @todo build HIP network header in the same fashion as in build_daemon_hdr().
 * <ul>
 * <li>Write missing headers in the header using accessor functions
 * (see hip_get/set_XXX() functions in the beginning of this file). You have to
 * create couple of new ones, but daemon and network messages use the same
 * locations for storing len and type (hip_common->err is stored in the
 * hip_common->checksum) and they can be used as they are.</li>
 * <li>payload_proto.</li>
 * <li>payload_len: see how build_daemon_hdr() works.</li>
 * <li>ver_res.</li>
 * <li>checksum (move the checksum function from hip.c to this file
 *     because this file is shared by kernel and userspace).</li>
 * <li>write the parameters of this function into the message.</li>
 * </ul>
 * @note Use @b only accessors to hide byte order and size conversion issues!
 */
void hip_build_network_hdr(struct hip_common *msg, uint8_t type_hdr,
			   uint16_t control, const struct in6_addr *hit_sender,
			   const struct in6_addr *hit_receiver)
{
	msg->payload_proto = IPPROTO_NONE; /* 1 byte, no htons()    */
	/* Do not touch the length; it is written by param builders */
	msg->type_hdr = type_hdr;              /* 1 byte, no htons()    */
	/* version includes the SHIM6 bit */
	msg->ver_res = (HIP_VER_RES << 4) | 1;   /* 1 byte, no htons() */

	msg->control = htons(control);
	msg->checksum = htons(0); /* this will be written by xmit */

	ipv6_addr_copy(&msg->hits, hit_sender ? hit_sender : &in6addr_any);
	ipv6_addr_copy(&msg->hitr, hit_receiver ? hit_receiver : &in6addr_any);
}

#ifndef __KERNEL__
/**
 * Builds a @c HMAC parameter.
 *
 * Builds a @c HMAC parameter to the HIP packet @c msg. This function calculates
 * also the hmac value from the whole message as specified in the drafts.
 *
 * @param msg a pointer to the message where the @c HMAC parameter will be
 *            appended.
 * @param key a pointer to a key used for hmac.
 * @param param_type HIP_PARAM_HMAC, HIP_PARAM_RELAY_HMAC or HIP_PARAM_RVS_HMAC accordingly
 * @return    zero on success, or negative error value on error.
 * @see       hip_build_param_hmac2_contents()
 * @see       hip_write_hmac().
 */
int hip_build_param_hmac(struct hip_common *msg,
			 struct hip_crypto_key *key,
                         hip_tlv_type_t param_type)
{
	int err = 0;
	struct hip_hmac hmac;

	hip_set_param_type(&hmac, param_type);
	hip_calc_generic_param_len(&hmac, sizeof(struct hip_hmac), 0);

	HIP_IFEL(hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, msg,
				hip_get_msg_total_len(msg),
				hmac.hmac_data), -EFAULT,
		 "Error while building HMAC\n");

	err = hip_build_param(msg, &hmac);
 out_err:
	return err;
}

/**
 * Builds a @c HIP_PARAM_HMAC parameter
 *
 * Builds a @c HIP_PARAM_HMAC parameter to the HIP packet @c msg. This function calculates
 * also the hmac value from the whole message as specified in the drafts.
 *
 * @param msg a pointer to the message where the @c HMAC parameter will be
 *            appended.
 * @param key a pointer to a key used for hmac.
 * @return    zero on success, or negative error value on error.
 * @see       hip_build_param_hmac_contents()
 */
int hip_build_param_hmac_contents(struct hip_common *msg,
			 struct hip_crypto_key *key)
{

	return hip_build_param_hmac(msg, key, HIP_PARAM_HMAC);
};

int hip_create_msg_pseudo_hmac2(const struct hip_common *msg,
				struct hip_common *msg_copy,
				struct hip_host_id *host_id) {
	struct hip_tlv_common_t *param = NULL;
	int err = 0;

	HIP_HEXDUMP("host id", host_id,
		    hip_get_param_total_len(host_id));

	memcpy(msg_copy, msg, sizeof(struct hip_common));
	hip_set_msg_total_len(msg_copy, 0);
	hip_zero_msg_checksum(msg_copy);

	/* copy parameters to a temporary buffer to calculate
	   pseudo-hmac (includes the host id) */
	while((param = hip_get_next_param(msg, param)) &&
	      hip_get_param_type(param) < HIP_PARAM_HMAC2) {
		HIP_IFEL(hip_build_param(msg_copy, param), -1,
			 "Failed to build param\n");
	}

	HIP_IFEL(hip_build_param(msg_copy, host_id), -1,
		 "Failed to append pseudo host id to R2\n");

 out_err:
	return err;
}

/**
 * Builds a @c HMAC2 parameter.
 *
 * Builds a @c HMAC2 parameter to the HIP packet @c msg. This function
 * calculates also the hmac value from the whole message as specified in the
 * drafts. Assumes that the hmac includes only the header and host id.
 *
 * @param msg      a pointer to the message where the @c HMAC2 parameter will be
 *                 appended.
 * @param key      a pointer to a key used for hmac.
 * @param host_id  a pointer to a host id.
 * @return         zero on success, or negative error value on error.
 * @see            hip_build_param_hmac_contents().
 * @see            hip_write_hmac().
 */
int hip_build_param_hmac2_contents(struct hip_common *msg,
				   struct hip_crypto_key *key,
				   struct hip_host_id *host_id)
{
	struct hip_hmac hmac2;
	struct hip_common *msg_copy = NULL;
	int err = 0;

	HIP_IFEL(!(msg_copy = hip_msg_alloc()), -ENOMEM, "Message alloc\n");

	_HIP_HEXDUMP("HMAC data", msg_copy, hip_get_msg_total_len(msg_copy));
	_HIP_HEXDUMP("HMAC key\n", key->key, 20);

	HIP_IFEL(hip_create_msg_pseudo_hmac2(msg, msg_copy, host_id), -1,
		 "pseudo hmac pkt failed\n");

	hip_set_param_type(&hmac2, HIP_PARAM_HMAC2);
	hip_calc_generic_param_len(&hmac2, sizeof(struct hip_hmac), 0);

	HIP_IFEL(hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, msg_copy,
				hip_get_msg_total_len(msg_copy),
				hmac2.hmac_data), -EFAULT,
		 "Error while building HMAC\n");

	err = hip_build_param(msg, &hmac2);
 out_err:
	if (msg_copy)
		HIP_FREE(msg_copy);

	return err;
}

/**
 * Calculates the checksum of a HIP packet with pseudo-header.
 *
 * @c src and @c dst are IPv4 or IPv6 addresses in network byte order.
 *
 * @param data a pointer to...
 * @param src  a pointer to...
 * @param dst  a pointer to...
 * @note       Checksumming is from Boeing's HIPD.
 * @return     ...
 */
u16 hip_checksum_packet(char *data, struct sockaddr *src, struct sockaddr *dst)
{
	u16 checksum = 0;
	unsigned long sum = 0;
	int count = 0, length = 0;
	unsigned short *p = NULL; /* 16-bit */
	struct pseudo_header pseudoh;
	struct pseudo_header6 pseudoh6;
	u32 src_network, dst_network;
	struct in6_addr *src6, *dst6;
	struct hip_common *hiph = (struct hip_common *) data;

	if (src->sa_family == AF_INET) {
		/* IPv4 checksum based on UDP-- Section 6.1.2 */
		src_network = ((struct sockaddr_in*)src)->sin_addr.s_addr;
		dst_network = ((struct sockaddr_in*)dst)->sin_addr.s_addr;

		memset(&pseudoh, 0, sizeof(struct pseudo_header));
		memcpy(&pseudoh.src_addr, &src_network, 4);
		memcpy(&pseudoh.dst_addr, &dst_network, 4);
		pseudoh.protocol = IPPROTO_HIP;
		length = (hiph->payload_len + 1) * 8;
		pseudoh.packet_length = htons(length);

		count = sizeof(struct pseudo_header); /* count always even number */
		p = (unsigned short*) &pseudoh;
	} else {
		/* IPv6 checksum based on IPv6 pseudo-header */
		src6 = &((struct sockaddr_in6*)src)->sin6_addr;
		dst6 = &((struct sockaddr_in6*)dst)->sin6_addr;

		memset(&pseudoh6, 0, sizeof(struct pseudo_header6));
		memcpy(&pseudoh6.src_addr[0], src6, 16);
		memcpy(&pseudoh6.dst_addr[0], dst6, 16);
		length = (hiph->payload_len + 1) * 8;
		pseudoh6.packet_length = htonl(length);
		pseudoh6.next_hdr = IPPROTO_HIP;

		count = sizeof(struct pseudo_header6); /* count always even number */
		p = (unsigned short*) &pseudoh6;
	}
	/*
	 * this checksum algorithm can be found
	 * in RFC 1071 section 4.1
	 */

	/* sum the pseudo-header */
	/* count and p are initialized above per protocol */
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}

	/* one's complement sum 16-bit words of data */
	HIP_DEBUG("Checksumming %d bytes of data.\n", length);
	count = length;
	p = (unsigned short*) data;
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */
	checksum = ~sum;

	return(checksum);
}

int hip_verify_network_header(struct hip_common *hip_common,
			      struct sockaddr *src, struct sockaddr *dst,
			      int len)
{
	int err = 0, plen, checksum;

	plen = hip_get_msg_total_len(hip_common);

        /* Currently no support for piggybacking */
        HIP_IFEL(len != hip_get_msg_total_len(hip_common), -EINVAL,
		 "Invalid HIP packet length (%d,%d). Dropping\n",
		 len, plen);
        HIP_IFEL(hip_common->payload_proto != IPPROTO_NONE, -EOPNOTSUPP,
		 "Protocol in packet (%u) was not IPPROTO_NONE. Dropping\n",
		 hip_common->payload_proto);
	HIP_IFEL(hip_common->ver_res != ((HIP_VER_RES << 4) | 1), -EPROTOTYPE,
		 "Invalid version in received packet. Dropping\n");

	HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a non-HIT in HIT-source. Dropping\n");
	HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hitr) &&
		 !ipv6_addr_any(&hip_common->hitr),
		 -EAFNOSUPPORT,
		 "Received a non-HIT or non NULL in HIT-receiver. Dropping\n");

	HIP_IFEL(ipv6_addr_any(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a NULL in HIT-sender. Dropping\n");

        /** @todo handle the RVS case better. */
        if (ipv6_addr_any(&hip_common->hitr)) {
                /* Required for e.g. BOS */
                HIP_DEBUG("Received opportunistic HIT\n");
	} else {
#ifdef CONFIG_HIP_RVS
                HIP_DEBUG("Received HIT is ours or we are RVS\n");
#elif HIPL_HIPD
		HIP_IFEL(!hip_hidb_hit_is_our(&hip_common->hitr), -EFAULT,
			 "Receiver HIT is not ours\n");
#endif /* CONFIG_HIP_RVS */
	}

#if 0
        HIP_IFEL(!ipv6_addr_cmp(&hip_common->hits, &hip_common->hitr), -ENOSYS,
		 "Dropping HIP packet. Loopback not supported.\n");
#endif

        /* Check checksum. */
        HIP_DEBUG("dst port is %d  \n", ((struct sockaddr_in *)dst)->sin_port);
	if (dst->sa_family == AF_INET && ((struct sockaddr_in *)dst)->sin_port) {
		HIP_DEBUG("HIP IPv4 UDP packet: ignoring HIP checksum\n");
	} else {
		checksum = hip_common->checksum;
		hip_common->checksum = 0;

		HIP_IFEL(hip_checksum_packet((char*)hip_common, src, dst)
			 !=checksum,
			 -EBADMSG, "HIP checksum failed.\n");

		hip_common->checksum = checksum;
	}

out_err:
        return err;
}

#endif /* __KERNEL__ */

/**
 * hip_build_param_encrypted_aes_sha1 - build the hip_encrypted parameter
 * @param msg the message where the parameter will be appended
 * @param param the parameter that will contained in the hip_encrypted
 *           parameter
 *
 * Note that this function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 *
 * Returns: zero on success, or negative on failure
 */
int hip_build_param_encrypted_aes_sha1(struct hip_common *msg,
					struct hip_tlv_common *param)
{
	int rem, err = 0;
	struct hip_encrypted_aes_sha1 enc;
	int param_len = hip_get_param_total_len(param);
	struct hip_tlv_common *common = param;
	char *param_padded = NULL;

	hip_set_param_type(&enc, HIP_PARAM_ENCRYPTED);
	enc.reserved = htonl(0);
	memset(&enc.iv, 0, 16);

	/* copy the IV *IF* needed, and then the encrypted data */

	/* AES block size must be multiple of 16 bytes */
	rem = param_len % 16;
	if (rem) {
		HIP_DEBUG("Adjusting param size to AES block size\n");

		param_padded = (char *)HIP_MALLOC(param_len + rem, GFP_KERNEL);
		if (!param_padded) {
			err = -ENOMEM;
			goto out_err;
		}

		/* this kind of padding works against Ericsson/OpenSSL
		   (method 4: RFC2630 method) */
		/* http://www.di-mgt.com.au/cryptopad.html#exampleaes */
		memcpy(param_padded, param, param_len);
		memset(param_padded + param_len, rem, rem);

		common = (struct hip_tlv_common *) param_padded;
		param_len += rem;
	}

	hip_calc_param_len(&enc, sizeof(enc) -
			   sizeof(struct hip_tlv_common) +
			   param_len);

	err = hip_build_generic_param(msg, &enc, sizeof(enc), common);

 out_err:

	if (param_padded)
		HIP_FREE(param_padded);

	return err;
}

/**
 * hip_build_param_signature2_contents - build HIP signature2
 * @param msg the message
 * @param contents pointer to the signature contents (the data to be written
 *                 after the signature field)
 * @param contents_size size of the contents of the signature (the data after the
 *                 algorithm field)
 * @param algorithm the algorithm as in the HIP drafts that was used for
 *                 producing the signature
 *
 * build_param_contents() is not very suitable for building a hip_sig2 struct,
 * because hip_sig2 has a troublesome algorithm field which need some special
 * attention from htons(). Thereby here is a separate builder for hip_sig2 for
 * conveniency. It uses internally hip_build_generic_param() for actually
 * writing the signature parameter into the message.
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_signature2_contents(struct hip_common *msg,
					const void *contents,
					hip_tlv_len_t contents_size,
					uint8_t algorithm)
{
	/* note: if you make changes in this function, make them also in
	   build_param_signature_contents(), because it is almost the same */

	int err = 0;
	struct hip_sig2 sig2;

	HIP_ASSERT(sizeof(struct hip_sig2) >= sizeof(struct hip_tlv_common));

	hip_set_param_type(&sig2, HIP_PARAM_HIP_SIGNATURE2);
	hip_calc_generic_param_len(&sig2, sizeof(struct hip_sig2),
				   contents_size);
	sig2.algorithm = algorithm; /* algo is 8 bits, no htons */

	err = hip_build_generic_param(msg, &sig2,
				      sizeof(struct hip_sig2), contents);

	return err;
}

/**
 * hip_build_param_signature_contents - build HIP signature1
 * @param msg the message
 * @param contents pointer to the signature contents (the data to be written
 *                 after the signature field)
 * @param contents_size size of the contents of the signature (the data after the
 *                 algorithm field)
 * @param algorithm the algorithm as in the HIP drafts that was used for
 *                 producing the signature
 *
 * This is almost the same as the previous, but the type is sig1.
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_signature_contents(struct hip_common *msg,
				       const void *contents,
				       hip_tlv_len_t contents_size,
				       uint8_t algorithm)
{
	/* note: if you make changes in this function, make them also in
	   build_param_signature_contents2(), because it is almost the same */

	int err = 0;
	struct hip_sig sig;

	HIP_ASSERT(sizeof(struct hip_sig) >= sizeof(struct hip_tlv_common));

	hip_set_param_type(&sig, HIP_PARAM_HIP_SIGNATURE);
	hip_calc_generic_param_len(&sig, sizeof(struct hip_sig),
				   contents_size);
	sig.algorithm = algorithm; /* algo is 8 bits, no htons */

	err = hip_build_generic_param(msg, &sig,
				      sizeof(struct hip_sig), contents);

	return err;
}

/**
 * hip_build_param_echo - build HIP ECHO parameter
 * @param msg the message
 * @param opaque opaque data copied to the parameter
 * @param len      the length of the parameter
 * @param sign true if parameter is under signature, false otherwise
 * @param request true if parameter is ECHO_REQUEST, otherwise parameter is ECHO_RESPONSE
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_echo(struct hip_common *msg, void *opaque, int len,
			 int sign, int request)
{
	struct hip_echo_request ping;
	int err;

	if (request)
		hip_set_param_type(&ping, sign ? HIP_PARAM_ECHO_REQUEST_SIGN : HIP_PARAM_ECHO_REQUEST);
	else
		hip_set_param_type(&ping, sign ? HIP_PARAM_ECHO_RESPONSE_SIGN : HIP_PARAM_ECHO_RESPONSE);

	hip_set_param_contents_len(&ping, len);
	err = hip_build_generic_param(msg, &ping, sizeof(struct hip_echo_request),
				      opaque);
	return err;
}

/**
 * hip_build_param_r1_counter - build HIP R1_COUNTER parameter
 * @param msg the message
 * @param generation R1 generation counter
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_r1_counter(struct hip_common *msg, uint64_t generation)
{
	struct hip_r1_counter r1gen;
	int err = 0;

	/* note: the length cannot be calculated with calc_param_len() */
	hip_set_param_contents_len(&r1gen,
				   sizeof(struct hip_r1_counter) -
				   sizeof(struct hip_tlv_common));
	/* Type 2 (in R1) or 3 (in I2) */
	hip_set_param_type(&r1gen, HIP_PARAM_R1_COUNTER);

	r1gen.reserved = 0;

	r1gen.generation = hton64(generation);

	err = hip_build_param(msg, &r1gen);
	return err;
}

/**
 * Builds a @c FROM parameter.
 *
 * Builds a @c FROM parameter to the HIP packet @c msg.
 *
 * @param msg      a pointer to a HIP packet common header
 * @param addr     a pointer to an IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param not_used this parameter is not used, but it is needed to make the
 *                 parameter list uniform with hip_build_param_relay_from().
 * @return         zero on success, or negative error value on error.
 * @see            <a href="http://tools.ietf.org/wg/hip/draft-ietf-hip-rvs/draft-ietf-hip-rvs-05.txt">
 *                 draft-ietf-hip-rvs-05</a> section 4.2.2.
 */
int hip_build_param_from(struct hip_common *msg, const struct in6_addr *addr,
			 const in_port_t not_used)
{
	struct hip_from from;
	int err = 0;

	hip_set_param_type(&from, HIP_PARAM_FROM);
	memcpy((struct in6_addr *)&from.address, addr, 16);

	hip_calc_generic_param_len(&from, sizeof(struct hip_from), 0);
	err = hip_build_param(msg, &from);
	return err;
}

/**
 * Builds a @c RELAY_FROM parameter.
 *
 * Builds a @c RELAY_FROM parameter to the HIP packet @c msg.
 *
 * @param msg  a pointer to a HIP packet common header
 * @param addr a pointer to an IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param port port number (host byte order).
 * @return     zero on success, or negative error value on error.
 */
int hip_build_param_relay_from(struct hip_common *msg, const struct in6_addr *addr,
			     const in_port_t port)
{
	struct hip_relay_from relay_from;
	int err = 0;

	hip_set_param_type(&relay_from, HIP_PARAM_RELAY_FROM);
	ipv6_addr_copy((struct in6_addr *)&relay_from.address, addr);
	relay_from.port = htons(port);
	relay_from.reserved = 0;
	relay_from.protocol = HIP_NAT_PROTO_UDP;
	hip_calc_generic_param_len(&relay_from, sizeof(relay_from), 0);
	err = hip_build_param(msg, &relay_from);

	return err;
}

/**
 * Builds a @c VIA_RVS parameter.
 *
 * Builds a @c VIA_RVS parameter to the HIP packet @c msg.
 *
 * @param msg           a pointer to a HIP packet common header
 * @param rvs_addresses a pointer to rendezvous server IPv6 or IPv4-in-IPv6
 *                      format IPv4 addresses.
 * @return              zero on success, or negative error value on error.
 * @see                 <a href="http://tools.ietf.org/wg/hip/draft-ietf-hip-rvs/draft-ietf-hip-rvs-05.txt">
 *                      draft-ietf-hip-rvs-05</a> section 4.2.3.
 */
int hip_build_param_via_rvs(struct hip_common *msg,
			    const struct in6_addr rvs_addresses[])
{
	HIP_DEBUG("hip_build_param_rvs() invoked.\n");
	int err = 0;
	struct hip_via_rvs viarvs;

	hip_set_param_type(&viarvs, HIP_PARAM_VIA_RVS);
	hip_calc_generic_param_len(&viarvs, sizeof(struct hip_via_rvs),
				   sizeof(struct in6_addr));
	err = hip_build_generic_param(msg, &viarvs, sizeof(struct hip_via_rvs),
				      (void *)rvs_addresses);
	return err;
}

/**
 * Builds a @c RELAY_TO parameter.
 *
 * Builds a @c RELAY_TO parameter to the HIP packet @c msg.
 *
 * @param msg  a pointer to a HIP packet common header
 * @param addr a pointer to IPv6 address
 * @param port portnumber
 * @return     zero on success, or negative error value on error.
 * @note       This used to be VIA_RVS_NAT, but because of the HIP-ICE
 *             draft, this is now RELAY_TO.
 */
int hip_build_param_relay_to(struct hip_common *msg,
			     const in6_addr_t *addr,
			     const in_port_t port)
{
     struct hip_relay_to relay_to;
     int err = 0;

     hip_set_param_type(&relay_to, HIP_PARAM_RELAY_TO);
     ipv6_addr_copy((struct in6_addr *)&relay_to.address, addr);
     relay_to.port = htons(port);
     relay_to.reserved = 0;
     relay_to.protocol = HIP_NAT_PROTO_UDP;
     
     hip_calc_generic_param_len(&relay_to, sizeof(relay_to), 0);
     err = hip_build_param(msg, &relay_to);

     return err;

}

/* NOTE! Keep this function before REG_REQUEST and REG_RESPONSE parameter
 * builders but after hip_calc_generic_param_len() and
 * hip_build_generic_param. */
/**
 * Builds REG_REQUEST and REG_RESPONSE parameters common parts. This function is
 * called from hip_build_param_reg_request() and hip_build_param_reg_response(),
 * and should not be called from anywhere else.
 *
 * @param msg        a pointer to a HIP message where to build the parameter.
 * @param param      a pointer to the parameter to be appended to the HIP
 *                   message @c msg.
 * @param lifetime   the lifetime to be put into the parameter.
 * @param type_list  a pointer to an array containing the registration types to
 *                   be put into the parameter.
 * @param type_count number of registration types in @c type_list.
 * @return           zero on success, non-zero otherwise.
 * @note             This is an static inline function that has no prototype in
 *                   the header file. There is no prototype because this
 *                   function is not to be called outside this file.
 */
static inline int hip_reg_param_core(hip_common_t *msg, void *param,
				     const uint8_t lifetime,
				     const uint8_t *type_list,
				     const int type_count)
{
	struct hip_reg_request *rreq = (struct hip_reg_request *) param;

	hip_calc_generic_param_len(rreq, sizeof(struct hip_reg_request),
				   type_count * sizeof(uint8_t));
	rreq->lifetime = lifetime;

	return hip_build_generic_param(msg, rreq, sizeof(struct hip_reg_request),
				       type_list);
}

/* gcc gives a weird warning if we use struct srv in the arguments of this function.
   Using void pointer as a workaround */
int hip_build_param_reg_info(hip_common_t *msg,
			     const void *srv_list,
			     const unsigned int service_count)
{
	int err = 0, i = 0;
	const struct hip_srv *service_list = (const struct hip_srv *) srv_list;
	struct hip_reg_info reg_info;
	uint8_t reg_type[service_count];

	if(service_count == 0) {
		return 0;
	}
	HIP_DEBUG("Building REG_INFO parameter(s) \n");

	for( ;i < service_count; i++) {
		if(service_list[0].min_lifetime !=
		   service_list[i].min_lifetime ||
		   service_list[0].max_lifetime !=
		   service_list[i].max_lifetime) {
			HIP_INFO("Warning! Multiple min and max lifetime "\
				 "values for a single REG_INFO parameter "\
				 "requested. Using lifetime values from "\
				 "service reg_type %d with all services.\n",
				 service_list[0].reg_type);
			break;
		}

	}

	for(i = 0; i < service_count; i++) {
		reg_type[i] = service_list[i].reg_type;
	}

	_HIP_HEXDUMP("reg_type", reg_type, service_count);

	hip_set_param_type(&reg_info, HIP_PARAM_REG_INFO);
	/* All services should have the same lifetime... */
	reg_info.min_lifetime = service_list[0].min_lifetime;
	reg_info.max_lifetime = service_list[0].max_lifetime;
	hip_calc_generic_param_len(&reg_info, sizeof(struct hip_reg_info),
				   service_count * sizeof(service_list[0].reg_type));

	err = hip_build_generic_param(
		msg, &reg_info, sizeof(struct hip_reg_info), (void *)reg_type);

	_HIP_DEBUG("Added REG_INFO parameter with %u service%s.\n", service_count,
		   (service_count > 1) ? "s" : "");

	return err;
}

int hip_build_param_reg_request(hip_common_t *msg, const uint8_t lifetime,
				const uint8_t *type_list, const int type_count)
{
	int err = 0;
	struct hip_reg_request rreq;

	hip_set_param_type(&rreq, HIP_PARAM_REG_REQUEST);
	err = hip_reg_param_core(msg, &rreq, lifetime, type_list, type_count);

	return err;
}

int hip_build_param_reg_response(hip_common_t *msg, const uint8_t lifetime,
				 const uint8_t *type_list, const int type_count)
{
	int err = 0;
	struct hip_reg_response rres;

	hip_set_param_type(&rres, HIP_PARAM_REG_RESPONSE);
	err = hip_reg_param_core(msg, &rres, lifetime, type_list, type_count);

	return err;
}

/**
 * hip_build_param_reg_failed - build HIP REG_FAILED parameter
 * @param msg the message
 * @param failure_type reason for failure
 * @param type_list list of types to be appended
 * @param cnt number of addresses in type_list
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_reg_failed(struct hip_common *msg, uint8_t failure_type,
			       uint8_t *type_list, int type_count)
{
	int err = 0;
	struct hip_reg_failed reg_failed;

	if(type_count == 0) {
		return 0;
	}

	hip_set_param_type(&reg_failed, HIP_PARAM_REG_FAILED);

	reg_failed.failure_type = failure_type;
	hip_calc_generic_param_len(&reg_failed, sizeof(struct hip_reg_failed),
				   type_count * sizeof(type_list[0]));

	err = hip_build_generic_param(
		msg, &reg_failed, sizeof(struct hip_reg_failed), (void *)type_list);

	HIP_DEBUG("Added REG_FAILED parameter with %u service%s.\n", type_count,
		  (type_count > 1) ? "s" : "");

	return err;

}

/**
 * hip_build_param_puzzle - build and append a HIP puzzle into the message
 * @param msg the message where the puzzle is to be appended
 * @param val_K the K value for the puzzle
 * @param lifetime lifetime field of the puzzle
 * @param opaque the opaque value for the puzzle
 * @param random_i random I value for the puzzle (in host byte order)
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_puzzle(struct hip_common *msg, uint8_t val_K,
			   uint8_t lifetime, uint32_t opaque, uint64_t random_i)
{
	struct hip_puzzle puzzle;
	int err = 0;

	/* note: the length cannot be calculated with calc_param_len() */
	hip_set_param_contents_len(&puzzle,
				   sizeof(struct hip_puzzle) -
				   sizeof(struct hip_tlv_common));
	/* Type 2 (in R1) or 3 (in I2) */
	hip_set_param_type(&puzzle, HIP_PARAM_PUZZLE);

	/* only the random_j_k is in host byte order */
	puzzle.K = val_K;
	puzzle.lifetime = lifetime;
	puzzle.opaque[0] = opaque & 0xFF;
	puzzle.opaque[1] = (opaque & 0xFF00) >> 8;
	/* puzzle.opaque[2] = (opaque & 0xFF0000) >> 16; */
	puzzle.I = random_i;

    err = hip_build_generic_param(msg, &puzzle,
			      sizeof(struct hip_tlv_common),
			      hip_get_param_contents_direct(&puzzle));
	return err;

}

/**
 * hip_build_param_solution - build and append a HIP solution into the message
 * @param msg the message where the solution is to be appended
 * @param pz values from the corresponding puzzle copied to the solution
 * @param val_J J value for the solution (in host byte order)
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_solution(struct hip_common *msg, struct hip_puzzle *pz,
			     uint64_t val_J)
{
	struct hip_solution cookie;
	int err = 0;

	/* note: the length cannot be calculated with calc_param_len() */
	hip_set_param_contents_len(&cookie,
				   sizeof(struct hip_solution) -
				   sizeof(struct hip_tlv_common));
	/* Type 2 (in R1) or 3 (in I2) */
	hip_set_param_type(&cookie, HIP_PARAM_SOLUTION);

	cookie.J = hton64(val_J);
	memcpy(&cookie.K, &pz->K, 12); /* copy: K (1), reserved (1),
					  opaque (2) and I (8 bytes). */
	cookie.reserved = 0;
        err = hip_build_generic_param(msg, &cookie,
				      sizeof(struct hip_tlv_common),
				      hip_get_param_contents_direct(&cookie));
	return err;
}
#ifndef __KERNEL__
/**
 * hip_build_param_diffie_hellman_contents - build HIP DH contents,
 *        with one or two public values.
 * @param msg the message where the DH parameter will be appended
 * @param group_id1 the group id of the first DH parameter
 *                  as specified in the drafts
 * @param pubkey1 the public key part of the first DH
 * @param pubkey_len1 length of the first public key part
 * @param group_id2 the group id of the second DH parameter,
 *        should be HIP_MAX_DH_GROUP_ID if there is only one DH key
 * @param pubkey2 the public key part of the second DH
 * @param pubkey_len2 length of the second public key part
 *
 * @return zero on success, or non-zero on error
 */
int hip_build_param_diffie_hellman_contents(struct hip_common *msg,
	      uint8_t group_id1, void *pubkey1, hip_tlv_len_t pubkey_len1,
	      uint8_t group_id2, void *pubkey2, hip_tlv_len_t pubkey_len2)
{
	int err = 0;
	struct hip_diffie_hellman diffie_hellman;
	uint8_t *value = NULL, *value_tmp = NULL;
	hip_tlv_len_t pubkey_len = pubkey_len1 + sizeof(uint8_t) +
	                           sizeof(uint16_t) + pubkey_len2;
	uint16_t tmp_pubkey_len2 = 0;


	HIP_ASSERT(pubkey_len >= sizeof(struct hip_tlv_common));

	_HIP_ASSERT(sizeof(struct hip_diffie_hellman) == 5);

	hip_set_param_type(&diffie_hellman, HIP_PARAM_DIFFIE_HELLMAN);

	if(group_id2 != HIP_MAX_DH_GROUP_ID)
	     pubkey_len = pubkey_len1 + sizeof(uint8_t) +
	                  sizeof(uint16_t) + pubkey_len2;
	else
	     pubkey_len = pubkey_len1;

	/* Allocating memory for the "value" packet */
	HIP_IFEL(!(value = value_tmp = HIP_MALLOC((pubkey_len), GFP_ATOMIC)),
	     -1, "Failed to alloc memory for value\n");

	hip_calc_generic_param_len(&diffie_hellman,
				   sizeof(struct hip_diffie_hellman),
				   pubkey_len);
	diffie_hellman.pub_val.group_id = group_id1; /* 1 byte, no htons() */
	diffie_hellman.pub_val.pub_len = htons(pubkey_len1);

	if(group_id2 != HIP_MAX_DH_GROUP_ID){
	     /* Creating "value" by joining the first and second DH values */
	     HIP_DEBUG("group_id2 = %d, htons(pubkey_len2)= %d\n",
		       group_id2, htons(pubkey_len2));

	     memcpy(value_tmp, pubkey1, pubkey_len1);
	     value_tmp += pubkey_len1;
	     *value_tmp++ = group_id2;
	     tmp_pubkey_len2 = htons(pubkey_len2);
	     memcpy(&value_tmp, &tmp_pubkey_len2, sizeof(uint16_t));
	     value_tmp += sizeof(uint16_t);
	     memcpy(value_tmp, pubkey2, pubkey_len2);
	}else
	     memcpy(value_tmp, pubkey1, pubkey_len1);

	err = hip_build_generic_param(msg, &diffie_hellman,
				      sizeof(struct hip_diffie_hellman),
				      value);

	_HIP_HEXDUMP("Own DH pubkey: ", pubkey, pubkey_len);

  out_err:

 	if (value)
 		HIP_FREE(value);

	return err;
}
#endif
/**
 * hip_get_transform_max - find out the maximum number of transform suite ids
 * @param transform_type the type of the transform
 *
 * @return the number of suite ids that can be used for transform_type
 */
uint16_t hip_get_transform_max(hip_tlv_type_t transform_type)
{
	uint16_t transform_max = 0;

	switch (transform_type) {
	case HIP_PARAM_HIP_TRANSFORM:
		transform_max = HIP_TRANSFORM_HIP_MAX;
		break;
	case HIP_PARAM_ESP_TRANSFORM:
		transform_max = HIP_TRANSFORM_ESP_MAX;
		break;
	default:
		HIP_ERROR("Unknown transform type %d\n", transform_type);
	}

	return transform_max;

}

/**
 * hip_build_param_transform - build an HIP or ESP transform
 * @param msg the message where the parameter will be appended
 * @param transform_type HIP_PARAM_HIP_TRANSFORM or HIP_PARAM_ESP_TRANSFORM
 *                       in host byte order
 * @param transform_suite an array of transform suite ids in host byte order
 * @param transform_count number of transform suites in transform_suite (in host
 *                        byte order)
 *
 * @return zero on success, or negative on error
 */
int hip_build_param_transform(struct hip_common *msg,
			      const hip_tlv_type_t transform_type,
			      const hip_transform_suite_t transform_suite[],
			      const uint16_t transform_count)
{
	int err = 0;
	uint16_t i;
	uint16_t transform_max;
	struct hip_any_transform transform_param;

	transform_max = hip_get_transform_max(transform_type);

	if (!(transform_type == HIP_PARAM_ESP_TRANSFORM ||
	      transform_type == HIP_PARAM_HIP_TRANSFORM)) {
		err = -EINVAL;
		HIP_ERROR("Invalid transform type %d\n", transform_type);
		goto out_err;
	}

	/* Check that the maximum number of transforms is not overflowed */
	if (transform_max > 0 && transform_count > transform_max) {
		err = -E2BIG;
		HIP_ERROR("Too many transforms (%d) for type %d.\n",
			  transform_count, transform_type);
		goto out_err;
	}

	if (transform_type == HIP_PARAM_ESP_TRANSFORM) {
		((struct hip_esp_transform *)&transform_param)->reserved = 0;
	}

	/* Copy and convert transforms to network byte order. */
	for(i = 0; i < transform_count; i++) {
		if (transform_type == HIP_PARAM_ESP_TRANSFORM) {
			((struct hip_esp_transform *)&transform_param)->suite_id[i] = htons(transform_suite[i]);
		} else {
			((struct hip_hip_transform *)&transform_param)->suite_id[i] = htons(transform_suite[i]);
		}
	}

	hip_set_param_type(&transform_param, transform_type);
	if (transform_type == HIP_PARAM_ESP_TRANSFORM) {
		hip_calc_param_len(&transform_param,
				   2+transform_count * sizeof(hip_transform_suite_t));
	} else {
		hip_calc_param_len(&transform_param,
				   transform_count * sizeof(hip_transform_suite_t));
	}
	err = hip_build_param(msg, &transform_param);

 out_err:
	return err;
}

/**
 * @brief Gets a suite id from a transform structure.
 *
 * @param transform_tlv a pointer to a transform structure
 * @param index         the index of the suite ID in transform_tlv
 * @return              the suite id on transform_tlv on index
 * @todo                Remove index and rename.
 */
hip_transform_suite_t hip_get_param_transform_suite_id(
	const void *transform_tlv, const uint16_t index)
{
	/** @todo Why do we have hip_select_esp_transform separately? */

        /* RFC 5201 chapter 6.9.:
           The I2 MUST have a single value in the HIP_TRANSFORM parameter,
	   which MUST match one of the values offered to the Initiator in
	   the R1 packet. Does this function check this?
	   -Lauri 01.08.2008. */
	hip_tlv_type_t type;
 	uint16_t supported_hip_tf[] = { HIP_HIP_NULL_SHA1,
 					HIP_HIP_3DES_SHA1,
 					HIP_HIP_AES_SHA1};
 	uint16_t supported_esp_tf[] = { HIP_ESP_NULL_SHA1,
 					HIP_ESP_3DES_SHA1,
 					HIP_ESP_AES_SHA1 };
 	uint16_t *table = NULL;
 	uint16_t *tfm;
 	int table_n = 0, pkt_tfms = 0, i;

 	_HIP_DEBUG("tfm len = %d\n", hip_get_param_contents_len(transform_tlv));

 	type = hip_get_param_type(transform_tlv);
 	if (type == HIP_PARAM_HIP_TRANSFORM) {
		table = supported_hip_tf;
		table_n = sizeof(supported_hip_tf)/sizeof(uint16_t);
		tfm = (void *)transform_tlv+sizeof(struct hip_tlv_common);
		pkt_tfms = hip_get_param_contents_len(transform_tlv)/sizeof(uint16_t);
 	} else if (type == HIP_PARAM_ESP_TRANSFORM) {
		table = supported_esp_tf;
		table_n = sizeof(supported_esp_tf)/sizeof(uint16_t);
		tfm = (void *)transform_tlv+sizeof(struct hip_tlv_common)+sizeof(uint16_t);
		pkt_tfms = (hip_get_param_contents_len(transform_tlv)-sizeof(uint16_t))/sizeof(uint16_t);
 	} else {
		HIP_ERROR("Invalid type %u\n", type);
		return 0;
 	}

 	for (i = 0; i < pkt_tfms; i++, tfm++) {
 		int j;
 		_HIP_DEBUG("testing pkt tfm=%u\n", ntohs(*tfm));
 		for (j = 0; j < table_n; j++) {
 			if (ntohs(*tfm) == table[j]) {
 				_HIP_DEBUG("found supported tfm %u, pkt tlv index of tfm=%d\n",
 					  table[j], i);
 				return table[j];
 			}
 		}
 	}
 	HIP_ERROR("Usable suite not found.\n");

 	return 0;
}

#ifndef __KERNEL__
/**
 * hip_build_param_locator - build HIP locator parameter
 *
 * @param msg the message where the REA will be appended
 * @param addresses list of addresses
 * @param address_count number of addresses
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_locator(struct hip_common *msg,
			struct hip_locator_info_addr_item *addresses,
			int address_count)
{
	int err = 0;
	struct hip_locator *locator_info = NULL;
	int addrs_len = address_count *
		(sizeof(struct hip_locator_info_addr_item));

	HIP_IFE(!(locator_info =
		  malloc(sizeof(struct hip_locator) + addrs_len)), -1);

	hip_set_param_type(locator_info, HIP_PARAM_LOCATOR);
	hip_calc_generic_param_len(locator_info,
				   sizeof(struct hip_locator),
				   addrs_len);
	_HIP_DEBUG("params size=%d\n", sizeof(struct hip_locator) -
		   sizeof(struct hip_tlv_common) +
		   addrs_len);

	memcpy(locator_info + 1, addresses, addrs_len);
	HIP_IFE(hip_build_param(msg, locator_info), -1);

	_HIP_DEBUG("msgtotlen=%d addrs_len=%d\n", hip_get_msg_total_len(msg),
		   addrs_len);
	//if (addrs_len > 0)
	//	memcpy((void *)msg+hip_get_msg_total_len(msg)-addrs_len,
	//	       addresses, addrs_len);

 out_err:
	if (locator_info)
		free(locator_info);
	return err;
}
#endif /* !__KERNEL__ */

/**
 * hip_build_param_keys - build and append crypto keys parameter
 * \addtogroup params
 * @{ \todo Properly comment parameters of hip_build_param_keys() @}
 * @param msg the message where the parameter will be appended
 * @param operation_id no description
 * @param alg_id no desription
 * @param addr no description
 * @param hit no description
 * @param spi no description
 * @param spi_old no description
 * @param key_len no description
 * @param enc encryption key
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_keys(struct hip_common *msg, uint16_t operation_id,
						uint16_t alg_id, struct in6_addr *addr,
						struct in6_addr *hit, struct in6_addr *peer_hit, uint32_t spi, uint32_t spi_old,
						uint16_t key_len, struct hip_crypto_key *enc)
{
	int err = 0;
	struct hip_keys keys;

	hip_set_param_type(&keys, HIP_PARAM_KEYS);
	hip_calc_generic_param_len(&keys, sizeof(struct hip_keys), 0);


	memcpy((struct in6_addr *)&keys.address, addr, 16);
	memcpy((struct in6_addr *)&keys.hit, hit, 16);
        memcpy((struct in6_addr *)&keys.peer_hit, peer_hit, 16);
	keys.operation = htons(operation_id);
	keys.alg_id = htons(alg_id);
	keys.spi = htonl(spi);
	keys.spi_old = htonl(spi_old);
	keys.key_len = htons(key_len);
	memcpy(&keys.enc, enc, sizeof(struct hip_crypto_key));

	err = hip_build_param(msg, &keys);
	return err;
}

int hip_build_param_keys_hdr(struct hip_keys *keys, uint16_t operation_id,
						uint16_t alg_id, struct in6_addr *addr,
						struct in6_addr *hit, struct in6_addr *peer_hit, uint32_t spi, uint32_t spi_old,
						uint16_t key_len, struct hip_crypto_key *enc)
{
	int err = 0;

	hip_set_param_type(keys, HIP_PARAM_KEYS);
	hip_calc_generic_param_len(keys, sizeof(struct hip_keys), 0);

	memcpy((struct in6_addr *)keys->address, addr, 16);
	memcpy((struct in6_addr *)keys->hit, hit, 16);
        memcpy((struct in6_addr *)keys->peer_hit, peer_hit, 16);
	keys->operation = htons(operation_id);
	keys->alg_id = htons(alg_id);
	keys->spi = htonl(spi);
	keys->spi_old = htonl(spi_old);
	keys->key_len = htons(key_len);
	memcpy(&keys->enc, enc, sizeof(struct hip_crypto_key));

	return err;
}

/**
 * hip_build_param_seq - build and append HIP SEQ parameter
 * @param msg the message where the parameter will be appended
 * @param update_id Update ID
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_seq(struct hip_common *msg, uint32_t update_id)
{
	int err = 0;
	struct hip_seq seq;

	hip_set_param_type(&seq, HIP_PARAM_SEQ);
	hip_calc_generic_param_len(&seq, sizeof(struct hip_seq), 0);
	seq.update_id = htonl(update_id);
	err = hip_build_param(msg, &seq);
	return err;
}

/**
 * hip_build_param_ack - build and append HIP ACK parameter
 * @param msg the message where the parameter will be appended
 * @param peer_update_id peer Update ID
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_ack(struct hip_common *msg, uint32_t peer_update_id)
{
        int err = 0;
        struct hip_ack ack;

        hip_set_param_type(&ack, HIP_PARAM_ACK);
        hip_calc_generic_param_len(&ack, sizeof(struct hip_ack), 0);
        ack.peer_update_id = htonl(peer_update_id);
        err = hip_build_param(msg, &ack);
        return err;
}
#ifndef __KERNEL__
/**
 * hip_build_param_esp_prot_mode - build and append ESP PROT transform parameter
 * @param msg the message where the parameter will be appended
 * @param transform the transform to be used for the esp extension header
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_esp_prot_transform(struct hip_common *msg, int num_transforms,
		uint8_t *transforms)
{
	struct esp_prot_preferred_tfms prot_transforms;
	int err = 0, i;

	hip_set_param_type(&prot_transforms, HIP_PARAM_ESP_PROT_TRANSFORMS);

	/* note: the length cannot be calculated with calc_param_len() */
	hip_set_param_contents_len(&prot_transforms, (num_transforms + 1) * sizeof(uint8_t));

	prot_transforms.num_transforms = num_transforms;
	HIP_DEBUG("added num_transforms: %u\n", prot_transforms.num_transforms);

	for (i = 0; i < prot_transforms.num_transforms; i++)
	{
		prot_transforms.transforms[i] = transforms[i];
		HIP_DEBUG("added transform %i: %u\n", i + 1, transforms[i]);
	}

	err = hip_build_generic_param(msg, &prot_transforms,
						      sizeof(struct hip_tlv_common),
						      hip_get_param_contents_direct(&prot_transforms));

	return err;
}

/**
 * hip_build_param_esp_prot_mode - build and append ESP PROT anchor parameter
 * @param msg the message where the parameter will be appended
 * @param transform the esp protection transform used for this anchor,
 *        if UNUSED 1 byte of 0 is sent
 * @param anchor the anchor for the hchain to be used for extended esp protection,
 *        if NULL
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_esp_prot_anchor(struct hip_common *msg, uint8_t transform,
		unsigned char *active_anchor, unsigned char *next_anchor, int hash_length,
		int hash_item_length)
{
	int err = 0;
	//unsigned char *anchors = NULL;
	struct esp_prot_anchor esp_anchor;

	HIP_ASSERT(msg != NULL);
	// NULL-active_anchor only allowed for UNUSED-transform
	HIP_ASSERT((!transform && !active_anchor) || (transform && active_anchor));
	// next_anchor might be NULL

	// set parameter type
	hip_set_param_type(&esp_anchor, HIP_PARAM_ESP_PROT_ANCHOR);

	// set parameter values
	esp_anchor.transform = transform;
	esp_anchor.hash_item_length = htonl(hash_item_length);

	// distinguish UNUSED from any other case
	if (!transform)
	{
		// send 1 byte of 0 per anchor in UNUSED case
		hash_length = 1;

		memset(&esp_anchor.anchors[0], 0, hash_length);
		memset(&esp_anchor.anchors[hash_length], 0, hash_length);

	} else
	{
		memcpy(&esp_anchor.anchors[0], active_anchor, hash_length);

		// send 0 if next_anchor not present
		if (next_anchor != NULL)
			memcpy(&esp_anchor.anchors[hash_length], next_anchor, hash_length);
		else
			memset(&esp_anchor.anchors[hash_length], 0, hash_length);
	}

	hip_set_param_contents_len(&esp_anchor, sizeof(uint8_t) + sizeof(uint32_t) +
			2 * hash_length);

	err = hip_build_generic_param(msg, &esp_anchor,
					      sizeof(struct hip_tlv_common),
					      hip_get_param_contents_direct(&esp_anchor));

	HIP_DEBUG("added esp protection transform: %u\n", transform);
	HIP_DEBUG("added hash item length: %u\n", hash_item_length);
	HIP_HEXDUMP("added esp protection active_anchor: ", &esp_anchor.anchors[0],
			hash_length);
	HIP_HEXDUMP("added esp protection next_anchor: ",
			&esp_anchor.anchors[hash_length], hash_length);

	return err;
}
#endif
/**
 * hip_build_param_unit_test - build and insert an unit test parameter
 * @param msg the message where the parameter will be appended
 * @param suiteid the id of the test suite
 * @param caseid the id of the test case
 *
 * This parameter is used for triggering the unit test suite in the kernel.
 * It is only for implementation internal purposes only.
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_unit_test(struct hip_common *msg, uint16_t suiteid,
			      uint16_t caseid)
{
	int err = 0;
	struct hip_unit_test ut;

	hip_set_param_type(&ut, HIP_PARAM_UNIT_TEST);
	hip_calc_generic_param_len(&ut, sizeof(struct hip_unit_test), 0);
	ut.suiteid = htons(suiteid);
	ut.caseid = htons(caseid);

	err = hip_build_param(msg, &ut);
	return err;
}

int hip_build_param_esp_prot_branch(struct hip_common *msg, int anchor_offset,
		int branch_length, unsigned char *branch_nodes)
{
	int err = 0;
	struct esp_prot_branch branch;

	HIP_ASSERT(msg != NULL);
	HIP_ASSERT(anchor_offset >= 0);
	HIP_ASSERT(branch_length > 0);
	HIP_ASSERT(branch_nodes != NULL);

	// set parameter type
	hip_set_param_type(&branch, HIP_PARAM_ESP_PROT_BRANCH);

	// set parameter values
	branch.anchor_offset = htonl(anchor_offset);
	branch.branch_length = htonl(branch_length);
	memcpy(&branch.branch_nodes[0], branch_nodes, branch_length);

	hip_set_param_contents_len(&branch, 2 * sizeof(uint32_t) + branch_length);

	err = hip_build_generic_param(msg, &branch,
					      sizeof(struct hip_tlv_common),
					      hip_get_param_contents_direct(&branch));

	HIP_DEBUG("added esp anchor offset: %u\n", branch.anchor_offset);
	HIP_DEBUG("added esp branch length: %u\n", branch.branch_length);
	HIP_HEXDUMP("added esp branch: ", &branch.branch_nodes[0], branch_length);

	return err;
}

int hip_build_param_esp_prot_secret(struct hip_common *msg, int secret_length,
		unsigned char *secret)
{
	int err = 0;
	struct esp_prot_secret esp_secret;

	HIP_ASSERT(msg != NULL);
	HIP_ASSERT(secret_length > 0);
	HIP_ASSERT(secret != NULL);

	// set parameter type
	hip_set_param_type(&esp_secret, HIP_PARAM_ESP_PROT_SECRET);

	// set parameter values
	esp_secret.secret_length = secret_length;
	memcpy(&esp_secret.secret[0], secret, secret_length);

	hip_set_param_contents_len(&esp_secret, sizeof(uint8_t) + secret_length);

	err = hip_build_generic_param(msg, &esp_secret,
					      sizeof(struct hip_tlv_common),
					      hip_get_param_contents_direct(&esp_secret));

	HIP_DEBUG("added esp secret length: %u\n", esp_secret.secret_length);
	HIP_HEXDUMP("added esp secret: ", &esp_secret.secret[0], secret_length);

	return err;
}

int hip_build_param_esp_prot_root(struct hip_common *msg, uint8_t root_length,
		unsigned char *root)
{
	int err = 0;
	struct esp_prot_root esp_root;

	HIP_ASSERT(msg != NULL);
	HIP_ASSERT(root_length > 0);
	HIP_ASSERT(root != NULL);

	// set parameter type
	hip_set_param_type(&esp_root, HIP_PARAM_ESP_PROT_ROOT);

	// set parameter values
	esp_root.root_length = root_length;
	memcpy(&esp_root.root[0], root, root_length);

	hip_set_param_contents_len(&esp_root, sizeof(uint8_t) + root_length);

	err = hip_build_generic_param(msg, &esp_root,
					      sizeof(struct hip_tlv_common),
					      hip_get_param_contents_direct(&esp_root));

	HIP_DEBUG("added esp root length: %u\n", esp_root.root_length);
	HIP_HEXDUMP("added esp root: ", &esp_root.root[0], root_length);

	return err;
}

/**
 * hip_build_param_esp_info - build esp_info parameter
 * \addtogroup params
 * @{ \todo Properly comment parameters of hip_build_param_esp_info() @}
 *
 * @param msg the message where the parameter will be appended
 * @param keymat_index no desription
 * @param old_spi no description
 * @param new_spi no description
 *
 * @return zero on success, or negative on failure
 */
int hip_build_param_esp_info(struct hip_common *msg, uint16_t keymat_index,
			     uint32_t old_spi, uint32_t new_spi)
{
	int err = 0;
	struct hip_esp_info esp_info;
	_HIP_DEBUG("Add SPI old: 0x%x (nwbo: 0x%x), new: 0x%x (nwbo: 0x%x)\n",
		old_spi, htonl(old_spi), new_spi, htonl(new_spi));
	hip_set_param_type(&esp_info, HIP_PARAM_ESP_INFO);
	hip_calc_generic_param_len(&esp_info, sizeof(struct hip_esp_info), 0);
	esp_info.reserved = htonl(0);
	esp_info.keymat_index = htons(keymat_index);
	esp_info.old_spi = htonl(old_spi);
	esp_info.new_spi = htonl(new_spi);
	_HIP_DEBUG("esp param old: 0x%x , new: 0x%x \n",
		  esp_info.old_spi, esp_info.new_spi);

	_HIP_DEBUG("keymat index = %d\n", keymat_index);
	_HIP_HEXDUMP("esp_info:", &esp_info, sizeof(struct hip_esp_info));
	err = hip_build_param(msg, &esp_info);
	return err;
}

#if 0
/**
 * hip_build_param_spi - build the SPI parameter
 * @param msg the message where the parameter will be appended
 * @param lsi the value of the lsi (in host byte order)
 * @param spi the value of the spi (in host byte order)
 *
 * XX FIXME: Obsoleted by esp_info in draft-jokela-hip-00
 *
 * @return zero on success, or negative on failure
 */
int hip_build_param_spi(struct hip_common *msg, uint32_t spi)
{
        int err = 0;
        struct hip_spi hspi;

        hip_set_param_type(&hspi, HIP_PARAM_ESP_INFO);
        hip_calc_generic_param_len(&hspi, sizeof(struct hip_spi), 0);
        hspi.spi = htonl(spi);

        err = hip_build_param(msg, &hspi);
        return err;
}
#endif


/**
 *
 */
/*int hip_build_param_encrypted(struct hip_common *msg,
					struct hip_tlv_common *param)
{
	//TODO
	return 0;
}*/


/**
 * hip_build_param_encrypted_3des_sha1 - build the hip_encrypted parameter
 * @param msg the message where the parameter will be appended
 * @param param the parameter that will contained in the hip_encrypted
 *           parameter
 *
 * Note that this function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 *
 * Returns: zero on success, or negative on failure
 */
int hip_build_param_encrypted_3des_sha1(struct hip_common *msg,
					struct hip_tlv_common *param)
{
	int err = 0;
	struct hip_encrypted_3des_sha1 enc;

	hip_set_param_type(&enc, HIP_PARAM_ENCRYPTED);
	hip_calc_param_len(&enc, sizeof(enc) -
			   sizeof(struct hip_tlv_common) +
			   hip_get_param_total_len(param));
	enc.reserved = htonl(0);
	memset(&enc.iv, 0, 8);

	/* copy the IV *IF* needed, and then the encrypted data */

	err = hip_build_generic_param(msg, &enc, sizeof(enc), param);

	return err;
}

/**
 * hip_build_param_encrypted_null_sha1 - build the hip_encrypted parameter
 * @param msg the message where the parameter will be appended
 * @param param the parameter that will contained in the hip_encrypted
 *           parameter
 *
 * Note that this function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 *
 * Returns: zero on success, or negative on failure
 */
int hip_build_param_encrypted_null_sha1(struct hip_common *msg,
 					struct hip_tlv_common *param)
{
	int err = 0;
 	struct hip_encrypted_null_sha1 enc;

 	hip_set_param_type(&enc, HIP_PARAM_ENCRYPTED);
 	hip_calc_param_len(&enc, sizeof(enc) -
 			   sizeof(struct hip_tlv_common) +
 			   hip_get_param_total_len(param));
 	enc.reserved = htonl(0);

 	/* copy the IV *IF* needed, and then the encrypted data */

 	err = hip_build_generic_param(msg, &enc, sizeof(enc), param);

 	return err;
}

void hip_build_param_host_id_hdr(struct hip_host_id *host_id_hdr,
				 const char *hostname,
				 hip_tlv_len_t rr_data_len,
                                 uint8_t algorithm)
{
	uint16_t hi_len = sizeof(struct hip_host_id_key_rdata) + rr_data_len;
	uint16_t fqdn_len;
        /* reserve 1 byte for NULL termination */
	if (hostname)
		fqdn_len = (strlen(hostname) + 1) & 0x0FFF;
	else
		fqdn_len = 0;

	host_id_hdr->hi_length = htons(hi_len);
	/* length = 12 bits, di_type = 4 bits */
	host_id_hdr->di_type_length = htons(fqdn_len | 0x1000);
	/* if the length is 0, then the type should also be zero */
	if (host_id_hdr->di_type_length == ntohs(0x1000))
		host_id_hdr->di_type_length = 0;

        hip_set_param_type(host_id_hdr, HIP_PARAM_HOST_ID);
        hip_calc_generic_param_len(host_id_hdr, sizeof(struct hip_host_id),
				   hi_len -
				   sizeof(struct hip_host_id_key_rdata) +
				   fqdn_len);

        host_id_hdr->rdata.flags = htons(0x0202); /* key is for a host */

	/* RFC 4034 obsoletes RFC 2535 and flags field differ */
        host_id_hdr->rdata.protocol = 0xFF; /* RFC 2535 */
	/* algo is 8 bits, no htons */
        host_id_hdr->rdata.algorithm = algorithm;

	_HIP_DEBUG("hilen=%d totlen=%d contlen=%d\n",
		   ntohs(host_id_hdr->hi_length),
		   hip_get_param_contents_len(host_id_hdr),
		   hip_get_param_total_len(host_id_hdr));
}

void hip_build_param_host_id_only(struct hip_host_id *host_id,
				    const void *rr_data,
				    const char *fqdn)
{
	unsigned int rr_len = ntohs(host_id->hi_length) -
		sizeof(struct hip_host_id_key_rdata);
	char *ptr = (char *) (host_id + 1);
	uint16_t fqdn_len;

	_HIP_DEBUG("hi len: %d\n", ntohs(host_id->hi_length));
	_HIP_DEBUG("Copying %d bytes\n", rr_len);

	memcpy(ptr, rr_data, rr_len);
	ptr += rr_len;

	fqdn_len = ntohs(host_id->di_type_length) & 0x0FFF;
	_HIP_DEBUG("fqdn len: %d\n", fqdn_len);
	if (fqdn_len)
		memcpy(ptr, fqdn, fqdn_len);
}

/**
 * hip_build_param_host_id - build and append host id into message
 * \addtogroup params
 * @{ \todo Comment parameters of hip_build_param_host_id() @}
 *
 */
int hip_build_param_host_id(struct hip_common *msg,
			    struct hip_host_id *host_id_hdr,
			    const void *rr_data,
			    const char *fqdn)
{
	int err = 0;
	hip_build_param_host_id_only(host_id_hdr, rr_data, fqdn);
        err = hip_build_param(msg, host_id_hdr);
	return err;
}

int hip_get_param_host_id_di_type_len(struct hip_host_id *host, char **id, int *len)
{
	int type;
	static char *debuglist[3] = {"none", "FQDN", "NAI"};

	type = ntohs(host->di_type_length);
	*len = type & 0x0FFF;
	type = (type & 0xF000) >> 12;

	if (type > 2) {
		HIP_ERROR("Illegal DI-type: %d\n",type);
		return -1;
	}

	*id = debuglist[type];
	return 0;
}

char *hip_get_param_host_id_hostname(struct hip_host_id *hostid)
{
	int hilen;
	char *ptr;

	hilen = ntohs(hostid->hi_length) - sizeof(struct hip_host_id_key_rdata);
	_HIP_DEBUG("Hilen: %d\n",hilen);
	ptr = (char *)(hostid + 1) + hilen;
	return ptr;
}

/*
 * - endpoint is not padded
 */
void hip_build_endpoint_hdr(struct endpoint_hip *endpoint_hdr,
			    const char *hostname,
			    se_hip_flags_t endpoint_flags,
			    uint8_t host_id_algo,
			    unsigned int rr_data_len)
{
	hip_build_param_host_id_hdr(&endpoint_hdr->id.host_id,
				    hostname, rr_data_len, host_id_algo);
	endpoint_hdr->family = PF_HIP;
	/* The length is not hip-length-padded, so it has be calculated
	   manually. sizeof(hip_host_id) is already included both in the
	   sizeof(struct endpoint_hip) and get_total_len(), so it has be
	   subtracted once. */
	endpoint_hdr->length = sizeof(struct endpoint_hip) +
		hip_get_param_total_len(&endpoint_hdr->id.host_id) -
		sizeof(struct hip_host_id);
	endpoint_hdr->flags = endpoint_flags;
	endpoint_hdr->algo = host_id_algo;
	_HIP_DEBUG("%d %d %d\n",
		  sizeof(struct endpoint_hip),
		  hip_get_param_total_len(&endpoint_hdr->id.host_id),
		  sizeof(struct hip_host_id));
	_HIP_DEBUG("endpoint hdr length: %d\n", endpoint_hdr->length);
}

/*
 * - endpoint is not padded
 * - caller is responsible of reserving enough mem for endpoint
 */
void hip_build_endpoint(struct endpoint_hip *endpoint,
			const struct endpoint_hip *endpoint_hdr,
			const char *hostname,
			const unsigned char *key_rr,
			unsigned int key_rr_len)
{
	_HIP_DEBUG("len=%d ep=%d rr=%d hostid=%d\n",
		  endpoint_hdr->length,
		  sizeof(struct endpoint_hip),
		  key_rr_len,
		  sizeof(struct hip_host_id));
	HIP_ASSERT(endpoint_hdr->length == sizeof(struct endpoint_hip) +
		   hip_get_param_total_len(&endpoint_hdr->id.host_id) -
		   sizeof(struct hip_host_id));
	memcpy(endpoint, endpoint_hdr, sizeof(struct endpoint_hip));
	hip_build_param_host_id_only(&endpoint->id.host_id, key_rr, hostname);
}

int hip_build_param_eid_endpoint_from_host_id(struct hip_common *msg,
					      const struct endpoint_hip *endpoint)
{
	int err = 0;

	HIP_ASSERT(!(endpoint->flags & HIP_ENDPOINT_FLAG_HIT));

	err = hip_build_param_contents(msg, endpoint, HIP_PARAM_EID_ENDPOINT,
				       endpoint->length);
	return err;
}

int hip_build_param_eid_endpoint_from_hit(struct hip_common *msg,
					  const struct endpoint_hip *endpoint)
{
	struct hip_eid_endpoint eid_endpoint;
	int err = 0;

	HIP_ASSERT(endpoint->flags & HIP_ENDPOINT_FLAG_HIT);

	hip_set_param_type(&eid_endpoint, HIP_PARAM_EID_ENDPOINT);

	hip_calc_param_len(&eid_endpoint,
			   sizeof(struct hip_eid_endpoint) -
			   sizeof (struct hip_tlv_common));

	memcpy(&eid_endpoint.endpoint, endpoint, sizeof(struct endpoint_hip));

	err = hip_build_param(msg, &eid_endpoint);

	return err;
}

/*
 * hip_build_param_eid_endpoint - build eid endpoint parameter
 * @param msg the message where the eid endpoint paramater will be appended
 * @param endpoint the endpoint to be wrapped into the eid endpoint structure
 * @param port the dst/src port used for the endpoint
 *
 * Used for passing endpoints to the kernel. The endpoint is wrapped into
 * an eid endpoint structure because endpoint_hip is not padded but all
 * parameter need to be padded in the builder interface.
 */
int hip_build_param_eid_endpoint(struct hip_common *msg,
				 const struct endpoint_hip *endpoint)
{
	int err = 0;

	if (endpoint->flags & HIP_ENDPOINT_FLAG_HIT) {
		err = hip_build_param_eid_endpoint_from_hit(msg, endpoint);
	} else {
		err = hip_build_param_eid_endpoint_from_host_id(msg, endpoint);
	}

	return err;
}

int hip_host_id_entry_to_endpoint(struct hip_host_id_entry *entry,
				  void *opaq)
{
	struct hip_common *msg = (struct hip_common *) opaq;
	struct endpoint_hip endpoint;
	int err = 0;

	endpoint.family = PF_HIP;
	endpoint.length = sizeof(struct endpoint_hip);

	/* struct endpoint flags were incorrectly assigned directly from
	   entry->lhi.anonymous. entry->lhi.anonymous is a boolean value while
	   endpoint.flags is a binary flag value. The entry lhi.anonymous should
	   be converted to binary flag to avoid this kind of mistakes.
	   -Lauri 18.07.2008 */
	if(entry->lhi.anonymous == 0) {
		endpoint.flags = HIP_ENDPOINT_FLAG_PUBKEY;
	}else if(entry->lhi.anonymous) {
		endpoint.flags = HIP_ENDPOINT_FLAG_ANON;
	}else {
		endpoint.flags = HIP_ENDPOINT_FLAG_HIT;
	}
	//endpoint.flags  = entry->lhi.anonymous;
	/* Next line is useless see couple of lines further --SAMU */
	//endpoint.algo   = entry->lhi.algo;
	endpoint.algo   = hip_get_host_id_algo(entry->host_id);
	ipv6_addr_copy(&endpoint.id.hit, &entry->lhi.hit);
	ipv4_addr_copy(&endpoint.lsi, &entry->lsi);

	HIP_IFEL(hip_build_param_eid_endpoint(msg, &endpoint), -1,
		 "Error when building parameter HIP_PARAM_EID_ENDPOINT.\n");

  out_err:
	return err;
}

int hip_build_param_eid_iface(struct hip_common *msg,
			      hip_eid_iface_type_t if_index)
{
	int err = 0;
	struct hip_eid_iface param;

	hip_set_param_type(&param, HIP_PARAM_EID_IFACE);
	hip_calc_generic_param_len(&param, sizeof(param), 0);
	param.if_index = htons(if_index);
	err = hip_build_param(msg, &param);

	return err;
}

int hip_build_param_eid_sockaddr(struct hip_common *msg,
                                 struct sockaddr *sockaddr,
                                 size_t sockaddr_len)
{
        int err = 0;
	_HIP_DEBUG("build family=%d, len=%d\n", sockaddr->sa_family,
		   sockaddr_len);
        err = hip_build_param_contents(msg, sockaddr, HIP_PARAM_EID_SOCKADDR,
                                       sockaddr_len);
        return err;
}

/**
 * Builds a NOTIFICATION parameter.
 *
 * @param msg              a pointer to the message where the parameter will be
 *                         appended
 * @param msgtype          NOTIFY message type
 * @param notification     the Notification data that will contained in the HIP
 *                         NOTIFICATION parameter
 * @param notification_len length of @c notification_data
 *
 * @return zero on success, or negative on failure
 */
int hip_build_param_notification(struct hip_common *msg, uint16_t msgtype,
				 void *data, size_t data_len)
{
	int err = 0;
	struct hip_notification notification;

	hip_set_param_type(&notification, HIP_PARAM_NOTIFICATION);
	hip_calc_param_len(&notification, sizeof(struct hip_notification) -
			   sizeof(struct hip_tlv_common) +
			   data_len);
	notification.reserved = 0;
	notification.msgtype = htons(msgtype);

	err = hip_build_generic_param(msg, &notification,
				      sizeof(struct hip_notification),
				      data);
	return err;
}

int hip_build_netlink_dummy_header(struct hip_common *msg)
{
	return hip_build_user_hdr(msg, SO_HIP_NETLINK_DUMMY, 0);
}

int hip_build_param_blind_nonce(struct hip_common *msg, uint16_t nonce)
{
	struct hip_blind_nonce param;
	int err = 0;

	hip_set_param_type(&param, HIP_PARAM_BLIND_NONCE);
	hip_calc_generic_param_len(&param, sizeof(param), 0);
	param.nonce = htons(nonce);
	err = hip_build_param(msg, &param);

	return err;
}

int hip_build_param_heartbeat(struct hip_common *msg, int seconds) {
	int err = 0;
	struct hip_heartbeat heartbeat;
	hip_set_param_type(&heartbeat, HIP_PARAM_HEARTBEAT);
	hip_calc_param_len(&heartbeat, sizeof(struct hip_heartbeat) -
			   sizeof(struct hip_tlv_common));
	memcpy(&heartbeat.heartbeat, &seconds, sizeof(seconds));
	err = hip_build_param(msg, &heartbeat);

	return err;
}

int hip_build_param_transform_order(struct hip_common *msg,
                                int *order)
{
    int err = 0;
    struct hip_transformation_order transorder;
    hip_set_param_type(&transorder, HIP_PARAM_TRANSFORM_ORDER);
    hip_calc_param_len(&transorder,
                       sizeof(struct hip_transformation_order) -
                       sizeof(struct hip_tlv_common));
    transorder.transorder = order;
    err = hip_build_param(msg, &transorder);
 out_err:
    return err;
}

int hip_build_param_opendht_set(struct hip_common *msg,
                                char *name)
{
    int err = 0;
    struct hip_opendht_set name_info;
    hip_set_param_type(&name_info, HIP_PARAM_OPENDHT_SET);
    hip_calc_param_len(&name_info,
                       sizeof(struct hip_opendht_set) -
                       sizeof(struct hip_tlv_common));
    strcpy(&name_info.name, name);
    err = hip_build_param(msg, &name_info);

    return err;
}

int hip_build_param_opendht_gw_info(struct hip_common *msg,
				    struct in6_addr *addr,
				    uint32_t ttl,
				    uint16_t port,
				    char* host_name)
{
	int err = 0;
	struct hip_opendht_gw_info gw_info;

	hip_set_param_type(&gw_info, HIP_PARAM_OPENDHT_GW_INFO);
	hip_calc_param_len(&gw_info,
			   sizeof(struct hip_opendht_gw_info) -
			   sizeof(struct hip_tlv_common));
	gw_info.ttl = ttl;
	gw_info.port = htons(port);
	//added +1 because the \0 was not being copied at the end of the string
	memcpy(&gw_info.host_name, host_name, strlen(host_name) + 1);
	ipv6_addr_copy(&gw_info.addr, addr);
	err = hip_build_param(msg, &gw_info);
	return err;
}
#ifndef __KERNEL__
int hip_build_param_cert_spki_info(struct hip_common * msg,
				    struct hip_cert_spki_info * cert_info)
{
	int err = 0;
	struct hip_cert_spki_info local;
	memset(&local, '\0', sizeof(struct hip_cert_spki_info));
	memcpy(&local, cert_info, sizeof(struct hip_cert_spki_info));
	hip_set_param_type(&local, HIP_PARAM_CERT_SPKI_INFO);
	hip_calc_param_len(&local,
			   sizeof(struct hip_cert_spki_info) -
			   sizeof(struct hip_tlv_common));
	_HIP_DEBUG("Param len spki_info %d\n", htons(local.length));
	err = hip_build_param(msg, &local);
	return err;
}

int hip_build_param_cert_x509_req(struct hip_common * msg,
				    struct in6_addr * addr)
{
	int err = 0;
        struct hip_cert_x509_req subj;

        hip_set_param_type(&subj, HIP_PARAM_CERT_X509_REQ);
        hip_calc_param_len(&subj,
                           sizeof(struct hip_cert_x509_req) -
                           sizeof(struct hip_tlv_common));
        ipv6_addr_copy(&subj.addr, addr);
        err = hip_build_param(msg, &subj);
 out_err:
	return err;
}

int hip_build_param_cert_x509_ver(struct hip_common * msg,
                                  char * der, int len)
{
	int err = 0;
        struct hip_cert_x509_resp subj;

        hip_set_param_type(&subj, HIP_PARAM_CERT_X509_REQ);
        hip_calc_param_len(&subj,
                           sizeof(struct hip_cert_x509_resp) -
                           sizeof(struct hip_tlv_common));
        memcpy(&subj.der, der, len);
        subj.der_len = len;
        err = hip_build_param(msg, &subj);
 out_err:
	return err;
}

int hip_build_param_cert_x509_resp(struct hip_common * msg,
				    char * der, int len)
{
	int err = 0;
        struct hip_cert_x509_resp local;
	hip_set_param_type(&local, HIP_PARAM_CERT_X509_RESP);
	hip_calc_param_len(&local,
			   sizeof(struct hip_cert_x509_resp) -
			   sizeof(struct hip_tlv_common));
        memcpy(&local.der, der, len);
        local.der_len = len;
	err = hip_build_param(msg, &local);
 out_err:
	return err;
}

int hip_build_param_hip_hdrr_info(struct hip_common * msg,
				    struct hip_hdrr_info * hdrr_info)
{
	int err = 0;
	hip_set_param_type(hdrr_info, HIP_PARAM_HDRR_INFO);
	hip_calc_param_len(hdrr_info,
			   sizeof(struct hip_hdrr_info) -
			   sizeof(struct hip_tlv_common));
	err = hip_build_param(msg, hdrr_info);
	return err;
}

int hip_build_param_hip_uadb_info(struct hip_common *msg, struct hip_uadb_info *uadb_info)
{
	int err = 0;
	hip_set_param_type(uadb_info, HIP_PARAM_UADB_INFO);
	hip_calc_param_len(uadb_info,
			   sizeof(struct hip_uadb_info) -
			   sizeof(struct hip_tlv_common));
	err = hip_build_param(msg, uadb_info);
	return err;
}

int hip_build_param_hit_to_ip_set(struct hip_common *msg,
                                char *name)
{
    int err = 0;
    struct hip_hit_to_ip_set name_info;
    hip_set_param_type(&name_info, HIP_PARAM_HIT_TO_IP_SET);
    hip_calc_param_len(&name_info,
                       sizeof(struct hip_hit_to_ip_set) -
                       sizeof(struct hip_tlv_common));
    strcpy(name_info.name, name);
    err = hip_build_param(msg, &name_info);

    return err;
}

int dsa_to_hip_endpoint(DSA *dsa, struct endpoint_hip **endpoint,
			se_hip_flags_t endpoint_flags, const char *hostname)
{
  int err = 0;
  unsigned char *dsa_key_rr = NULL;
  int dsa_key_rr_len;
  struct endpoint_hip endpoint_hdr;

  _HIP_DEBUG("dsa_to_hip_endpoint called\n");

  dsa_key_rr_len = dsa_to_dns_key_rr(dsa, &dsa_key_rr);
  if (dsa_key_rr_len <= 0) {
    HIP_ERROR("dsa_key_rr_len <= 0\n");
    err = -ENOMEM;
    goto out_err;
  }

  /* build just an endpoint header to see how much memory is needed for the
     actual endpoint */
  hip_build_endpoint_hdr(&endpoint_hdr, hostname, endpoint_flags,
			 HIP_HI_DSA, dsa_key_rr_len);

  *endpoint = malloc(endpoint_hdr.length);
  if (!(*endpoint)) {
    err = -ENOMEM;
    goto out_err;
  }
  memset(*endpoint, 0, endpoint_hdr.length);

  _HIP_DEBUG("Allocated %d bytes for endpoint\n", endpoint_hdr.length);
  hip_build_endpoint(*endpoint, &endpoint_hdr, hostname,
		     dsa_key_rr, dsa_key_rr_len);
  _HIP_HEXDUMP("endpoint contains: ", *endpoint, endpoint_hdr.length);

 out_err:

  if (dsa_key_rr)
    free(dsa_key_rr);

  return err;
}

int rsa_to_hip_endpoint(RSA *rsa, struct endpoint_hip **endpoint,
			se_hip_flags_t endpoint_flags, const char *hostname)
{
  int err = 0;
  unsigned char *rsa_key_rr = NULL;
  int rsa_key_rr_len;
  struct endpoint_hip endpoint_hdr;

  HIP_DEBUG("rsa_to_hip_endpoint called\n");

  rsa_key_rr_len = rsa_to_dns_key_rr(rsa, &rsa_key_rr);
  if (rsa_key_rr_len <= 0) {
    HIP_ERROR("rsa_key_rr_len <= 0\n");
    err = -ENOMEM;
    goto out_err;
  }

  /* build just an endpoint header to see how much memory is needed for the
     actual endpoint */
  hip_build_endpoint_hdr(&endpoint_hdr, hostname, endpoint_flags,
			 HIP_HI_RSA, rsa_key_rr_len);

    *endpoint = malloc(endpoint_hdr.length);
  if (!(*endpoint)) {
    err = -ENOMEM;
    goto out_err;
  }
  memset(*endpoint, 0, endpoint_hdr.length);

  _HIP_DEBUG("Allocated %d bytes for endpoint\n", endpoint_hdr.length);

  hip_build_endpoint(*endpoint, &endpoint_hdr, hostname,
		     rsa_key_rr, rsa_key_rr_len);

  _HIP_HEXDUMP("endpoint contains: ", *endpoint, endpoint_hdr.length);

 out_err:

  if (rsa_key_rr)
    free(rsa_key_rr);

  return err;
}
#endif
int alloc_and_set_host_id_param_hdr(struct hip_host_id **host_id,
				    unsigned int key_rr_len,
				    uint8_t algo,
				    const char *hostname)
{
  int err = 0;
  struct hip_host_id host_id_hdr;
  hip_build_param_host_id_hdr(&host_id_hdr, hostname,
			      key_rr_len, algo);

  *host_id = HIP_MALLOC(hip_get_param_total_len(&host_id_hdr), GFP_ATOMIC);
  if (!host_id) {
    err = -ENOMEM;
  }

  memcpy(*host_id, &host_id_hdr, sizeof(host_id_hdr));

  return err;
}

int alloc_and_build_param_host_id_only(struct hip_host_id **host_id,
				       unsigned char *key_rr, int key_rr_len,
				       int algo, char *hostname) {
  int err = 0;
  HIP_IFEL(alloc_and_set_host_id_param_hdr(host_id, key_rr_len, algo,
					   hostname), -1, "alloc\n");
  hip_build_param_host_id_only(*host_id, key_rr, "hostname");
 out_err:
  if (err && *host_id) {
    *host_id = NULL;
    HIP_FREE(host_id);
  }

  return err;
}

#ifndef __KERNEL__
/* Note: public here means that you only have the public key,
   not the private */
int hip_any_key_to_hit(void *any_key, unsigned char *any_key_rr, int hit_type,
		       hip_hit_t *hit, int is_public, int is_dsa) {
  int err = 0, key_rr_len;
  unsigned char *key_rr = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
  struct hip_host_id *host_id = NULL;
  RSA *rsa_key = (RSA *) any_key;
  DSA *dsa_key = (DSA *) any_key;

  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  HIP_IFEL(gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1), -1,
  	   "gethostname failed\n");

  if (is_dsa) {
    HIP_IFEL(((key_rr_len = dsa_to_dns_key_rr(dsa_key, &key_rr)) <= 0), -1,
	     "key_rr_len\n");
    HIP_IFEL(alloc_and_build_param_host_id_only(&host_id, key_rr, key_rr_len,
						HIP_HI_DSA, hostname), -1,
	     "alloc\n");
    if (is_public) {
      HIP_IFEL(hip_dsa_host_id_to_hit(host_id, hit, HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    } else {
      HIP_IFEL(hip_private_dsa_host_id_to_hit(host_id, hit,
					      HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    }
  } else /* rsa */ {
    HIP_IFEL(((key_rr_len = rsa_to_dns_key_rr(rsa_key, &key_rr)) <= 0), -1,
	     "key_rr_len\n");
    HIP_IFEL(alloc_and_build_param_host_id_only(&host_id, key_rr, key_rr_len,
						HIP_HI_RSA, hostname), -1,
	     "alloc\n");
    if (is_public) {
      HIP_IFEL(hip_rsa_host_id_to_hit(host_id, hit, HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    } else {
      HIP_IFEL(hip_private_rsa_host_id_to_hit(host_id, hit,
					      HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    }
  }

   HIP_DEBUG_HIT("hit", hit);
   HIP_DEBUG("hi is %s %s\n", (is_public ? "public" : "private"),
	     (is_dsa ? "dsa" : "rsa"));

 out_err:

  if (key_rr)
    HIP_FREE(key_rr);
  if (host_id)
    HIP_FREE(host_id);

  return err;
}

int hip_public_rsa_to_hit(RSA *rsa_key, unsigned char *rsa, int type,
			  struct in6_addr *hit) {
  return hip_any_key_to_hit(rsa_key, rsa, type, hit, 1, 0);
}

int hip_private_rsa_to_hit(RSA *rsa_key, unsigned char *rsa, int type,
			  struct in6_addr *hit) {
  return hip_any_key_to_hit(rsa_key, rsa, type, hit, 0, 0);
}

int hip_public_dsa_to_hit(DSA *dsa_key, unsigned char *dsa, int type,
			  struct in6_addr *hit) {
  return hip_any_key_to_hit(dsa_key, dsa, type, hit, 1, 1);
}

int hip_private_dsa_to_hit(DSA *dsa_key, unsigned char *dsa, int type,
			   struct in6_addr *hit) {
  return hip_any_key_to_hit(dsa_key, dsa, type, hit, 0, 1);
}
#endif

/**
 * Builds a @c NAT_Transfer  parameter.
 *
 * Builds a @c NAT_TRANSFER parameter to the HIP packet @c msg.
 *
 * @param msg      a pointer to a HIP packet common header
 * @param nat_control     16bit integer indicate the nat_transfer type
 * @return         zero on success, or negative error value on error.
 * @see            <a href="http://tools.ietf.org/wg/hip/draft-ietf-hip-rvs/draft-ietf-hip-rvs-05.txt">
 *                 draft-ietf-hip-rvs-05</a> section 4.2.2.
 */
int hip_build_param_nat_transform(struct hip_common *msg,
				  hip_transform_suite_t *suite,
				  int suite_count)
{
	int i;
	hip_transform_suite_t tfm[HIP_TRANSFORM_NAT_MAX + 1];

	HIP_HEXDUMP("", suite, suite_count * sizeof(hip_transform_suite_t));

	for (i = 0; i < HIP_TRANSFORM_NAT_MAX && i <= suite_count; i++)
		tfm[i] = (i == 0 ? 0 : htons(suite[i-1]));

	HIP_HEXDUMP("", tfm, suite_count * sizeof(hip_transform_suite_t) + sizeof(hip_transform_suite_t));

	return hip_build_param_contents(msg, tfm, HIP_PARAM_NAT_TRANSFORM,
				       suite_count * sizeof(hip_transform_suite_t) + sizeof(hip_transform_suite_t));
}

int hip_build_param_nat_pacing(struct hip_common *msg, uint32_t min_ta)
{
	struct hip_nat_pacing nat_pacing;
	int err = 0;

	hip_set_param_type(&nat_pacing, HIP_PARAM_NAT_PACING);
	nat_pacing.min_ta = htonl(min_ta);

	hip_calc_generic_param_len(&nat_pacing,
				   sizeof(struct hip_nat_pacing),
				   sizeof(struct hip_nat_pacing) -
				   sizeof(hip_tlv_common_t));
	err = hip_build_param(msg, &nat_pacing);
	return err;
}

void hip_set_locator_addr_length(void * locator, hip_tlv_len_t  length){
	((struct hip_locator *)locator)->length = htons(length);
	return;
}

/**
 *
 * return the amount the locator items(type 1 and 2 are both supproted).
 * */
int hip_get_locator_addr_item_count(struct hip_locator *locator) {
	char *address_pointer =(char*) (locator + 1);
	int amount = 0;

	for(;address_pointer < ((char*)locator) + hip_get_param_contents_len(locator); ) {
		if (((struct hip_locator_info_addr_item*)address_pointer)->locator_type
                    == HIP_LOCATOR_LOCATOR_TYPE_UDP) {
                        address_pointer += sizeof(struct hip_locator_info_addr_item2);
                        amount += 1;
                }
                else if(((struct hip_locator_info_addr_item*)address_pointer)->locator_type
                        == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
                        address_pointer += sizeof(struct hip_locator_info_addr_item);
                        amount += 1;
                }
                else if(((struct hip_locator_info_addr_item*)address_pointer)->locator_type
                        == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
                        address_pointer += sizeof(struct hip_locator_info_addr_item);
                        amount += 1;
                }
                else
                        address_pointer += sizeof(struct hip_locator_info_addr_item);
	}
	return amount;
}

/**
 * retreive a locator address item from a list
 *
 * retreive a @c LOCATOR ADDRESS ITEM@c from a list.
 *
 * @param item_list      a pointer to the first item in the list
 * @param index     the index of the item in the list
 */
union hip_locator_info_addr * hip_get_locator_item(void* item_list, int index){
	int i= 0;
	struct hip_locator_info_addr_item *temp;
 	char *result ;
 	result = (char*) item_list;
 	
 	
	for(i=0;i<= index-1;i++){
		temp = (struct hip_locator_info_addr_item*) result;
		if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI ||
				temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6)
			result += sizeof(struct hip_locator_info_addr_item);
		else
			result += sizeof(struct hip_locator_info_addr_item2);
	}
	_HIP_DEBUG("*****locator %d has offset :%d \n", index, (char*)result - (char*)item_list );
	return (union hip_locator_info_addr *) result;
}

/**
 * retreive a locator address item from a list
 *
 * retreive a @c LOCATOR ADDRESS ITEM@c from a list.
 *
 * @param item_list      a pointer to the first item in the list
 * @param index     the index of the item in the list
 * @note DO NOT GIVE TOO LARGE INDEX
 */
struct hip_locator_info_addr_item * hip_get_locator_item_as_one(
	struct hip_locator_info_addr_item* item_list, int index){

    char * address_pointer;
    int i = 0;
    struct hip_locator_info_addr_item *item = NULL;
    struct hip_locator_info_addr_item2 *item2 = NULL;

    address_pointer = (char *)item_list;

    HIP_DEBUG("LOCATOR TYPE %d\n",
		      ((struct hip_locator_info_addr_item *)address_pointer)->locator_type);
    if (index ==  0) {
	    if (((struct hip_locator_info_addr_item *)address_pointer)->locator_type
		== HIP_LOCATOR_LOCATOR_TYPE_UDP) {
		    item2 = (struct hip_locator_info_addr_item2 *)address_pointer;
		    HIP_DEBUG_IN6ADDR("LOCATOR", (struct in6_addr *)&item2->address);
	    } else {
		    item = (struct hip_locator_info_addr_item *)address_pointer;
		    HIP_DEBUG_IN6ADDR("LOCATOR", (struct in6_addr *)&item->address);
	    }
	    return address_pointer;
    }

    for(i = 0; i < index; i++) {
	    if (((struct hip_locator_info_addr_item *)address_pointer)->locator_type
		== HIP_LOCATOR_LOCATOR_TYPE_UDP) {
		    address_pointer += sizeof(struct hip_locator_info_addr_item2);
		    item2 = (struct hip_locator_info_addr_item2 *)address_pointer;
		    HIP_DEBUG_IN6ADDR("LOCATOR", (struct in6_addr *)&item2->address);
	    }
	    else if(((struct hip_locator_info_addr_item *)address_pointer)->locator_type
		    == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
		    address_pointer += sizeof(struct hip_locator_info_addr_item);
		    item = (struct hip_locator_info_addr_item *)address_pointer;
		    HIP_DEBUG_IN6ADDR("LOCATOR", (struct in6_addr *)&item->address);
	    }
	    else if(((struct hip_locator_info_addr_item *)address_pointer)->locator_type
		    == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
		    address_pointer += sizeof(struct hip_locator_info_addr_item);
		    item = (struct hip_locator_info_addr_item *)address_pointer;
		    HIP_DEBUG_IN6ADDR("LOCATOR", (struct in6_addr *)&item->address);
	    }
	    else
		    address_pointer += sizeof(struct hip_locator_info_addr_item);
    }  
    return address_pointer;
} 

/**
 * retreive a IP address  from a locator item structure
 *
 *
 * @param item      a pointer to the item
 */
struct in6_addr * hip_get_locator_item_address(void* item){

	struct hip_locator_info_addr_item *temp;


	temp = (struct hip_locator_info_addr_item*) item;
	if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI){
		return &temp->address;
	} else 	if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6){
		return &temp->address;
	} else {
		return &((struct hip_locator_info_addr_item2 *)temp)->address;
	}

}

/**
 * retreive a port from a locator item structure
 *
 *
 * @param item      a pointer to the item
 */
uint16_t hip_get_locator_item_port(void* item){

	struct hip_locator_info_addr_item *temp;


	temp = (struct hip_locator_info_addr_item*) item;
	if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI){
		return 0;
	}
	else {
		return ntohs(((struct hip_locator_info_addr_item2 *)temp)->port);
	}

}


/**
 * retreive a port from a locator item structure
 *
 *
 * @param item      a pointer to the item
 */
uint32_t hip_get_locator_item_priority(void* item){

	struct hip_locator_info_addr_item *temp;


	temp = (struct hip_locator_info_addr_item*) item;
	if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI){
		//todo check the constant value
		return HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI_PRIORITY;
	}
	else {
		return ntohl(((struct hip_locator_info_addr_item2 *)temp)->priority);
	}

}
/**
 * Count the a locator item list length in bytes.
 *
 *
 * @param item_list      a pointer to the first item
 * @param amount          the number of items in the list
 */
int hip_get_locator_item_list_length(void* item_list, int amount) {

	int i= 0;
	struct hip_locator_info_addr_item *temp;
	char * result = (char*) item_list;

	for(;i<amount+1;i++){
		temp = (struct hip_locator_info_addr_item*) result;
		if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI)
			result  +=  sizeof(struct hip_locator_info_addr_item);
		else
			result  +=  sizeof(struct hip_locator_info_addr_item2);

	}
	return result - (char*) item_list;

}


/**
 * hip_build_param_locator2 - build HIP locator parameter
 *
 * @param msg the message where the REA will be appended
 * @param addresses1 list of addresses type1
 * @param addresses2 list of addresses type2
 * @param address_count1 number of addresses1
 * @param address_count2 number of addresses2
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_locator2(struct hip_common *msg,
			struct hip_locator_info_addr_item  *addresses1,
			struct hip_locator_info_addr_item2 *addresses2,
			int address_count1,
			int address_count2) {
	int err = 0;
	struct hip_locator *locator_info = NULL;
	int addrs_len1 = address_count1 *
		(sizeof(struct hip_locator_info_addr_item));
	int addrs_len2 = address_count2 *
		(sizeof(struct hip_locator_info_addr_item2));

	HIP_IFE(!(locator_info =
		  HIP_MALLOC(sizeof(struct hip_locator) + addrs_len1 + addrs_len2, GFP_ATOMIC)), -1);
	HIP_DEBUG("msgtotl 1\n");
	hip_set_param_type(locator_info, HIP_PARAM_LOCATOR);
	hip_calc_generic_param_len(locator_info,
				   sizeof(struct hip_locator),
				   addrs_len1+addrs_len2);
	HIP_DEBUG("msgtotl 2\n");
	if(addrs_len1 > 0)
		memcpy(locator_info + 1, addresses1, addrs_len1);
	HIP_DEBUG("msgtotl 3\n");
	if(address_count2 > 0)
               memcpy(((char *)(locator_info + 1) + addrs_len1),
                      addresses2, addrs_len2);

	HIP_IFE(hip_build_param(msg, locator_info), -1);
	
	
	HIP_INFO_LOCATOR("print locator out",locator_info);
	
	_HIP_DEBUG("msgtotlen=%d addrs_len=%d\n", hip_get_msg_total_len(msg),
		   addrs_len);
 out_err:
	if (locator_info)
		HIP_FREE(locator_info);
	return err;
}


/**
 * Builds a @c RELAY_TO parameter.
 *
 * Builds a @c RELAY_TO parameter to the HIP packet @c msg.
 *
 * @param msg  a pointer to a HIP packet common header
 * @param addr a pointer to IPv6 address
 * @param port portnumber
 * @return     zero on success, or negative error value on error.
 * @note       This used to be VIA_RVS_NAT, but because of the HIP-ICE
 *             draft, this is now RELAY_TO.
 */
int hip_build_param_reg_from(struct hip_common *msg,
			     const in6_addr_t *addr,
			     const in_port_t port)
{

     struct hip_reg_from reg_from;
     int err = 0;

     hip_set_param_type(&reg_from, HIP_PARAM_REG_FROM);
     ipv6_addr_copy((struct in6_addr *)&reg_from.address, addr);
     HIP_DEBUG_IN6ADDR("reg_from address is ", &reg_from.address);
     HIP_DEBUG_IN6ADDR("the given address is ", addr);
     reg_from.port = htons(port);
     reg_from.reserved = 0;
     reg_from.protocol = HIP_NAT_PROTO_UDP;
     hip_calc_generic_param_len(&reg_from, sizeof(reg_from), 0);
     err = hip_build_param(msg, &reg_from);

     return err;

}

int hip_build_param_nat_port(hip_common_t *msg, const in_port_t port, hip_tlv_type_t hipparam)
{
	int err = 0;
	struct hip_port_info nat_port;
	
	hip_set_param_type(&nat_port, hipparam);
	nat_port.port = port;
	hip_calc_generic_param_len(&nat_port, sizeof(nat_port), 0);
	err = hip_build_param(msg, &nat_port);

	return err;
}


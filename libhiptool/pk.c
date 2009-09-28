#include "pk.h"

int hip_rsa_sign(RSA *rsa, struct hip_common *msg) {
	u8 sha1_digest[HIP_AH_SHA_LEN];
	u8 *signature = NULL;
	int err = 0, len;
	unsigned int sig_len;

	len = hip_get_msg_total_len(msg);
	HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, len, sha1_digest) < 0,
		 -1, "Building of SHA1 digest failed\n");

	len = RSA_size(rsa);
	signature = malloc(len);
	HIP_IFEL(!signature, -1, "Malloc for signature failed.");
	memset (signature, 0, len);

	/* RSA_sign returns 0 on failure */
	HIP_IFEL(!RSA_sign(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH, signature,
					&sig_len, rsa), -1, "Signing error\n");

	if (hip_get_msg_type(msg) == HIP_R1) {
	    HIP_IFEL(hip_build_param_signature2_contents(msg, signature,
							len, HIP_SIG_RSA), 
					-1,  "Building of signature failed\n");
	} else {
	    HIP_IFEL(hip_build_param_signature_contents(msg, signature,
							len, HIP_SIG_RSA), 
					 -1, "Building of signature failed\n");
	}

 out_err:
	if(signature)
	    free(signature);
	return err;
}

int hip_dsa_sign(DSA *dsa, struct hip_common *msg) {
	u8 sha1_digest[HIP_AH_SHA_LEN];
	u8 signature[HIP_DSA_SIGNATURE_LEN];
	int err = 0, len;

	len = hip_get_msg_total_len(msg);
	HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, len, sha1_digest) < 0,
		 -1, "Building of SHA1 digest failed\n");
	HIP_IFEL(impl_dsa_sign(sha1_digest, dsa, signature), 
		 -1, "Signing error\n");

	if (hip_get_msg_type(msg) == HIP_R1) {
	    HIP_IFEL(hip_build_param_signature2_contents(msg, signature,
					 HIP_DSA_SIGNATURE_LEN, HIP_SIG_DSA),
					 -1, "Building of signature failed\n");
	} else {
	    HIP_IFEL(hip_build_param_signature_contents(msg, signature,
					 HIP_DSA_SIGNATURE_LEN, HIP_SIG_DSA),
					 -1, "Building of signature failed\n");
	}

 out_err:
	return err;
}

static int verify(void *peer_pub, struct hip_common *msg, int rsa)
{
	int err = 0, len, origlen;
	struct hip_sig *sig;
	u8 sha1_digest[HIP_AH_SHA_LEN];
	struct in6_addr tmpaddr;	
	struct hip_puzzle *pz = NULL;
	uint8_t opaque[3];
	uint64_t randi = 0;

	ipv6_addr_copy(&tmpaddr, &msg->hitr); /* so update is handled, too */

	origlen = hip_get_msg_total_len(msg);
	if (hip_get_msg_type(msg) == HIP_R1) {
	    HIP_IFEL(!(sig = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE2)),
				       -ENOENT, "Could not find signature2\n");
		
	    //ipv6_addr_copy(&tmpaddr, &msg->hitr);
	    memset(&msg->hitr, 0, sizeof(struct in6_addr));

	    HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)),
			      -ENOENT, "Illegal R1 packet (puzzle missing)\n");
	    memcpy(opaque, pz->opaque, 3);
	    randi = pz->I;

	    memset(pz->opaque, 0, 3);
	    pz->I = 0;
	} else {
	    HIP_IFEL(!(sig = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE)),
					-ENOENT, "Could not find signature\n");
	}

	//HIP_HEXDUMP("SIG", sig, hip_get_param_total_len(sig));
	len = ((u8 *) sig) - ((u8 *) msg);
	hip_zero_msg_checksum(msg);
	HIP_IFEL(len < 0, -ENOENT, "Invalid signature len\n");
	hip_set_msg_total_len(msg, len);

	//HIP_HEXDUMP("Verifying:", msg, len);
	//HIP_HEXDUMP("Pubkey:", peer_pub, hip_get_param_total_len(peer_pub));

	HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, len, sha1_digest), 
		 -1, "Could not calculate SHA1 digest\n");
	if (rsa) {
	    /* RSA_verify returns 0 on failure */
	    err = !RSA_verify(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH,
					sig->signature, RSA_size(peer_pub), peer_pub);
	} else {
	    err = impl_dsa_verify(sha1_digest, peer_pub, sig->signature);
	}

	if (hip_get_msg_type(msg) == HIP_R1) {
	    memcpy(pz->opaque, opaque, 3);
	    pz->I = randi;
	}

	ipv6_addr_copy(&msg->hitr, &tmpaddr);

	/*switch(err) {
	case 0:
	    err = 0;
	    break;
	case 1:
	default:
	    err = -1;
	    break;
	}*/

	if(err)
	    err = -1;

 out_err:
	hip_set_msg_total_len(msg, origlen);
	return err;
}

int hip_rsa_verify(void *peer_pub, struct hip_common *msg)
{
	return verify((RSA *)peer_pub, msg, 1);
}

int hip_dsa_verify(void *peer_pub, struct hip_common *msg)
{
	return verify((DSA *)peer_pub, msg, 0);
}

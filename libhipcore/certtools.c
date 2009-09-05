/** @file
 * This file defines the certificate building and verification functions to use with HIP
 *
 * Syntax in the names of functions is as follows, hip_cert_XX_YY_VV(), where 
 *   XX is the certificate type
 *   YY is build or verify
 *   VV is what the function really does like sign etc.
 *
 * @author Samu Varjonen
 *
 */
#include "certtools.h"
 
/*******************************************************************************
 * FUNCTIONS FOR SPKI                                                          *
 *******************************************************************************/

/**
 * Function that verifies the signature in the given SPKI cert sent by the "client"
 *
 * @param cert points to hip_cert_spki_info 
 *
 * @return 0 if signature matches, -1 if error or signature did NOT match
 * 
 * @note see hip_cert_spki_char2certinfo to convert from wire to hip_cert_spki_info
 */
int hip_cert_spki_lib_verify(struct hip_cert_spki_info * cert) {
	int err = 0, start = 0, stop = 0, evpret = 0, keylen = 0, algo = 0;
        char buf[200];

        char sha_digest[21];
        unsigned char *sha_retval;
        char * signature_hash = NULL;
        char * signature_hash_b64 = NULL;
        char * signature_b64 = NULL;

        char * signature = NULL;

        /** RSA **/
        RSA *rsa = NULL;
        unsigned long e_code;
        char * e_hex = NULL;
        char * modulus_b64 = NULL;
        char * modulus = NULL;

        /** DSA **/
        DSA *dsa = NULL;
        char * p_bin = NULL, * q_bin = NULL, * g_bin = NULL, * y_bin = NULL;
        char * p_b64 = NULL, * q_b64 = NULL, * g_b64 = NULL, * y_b64 = NULL;
	DSA_SIG *dsa_sig;

        /* rules for regular expressions */

        /* 
           Rule to get the info if we are using DSA
        */
        char dsa_rule[] = "[d][s][a][-][p][k][c][s][1][-][s][h][a][1]";

        /* 
           Rule to get the info if we are using RSA
        */
        char rsa_rule[] = "[r][s][a][-][p][k][c][s][1][-][s][h][a][1]";

        /* 
           Rule to get DSA p
           Look for pattern "(p |" and stop when first "|" 
           anything in base 64 is accepted inbetween
        */
        char p_rule[] = "[(][p][ ][|][[A-Za-z0-9+/()#=-]*[|]";

        /*
          Rule to get DSA q
           Look for pattern "(q |" and stop when first "|" 
           anything in base 64 is accepted inbetween
        */
        char q_rule[] = "[(][q][ ][|][[A-Za-z0-9+/()#=-]*[|]";

        /*
          Rule to get DSA g
           Look for pattern "(g |" and stop when first "|" 
           anything in base 64 is accepted inbetween
        */
        char g_rule[] = "[(][g][ ][|][[A-Za-z0-9+/()#=-]*[|]";

        /*
          Rule to get DSA y / pub_key
          Look for pattern "(y |" and stop when first "|" 
           anything in base 64 is accepted inbetween
        */
        char y_rule[] = "[(][y][ ][|][[A-Za-z0-9+/()#=-]*[|]";

        /* 
           rule to get the public exponent RSA 
           Look for the part that says # and after that some hex blob and #
        */
        char e_rule[] = "[#][0-9A-Fa-f]*[#]";

        /* 
           rule to get the public modulus RSA
           Look for the part that starts with '|' and after that anything
           that is in base 64 char set and then '|' again
        */
        char n_rule[] = "[|][A-Za-z0-9+/()#=-]*[|]";

        /* 
           rule to get the signature hash 
           Look for the similar than the n_rule
        */
        char h_rule[] = "[|][A-Za-z0-9+/()#=-]*[|]";

        /* 
           rule to get the signature 
           Look for part that starts ")|" and base 64 blob after it
           and stops to '|' char remember to add and subtract 2 from 
           the indexes below
        */
        char s_rule[] = "[)][|][A-Za-z0-9+/()#=-]*[|]";

        _HIP_DEBUG("\n\n** CONTENTS of public key sequence **\n"
                   "%s\n\n",cert->public_key); 

        /* check the algo DSA or RSA  */
        HIP_DEBUG("Verifying\nRunning regexps to identify algo\n");
        start = stop = 0;
        algo = hip_cert_regex(dsa_rule, cert->public_key, &start, &stop);
        if (algo != -1) {
                HIP_DEBUG("Public-key is DSA\n");
                algo = HIP_HI_DSA;
                goto algo_check_done;
        }
        start = stop = 0;
        algo = hip_cert_regex(rsa_rule, cert->public_key, &start, &stop);
        if (algo != -1) { 
                HIP_DEBUG("Public-key is RSA\n");
                algo = HIP_HI_RSA;
                goto algo_check_done;
        }
        HIP_DEBUG((1!=1), -1,"Unknown algorithm\n");
               
 algo_check_done:
        if (algo == HIP_HI_RSA) {

                /* malloc space for new rsa */
                rsa = RSA_new();
                HIP_IFEL(!rsa, -1, "Failed to malloc RSA\n");

                /* extract the public-key from cert to rsa */

                /* public exponent first */
                start = stop = 0;
                HIP_IFEL(hip_cert_regex(e_rule, cert->public_key, &start, &stop), -1,
                         "Failed to run hip_cert_regex (exponent)\n");
                _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
                e_hex = malloc(stop-start);
                HIP_IFEL((!e_hex), -1, "Malloc for e_hex failed\n");
                snprintf(e_hex, (stop-start-1), "%s", &cert->public_key[start + 1]);
                _HIP_DEBUG("E_HEX %s\n",e_hex);
                
                /* public modulus */
                start = stop = 0;
                HIP_IFEL(hip_cert_regex(n_rule, cert->public_key, &start, &stop), -1,
                         "Failed to run hip_cert_regex (modulus)\n");
                _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
                modulus_b64 = malloc(stop-start+1);
                HIP_IFEL((!modulus_b64), -1, "Malloc for modulus_b64 failed\n");
                memset(modulus_b64, 0, (stop-start+1));
                modulus = malloc(stop-start+1);
                HIP_IFEL((!modulus), -1, "Malloc for modulus failed\n");
                memset(modulus, 0, (stop-start+1));
                snprintf(modulus_b64, (stop-start-1), "%s", &cert->public_key[start + 1]);
                _HIP_DEBUG("modulus_b64 %s\n",modulus_b64);
                
                /* put the stuff into the RSA struct */
                BN_hex2bn(&rsa->e, e_hex);
                evpret = EVP_DecodeBlock(modulus, modulus_b64, 
                                         strlen(modulus_b64));
                
                /* EVP returns a multiple of 3 octets, subtract any extra */
                keylen = evpret;
                if (keylen % 4 != 0)
                        keylen = --keylen - keylen % 2;
                _HIP_DEBUG("keylen = %d (%d bits)\n", keylen, keylen * 8);
                signature = malloc(keylen);
                HIP_IFEL((!signature), -1, "Malloc for signature failed.\n");
                rsa->n = BN_bin2bn(modulus, keylen, 0);
                
                _HIP_DEBUG("In verification RSA e=%s\n", BN_bn2hex(rsa->e));
                _HIP_DEBUG("In verification RSA n=%s\n", BN_bn2hex(rsa->n));

        } else if (algo == HIP_HI_DSA) {
                
                /* malloc space for new dsa */
                dsa = DSA_new();
                HIP_IFEL(!dsa, -1, "Failed to malloc DSA\n");
                
                /* Extract public key from the cert */
                
                /* dsa->p */
                start = stop = 0;
                HIP_IFEL(hip_cert_regex(p_rule, cert->public_key, &start, &stop), -1,
                         "Failed to run hip_cert_regex dsa->p\n");
                _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
                p_b64 = malloc(stop-start+1);
                HIP_IFEL((!p_b64), -1, "Malloc for p_b64 failed\n");
                memset(p_b64, 0, (stop-start+1));
                p_bin = malloc(stop-start+1);
                HIP_IFEL((!p_bin), -1, "Malloc for p_bin failed\n");
                memset(p_bin, 0, (stop-start+1));
                snprintf(p_b64, (stop-start-1), "%s", &cert->public_key[start + 1]);
                _HIP_DEBUG("p_b64 %s\n",p_b64);
                evpret = EVP_DecodeBlock(p_bin, p_b64, strlen(p_b64));

                /* dsa->q */
                start = stop = 0;
                HIP_IFEL(hip_cert_regex(q_rule, cert->public_key, &start, &stop), -1,
                         "Failed to run hip_cert_regex dsa->q\n");
                _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
                q_b64 = malloc(stop-start+1);
                HIP_IFEL((!q_b64), -1, "Malloc for q_b64 failed\n");
                memset(q_b64, 0, (stop-start+1));
                q_bin = malloc(stop-start+1);
                HIP_IFEL((!q_bin), -1, "Malloc for q_bin failed\n");
                memset(q_bin, 0, (stop-start+1));
                snprintf(q_b64, (stop-start-1), "%s", &cert->public_key[start + 1]);
                _HIP_DEBUG("q_b64 %s\n",q_b64);
                evpret = EVP_DecodeBlock(q_bin, q_b64, strlen(q_b64));

                /* dsa->g */
                start = stop = 0;
                HIP_IFEL(hip_cert_regex(g_rule, cert->public_key, &start, &stop), -1,
                         "Failed to run hip_cert_regex dsa->g\n");
                _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
                g_b64 = malloc(stop-start+1);
                HIP_IFEL((!g_b64), -1, "Malloc for g_b64 failed\n");
                memset(g_b64, 0, (stop-start+1));
                g_bin = malloc(stop-start+1);
                HIP_IFEL((!g_bin), -1, "Malloc for g_bin failed\n");
                memset(g_bin, 0, (stop-start+1));
                snprintf(g_b64, (stop-start-1), "%s", &cert->public_key[start + 1]);
                _HIP_DEBUG("g_b64 %s\n",g_b64);
                evpret = EVP_DecodeBlock(g_bin, g_b64, strlen(g_b64));

                /* dsa->y */
                start = stop = 0;
                HIP_IFEL(hip_cert_regex(y_rule, cert->public_key, &start, &stop), -1,
                         "Failed to run hip_cert_regex dsa->y\n");
                _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
                y_b64 = malloc(stop-start+1);
                HIP_IFEL((!y_b64), -1, "Malloc for y_b64 failed\n");
                memset(y_b64, 0, (stop-start+1));
                y_bin = malloc(stop-start+1);
                HIP_IFEL((!y_bin), -1, "Malloc for y_bin failed\n");
                memset(y_bin, 0, (stop-start+1));
                snprintf(y_b64, (stop-start-1), "%s", &cert->public_key[start + 1]);
                _HIP_DEBUG("y_b64 %s\n",y_b64);
                evpret = EVP_DecodeBlock(y_bin, y_b64, strlen(y_b64));
                
        } else HIP_IFEL((1==0), -1, "Unknown algorithm\n");        

        memset(sha_digest, '\0', sizeof(sha_digest));        
        /* build sha1 digest that will be signed */
        HIP_IFEL(!(sha_retval = SHA1(cert->cert, 
                                     strlen(cert->cert), sha_digest)),
                 -1, "SHA1 error when creating digest.\n");        
        _HIP_HEXDUMP("SHA1 digest of cert sequence ", sha_digest, 20);          
   
        /* Get the signature hash and compare it to the sha_digest we just made */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(h_rule, cert->signature, &start, &stop), -1,
                 "Failed to run hip_cert_regex (signature hash)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        signature_hash_b64 = malloc(stop-start+1);
        HIP_IFEL((!signature_hash_b64), -1, "Failed to malloc signature_hash_b64\n");
        memset(signature_hash_b64, '\0', (stop-start+1));        
        signature_hash = malloc(stop-start+1);
        HIP_IFEL((!signature_hash), -1, "Failed to malloc signature_hash\n");
        snprintf(signature_hash_b64, (stop-start-1), "%s", 
                 &cert->signature[start + 1]);       
        _HIP_DEBUG("SIG HASH B64 %s\n", signature_hash_b64);
        evpret = EVP_DecodeBlock(signature_hash, signature_hash_b64, 
                                 strlen(signature_hash_b64));
        HIP_IFEL(memcmp(sha_digest, signature_hash, 20), -1,
                 "Signature hash did not match of the one made from the"
                 "cert sequence in the certificate\n");

        /* memset signature and put it into its place */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(s_rule, cert->signature, &start, &stop), -1,
                 "Failed to run hip_cert_regex (signature)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        signature_b64 = malloc(stop-start+1);
        HIP_IFEL((!signature_b64), -1, "Failed to malloc signature_b64\n");
        memset(signature_b64, '\0', keylen);
        snprintf(signature_b64, (stop-start-2),"%s", &cert->signature[start + 2]);       
        _HIP_DEBUG("SIG_B64 %s\n", signature_b64);
        if (algo == HIP_HI_DSA) {
                signature = malloc(stop-start+1);
                HIP_IFEL(!signature, -1, "Failed to malloc signature (dsa)\n");
        }
        evpret = EVP_DecodeBlock(signature, signature_b64, 
                                 strlen(signature_b64));
        _HIP_HEXDUMP("SIG\n", signature, keylen);

        if (algo == HIP_HI_RSA) {
                /* do the verification */
                err = RSA_verify(NID_sha1, sha_digest, SHA_DIGEST_LENGTH,
                                 signature, RSA_size(rsa), rsa);
                e_code = ERR_get_error();
                ERR_load_crypto_strings();
                ERR_error_string(e_code ,buf);
                
                _HIP_DEBUG("***********RSA ERROR*************\n");
                _HIP_DEBUG("RSA_size(rsa) = %d\n",RSA_size(rsa));
                _HIP_DEBUG("Signature length :%d\n",strlen(signature));
                _HIP_DEBUG("Error string :%s\n",buf);
                _HIP_DEBUG("LIB error :%s\n",ERR_lib_error_string(e_code));
                _HIP_DEBUG("func error :%s\n",ERR_func_error_string(e_code));
                _HIP_DEBUG("Reason error :%s\n",ERR_reason_error_string(e_code));
                _HIP_DEBUG("***********RSA ERROR*************\n");

                /* RSA_verify returns 1 if success. */
                cert->success = err == 1 ? 0 : -1;
                HIP_IFEL((err = err == 1 ? 0 : -1), -1, "RSA_verify error\n");

        } else if (algo == HIP_HI_DSA) {

                /* build the signature structure */
                dsa_sig = DSA_SIG_new();
                HIP_IFEL(!dsa_sig, 1, "Failed to allocate DSA_SIG\n");
                dsa_sig->r = BN_bin2bn(&signature[1], DSA_PRIV, NULL);
                dsa_sig->s = BN_bin2bn(&signature[1 + DSA_PRIV], DSA_PRIV, NULL);

                /* verify the DSA signature */
                err = DSA_do_verify(sha_digest, SHA_DIGEST_LENGTH, 
                                    dsa_sig, dsa) == 0 ? 1 : 0;

                /* DSA_do_verify returns 1 if success. */
                cert->success = err == 1 ? 0 : -1;
                HIP_IFEL((err = err == 1 ? 0 : -1), -1, "DSA_do_verify error\n");

        } else HIP_IFEL((1==0), -1, "Unknown algorithm\n");

out_err:
        if (signature_hash_b64) free(signature_hash_b64);
        if (signature_hash) free(signature_hash);
        if (modulus_b64) free(modulus_b64);
        if (modulus) free(modulus);
        if (rsa) RSA_free(rsa);
	if (e_hex) free(e_hex);
        if (dsa) DSA_free(dsa);
	return (err);
}

/**  
 * Function to build the create minimal SPKI cert  
 * @param minimal_content holds the struct hip_cert_spki_info containing 
 *                        the minimal needed information for cert object, 
 *                        also contains the char table where the cert object 
 *                        is to be stored
 * @param issuer_type With HIP its HIT
 * @param issuer HIT in representation encoding 2001:001...
 * @param subject_type With HIP its HIT
 * @param subject HIT in representation encoding 2001:001...
 * @param not_before time in timeval before which the cert should not be used
 * @param not_after time in timeval after which the cert should not be used
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_create_cert(struct hip_cert_spki_info * content,
                              char * issuer_type, struct in6_addr * issuer,
                              char * subject_type, struct in6_addr * subject,
                              time_t * not_before, time_t * not_after) {
	int err = 0;
        char * tmp_issuer;
        char * tmp_subject;
        char * tmp_before;
        char * tmp_after;
        struct tm *ts;
        char buf_before[80];
        char buf_after[80];
        char present_issuer[41];
        char present_subject[41];
        struct hip_common * msg;
        struct hip_cert_spki_info * returned;

        /* Malloc needed */
        tmp_issuer = malloc(128);
        if (!tmp_issuer) goto out_err; /* Why does this return 0? */
        tmp_subject = malloc(128);
        if (!tmp_subject) goto out_err;
        tmp_before = malloc(128);
        if (!tmp_before) goto out_err;
        tmp_after = malloc(128);
        if (!tmp_after) goto out_err;
        HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, 
                 "Malloc for msg failed\n");   

        /* Memset everything */
        HIP_IFEL(!memset(buf_before, '\0', sizeof(buf_before)), -1,
                 "Failed to memset memory for tmp buffers variables\n");
        HIP_IFEL(!memset(buf_after, '\0', sizeof(buf_after)), -1,
                 "Failed to memset memory for tmp buffers variables\n");
        HIP_IFEL(!memset(tmp_issuer, '\0', sizeof(tmp_issuer)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_subject, '\0', sizeof(tmp_subject)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_before, '\0', sizeof(tmp_before)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_after, '\0', sizeof(tmp_after)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(present_issuer, '\0', sizeof(present_issuer)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(present_subject, '\0', sizeof(present_subject)), -1,
                 "Failed to memset memory for tmp variables\n");

        /* Make needed transforms to the date */
        _HIP_DEBUG("not_before %d not_after %d\n",*not_before,*not_after);
        /*  Format and print the time, "yyyy-mm-dd hh:mm:ss"
           (not-after "1998-04-15_00:00:00") */
        ts = localtime(not_before);
        strftime(buf_before, sizeof(buf_before), "%Y-%m-%d_%H:%M:%S", ts);
        ts = localtime(not_after);
        strftime(buf_after, sizeof(buf_after), "%Y-%m-%d_%H:%M:%S", ts);
        _HIP_DEBUG("Not before %s\n", buf_before);
        _HIP_DEBUG("Not after %s\n", buf_after);

        sprintf(tmp_before, "(not-before \"%s\")", buf_before);
        sprintf(tmp_after, "(not-after \"%s\")", buf_after);
        
        ipv6_addr_copy(&content->issuer_hit, issuer);
        hip_in6_ntop(issuer, present_issuer);        
        hip_in6_ntop(subject, present_subject);

        sprintf(tmp_issuer, "(hash %s %s)", issuer_type, present_issuer);
        sprintf(tmp_subject, "(hash %s %s)", subject_type, present_subject);

        /* Create the cert sequence */        
        HIP_IFEL(hip_cert_spki_build_cert(content), -1, 
                 "hip_cert_spki_build_cert failed\n");

        HIP_IFEL(hip_cert_spki_inject(content, "cert", tmp_after), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "cert", tmp_before), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "cert", "(subject )"), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "subject", tmp_subject), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "cert", "(issuer )"), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "issuer", tmp_issuer), -1, 
                 "hip_cert_spki_inject failed to inject\n");

        /* Create the signature and the public-key sequences */

        /* Send the daemon the struct hip_cert_spki_header 
           containing the cert sequence in content->cert. 
           As a result you should get the struct back with 
           public-key and signature fields filled */

        /* build the msg to be sent to the daemon */
	hip_msg_init(msg);
        HIP_IFEL(hip_build_param_cert_spki_info(msg, content), -1,
                 "Failed to build cert_info\n");         
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_SPKI_SIGN, 0), -1, 
                 "Failed to build user header\n");
        /* send and wait */
        HIP_DEBUG("Sending request to sign SPKI cert sequence to "
                  "daemon and waiting for answer\n");	
        hip_send_recv_daemon_info(msg, 0, 0);
        
        /* get the struct from the message sent back by the daemon */
	_HIP_DUMP_MSG(msg);
        HIP_IFEL(!(returned = hip_get_param(msg, HIP_PARAM_CERT_SPKI_INFO)), 
                 -1, "No hip_cert_spki_info struct found from daemons msg\n");

	_HIP_DEBUG("PUBLIC-KEY\n%s\nCERT\n%s\nSIGNATURE\n%s\n", returned->public_key,
		  returned->cert, returned->signature);
        memcpy(content, returned, sizeof(struct hip_cert_spki_info));

out_err:
        /* free everything malloced */
        if (tmp_before) free(tmp_before);
        if (tmp_after) free(tmp_after);
        if (tmp_issuer) free(tmp_issuer);
        if (tmp_subject) free(tmp_subject);
        if (msg) free(msg);
	return (err);
} 
 
/**
 * Function to build the basic cert object of SPKI clears public-key object
 * and signature in hip_cert_spki_header
 * @param minimal_content holds the struct hip_cert_spki_header containing 
 *                        the minimal needed information for cert object, 
 *                        also contains the char table where the cert object 
 *                        is to be stored
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_build_cert(struct hip_cert_spki_info * minimal_content) {
	int err = 0;
	char needed[] = "(cert )";
	memset(minimal_content->public_key, '\0', sizeof(minimal_content->public_key));
	memset(minimal_content->cert, '\0', sizeof(minimal_content->cert));
	memset(minimal_content->signature, '\0', sizeof(minimal_content->signature));
        sprintf(minimal_content->cert, "%s", needed);

out_err:
	return (err);
}

/**
 * Function for injecting objects to cert object
 *
 * @param to hip_cert_spki_info containing the char table where to insert
 * @param after is a char pointer for the regcomp after which the inject happens
 * @param what is char pointer of what to 
 *
 * @return 0 if ok and negative if error. -1 returned for example when after is NOT found
 *
 * @note Remember to inject in order last first first last, its easier
 */
int hip_cert_spki_inject(struct hip_cert_spki_info * to, 
                         char * after, char * what) {
	int err = 0, status = 0;
        regex_t re;
        regmatch_t pm[1];
        char * tmp_cert;        

        _HIP_DEBUG("Before inject:\n%s\n",to->cert);
        _HIP_DEBUG("Inserting \"%s\" after \"%s\"\n", what, after);       
        tmp_cert = malloc(strlen(to->cert) + strlen(what) + 1);
        if (!tmp_cert) return(-1);
        HIP_IFEL(!memset(tmp_cert, 0, sizeof(tmp_cert)), -1,
                 "Failed to memset temporary workspace\n");        
        /* Compiling the regular expression */
        HIP_IFEL(regcomp(&re, after, REG_EXTENDED), -1, 
                 "Compilation of the regular expression failed\n");       
        /* Running the regular expression */
        HIP_IFEL((status = regexec(&re, to->cert, 1, pm, 0)), -1,
                 "Handling of regular expression failed\n");
        _HIP_DEBUG("Found \"%s\" at %d and it ends at %d\n",
                  after, pm[0].rm_so, pm[0].rm_eo);
        /* Using tmp char table to do the inject (remember the terminators)
           first the beginning */
        snprintf(tmp_cert, pm[0].rm_eo + 2, "%s", to->cert);
        /* Then the middle part to be injected */
        snprintf(&tmp_cert[pm[0].rm_eo + 1], strlen(what) + 1, "%s", what);
        /* then glue back the rest of the original at the end */
        snprintf(&tmp_cert[(pm[0].rm_eo + strlen(what) + 1)], 
                (strlen(to->cert) - pm[0].rm_eo), "%s", &to->cert[pm[0].rm_eo + 1]);
        /* move tmp to the result */
        sprintf(to->cert, "%s", tmp_cert);
        _HIP_DEBUG("After inject:\n%s\n",to->cert);
out_err:
        free(tmp_cert);
	regfree(&re);
	return (err);
}

/**
 * Function that takes the cert in char and constructs hip_cert_spki_info from it
 *
 * @param from char pointer to the whole certificate
 * @param to hip_cert_spki_info containing the char table where to insert
 *
 * @return 0 if ok and negative if error. 
 */
int hip_cert_spki_char2certinfo(char * from, struct hip_cert_spki_info * to) {
        int err = 0, start = 0, stop = 0;
        /* 
           p_rule looks for string "(public_key " after which there can be
           pretty much anything until string "|)))" is encountered.
           This is the public-key sequence.
        */
        char p_rule[] = "[(]public_key [ A-Za-z0-9+|/()#=-]*[|][)][)][)]";
        /* 
           c_rule looks for string "(cert " after which there can be
           pretty much anything until string '"))' is encountered.
           This is the cert sequence.
        */ 
        char c_rule[] = "[(]cert [ A-Za-z0-9+|/():=_\"-]*[\"][)][)]"; //\" is one char  
        /* 
           s_rule looks for string "(signature " after which there can be
           pretty much anything until string "|))" is encountered.
           This is the signature sequence.
        */
        char s_rule[] = "[(]signature [ A-Za-z0-9+/|()=]*[|][)][)]";
        
        _HIP_DEBUG("FROM %s\n", from);

        /* Look for the public key */ 
        HIP_IFEL(hip_cert_regex(p_rule, from , &start, &stop), -1,
                 "Failed to run hip_cert_regex (public-key)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        snprintf(to->public_key, (stop-start) + 1,"%s", &from[start]);

        /* Look for the cert sequence */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(c_rule, from, &start, &stop), -1,
                 "Failed to run hip_cert_regex (cert)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        snprintf(to->cert, (stop-start) + 1,"%s", &from[start]);        

        /* look for the signature sequence */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(s_rule, from, &start, &stop), -1,
                 "Failed to run hip_cert_regex (signature)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        snprintf(to->signature, (stop-start) + 1,"%s", &from[start]);
        
        _HIP_DEBUG("PK %s\nCert %s\nSign %s\n",
                  to->public_key, to->cert, to->signature);

 out_err:
        return(err);
}

/**
 * Function that sends the given hip_cert_spki_info to the daemon to verification
 *
 * @param to_verification is the cert to be verified
 *
 * @return 0 if ok and negative if error or unsuccesfull. 
 *
 * @note use hip_cert_spki_char2certinfo to build the hip_cert_spki_info
 */
int hip_cert_spki_send_to_verification(struct hip_cert_spki_info * to_verification) {
        int err = 0;
        struct hip_common * msg;
        struct hip_cert_spki_info * returned;

        HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, 
                 "Malloc for msg failed\n");   
        hip_msg_init(msg);
        /* build the msg to be sent to the daemon */
        HIP_IFEL(hip_build_param_cert_spki_info(msg, to_verification), -1,
                 "Failed to build cert_info\n");         
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_SPKI_VERIFY, 0), -1, 
                 "Failed to build user header\n");

        /* send and wait */
        HIP_DEBUG("Sending request to verify SPKI cert to "
                  "daemon and waiting for answer\n");	
        hip_send_recv_daemon_info(msg, 0, 0);
        
        HIP_IFEL(!(returned = hip_get_param(msg, HIP_PARAM_CERT_SPKI_INFO)), 
                 -1, "No hip_cert_spki_info struct found from daemons msg\n");
         
	_HIP_DEBUG("Success = %d (should be 0 if OK\n", returned->success);
        memcpy(to_verification, returned, sizeof(struct hip_cert_spki_info));

 out_err:
        if (msg) free(msg);
        return (err);
}

/*******************************************************************************
 * FUNCTIONS FOR x509v3                                                        *
 *******************************************************************************/

/**
 * Function that requests for a certificate from daemon and gives it back
 *
 * @param subject is the subject
 *
 * @param cert is pointer to where this function writes the completed cert 
 *
 * @return < 0 on success negative otherwise
 * 
 * @note The certificate is given in DER encoding
 */ 
int hip_cert_x509v3_request_certificate(struct in6_addr * subject, 
                                        unsigned char * certificate) {
        int err = 0;
        struct hip_common * msg;
        struct hip_cert_x509_resp * p;
        
        HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, 
                 "Malloc for msg failed\n");   
	hip_msg_init(msg);
        /* build the msg to be sent to the daemon */

        HIP_IFEL(hip_build_param_cert_x509_req(msg, subject), -1,
                 "Failed to build cert_info\n");         
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_X509V3_SIGN, 0), -1, 
                 "Failed to build user header\n");
        /* send and wait */
        HIP_DEBUG("Sending request to sign x509 cert to "
                  "daemon and waiting for answer\n");	
        hip_send_recv_daemon_info(msg, 0, 0);
        /* get the struct from the message sent back by the daemon */
        HIP_IFEL(!(p = hip_get_param(msg, HIP_PARAM_CERT_X509_RESP)), -1,
                 "No name x509 struct found\n");
        _HIP_HEXDUMP("DER:\n", p->der, p->der_len);
        _HIP_DEBUG("DER length %d\n", p->der_len);
        memcpy(certificate, p->der, p->der_len);
        err = p->der_len;
	_HIP_DUMP_MSG(msg);

 out_err:
        if (msg) free(msg);
        return(err);
}

/**
 * Function that requests for a verification of a certificate from daemon and
 * tells the result
 *
 * @param cert is pointer to a certificate to be verified
 *
 * @return 0 on success negative otherwise
 *
 * @note give the certificate in PEM encoding
 */ 
int hip_cert_x509v3_request_verification(unsigned char * certificate, int len) {
        int err = 0;
        struct hip_common * msg;
        struct hip_cert_x509_resp * received;
        
        HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, 
                 "Malloc for msg failed\n");   
        hip_msg_init(msg);

        _HIP_HEXDUMP("DER DUMP:\n", certificate, len);
        _HIP_DEBUG("DER LEN %d\n", len);
        
        /* build the msg to be sent to the daemon */
        HIP_IFEL(hip_build_param_cert_x509_ver(msg, certificate, len), -1, 
                 "Failed to build cert_info\n");         
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_X509V3_VERIFY, 0), -1, 
                 "Failed to build user header\n");
        /* send and wait */
        HIP_DEBUG("Sending request to verify x509  cert to "
                  "daemon and waiting for answer\n");
        _HIP_DUMP_MSG(msg);	
        hip_send_recv_daemon_info(msg, 0, 0);
        /* get the struct from the message sent back by the daemon */
        HIP_IFEL(!(received = hip_get_param(msg, HIP_PARAM_CERT_X509_RESP)), -1,
                 "No x509 struct found\n");
        err = hip_get_msg_err(msg); 
        if (err == 0) HIP_DEBUG("Verified successfully\n");
        else HIP_DEBUG("Verification failed\n");
	_HIP_DUMP_MSG(msg);

 out_err:
        if (msg) free(msg);
        return(err);
}

/*******************************************************************************
 * UTILITARY FUNCTIONS                                                         *
 *******************************************************************************/

/**
 * Function that displays the contents of the DER encoded x509 certificate
 *
 * @param pem points to DER encoded certificate
 *
 * @return void 
 */
void hip_cert_display_x509_der_contents(char * der, int length) {
#if 0
        int err = 0;
	X509 * cert = NULL;

	cert = hip_cert_der_to_x509(der, length);
        HIP_IFEL((cert == NULL), -1, "Cert is NULL\n");
        HIP_DEBUG("x.509v3 certificate in readable format\n\n");
        HIP_IFEL(!X509_print_fp(stdout, cert), -1,
                 "Failed to print x.509v3 in human readable format\n");    
#endif
 out_err:
        return;
}

/**
 * Function that converts the DER encoded X509 to X509 struct
 *
 * @param der points to DER encoded certificate
 * @param length of DER
 *
 * @return * X509
 */
X509 * hip_cert_der_to_x509(unsigned char * der, int length) {
        int err = 0;
        X509 * cert = NULL;

        _HIP_HEXDUMP("DER:\n", der, length);
        _HIP_DEBUG("DER length %d\n", length);

        HIP_IFEL(((cert = d2i_X509(NULL, &der , length)) == NULL), -1,
                 "Failed to convert cert from DER to internal format\n");
 out_err:
	if (err == -1) return NULL;
        return cert;
}

/**
 * Function that displays the contents of the PEM encoded x509 certificate
 *
 * @param pem points to PEM encoded certificate
 *
 * @return void 
 */
void hip_cert_display_x509_pem_contents(char * pem) {
        int err = 0;
	X509 * cert = NULL;

	cert = hip_cert_pem_to_x509(pem);
        HIP_IFEL((cert == NULL), -1, "Cert is NULL\n");
        HIP_DEBUG("x.509v3 certificate in readable format\n\n");
        HIP_IFEL(!X509_print_fp(stdout, cert), -1,
                 "Failed to print x.509v3 in human readable format\n");    
 out_err:
        return;
}

/**
 * Function that converts the PEM encoded X509 to X509 struct
 *
 * @param pem points to PEM encoded certificate
 *
 * @return *X509
 */
X509 * hip_cert_pem_to_x509(char * pem) {
        int err = 0;
        BIO *out = NULL; 
        X509 * cert = NULL;

        _HIP_DEBUG("PEM:\n%s\nLength of PEM %d\n", pem, strlen(pem));        
        out = BIO_new_mem_buf(pem, -1);      
        HIP_IFEL((NULL == (cert = PEM_read_bio_X509(out, NULL, 0, NULL))), -1,
                 "Cert variable is NULL\n");
 out_err:
        if (out) BIO_flush(out);
	if (err == -1) return NULL;
        return cert;
}
 
/**
 * Function that reads configuration section from HIP_CERTCONF_PATH,
 *
 * @param char pointer pointing to the name of desired section name
 *
 * @return STACK_OF(CONF_VALUE) pointer if ok and NULL if error or unsuccesfull. 
 */
STACK_OF(CONF_VALUE) * hip_cert_read_conf_section(char * section_name, CONF * conf) {
	long err = 0;
	int i;
	STACK_OF(CONF_VALUE) * sec;
	CONF_VALUE *item;
	
	_HIP_DEBUG("Started to read cert configuration file\n");

	conf = NCONF_new(NCONF_default());
	HIP_IFEL(!NCONF_load(conf, HIP_CERT_CONF_PATH, &err),
		 -1, "Error opening the configuration file");

	HIP_IFEL(!(sec = NCONF_get_section(conf, section_name)), -1,
		 "Section %s was not in the configuration (%s)\n", 
                 section_name,HIP_CERT_CONF_PATH);

	for (i = 0; i < sk_CONF_VALUE_num(sec); i++) {
		item = sk_CONF_VALUE_value(sec, i);
		_HIP_DEBUG("Sec: %s, Key; %s, Val %s\n", 
			  item->section, item->name, item->value);
	}
out_err:
	if (err == -1) return NULL;
	return sec;
}

/**
 * Function that opens an configuration file from HIP_CERTCONF_PATH,
 *
 * @param void
 *
 * @return CONF pointer if ok and NULL if error or unsuccesfull. 
 */
CONF * hip_cert_open_conf(void) {
	long err = 0;
	int i;
	CONF *conf = NULL;
	STACK_OF(CONF_VALUE) * sec;
	CONF_VALUE *item;
	
	_HIP_DEBUG("Started to read cert configuration file\n");

	conf = NCONF_new(NCONF_default());
	HIP_IFEL(!NCONF_load(conf, HIP_CERT_CONF_PATH, &err),
		 -1, "Error opening the configuration file");
out_err:
	if (err == -1) return NULL;
	return conf;
}

/**
 * Function that frees the memory of a allocated configuration
 *
 * @param CONF pointer to the to be freed configuration 
 *
 * @return void 
 */
void hip_cert_free_conf(CONF * conf) {
	if (conf) NCONF_free(conf);
}

/**
 * Function that goes through stack of conf values
 *
 * @param CONF pointer to the to be freed configuration 
 *
 * @return void 
 */
void hip_for_each_conf_value(STACK_OF(CONF_VALUE) * sconfv, 
                             int (func)(char * name, char * value, void *opaq) , 
                             void * opaque) {
        int err = 0, i = 0;
        CONF_VALUE *item;
        
        for (i = 0; i < sk_CONF_VALUE_num(sconfv); i++) {
                item = sk_CONF_VALUE_value(sconfv, i);
                _HIP_DEBUG("Sec: %s, Key; %s, Val %s\n", 
                          item->section, item->name, item->value);
                HIP_IFEL(func(item->name, item->value, opaque), -1, 
                         "Error, see above lines\n");
        }

 out_err:
        return;
}

/**
 * Function that wraps regular expression stuff and gives the answer :)
 *
 * @param what is a char pointer to the rule used in the search (POSIX)
 * @param from where are we looking for it char pointer
 * @param answer to the question in regmatch_t
 *
 * @return 0 if ok and negative if error. 
 * 
 * @note Be carefull with the what so you get what you want :)
 */
int hip_cert_regex(char * what, char * from, int * start, int * stop) {
        int err = 0, status = 0, i = 0;
        regex_t re;
        regmatch_t answer[1];
                
        /* Compiling the regular expression */
        HIP_IFEL(regcomp(&re, what, REG_EXTENDED), -1, 
                 "Compilation of the regular expression failed\n");       
        /* Running the regular expression */
        HIP_IFEL((status = regexec(&re, from, 1, answer, 0)), -1,
                 "No match for regexp or failed to run it\n");
        _HIP_DEBUG("Found \"%s\" at %d and it ends at %d\n",
                  what, answer[0].rm_so, answer[0].rm_eo); 

        *start = answer[0].rm_so;
        *stop = answer[0].rm_eo;

        /* Just for debugging do NOT leave these 2 lines uncommented */
        /*
        for (i = answer[0].rm_so; i < answer[0].rm_eo; i++) HIP_DEBUG("%c", from[i]);
        HIP_DEBUG("\n");
        */
 out_err:
	regfree(&re);
        return (err);
}

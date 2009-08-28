/** @file
 * A teststub for certtools.c/h
 *
 * File for testing the main operations of certtools.
 * First this test takes the default HIT and the corresponding key.
 * Secondly it creates a certificate where itself is the issuer and the subject.
 * Then it tries to verify it. If it succeeds everything should be OK :)
 *
 * @author Samu Varjonen
 *
 */
#include <sys/time.h>
#include <time.h>
#include <zlib.h>
#include "ife.h"
#include "icomm.h"
#include "debug.h"
#include "certtools.h"

void compression_test(unsigned char * orig, int len) {
	int err = 0;
        unsigned char original[1024];
        unsigned char compressed[1024];
        unsigned char uncompressed[1024];
        int return_value = 0;
        uLongf compressed_buf_length = 0; 
        uLongf uncompressed_buf_length = 0;

        HIP_DEBUG("Testing Zlib compression on the data\n");
        memset(&compressed, '\0', sizeof(compressed));
        memset(&uncompressed, '0', sizeof(uncompressed));
	memcpy(original, orig, len);

        compressed_buf_length = sizeof(compressed);
      
        return_value = compress2((Bytef *)compressed , &compressed_buf_length, 
                                (Bytef *)&original, (uLong)len,
                                 Z_BEST_COMPRESSION);

        if (return_value == Z_OK) HIP_DEBUG("Compression was succesfull\n");

        if (return_value == Z_BUF_ERROR) 
                HIP_DEBUG("Compression was NOT succesfull (given buffer is too small)\n");
        if (return_value == Z_MEM_ERROR) 
                HIP_DEBUG("Compression was NOT succesfull (not enough memory)\n");
        
        uncompressed_buf_length = sizeof(uncompressed);

        /* compressed_buf_length contains used buffer length after compress */
        HIP_DEBUG("Uncompressed data length: %d\n"
                  "Compressed data length: %d\n", 
                  len, compressed_buf_length); 

        return_value = uncompress((Bytef *)uncompressed, &uncompressed_buf_length,
                                  (Bytef *)compressed, (uLong)compressed_buf_length);

        if (return_value == Z_OK) HIP_DEBUG("Uncompression was succesfull\n");

        if (return_value == Z_BUF_ERROR) 
                HIP_DEBUG("Uncompression was NOT succesfull (given buffer is too small)\n");
        if (return_value == Z_MEM_ERROR) 
                HIP_DEBUG("Uncompression was NOT succesfull (not enough memory)\n");        

        if (memcmp(original, uncompressed, len) == 0)
                HIP_DEBUG("Uncompressed data did match the original\n\n");
        else
                HIP_DEBUG("Uncompressed data did NOT match the original\n\n");
out_err:
	return;
}
 
int main(int argc, char *argv[])
{
        int err = 0, i = 0, len;
        struct hip_cert_spki_info * cert = NULL;
        struct hip_cert_spki_info * to_verification = NULL;
        time_t not_before = 0, not_after = 0;
        struct hip_common *msg;
        struct in6_addr *defhit;
        struct hip_tlv_common *current_param = NULL;
        struct endpoint_hip *endp = NULL;
        char certificate[1024];
        unsigned der_cert[1024];
	CONF * conf;
	CONF_VALUE *item;
	STACK_OF(CONF_VALUE) * sec = NULL;
	STACK_OF(CONF_VALUE) * sec_general = NULL;
	STACK_OF(CONF_VALUE) * sec_name = NULL;
	STACK_OF(CONF_VALUE) * sec_ext = NULL;

	if (argc != 2) {
		printf("Usage: %s spki|x509\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

        HIP_DEBUG("- This test tool has to be run as root otherwise this will fail!\n") ;
        HIP_DEBUG("- Hipd has to run otherwise this will hang!\n");

        HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, 
                 "Malloc for msg failed\n");        
	defhit = malloc(sizeof(struct in6_addr));
	if (!defhit) goto out_err;

	if (strcmp(argv[1], "spki")) goto skip_spki; 

        HIP_DEBUG("Starting to test SPKI certficate tools\n");
       
        cert = malloc(sizeof(struct hip_cert_spki_info));
        if (!cert) goto out_err;
        
        to_verification = malloc(sizeof(struct hip_cert_spki_info));
        if (!to_verification) goto out_err;

        time(&not_before);
        time(&not_after);
	HIP_DEBUG("Reading configuration file (%s)\n", HIP_CERT_CONF_PATH);
	conf = hip_cert_open_conf();
	sec = hip_cert_read_conf_section("hip_spki", conf);

	for (i = 0; i < sk_CONF_VALUE_num(sec); i++) {
		item = sk_CONF_VALUE_value(sec, i);
		_HIP_DEBUG("Sec: %s, Key; %s, Val %s\n", 
			  item->section, item->name, item->value);
		if (!strcmp(item->name, "issuerhit")) {
			err = inet_pton(AF_INET6, item->value, defhit);
			if (err < 1) {
				err = -1;
				goto out_err;
			}
		}
		if (!strcmp(item->name, "days")) {
			_HIP_DEBUG("Days in sec = %d\n", HIP_CERT_DAY * atoi(item->value));
			not_after += HIP_CERT_DAY * atoi(item->value);
		} 
	}
	hip_cert_free_conf(conf);

        hip_cert_spki_create_cert(cert, 
                                  "hit", defhit,
                                  "hit", defhit,
                                  &not_before,
                                  &not_after);

        _HIP_DEBUG("\n\nPublic-key sequence contents after all is done:\n\n"
                  "%s\n\n", cert->public_key);
        
        _HIP_DEBUG("Cert sequence contents after all is done:\n\n"
                  "%s\n\n", cert->cert);
           
        _HIP_DEBUG("Signature sequence contents after all is done:\n\n"
                  "%s\n\n", cert->signature);
        /* 
           Concatenate everything together as if we would have gotten 
           it from someone else and we would be starting to verify. 

           So the process would be take the cert blob and take out
           public-key sequence, cert sequence and signature sequence
           and create a hip_cert_spki_info and send it to the daemon 
           for verification.
        */
        memset(&certificate, '\0', sizeof(certificate));
        sprintf(&certificate,"(sequence %s%s%s)", 
                cert->public_key, cert->cert, cert->signature);
        HIP_DEBUG("\n\nCertificate gotten back from daemon:\n\n"
                  "%s\n\nCertificate len %d\n\n",
                  certificate, strlen(certificate));

	compression_test(certificate, strlen(certificate));

        HIP_IFEL(hip_cert_spki_char2certinfo(certificate, to_verification), -1,
                 "Failed to construct the hip_cert_spki_info from certificate\n");

        /* 
           Send the cert to the daemon for verification 
           See also below about the verification function in libinet6
           XXTODO convert this to use the library also, if this is really needed
        */
        /*
        HIP_DEBUG("Sending the certificate to daemon for verification\n");

        HIP_IFEL(hip_cert_spki_send_to_verification(to_verification), -1,
                 "Failed in sending to verification\n");
        HIP_IFEL(to_verification->success, -1, 
                 "Verification was not successfull\n");
        HIP_DEBUG("Verification was successfull (return value %d)\n", 
                  to_verification->success);
        */
        /* Lets do the verification in library */
        HIP_IFEL(hip_cert_spki_lib_verify(to_verification), -1,
                 "Verification was not succesfull\n");
        HIP_DEBUG("Verification was successfull (return value %d)\n", 
                  to_verification->success);

	goto out_err;
	
skip_spki:
	HIP_DEBUG("Starting to test x509v3 support\n");

	conf = hip_cert_open_conf();
        sec_name = hip_cert_read_conf_section("hip_x509v3_name", conf);

	for (i = 0; i < sk_CONF_VALUE_num(sec_name); i++) {
		item = sk_CONF_VALUE_value(sec_name, i);
		_HIP_DEBUG("Sec: %s, Key; %s, Val %s\n", 
			  item->section, item->name, item->value);
		if (!strcmp(item->name, "issuerhit")) {
			err = inet_pton(AF_INET6, item->value, defhit);
			if (err < 1) {
				err = -1;
				goto out_err;
			}
		}
	}
        hip_cert_free_conf(conf);
        len = hip_cert_x509v3_request_certificate(defhit, der_cert); 

        hip_cert_display_x509_der_contents(der_cert, len);
        
	compression_test(der_cert, len);

        /** Now send it back for the verification **/
        HIP_IFEL(((err = hip_cert_x509v3_request_verification(der_cert, len)) < 0), -1,
		"Failed to verify a certificate\n");

 out_err:
        HIP_DEBUG("If there was no errors above, \"everything\" is OK\n");

        if (cert) free(cert);
        if (to_verification) free(to_verification);
        exit(err);
}


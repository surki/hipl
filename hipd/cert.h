#ifndef HIP_CERT_H
#define HIP_CERT_H

/** @file
 * A header file for cert.c
 *
 * Certificate signing and verification functions.
 * Syntax as follows, hip_cert_XX_YY_VV(), where 
 *   XX is the certificate type
 *   YY is build or verify
 *  VV is what the function really does like sign etc.
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "debug.h"
#include "ife.h"
#include "misc.h"
#include "hidb.h"
#include "hashtable.h"

/** SPKI **/
int hip_cert_spki_sign(struct hip_common *, HIP_HASHTABLE *);
int hip_cert_spki_verify(struct hip_common *);

/** x509v3 **/
int hip_cert_x509v3_handle_request_to_sign(struct hip_common *, HIP_HASHTABLE *);
int hip_cert_x509v3_handle_request_to_verify(struct hip_common *);

/** utilitary functions **/
int hip_cert_hostid2rsa(struct hip_host_id *, RSA *);
int hip_cert_hostid2dsa(struct hip_host_id *, DSA *);
int hip_cert_hostid2key(HIP_HASHTABLE *, hip_hit_t *, RSA **, DSA **);

#endif /* HIP_CERT_H */

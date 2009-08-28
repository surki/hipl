#ifndef HIPD_CRYPTO_H
#define HIPD_CRYPTO_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/time.h>
#include <time.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/types.h>
#include <string.h>
#include <netinet/in.h>

#include "hidb.h"
#include "debug.h"
#include "ife.h"
#include "hadb.h"
#define HIP_DSA_SIG_SIZE 41 /* T(1) + R(20) + S(20)  from RFC 2536 */
#define DSA_PRIV 20 /* Size in bytes of DSA private key and Q value */



/* These should be consistent with the table length in crypto.c and crypto/dh.c */
#define HIP_DH_384                    1 /* 384-bit group */
#define HIP_DH_OAKLEY_1               2 /* 768-bit OAKLEY well known group 1 */
#define HIP_DH_OAKLEY_5               3 /* 1536-bit MODP group */
#define HIP_DH_OAKLEY_15              4 /* 3072-bit MODP group */
#define HIP_DH_OAKLEY_17              5 /* 6144-bit MODP group */
#define HIP_DH_OAKLEY_18              6 /* 8192-bit MODP group */
#define HIP_FIRST_DH_GROUP_ID       HIP_DH_OAKLEY_5
#define HIP_SECOND_DH_GROUP_ID      HIP_DH_384
#define HIP_MAX_DH_GROUP_ID 7

//#define HIP_MAX_DSA_KEY_LEN 4096
#define HIP_MAX_DSA_KEY_LEN 1024 // Doesn't RFC 2536 limit this to 1024?
#define HIP_MAX_RSA_KEY_LEN 4096

//#define DSA_KEY_DEFAULT_BITS    (128 * 8)
//#define RSA_KEY_DEFAULT_BITS    1024

#define DSA_KEY_DEFAULT_BITS    1024
#define RSA_KEY_DEFAULT_BITS    1024

#ifdef ANDROID
#   define DEFAULT_CONFIG_DIR        "/system/etc/hip"
#else
#   define DEFAULT_CONFIG_DIR        "/etc/hip"
#endif
#define DEFAULT_CONFIG_DIR_MODE   0755
#define DEFAULT_HOST_DSA_KEY_FILE_BASE "hip_host_dsa_key"
#define DEFAULT_HOST_RSA_KEY_FILE_BASE "hip_host_rsa_key"
#define DEFAULT_PUB_FILE_SUFFIX ".pub"

#define DEFAULT_PUB_HI_FILE_NAME_SUFFIX "_pub"
#define DEFAULT_ANON_HI_FILE_NAME_SUFFIX "_anon"

/* Only one crypto-filefmt supported */
#define HIP_KEYFILE_FMT_HIP_PEM 1

#ifdef CONFIG_HIP_DEBUG
void keygen_callback(int a, int b, void* arg);
#define KEYGEN_CALLBACK keygen_callback
#else
#define KEYGEN_CALLBACK NULL
#endif

#ifdef OPENSSL_NO_SHA0
# define HIP_SHA(buffer, total_len, hash)	SHA1((buffer), (total_len), (hash));
#else
# define HIP_SHA(buffer, total_len, hash)	SHA((buffer), (total_len), (hash));
#endif

int ssl_rsa_verify(u8 *digest, u8 *public_key, u8 *signature, int pub_klen);
int ssl_dsa_verify(u8 *digest, u8 *public_key, u8 *signature);

int hip_init_cipher(void);
void hip_uninit_cipher(void);

/* In kernel these come from crypto/dh.h, included above */
int hip_gen_dh_shared_key(DH *dh, u8 *peer_key, size_t peer_len, u8 *out,
			  size_t outlen);
int hip_encode_dh_publickey(DH *dh, u8 *out, int outlen);
DH *hip_generate_dh_key(int group_id);
void hip_free_dh(DH *target);
u16 hip_get_dh_size(u8 hip_dh_group_type);

int dsa_to_hit(DSA *dsa_key, unsigned char *dsa, int type,
	       struct in6_addr *hit);
int rsa_to_hit(RSA *rsa_key, unsigned char *rsa, int type,
	       struct in6_addr *hit);
DSA *create_dsa_key(int bits);
RSA *create_rsa_key(int bits);
int save_dsa_private_key(const char *filenamebase, DSA *dsa);
int load_dsa_private_key(const char *filenamebase, DSA **dsa);
int load_dsa_public_key(const char *filenamebase, DSA **dsa);

int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len);
int hip_write_hmac(int type, void *key, void *in, int in_len, void *out);
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
			 void* enc_key, int direction);

#endif /* HIPD_CRYPTO_H */

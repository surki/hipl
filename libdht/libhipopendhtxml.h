#ifndef HIP_LIBHIPOPENDHTXML_H
#define HIP_LIBHIPOPENDHTXML_H

/** @file
 * A header file for libhipopendhtxml.c
 *
 * All xml-rpc message building functions for opendht.
 * Also contains base 64 encoding and decoding wrappers that should
 * be moved somewhere else because they are used also in cert stuff.
 *
 * @author Samu Varjonen
 * @version 0.2
 *
 */

/* All XML RPC packet creation and reading functions */

int build_packet_put_rm(unsigned char *, int, unsigned char *, 
                     int, unsigned char *, int, int, unsigned char*, char *, int);

int build_packet_put(unsigned char *, int, unsigned char *, 
                     int, int, unsigned char*, char *, int);

int build_packet_get(unsigned char *, int, int, unsigned char*, char *);

int build_packet_rm(unsigned char *, int, unsigned char *,
                    int, unsigned char *, int, int, unsigned char *, char *, int); 

int read_packet_content(char *, char *);

/* openSSL wrapper functions for base64 encoding and decoding */

unsigned char * base64_encode(unsigned char *, unsigned int);

unsigned char * base64_decode(unsigned char *, unsigned int *);

struct opendht_answers {
  int count;
  char addrs[440];
};

#endif /* HIP_LIBHIPOPENDHTXML_H */


/*
 * pfkey flush test (requires pfkey+sadb headers and pfkey from usagitoolkit)
 *
 * Example:
 * pfkey -A sa -T ah -S 0x1234 -p udp -s 3ffe:a:b:c:d::1 -d 3ffe:a:b:c:d::2 \
 *    --auth hmac-md5 --authkey 0x0123456789abcdef0123456789abcdef
 * pfkey -L
 * ./flush
 * pfkey -L
 *
 * tadaa!
 * 
 */

#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define uint8_t u_int8_t
#define uint16_t u_int16_t
#define uint32_t u_int32_t
#define uint64_t u_int64_t

// these headers have to be after unistd and socket, otherwise gcc
// would not compile this (weird)

#include <net/pfkeyv2.h>
#include <net/sadb.h>
#include <net/spd.h>

#define DIVUP(x,y) ((x + y -1) / y) /* divide, rounding upwards */
#define IPSEC_PFKEYv2_ALIGN (sizeof(uint64_t)/sizeof(uint8_t))

int main(int argc, char **argv) {
  int pf_sock = 0;
  ssize_t ret_size = 0;

  int error;
  struct sadb_msg msg_hdr;

  memset(&msg_hdr, 0, sizeof(msg_hdr));

  msg_hdr.sadb_msg_version = PF_KEY_V2;
  msg_hdr.sadb_msg_type = SADB_FLUSH;
  msg_hdr.sadb_msg_errno = 0;
  msg_hdr.sadb_msg_satype = SADB_SATYPE_UNSPEC;
  msg_hdr.sadb_msg_len = DIVUP(sizeof(msg_hdr), IPSEC_PFKEYv2_ALIGN);
  msg_hdr.sadb_msg_seq = 0;
  msg_hdr.sadb_msg_pid = getpid();

  pf_sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  if (pf_sock < 0) {
    perror("pf_sock");
    exit(1);
  }

  errno = 0;
  error = write(pf_sock, (char*)&msg_hdr, sizeof(msg_hdr));
  if(error<0){
    fprintf(stderr, "pfkey_send_flush: send error with %s\n", strerror(errno));
    exit(1);
  }

  fprintf(stderr, "succeeded\n");

  return 0;
  
}

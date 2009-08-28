/***************************************************************************
                          token_bucket.c  -  description
                             -------------------
    begin                : Nov 20 2002
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include "i3.h"
#include "i3_fun.h"
#include "i3_debug.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/***************************************************************************
 *  alloc_token_bucket - allocate a token bucket data structure
 *
 *  return:
 *    pointer to the allocated token bucket
 ***************************************************************************/

token_bucket *alloc_token_bucket()
{
  token_bucket *tb;

  tb = (token_bucket *)calloc(1, sizeof(token_bucket));
  if (tb) 
    return tb;
  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL,
	      "alloc_token_bucket: memory allocation error.\n");
  return NULL;
}


/***************************************************************************
 *  init_token_bucket - initialize token bucket's fields
 *
 *  return:
 *    pointer to the allocated token bucket 
 ***************************************************************************/

void init_token_bucket(token_bucket *tb, uint8_t type,
		       uint32_t depth, uint32_t r, uint32_t R)
{
  tb->type = type;
  tb->depth = depth;
  tb->r = r;
  tb->R = R;
}


/***************************************************************************
 *  free_token_bucket - free tb data structure 
 *
 *  input:
 *    tb to be freed
 ***************************************************************************/

void free_token_bucket(token_bucket *tb)
{
  free(tb);
}


/***************************************************************************
 *  duplicate_token_bucket - create a replica of a token bucket
 *
 *  input:
 *    tb - token bucket to be duplicated
 *
 *  return:
 *    replica of tb
 ***************************************************************************/

token_bucket *duplicate_token_bucket(token_bucket *tb)
{
  token_bucket *tbnew = alloc_token_bucket();

  init_token_bucket(tbnew, tb->type, tb->depth, tb->r, tb->R);

  return tbnew;
}




/***************************************************************************
 *  pack_token_bucket - convert a token bucket data structure in packet format
 *
 *  input:
 *    p - address of the buffer where the token bucket is to be stored in 
 *        packet format (the buffer is pre-allocated)
 *    tb - token bucket to be converted in packet format
 *    
 *  output:
 *    length - length of the token bucket in packet format
 ***************************************************************************/

void pack_token_bucket(char *p, token_bucket *tb, unsigned short *length)
{
  uint32_t temp;

  p[0] = tb->type;
  p += sizeof(char);
  *length = sizeof(char);

  temp = htons(tb->depth);
  memcpy(p, &temp, sizeof(uint32_t));
  p += sizeof(uint32_t);
  *length += sizeof(uint32_t);

  temp = htons(tb->r);
  memcpy(p, &temp, sizeof(uint32_t));
  p += sizeof(uint32_t);
  *length += sizeof(uint32_t);

  temp = htons(tb->R);
  memcpy(p, &temp, sizeof(uint32_t));
  p += sizeof(uint32_t);
  *length += sizeof(uint32_t);
}

unsigned short get_token_bucket_len()
{
  return 3*sizeof(uint32_t) + sizeof(uint8_t);
}


/***************************************************************************
 *  unpack_token_bucket - copy token bucket info from packet to a tb 
 *                        data structure 
 *
 *  input:
 *    p - address where token bucket is stored in packet format
 *   
 *  return:
 *    token bucket data structure
 * 
 *  output:
 *    length - length of the token bucket info in packet format
 *
 ***************************************************************************/

token_bucket *unpack_token_bucket(char *p, unsigned short *length)
{
  token_bucket *tb = alloc_token_bucket();

  tb->type = *p;
  *length = sizeof(char);
  p += sizeof(char);

  tb->depth = ntohs(*((uint32_t *)p));
  *length += sizeof(uint32_t);
  p += sizeof(uint32_t);

  tb->r = ntohs(*((uint32_t *)p));
  *length += sizeof(uint32_t);
  p += sizeof(uint32_t);

  tb->R = ntohs(*((uint32_t *)p));
  *length += sizeof(uint32_t);
  p += sizeof(uint32_t);

  return tb;
}


/***************************************************************************
 *  check_token_bucket - check token bucket whether is well-formed
 *
 *  input:
 *    p - address where token bucket is stored in packet format
 *   
 *  return:
 *    error code; FALSE if no error
 * 
 *  output:
 *    length - length of the token bucket info in packet format
 *
 ***************************************************************************/

int check_token_bucket(char *p, unsigned short *length)
{
  *length = 3*sizeof(uint32_t) + sizeof(uint8_t);
  return FALSE;
}


/***************************************************************************
 *  token_bucket_accept_pkt - check whether token bucket constraints
 *                            allow to send packet
 *
 *  input:
 *    tb  - token bucket
 *    len - packet length
 *   
 *  return:
 *    1 - if the packet can be sent,
 *    0 - if the packet cannot be sent (in this case, the packet is dropped)
 * 
 *
 ***************************************************************************/

int token_bucket_accept_pkt(token_bucket *tb, uint32_t len, uint64_t now)
{
  uint64_t tokens;

  assert(tb);

  /* update # of tokens in the bucket */
  tokens = (now - tb->last_time)*tb->r/1000000ULL;
  tb->tokens += tokens;

  if (tb->tokens == 0) {
    return 0;
  }

  if (tb->tokens <= tb->depth) {
    tb->last_time += tokens*1000000ULL/tb->r;
  } else {
    tb->last_time = now;
     /* number of tokens cannot exceed bucket's depth */ 
    tb->tokens = tb->depth;
  }

  if (tb->type == TOKEN_BUCKET_BYTE) {
    if (tb->tokens < len) {
       /* not enough tokens; cannot send the packet */
      return 0;
    }
    tb->tokens -= len;
    return 1;
  } else if (tb->type == TOKEN_BUCKET_PACKET) {
    if (tb->tokens < 1) {
      /* not enough tokens; cannot send the packet */
      return 0;
    }
    tb->tokens--;
    return 1;
  } else
    panic("token_bucket_accept_pkt: invalid token bucket type!\n");

  /* we shouldn't get here, but we need to return something
   * to make the compiler happy
   */
  return 0;
}
 

/****************************************
 ** print token bucket; just for test  **
 ****************************************/

void printf_token_bucket(token_bucket *tb, int indent)
{
  char buf[INDENT_BUF_LEN];

  memset(buf, ' ', INDENT_BUF_LEN);
  buf[indent] = 0;

  printf("%s type=%d, depth=%u, r=%u, R=%u (tokens=%u, last_time=%u)\n", 
	 buf, tb->type, tb->depth, tb->r, tb->R,
	 tb->tokens, tb->last_time);
}


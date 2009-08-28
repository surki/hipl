/***************************************************************************
                          token_bucket.h  -  description
                             -------------------
    begin                : Fre Jun 20 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef TOKEN_BUCKET_H
#define TOKEN_BUCKET_H
 
/* functions implemented in token_bucket.c */
token_bucket *alloc_token_bucket();
void free_token_bucket(token_bucket *tb);
void init_token_bucket(token_bucket *tb, uint8_t type,
		       uint32_t depth, uint32_t r, uint32_t R);
token_bucket *duplicate_token_bucket(token_bucket *tb);
void pack_token_bucket(char *p, token_bucket *tb, unsigned short *length);
unsigned short get_token_bucket_len();
token_bucket *unpack_token_bucket(char *p, unsigned short *length);
int check_token_bucket(char *p, unsigned short *length);
int token_bucket_accept_pkt(token_bucket *tb, uint32_t len, uint64_t now);
void printf_token_bucket(token_bucket *tb, int indent);

#endif // TOKEN_BUCKET_H 

/***************************************************************************
                          i3_id.h  -  description
                             -------------------
    begin                : Fre Jun 20 2003
    copyright            : (C) 2003 by Ion
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_ID_H
#define I3_ID_H
 
#include <stdio.h>

/* functions implemented in i3_id.c */
ID *alloc_i3_id();
void init_i3_id(ID *id, const ID *id1);
void free_i3_id(ID *id);
void pack_i3_id(char *packedid, ID *id, unsigned short *length);
ID *unpack_i3_id(char *p, unsigned short *length);
void printf_i3_id(ID *id, int intend);
void fprintf_i3_id(FILE *fp, ID *id, int intend);

char* sprintf_i3_id(char* s, const ID *id);
char* sprintf_i3_key(char* s, const Key *key);
ID* sscanf_i3_id(char *s, ID *id);
Key* sscanf_i3_key(char *s, Key *key);

ID *duplicate_i3_id(ID *id);
int compare_ids(ID *id1, ID *id2);
ID atoi3id(char *str);

/* for public ID constraints */
char get_id_type(ID *id);
void set_id_type(ID *id,  char type);
#define set_public_id(id) set_id_type(id, I3_ID_TYPE_PUBLIC)
#define set_private_id(id) set_id_type(id, I3_ID_TYPE_PRIVATE)

#endif

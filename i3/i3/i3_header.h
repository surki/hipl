/***************************************************************************
                          i3_header.h  -  description
                             -------------------
    begin                : Fre Jun 20 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef I3_HEADER_H
#define I3_HEADER_H

 
/* functions implemented in i3_header.c */
i3_header *alloc_i3_header();
void init_i3_header(i3_header *hdr, char data,
		    i3_stack *stack, i3_option_list *option_list);
i3_header *duplicate_i3_header(i3_header *h);
void free_i3_header(i3_header *hdr);
void pack_i3_header(char *packedhdr, i3_header *hdr,
		    unsigned short *length);
unsigned short get_i3_header_len(i3_header *hdr);
i3_header *unpack_i3_header(char *packedhdr, unsigned short *length);
int check_i3_header(char *p, int pkt_len);
char *get_first_id(char *packet);
void printf_i3_header(struct i3_header *hdr, int indent);

#endif

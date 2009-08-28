/***************************************************************************
                          i3_options.h  -  description
                             -------------------
    begin                : Fre Jun 20 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef I3_OPTIONS_H
#define I3_OPTIONS_H

/* functions implemented in i3_options.c */
i3_option *alloc_i3_option();
void init_i3_option(i3_option *option, char type, void *entry);
void free_i3_option(i3_option *option);
int is_local_option(i3_option *option);
int is_valid_option(i3_option *option);
i3_option_list *alloc_i3_option_list();
void free_i3_option_list(i3_option_list *option_list);
i3_option *get_i3_option_from_list(i3_option_list *option_list, int type);
int remove_local_i3_options(i3_option_list *option_list);
int remove_i3_option_from_list(i3_option_list *option_list, i3_option *opt);

void append_i3_option(i3_option_list *option_list,
		      i3_option *option);
void pack_i3_option(char *packedbuff, i3_option *option,
		    unsigned short *length);
unsigned short get_i3_option_len(i3_option *option); 
i3_option *unpack_i3_option(char *p, unsigned short *length);
int check_i3_option(char *p, unsigned short *length);
int sizeof_i3_option(char *p);
void pack_i3_option_list(char *p, i3_option_list *option_list,
			 unsigned short *length);
unsigned short get_i3_option_list_len(i3_option_list *option_list);
i3_option_list *unpack_i3_option_list(char *p, unsigned short *length);
int check_i3_option_list(char *p, unsigned short *length);
i3_option_list *duplicate_i3_option_list(i3_option_list *opt_list);
void printf_i3_option(i3_option *option, int intend);
void printf_i3_option_list(i3_option_list *option_list, int intend);
void printf_i3_option_type(int option_type);
#endif

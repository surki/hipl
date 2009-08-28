/***************************************************************************
                          i3_stack.h  -  description
                             -------------------
    begin                : Fre Jun 20 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef I3_STACK_H
#define I3_STACK_H
 
/* functions implemented in i3_stack.c */
i3_stack *alloc_i3_stack();
void init_i3_stack(i3_stack *s, ID *ids, int len);
void init_i3_stack2(i3_stack *s, ID **ids, int len);
void free_i3_stack(i3_stack *stack);
void pack_i3_stack(char *packedstack, i3_stack *stack,
		   unsigned short *length);
unsigned short get_i3_stack_len(i3_stack *stack);
i3_stack *unpack_i3_stack(char *p, unsigned short *length);
int check_i3_stack(char *p, unsigned short *length);
void printf_i3_stack(i3_stack *stack, int intend);
i3_stack *duplicate_i3_stack(i3_stack *s);


#endif

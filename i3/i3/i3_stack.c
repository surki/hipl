/***************************************************************************
                          i3_stack.c  -  description
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
 *  alloc_i3_stack - allocate a stack data structure
 *
 *  return:
 *    pointer to the allocated stack 
 ***************************************************************************/

i3_stack *alloc_i3_stack()
{
  i3_stack *stack;

  stack = (i3_stack *)malloc(sizeof(i3_stack));
  if (stack) {
    stack->ids = NULL;
    return stack;
  }
  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL,"alloc_i3_stack: memory allocation error.\n");
  return NULL;
}


/***************************************************************************
 *  alloc_i3_stack - allocate a stack data structure, and initialize
 *                   its fields
 *
 *  return:
 *    pointer to the allocated stack 
 ***************************************************************************/

void init_i3_stack(i3_stack *s, ID *ids, int len)
{
  s->len = len;
  s->ids = (ID *)malloc(sizeof(ID)*len);
  if (s->ids) {
    memcpy((char *)s->ids, ids, sizeof(ID)*len);
    return;
  }

  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL,"init_i3_stack: memory allocation error.\n");
}

void init_i3_stack2(i3_stack *s, ID **ids, int len)
{
  int i;

  s->len = len;
  s->ids = (ID *)malloc(sizeof(ID)*len);

  if (s->ids) {
    for (i = 0; i < len; i++) 
      memcpy((char *)s->ids, ids[i], sizeof(ID));
    return;
  }

  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL,"init_i3_stack2: memory allocation error.\n");
}


/***************************************************************************
 *  free_i3_stack - free stack data structure including its list of IDs 
 *
 *  input:
 *    stack to be freed
 ***************************************************************************/

void free_i3_stack(i3_stack *stack)
{
  if (stack->ids)
    free(stack->ids);
  free(stack);
}


/***************************************************************************
 *  duplicate_i3_stack - create a replica of stack s
 *
 *  input:
 *    s - stack to be duplicated
 *
 *  return:
 *    replica of s
 ***************************************************************************/

i3_stack *duplicate_i3_stack(i3_stack *s)
{
  i3_stack *snew = alloc_i3_stack();

  snew->len = s->len;
  if ((snew->ids = (ID *)malloc(sizeof(ID)*s->len))) {
    memcpy((char *)snew->ids, (char *)s->ids, sizeof(ID)*s->len);
    return snew;
  }

  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL,"init_i3_stack: memory allocation error.\n");
  return NULL;
}




/***************************************************************************
 *  pack_i3_stack - convert a stack data structure in packet format
 *
 *  input:
 *    p - address of the buffer where the stack is to be stored in 
 *        packet format (the buffer is pre-allocated)
 *    stack - stack to be converted in packet format
 *    
 *  output:
 *    length - length of the stack in packet format
 ***************************************************************************/

void pack_i3_stack(char *p, i3_stack *stack, unsigned short *length)
{
  int i;
  int num_ids;

  num_ids = (stack ? stack->len : 0);

  *p = (*p & 0xf0) + num_ids; /* init stack length */
  *length = sizeof(char); p += sizeof(char); /* skip stack len */

  if (!num_ids) return; /* no stack to pack */

  for (i = 0; i < num_ids; i++) { 
    memcpy(p, (char *)&stack->ids[i].x, sizeof(ID));
    *length += sizeof(ID); p += sizeof(ID);
  }
}

unsigned short get_i3_stack_len(i3_stack *stack)
{
  int num_ids;

  num_ids = (stack ? stack->len : 0);

  return (unsigned short) (sizeof(char) + num_ids*sizeof(ID)); 
}


/***************************************************************************
 *  unpack_i3_stack - copy stack info from packet to a stack 
 *                      data structure 
 *
 *  input:
 *    p - address where stack is stored in packet format
 *   
 *  return:
 *    stack data structure
 * 
 *  output:
 *    length - length of the stack info in packet format
 *
 ***************************************************************************/

i3_stack *unpack_i3_stack(char *p, unsigned short *length)
{
  int i, len;
  i3_stack *stack;

  len = *p & 0xf;
  
  if (!len) {
    /* there is no stack */
    *length = sizeof(char);
    return NULL;
  }

  stack = alloc_i3_stack();
  stack->len = len;
  *length = sizeof(char); 
  p += sizeof(char); /* skip stack len field */

  if (!(stack->ids = (ID*)malloc(stack->len*sizeof(ID))))
    panic("unpack_i3_stack: memory allocation error!\n");
  
  for (i = 0; i < stack->len; i++) { 
    memcpy((char *)&stack->ids[i].x, p, sizeof(ID));
    *length += sizeof(ID); p += sizeof(ID);
  }

  return stack;
}


/***************************************************************************
 *  check_i3_stack - check i3_stack whether is well-formed
 *
 *  input:
 *    p - address where stack is stored in packet format
 *   
 *  return:
 *    error code; FALSE if no error
 * 
 *  output:
 *    length - length of the stack info in packet format
 *
 ***************************************************************************/

int check_i3_stack(char *p, unsigned short *length)
{
  int len = *p & 0xf;
  
  *length = (int) (sizeof(char) + len*sizeof(ID));
  return FALSE;
}


/*************************************
 ** print i3_stack; just for test   **
 *************************************/

void printf_i3_stack(i3_stack *stack, int indent)
{
   char buf[INDENT_BUF_LEN];
   int i;
   uint k;

  memset(buf, ' ', INDENT_BUF_LEN);
  buf[indent] = 0;

  printf("%s stack:\n", buf);

  if (!stack)
    return;

  for (i = 0; i < stack->len; i++) {
    printf("%s   id(%u) = ", buf, i);
    for (k = 0; k < sizeof(ID); k++)
      printf("%x.", (int)(stack->ids[i].x[k])); 
    printf("\n");
  }
}


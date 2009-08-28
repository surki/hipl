/***************************************************************************
                          i3_options.c  -  description
                             -------------------
    begin                : Nov 21 2002
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
 *  alloc_i3_option - allocate i3 option data structure
 *
 *  return:
 *    pointer to the allocated data structure 
 ***************************************************************************/
struct i3_option *alloc_i3_option()
{
  struct i3_option *option;

   option = (i3_option *)calloc(1, sizeof(i3_option));
   if (option) 
      return option;

   I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL,"FATAL ERROR: memory allocation error in alloc_i3_option\n");
   return NULL;
}


/***************************************************************************
 *  init_i3_option - initialize i3 option data structure
 *
 *  input:
 *    option - data structure to be initialized
 *    type - option type
 *    entry - option entry, e.g., ret_addr, trigger (pre-allocated)
 *
 ***************************************************************************/
void init_i3_option(i3_option *option, char type, void * __RTTI entry)
{
  option->type = type;
  /* all are pointers; just use one type for assigment */
  if (type == I3_OPT_REQUEST_FOR_CACHE 
      || type == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT
      || type == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR 
#if NEWS_INSTRUMENT
      || type == I3_OPT_LOG_PACKET || type == I3_OPT_APPEND_TS
#endif
      )
    option->entry.nothing = (void *)NULL;
  else
    option->entry.trigger = (i3_trigger *)entry;
}

static void * __RTTI duplicate_i3_option_entry(char type, void * __RTTI entry)
{
  if (NULL == entry)
    return NULL;

  if (I3_OPT_SENDER == type || I3_OPT_DESTINATION == type)
    return duplicate_i3_addr((i3_addr *) entry);
  else if (I3_OPT_TRIGGER_INSERT == type ||
	   I3_OPT_TRIGGER_CHALLENGE == type ||
	   I3_OPT_CONSTRAINT_FAILED == type ||
	   I3_OPT_TRIGGER_ACK == type ||
	   I3_OPT_TRIGGER_REMOVE == type ||
	   I3_OPT_CACHE_ADDR == type ||
	   I3_OPT_CACHE_DEST_ADDR == type ||
	   I3_OPT_CACHE_SHORTCUT_ADDR == type ||
	   I3_OPT_FORCE_CACHE_ADDR == type ||
	   I3_OPT_ROUTE_BROKEN == type)
    return duplicate_i3_trigger((i3_trigger *) entry);
  else if (I3_OPT_TRIGGER_NOT_PRESENT == type ||
	   I3_OPT_TRIGGER_RATELIMIT == type)
    return duplicate_i3_id((ID *) entry);
  else {
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "duplicate_i3_option: invalid option type\n");
    return NULL;
  }
}

i3_option *duplicate_i3_option(i3_option *option)
{
    i3_option *new_option = alloc_i3_option();
    
    new_option->type = option->type;
    new_option->entry.trigger = (i3_trigger *)
	duplicate_i3_option_entry(option->type, (void *)option->entry.trigger);
    
    return new_option;
}

/***************************************************************************
 *  free_i3_option - free option data structure
 *
 *  input:
 *    data structure to be freed
 *
 ***************************************************************************/
void free_i3_option(i3_option *option)
{
  switch (option->type) {
  case I3_OPT_SENDER: 
    if (option->entry.ret_addr)
      free_i3_addr(option->entry.ret_addr);
    break;
  case I3_OPT_DESTINATION: 
    if (option->entry.dst_addr)
      free_i3_addr(option->entry.dst_addr);
    break;
  case I3_OPT_TRIGGER_INSERT:
  case I3_OPT_TRIGGER_CHALLENGE:
  case I3_OPT_CONSTRAINT_FAILED:
  case I3_OPT_TRIGGER_ACK: 
  case I3_OPT_TRIGGER_REMOVE:
  case I3_OPT_CACHE_ADDR:
  case I3_OPT_CACHE_DEST_ADDR:
  case I3_OPT_CACHE_SHORTCUT_ADDR:
  case I3_OPT_FORCE_CACHE_ADDR:
  case I3_OPT_ROUTE_BROKEN:
    if (option->entry.trigger)
      free_i3_trigger(option->entry.trigger);
    break;
  case I3_OPT_TRIGGER_NOT_PRESENT:
  case I3_OPT_TRIGGER_RATELIMIT:
    if (option->entry.id)
      free_i3_id(option->entry.id);
    break;
  case I3_OPT_REQUEST_FOR_CACHE:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR:
#if NEWS_INSTRUMENT
  case I3_OPT_LOG_PACKET:
  case I3_OPT_APPEND_TS:
#endif
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "free_i3_option: invalid option type: %d\n", option->type);
  }
  free(option);
}


i3_option_list *alloc_i3_option_list()
{
  i3_option_list *option_list;

  option_list = (i3_option_list *)malloc(sizeof(i3_option_list));
  if (option_list) {
    option_list->head = option_list->tail = NULL;
    return option_list;
  }

  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "alloc_i3_option_list: memory allocation error.\n");
  return NULL;
}


void free_i3_option_list(i3_option_list *option_list)
{
  i3_option *option;
 
  while (option_list->head) {
    option = option_list->head;
    option_list->head = option_list->head->next;
    free_i3_option(option);
  }
    
  free(option_list);
}



/***************************************************************************
 * Purpose: To check if an option is "local" to an i3 node
 * 	    or needs to be forwarded along a path
 * 
 * Example: I3_OPT_LOG_PACKET (ie. instrumenting to log packets)
 * 	needs to be forwarded along an i3 path, whereas I3_OPT_SENDER
 * 	is just for this i3 node in case any control mesg is returned
 * 	
 ***************************************************************************/
int is_local_option(i3_option *option)
{
#ifdef NEWS_INSTRUMENT
  if (option->type == I3_OPT_LOG_PACKET ||
      option->type == I3_OPT_APPEND_TS ||
      option->type == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT ||
      option->type == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR) {
    return FALSE;
  } else {
    return TRUE;
  }
#else
  if (option->type == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT ||
      option->type == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR) {
    /* this might be associated to another non-local option */
    return FALSE;
  } else {
    return TRUE;
  }
#endif
}



/***************************************************************************
 * Purpose: Returns true if the type of the option is valid
 * 
 **************************************************************************/
int is_valid_option(i3_option *option)
{
  char type = option->type;

  if (type == I3_OPT_SENDER ||
      type == I3_OPT_TRIGGER_INSERT ||
      type == I3_OPT_TRIGGER_CHALLENGE ||
      type == I3_OPT_CONSTRAINT_FAILED ||
      type == I3_OPT_TRIGGER_ACK ||
      type == I3_OPT_TRIGGER_REMOVE ||
      type == I3_OPT_TRIGGER_NOT_PRESENT ||
      type == I3_OPT_TRIGGER_RATELIMIT ||
      type == I3_OPT_REQUEST_FOR_CACHE ||
      type == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT ||
      type == I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR ||
      type == I3_OPT_ROUTE_BROKEN ||
      type == I3_OPT_DESTINATION ||
#if NEWS_INSTRUMENT
      type == I3_OPT_LOG_PACKET ||
      type == I3_OPT_APPEND_TS ||
#endif
      type == I3_OPT_CACHE_ADDR ||
      type == I3_OPT_CACHE_DEST_ADDR ||
      type == I3_OPT_CACHE_SHORTCUT_ADDR ||
      type == I3_OPT_FORCE_CACHE_ADDR)
    {
      return TRUE;
    } else {
      return FALSE;
    }
}


/***************************************************************************
 * Purpose: Find an option of a given type in the option list
 *
 * Return: pointer to option, if option found; NULL otherwise 
 * 
 ***************************************************************************/
i3_option *get_i3_option_from_list(i3_option_list *option_list, int type)
{
  i3_option *o;

  if (option_list == NULL)
    return NULL;

  for (o = option_list->head; o; o = o->next) 
    if (o->type == type)
      return o;
  return NULL;
}


/***************************************************************************
 * Purpose: Remove all the options that should not be forwarded in
 *	the path, ie. all opts such that is_local_option(opt) is true
 *
 * Return: 0 if there is nothing left in the option list, 1 otherwise
 * 
 ***************************************************************************/
int remove_local_i3_options(i3_option_list *option_list)
{
  i3_option *curr, *next, *prev;

  for (prev = 0, curr = option_list->head; curr != 0;) {
    next = curr->next;
    /* save I3_OPT_SENDER option just in case a non-local option needs it */
    if (is_local_option(curr) && (curr->type != I3_OPT_SENDER)) {
      free_i3_option(curr);
      
      if (NULL == prev)
	option_list->head = next;
      else
	prev->next = next;
    } else
      prev = curr;
    
    curr = next;
  }
  option_list->tail = prev;

  /* check whether there is any non-local option needing I3_OPT_SENDER 
   * option; if not remove it
   * XXX - now check only if I3_OPT_SENDER is the only option; 
   * need to be changed when more non-local options are added
   */
  if (  
            option_list &&  //FIX by Andrei
            option_list->head == option_list->tail && 
            option_list->head && //FIX by Andrei
            option_list->head->type == I3_OPT_SENDER
        ) {
    free_i3_option(option_list->head);
    option_list->head = option_list->tail = NULL;
  }

  return (NULL != option_list->tail);
}


/***************************************************************************
 * Purpose: Remove a option from the option list 
 *
 * Return: 0 if there is nothing left in the option list, 1 otherwise
 * 
 ***************************************************************************/

int remove_i3_option_from_list(i3_option_list *option_list, i3_option *opt)
{
  i3_option *o;

  assert(option_list);

  if (option_list->head == opt) {
    if (option_list->head == option_list->tail) 
      /* only option "opt" in the list */
      option_list->tail = NULL;
    option_list->head = option_list->head->next;
    free_i3_option(opt);
    return (NULL != option_list->tail);
  }

  for (o = option_list->head; o; o = o->next) {
    if (o->next == opt) {
      if (opt == option_list->tail) 
	/* "opt" is the last option in the list */
	option_list->tail = o;
      o->next = o->next->next;
      free_i3_option(opt);
    }
  }

  return (NULL != option_list->tail);
}


/***************************************************************************
 *  append_i3_option - append a new option to the option list
 *
 *  input:
 *    option_list - option list
 *    option - option to be added to the option_list
 ***************************************************************************/
void append_i3_option(i3_option_list *option_list, 
		      i3_option *option)
{
  if (!option_list->head)
    option_list->head = option_list->tail = option;
  else {
    option_list->tail->next = option;
    option_list->tail = option;
  }
}
 

/***************************************************************************
 *  pack_i3_option - convert an option data structure in packet format
 *
 *  input:
 *    p - address of the buffer where the option is to be stored in 
 *        packet format (pre-allocated)
 *    option - option data structure to be converted in packet format
 *    
 *  output:
 *    length - length of the option in packet format (bytes)
 ***************************************************************************/
void pack_i3_option(char *p, i3_option *option, 
		    unsigned short *length)
{
  unsigned short len;

  p[0] = option->type;
  p++; *length = 1; /* skip option's type */

  switch (option->type) {
  case I3_OPT_SENDER:
    pack_i3_addr(p, option->entry.ret_addr, &len);
    *length += len;
    break;
  case I3_OPT_DESTINATION:
    pack_i3_addr(p, option->entry.dst_addr, &len);
    *length += len;
    break;
  case I3_OPT_TRIGGER_INSERT: 
  case I3_OPT_TRIGGER_CHALLENGE:
  case I3_OPT_CONSTRAINT_FAILED:
  case I3_OPT_TRIGGER_ACK:
  case I3_OPT_TRIGGER_REMOVE:
  case I3_OPT_CACHE_ADDR:
  case I3_OPT_CACHE_DEST_ADDR:
  case I3_OPT_CACHE_SHORTCUT_ADDR:
  case I3_OPT_FORCE_CACHE_ADDR:
  case I3_OPT_ROUTE_BROKEN:
    pack_i3_trigger(p, option->entry.trigger, &len);
    *length += len;
    break;
  case I3_OPT_TRIGGER_NOT_PRESENT:
  case I3_OPT_TRIGGER_RATELIMIT:
    pack_i3_id(p, option->entry.id, &len);
    *length += len;
    break;
  case I3_OPT_REQUEST_FOR_CACHE:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR:
#if NEWS_INSTRUMENT
  case I3_OPT_LOG_PACKET:
  case I3_OPT_APPEND_TS:
#endif
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, 
		"pack_i3_option: invalid address type %d\n", option->type);
  }
}

unsigned short get_i3_option_len(i3_option *option) 
{
  unsigned short length;

  length = sizeof(char); /* option type */

  switch (option->type) {
  case I3_OPT_SENDER:
    length += get_i3_addr_len(option->entry.ret_addr);
    break;
  case I3_OPT_DESTINATION:
    length += get_i3_addr_len(option->entry.dst_addr);
    break;
  case I3_OPT_TRIGGER_INSERT: 
  case I3_OPT_TRIGGER_CHALLENGE:
  case I3_OPT_CONSTRAINT_FAILED:
  case I3_OPT_TRIGGER_ACK:
  case I3_OPT_TRIGGER_REMOVE:
  case I3_OPT_CACHE_ADDR:
  case I3_OPT_CACHE_DEST_ADDR:
  case I3_OPT_CACHE_SHORTCUT_ADDR:
  case I3_OPT_FORCE_CACHE_ADDR:
  case I3_OPT_ROUTE_BROKEN:
    length += get_i3_trigger_len(option->entry.trigger);
    break;
  case I3_OPT_TRIGGER_NOT_PRESENT:
  case I3_OPT_TRIGGER_RATELIMIT:
    length += sizeof(ID);
    break;
  case I3_OPT_REQUEST_FOR_CACHE:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR:
#if NEWS_INSTRUMENT
  case I3_OPT_LOG_PACKET:
  case I3_OPT_APPEND_TS:
#endif
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "pack_i3_option: invalid address type %d\n",option->type);
  }
  return length;
}


/***************************************************************************
 *  unpack_i3_option - allocate an i3 option data structure
 *                      and copy info from packet into it
 *
 *  input:
 *    p - address where option is stored in packet format
 *    
 *  output:
 *    length - length of the option in packet format (bytes)
 *
 ***************************************************************************/
i3_option *unpack_i3_option(char *p, unsigned short *length)
{
  i3_option *option = alloc_i3_option();
  unsigned short len = 0;

  option->type = p[0];
  p++; *length = 1;

  switch (option->type) {
  case I3_OPT_SENDER:
    option->entry.ret_addr = unpack_i3_addr(p, &len);
    p += len; 
    *length += len;
    break;
  case I3_OPT_DESTINATION:
    option->entry.dst_addr = unpack_i3_addr(p, &len);
    p += len; 
    *length += len;
    break;
  case I3_OPT_TRIGGER_INSERT: 
  case I3_OPT_TRIGGER_CHALLENGE:
  case I3_OPT_CONSTRAINT_FAILED:
  case I3_OPT_TRIGGER_ACK:
  case I3_OPT_TRIGGER_REMOVE:
  case I3_OPT_CACHE_ADDR:
  case I3_OPT_CACHE_DEST_ADDR:
  case I3_OPT_CACHE_SHORTCUT_ADDR:
  case I3_OPT_FORCE_CACHE_ADDR:
  case I3_OPT_ROUTE_BROKEN:
    option->entry.trigger = unpack_i3_trigger(p, &len);
    *length += len;
    break;
  case I3_OPT_TRIGGER_NOT_PRESENT:
  case I3_OPT_TRIGGER_RATELIMIT:
    option->entry.id = unpack_i3_id(p, &len);
    *length += len;
    break;
  case I3_OPT_REQUEST_FOR_CACHE:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR:
#if NEWS_INSTRUMENT
  case I3_OPT_LOG_PACKET:
  case I3_OPT_APPEND_TS:
#endif
    option->entry.nothing = (void *)NULL;
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "unpack_i3_option: invalid address type %d\n", option->type);
  }
  return option;
}

/***************************************************************************
 *  check_i3_option - check whether i3 option is well-formed
 *
 *  input:
 *    p - address where option is stored in packet format
 *    
 *  return:
 *    error code; FALSE if no error

 *  output:
 *    length - length of the option in packet format (bytes)
 *    
 ***************************************************************************/

int check_i3_option(char *p, unsigned short *length)
{
  unsigned short len = 0;
  char            option_type = p[0], type;
  int rc;

  p++; *length = 1; /* account for option's type */

  switch (option_type) {
  case I3_OPT_SENDER:
  case I3_OPT_DESTINATION:
    if ((rc = check_i3_addr(p, &len, &type)) != FALSE)
      return rc;
    *length += len;
    break;
  case I3_OPT_TRIGGER_INSERT: 
  case I3_OPT_TRIGGER_CHALLENGE:
  case I3_OPT_CONSTRAINT_FAILED:
  case I3_OPT_TRIGGER_ACK:
  case I3_OPT_TRIGGER_REMOVE:
  case I3_OPT_CACHE_ADDR:
  case I3_OPT_CACHE_DEST_ADDR:
  case I3_OPT_CACHE_SHORTCUT_ADDR:
  case I3_OPT_FORCE_CACHE_ADDR:
  case I3_OPT_ROUTE_BROKEN:
    if ((rc = check_i3_trigger(p, &len)) != FALSE)
      return rc;
    *length += len;
    break;
  case I3_OPT_TRIGGER_NOT_PRESENT:
  case I3_OPT_TRIGGER_RATELIMIT:
    *length += sizeof(ID);
    break;
  case I3_OPT_REQUEST_FOR_CACHE:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR:
#if NEWS_INSTRUMENT
  case I3_OPT_LOG_PACKET:
  case I3_OPT_APPEND_TS:
#endif
    break;
  default:
    return I3_ERR_INVALID_OPTION;
  }

  return FALSE;
}


/***************************************************************************
 *  pack_i3_option_list - store a list of options in packet format
 *
 *  input:
 *    packedbuff - address of the buffer where the option_list is to 
 *                 be stored in packet format (pre-allocated)
 *    option_list - list of options to be stored in packet format
 *    
 *  output:
 *    length - length of the entire list of option in packet format (bytes)
 ***************************************************************************/
void pack_i3_option_list(char *packedbuff, 
			 i3_option_list *option_list, 
			 unsigned short *length)
{
  unsigned short len;
  char           *p = packedbuff;
  i3_option *option;

  p += sizeof(unsigned short);      /* skip option list's length field */
  *length = sizeof(unsigned short); /* account for length field */

  for (option = option_list->head; option; option = option->next) {
    len = 0;
    pack_i3_option(p, option, &len);
    /* set the link flag */
    p += len;
    *length += len;  
  }
  len = htons(*length);
  memcpy(packedbuff, (char *)&len, sizeof(unsigned short));
}

unsigned short get_i3_option_list_len(i3_option_list *option_list)
{
  unsigned short length;
  i3_option      *option;

  length = sizeof(unsigned short); /* account for option list's length field */

  for (option = option_list->head; option; option = option->next) {
    length += get_i3_option_len(option);
  }

  return length;
}


/***************************************************************************
 *  unpack_i3_option_list - allocate an option list data structure
 *                          and copy info from packet into it
 *
 *  input:
 *    p - address where the option list is stored in packet format
 *    
 *  output:
 *    length - length of the option list info in packet format (bytes)
 *
 ***************************************************************************/
i3_option_list *unpack_i3_option_list(char *p, unsigned short *length)
{
  unsigned short len, len1;
  i3_option *option;
  i3_option_list *option_list = alloc_i3_option_list();

  *length = len1 = ntohs(*(unsigned short *)p); /* get option list's length */
  len1 -= sizeof(unsigned short); /* skip option list's length field */
  p += sizeof(unsigned short);

  while (len1) {
    option = unpack_i3_option(p, &len);
    append_i3_option(option_list, option);
    p += len;
    len1 -= len;
  }

  return option_list;
}

/***************************************************************************
 *  check_i3_option_list - check whether the option list is well formatted
 *
 *  input:
 *    p - address where the option list is stored in packet format
 *    
 *  return:
 *    error code; FALSE, if no error
 *
 *  output:
 *    length - length of the option list info in packet format (bytes)
 *
 ***************************************************************************/
int check_i3_option_list(char *p, unsigned short *length)
{
  unsigned short len;
  int ol_len;
  int rc;

  ol_len = ntohs(*(unsigned short *)p); /* get option list's length */
  p += sizeof(unsigned short);
  *length = sizeof(unsigned short); 
  ol_len -= sizeof(unsigned short); /* account for option length */ 

  while (ol_len) {
    rc = check_i3_option(p, &len);
    if (rc != FALSE)
      return rc;
    p += len;
    ol_len -= len;
    if (ol_len < 0)
      return I3_ERR_INVALID_OPTLIST;
  }

  if (ol_len) /* ol_len should be zero */
    return I3_ERR_INVALID_OPTLIST;
    
  return FALSE;
}


/***************************************************************************
 * duplicate_i3_option_list - perform a deep copy
 **************************************************************************/
i3_option_list *duplicate_i3_option_list(i3_option_list *option_list)
{
    i3_option *option, *new_option;
    i3_option_list *new_option_list = alloc_i3_option_list();
    
    for (option = option_list->head; option; option = option->next) {
	new_option = duplicate_i3_option(option);
	append_i3_option(new_option_list, new_option);
    }

    return new_option_list;
}


/*******************************************
 ** print i3_option; just for debbuging   **
 *******************************************/
void printf_i3_option(i3_option *option, int indent)
{
  char buf[INDENT_BUF_LEN];

  memset(buf, ' ', INDENT_BUF_LEN);
  buf[indent] = 0;

  printf("%s option type = ", buf);
  printf_i3_option_type(option->type); printf("\n");

  switch (option->type) {
  case I3_OPT_SENDER:
    printf_i3_addr(option->entry.ret_addr, indent + INDENT_CONST);
    break;
  case I3_OPT_DESTINATION:
    printf_i3_addr(option->entry.dst_addr, indent + INDENT_CONST);
    break;
  case I3_OPT_TRIGGER_INSERT: 
  case I3_OPT_TRIGGER_CHALLENGE:
  case I3_OPT_CONSTRAINT_FAILED:
  case I3_OPT_TRIGGER_ACK:
  case I3_OPT_TRIGGER_REMOVE:
  case I3_OPT_CACHE_ADDR:
  case I3_OPT_CACHE_DEST_ADDR:
  case I3_OPT_CACHE_SHORTCUT_ADDR:
  case I3_OPT_FORCE_CACHE_ADDR:
  case I3_OPT_ROUTE_BROKEN:
    printf_i3_trigger(option->entry.trigger, indent + INDENT_CONST);
    break;
  case I3_OPT_TRIGGER_NOT_PRESENT:
  case I3_OPT_TRIGGER_RATELIMIT:
    printf_i3_id(option->entry.id, indent + INDENT_CONST);
    break;
  case I3_OPT_REQUEST_FOR_CACHE:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT:
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR:
#if NEWS_INSTRUMENT
  case I3_OPT_LOG_PACKET:
  case I3_OPT_APPEND_TS:
#endif
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "printf_i3_option: invalid address type %d\n", option->type);
  }
}


/**************************
 ** print i3_option_list **
 **************************/
void printf_i3_option_list(i3_option_list *option_list, int indent)
{
  i3_option *option;
  char buf[INDENT_BUF_LEN];

  memset(buf, ' ', INDENT_BUF_LEN);
  buf[indent] = 0;

  printf("%s option list:\n", buf);

  for (option = option_list->head; option; option = option->next) 
   printf_i3_option(option, indent + INDENT_CONST); 
}


void printf_i3_option_type(int option_type)
{
  switch (option_type) {
  case I3_OPT_SENDER:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_SENDER\n");
    break;
  case I3_OPT_DESTINATION:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_DESTINATION");
    break;
  case I3_OPT_TRIGGER_INSERT: 
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_TRIGGER_INSERT");
    break;
  case I3_OPT_TRIGGER_CHALLENGE:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_TRIGGER_CHALLENG");
    break;
  case I3_OPT_CONSTRAINT_FAILED:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_CONSTRAINT_FAILED");
    break;
  case I3_OPT_TRIGGER_ACK:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_TRIGGER_ACK");
    break;
  case I3_OPT_TRIGGER_REMOVE:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_TRIGGER_REMOVE");
    break;
  case I3_OPT_CACHE_ADDR:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_CACHE_ADDR");
    break;
  case I3_OPT_CACHE_DEST_ADDR:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_CACHE_DEST_ADDR");
    break;
  case I3_OPT_CACHE_SHORTCUT_ADDR:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_CACHE_SHORTCUT_ADDR");
    break;
  case I3_OPT_FORCE_CACHE_ADDR:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_FORCE_CACHE_ADDR");
    break;
  case I3_OPT_ROUTE_BROKEN:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_ROUTE_BROKEN");
    break;
  case I3_OPT_TRIGGER_NOT_PRESENT:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_TRIGGER_NOT_PRESENT");
    break;
  case I3_OPT_TRIGGER_RATELIMIT:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_TRIGGER_RATELIMIT");
  case I3_OPT_REQUEST_FOR_CACHE:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_REQUEST_FOR_CACHE");
    break;
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_REQUEST_FOR_CACHE_SHORTCUT");
    break;
  case I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR:
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "I3_OPT_REQUEST_FOR_CACHE_SHORTCUT_INDIR");
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "%d", option_type);
  }
}

/***************************************************************************
                          i3_id.c  -  description
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
#include <ctype.h>

/***************************************************************************
 *  alloc_i3_id - allocate a indientifie data structure
 *
 *  return:
 *    allocated identifier 
 ***************************************************************************/

ID *alloc_i3_id()
{
  ID *id;

  if ((id = (ID *)malloc(sizeof(ID))) == NULL)
        I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "alloc_i3_id: memory allocation error.\n");
  return id;
}


/***************************************************************************
 *  init_i3_id - initialized identifier
 *
 *  input
 *    id, id1 - set id to id1
 *    
 ***************************************************************************/

void init_i3_id(ID *id, const ID *id1)
{
  memcpy(id->x, id1->x, sizeof(ID));
}


/***************************************************************************
 *  free_i3_id - free identifier
 *
 *  input:
 *    id to be freed
 ***************************************************************************/

void free_i3_id(ID *id)
{
  free(id);
}


/***************************************************************************
 *  duplicate_i3_id - create a replica of identifier id
 *
 *  input:
 *    id - identifier to be duplicated
 *
 *  return:
 *    replica of id
 ***************************************************************************/

ID *duplicate_i3_id(ID *id)
{
  ID *idnew = alloc_i3_id();

  init_i3_id(idnew, id);
  return idnew;
}

/***************************************************************************
 *  pack_i3_id - convert identifier in packet format
 *
 *  input:
 *    p - address of the buffer where the id is to be stored in 
 *        packet format (the buffer is pre-allocated)
 *    id - id to be converted in packet format
 *    
 *  output:
 *    length - length of the identifier in packet format
 ***************************************************************************/

void pack_i3_id(char *p, ID *id, unsigned short *length)
{
  memcpy(p, id->x, sizeof(ID));
  *length = sizeof(ID);
}



/***************************************************************************
 *  unpack_i3_id - copy identifier info from packet to an identifier 
 *                 data structure 
 *
 *  input:
 *    p - address where identifier is stored in packet format
 *   
 *  return:
 *    id - identifier data structure
 * 
 *  output:
 *    length - length of the id info in packet format
 *
 ***************************************************************************/

ID *unpack_i3_id(char *p, unsigned short *length)
{
  ID *id = alloc_i3_id();
 
  memcpy(id->x, p, sizeof(ID));
  *length = sizeof(ID);

  return id;
}

// Assume: s has enough space
/**
  * This function prints the ID specified by <code>id</code>
  * in the character pointed to by <code>s</code>.
  * It is assumed that enough space has already been allocated
  * for the character array.
  * @param s  the character array into which the id should be printed.
  * @param id the ID to be printed.
  * @return Returns the same pointer as that passed in parameter <code>s</code>.  
  * This is useful when you want to use sprintf_i3_id as part of some other 
  * printf statement.
  */
char* sprintf_i3_id(char* s, const ID *id)
{
   uint i; 

   *s = 0;
   for (i = 0; i < sizeof(ID); i++)
   {
     char ts[20];
     sprintf(ts, "%02x", (int)(id->x[i]));
     strcat(s,ts);
   }

   return s;
}

/**
 * This function can read back the ID from the 
 * string printed by sprintf_i3_id.
 */
ID* sscanf_i3_id(char *id_str, ID* id) {
  uint i;
  int c;
  for (i = 0; i < sizeof(ID); i++) {
    sscanf(id_str, "%02x", &c);
    id->x[i] = (uint8_t)c;
    id_str += 2;
  }
  return id;
}

char* sprintf_i3_key(char* s, const Key *key)
{
   uint i; 

   *s = 0;
   for (i = 0; i < sizeof(Key); i++)
   {
     char ts[20];
     sprintf(ts, "%02x", (int)(key->x[i]));
     strcat(s,ts);
   }

   return s;
}


/**
 * This function can read back the Key from the 
 * string printed by sprintf_i3_key.
 */
Key* sscanf_i3_key(char *id_str, Key *key) {
  uint i; 
  int c;
  for (i = 0; i < sizeof(Key); i++) {
    sscanf(id_str, "%02x", &c);
    key->x[i] = (uint8_t) c;
    id_str += 2;
  }

  return key;
}
/*************************************
 ** print i3_id; just for test   **
 *************************************/

void fprintf_i3_id(FILE *fp, ID *id, int indent)
{
   char buf[INDENT_BUF_LEN];
   uint i;

  memset(buf, ' ', INDENT_BUF_LEN);
  buf[indent] = 0;

  fprintf(fp, "%s id: ", buf);
  for (i = 0; i < sizeof(ID); i++)
    fprintf(fp, "%02x", (int)(id->x[i])); 
  fprintf(fp, "\n");
}

void printf_i3_id(ID *id, int indent)
{
   char buf[INDENT_BUF_LEN];
   uint i;

  memset(buf, ' ', INDENT_BUF_LEN);
  buf[indent] = 0;

  printf("%s id: ", buf);
  for (i = 0; i < sizeof(ID); i++)
    printf("%02x", (int)(id->x[i])); 
  printf("\n");
}

/************************************************************************
 * Compare two ids and return an integer less than, equal  to, or
 * greater than zero if id1 is found, respectively, to be less than,
 * to match, or be greater than s2.
 ***********************************************************************/
int compare_ids(ID *id1, ID *id2)
{
    assert(NULL != id1 && NULL != id2);
    return memcmp(id1->x, id2->x, ID_LEN);
}

/************************************************************************
 * Purpose: Convert a string to i3 id eg. read from file
 * XXX Check where this should be included ... may be in some other
 * file -- To check for bugs also
 ***********************************************************************/
static unsigned char todigit(char ch)
{
    if (isdigit((int) ch))
	return (ch - '0');
    else
	return (10 + ch - 'a');
}

ID atoi3id(char *str)
{
    ID id;
    int i, len;
    
	len = (int) strlen(str);
	assert(len <= 2*ID_LEN);
    memset(id.x, 0, ID_LEN);
    
    if (len % 2 != 0) {
	str[len] = '0';
	len++;
    }
    
    for (i = 0; i < len/2; i++)
	id.x[ i ] = (todigit(str[2*i]) << 4) | todigit(str[2*i+1]);

    str[len--] = 0;	// to restore old str
    return id;
}

/************************************************************************
 * Purpose:  Public ID constraint
 * 	Public IDs (ie. IDs that need to be protected from
 * 	impersonation) need to have "public_id" bit set. The public_id
 * 	bit is the last bit in the prefix.
 ***********************************************************************/
void set_id_type(ID *id,  char type)
{
    uint8_t mask = 1;

    if (I3_ID_TYPE_PUBLIC == type) {
	
        // last two bits 01 if UNCONSTRAINED type exists
        id->x[PREFIX_LEN-1] |= mask;
        //id->x[PREFIX_LEN - 2] &= ~mask;
        
    } else if (I3_ID_TYPE_PRIVATE == type) {
	     
        // last two bits 00 if UNCONSTRAINED ID type exists
        id->x[PREFIX_LEN-1] &= ~mask;
        //id->x[PREFIX_LEN - 2] &= ~mask;
   
    /**
    } else if (I3_ID_TYPE_UNCONSTRAINED == type) {
        
        // last two bits 10
        id->x[PREFIX_LEN - 2] |= mask;
        id->x[PREFIX_LEN - 1] &= ~mask;
    */
        
    } else {
	    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "set_id_type: Unknown type: %d\n", type);
    }
}

char get_id_type(ID *id)
{
    uint8_t mask = 1;

    /* Only if UNCONSTRAINED id type exists
    if ((id->x[PREFIX_LEN - 2] & mask) == 1) {
        //second last bit 1
        if ((id->x[PREFIX_LEN - 1] & mask) == 1) {
            //last bit 1
            return I3_ID_TYPE_UNKNOWN;
        } else {
            // last bit 0
            return I3_ID_TYPE_UNCONSTRAINED;
        }
    } else {
        //second last bit 0

    */
        if ((id->x[PREFIX_LEN-1] & mask) == 1) {
            //last bit 1
	        return I3_ID_TYPE_PUBLIC;
        } else {
            //last bit 0
	        return I3_ID_TYPE_PRIVATE;
        }

    /* Only if UNCONSTRAINED id type exists
       }
    */
}

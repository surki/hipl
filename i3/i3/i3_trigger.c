/***************************************************************************
                          i3_trigger.c  -  description
                             -------------------
    begin                : Nov 18 2002
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include "i3.h"
#include "i3_fun.h"
#include "i3_debug.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../aeshash/aes.h"


/***************************************************************************
 *  alloc_i3_trigger - allocate trigger data structure
 *
 *  return:
 *    pointer to the allocated data structure 
 ***************************************************************************/

i3_trigger *alloc_i3_trigger()
{
  i3_trigger *trigger;

  /* XXX: just simply call alloc for now; preallocate a pool of buffers 
     in the future */
  trigger = (i3_trigger *)calloc(1, sizeof(i3_trigger));
  trigger->flags = 0;
  trigger->tb = NULL;
  
  if (trigger) 
    return trigger;
  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL,"alloc_i3_trigger: memory allocation error.\n");
  return NULL;
}


/***************************************************************************
 *  init_i3_trigger - initialize trigger fields
 *
 *  input:
 *    t - trigger to be initialized
 *    prefix_len - prefix length
 *    id - trigger ID
 *    to - pointer to the address where packets matching "id"
 *         are forwarded (this data structure is not copied; don't
 *         free it after calling the function)
 *
 *  note:
 *    the nonce field is updated separately; see update_nonce() function
 ***************************************************************************/

void init_i3_trigger(i3_trigger *t, ID *id, uint16_t prefix_len,
		     i3_addr *to, Key *key, uint8_t flags)
{
  t->flags = flags;
  memcpy((char *)&t->id.x, id->x, sizeof(ID));
  t->prefix_len = prefix_len;
  t->to = to;
  if (key) {
      memcpy(t->key.x, key->x, KEY_LEN);
  }
}

/***************************************************************************
 *  free_i3_trigger - free trigger data structure
 *
 *  input:
 *    trigger to be freed
 *
 ***************************************************************************/

void free_i3_trigger(i3_trigger *trigger)
{
  /* XXX: just simply call free for now ... */
  if (trigger->to)
    free_i3_addr(trigger->to);
  if (trigger->tb)
    free_token_bucket(trigger->tb);
  free(trigger);
}



/***************************************************************************
 *  duplicate_i3_trigger - create a replica of trigger t
 *
 *  input:
 *    t - trigger to be duplicated
 *
 *  return:
 *    t's replica
 ***************************************************************************/

i3_trigger *duplicate_i3_trigger(i3_trigger *t)
{
  i3_trigger *tnew = alloc_i3_trigger();

  tnew->flags = t->flags;
  memcpy((char *)&tnew->id.x, (char *)&t->id.x, sizeof(ID));
  tnew->prefix_len = t->prefix_len;
  memcpy((char *)tnew->nonce, (char *)t->nonce, NONCE_LEN);
  tnew->to = duplicate_i3_addr(t->to);
  memcpy(tnew->key.x, t->key.x, KEY_LEN);
  if (t->flags & I3_TRIGGER_FLAG_RATE_LIMIT) {
    assert(t->tb);
    tnew->tb = duplicate_token_bucket(t->tb);
  }
  return tnew;
}




/***************************************************************************
 *  pack_i3_trigger - convert a trigger data structure in packet format
 *
 *  input:
 *    p - address of the buffer where the trigger is to be stored in 
 *        packet format (pre-allocated)
 *    trigger - trigger to be converted in packet format
 *    
 *  output:
 *    length - length of the trigger in packet format
 ***************************************************************************/

void pack_i3_trigger(char *p, i3_trigger *trigger, 
		     unsigned short *length)
{
  unsigned short len = 0, temp;

  *p = trigger->flags;
  p += sizeof(char);
  *length = sizeof(char);

  memcpy(p, &trigger->id.x, sizeof(ID));
  p += sizeof(ID); 
  *length += sizeof(ID);

  temp = htons(trigger->prefix_len);
  memcpy(p, &temp, sizeof(uint16_t));
  p += sizeof(uint16_t);
  *length += sizeof(uint16_t);

  memcpy(p, trigger->nonce, NONCE_LEN);
  p += NONCE_LEN; 
  *length += NONCE_LEN;

  pack_i3_addr(p, trigger->to, &len);
  *length += len;
  p += len;

  if (I3_ADDR_TYPE_STACK != trigger->to->type) {
    memcpy(p, trigger->key.x, KEY_LEN);
    *length += KEY_LEN;
    p += KEY_LEN;
  }

  if (trigger->flags & I3_TRIGGER_FLAG_RATE_LIMIT) {
    assert(trigger->tb);
    pack_token_bucket(p, trigger->tb, &len);
    *length += len;
    p += len;
  }
}

unsigned short get_i3_trigger_len(i3_trigger *trigger) 
{
  unsigned short length;

  length = sizeof(char) + sizeof(ID); // flags + id

  length += sizeof(uint16_t); /* prefix length */

  length += NONCE_LEN;

  length += get_i3_addr_len(trigger->to);

  if (I3_ADDR_TYPE_STACK != trigger->to->type) {
      length += KEY_LEN;
  }

  if (trigger->flags & I3_TRIGGER_FLAG_RATE_LIMIT) {
      assert(trigger->tb);
      length += get_token_bucket_len();
  }

  return length;
}


/***************************************************************************
 *  unpack_i3_trigger - allocate an i3_trigger data structure
 *                      and copy info from packet into it
 *
 *  input:
 *    p - address where trigger is stored in packet format
 *    
 *  output:
 *    length - length of the trigger info in packet format
 *
 ***************************************************************************/

i3_trigger *unpack_i3_trigger(char *p, unsigned short *length)
{
  i3_trigger *trigger = alloc_i3_trigger();
  unsigned short len;

  trigger->flags = *p;
   
  *length = sizeof(char);
  p += sizeof(char);

  memcpy(&trigger->id.x, p, sizeof(ID));
  *length += sizeof(ID); 
  p += sizeof(ID);

  trigger->prefix_len = ntohs(*((uint16_t *)p));
  *length += sizeof(uint16_t);
  p += sizeof(uint16_t);

  memcpy(&trigger->nonce, p, NONCE_LEN);
  *length += NONCE_LEN; 
  p += NONCE_LEN;

  trigger->to = unpack_i3_addr(p, &len);
  *length += len;
  p += len;

  if (I3_ADDR_TYPE_STACK != trigger->to->type) {
      memcpy(trigger->key.x, p, KEY_LEN);
      *length += KEY_LEN;
      p += KEY_LEN;
  }

  if (trigger->flags & I3_TRIGGER_FLAG_RATE_LIMIT) {
      trigger->tb = unpack_token_bucket(p, &len);
      *length += len;
      p += len;
  }
  
   return trigger;
}


/***************************************************************************
 *  check_i3_trigger - check whether i3 trigger is well-formed
 *
 *  input:
 *    p - address where trigger is stored in packet format
 *
 *  return:
 *    error code; FALSE if no error
 *
 *  output:
 *    length - length of the trigger info in packet format
 *
 ***************************************************************************/

int check_i3_trigger(char *p, unsigned short *length)
{
  unsigned short len;
  char type, flags;
  int rc;

  flags = p[0];
  *length = sizeof(char); /* Flags */
  p += sizeof(char);

  *length += sizeof(ID); /* ID */
  p += sizeof(ID);

  *length += sizeof(uint16_t); /* prefix len */
  p += sizeof(uint16_t);

  *length += NONCE_LEN;  /* nonce */
  p += NONCE_LEN;

  if ((rc = check_i3_addr(p, &len, &type)) != FALSE)
    return rc;

  *length += len;

  if (I3_ADDR_TYPE_STACK != type) 
    *length += KEY_LEN;
  
  if (flags & I3_TRIGGER_FLAG_RATE_LIMIT) 
    *length += get_token_bucket_len();

  return FALSE;
}



/***************************************************************************
 *  trigger_equal - compare two triggers
 *
 *  input:
 *    t1, t2 - triggers to be compared
 *    
 *  return:
 *    TRUE, if triggers are identical; FALSE, if they are not
 *
 *  note:
 *    ingnore the "id" field since this function is used to compare 
 *    triggers with the same ids; also ignore the "nonce" field as
 *    the nonce is checked when the trigger is inserted
 *
 ***************************************************************************/

int trigger_equal(i3_trigger *t1, i3_trigger *t2)
{
  if (memcmp(t1->id.x, t2->id.x, ID_LEN)) {
      return FALSE;
  }
//   if (memcmp(t1->key.x, t2->key.x, KEY_LEN))
//       return FALSE;
  return addr_equal(t1->to, t2->to);
}


/***************************************************************************
 *  update_nonce - compute nonce of a given trigger
 *
 *  input:
 *    t - given trigger
 *
 *  note:
 *    the algorithm to compute a nonce is trival now; it will be
 *    modified in the future
 ***************************************************************************/

void update_nonce(i3_trigger *t)
{
  compute_nonce(t->nonce, t->to);
}

/***************************************************************************
 *  check_nonce - check the nonce of a given trigger
 *
 *  input:
 *    t - given trigger
 *
 *  note:
 *    obviously, this function has to implement the same algorithm to
 *    compute the nonce as "update_nonce"! So if the algorithm is changed
 *    this needs to be done in both "check_nonce" and "update_nonce" 
 *    functions
 *
 ***************************************************************************/

int check_nonce(i3_trigger *t)
{
  char nonce[NONCE_LEN];

  compute_nonce(nonce, t->to);
  
  if (!memcmp(nonce, t->nonce, NONCE_LEN))
    return TRUE;
  else
    return FALSE;
}

  
/*******************************************************
 ** print i3_trigger -- this is for debuging proposes **
 *******************************************************/

void printf_i3_trigger(i3_trigger *trigger, int indent)
{
  int i;
  char buf[INDENT_BUF_LEN];

  memset(buf, ' ', indent);
  buf[indent] = 0;

  printf("%s flags = %x\n", buf, trigger->flags);
  printf_i3_id(&trigger->id, indent + 2);
  printf("%s  prefix_len: %d\n", buf, trigger->prefix_len);
  printf("%s nonce = ", buf);
  for (i=0; i < NONCE_LEN; i++)
    printf("%d.", trigger->nonce[i]);
  printf("\n");
  printf_i3_addr(trigger->to, indent + 2);
  if (trigger->flags & I3_TRIGGER_FLAG_RATE_LIMIT) 
    printf_token_bucket(trigger->tb, indent + 2);
}

/********************************************************
 *
 * Constrained triggers:
 * --------------------
 *
 *  T = (x, y), where {x,y} E I3_Addr
 *  Also, x = [x.prefix | x.key | x.suffix]
 *
 *  l-constraint: 
 *  	if y E ID
 *  	  	x.key = h_l(y)
 *  	else if y E IP Addr
 *  		x.key = h_l(y.key)
 *  		
 *  r-constraint:
 *  	y.key = h_r(x)
 *
 *
 * For generating a 256->128 hash fn from a 128->128 hash function,
 * foll is done:
 *
 * 	x (256 bits) = [x1 | x2] where x1 and x2 are 128 bits long
 *
 * 	y1 = First 64 bits of h(x1)
 * 	y2 = Last 64 bits of h(x2)
 *
 * 	Y = H(x) = h( y1|y2 )
 *
 ********************************************************/

/********************************************************
 * Generate constraints 
 *******************************************************/
typedef void (*AesHash) (const unsigned char in[], unsigned char out[]);
static const AesHash aeshash[2] = {&aeshash_l, &aeshash_r};

void printf_i3_key(uint8_t *t, int indent)
{
    char buf[INDENT_BUF_LEN];
    uint i;
    
    memset(buf, ' ', INDENT_BUF_LEN);
    buf[indent] = 0;
    
    printf("%s key: ", buf);
    for (i = 0; i < KEY_LEN; i++)
	printf("%02x", (int)(t[i]));
    printf("\n");
}

void generate_constraint_id(ID *id, Key *key, int type)
{
    Key k1, k2;
    
    aeshash[type](id->x, k1.x);
    aeshash[type](id->x + ID_LEN/2, k2.x);

    memcpy(k1.x + KEY_LEN/2, k2.x + KEY_LEN/2, KEY_LEN/2);

    aeshash[type](k1.x, key->x);
}

void generate_l_constraint_addr(Key *rkey, Key *lkey)
{
    aeshash_l(rkey->x, lkey->x);
}   

void generate_r_constraint_addr(Key *lkey, Key *rkey)
{
    aeshash_r(lkey->x, rkey->x); 
}   


void generate_l_constraint(i3_trigger *t, Key *key)
{
    if (I3_ADDR_TYPE_STACK == t->to->type)
	    generate_l_constraint_id(t->to->t.stack->ids, key);
    else {
	    // printf("l-constr from key: ");
	    // printf_i3_key(t->key.x, 2);
	    generate_l_constraint_addr(&t->key, key);
    }
}

int is_constrained(ID *id, Key *key)
{
    int retval;
    retval = (0 == memcmp(KEY_ID_PTR(id), key->x, KEY_LEN));

    // printf("Required key: "); printf_i3_key(key->x, 2);
    // printf("Obtained key: "); printf_i3_key(KEY_ID_PTR(id), 2);
    
    return retval;
}

/*******************************************************
 * Check constraints
 *  -- called by server when trigger insert is attempted 
 *******************************************************/
int check_constraint(i3_trigger *t)
{
    Key key;
    char type;

    type = get_id_type (&(t->id));
   
    /*
    if (I3_ID_TYPE_UNCONSTRAINED == type) {
        //Unconstrained ids require no checking.
        printf ("\n\nUnconstrained trigger being checked\n\n");
        return 1;
    }

    */
    
    /* l-constraint is ok for any ID type (ie. public/private) */
    generate_l_constraint(t, &key);
    if (is_constrained(&(t->id), &key)) {
	    return 1;
    }

    /* r-constraint is ok only for private IDs */
    type = get_id_type(&(t->id));
    if (I3_ID_TYPE_PRIVATE != type) {
	    return 0;
    }
   
    /* check for r-constraint */
    generate_r_constraint(&t->id, &key);
    if (I3_ADDR_TYPE_STACK == t->to->type) {
        I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL,"c1 -- check_constraint\n");
	    if (is_constrained(t->to->t.stack->ids, &key)) {
	        return 1;
	    }
    } else {
	    if (0 == memcmp(t->key.x, key.x, KEY_LEN)) {
	        return 1;
	    }
    }

    return 0;
}

/*******************************************************
 * set the key in the client data structures
 ******************************************************/
void set_key_id(ID *id, Key *key)
{
    memcpy(KEY_ID_PTR(id), key->x, KEY_LEN);
}

void set_key_addr(Key *dst, Key *src)
{
    memcpy(dst, src, KEY_LEN);
}


/*******************************************************
 * Set key in path
 * Parameters:	- id array
 * 		- array length
 * 		- key of the first/last ID depending on l/r-constraint
 * 		- return key ie. of the other end of path
 ******************************************************/
void l_constrain_path(ID *id, int path_len)
{
    Key key;
    int i; 

    for (i = path_len - 1; i > 0; i--) {
	generate_l_constraint_id(&(id[i]), &key);
	set_key_id(&(id[i-1]), &key);
    }
}

void r_constrain_path(ID *id, int path_len)
{
    Key key;
    int i; 

    for (i = 0; i < path_len - 1; i++) {
	generate_r_constraint_id(&(id[i]), &key);
	set_key_id(&(id[i+1]), &key);
    }
}

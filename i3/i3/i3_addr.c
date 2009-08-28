/***************************************************************************
                          i3_addr.c  -  description
                             -------------------
    begin                : Nov 18 2002
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include "i3.h"
#include "i3_fun.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32 
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#endif

#include "i3_debug.h"


#include "../utils/gen_utils.h"

/***************************************************************************
 *  alloc_i3_addr - allocate address data structure
 *
 *  return:
 *    pointer to the allocated data structure 
 ***************************************************************************/
i3_addr *alloc_i3_addr()
{
  i3_addr *addr;

  /* TODO: just simply call alloc for now;
   * preallocate a pool of buffers in the future */
  addr = (i3_addr *)malloc(sizeof(i3_addr));
  if (addr) 
    return addr;

  I3_PRINT_INFO0(
          I3_INFO_LEVEL_FATAL_ERROR, 
          "FATAL ERROR: memory allocation error in alloc_i3_addr\n"
        );
  return NULL;
}


/***************************************************************************
 *  init_i3_addr_ipv4, init_i3_addr_ipv6, init_i3_addr_stack - 
 *    initailize the fields of address data structure
 *
 *  input:
 *    addr, port: IPv4/IPv6 address and port numbres
 *    - or -
 *    stack: pointer to stack (this data structure is not copied; don't
 *           free it after calling the function)
 *
 ***************************************************************************/
void init_i3_addr_ipv4(i3_addr *a, struct in_addr addr, uint16_t port)
{
  a->type = I3_ADDR_TYPE_IPv4;
  a->t.v4.addr.s_addr = addr.s_addr;
  a->t.v4.port = port;
}

void init_i3_addr_ipv4_nat(i3_addr *a, 
			   struct in_addr host_addr, uint16_t host_port,
			   struct in_addr nat_addr, uint16_t nat_port,
			   struct in_addr i3srv_addr, uint16_t i3srv_port)
{
  a->type = I3_ADDR_TYPE_IPv4_NAT;
  a->t.v4_nat.host_addr.s_addr = host_addr.s_addr;
  a->t.v4_nat.host_port = host_port;
  a->t.v4_nat.nat_addr.s_addr = nat_addr.s_addr;
  a->t.v4_nat.nat_port = nat_port;
  a->t.v4_nat.i3srv_addr.s_addr = i3srv_addr.s_addr;
  a->t.v4_nat.i3srv_port = i3srv_port;
}
#ifndef __CYGWIN__
void init_i3_addr_ipv6(i3_addr *a, struct in6_addr addr, uint16_t port)
{
  a->type = I3_ADDR_TYPE_IPv6;
#ifndef CCURED  
  memcpy((char *)&a->t.v6.addr.s6_addr, (char *)&addr.s6_addr,
	 sizeof(struct in6_addr));
#else
  a->t.v6.addr = addr;
#endif  
  a->t.v6.port = port;
}
#endif
void init_i3_addr_stack(i3_addr *a, i3_stack *s)
{
  a->type = I3_ADDR_TYPE_STACK;
  a->t.stack = s;
}


/***************************************************************************
 *  free_i3_trigger - free address data structure
 *
 *  input:
 *    i3 address to be freed
 *
 ***************************************************************************/

void free_i3_addr(i3_addr *addr)
{
  if (addr->type == I3_ADDR_TYPE_STACK)
    free_i3_stack(addr->t.stack);
  free(addr);
}

/***************************************************************************
 *  duplicate_i3_addr - duplicate a given address
 *
 *  input:
 *    a - address to be duplicated
 *
 *  return:
 *    a's replica
 ***************************************************************************/

i3_addr *duplicate_i3_addr(i3_addr *a)
{
  i3_addr *anew;

  if (NULL == a)
    return NULL;
  else
    anew = alloc_i3_addr();

  anew->type = a->type;
  switch (a->type) {
  case I3_ADDR_TYPE_IPv4:
    anew->t.v4.addr.s_addr = a->t.v4.addr.s_addr;
    anew->t.v4.port = a->t.v4.port;
    break;
  case I3_ADDR_TYPE_IPv4_NAT:
    anew->t.v4_nat.host_addr.s_addr = a->t.v4_nat.host_addr.s_addr;
    anew->t.v4_nat.host_port = a->t.v4_nat.host_port;
    anew->t.v4_nat.nat_addr.s_addr = a->t.v4_nat.nat_addr.s_addr;
    anew->t.v4_nat.nat_port = a->t.v4_nat.nat_port;
    anew->t.v4_nat.i3srv_addr.s_addr = a->t.v4_nat.i3srv_addr.s_addr;
    anew->t.v4_nat.i3srv_port = a->t.v4_nat.i3srv_port;
    break;
#ifndef __CYGWIN__
  case I3_ADDR_TYPE_IPv6:
#ifndef CCURED    
    memcpy((char *)&anew->t.v6.addr.s6_addr, (char *)&a->t.v6.addr.s6_addr,
         sizeof(struct in6_addr));
#else
    // Cleaner and faster
    anew->t.v6.addr = a->t.v6.addr;
#endif    
    anew->t.v6.port = a->t.v6.port;
    break;
#endif
  case I3_ADDR_TYPE_STACK:
    anew->t.stack = duplicate_i3_stack(a->t.stack);
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "duplicate_i3_id: invalid address type %d.\n", a->type);
  }

  return anew;
}



/***************************************************************************
 *  pack_i3_addr - convert an i3 address data structure in packet format
 *
 *  input:
 *    p - address of the buffer where the address is to be stored in 
 *        packet format (pre-allocated)
 *    addr - trigger to be converted in packet format
 *    
 *  output:
 *    length - length of the address in packet format
 *
 ***************************************************************************/

void pack_i3_addr(char *p, i3_addr *addr, unsigned short *length)
{
  unsigned short len = 0, l;
  long         long_temp;
  short        short_temp; 

  p[0] = addr->type;
  p++; len++;

  switch (addr->type) {
    case I3_ADDR_TYPE_STACK:
      pack_i3_stack(p, addr->t.stack, &l);
      len += l;
      break;
      
    case I3_ADDR_TYPE_IPv4:
      long_temp = htonl(addr->t.v4.addr.s_addr);
      memcpy(p, (char *)&long_temp, sizeof(long));
      p += sizeof(long);
      len += sizeof(long);
      
      short_temp = htons(addr->t.v4.port);
      memcpy(p, &short_temp, sizeof(short));
      p += sizeof(short);
      len += sizeof(short);
      
      break;
      
    case I3_ADDR_TYPE_IPv4_NAT:
      long_temp = htonl(addr->t.v4_nat.host_addr.s_addr);
      memcpy(p, (char *)&long_temp, sizeof(long));
      p += sizeof(long);
      len += sizeof(long);
      short_temp = htons(addr->t.v4_nat.host_port);
      memcpy(p, &short_temp, sizeof(short));
      p += sizeof(short);
      len += sizeof(short);
      
      long_temp = htonl(addr->t.v4_nat.nat_addr.s_addr);
      memcpy(p, (char *)&long_temp, sizeof(long));
      p += sizeof(long);
      len += sizeof(long);
      short_temp = htons(addr->t.v4_nat.nat_port);
      memcpy(p, &short_temp, sizeof(short));
      p += sizeof(short);
      len += sizeof(short);
      
      long_temp = htonl(addr->t.v4_nat.i3srv_addr.s_addr);
      memcpy(p, (char *)&long_temp, sizeof(long));
      p += sizeof(long);
      len += sizeof(long);
      short_temp = htons(addr->t.v4_nat.i3srv_port);
      memcpy(p, &short_temp, sizeof(short));
      p += sizeof(short);
      len += sizeof(short);
      break;
      
#ifndef _WIN32
    case I3_ADDR_TYPE_IPv6:
#ifndef CCURED      
      memcpy(p, (char *)&addr->t.v6.addr.s6_addr, sizeof(struct in6_addr));
#else
      * (struct in6_addr *)p = addr->t.v6.addr;
#endif      
      p += sizeof(struct in6_addr);
      len += sizeof(struct in6_addr);
      
      short_temp = htons(addr->t.v6.port);
      memcpy(p, &short_temp, sizeof(short));
      len += sizeof(short);
      p += sizeof(short);
      
      break;
#endif    
      
    default:
      printf("pack_i3_addr: invalid address type %d\n", addr->type);
  }

  *length = len;
}

unsigned short get_i3_addr_len(i3_addr *addr)
{
  unsigned short length;

  length = sizeof(char); /* type */

  switch (addr->type) {
  case I3_ADDR_TYPE_STACK:
    length += get_i3_stack_len(addr->t.stack);
    break;
  case I3_ADDR_TYPE_IPv4:
    length += sizeof(long) + sizeof(short);
    break;
  case I3_ADDR_TYPE_IPv4_NAT:
    length += 3*(sizeof(long) + sizeof(short));
    break;
#ifndef __CYGWIN__  
  case I3_ADDR_TYPE_IPv6:
    length += sizeof(struct in6_addr) + sizeof(short);
    break;
#endif
  default:
	  I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, "pack_i3_addr: invalid address type %d\n", addr->type);
  }

  return length;
}


/***************************************************************************
 *  unpack_i3_addr - copy address info from packet to a trigger 
 *                   data structure 
 *
 *  input:
 *    p - address where address is stored in packet format
 *    
 *  return:
 *    address data structure initialized with the info from buffer "p"
 *
 *  output:
 *    length - length of the address info in packet format
 *
 ***************************************************************************/

i3_addr *unpack_i3_addr(char *p, unsigned short *length)
{
  unsigned short len;
  i3_addr *addr = alloc_i3_addr();

  addr->type = p[0];
  p++; *length = 1;

  switch (addr->type) {
    case I3_ADDR_TYPE_STACK:
      addr->t.stack = unpack_i3_stack(p, &len);
      *length += len;
      break;
      
    case I3_ADDR_TYPE_IPv4:
      addr->t.v4.addr.s_addr = ntohl(*((long *)p));
      p += sizeof(long);
      *length += sizeof(long);
      
      addr->t.v4.port = ntohs(*((short *)p));
      *length += sizeof(short);
      p += sizeof(short);
      
      break;
    
    case I3_ADDR_TYPE_IPv4_NAT:
      addr->t.v4_nat.host_addr.s_addr = ntohl(*((long *)p));
      p += sizeof(long);
      *length += sizeof(long);
      addr->t.v4_nat.host_port = ntohs(*((short *)p));
      *length += sizeof(short);
      p += sizeof(short);
      
      addr->t.v4_nat.nat_addr.s_addr = ntohl(*((long *)p));
      p += sizeof(long);
      *length += sizeof(long);
      addr->t.v4_nat.nat_port = ntohs(*((short *)p));
      *length += sizeof(short);
      p += sizeof(short);
      
      addr->t.v4_nat.i3srv_addr.s_addr = ntohl(*((long *)p));
      p += sizeof(long);
      *length += sizeof(long);
      addr->t.v4_nat.i3srv_port = ntohs(*((short *)p));
      *length += sizeof(short);
      p += sizeof(short);
      break;
    
#ifndef __CYGWIN__
    case I3_ADDR_TYPE_IPv6:
#ifndef CCURED      
      memcpy((char *)&addr->t.v6.addr.s6_addr, p, sizeof(struct in6_addr));
#else
      addr->t.v6.addr = * (struct in6_addr *)p;
#endif
      
      p += sizeof(struct in6_addr);
      *length += sizeof(struct in6_addr);
      
      addr->t.v6.port = ntohs(*((short *)p));
      *length += sizeof(short);
      p += sizeof(short);
      
      break;
#endif

    default:
      I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL,"unpack_i3_addr: invalid address type %d\n", addr->type);
  }
  return addr;
}

/***************************************************************************
 *  check_i3_addr - check address whether is well-formed
 *
 *  input:
 *    p - address where i3_addr is stored in packet format
 *    
 *  return:
 *    error code; FALSE if no error
 *
 *  output:
 *    length - length of the address info in packet format
 *
 ***************************************************************************/

int check_i3_addr(char *p, unsigned short *length, char *type)
{
  *type = p[0];

  p++; /* skip address type field */

  switch (*type) {
    case I3_ADDR_TYPE_STACK:
      check_i3_stack(p, length); 
      break;
    case I3_ADDR_TYPE_IPv4:
      *length = sizeof(long)/*IP address*/ + sizeof(short)/*port*/;
      break;
    case I3_ADDR_TYPE_IPv4_NAT:
      *length = 3*(sizeof(long)/*IP address*/ + sizeof(short)/*port*/);
      break;
#ifndef __CYGWIN__
    case I3_ADDR_TYPE_IPv6:
      *length = sizeof(struct in6_addr)/*IP address*/ + sizeof(short)/*port*/;
      break;
#endif
    default:
      return I3_ERR_INVALID_ADDR;

  }

  *length += 1; /* account for address type */

  return FALSE;
}


/**
  * This function understands natted addresses.
  * If an address is natted, the nat_address and nat_port number
  * are used in the comparison.
  * @author Dilip
  */
int addr_nat_equal(i3_addr *a1, i3_addr *a2)
{
 
  struct in_addr cmp_addr_A, cmp_addr_B;
  int cmp_port_A, cmp_port_B;
  
  if (a1->type == I3_ADDR_TYPE_IPv4) {
    memcpy(&cmp_addr_A, &a1->t.v4.addr, sizeof(struct in_addr));
    cmp_port_A = a1->t.v4.port;
  } else if (a1->type == I3_ADDR_TYPE_IPv4_NAT) {
    memcpy(&cmp_addr_A, &a1->t.v4_nat.host_addr, sizeof(struct in_addr));
    cmp_port_A = a1->t.v4_nat.host_port;
  }

  if (a2->type == I3_ADDR_TYPE_IPv4) {
    memcpy(&cmp_addr_B, &a2->t.v4.addr, sizeof(struct in_addr));
    cmp_port_B = a2->t.v4.port;
  } else if (a2->type == I3_ADDR_TYPE_IPv4_NAT) {
    memcpy(&cmp_addr_B, &a2->t.v4_nat.host_addr, sizeof(struct in_addr));
    cmp_port_B = a2->t.v4_nat.host_port;
  }

    if (cmp_addr_A.s_addr != cmp_addr_B.s_addr || cmp_port_A != cmp_port_B) {
        return FALSE;
    } else {
        return TRUE;
    }
  
}


/***************************************************************************
 *  addr_equal - compare two addresses
 *
 *  input:
 *    t1, t2 - addresses to be compared
 *    
 *  return:
 *    TRUE, if the addresses are identical; FALSE, otherwise
 *
 ***************************************************************************/

int addr_equal(i3_addr *a1, i3_addr *a2)
{
#ifndef __CYGWIN__
  uint i;
#endif

  if (a1->type != a2->type)
    return FALSE;
 
  switch (a1->type) {
  case I3_ADDR_TYPE_IPv4:
    if ((a1->t.v4.addr.s_addr != a2->t.v4.addr.s_addr) ||
	(a1->t.v4.port != a2->t.v4.port))
      return FALSE;
    break;
  case I3_ADDR_TYPE_IPv4_NAT:
    if ((a1->t.v4_nat.host_addr.s_addr != a2->t.v4_nat.host_addr.s_addr) ||
	(a1->t.v4_nat.host_port != a2->t.v4_nat.host_port) ||
	(a1->t.v4_nat.nat_addr.s_addr != a2->t.v4_nat.nat_addr.s_addr) ||
	(a1->t.v4_nat.nat_port != a2->t.v4_nat.nat_port) ||
	(a1->t.v4_nat.i3srv_addr.s_addr != a2->t.v4_nat.i3srv_addr.s_addr) ||
	(a1->t.v4_nat.i3srv_port != a2->t.v4_nat.i3srv_port))
      return FALSE;
    break;
#ifndef __CYGWIN__
  case I3_ADDR_TYPE_IPv6:
    for (i = 0; i < sizeof(struct in6_addr); i++) 
      if (a1->t.v6.addr.s6_addr[i] != a2->t.v6.addr.s6_addr[i])
	return FALSE;
    if (a1->t.v6.port == a2->t.v6.port)
      return FALSE;
    break;
#endif
  case I3_ADDR_TYPE_STACK:
    if (a1->t.stack->len != a2->t.stack->len)
      return FALSE;
    if (memcmp((char *)a1->t.stack->ids, (char *)a2->t.stack->ids, 
	       a1->t.stack->len*sizeof(ID)))
      return FALSE;
  }
  return TRUE;
}


/***************************************************************************
 *  sizeof_addr - return the length of the address data structure
 *
 *  input:
 *    a - given address
 *
 *  return:
 *    length in bytes of the address
 *
 ***************************************************************************/

int sizeof_addr(i3_addr *a)
{
  switch (a->type) {
  case I3_ADDR_TYPE_IPv4:
    return (sizeof(struct in_addr) + sizeof(uint16_t) + sizeof(a->type) + 
	    KEY_LEN);
  case I3_ADDR_TYPE_IPv4_NAT:
    return (3*(sizeof(struct in_addr) + sizeof(uint16_t)) + sizeof(a->type) + 
	    KEY_LEN);
#ifndef __CYGWIN__
  case I3_ADDR_TYPE_IPv6:
    return (sizeof(struct in6_addr) + sizeof(uint16_t) + sizeof(a->type) + 
	    KEY_LEN);
#endif
  case I3_ADDR_TYPE_STACK:
    return (a->t.stack->len*sizeof(ID) + sizeof(a->type));
  }
  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "addr_len: Invalid trigger type");
  return -1;
}

/***************************************************************************
 * printf_id - print i3-id with an indentation of "indent"
 **************************************************************************/

void printf_id(ID *id, int indent)
{
  uint i;
  char buf[INDENT_BUF_LEN];

  memset(buf, ' ', indent);
  buf[indent] = 0;

  printf("%s i3-id = ", buf);
  for (i = 0; i < sizeof(ID); i++)
    printf("%02x", id->x[i]); 
  printf("\n");
}    
   
/***************************************************************************
 * printf_i3_addr - print i3-addr with an indentation of "indent"
 **************************************************************************/

void printf_i3_addr(i3_addr *addr, int indent)
{
#ifndef __CYGWIN__
  uint i;
#endif
  char buf[INDENT_BUF_LEN];
  struct in_addr ia;

  memset(buf, ' ', indent);
  buf[indent] = 0;

  printf("%s addr type = %d\n", buf, addr->type);

  switch (addr->type) {
  case I3_ADDR_TYPE_STACK:
    printf_i3_stack(addr->t.stack, indent);
    break;
  case I3_ADDR_TYPE_IPv4:
    ia.s_addr = htonl(addr->t.v4.addr.s_addr);
    printf("%s IPv4 (address, port) = (%s, %d)", 
	   buf, inet_ntoa(ia), addr->t.v4.port); 
    break;
  case I3_ADDR_TYPE_IPv4_NAT:
    ia.s_addr = htonl(addr->t.v4_nat.host_addr.s_addr);
    printf("%s NAT_IPv4 (host_addr, host_port) = (%s, %d)\n", 
	   buf, inet_ntoa(ia), addr->t.v4_nat.host_port); 
    ia.s_addr = htonl(addr->t.v4_nat.nat_addr.s_addr);
    printf("%s          (nat_addr, nat_port) = (%s, %d)\n", 
	   buf, inet_ntoa(ia), addr->t.v4_nat.nat_port); 
    ia.s_addr = htonl(addr->t.v4_nat.i3srv_addr.s_addr);
    printf("%s          (i3srv_addr, i3srv_port) = (%s, %d)\n", 
	   buf, inet_ntoa(ia), addr->t.v4_nat.i3srv_port); 
    break;
#ifndef __CYGWIN__
  case I3_ADDR_TYPE_IPv6:
    printf("%s IPv6 (address, port) = (", buf);
    for (i = 0; i < sizeof(struct in6_addr); i++) 
      printf("%d.", addr->t.v6.addr.s6_addr[i]);
    printf(", %d)", addr->t.v6.port);
    break;
#endif
  default:
    printf("Unknown addr type\n");
  }
  printf("\n");
}

/***************************************************************************
 * compute_nonce - compute the nonce for challenging trigger insertion
 **************************************************************************/

void compute_nonce(char *nonce, i3_addr *a)
{
  memset(nonce, 0, NONCE_LEN);

  switch (a->type) {
  case I3_ADDR_TYPE_IPv4:
#ifndef CCURED    
    memcpy(nonce, (char *)&a->t.v4.addr.s_addr, sizeof(struct in_addr));
#else
    * (struct in_addr *)nonce = a->t.v4.addr;
#endif
#ifndef CCURED    
    memcpy(nonce + sizeof(struct in_addr),
         (char *)&a->t.v4.port, sizeof(a->t.v4.port));
#else
    * (uint16_t *)(nonce + sizeof(struct in_addr)) = a->t.v4.port;
#endif    
    break;
  case I3_ADDR_TYPE_IPv4_NAT:
    /* the 2nd address in the two-hop route represents the 
     * the Internet-routable address of the destination
     */
    memcpy(nonce, (char *)&a->t.v4_nat.nat_addr.s_addr, 
	   sizeof(struct in_addr));
    memcpy(nonce + sizeof(struct in_addr),
	   (char *)&a->t.v4_nat.host_port, sizeof(a->t.v4_nat.nat_port));
    break;
#ifndef __CYGWIN__
  case I3_ADDR_TYPE_IPv6:
#ifndef CCURED    
    memcpy(nonce, (char *)&a->t.v6.addr.s6_addr,
         MIN(sizeof(struct in6_addr), NONCE_LEN));
#else
    {
      struct in6_addr tmp = a->t.v6.addr;
      memcpy(nonce, (char*)&tmp, MIN(sizeof(struct in6_addr), NONCE_LEN));
    }
#endif    
    break;
#endif
  case I3_ADDR_TYPE_STACK:
    memcpy(nonce, a->t.stack->ids, NONCE_LEN);
    break;
  default:
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL,"compute_nonce: invalid address type %d\n", a->type);
    printf_i3_addr(a, 2);
  }
}

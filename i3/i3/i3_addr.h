/***************************************************************************
                          i3_addr.h  -  description
                             -------------------
    begin                : Fre Jun 20 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef I3_ADDR_H
#define I3_ADDR_H
 
/* functions implemented in i3_addr.c */
i3_addr *alloc_i3_addr();

void init_i3_addr_ipv4(i3_addr *a, struct in_addr addr, uint16_t port);
void init_i3_addr_ipv4_nat(i3_addr *a, 
			   struct in_addr host_addr, uint16_t host_port,
			   struct in_addr nat_addr, uint16_t nat_port,
			   struct in_addr i3srv_addr, uint16_t i3srv_port);
#ifndef __CYGWIN__
void init_i3_addr_ipv6(i3_addr *a, struct in6_addr addr, uint16_t port);
#endif
void init_i3_addr_stack(i3_addr *a, i3_stack *s);
i3_addr *duplicate_i3_addr(i3_addr *a);
void free_i3_addr(i3_addr *addr);
void pack_i3_addr(char *p, i3_addr *addr, unsigned short *length);
unsigned short get_i3_addr_len(i3_addr *addr);
i3_addr *unpack_i3_addr(char *p, unsigned short *length);
int check_i3_addr(char *p, unsigned short *length, char *type);
int addr_equal(i3_addr *a1, i3_addr *a2);
int addr_nat_equal(i3_addr *a1, i3_addr *a2);
int sizeof_addr(i3_addr *a);
void printf_i3_addr(i3_addr *addr, int intend);
void printf_id(ID *id, int indent);
void compute_nonce(char *nonce, i3_addr *a);

#endif


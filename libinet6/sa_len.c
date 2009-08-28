/* Copyright (C) 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>

#ifdef HAVE_NETASH_ASH_H
#include <netash/ash.h>
#endif
#ifdef HAVE_NETATALK_AT_H
#include <netatalk/at.h>
#endif
#ifdef HAVE_NETAX25_AX25_H
#include <netax25/ax25.h>
#endif
#ifdef HAVE_NETECONET_EC_H
#include <neteconet/ec.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_NETIPX_IPX_H
#include <netipx/ipx.h>
#endif
#include <netpacket/packet.h>
#ifdef HAVE_NETROSE_ROSE_H
#include <netrose/rose.h>
#endif
#include <sys/un.h>

int
__usagi_sa_len (sa_family_t af)
{
  switch (af)
    {
#ifdef HAVE_NETATALK_AT_H
    case AF_APPLETALK:
      return sizeof (struct sockaddr_at);
#endif
#ifdef HAVE_NETASH_ASH_H
    case AF_ASH:
      return sizeof (struct sockaddr_ash);
#endif
#ifdef HAVE_NETAX25_AX25_H
    case AF_AX25:
      return sizeof (struct sockaddr_ax25);
#endif
#ifdef HAVE_NETECONET_EC_H
    case AF_ECONET:
      return sizeof (struct sockaddr_ec);
#endif
    case AF_INET:
      return sizeof (struct sockaddr_in);
    case AF_INET6:
      return sizeof (struct sockaddr_in6);
#ifdef HAVE_NETIPX_IPX_H
    case AF_IPX:
      return sizeof (struct sockaddr_ipx);
#endif
    case AF_LOCAL:
      return sizeof (struct sockaddr_un);
    case AF_PACKET:
      return sizeof (struct sockaddr_ll);
#ifdef HAVE_NETROSE_ROSE_H
    case AF_ROSE:
      return sizeof (struct sockaddr_rose);
#endif
    }
  return 0;
}

/* $USAGI: ifnames.c,v 1.22 2002/12/08 08:22:19 yoshfuji Exp $ */

/*
 * ifnames.c 
 * Copyright (C)2000 YOSHIFUJI Hideaki
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <time.h>
#include <malloc.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>	/* the L2 protocols */
#include <sys/uio.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#ifdef _USAGI_LIBINET6
#include "libc-compat.h"
#endif

/* ====================================================================== */
struct nlmsg_list
{
  struct nlmsg_list *nlm_next;
  struct nlmsghdr *nlh;
  int size;
  time_t seq;
};

/* ====================================================================== */
static int
nl_sendreq (int sd, int request, int flags, int *seq)
{
  char reqbuf[NLMSG_ALIGN (sizeof (struct nlmsghdr)) +
	      NLMSG_ALIGN (sizeof (struct rtgenmsg))];
  struct sockaddr_nl nladdr;
  struct nlmsghdr *req_hdr;
  struct rtgenmsg *req_msg;
  time_t t = time (NULL);

  if (seq)
    *seq = t;
  memset (&reqbuf, 0, sizeof (reqbuf));
  req_hdr = (struct nlmsghdr *) reqbuf;
  req_msg = (struct rtgenmsg *) NLMSG_DATA (req_hdr);
  req_hdr->nlmsg_len = NLMSG_LENGTH (sizeof (*req_msg));
  req_hdr->nlmsg_type = request;
  req_hdr->nlmsg_flags = flags | NLM_F_REQUEST;
  req_hdr->nlmsg_pid = 0;
  req_hdr->nlmsg_seq = t;
  req_msg->rtgen_family = AF_UNSPEC;
  memset (&nladdr, 0, sizeof (nladdr));
  nladdr.nl_family = AF_NETLINK;
  return (sendto (sd, (void *) req_hdr, req_hdr->nlmsg_len, 0,
		  (struct sockaddr *) &nladdr, sizeof (nladdr)));
}

static int
nl_recvmsg (int sd, int request, int seq,
	    void *buf, size_t buflen, int *flags)
{
  struct msghdr msg;
  struct iovec iov = { buf, buflen };
  struct sockaddr_nl nladdr;
  int read_len;

  for (;;)
    {
      msg.msg_name = (void *) &nladdr;
      msg.msg_namelen = sizeof (nladdr);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_control = NULL;
      msg.msg_controllen = 0;
      msg.msg_flags = 0;
      /* XX MIIKA FIX: HANGS AFTER BEING CALLED MULTIPLE TIMES */
      read_len = recvmsg (sd, &msg, 0);
      if ((read_len < 0 && errno == EINTR) || (msg.msg_flags & MSG_TRUNC))
	continue;
      if (flags)
	*flags = msg.msg_flags;
      break;
    }
  return read_len;
}

static int
nl_getmsg (int sd, int request, int seq, struct nlmsghdr **nlhp, int *done)
{
  struct nlmsghdr *nh;
  size_t bufsize = 65536, lastbufsize = 0;
  void *buff = NULL;
  int result = 0, read_size;
  int msg_flags;
  pid_t pid = getpid ();
  for (;;)
    {
      void *newbuff = realloc (buff, bufsize);
      if (newbuff == NULL || bufsize < lastbufsize)
	{
	  result = -1;
	  break;
	}
      buff = newbuff;
      result = read_size =
	nl_recvmsg (sd, request, seq, buff, bufsize, &msg_flags);
      if (read_size < 0 || (msg_flags & MSG_TRUNC))
	{
	  lastbufsize = bufsize;
	  bufsize *= 2;
	  continue;
	}
      if (read_size == 0)
	break;
      nh = (struct nlmsghdr *) buff;
      for (nh = (struct nlmsghdr *) buff;
	   NLMSG_OK (nh, read_size);
	   nh = (struct nlmsghdr *) NLMSG_NEXT (nh, read_size))
	{
	  if (nh->nlmsg_pid != pid || nh->nlmsg_seq != seq)
	    continue;
	  if (nh->nlmsg_type == NLMSG_DONE)
	    {
	      (*done)++;
	      break;		/* ok */
	    }
	  if (nh->nlmsg_type == NLMSG_ERROR)
	    {
	      struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA (nh);
	      result = -1;
	      if (nh->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr)))
		__set_errno (EIO);
	      else
		__set_errno (-nlerr->error);
	      break;
	    }
	}
      break;
    }
  if (result < 0)
    if (buff)
      {
	int saved_errno = errno;
	free (buff);
	__set_errno (saved_errno);
      }
  *nlhp = (struct nlmsghdr *) buff;
  return result;
}

static int
nl_getlist (int sd, int seq,
	    int request,
	    struct nlmsg_list **nlm_list, struct nlmsg_list **nlm_end)
{
  struct nlmsghdr *nlh = NULL;
  int status;
  int done = 0;

  status = nl_sendreq (sd, request, NLM_F_ROOT | NLM_F_MATCH, &seq);
  if (status < 0)
    return status;
  if (seq == 0)
    seq = (int) time (NULL);
  while (!done)
    {
      status = nl_getmsg (sd, request, seq, &nlh, &done);
      if (status < 0)
	return status;
      if (nlh)
	{
	  struct nlmsg_list *nlm_next =
	    (struct nlmsg_list *) malloc (sizeof (struct nlmsg_list));
	  if (nlm_next == NULL)
	    {
	      int saved_errno = errno;
	      free (nlh);
	      __set_errno (saved_errno);
	      status = -1;
	    }
	  else
	    {
	      nlm_next->nlm_next = NULL;
	      nlm_next->nlh = (struct nlmsghdr *) nlh;
	      nlm_next->size = status;
	      nlm_next->seq = seq;
	      if (*nlm_list == NULL)
		{
		  *nlm_list = nlm_next;
		  *nlm_end = nlm_next;
		}
	      else
		{
		  (*nlm_end)->nlm_next = nlm_next;
		  *nlm_end = nlm_next;
		}
	    }
	}
    }
  return status >= 0 ? seq : status;
}

/* ---------------------------------------------------------------------- */
static void
free_nlmsglist (struct nlmsg_list *nlm0)
{
  struct nlmsg_list *nlm, *nlm_next;
  int saved_errno;
  if (!nlm0)
    return;
  saved_errno = errno;
  nlm = nlm0;
  while(nlm)
    {
      if (nlm->nlh)
	free (nlm->nlh);
      nlm_next = nlm->nlm_next;
      free(nlm);
      nlm = nlm_next;
    }
  __set_errno (saved_errno);
}

static void
free_data (void *data, void *ifdata)
{
  int saved_errno = errno;
  if (data != NULL)
    free (data);
  if (ifdata != NULL)
    free (ifdata);
  __set_errno (saved_errno);
}

/* ---------------------------------------------------------------------- */
static void
nl_close (int sd)
{
  int saved_errno = errno;
  if (sd >= 0)
    close (sd);
  __set_errno (saved_errno);
}

/* ---------------------------------------------------------------------- */
static int
nl_open (void)
{
  struct sockaddr_nl nladdr;
  int sd;

  sd = socket (PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sd < 0)
    return -1;
  memset (&nladdr, 0, sizeof (nladdr));
  nladdr.nl_family = AF_NETLINK;
  if (bind (sd, (struct sockaddr *) &nladdr, sizeof (nladdr)) < 0)
    {
      nl_close (sd);
      return -1;
    }
  return sd;
}

/* ====================================================================== */
struct if_nameindex *
if_nameindex (void)
{
  struct if_nameindex *ifn0;
  int sd;
  struct nlmsg_list *nlmsg_list, *nlmsg_end, *nlm;
  /* - - - - - - - - - - - - - - - */
  int icnt;
  size_t nlen;
  uint32_t max_ifindex = 0;

  pid_t pid = getpid ();
  int seq;
  int result;
  int build;			/* 0 or 1 */

/* ---------------------------------- */
  /* initialize */
  icnt = nlen = 0;
  nlmsg_list = nlmsg_end = NULL;

  ifn0 = NULL;

/* ---------------------------------- */
  /* open socket and bind */
  sd = nl_open ();
  if (sd < 0)
    return NULL;

/* ---------------------------------- */
  /* gather info */
  if ((seq = nl_getlist (sd, 0, RTM_GETLINK, &nlmsg_list, &nlmsg_end)) < 0)
    {
      free_nlmsglist (nlmsg_list);
      nl_close (sd);
      return NULL;
    }
  if ((seq = nl_getlist (sd, seq + 1, RTM_GETADDR,
			 &nlmsg_list, &nlmsg_end)) < 0)
    {
      free_nlmsglist (nlmsg_list);
      nl_close (sd);
      return NULL;
    }

/* ---------------------------------- */
  /* Estimate size of result buffer and fill it */
  for (build = 0; build <= 1; build++)
    {
      struct if_nameindex *ifn = NULL;
      struct nlmsghdr *nlh, *nlh0;
      void *data = NULL, *ifdata = NULL;
      char *ifname = NULL, **iflist = NULL;
      uint16_t *ifflist = NULL;

      if (build)
	{
	  ifn = data = calloc (1,
			       NLMSG_ALIGN (sizeof
					    (struct if_nameindex[icnt + 1])) +
			       nlen);
	  ifdata =
	    calloc (1,
		    NLMSG_ALIGN (sizeof (char *[max_ifindex + 1])) +
		    NLMSG_ALIGN (sizeof (uint16_t[max_ifindex + 1])));
	  ifn0 = (ifdata != NULL) ? ifn : NULL;
	  if (data == NULL || ifdata == NULL)
	    {
	      free_data (data, ifdata);
	      result = -1;
	      break;
	    }
	  ifname =
	    data + NLMSG_ALIGN (sizeof (struct if_nameindex[icnt + 1]));
	  iflist = ifdata;
	  ifflist =
	    ((void *) iflist) +
	    NLMSG_ALIGN (sizeof (char *[max_ifindex + 1]));
	}

      for (nlm = nlmsg_list; nlm; nlm = nlm->nlm_next)
	{
	  int nlmlen = nlm->size;
	  if (!(nlh0 = nlm->nlh))
	    continue;
	  for (nlh = nlh0;
	       NLMSG_OK (nlh, nlmlen); nlh = NLMSG_NEXT (nlh, nlmlen))
	    {
	      struct ifinfomsg *ifim = NULL;
	      struct rtattr *rta;

	      size_t nlm_struct_size = 0;
	      sa_family_t nlm_family = 0;
	      uint32_t nlm_scope = 0, nlm_index = 0;
	      size_t rtasize;

	      /* check if the message is what we want */
	      if (nlh->nlmsg_pid != pid || nlh->nlmsg_seq != nlm->seq)
		continue;
	      if (nlh->nlmsg_type == NLMSG_DONE)
		{
		  break;	/* ok */
		}
	      switch (nlh->nlmsg_type)
		{
		case RTM_NEWLINK:
		  ifim = (struct ifinfomsg *) NLMSG_DATA (nlh);
		  nlm_struct_size = sizeof (*ifim);
		  nlm_family = ifim->ifi_family;
		  nlm_scope = 0;
		  nlm_index = ifim->ifi_index;
		  break;
		default:
		  continue;
		}

	      if (!build)
		{
		  if (max_ifindex < nlm_index)
		    max_ifindex = nlm_index;
		}

	      rtasize =
		NLMSG_PAYLOAD (nlh, nlmlen) - NLMSG_ALIGN (nlm_struct_size);
	      for (rta =
		   (struct rtattr *) (((char *) NLMSG_DATA (nlh)) +
				      NLMSG_ALIGN (nlm_struct_size));
		   RTA_OK (rta, rtasize); rta = RTA_NEXT (rta, rtasize))
		{
		  void *rtadata = RTA_DATA (rta);
		  size_t rtapayload = RTA_PAYLOAD (rta);

		  switch (nlh->nlmsg_type)
		    {
		    case RTM_NEWLINK:
		      switch (rta->rta_type)
			{
			case IFLA_IFNAME:	/* Name of Interface */
			  if (!build)
			    nlen += NLMSG_ALIGN (rtapayload + 1);
			  else
			    {
			      ifn->if_name = ifname;
			      if (iflist[nlm_index] == NULL)
				iflist[nlm_index] = ifn->if_name;
			      strncpy (ifn->if_name, rtadata, rtapayload);
			      ifn->if_name[rtapayload] = '\0';
			      ifn->if_index = nlm_index;
			      ifname += NLMSG_ALIGN (rtapayload + 1);
			    }
			  break;
			}
		      break;
		    }
		}
	      if (!build)
		{
		  icnt++;
		}
	      else
		{
		  if (ifn->if_name == NULL)
		    ifn->if_name = iflist[nlm_index];
		  ifn++;
		}
	    }
	}
      if (!build)
	{
	  if (icnt == 0 && nlen == 0)
	    {
	      ifn0 = NULL;
	      break;		/* cannot found any addresses */
	    }
	}
      else
	free_data (NULL, ifdata);
    }

/* ---------------------------------- */
  /* Finalize */
  free_nlmsglist (nlmsg_list);
  nl_close (sd);
  return ifn0;
}

void
if_freenameindex (struct if_nameindex *ifn)
{
  free (ifn);
}

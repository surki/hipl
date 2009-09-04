#include "nlink.h"

/* 
 * Note that most of the functions are modified versions of
 * libnetlink functions.
 */

int lsi_total = 0;

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		HIP_ERROR("addattr_l ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

/*
 * Unfortunately libnetlink does not provide a generic receive a
 * message function. This is a modified version of the rtnl_listen
 * function that processes only a finite amount of messages and then
 * returns.
*/
int hip_netlink_receive(struct rtnl_handle *nl,
			hip_filter_t handler,
			void *arg)
{
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov;
        struct msghdr msg = {
                (void*)&nladdr, sizeof(nladdr),
                &iov,   1,
                NULL,   0,
                0
        };
	int msg_len = 0, status = 0;
	char buf[NLMSG_SPACE(HIP_MAX_NETLINK_PACKET)];

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = 0;
        nladdr.nl_groups = 0;
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

        msg_len = recvfrom(nl->fd, buf, sizeof(struct nlmsghdr),
			   MSG_PEEK|MSG_DONTWAIT, NULL, NULL);
	if (msg_len != sizeof(struct nlmsghdr)) {
		HIP_ERROR("Bad netlink msg\n");
		return -1;
	}

	HIP_DEBUG("Received a netlink message\n");
 
	while (1) {
		iov.iov_len = sizeof(buf);

		/* note: not using recvmsg interface anymore as
		   a workaround for bug id 782 */

		status = recvfrom(nl->fd, buf, sizeof(buf),
				  0, NULL, NULL);
                //status = recvmsg(nl->fd, &msg, 0);

                if (status < 0) {
			HIP_PERROR("perror: ");
                        if (errno == EINTR)
                                continue;
			HIP_ERROR("Netlink overrun.\n");
                        return -1;
                        continue;
                }
                if (status == 0) {
                        HIP_ERROR("EOF on netlink\n");
                        return -1;
                }
                if (msg.msg_namelen != sizeof(nladdr)) {
                        HIP_ERROR("Sender address length == %d\n", msg.msg_namelen);
                        return -1;
                }
		for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
                        int err;
                        int len = h->nlmsg_len;
                        int l = len - sizeof(*h);

			_HIP_DEBUG("l=%d, len=%d status=%d\n", l, len, status);

                        if (l < 0 || len > status) {
                                if (msg.msg_flags & MSG_TRUNC) {
                                        HIP_ERROR("Truncated netlink message\n");
                                        return -1;
                                }

                                HIP_ERROR("Malformed netlink message: len=%d\n", len);
                                return -1;
                        }

                        err = handler(h, len, arg);
                        if (err < 0)
                                return err;

                        status -= NLMSG_ALIGN(len);
                        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                }
                if (msg.msg_flags & MSG_TRUNC) {
                        HIP_ERROR("Message truncated\n");
                        break;
                }

                if (status) {
                        HIP_ERROR("Remnant of size %d\n", status);
                        return -1;
                }

		/* All messages processed */
		return 0;
	}
	return 0;
}

/**
 * This is a copy from the libnetlink's talk function. It has a fixed
 * handling of message source/destination validation and proper buffer
 * handling for junk messages.
 */
int netlink_talk(struct rtnl_handle *nl, struct nlmsghdr *n, pid_t peer,
			unsigned groups, struct nlmsghdr *answer,
			hip_filter_t junk, void *arg)
{
	int status, err = 0;
	unsigned seq;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	char   buf[16384];
	struct iovec iov = {
		.iov_base = (void*) n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	memset(&nladdr, 0, sizeof(nladdr));
	/*Assign values to the socket address*/
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = peer;
	nladdr.nl_groups = groups;

	n->nlmsg_seq = seq = ++nl->seq;

	/* Note: the TALK_ACK are here because I experienced problems
	   with SMP machines. The application added a mapping which caused
	   the control flow to arrive here. The sendmsg adds an SP and the
	   while loop tries to read the ACK for the SP. However, there will
	   be an acquire message arriving from the kernel before we read the
	   ack which confuses the loop completely, so I disabled the ACK.
	   The reason why this all happens is that we are using the same
	   netlink socket to read both acquire messages and sending SP.
	   Only a single netlink socket exist per PID, so we either do it
	   as it is here or create another thread for handling acquires.
	   For testing SP/SA related issues you might want to re-enable these
	   -mk */
	if (HIP_NETLINK_TALK_ACK)
		if (answer == NULL)
			n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(nl->fd, &msg, 0);
	
	if (status < 0)
	{
		HIP_PERROR("Cannot talk to rtnetlink");
		err = -1;
		goto out_err;
	}

	
	memset(buf,0,sizeof(buf));
	iov.iov_base = buf;

	while (HIP_NETLINK_TALK_ACK) {
		HIP_DEBUG("inside the while\n");
		iov.iov_len = sizeof(buf);
		status = recvmsg(nl->fd, &msg, 0);

		if (status < 0)
		{
			if (errno == EINTR)
			{
				HIP_DEBUG("EINTR\n");
				continue;
			}
			HIP_PERROR("OVERRUN");
			continue;
		}
		if (status == 0) {
                        HIP_ERROR("EOF on netlink.\n");
			err = -1;
			goto out_err;
                }
                if (msg.msg_namelen != sizeof(nladdr)) {
                        HIP_ERROR("sender address length == %d\n",
				  msg.msg_namelen);
			err = -1;
			goto out_err;
                }
                for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
                        int err;
                        int len = h->nlmsg_len;
                        int l = len - sizeof(*h);

                        if (l<0 || len>status) {
                                if (msg.msg_flags & MSG_TRUNC) {
                                        HIP_ERROR("Truncated message\n");
					err = -1;
					goto out_err;
                                }
                                HIP_ERROR("Malformed message: len=%d\n", len);
				err = -1;
				goto out_err;
                        }

                        if (nladdr.nl_pid != peer ||
                            h->nlmsg_seq != seq) {
				HIP_DEBUG("%d %d %d %d\n", nladdr.nl_pid, peer, h->nlmsg_seq, seq);
                                if (junk) {
					err = junk(h, len, arg);
                                        if (err < 0) {
						err = -1;
						goto out_err;
					}
                                }
                                /* Don't forget to skip that message. */
                                status -= NLMSG_ALIGN(len);
                                h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                                continue;
                        }

                        if (h->nlmsg_type == NLMSG_ERROR) {
                                struct nlmsgerr *nl_err =
					(struct nlmsgerr*)NLMSG_DATA(h);
                                if (l < sizeof(struct nlmsgerr)) {
                                        HIP_ERROR("Truncated\n");
                                } else {
                                        errno = -nl_err->error;
                                        if (errno == 0) {
                                                if (answer)
                                                        memcpy(answer, h, h->nlmsg_len);
						goto out_err;
                                        }
                                        HIP_PERROR("NETLINK answers");
                                }
				err = -1;
				goto out_err;

                        }
                        if (answer) {
                                memcpy(answer, h, h->nlmsg_len);
				goto out_err;
                        }

                        HIP_ERROR("Unexpected netlink reply!\n");

                        status -= NLMSG_ALIGN(len);
                        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                }
                if (msg.msg_flags & MSG_TRUNC) {
                        HIP_ERROR("Message truncated\n");
                        continue;
                }
                if (status) {
                        HIP_ERROR("Remnant of size %d\n", status);
			err = -1;
			goto out_err;
                }
        }

out_err:

	return err;
}


int hip_netlink_send_buf(struct rtnl_handle *rth, const char *buf, int len)
{
        struct sockaddr_nl nladdr;

        memset(&nladdr, 0, sizeof(struct sockaddr_nl));
        nladdr.nl_family = AF_NETLINK;
        return sendto(rth->fd, buf, len, 0, (struct sockaddr*)&nladdr, sizeof(struct sockaddr_nl));
}

int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
			  int protocol)
{
        socklen_t addr_len;
        int sndbuf = 32768, rcvbuf = 32768;
	int err = 0, on = 1;

        memset(rth, 0, sizeof(*rth));

	rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
        if (rth->fd < 0) {
                HIP_PERROR("Cannot open a netlink socket");
                return -1;
        }
	_HIP_DEBUG("setsockopt SO_SNDBUF\n");
        if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
                HIP_PERROR("SO_SNDBUF");
                return -1;
        }
	_HIP_DEBUG("setsockopt SO_RCVBUF\n");
        if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
                HIP_PERROR("SO_RCVBUF");
                return -1;
        }

        memset(&rth->local, 0, sizeof(rth->local));
        rth->local.nl_family = AF_NETLINK;
        rth->local.nl_groups = subscriptions;

        if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
                HIP_PERROR("Cannot bind a netlink socket");
                return -1;
        }
        addr_len = sizeof(rth->local);
        if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
                HIP_PERROR("Cannot getsockname");
                return -1;
        }
        if (addr_len != sizeof(rth->local)) {
                HIP_ERROR("Wrong address length %d\n", addr_len);
                return -1;
        }
        if (rth->local.nl_family != AF_NETLINK) {
                HIP_ERROR("Wrong address family %d\n", rth->local.nl_family);
                return -1;
        }
        rth->seq = time(NULL);
        return 0;
}

void rtnl_close(struct rtnl_handle *rth)
{
	close(rth->fd);
}


/**
 * Functions for adding ip address
 */

unsigned ll_name_to_index(const char *name, struct idxmap **idxmap)
{
        static char ncache[16];
        static int icache;
        struct idxmap *im;
        int i;

        if (name == NULL)
                return 0;
        if (icache && strcmp(name, ncache) == 0)
                return icache;
        for (i=0; i<16; i++) {
                for (im = idxmap[i]; im; im = im->next) {
                        if (strcmp(im->name, name) == 0) {
                                icache = im->index;
                                strcpy(ncache, name);
                                return im->index;
                        }
                }
        }

	/* XX FIXME: having more that one NETLINK socket open at the same
	   time is bad! See hipd.c:addresses comments */
        return if_nametoindex(name);
}

int get_unsigned(unsigned *val, const char *arg, int base)
{
        unsigned long res;
        char *ptr;

        if (!arg || !*arg)
                return -1;
        res = strtoul(arg, &ptr, base);
        if (!ptr || ptr == arg || *ptr || res > UINT_MAX)
                return -1;
        *val = res;
        return 0;
}



int get_addr_1(inet_prefix *addr, const char *name, int family)
{
        const char *cp;
        unsigned char *ap = (unsigned char*)addr->data;
        int i;

        memset(addr, 0, sizeof(*addr));

        if (strcmp(name, "default") == 0 ||
            strcmp(name, "all") == 0 ||
            strcmp(name, "any") == 0) {
                if (family == AF_DECnet)
                        return -1;
                addr->family = family;
                addr->bytelen = (family == AF_INET6 ? 16 : 4);
                addr->bitlen = -1;
                return 0;
        }

        if (strchr(name, ':')) {
                addr->family = AF_INET6;
                if (family != AF_UNSPEC && family != AF_INET6)
                        return -1;
                if (inet_pton(AF_INET6, name, addr->data) <= 0)
                        return -1;
                addr->bytelen = 16;
                addr->bitlen = -1;
                return 0;
        }

        addr->family = AF_INET;
        if (family != AF_UNSPEC && family != AF_INET)
                return -1;
        addr->bytelen = 4;
        addr->bitlen = -1;
        for (cp=name, i=0; *cp; cp++) {
                if (*cp <= '9' && *cp >= '0') {
                        ap[i] = 10*ap[i] + (*cp-'0');
                        continue;
                }
                if (*cp == '.' && ++i <= 3)
                        continue;
                return -1;
        }
        return 0;
}

int get_prefix_1(inet_prefix *dst, char *arg, int family)
{
        int err;
        unsigned plen;
        char *slash;

        memset(dst, 0, sizeof(*dst));

        if (strcmp(arg, "default") == 0 ||
            strcmp(arg, "any") == 0 ||
            strcmp(arg, "all") == 0) {
                if (family == AF_DECnet)
                        return -1;
                dst->family = family;
                dst->bytelen = 0;
                dst->bitlen = 0;
                return 0;
        }

        slash = strchr(arg, '/');
        if (slash)
               *slash = 0;

        err = get_addr_1(dst, arg, family);
        if (err == 0) {
                switch(dst->family) {
                        case AF_INET6:
                                dst->bitlen = 128;
                                break;
                        case AF_DECnet:
                                dst->bitlen = 16;
                                break;
                        default:
                        case AF_INET:
                                dst->bitlen = 32;
                 }
                if (slash) {
                        if (get_unsigned(&plen, slash+1, 0) || plen > dst->bitlen) {
                                err = -1;
                                goto done;
                        }
                        dst->flags |= PREFIXLEN_SPECIFIED;
                        dst->bitlen = plen;
                }
        }
done:
        if (slash)
                *slash = '/';
        return err;
}


int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
        int len = RTA_LENGTH(4);
        struct rtattr *rta;
        if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
                HIP_ERROR("addattr32: Error! max allowed bound %d exceeded\n",maxlen);
                return -1;
        }
        rta = NLMSG_TAIL(n);
        rta->rta_type = type;
        rta->rta_len = len;
        memcpy(RTA_DATA(rta), &data, 4);
        n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
        return 0;
}



int hip_iproute_modify(struct rtnl_handle *rth,
		       int cmd, int flags, int family, char *ip,
		       char *dev)
{
        struct {
                struct nlmsghdr         n;
                struct rtmsg            r;
                char                    buf[1024];
        } req1;
        inet_prefix dst;
	struct idxmap *idxmap[16];
        int dst_ok = 0, err;
        int idx, i;

        memset(&req1, 0, sizeof(req1));
	for (i = 0; i < 16; i++)
		idxmap[i] = NULL;

        req1.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
        req1.n.nlmsg_flags = NLM_F_REQUEST|flags;
        req1.n.nlmsg_type = cmd;
        req1.r.rtm_family = family;
        req1.r.rtm_table = RT_TABLE_MAIN;
        req1.r.rtm_scope = RT_SCOPE_NOWHERE;

        if (cmd != RTM_DELROUTE) {
                req1.r.rtm_protocol = RTPROT_BOOT;
                req1.r.rtm_scope = RT_SCOPE_UNIVERSE;
                req1.r.rtm_type = RTN_UNICAST;
        }

	if (family== AF_INET) HIP_DEBUG("Setting %s as route for %s device with family %d\n",ip, dev, family);
        HIP_IFEL(get_prefix_1(&dst, ip, req1.r.rtm_family), -1, "prefix\n");
        //if (req.r.rtm_family == AF_UNSPEC)
                //req.r.rtm_family = dst.family;
        req1.r.rtm_dst_len = dst.bitlen;
        dst_ok = 1;
        if (dst.bytelen)
		addattr_l(&req1.n, sizeof(req1), RTA_DST, &dst.data,
			  dst.bytelen);

	ll_init_map(rth, idxmap);

	HIP_IFEL(((idx = ll_name_to_index(dev, idxmap)) == 0), -1,
		"ll_name_to_index failed\n");

	addattr32(&req1.n, sizeof(req1), RTA_OIF, idx);

  	HIP_IFEL((netlink_talk(rth, &req1.n, 0, 0, NULL, NULL, NULL) < 0), -1,
		"netlink_talk failed\n");

 out_err:
	for (i = 0; i < 16; i++)
	  if (idxmap[i])
	    HIP_FREE(idxmap[i]);

        return 0;
}

int hip_parse_src_addr(struct nlmsghdr *n, struct in6_addr *src_addr)
{
	struct rtmsg *r = NLMSG_DATA(n);
        struct rtattr *tb[RTA_MAX+1];
	union {
		struct in_addr *in;
		struct in6_addr *in6;
	} addr;
	int err = 0, entry;

	/* see print_route() in ip/iproute.c */
        parse_rtattr(tb, RTA_MAX, RTM_RTA(r), n->nlmsg_len);
	_HIP_DEBUG("sizeof(struct nlmsghdr) =%d\n",sizeof(struct nlmsghdr));
	_HIP_DEBUG("sizeof(struct rtmsg) =%d\n",sizeof(struct rtmsg));
	_HIP_DEBUG("sizeof  n->nlmsg_len =%d\n",  n->nlmsg_len );
	_HIP_HEXDUMP("nlmsghdr : ", n,sizeof(struct nlmsghdr));
	_HIP_HEXDUMP("rtmsg : ", r, sizeof(struct rtmsg));
	_HIP_HEXDUMP("nlmsg : ", n, n->nlmsg_len);
	_HIP_HEXDUMP("tb[RTA_SRC] : ", &tb[RTA_SRC],sizeof(struct rtattr));
	//entry = (tb[RTA_SRC] ? RTA_SRC : RTA_PREFSRC);
	addr.in6 = (struct in6_addr *) RTA_DATA(tb[2]);
	entry = 7;
	addr.in6 = (struct in6_addr *) RTA_DATA(tb[entry]);
	if(r->rtm_family == AF_INET){
		IPV4_TO_IPV6_MAP(addr.in, src_addr);
	}else
		memcpy(src_addr, addr.in6, sizeof(struct in6_addr));

 out_err:

	return err;
}

int hip_iproute_get(struct rtnl_handle *rth, struct in6_addr *src_addr,
		    struct in6_addr *dst_addr, char *idev, char *odev,
		    int family, struct idxmap **idxmap)
{
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
		char   			buf[1024];
	} req;

	int err = 0, idx, preferred_family = family;
	inet_prefix addr;
	char dst_str[INET6_ADDRSTRLEN];
	struct in_addr ip4;
	HIP_ASSERT(dst_addr);

	HIP_DEBUG_IN6ADDR("Getting route for destination address", dst_addr);
	
	if(IN6_IS_ADDR_V4MAPPED(dst_addr)) {
		IPV6_TO_IPV4_MAP(dst_addr, &ip4);
		preferred_family = AF_INET;
		HIP_IFEL((!inet_ntop(preferred_family, &ip4, dst_str,
                             INET6_ADDRSTRLEN)), -1,"inet_pton\n");
	} else {
		HIP_IFEL((!inet_ntop(preferred_family, dst_addr, dst_str,
				     INET6_ADDRSTRLEN)), -1,
			 "inet_pton\n");
	}
	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = preferred_family;
	req.r.rtm_table = 0;
	req.r.rtm_protocol = 0;
	req.r.rtm_scope = 0;
	req.r.rtm_type = 0;
	req.r.rtm_src_len = 0;
	req.r.rtm_dst_len = 0;
	req.r.rtm_tos = 0;

	get_prefix(&addr, dst_str, req.r.rtm_family);
       
	if (addr.bytelen)
		addattr_l(&req.n, sizeof(req), RTA_DST, &addr.data,
			  addr.bytelen);
	req.r.rtm_dst_len = addr.bitlen;

	ll_init_map(rth, idxmap);

	if (idev) {
		HIP_IFEL(((idx = ll_name_to_index(idev, idxmap)) == 0),
			 -1, "Cannot find device \"%s\"\n", idev);
		addattr32(&req.n, sizeof(req), RTA_IIF, idx);
	}
	if (odev) {
		HIP_IFEL(((idx = ll_name_to_index(odev, idxmap)) == 0),
			 -1, "Cannot find device \"%s\"\n", odev);
		addattr32(&req.n, sizeof(req), RTA_OIF, idx);
	}
	HIP_IFE((rtnl_talk(rth, &req.n, 0, 0, &req.n, NULL, NULL) < 0), -1);

	HIP_IFE(hip_parse_src_addr(&req.n, src_addr), -1);

 out_err:

	return err;
}

int convert_ipv6_slash_to_ipv4_slash(char *ip, struct in_addr *ip4){
	struct in6_addr ip6_aux;
	char *slash = strchr(ip, '/');
	char *aux_slash = NULL;
	int err;

	if (slash){
		HIP_IFEL(!(aux_slash = HIP_MALLOC(sizeof(slash), 0)), -1, "alloc\n");
		strcpy(aux_slash, slash);
             	*slash = 0;
	}

	inet_pton(AF_INET6, ip, &ip6_aux);

	if (err = IN6_IS_ADDR_V4MAPPED(&ip6_aux)){
		IPV6_TO_IPV4_MAP(&ip6_aux, ip4);
		_HIP_DEBUG("ip4 value is %s\n", inet_ntoa(*ip4));
	}
	*slash = *aux_slash;

 out_err:
 	if (aux_slash)	
		HIP_FREE(aux_slash);	  
	return err;
}

int hip_ipaddr_modify(struct rtnl_handle *rth, int cmd, int family, char *ip,
		      char *dev, struct idxmap **idxmap)
{
        struct {
                struct nlmsghdr         n;
                struct ifaddrmsg        ifa;
                char                    buf[256];
        } req;

        inet_prefix lcl;
        int local_len = 0, err = 0, size_dev;
        inet_prefix addr;
	struct in6_addr ip6_aux;
	struct in_addr ip4;
	int ip_is_v4 = 0;
	char label[4];
	char *res = NULL;

        memset(&req, 0, sizeof(req));
	if(convert_ipv6_slash_to_ipv4_slash(ip, &ip4)){
		family = AF_INET;		
		ip_is_v4 = 1;
		lsi_total++;		
		ip = strcat(inet_ntoa(ip4), HIP_LSI_FULL_PREFIX_STR);
		sprintf(label, ":%d", lsi_total);
		HIP_DEBUG("Label %s:%d\n", ip, lsi_total);
	}

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)); 
	req.n.nlmsg_type = cmd;
        req.n.nlmsg_flags = NLM_F_REQUEST;
	req.ifa.ifa_family = family;

	get_prefix_1(&lcl, ip, req.ifa.ifa_family);
	addattr_l(&req.n, sizeof(req), IFA_LOCAL, &lcl.data, lcl.bytelen);
	
        if(ip_is_v4 && lsi_total > 0){
		size_dev = sizeof(dev)+sizeof(label);
		res = (char *)malloc(size_dev+1);
		memset(res,'\0',size_dev+1);
		strcat(res, dev);
		strcat(res, label);
		_HIP_DEBUG("Name device inserted %s\n", res);
		addattr_l(&req.n, sizeof(req), IFA_LABEL, res, strlen(dev) + strlen(label)+1);		
	}	

        local_len = lcl.bytelen;

	if (req.ifa.ifa_prefixlen == 0)
                req.ifa.ifa_prefixlen = lcl.bitlen;

        HIP_IFEL(((req.ifa.ifa_index = ll_name_to_index(dev, idxmap)) == 0),
		 -1, "ll_name_to_index failed\n");

	HIP_DEBUG("IFA INDEX IS %d\n",req.ifa.ifa_index);

	int aux = netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL);// adds to the device dummy0
	HIP_DEBUG("value exit function netlink_talk %i\n", aux);
        HIP_IFEL((aux < 0), -1,
		 "netlink talk failed\n");

 out_err:
	if (res)
		HIP_FREE(res);
	return 0;
}

/**
 * Functions for setting up dummy interface
 */

int get_ctl_fd(void)
{
        int s_errno;
        int fd;

        fd = socket(PF_INET, SOCK_DGRAM, 0);
        if (fd >= 0)
                return fd;
        s_errno = errno;
        fd = socket(PF_PACKET, SOCK_DGRAM, 0);
        if (fd >= 0)
                return fd;
        fd = socket(PF_INET6, SOCK_DGRAM, 0);
        if (fd >= 0)
                return fd;
        errno = s_errno;
        HIP_PERROR("Cannot create control socket");
        return -1;
}


int do_chflags(const char *dev, __u32 flags, __u32 mask)
{
        struct ifreq ifr;
        int fd;
        int err;

        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
        fd = get_ctl_fd();
        if (fd < 0)
                return -1;

        err = ioctl(fd, SIOCGIFFLAGS, &ifr);// get interface dummy0 flags
        if (err) {
                HIP_PERROR("SIOCGIFFLAGS");
                close(fd);
                return -1;
        }

        if ((ifr.ifr_flags^flags)&mask) {
                ifr.ifr_flags &= ~mask;
                ifr.ifr_flags |= mask&flags;
		// the following did not work, see bug id 595
		// ifr.ifr_mtu = HIP_DEFAULT_MTU;
                err = ioctl(fd, SIOCSIFFLAGS, &ifr);
                if (err)
                        HIP_PERROR("SIOCSIFFLAGS");
        }

        close(fd);
        return err;
}


int set_up_device(char *dev, int up)
{
	int err = -1, total_add;
	__u32 mask = 0;
	__u32 flags = 0;
	char label[4];
	char *res = NULL;
	int size_dev;

	if(up == 1){
		mask |= IFF_UP;
		flags |= IFF_UP;
	} else {
		mask |= IFF_UP;
		flags &= ~IFF_UP;
		for( total_add = lsi_total; total_add >0; total_add--){
			sprintf(label, ":%d", total_add);
			size_dev = sizeof(dev)+sizeof(label);
			res = (char *)malloc(size_dev+1);
			memset(res,'\0',size_dev+1);
			strcat(strcat(res, dev), label);
			err = do_chflags(res, flags, mask);
			if (res)
				HIP_FREE(res);
		}
	}
	err = do_chflags(dev, flags, mask);
	
out_err:
	return err;
}

/**
 * xfrm_selector_ipspec - fill port info in the selector.
 * Selector is bound to HITs
 * @param sel pointer to xfrm_selector to be filled in
 * @param src_port Source port
 * @param dst_port Destination port
 *
 * @return 0
 */

int xfrm_selector_upspec(struct xfrm_selector *sel,
				uint32_t src_port, uint32_t dst_port)
{
	sel->sport = htons(src_port);
        if (sel->sport)
		sel->sport_mask = ~((__u16)0);

	sel->dport = htons(dst_port);
        if (sel->dport)
        	sel->dport_mask = ~((__u16)0);

	return 0;


}
int xfrm_fill_encap(struct xfrm_encap_tmpl *encap, int sport, int dport, struct in6_addr *oa)
{
	encap->encap_type = HIP_UDP_ENCAP_ESPINUDP;
	encap->encap_sport = htons(sport);
	encap->encap_dport = htons(dport);
	encap->encap_oa.a4 = oa->s6_addr32[3];
	//memcpy(&encap->encap_oa, oa, sizeof(encap->encap_oa));
	//memcpy(&encap->encap_oa, oa, sizeof(struct in_addr));
	return 0;
}
/**
 * xfrm_fill_selector - fill in the selector.
 * Selector is bound to HITs
 * @param sel pointer to xfrm_selector to be filled in
 * @param hit_our Source HIT or LSI, if the last is defined
 * @param hit_peer Peer HIT or LSI, if the last is defined 
 * @param proto ?
 * @param id_prefix Length of the identifier's prefix
 * @param src_port ?
 * @param dst_port ?
 * @param preferred_family ?
 *
 * @return 0
 */


int xfrm_fill_selector(struct xfrm_selector *sel,
		       struct in6_addr *id_our,
		       struct in6_addr *id_peer,
		       __u8 proto, u8 id_prefix,
		       uint32_t src_port, uint32_t dst_port,
		       int preferred_family)
{

	struct in_addr in_id_our, in_id_peer;

	if (IN6_IS_ADDR_V4MAPPED(id_our)){
		sel->family = AF_INET;
		IPV6_TO_IPV4_MAP(id_our, &in_id_our);
		IPV6_TO_IPV4_MAP(id_peer, &in_id_peer);
		memcpy(&sel->daddr, &in_id_our, sizeof(sel->daddr));
		memcpy(&sel->saddr, &in_id_peer, sizeof(sel->saddr));
	}
	else{
		sel->family = preferred_family;
		int aux = sizeof(sel->daddr);
		int aux1 = sizeof(id_peer);
		memcpy(&sel->daddr, id_peer, sizeof(sel->daddr));
		memcpy(&sel->saddr, id_our, sizeof(sel->saddr));
	}

	if (proto) {
		HIP_DEBUG("proto = %d\n", proto);
		sel->proto = proto;
	}

	sel->prefixlen_d = id_prefix;
	sel->prefixlen_s = id_prefix;

	//xfrm_selector_upspec(sel, src_port, dst_port);

	return 0;
}

/** xfrm_init_lft - Initializes the lft
 * @param lft pointer to the lft struct to be initialized
 *
 * @return 0
 */
int xfrm_init_lft(struct xfrm_lifetime_cfg *lft) {

	lft->soft_byte_limit = XFRM_INF;
	lft->hard_byte_limit = XFRM_INF;
	lft->soft_packet_limit = XFRM_INF;
	lft->hard_packet_limit = XFRM_INF;

	return 0;
}

int get_u8(__u8 *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0xFF)
		return -1;
	*val = res;
	return 0;
}

int xfrm_algo_parse(struct xfrm_algo *alg, enum xfrm_attr_type_t type,
		    char *name, char *key, int key_len, int max)
{
	int len = 0;
	int slen = key_len;

	strncpy(alg->alg_name, name, sizeof(alg->alg_name));

	len = slen;
	if (len > 0) {
		if (len > max) {
			HIP_ERROR("\"ALGOKEY\" makes buffer overflow\n", key);
			return -1;
		}
		memcpy(alg->alg_key, key, key_len * 8);
	}

	alg->alg_key_len = len * 8;

	return 0;
}

void rtnl_tab_initialize(char *file, char **tab, int size)
{
	char buf[512];
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp) return;

	while (fgets(buf, sizeof(buf), fp))
	{
		char *p = buf;
		int id;
		char namebuf[512];

		while (*p == ' ' || *p == '\t') p++;
		
		if (*p == '#' || *p == '\n' || *p == 0) continue;

		if (sscanf(p, "0x%x %s\n", &id, namebuf) != 2 &&
		    sscanf(p, "0x%x %s #", &id, namebuf) != 2 &&
		    sscanf(p, "%d %s\n", &id, namebuf) != 2 &&
		    sscanf(p, "%d %s #", &id, namebuf) != 2)
		{
				HIP_ERROR("Database %s is corrupted at %s\n", file, p);
				return;
		}

		if (id < 0 || id > size) continue;

		tab[id] = strdup(namebuf);
	}
	
	fclose(fp);
}

int rtnl_dsfield_a2n(__u32 *id, char *arg, char **rtnl_rtdsfield_tab)
{
        static char *cache = NULL;
        static unsigned long res;
        char *end;
        int i;

        if (cache && strcmp(cache, arg) == 0) {
                *id = res;
                return 0;
        }

	/* rtnl_rtdsfield_initialize() handled in hip_select_source_address */

        for (i=0; i<256; i++) {
                if (rtnl_rtdsfield_tab[i] &&
                    strcmp(rtnl_rtdsfield_tab[i], arg) == 0) {
                        cache = rtnl_rtdsfield_tab[i];
                        res = i;
                        *id = res;
                        return 0;
                }
        }

        res = strtoul(arg, &end, 16);
        if (!end || end == arg || *end || res > 255)
                return -1;
        *id = res;
        return 0;
}

int get_prefix(inet_prefix *dst, char *arg, int family)
{
        if (family == AF_PACKET) {
                HIP_ERROR("Error: \"%s\" may be inet prefix, but it is not allowed in this context.\n", arg);
                return -1;
        }
        if (get_prefix_1(dst, arg, family)) {
                HIP_ERROR("Error: an inet prefix is expected rather than \"%s\".\n", arg);
                return -1;
        }
        return 0;
}

int ll_remember_index(const struct sockaddr_nl *who,
                      struct nlmsghdr *n, void **arg)
{
        int h;
        struct ifinfomsg *ifi = NLMSG_DATA(n);
        struct idxmap *im = NULL, **imp;
	struct idxmap **idxmap = (struct idxmap **) arg;
        struct rtattr *tb[IFLA_MAX+1];

        if (n->nlmsg_type != RTM_NEWLINK)
                return 0;

        if (n->nlmsg_len < NLMSG_LENGTH(sizeof(ifi)))
                return -1;


        memset(tb, 0, sizeof(tb));
        parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));
        if (tb[IFLA_IFNAME] == NULL)
                return 0;

        h = ifi->ifi_index&0xF;

        for (imp=&idxmap[h]; (im=*imp)!=NULL; imp = &im->next)
		if (im->index == ifi->ifi_index)
                        break;

        /* the malloc leaks memory */
        if (im == NULL) {
                im = malloc(sizeof(*im));
                if (im == NULL)
                        return 0;
                im->next = *imp;
                im->index = ifi->ifi_index;
                *imp = im;
        }

        im->type = ifi->ifi_type;
        im->flags = ifi->ifi_flags;
        if (tb[IFLA_ADDRESS]) {
                int alen;
                im->alen = alen = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
                if (alen > sizeof(im->addr))
                        alen = sizeof(im->addr);
                memcpy(im->addr, RTA_DATA(tb[IFLA_ADDRESS]), alen);
        } else {
                im->alen = 0;
                memset(im->addr, 0, sizeof(im->addr));
        }
        strcpy(im->name, RTA_DATA(tb[IFLA_IFNAME]));

        return 0;
}

int rtnl_wilddump_request(struct rtnl_handle *rth, int family, int type)
{
        struct {
                struct nlmsghdr nlh;
                struct rtgenmsg g;
        } req;
        struct sockaddr_nl nladdr;

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;

        memset(&req, 0, sizeof(req));
        req.nlh.nlmsg_len = sizeof(req);
        req.nlh.nlmsg_type = type;
        req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
        req.nlh.nlmsg_pid = 0;
        req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
        req.g.rtgen_family = family;

        return sendto(rth->fd, (void*)&req, sizeof(req), 0,
                      (struct sockaddr*)&nladdr, sizeof(nladdr));
}

int ll_init_map(struct rtnl_handle *rth, struct idxmap **idxmap)
{
	if (rtnl_wilddump_request(rth, AF_UNSPEC, RTM_GETLINK) < 0) {
                HIP_PERROR("Cannot send dump request");
                return -1;
        }

        if (rtnl_dump_filter(rth,
			     /*ll_remember_index*/ NULL,
			     idxmap, NULL, NULL) < 0) {
                HIP_ERROR("Dump terminated\n");
                return -1;
        }
        return 0;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
        memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
        while (RTA_OK(rta, len)) {
                if (rta->rta_type <= max)
                        tb[rta->rta_type] = rta;
                rta = RTA_NEXT(rta,len);
        }
        if (len)
                HIP_ERROR("Deficit len %d, rta_len=%d\n",
			  len, rta->rta_len);
        return 0;
}

int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
              unsigned groups, struct nlmsghdr *answer,
              rtnl_filter_t junk,
              void *jarg, struct idxmap **idxmap)
{
        int status;
        unsigned seq;
        struct nlmsghdr *h;
        struct sockaddr_nl nladdr;
        struct iovec iov = {
                .iov_base = (void*) n,
                .iov_len = n->nlmsg_len
        };
        struct msghdr msg = {
                .msg_name = &nladdr,
                .msg_namelen = sizeof(nladdr),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        char   buf[16384];

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = peer;
        nladdr.nl_groups = groups;

        n->nlmsg_seq = seq = ++rtnl->seq;

        if (answer == NULL)
                n->nlmsg_flags |= NLM_F_ACK;

        status = sendmsg(rtnl->fd, &msg, 0);
	_HIP_HEXDUMP("Msg sent : ", &msg, sizeof(struct nlmsghdr));
        if (status < 0) {
                HIP_PERROR("Cannot talk to rtnetlink");
                return -1;
        }

        memset(buf,0,sizeof(buf));

        iov.iov_base = buf;

        while (1) {
                iov.iov_len = sizeof(buf);
                status = recvmsg(rtnl->fd, &msg, 0);

                if (status < 0) {
                        if (errno == EINTR)
                                continue;
                        HIP_PERROR("OVERRUN");
                        continue;
                }
                if (status == 0) {
                        HIP_ERROR("EOF on netlink\n");
                        return -1;
                }
                if (msg.msg_namelen != sizeof(nladdr)) {
                        HIP_ERROR("sender address length == %d\n", msg.msg_namelen);
                        return -1;
                }
                for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
                        int err;
                        int len = h->nlmsg_len;
                        int l = len - sizeof(*h);

                        if (l<0 || len>status) {
                                if (msg.msg_flags & MSG_TRUNC) {
                                        HIP_ERROR("Truncated message\n");
                                        return -1;
                                }
                                HIP_ERROR("malformed message: len=%d\n", len);
                                return -1;
                        }

                        if (nladdr.nl_pid != peer ||
                            h->nlmsg_pid != rtnl->local.nl_pid ||
                            h->nlmsg_seq != seq) {
                                if (junk) {
                                        err = junk(&nladdr, h, jarg);
                                        if (err < 0)
                                                return err;
                                }
                               /* Don't forget to skip that message. */
                                status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));

                                continue;
                        }

                        if (h->nlmsg_type == NLMSG_ERROR) {
                                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                                if (l < sizeof(struct nlmsgerr)) {
                                        HIP_ERROR("ERROR truncated\n");
                                } else {
                                        errno = -err->error;
                                        if (errno == 0) {
                                                if (answer)
                                                        memcpy(answer, h, h->nlmsg_len);
                                                return 0;
                                        }
                                        HIP_PERROR("RTNETLINK answers");
                                }
                                return -1;
                        }
                        if (answer) {
                                memcpy(answer, h, h->nlmsg_len);
				_HIP_HEXDUMP("Answer : ", h,h->nlmsg_len);
                                return 0;
                        }

                        HIP_ERROR("Unexpected reply!!!\n");

                        status -= NLMSG_ALIGN(len);
                        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                }
                if (msg.msg_flags & MSG_TRUNC) {
                        HIP_ERROR("Message truncated\n");
                        continue;
                }
                if (status) {
                        HIP_ERROR("Remnant of size %d\n", status);
                        return -1;
                }
        }
}

int rtnl_dump_filter(struct rtnl_handle *rth,
                     rtnl_filter_t filter,
                     void *arg1,
                     rtnl_filter_t junk,
                     void *arg2)
{
        struct sockaddr_nl nladdr;
        struct iovec iov;
        struct msghdr msg = {
                .msg_name = &nladdr,
                .msg_namelen = sizeof(nladdr),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        char buf[16384];

        while (1) {
                int status;
                struct nlmsghdr *h;

		        iov.iov_base = buf;
                iov.iov_len = sizeof(buf);
                status = recvmsg(rth->fd, &msg, 0);

                if (status < 0) {
                        if (errno == EINTR)
                                continue;
                        HIP_PERROR("OVERRUN");
                        continue;
                }

                if (status == 0) {
                        HIP_ERROR("EOF on netlink\n");
                        return -1;
                }

                h = (struct nlmsghdr*)buf;
                while (NLMSG_OK(h, status)) {
                        int err = 0;

                        if (nladdr.nl_pid != 0 ||
                            h->nlmsg_pid != rth->local.nl_pid ||
                            h->nlmsg_seq != rth->dump) {
                                if (junk) {
                                        err = junk(&nladdr, h, arg2);
                                        if (err < 0)
                                                return err;
                                }
                                goto skip_it;
                        }

                        if (h->nlmsg_type == NLMSG_DONE)
                                return 0;
                        if (h->nlmsg_type == NLMSG_ERROR) {
                                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                                        HIP_ERROR("ERROR truncated\n");
                                } else {
                                        errno = -err->error;
                                        HIP_PERROR("RTNETLINK answers");
                                }
                                return -1;
                        }
			if (filter)
				err = filter(&nladdr, h, arg1);
                        if (err < 0)
                                return err;

skip_it:
                        h = NLMSG_NEXT(h, status);
                }
                if (msg.msg_flags & MSG_TRUNC) {
                        HIP_ERROR("Message truncated\n");
                        continue;
                }
                if (status) {
                        HIP_ERROR("Remnant of size %d\n", status);
                        return -1;
                }
        }
}

#ifdef CONFIG_HIP_OPPTCP

/**
* Standard BSD internet checksum routine from nmap
*/
unsigned short in_cksum(u16 *ptr,int nbytes){
	register u32 sum;
	u16 oddbyte;
	register u16 answer;

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */

	sum = 0;
	while (nbytes > 1){
		sum += *ptr++;
		nbytes -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;            /* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

	sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
	sum += (sum >> 16);                     /* add carry */
	answer = ~sum;          /* ones-complement, then truncate to 16 bits */
	return(answer);
}



/**
 * adds the i1 option to a packet if required
 * adds the default HIT after the i1 option (if i1 option should be added)
 * and sends it off with the correct checksum
 */
void send_tcp_packet(void * hdr, int newSize, int trafficType, int addOption, int addHIT){
	int   sockfd, socketFamily;
	int   on = 1, i, j;
	int   hdr_size, newHdr_size, twoHdrsSize;
	char  *packet;
	char  *bytes =(char*)hdr;
	struct sockaddr_in  sock_raw;
	struct sockaddr_in6 sock6_raw;
	struct in_addr  dstAddr;
	struct in6_addr dst6Addr;
	struct tcphdr *tcphdr;
	struct tcphdr *newTcphdr;
	struct ip * iphdr;
	struct ip * newIphdr;
	struct ip6_hdr * ip6_hdr;
	struct ip6_hdr * newIp6_hdr;
	struct pseudo_hdr  *pseudo;
	struct pseudo6_hdr *pseudo6;
	void *pointer;
	char *HITbytes;
	struct in6_addr *defaultHit;
	char newHdr [newSize + 4*addOption + (sizeof(struct in6_addr))*addHIT];

	if(addOption)
		newSize = newSize + 4;
	if(addHIT)
		newSize = newSize + sizeof(struct in6_addr);

	//initializing the raw socket
	if(trafficType == 4)
		socketFamily = AF_INET;
	else if(trafficType == 6)
		socketFamily = AF_INET6;

	if((sockfd = socket(socketFamily, SOCK_RAW, IPPROTO_RAW)) < 0 ){
			HIP_DEBUG("Error creating raw socket\n");
			return;
	}
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0 ){
		HIP_DEBUG("Error setting an option to raw socket\n"); 
		return;
	}

	//initializing the headers and setting socket settings
	if(trafficType == 4){
		//get the ip header
		iphdr = (struct ip *)hdr;
		//get the tcp header
		hdr_size = (iphdr->ip_hl * 4);
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));
		//socket settings
		sock_raw.sin_family = AF_INET;
		sock_raw.sin_port = htons(tcphdr->dest);
		sock_raw.sin_addr = iphdr->ip_dst;
	}
	else if(trafficType == 6){
		//get the ip header
		ip6_hdr = (struct ip6_hdr *)hdr;
		//get the tcp header		
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));
		//socket settings
		sock6_raw.sin6_family = AF_INET6;
		sock6_raw.sin6_port = htons(tcphdr->dest);
		sock6_raw.sin6_addr = ip6_hdr->ip6_dst;
	}

	//measuring the size of ip and tcp headers (no options)
	twoHdrsSize = hdr_size + 4*5;

	//copy the ip header and the tcp header without the options
	i = 0;
	while(i < twoHdrsSize){
		newHdr[i] = bytes[i];
		i++;
	}

	//add the i1 option and copy the old options
	//add the HIT if required, 
	if(tcphdr->doff == 5){//there are no previous options
		if(addOption){
			newHdr[twoHdrsSize]     = (char)HIP_OPTION_KIND;
			newHdr[twoHdrsSize + 1] = '0';
			newHdr[twoHdrsSize + 2] = '0';
			newHdr[twoHdrsSize + 3] = '0';
			if(addHIT){
				//get the default hit
				hip_get_default_hit(defaultHit);
				//copy the hit
				HITbytes = (char*)defaultHit;
				for(j = 0; j < 16; j++)
					newHdr[twoHdrsSize + 4 + j] = HITbytes[j];
			}
		}
		else{
			if(addHIT){
				//get the default hit
				hip_get_default_hit(defaultHit);
				//copy the hit
				HITbytes = (char*)defaultHit;
				for(j = 0; j < 16; j++)
					newHdr[twoHdrsSize + j] = HITbytes[j];
			}
		}
	}
	else{//there are previous options
		if(addOption){
			newHdr[twoHdrsSize]     = (char)HIP_OPTION_KIND;
			newHdr[twoHdrsSize + 1] = (char)2;
			newHdr[twoHdrsSize + 2] = (char)1;
			newHdr[twoHdrsSize + 3] = (char)1;

			//if the HIT is to be sent, the
			//other options are not important
			if(addHIT){
				//get the default hit
				hip_get_default_hit(defaultHit);
				//copy the hit
				HITbytes = (char*)defaultHit;
				for(j = 0; j < 16; j++)
					newHdr[twoHdrsSize + 4 + j] = HITbytes[j];
			}
			else{
				i = 0;
				while(i < 4*(tcphdr->doff-5)){
					newHdr[i + twoHdrsSize + 4] = bytes[i + twoHdrsSize];
					i++;
				}
			}
		}
		else
		{
			//if the HIT is to be sent, the
			//other options are not important
			if(addHIT){
				//get the default hit
				hip_get_default_hit(defaultHit);
				//copy the hit
				HITbytes = (char*)defaultHit;
				for(j = 0; j < 16; j++)
					newHdr[twoHdrsSize + j] = HITbytes[j];
			}
			else{
				i = 0;
				while(i < 4*(tcphdr->doff-5)){
					newHdr[i + twoHdrsSize] = bytes[i + twoHdrsSize];
					i++;
				}
			}
		}
	}

	pointer = &newHdr[0];
	//get pointers to the new packet
	if(trafficType == 4){
		//get the ip header
		newIphdr = (struct ip *)pointer;
		//get the tcp header
		newHdr_size = (iphdr->ip_hl * 4);
		newTcphdr = ((struct tcphdr *) (((char *) newIphdr) + newHdr_size));
	}
	else if(trafficType == 6){
		//get the ip header
		newIp6_hdr = (struct ip6_hdr *)pointer;
		//get the tcp header		
		newHdr_size = (newIp6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		newTcphdr = ((struct tcphdr *) (((char *) newIp6_hdr) + newHdr_size));
	}

	//change the values of the checksum and the tcp header length(+1) 
	newTcphdr->check = 0;
	if(addOption)
		newTcphdr->doff = newTcphdr->doff + 1;
	if(addHIT)
		newTcphdr->doff = newTcphdr->doff + 4;//16 bytes HIT - 4 more words

	//the checksum
	if(trafficType == 4){
		pseudo = (struct pseudo_hdr *) ((u8*)newTcphdr - sizeof(struct pseudo_hdr));

		pseudo->s_addr = newIphdr->ip_src.s_addr;
		pseudo->d_addr = newIphdr->ip_dst.s_addr;
		pseudo->zer0    = 0;
		pseudo->protocol = IPPROTO_TCP;
		pseudo->length  = htons(sizeof(struct tcphdr) + 4*(newTcphdr->doff-5) + 0);

		newTcphdr->check = in_cksum((unsigned short *)pseudo, sizeof(struct tcphdr) + 
							4*(newTcphdr->doff-5) + sizeof(struct pseudo_hdr) + 0);
	}
	else if(trafficType == 6){
		pseudo6 = (struct pseudo6_hdr *) ((u8*)newTcphdr - sizeof(struct pseudo6_hdr));

		pseudo6->s_addr = newIp6_hdr->ip6_src;
		pseudo6->d_addr = newIp6_hdr->ip6_dst;
		pseudo6->zer0    = 0;
		pseudo6->protocol = IPPROTO_TCP;
		pseudo6->length  = htons(sizeof(struct tcphdr) + 4*(newTcphdr->doff-5) + 0);

		newTcphdr->check = in_cksum((unsigned short *)pseudo6, sizeof(struct tcphdr) +
							4*(newTcphdr->doff-5) + sizeof(struct pseudo6_hdr) + 0);
	}

	//replace the pseudo header bytes with the correct ones
	i = 0;
	while(i < hdr_size){
		newHdr[i] = bytes[i];
		i++;
	}

	//change the src and dst ip if it was an incoming packet******


	//finally send through the socket
	sendto(sockfd, &newHdr[0], newSize, 0, 
			(struct sockaddr *)&sock_raw, sizeof(sock_raw));
}


#endif

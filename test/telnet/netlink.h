/* $USAGI: netlink.h,v 1.3 2001/01/12 21:36:32 sekiya Exp $ */

class netlink {
 protected:
    int net;
 public:
    netlink();
    ~netlink();

#ifdef USE_HIP
    int connect(int debug, struct endpointinfo *endpointinfo,
		char *srcroute, int srlen, int tos);
#else /* !USE_HIP */
    int connect(int debug, struct addrinfo *hostaddr, 
		char *srcroute, int srlen,
		int tos);
#endif /* USE_HIP */
    void close(int doshutdown);

    int setdebug(int debug);
    void oobinline();
    void nonblock(int onoff);

    int stilloob();

    int send(const char *buf, int len, int flags);

    int getfd();
};

extern netlink nlink;

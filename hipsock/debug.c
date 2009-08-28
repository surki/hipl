/*
 * HIP kernelspace debugging functions
 * Licence: GNU/GPL
 *
 * @author Miika Komu <miika#iki.fi>
 * @author Mika Kousa <mkousa#iki.fi>
 */
#include "debug.h"

/**
 * Prints a HIT.
 * 
 * @param str string to be printed before the HIT.
 * @param hit the HIT to be printed.
 */
inline void hip_print_hit(const char *str, const struct in6_addr *hit)
{
	char dst[INET6_ADDRSTRLEN];

	hip_in6_ntop(hit, dst);
	HIP_DEBUG("%s: %s\n", str, dst);
	return;
}

/**
 * A hexdumper for the HIP kernel module. Hexdumps data starting from address
 * @c data of length @c len.
 * 
 * @param tag  a start tag (a string ending in '\\0') that will be printed before
 *             the actual hexdump
 * @param data the data to be hexdumped
 * @param len  the length of the data to hexdumped
 */
inline void hip_khexdump(const char *tag, const void *data, const int len)
{
	char *buf, *bufpos;
	const void *datapos;
	int buflen, i;
	unsigned char c;

	if (!data || len < 0) {
		HIP_ERROR("NULL data or len < 0 (len=%d)\n", len);
		return;
	}

	/* every hexdump line contains offset+": "+32 bytes of data (space every 4 bytes) */
	buflen = 4+2+2*32+((32-1)/4)+1;
	buf = kmalloc(buflen, GFP_ATOMIC);
	if (!buf)
		return;

	HIP_DEBUG("%s: begin dump %d bytes from 0x%p\n", tag, len, data);
	datapos = data;

	i = 0;
	while (i < len) {
		int j;

		bufpos = buf;
		memset(buf, 0, buflen);
		sprintf(bufpos, "%4d: ", i);
		bufpos += 4+2;
		for (j = 0; i < len && bufpos < buf+buflen-1;
		     j++, i++, bufpos += 2*sizeof(char)) {
			c = (unsigned char)(*(((unsigned char *)data)+i));
			if (j && !(j%4)) {
				sprintf(bufpos, " ");
				bufpos += sizeof(char);
			}
			sprintf(bufpos, "%02x", c);
		}
		printk(KERN_DEBUG "%s\n", buf);
	}

	HIP_DEBUG("end of dump (0x%p)\n", data+len);
	kfree(buf);
	return;
}


inline int is_big_endian(void)
{
	int i = 1;
	char *p = (char *) &i;

	if (p[0] == 1)
		return 0;
	else
		return 1;
}

inline uint64_t hton64(uint64_t i) {
	if (is_big_endian())
		return i;
	else
		return ( ((__u64)(htonl((i) & 0xffffffff)) << 32) | htonl(((i) >> 32) & 0xffffffff) );
}

inline uint64_t ntoh64(uint64_t i) {
	if (is_big_endian())
		return i;
	else
		return hton64(i);
}

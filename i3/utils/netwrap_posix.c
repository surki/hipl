#include "netwrap.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int
nw_init(void)
{
    return 0;
}

int
nw_fini(void)
{
    return 0;
}

int
nw_close(nw_skt_t socket)
{
    return close(socket);
}

int
nw_error(void)
{
    return errno;
}

int
nw_set_nblk(nw_skt_t socket, int nblk)
{
    int flags;

    flags = fcntl(socket, F_GETFL);
    if (0 != nblk) {
	flags |= O_NONBLOCK;
    } else {
	flags &= ~O_NONBLOCK;
    }
    return (-1 != fcntl(socket, F_SETFL, flags)) ? 0 : -1;
}

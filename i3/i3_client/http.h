#ifndef _HTTP_TEST_H
#define _HTTP_TEST_H

#include "i3server_list.h"

void update_i3_server_list(char *web_url, I3ServerList *list,
			   I3ServerListNode **next_ping);

#endif

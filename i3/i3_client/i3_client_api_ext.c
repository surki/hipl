#include "i3.h"

#include <errno.h>    
#include <time.h>
#ifndef _WIN32
    #include <pthread.h>
#else
    #include <process.h>
#endif
#include "i3_fun.h"
#include "i3_client.h"
#include "i3_client_fun.h"
#include "ping_thread.h"
#include "i3server_list.h"
#include "i3_debug.h"

#include "i3_client_api.h"
#include "i3_client_api_ctx.h"

/**********************************************************************
 *
 **********************************************************************/
int cl_init_ping(cl_context* ctx, char *url)
{
#ifndef _WIN32
    pthread_t ping_thread;
#else
    uintptr_t err;
    unsigned ping_thread = 0;
#endif
    PingThreadData *data;
    Coordinates coord;
    char *temp_str;
    int i;
    
    if (ctx == NULL)
	return CL_RET_DUP_CONTEXT;
    
    ctx->list = (I3ServerList *) malloc(sizeof(I3ServerList));
    ctx->ping_start_time = (uint64_t *) malloc(sizeof(uint64_t));
    init_i3server_list(ctx->list);

    coord.latitude = COORD_UNDEFINED; coord.longitude = COORD_UNDEFINED;
    for (i = 0; i < ctx->num_servers; i++)
      create_i3server(ctx->list, ctx->s_array[i].addr.s_addr,
	  	ctx->s_array[i].port, ctx->s_array[i].id, coord);
    
    data = (PingThreadData *) malloc(sizeof(PingThreadData));
    temp_str = (char *) malloc(strlen(url)+1);
    strcpy(temp_str, url);
    data->url = temp_str;
    data->list = ctx->list;
    data->ping_start_time = ctx->ping_start_time;

#ifndef _WIN32
    pthread_create(&ping_thread, NULL, ping_thread_entry, (void *)data);
    return CL_RET_OK;
#else
    err = _beginthreadex(NULL, 0, ping_thread_entry, (void *)data, 0, &ping_thread);
    return (0 != err) ? CL_RET_OK : errno;
#endif
}




/***************************************************************************
                          i3_client_id.h  -  description
                             -------------------
    begin                : Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_TIMER_H
#define I3_CLIENT_TIMER_H 

/* functions implemented in i3_client_timer.c */
void init_timer_heap(cl_context *ctx);
void free_timer_heap(cl_context *ctx);
void invoke_timers(cl_context *ctx, uint64_t now);
int get_next_timer(cl_context *ctx, struct timeval *to, uint64_t now);

#endif

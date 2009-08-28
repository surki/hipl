
#include "i3.h"
#include "i3_fun.h"
#include "i3_client.h"
#include "i3_client_fun.h"
#include "../utils/event.h"

#define TIMER_HEAP_SIZE 65536

void init_timer_heap(cl_context *ctx)
{

  ctx->timer_heap.heap = newEventArray(TIMER_HEAP_SIZE);
  ctx->timer_heap.size = 0;
  ctx->timer_heap.max_size = TIMER_HEAP_SIZE;
}

void free_timer_heap(cl_context *ctx)
{
  if (ctx->timer_heap.heap)
    free(ctx->timer_heap.heap);
}

/***********************************************************************
 *  cl_invoke_timer - invoke all timers up to current time 'now'
 ************************************************************************/

void invoke_timers(cl_context *ctx, uint64_t now)
{
  Event *ev;
  void (*fun)();
  void *data;

  while (1) {
    ev = getNextEvent(&ctx->timer_heap);
    if (ev && ev->time <= now) {
      if (ev->cancel == FALSE) {
	/* invoke timer only if it wasn't canceled in between */
	fun = ev->fun;
	data = ev->params;
	fun(data);
      }
      removeNextEvent(&ctx->timer_heap);
    } else
      return;
  }
}


int get_next_timer(cl_context *ctx, struct timeval *to, uint64_t now)
{
  uint64_t diff;
  Event *ev = getNextEvent(&ctx->timer_heap);

  if (!ev)
    return 0;

  if (ev->time < now)  
    to->tv_sec = to->tv_usec = 0;
  else {
    diff = ev->time - now;
    to->tv_usec = diff % UMILLION;
    to->tv_sec = diff / UMILLION;
  }
  return 1;
}


/*
 *
 * Copyright (C) 2001 Ion Stoica (istoica@cs.berkeley.edu)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining
 *  a copy of this software and associated documentation files (the
 *  "Software"), to deal in the Software without restriction, including
 *  without limitation the rights to use, copy, modify, merge, publish,
 *  distribute, sublicense, and/or sell copies of the Software, and to
 *  permit persons to whom the Software is furnished to do so, subject to
 *  the following conditions:
 *
 *  The above copyright notice and this permission notice shall be
 *  included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
    #include <inttypes.h>
#else
    #include "fwint.h"
#endif


#include "event.h"

Event *newEvent(void (*fun)(), void *params, uint64_t time)
{
  Event *ev;

  if (!(ev = (Event *)calloc(1, sizeof(Event)))) {
    printf("newEvent: memory alloc. error.\n");
    exit(-1);
  }
  ev->fun = fun;
  ev->params = params;
  ev->time = time;
  ev->cancel = 0;

  return ev;
}

// allocate an array of pointers to events
Event **newEventArray(int max_heap_size)
{
  Event **q;

  if (!(q = (Event **)calloc(1, max_heap_size*sizeof(Event **)))) {
    printf("initEventQueue: memory alloc. error.\n");
    exit(-1);
  }
  return q;
}


// swap two events in the heap      
void swap_events(EventHeap *h, unsigned int idx, unsigned int idx1)
{
  Event *t;
  
  t = h->heap[idx];
  h->heap[idx] = h->heap[idx1];
  h->heap[idx1] = t;
}


// insert new event in the heap
void insertEvent(EventHeap *h, Event *ev)
{
  int idx, idx1;

  if (h->size > h->max_size - 1) {
    printf("Event not inserted; too many events.\n");
    return;
  }

  h->heap[h->size] = ev;
  (h->size)++;

  // rebuild heap
  idx = h->size - 1;
  idx1 = (idx-1)/2;
  while ((idx >= 1) && (h->heap[idx]->time < h->heap[idx1]->time)) {
    swap_events(h, idx, idx1);
    idx = idx1;
    idx1 = (idx-1)/2;
  }
}

// get the top of the heap
Event *getNextEvent(EventHeap *h)
{
  if (h->size > 0)
    return h->heap[0];
  else
    return NULL;
}


// remove the event at the top of the heap
void removeNextEvent(EventHeap *h)
{
  unsigned int idx, idx1, idx_left, idx_right;

  free(h->heap[0]);
  if (h->size > 1) 
    h->heap[0] = h->heap[h->size - 1];
  if (h->size)
    h->size--;

  // rebuild heap
  idx = 0;
  while (1) {
    idx_left = 2*idx + 1;
    idx_right = idx_left + 1;
    if (idx_left >= h->size) {
      return;
    }
    if (idx_left == h->size - 1)
      // only left child
      idx1 = idx_left;
    else {
      if (h->heap[idx_left]->time < h->heap[idx_right]->time)
	idx1 = idx_left;
      else
	idx1 = idx_right;
    }
    if (h->heap[idx]->time > h->heap[idx1]->time) {
      swap_events(h, idx, idx1);
      idx = idx1;
    } else { 
      return;
    }
  } 
}
        
void printEventHeap(EventHeap *h)
{
  int i;

  printf("   (%d/%d)\n", h->size, h->max_size);
  printf("   ");

  for (i = 0; i < h->size; i++) {
    Event *ev =  h->heap[i];
    printf("[%p/", ev);
    printf("%d/", ev->time);
    printf("%d]", ev->cancel);
  }
  printf("\n");
}

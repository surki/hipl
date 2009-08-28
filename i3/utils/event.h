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

#ifndef INCL_EVENTS
#define INCL_EVENTS

/* stg: under cygwin, _WIN32 can be defined if win32api header files get included */
#if defined(_WIN32)
    #include "fwint.h"
#else
    #include <inttypes.h>
#endif

typedef struct _event {
  uint64_t  time;
  uint16_t  cancel;   /* specify whether the timeout is canceled */
  void     (*fun)();  /* function to be called when the evnt occurs */
  void      *params;  /* address to the parameters to be passed to fun */
} Event;

typedef struct _eventHeap {
  Event **heap;
  unsigned int size;
  unsigned int max_size;
} EventHeap;


#define isEventCanceled(ev) (ev->cancel)

/* function prototypes */
Event *newEvent(void (*fun)(), void *params, uint64_t time);
Event **newEventArray(int max_heap_size);
void insertEvent(EventHeap *h, Event *ev);
Event *getNextEvent(EventHeap *h);
void removeNextEvent(EventHeap *h);
void printEventHeap(EventHeap *h);

#endif

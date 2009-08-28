#ifndef HIP_TIMER_H
#define HIP_TIMER_H

#if 0
#ifdef __KERNEL__

/* XX TODO: hipmod */

#else
#  include <sys/time.h>
#  include <time.h>

typedef struct timeval hip_timer_t;

#define HIP_START_TIMER(timer) do {\
      do_gettimeofday(&timer);\
 } while(0)

#define HIP_STOP_TIMER(timer, msg) do {\
      hip_timer_t hip_stop_timer; \
      hip_timer_t hip_timer_result; \
      do_gettimeofday(&hip_stop_timer);\
      hip_timeval_diff(&timer, &hip_stop_timer, &hip_timer_result);\
      HIP_DEBUG("%s: %ld usec\n", msg, \
              hip_timer_result.tv_usec + hip_timer_result.tv_sec * 1000000);\
 } while(0)

#endif /* !__KERNEL__ */
#endif
#endif /* HIP_TIMER_H  */

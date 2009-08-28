#ifndef __KERNEL__
#  define __KERNEL__
#endif

#ifndef MODULE
#  define MODULE
#endif

#include <linux/kernel.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <linux/linkage.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/sysctl.h>

#include <net/hip.h>


/*

 Add to net/netsyms.c:

 extern struct hip_local_hi local_his[HIP_MAX_HI];
 EXPORT_SYMBOL(local_his); 

 hip.c:
 static struct hip_local_hi local_his[HIP_MAX_HI];
 ->
 struct hip_local_hi local_his[HIP_MAX_HI];


 gcc -c -Wall -I/lib/modules/`uname -r`/build/include hiplisthi.c

 TODO:
 - byte order printk
 - /proc support

*/

MODULE_AUTHOR("Mika");
MODULE_DESCRIPTION("HIP test module, dump local HI table");
MODULE_LICENSE("GPL");

extern struct hip_local_hi local_his[HIP_MAX_HI];

int init_module() {
  int i = 0;
  struct hip_local_hi *hi;

  printk(KERN_DEBUG "HIP: Local HI table (HIP_MAX_HI=%d):\n", HIP_MAX_HI);
  /* printk(KERN_DEBUG "local_his addr=%p\n", local_his); */

  for(; i < HIP_MAX_HI; i++) {
    hi = &local_his[i];
    printk(KERN_DEBUG "%d:anon=%d inuse=%d %08x-%08x-%08x-%08x\n",
	   i, hi->anonymous, hi->inuse,
	   hi->lhit.s6_addr32[0], hi->lhit.s6_addr32[1],
	   hi->lhit.s6_addr32[2], hi->lhit.s6_addr32[3]);
  }

  return 0;
}

void cleanup_module() {
  printk("HIP: cleanup_module\n");
}

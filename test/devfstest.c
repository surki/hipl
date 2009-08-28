#ifndef __KERNEL__
#  define __KERNEL__
#endif

#ifndef MODULE
#  define MODULE
#endif

#if CONFIG_MODVERSIONS==1
#define MODVERSIONS
#include <linux/modversions.h>
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

#include <linux/devfs_fs_kernel.h>

/*

 gcc -c -Wall -I/lib/modules/`uname -r`/build/include devfstest.c

*/

MODULE_AUTHOR("Mika");
MODULE_DESCRIPTION("devfs test module");
MODULE_LICENSE("GPL");

static devfs_handle_t devfs_hip_root;
static devfs_handle_t devfs_hip_dev;

/* owner */
loff_t my_llseek(struct file *file, loff_t off, int whence) {
  printk(KERN_DEBUG "HIP: my_llseek\n");
  return(-ENOSYS);
}

ssize_t my_read(struct file *file, char *buf, size_t count, loff_t *offset) {
  printk(KERN_DEBUG "HIP: my_read\n");
  printk(KERN_DEBUG "my_read %p %p\n", my_read, file->f_op->read);
  return(0);
  return(-ENOSYS);
}

ssize_t my_write(struct file *file, const char *buf, size_t size, loff_t *offset) {
  printk(KERN_DEBUG "HIP: my_write\n");
  return(-ENOSYS);
}

int my_readdir(struct file *file, void *p, filldir_t t) {
  printk(KERN_DEBUG "HIP: my_readdir\n");
  return(-ENOSYS);
}

unsigned int my_poll(struct file *file, struct poll_table_struct *pt) {
  printk(KERN_DEBUG "HIP: my_poll\n");
  return(-ENOSYS);
}

int my_ioctl(struct inode *inode, struct file *file, unsigned int a, unsigned long b) {
  printk(KERN_DEBUG "HIP: my_ioctl\n");
  return(-ENOSYS);
}
int my_mmap(struct file *file, struct vm_area_struct *vm) {
  printk(KERN_DEBUG "HIP: my_mmap\n");
  return(-ENOSYS);
}

int my_open(struct inode *inode, struct file *file) {
  int major = MAJOR(inode->i_rdev);
  int minor = MINOR(inode->i_rdev);

  printk(KERN_DEBUG "HIP: my_open major=%d minor=%d\n", major, minor);
  printk(KERN_DEBUG "my_open %p %p\n", my_open, inode->i_fop->open);

  return(-ENOSYS);
}

int my_flush(struct file *file) {
  printk(KERN_DEBUG "HIP: my_flush\n");
  return(-ENOSYS);
}

int my_release(struct inode *inode, struct file *file) {
  int major = MAJOR(inode->i_rdev);
  int minor = MINOR(inode->i_rdev);

  printk(KERN_DEBUG "HIP: my_release major=%d minor=%d\n", major, minor);
  return(-ENOSYS);
}

int my_fsync(struct file *file, struct dentry *dentry, int datasync) {
  printk(KERN_DEBUG "HIP: my_fsync\n");
  return(-ENOSYS);
}

int my_fasync(int a, struct file *file, int b) {
  printk(KERN_DEBUG "HIP: my_fasync\n");
  return(-ENOSYS);
}

int my_lock(struct file *file, int a, struct file_lock *lock) {
  printk(KERN_DEBUG "HIP: my_lock\n");
  return(-ENOSYS);
}

ssize_t my_readv(struct file *file, const struct iovec *iv, unsigned long a, loff_t *offset) {
  printk(KERN_DEBUG "HIP: my_readv\n");
  return(-ENOSYS);
}

ssize_t my_writev(struct file *file, const struct iovec *iv, unsigned long a, loff_t *offset) {
  printk(KERN_DEBUG "HIP: my_writev\n");
  return(-ENOSYS);
}

ssize_t my_sendpage(struct file *file, struct page *page, int a, size_t b, loff_t *offst, int c) {
  printk(KERN_DEBUG "HIP: my_sendpage\n");
  return(-ENOSYS);
}

unsigned long my_get_unmapped_area(struct file *file, unsigned long a, unsigned long b, unsigned long c, unsigned long d) {
  printk(KERN_DEBUG "HIP: my_get_unmapped_area\n");
  return(-ENOSYS);
}



/* ei saa olla static ? LDD sivu 57 */
struct file_operations file_ops = {
  NULL,
  my_llseek, NULL/*my_read*/, my_write, my_readdir, my_poll,
  my_ioctl, my_mmap, /*NULL*/ my_open, my_flush, my_release,
  my_fsync, my_fasync, my_lock, my_readv, my_writev,
  my_sendpage, my_get_unmapped_area };

int init_module() {

  printk(KERN_DEBUG "HIP: init_module\n");

  SET_MODULE_OWNER(&file_ops);

  devfs_hip_root = devfs_mk_dir(NULL, "hip", NULL);
  if (!devfs_hip_root) {
    printk(KERN_DEBUG "HIP: devfs_mk_dir failed\n");
    return(-EBUSY);
  }
  printk(KERN_DEBUG "HIP: devfs_mk_dir ok\n");


  /**
   *devfs_register - Register a device entry.
   *@dir: The handle to the parent devfs directory entry. If this is %NULL the
   *new name is relative to the root of the devfs.
   *@name: The name of the entry.
   *@flags: A set of bitwise-ORed flags (DEVFS_FL_*).
   *@major: The major number. Not needed for regular files.
   *@minor: The minor number. Not needed for regular files.
   *@mode: The default file mode.
   *@ops: The &file_operations or &block_device_operations structure.
   *This must not be externally deallocated.
   *@info: An arbitrary pointer which will be written to the @private_data
   *field of the &file structure passed to the device driver. You can set
   *this to whatever you like, and change it once the file is opened (the next
   *file opened will not see this change).
   *
   *Returns a handle which may later be used in a call to devfs_unregister().
   *On failure %NULL is returned.
   */
  /*
  devfs_handle_t devfs_register (devfs_handle_t dir, const char *name,
				 unsigned int flags,
				 unsigned int major, unsigned int minor,
				 umode_t mode, void *ops, void *info)


*/


  devfs_hip_dev = devfs_register(devfs_hip_root, "hipsocket",
				 DEVFS_FL_NONE,
				 HIP_CHAR_MAJOR,
				 0,
				 S_IFCHR | S_IRUSR | S_IWUSR,
                                 &file_ops,
				 NULL);

  if (!devfs_hip_dev) {
    devfs_unregister(devfs_hip_root);
    printk(KERN_DEBUG "HIP: devfs_register failed\n");
    return(-EBUSY);
  }

printk(KERN_DEBUG "HIP: devfs_register ok\n");


  return 0;
}

void cleanup_module() {
  printk("HIP: cleanup_module\n");

  devfs_unregister(devfs_hip_dev);
  devfs_unregister(devfs_hip_root);
}

#include "misc_install.h"

int init_daemon()
{
	int err = 0;
        /***************************************
	 * Initialization of hip daemon: not yet considered
	 * This has to be fixed in future, according on how to identify
	 * the user space is compiled in the kernel
	 ***************************************/
	system("killall hipd");
	/* 
	 * The path has to be decided. We assume that this is run from test/ directory 
	 * in an unstable and initial version.
	 * Later on this will changed to the only command, without specifying the
	 * path, because we will insert it into $PATH
	 */
	err = system("../hipd/hipd -b");
	if (err == -1)
		printf("Please run 'make install' in top directory\n");
		
}

int install_module()
{
	
	int err;
	err = system("grep -q hipmod /proc/modules");
	if (!err){
		printf("Removing the hipmod module.\n");
		err = system("rmmod hipmod");
		if(err == -1) {
			printf("Some error occured while removing the hipmod module\n");
			return(err);
		}
	}
	
	printf("The hipmod module is being installed...\n");
	err = system("/sbin/modprobe -v hipmod");

	return err;
}

int add_hi_default(struct hip_common *msg)
{	
	/*
	  $HIPL_DIR/tools/hipconf add hi default
	  This function is in hipconftool.c and is handle_hi()
	*/
	char *opts[1];
	int err;
	opts[0] = "default";
	printf("Calling handle_hi...\n");
	err = hip_conf_handle_hi(msg, ACTION_ADD, (const char **) opts, 1, 0);
	return err;
}

int main_install(struct hip_common *msg)
{
	int err = 0;
	if (!getuid()) {
		//err = install_module(msg);
		HIP_IFEL(install_module(), -1, "Error in installing modules\n");
		/*
		  if (err) {
		  HIP_ERROR("error in installing modules\n");
		  goto out_err;
		  }
		*/
		printf("Initializing the hipd daemon...\n");
		if (init_daemon() == -1) {
			err = -1;
			goto out_err;
		}
		sleep(3);
		HIP_IFEL(add_hi_default(msg), -1, "Error in add_hi_default\n");
		//add_hi_default(msg);
				
	}
	else {
		HIP_ERROR("Installation must be done as root\n");
		err = -1;
		goto out_err;
	}

	/* hipconf new hi does not involve any messages to kernel */
	HIP_IFE((!hip_get_msg_type(msg)), -1);
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "sending msg failed\n");
out_err:
	return err;
}

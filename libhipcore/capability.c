#ifdef CONFIG_HIP_PRIVSEP
#ifdef CONFIG_HIP_ALTSEP
# include <linux/capability.h>
#else
# include <sys/capability.h>
#endif
#endif /* CONFIG_HIP_PRIVSEP */
#include <sys/prctl.h>
#include <sys/types.h>
#include <pwd.h>
#include "debug.h"
#include "ife.h"
#ifdef CONFIG_HIP_AGENT
# include "sqlitedbapi.h"
#endif

#ifdef CONFIG_HIP_PRIVSEP

#define USER_NOBODY "nobody"
#define USER_HIPD "hipd"

#endif /* CONFIG_HIP_PRIVSEP */

#ifndef CONFIG_HIP_OPENWRT
int hip_user_to_uid(char *name) {
	int uid = -1, i;

	//Added by Dmitriy
	struct passwd *pwp = NULL, pw;
	char buf[4096];

	setpwent();
	while (1) {
		i = getpwent_r(&pw, buf, sizeof(buf), &pwp);
		if (i)
			break;
		_HIP_DEBUG("%s (%d)\tHOME %s\tSHELL %s\n", pwp->pw_name,
			  pwp->pw_uid, pwp->pw_dir, pwp->pw_shell);
		if (!strcmp(pwp->pw_name, name)) {
			uid = pwp->pw_uid;
			break;
		}
	}
	endpwent();
	return uid;
}
#endif

#ifdef CONFIG_HIP_ALTSEP

#define _LINUX_CAPABILITY_VERSION_HIPL	0x19980330

/*
 * Note: this function does not go well with valgrind
 */
int hip_set_lowcapability(int run_as_sudo) {
  int err = 0;

#ifdef CONFIG_HIP_PRIVSEP
  uid_t uid;
  //struct passwd *nobody_pswd;
  //uid_t ruid,euid;
  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data; 

  header.pid=0;
  header.version = _LINUX_CAPABILITY_VERSION_HIPL;
  data.effective = data.permitted = data.inheritable = 0;

  /* openwrt code */

  HIP_IFEL(prctl(PR_SET_KEEPCAPS, 1), -1, "prctl err\n");

  HIP_DEBUG("Now PR_SET_KEEPCAPS=%d\n", prctl(PR_GET_KEEPCAPS));

#ifndef CONFIG_HIP_OPENWRT
  uid = hip_user_to_uid(USER_NOBODY);
#else
  /* todo: hardcode the uid for a suitable user for openwrt */
  uid = -1;
#endif
  HIP_IFEL((uid < 0), -1,
	   "Error while retrieving USER 'nobody' uid\n"); 

  HIP_IFEL(capget(&header, &data), -1,
	   "error while retrieving capabilities through capget()\n");

  HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
	    data.effective, data.permitted, data.inheritable);

  //ruid=nobody_pswd->pw_uid; 
  //euid=nobody_pswd->pw_uid;

  HIP_DEBUG("Before setreuid(,) UID=%d and EFF_UID=%d\n",
	    getuid(), geteuid());

  /* openwrt code */

  HIP_IFEL(setreuid(uid, uid), -1, "setruid failed\n");

  HIP_DEBUG("After setreuid(,) UID=%d and EFF_UID=%d\n",
	    getuid(), geteuid());
  HIP_IFEL(capget(&header, &data), -1,
	   "error while retrieving capabilities through 'capget()'\n");

  HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
	    data.effective,data.permitted, data.inheritable);
  HIP_DEBUG ("Going to clear all capabilities except the ones needed\n");
  data.effective = data.permitted = data.inheritable = 0;
  // for CAP_NET_RAW capability 
  data.effective |= (1 <<CAP_NET_RAW );
  data.permitted |= (1 <<CAP_NET_RAW );
  // for CAP_NET_ADMIN capability 
  data.effective |= (1 <<CAP_NET_ADMIN );
  data.permitted |= (1 <<CAP_NET_ADMIN );

  /* openwrt code */

  HIP_IFEL(capset(&header, &data), -1, 
	   "error in capset (do you have capabilities kernel module?)");

  HIP_DEBUG("UID=%d EFF_UID=%d\n", getuid(), geteuid());  
  HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
	    data.effective, data.permitted, data.inheritable);
#endif /* CONFIG_HIP_PRIVSEP */

 out_err:
  return err;

}

#else /* ! ALTSEP */

/*
 * Note: this function does not go well with valgrind
 */
int hip_set_lowcapability(int run_as_sudo) {
	int err = 0;

#ifdef CONFIG_HIP_PRIVSEP
	uid_t uid = -1;
	cap_value_t cap_list[] = {CAP_NET_RAW, CAP_NET_ADMIN };
	int ncap_list = 2; 
	cap_t cap_p = NULL;
	char *cap_s = NULL;
	char *name = NULL;

	/* @todo: does this work when you start hipd as root (without sudo) */
         
	if (run_as_sudo) {
 		HIP_IFEL(!(name = getenv("SUDO_USER")), -1,
			 "Failed to determine current username\n");
	} else {
		/* Check if user "hipd" exists if it does use it
		   otherwise use "nobody" */
		if (hip_user_to_uid(USER_HIPD) >= 0)
			name = USER_HIPD;
		else if (hip_user_to_uid(USER_NOBODY) >= 0)
			name = USER_NOBODY;
		else
			HIP_IFEL(1, -1, "System does not have nobody account\n");
	}

	HIP_IFEL(prctl(PR_SET_KEEPCAPS, 1), -1, "prctl err\n");

	HIP_DEBUG("Now PR_SET_KEEPCAPS=%d\n", prctl(PR_GET_KEEPCAPS));

	uid = hip_user_to_uid(name);
        HIP_IFEL((uid < 0), -1,
                 "Error while retrieving USER '%s' uid\n", name);

	HIP_IFEL(!(cap_p = cap_get_proc()), -1,
		 "Error getting capabilities\n");
	HIP_DEBUG("cap_p %s\n", cap_s = cap_to_text(cap_p, NULL));
	/* It would be better to use #if DEBUG */
	if (cap_s != NULL) {
		cap_free(cap_s);
		cap_s = NULL;
	}

	HIP_DEBUG("Before setreuid UID=%d and EFF_UID=%d\n",
		  getuid(), geteuid());

	HIP_IFEL(setreuid(uid,uid), -1, "setruid failed\n");

	HIP_DEBUG("After setreuid UID=%d and EFF_UID=%d\n",
		  getuid(), geteuid());

	HIP_DEBUG ("Going to clear all capabilities except the ones needed\n");
	HIP_IFEL(cap_clear(cap_p)<0, -1, "Error clearing capabilities\n");

	HIP_IFEL(cap_set_flag(cap_p, CAP_EFFECTIVE, ncap_list, cap_list, CAP_SET)<0, 
		 -1, "Error setting capability flags\n");
	HIP_IFEL(cap_set_flag(cap_p, CAP_PERMITTED, ncap_list, cap_list, CAP_SET)<0, 
		 -1, "Error setting capability flags\n");
	HIP_IFEL(cap_set_proc(cap_p)<0, -1, "Error modifying capabilities\n");
	HIP_DEBUG("UID=%d EFF_UID=%d\n", getuid(), geteuid());	
	HIP_DEBUG("cap_p %s\n", cap_s = cap_to_text(cap_p, NULL));
	/* It would be better to use #if DEBUG */
	if (cap_s != NULL) {
		cap_free(cap_s);
		cap_s = NULL;
	}

out_err:
	cap_free(cap_p);

#endif /* CONFIG_HIP_PRIVSEP */

	return err;

}
#endif

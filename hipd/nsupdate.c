/*
 * Execute nsupdate.pl with HIT and IP addresses in environment variables
 * Oleg Ponomarev, Helsinki Institute for Information Technology
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/resource.h> // for getrlimit

#include "hidb.h"

#include "nsupdate.h"

int hip_nsupdate_status = 0;

void hip_set_nsupdate_status(int status) {
  hip_nsupdate_status = status;
}

int hip_get_nsupdate_status(void) {
  return hip_nsupdate_status;
}

/*
 * returns string "name=value"
 * remember to free()
 */
char *make_env(char *name, char *value)
{
 if ((name==NULL) || (value==NULL))
	return NULL;

 char *result = malloc(strlen(name) + 1 + strlen(value) + 1); // name,'=',value,0

 if (result == NULL) {
	HIP_PERROR("malloc");
	return NULL;
 }

 strcpy(result, name);
 strcat(result, "=");
 strcat(result, value);
 return result;
}

/*
 * Handle child exits to avoid zombies
 */
static void sig_chld (int signo)
{
	pid_t child_pid;
	int child_status; // child exit code
	child_pid = waitpid (0, &child_status, WNOHANG);
	HIP_DEBUG("child pid: %d, status: %d\n", child_pid, child_status);
}

#if 0 /* See bug id 805  */
/*
 * Close file descriptors except for the standard output and the standard error
 */
int close_all_fds_except_stdout_and_stderr()
{
	/* get maximum file descriptor number that can be opened */
        struct rlimit rlim;
        if (getrlimit(RLIMIT_NOFILE, &rlim)!=0) {
                HIP_PERROR("getrlimit");
		return ERR;
	}

	int fd; // no C99 :(
	for (fd = 0; fd < rlim.rlim_cur; fd++)
		switch (fd) {
			case STDOUT_FILENO: break;
			case STDERR_FILENO: break;
			default: close(fd);
		}

	return OK;
}
#endif

/*
 * This function converts the netdev_address structure src into
 * a character string, which is copied to a character buffer dst, which is cnt bytes long.
 */
const char *netdev_address_to_str(struct netdev_address *src, char *dst, socklen_t cnt)
{
	struct sockaddr *tmp_sockaddr_ptr = (struct sockaddr*) &(src->addr);
	struct sockaddr_in *tmp_sockaddr_in_ptr = (struct sockaddr_in*) tmp_sockaddr_ptr;
	struct sockaddr_in6 *tmp_sockaddr_in6_ptr = (struct sockaddr_in6*) tmp_sockaddr_ptr;

	struct in_addr tmp_in_addr;
	struct in6_addr *tmp_in6_addr_ptr = NULL;

	void *inet_ntop_src = NULL;
	int af = tmp_sockaddr_ptr->sa_family ; // might be changed because of ip4->ip6 mapping

	switch (af) {
		case AF_INET:
			inet_ntop_src = & (tmp_sockaddr_in_ptr->sin_addr);
			break;

		case AF_INET6:
			tmp_in6_addr_ptr = & (tmp_sockaddr_in6_ptr->sin6_addr);
			if (IN6_IS_ADDR_V4MAPPED(tmp_in6_addr_ptr)) {
				IPV6_TO_IPV4_MAP(tmp_in6_addr_ptr, &tmp_in_addr)
				af = AF_INET;
				inet_ntop_src = &tmp_in_addr;
			} else
				inet_ntop_src = tmp_in6_addr_ptr;
			break;
	}
	
	return inet_ntop(af, inet_ntop_src, dst, cnt);
}

/*
 * Execute nsupdate.pl with IP and HIT given as environment variables
 */
int run_nsupdate(char *ips, char *hit, int start)
{
	struct sigaction act;
	pid_t child_pid;

	HIP_DEBUG("Updating dns records...\n");

	act.sa_handler = sig_chld;

	/* We don't want to block any other signals */
	sigemptyset(&act.sa_mask);

	/*
	 * We're only interested in children that have terminated, not ones
	 * which have been stopped (eg user pressing control-Z at terminal)
	 */
	act.sa_flags = SA_NOCLDSTOP | SA_RESTART;

	/* Make the handler effective */
	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		HIP_PERROR("sigaction");
        	return ERR;
	}

	/* Let us fork to execute nsupdate as a separate process */
	child_pid=fork();

	if (child_pid<0) {
		HIP_PERROR("fork");
		return ERR;
	}
	else if (child_pid == 0) {// CHILD
		char start_str[2];
#if 0
		/* Close open sockets since FD_CLOEXEC was not used */
		close_all_fds_except_stdout_and_stderr();
#endif

		snprintf(start_str, sizeof(start_str), "%i", start);

		char *env_ips = make_env(VAR_IPS, ips);
		char *env_hit = make_env(VAR_HIT, hit);
		char *env_start = make_env(VAR_START, start_str);

		char *cmd[] = { NSUPDATE_ARG0, NULL };
		char *env[] = { env_ips, env_hit, env_start, NULL };

		HIP_DEBUG("Executing %s with %s; %s; %s\n", NSUPDATE_PL, env_hit, env_ips, env_start);
		execve (NSUPDATE_PL, cmd, env);

		/* Executed only if error */
		HIP_PERROR("execve");
		exit(1); // just in case
	}
	else {// PARENT
		/* We execute waitpid in SIGCHLD handler */
		return OK;
	}
}


/*
 * Called from hip_for_each_hi
 */
int run_nsupdate_for_hit (struct hip_host_id_entry *entry, void *opaq)
{
	int start = 0;
	char ip_str[40]; // buffer for one IP address
	char ips_str[1024] = ""; // list of IP addresses
  	hip_list_t *item, *tmp_hip_list_t;
  	int i;
	char hit[INET6_ADDRSTRLEN + 2];

	if (opaq != NULL)
		start = * (int *) opaq;

	HIP_DEBUG("run_nsupdate_for_hit (start=%d)\n", start);

	hip_convert_hit_to_str(&entry->lhi.hit,NULL, hit);

	/* make space-separated list of IP addresses in ips_str */
  	list_for_each_safe(item, tmp_hip_list_t, addresses, i) {
		struct netdev_address *n = list_entry(item);

		if (netdev_address_to_str(n, ip_str, sizeof(ip_str))==NULL)
			HIP_PERROR("netdev_address_to_str");
		else {
			if (ips_str[0]!=0) // not empty
				strncat(ips_str, " ", sizeof(ips_str)-strlen(ips_str));
			strncat(ips_str, ip_str, sizeof(ips_str)-strlen(ips_str));
		}
	}

	run_nsupdate(ips_str, hit, start);

	return 0;
}

/*
 * Update records for all hits. The host should be able to send packets to HITs to modify the DNS records
 */ 
int nsupdate(const int start)
{
	HIP_DEBUG("Updating dns records...\n");
	hip_for_each_hi(run_nsupdate_for_hit, (void *) &start);
	return OK;
}


/*
 * Just calls run_nsupdate with some values for debugging
 */
#if 0
int main(void)
{
	int ret;

	ret = run_nsupdate("193.167.187.3 193.167.187.5","def",1);
	HIP_DEBUG("ret=%d\n", ret);
	sleep(1);

	/* wait for children */	
	while (1) {
		sleep(1);
	}
	return 0;
}
#endif

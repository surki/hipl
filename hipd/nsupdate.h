#ifndef HIP_NSUPDATE_H
#define HIP_NSUPDATE_H

void hip_set_nsupdate_status(int status);
int hip_get_nsupdate_status(void);
int run_nsupdate_for_hit (struct hip_host_id_entry *entry, void *opaq);
int nsupdate(const int start);

#define VAR_IPS "HIPD_IPS"
#define VAR_HIT "HIPD_HIT"
#define VAR_START "HIPD_START"
#define NSUPDATE_PL HIPL_DEFAULT_PREFIX "/sbin/" "nsupdate.pl"
#define NSUPDATE_ARG0 "nsupdate.pl"
#define ERR -1


#endif /* HIP_NSUPDATE_H */

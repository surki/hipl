#ifndef I3_CLIENT_PARAMS_H
#define I3_CLIENT_PARAMS_H

#define MIN_PORT_NUM 10000
#define MAX_PORT_NUM 11000
#define DEFAULT_SRV_LIST_FILE "srv_list.cfg"

/** How often should we check if the Proxy's IP address has changed?  (time in seconds) */
#define ADDR_CHECK_PERIOD    2  /* in seconds */

#define SERVER_UPDATE_PERIOD 30 /* in seconds */

/** How often should a trigger be refreshed?
  * This value should always be a little less than
  * the trigger refresh value at the i3 server.
  */
#define TRIGGER_REFRESH_PERIOD	20
#define ACK_TIMEOUT		2
#define ID_REFRESH_PERIOD	10
#define MAX_NUM_TRIG_RETRIES	6
#define MAX_NUM_ID_RETRIES	3


#endif

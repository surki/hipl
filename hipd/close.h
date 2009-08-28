#ifndef HIP_CLOSE_H
#define HIP_CLOSE_H

#include "hadb.h"
#include "misc.h"
#include "hadb.h"
#include "hidb.h"
#include "builder.h"
#include "cookie.h"
#include "builder.h"
#include "output.h"
#include "debug.h"
#include "keymat.h"
#include "crypto.h"
#include "misc.h"
#include "pk.h"

int hip_send_close(struct hip_common *msg, int delete_ha_info);
int hip_xmit_close(hip_ha_t *entry, void *opaque);
int hip_handle_close(struct hip_common *close, hip_ha_t *entry);
int hip_handle_close_ack(struct hip_common *close_ack, hip_ha_t *entry);

#endif /* HIP_CLOSE_H */

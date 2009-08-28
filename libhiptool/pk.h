#ifndef HIP_PK_H
#define HIP_PK_H

#include "hidb.h"
#include "crypto.h"

int hip_dsa_verify(DSA *peer_pub, struct hip_common *msg);
int hip_dsa_sign(DSA *dsa, struct hip_common *msg);
int hip_rsa_verify(RSA *peer_pub, struct hip_common *msg);
int hip_rsa_sign(RSA *rsa, struct hip_common *msg);

#endif /* HIP_PK_H */

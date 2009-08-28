#ifndef HIPSETUPNEW_H
#define HIPSETUPNEW_H

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include "hipconftool.h"
//#include "conntest.h"
#include "debug.h"
#include "crypto.h"

#include "misc_install.h"

#define DEFAULT_PORT 1111

void usage_f();
int install_module();
void init_deamon();
int add_hi_default(struct hip_common *msg);


#endif /*HIPSETUPNEW_H*/

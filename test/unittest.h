#ifndef HIP_UNIT_TEST

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <asm/errno.h>

#include "builder.h"
#include "unit.h"
#include "debug.h"

#define HIP_UNIT_ERR_LOG_MSG_MAX_LEN 200

#define TEST_SPACE         0
#define TEST_SUITE         1
#define TEST_CASE          2
#define TEST_TYPE_MAX      3

#define ERR_MSG_MAX_LEN    500
#define ARG_NUMBER         TEST_TYPE_MAX + 1  /* 1 = executable name */

extern struct hip_unit_test_suite unit_test_suite_kernel;
struct hip_unit_test_suite_list unit_test_suite_list_userspace;

#endif /* HIP_UNIT_TEST */

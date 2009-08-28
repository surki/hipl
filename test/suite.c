/*
 * HIPL userspace unit tests.
 *
 * USAGE:
 * - How to add a new test suite in the userspace:
 *   - Add a new struct hip_unit_test_suite.
 *   - Insert the name of the struct into unit_test_suite_list_userspace
 *     in this file.
 *   - Increase the counter in unit_test_suite_list_userspace by one.
 * - How to add a new test case in the userspace:
 *   - Insert a new HIP_UNIT_TEST_CASE(name) macro before the test suite in
 *     which the test case belongs to.
 *   - Insert the name of the macro into the test suite.
 *   - Increase the counter in the test suite by one. An empty test suite has
 *     0 as the counter value.
 * - How to add a new test into a test case:
 *   - Insert a HIP_UNIT_ASSERT(value) macro call into the test case.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "crypto.h"
#include "unit.h"
#include "hipconftool.h"

extern uint16_t suiteid, caseid;

/*************************** builder test suite ****************************/

HIP_UNIT_TEST_CASE(test_hip_user_null_op) {
  int err = 0;
  void *input_msg;

  input_msg = malloc(HIP_MAX_PACKET);
  hip_msg_init(input_msg);
  HIP_UNIT_ASSERT(input_msg);
  err = hip_build_user_hdr(input_msg, SO_HIP_NULL_OP, 0);
  HIP_UNIT_ASSERT(!err);

  free(input_msg);
}

struct hip_unit_test_suite unit_test_suite_builder = {
  1,
  {
    test_hip_user_null_op
  }
};

/************************** hipconf test suite *******************************/

HIP_UNIT_TEST_CASE(test_add_default_hi) {
  void *msg;
  int err = 0;
  char *opts[1];
  msg = malloc(HIP_MAX_PACKET);
  HIP_UNIT_ASSERT(msg);
  hip_msg_init(msg);

  opts[1] = "default";
  err = hip_conf_handle_hi(msg, ACTION_ADD, (const char **) opts, 1);
  HIP_UNIT_ASSERT(!err);
}


struct hip_unit_test_suite unit_test_suite_hipconf = {
  1,
  {
    test_add_default_hi
  }
};

/*************************** test suite internal  ****************************/

HIP_UNIT_TEST_CASE(test_internal) {
  int i = 1;
  HIP_UNIT_ASSERT(i);
}

/*
 * Test cases for testing the unit test framework itself.
 *
 */
struct hip_unit_test_suite unit_test_suite_internal = {
  1,
  {
    test_internal
  }
};

/*********************** Test suite kernel **********************************/

/*
 * Wrapper for executing test cases in the kernel. Currently the result of the
 * test cases in the kernel have to be read from the logfiles. This will be
 * changed later on when the hipconf interface with kernel supports also
 * messages back from kernel. -miika
 */
HIP_UNIT_TEST_CASE(test_kernel) {
    int err = 0;
    struct hip_common *msg;

    msg = malloc(HIP_MAX_PACKET);
    HIP_UNIT_ASSERT(msg);
    hip_msg_init(msg);
    
    err = hip_build_user_hdr(msg, SO_HIP_UNIT_TEST, 0);
    HIP_UNIT_ASSERT(!err);

    err = hip_build_param_unit_test(msg, suiteid, caseid);
    HIP_UNIT_ASSERT(!err);

    err = hip_send_daemon_info(msg);
    HIP_UNIT_ASSERT(!err);
    HIP_UNIT_ASSERT(!hip_get_msg_err(msg));
}

/*
 * Test case wrapper for executing test in the kernel. Do not modify this.
 *
 */
struct hip_unit_test_suite unit_test_suite_kernel = {
  1,
  {
    test_kernel
  }
};

/*************************** All Test Suites ********************************/

/*
 * All test suites in userspace. Insert new test suites here.
 * KEEP THIS AS THE LAST ONE IN THIS FILE.
 */
struct hip_unit_test_suite_list unit_test_suite_list_userspace = {
  4,
  {
    &unit_test_suite_internal,
    &unit_test_suite_hipconf,
    &unit_test_suite_builder
  }
};



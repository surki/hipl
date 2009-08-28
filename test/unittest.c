/*
 * Unit testing command for HIPL userspace and kernel functionality.
 *
 * ABOUT:
 * - Command line usage will be displayed by executing the command without
 *   any parameters.
 * - The test results and errors will be displayed as a summary after executing
 *   the test cases.
 * - There are some limitations in this command due to limitations in the
 *   kernel-userspace communication mechanism. If there is one or more errors
 *   in the kernel, they will show up as one single error on the terminal and
 *   kernel test error logs have to looked up from the /var/log files.
 * - A short explanation of terms used:
 *   - Test space describes that whether the tests will be executed in
 *     userspace or kernel.
 *   - Test suite is a collection of related test cases.
 *   - Test case is a function that has multiple test assertions to check
 *     the validity of other functions.
 * - See hipl/test/suite.c for instructions on adding new test suites and cases
 *   into userspace. See hipl/linux/net/ipv6/hip/test.c for instruction on
 *   adding tests in the kernelspace.
 * 
 * TODO
 * - xx
 *
 */

#include "unittest.h"

char *unittest_usage = "unittest <testspaceid> <testsuiteid> <testcaseid>\n"
                       "  where <*id> = number [1..n] or 'all'\n"
                       "shorthand for executing all tests: unittest all\n";

/* Kernel test are executed using a unit test case which needs the
   test suite id and case id so that the kernel module can execute
   correct test suites and cases. This is problem because test cases
   do accept any parameters. but it can be bypassed by using global
   variables. Note that the userspace test cases do not need these
   variables. */
uint16_t suiteid = 0, caseid = 0;

/*
 * Wrapper for executing the test suites in kernel. Do not modify this!
 */
struct hip_unit_test_suite_list unit_test_suite_list_kernel = {
  1,
  {
    &unit_test_suite_kernel
  }
};

/*
 * This structure contains a list of all test suite lists. Do not modify this!
 */
struct hip_unit_test_space unit_test_space = {
  2,
  {
    &unit_test_suite_list_userspace,
    &unit_test_suite_list_kernel
  }
};

/*
 * execute the given the test cases in the given test suite in the given
 * testspace
 *
 * argc: the number of arguments to the unit test command line tool
 * argv: the command line arguments in an array of pointers; the name or the
 *       program, testspace id, testsuite id and testcase id
 *
 * All "id" arguments are given as numbers. The numbers can be mapped to
 * symbolic actions from the source file only. Id "0" or the string "all"
 * means that all entries from id should be selected.
 *
 * A shorthand for running all of the test cases is "unittest all". It is
 * equivalent to "unittest all all all".
 *
 * Returns 0 if no errors were found during the executions of test cases.
 * Otherwise returns the number of errors found.
 *
 */
int main(int argc, char *argv[]) {
  int i;
  uint16_t err = 0;
  uint16_t test_type[TEST_TYPE_MAX];
  char *testsuite_name, *testcase_name;
  char err_log[ERR_MSG_MAX_LEN] = "";

  /* Default value is zero (= execute "all"). This is useful in the case
     the arguments contain just "all" or "all all". */
  test_type[TEST_SPACE] = 0;
  test_type[TEST_SUITE] = 0;
  test_type[TEST_CASE] = 0;

  if (argc < 2 || argc > ARG_NUMBER) {
    err = -EINVAL;
    HIP_ERROR("Expected %d args, got %d\n", ARG_NUMBER - 1, argc);
    HIP_ERROR("usage: %s\n", unittest_usage);
    goto out;
  }

  /* Map symbolic arguments to numbers. */ 
  for (i = 0; i < argc - 1; i++) {
    test_type[i] = (!strcmp(argv[i + 1], "all")) ?
      0 : (uint16_t) atoi(argv[i + 1]);
  }
  
  HIP_DEBUG("Executing testspace=%d testsuite=%d testcase=%d\n",
	    test_type[TEST_SPACE],
	    test_type[TEST_SUITE],
	    test_type[TEST_CASE]);

  /* Kernel test are executed using a unit test case which needs the
     test suite id and case id so that the kernel module can execute
     correct test suites and cases. This is problem because test cases
     do accept any parameters. but it can be bypassed by using global
     variables. Note that the userspace test cases do not need these
     variables. */
  suiteid = test_type[TEST_SUITE];
  caseid = test_type[TEST_CASE];

  err = hip_run_unit_test_space(&unit_test_space, test_type[TEST_SPACE],
				test_type[TEST_SUITE], test_type[TEST_CASE],
				err_log, ERR_MSG_MAX_LEN);

  if (err)
    HIP_ERROR("\n===Unit Test Summary===\nTotal %d errors:\n%s\n",
	      err, err_log);
  else
    HIP_INFO("\n===Unit Test Summary===\nAll tests passed, no errors!\n");

 out:

  return err;
}


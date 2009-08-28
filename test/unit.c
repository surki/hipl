/*
 * HIPL unit test suite implementation. The actual unit test suite functions
 * are in separate file.
 *
 * NOTE: This file is shared between userspace and kernel!
 *
 * Licence: GNU/GPL
 * Authors:
 * - Miika Komu <miika@iki.fi>
 *
 */

#include "unit.h"

/**
 * hip_run_unit_test_case - run a single or multiple HIP unit test cases.
 *
 * @param list pointer to a test suite list
 * @param suiteid test suite number (zero = all suites in the list)
 * @param caseid test case nuber (zero = all cases in the suite)
 * @param err_log a string where the error log is stored
 * @param err_max the capacity of the string
 *
 * @return the number of errors found from the runned testcases. Error
 * log of the test cases will be recorded into err_log.
 *
 */
uint16_t hip_run_unit_test_case(struct hip_unit_test_suite_list *list,
				uint16_t suiteid, uint16_t caseid,
				void *err_log, size_t err_max)
{
	size_t err_len = 0, space_left = 0;
	void *err_index = err_log;
	uint16_t err = 0;
	/* Suiteid and caseid are indexed in the range [1..n] because zero is
	   reserved for executing all tests. However, xx_suite and xx_case
	   variables below are indexed in the range [0..n-1] for direct
	   access into the corresponding arrays */
	uint16_t first_suite, current_suite, last_suite;
	uint16_t first_case, current_case, last_case;

	first_suite = (suiteid == 0) ? 0 : suiteid - 1;
	last_suite = (suiteid == 0) ?
		list->nbr - 1 : suiteid - 1;
	first_case = (caseid == 0) ? 0 : caseid - 1;

	_HIP_DEBUG("for1 index: %d-%d\n", suiteid, first_suite, last_suite);

	if (last_suite > list->nbr - 1) {
		HIP_ERROR("Trying to access illegal unit test suite (%d/%d)\n",
			  last_suite, list->nbr - 1);
		err = 1;
		goto out;
	}

        /* make sure that the string will null padded even if nothing
	   will actually be written to err_log in the call to test suite */
	if (err_max > 0)
		((char *)err_log)[0] = '\0';

	for (current_suite = first_suite; current_suite <= last_suite;
	     current_suite++) {
		last_case = (caseid == 0) ?
			list->test_suite[current_suite]->nbr - 1 :
		  caseid - 1;
		if (last_case >
		    list->test_suite[current_suite]->nbr - 1) {
			HIP_ERROR("Trying to access illegal test case (%d/%d)\n", last_case, list->test_suite[current_suite]->nbr - 1);
			err += 1;
			goto out;
		}

		for (current_case = first_case; current_case <= last_case;
		     current_case++) {
		  _HIP_DEBUG("for2 index: %d-%d\n", first_case, last_case);
			space_left = ((void *)err_log) - err_index + err_max;
			/* if no space left - ignore error messages,
			   just count errors */
			if (space_left <= 0)
				err_len = 0;
			list->test_suite[current_suite]->test_case[current_case]
				(&err, err_index, &err_len, space_left);

			/* glibc versions prior to 2.0.6 may return -1
			   if truncated */
			if (err_len < 0)
				space_left = 0;
			err_index += err_len;
		}
	}
 out:
	return err;

}

/**
 * hip_run_unit_test_space - select and run tests in the unit test space
 * @param unit_space pointer to an unit space structure
 * @param spaceid test space id (zero = all spaces)
 * @param suiteid test suite number (zero = all suites)
 * @param caseid test case nuber (zero = all cases)
 * @param err_log a string where the error log is stored
 * @param err_max the capacity of the string
 *
 * This is only needed in the userspace for selecting and launching the
 * test cases in the correct testspace (kernelspace or userspace).
 *
 * @return the number of errors occurred when the test cases were run.
 */
uint16_t hip_run_unit_test_space(struct hip_unit_test_space *unit_space,
				 uint16_t spaceid, uint16_t suiteid,
				 uint16_t caseid, void *err_log,
				 size_t err_max)
{
	/* Spaceid is indexed in the range [1..n] because zero is reserved for
	   executing in all spaces. However, xx_space variables below are
	   indexed in the range [0..n-1] for direct access into the
	   corresponding array. */
	uint16_t first_space, current_space, last_space;
	size_t err_len = 0, space_left = 0;
	void *err_index = err_log;
	uint16_t err = 0;

	first_space = (spaceid == 0) ? 0 : spaceid - 1;
	last_space = (spaceid == 0) ?
		unit_space->nbr - 1 : spaceid - 1;

	if (last_space > unit_space->nbr - 1) {
		HIP_ERROR("Trying to access illegal unit test spaceid (%d/%d).", last_space, unit_space->nbr - 1);
		err = 1;
		goto out;
	}

	/* make sure that the string will null padded even if nothing
	   will actually be written to err_log in the call to test suite */
	if (err_max > 0)
		((char *)err_log)[0] = '\0';

	_HIP_DEBUG("for index: %d-%d\n", first_space, last_space);

	for (current_space = first_space; current_space <= last_space;
	     current_space++) {
		space_left = ((void *)err_log) - err_index + err_max;
		/* if no space - ignore error messages, just count errors */
		if (space_left <= 0)
			err_len = 0;
		err += hip_run_unit_test_case(unit_space->test_suite_list[current_space], suiteid, caseid, err_index, space_left);
		err_len = strlen(err_index);
		err_index += err_len;
	}

 out:
	return err;
}

/*
 * This software is a copyright (c) of Carnegie Mellon University, 2002.
 *           
 * Permission to reproduce, use and prepare derivative works of this
 * software for use is granted provided the copyright and "No Warranty"
 * statements are included with all reproductions and derivative works.
 * This software may also be redistributed provided that the copyright
 * and "No Warranty" statements are included in all redistributions.
 *           
 * NO WARRANTY. THIS SOFTWARE IS FURNISHED ON AN "AS IS" BASIS.  CARNEGIE
 * MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
 * IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
 * FITNESS FOR PURPOSE OR MERCHANABILITY, EXCLUSIVITY OF RESULTS OR
 * RESULTS OBTAINED FROM USE OF THIS SOFTWARE. CARNEGIE MELLON UNIVERSITY
 * DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM
 * PATENT, TRADEMARK OR COPYRIGHT INFRINGEMENT.
 *
 * Carnegie Mellon encourages (but does not require) users of this
 * software to return any improvements or extensions that they make, and
 * to grant Carnegie Mellon the rights to redistribute these changes
 * without encumbrance.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#define TINY 1.0e-10
#define NMAX 500000

/*
  note: all effective array indices are 1..N, not 0..N-1

  simplex - the initial simplex, must contain d + 1 points
  values - the initial function values at the simplex points
  d - the number of dimensions
  ftol - the tolerate for convergence
  obj - the objective function to minimize
  num_eval - the number of evaluations of obj
  stuff - things that are needed by obj
*/
void downhill_simplex(float **simplex, float *values, int d, float ftol,
	 	      float (*obj)(float *, int), int *num_eval) {

  int i, j, low, high, second_high, ssize;
  float rtol, sum, *simplex_sum, *test_point, test_value, mult;

  /* initializations */
  *num_eval = 0;
  ssize = d + 1; /* size of the simplex */

  /* for each dimension, pre-compute the sum of all points */
  /* this is used later to compute the average coordinates */
  simplex_sum = (float*) malloc(sizeof(float)*(d+1)); /* array starts at 1 */
  for (i=1; i<=d; i++) { 
    sum = 0.0;
    for(j=1; j<=ssize; j++) {
      sum = sum + simplex[j][i];
    }
    simplex_sum[i] = sum;
  }

  /* create a test point */
  test_point = (float*) malloc(sizeof(float)*(d+1)); /* array starts at 1 */


  /* begin algorithm */
  while (1) {

    /* find the lowest point, the highest point and the second highest
       point in the simplex */
    if (values[1] > values[2]) {
      low = 2;
      high = 1;
      second_high = 2;
    } else {
      low = 1;
      high = 2;
      second_high = 1;
    }
    for (i=1; i<=ssize; i++) {
      if (values[i] > values[high]) {
	second_high = high;
	high = i;
      } else if (values[i] > values[second_high] && i != high) {
	second_high = i;
      } else if (values[i] <= values[low]) {
	low = i;
      }
    }


    /* we will quit if there are too many tries
       the tolerance is met, or if the function
       value is so low that we really don't care anymore
    */
    rtol=2.0*fabs(values[high]-values[low])/
      (fabs(values[high])+fabs(values[low])+TINY);
    if (*num_eval >= NMAX || rtol < ftol || values[low] < 1.0e-6) {
      values[1] = values[low];
      for (i=1; i<=d; i++) {
	simplex[1][i] = simplex[low][i];
      }
      break;
    }


    /* first try to reflect the high point across the mean point */
    /* i.e. want (x_mean - x_high) = - (x_mean - x_test) */
    mult = 2.0/d;
    for (i=1; i<=d; i++) {
      test_point[i] = (simplex_sum[i] - simplex[high][i])*mult
	- simplex[high][i];
    }
    test_value = (*obj)(&test_point[1], d);
    (*num_eval)++;
    if (test_value < values[high]) {
      /* better point, update the simplex, update also the sum */
      values[high] = test_value;
      for (i=1; i<=d; i++) {
	simplex_sum[i] = simplex_sum[i] - simplex[high][i] + test_point[i];
	simplex[high][i] = test_point[i];
      }
    }

    if (test_value <= values[low]) {
      /* the new point is even better than our lowest point, okay, now,
	 extend the point we just found even further
	 i.e. want 2*(x_mean - x_high) = (x_mean - x_test)
      */
      mult = -1.0/d;
      for (i=1; i<=d; i++) {
	test_point[i] = (simplex_sum[i] - simplex[high][i])*mult
	  + 2.0*simplex[high][i];
      }
      test_value = (*obj)(&test_point[1], d);
      (*num_eval)++;
      if (test_value < values[high]) {
	/* better point, update the simplex, update also the sum */
	values[high] = test_value;
	for (i=1; i<=d; i++) {
	  simplex_sum[i] = simplex_sum[i] - simplex[high][i] + test_point[i];
	  simplex[high][i] = test_point[i];
	}
      }

    } else if (test_value >= values[second_high]) {
      /* the new point is still the highest, no improvement,
         so we are going to shrink the high point towards the mean
	 i.e. want (x_mean - x_high) = 2*(x_mean - x_test)
      */
      mult = 0.5/d;
      for (i=1; i<=d; i++) {
	test_point[i] = (simplex_sum[i] - simplex[high][i])*mult
	  + 0.5*simplex[high][i];
      }
      test_value = (*obj)(&test_point[1], d);
      (*num_eval)++;
      if (test_value < values[high]) {
	/* better point, update the simplex, update also the sum */
	values[high] = test_value;
	for (i=1; i<=d; i++) {
	  simplex_sum[i] = simplex_sum[i] - simplex[high][i] + test_point[i];
	  simplex[high][i] = test_point[i];
	}
      } else {
	/* no good, we better just contract the whole simplex
	   toward the low point
	*/
	for (i=1; i<=ssize; i++) {
	  if (i != low) {
	    for (j=1; j<=d; j++) {
	      simplex[i][j]=test_point[j]=0.5*(simplex[i][j]+simplex[low][j]);
	    }
	    values[i]=(*obj)(&test_point[1], d);
	  }
	}
	*num_eval = *num_eval + d;

	/* recompute the sums */
	for (i=1; i<=d; i++) { 
	  sum = 0.0;
	  for(j=1; j<=ssize; j++) {
	    sum = sum + simplex[j][i];
	  }
	  simplex_sum[i] = sum;
	}
      }
    }
  }

  free(simplex_sum);
  free(test_point);

}

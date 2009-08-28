#ifndef __DOWNHILL_SIMPLEX_H
#define __DOWNHILL_SIMPLEX_H

void downhill_simplex(float **simplex, float *values, int dim, float ftol,
	float (*obj_func)(float [], int ndim), int *num_eval);
    
#endif

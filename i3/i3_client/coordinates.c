#include "assert.h"

#include "coordinates.h"
#include "downhill_simplex.h"
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#define DIM 3

/* global to coordinate computation */
int curr_num = 0;
static Coordinates_RTT *curr_coord_rtt;
static Coordinates my_coordinates;

/* function to minimize */
float objective_function(float dim[], int ndim)
{
    int i;
    float sum = 0;
    float l1, l2, temp;
    
    static int count = 0;
    ++count;
    
    // TODO: handle wraparound for longitude
    assert(curr_num > 0);
    for (i = 0; i < curr_num; i++) {
	l1 = dim[0]-curr_coord_rtt[i].coord.latitude;
	l2 = dim[1]-curr_coord_rtt[i].coord.longitude;

	temp = (float)(sqrt(l1*l1 + l2*l2) - dim[2]*((float)curr_coord_rtt[i].rtt/1000.0));
	sum += temp*temp;
    }

    return sum;
}

#define FTOL 0.000001F
void compute_coordinates(int num, Coordinates_RTT coord_rtt[])
{
    int i, j, nfunc;
    static int firsttime = 1;
    static float **p;
    static float *y;
    int mean[] = {0, 0, 0, 10};
    int width[] = {0, 180, 360, 20};
 
    if (firsttime) {
	p = (float **)malloc(sizeof(float *)*(DIM+2));
	y = (float *)malloc(sizeof(float)*(DIM+2));
	for (i = 1; i <= DIM+1; ++i) {
	    p[i] = (float *)malloc(sizeof(float)*(DIM+1));
	}
	firsttime = 0;
    }
    
    curr_num = num;
    curr_coord_rtt = coord_rtt;

    if (curr_num == 0) {
	printf("No landmarks specified for coordinate computation.  Exiting function...\n");
	return;
    }
   
    /* choose random numbers, and initializations */
    for (i = 1; i <= DIM+1; ++i) {
	for (j = 1; j <= DIM; j++) {
	    p[i][j] = (float)(mean[j] + rand() % width[j] - width[j]/2);
	}
    }
    for (i = 1; i <= DIM+1; ++i) {
	y[i] = objective_function(p[i], DIM);
    }
   
    /* multiple runs */
#define NUM_RUNS_DOWNHILL 10
    for (i = 0; i < NUM_RUNS_DOWNHILL; i++) 
	downhill_simplex(p, y, DIM, FTOL, objective_function, &nfunc);
    
    printf("%.2f %.2f %.2f\n", p[1][1], p[1][2], p[1][3]);
    my_coordinates.latitude = p[1][1];
    my_coordinates.longitude = p[1][2];
}

float coordinates_distance(Coordinates coord)
{
    if (COORD_UNDEFINED == coord.latitude || COORD_UNDEFINED == coord.longitude)
	return -1;
    
    return (float)(sqrt(pow(coord.latitude - my_coordinates.latitude, 2) + 
	    pow(coord.longitude - my_coordinates.longitude, 2)));
}

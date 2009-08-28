#ifndef _COORDINATES_H
#define _COORDINATES_H

#if !defined(_WIN32) || defined(__CYGWIN__)
    #include <inttypes.h>
#else
    #include "../utils/fwint.h"
#endif

#define COORD_UNDEFINED 1000

typedef struct Coordinates {
    float latitude;
    float longitude;
} Coordinates;

typedef struct Coordinates_RTT {
    Coordinates coord;
    uint64_t rtt;
} Coordinates_RTT;

void compute_coordinates(int num, Coordinates_RTT coord_rtt[]);

float coordinates_distance(Coordinates coord);

#endif

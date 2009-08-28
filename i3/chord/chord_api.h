#ifndef _CHORD_API_H
#define _CHORD_API_H

typedef unsigned char byte;

enum {
  CHORD_ID_BITS = 160,
};

typedef struct {
    byte x[CHORD_ID_BITS/8];
} chordID;

/* init: initialize chord server, provide configuration file */
int chord_init(char *conf_file);

/* route: forward message M towards the root of key K. */
void chord_route(chordID *k, char *data, int len);

/* get_range: returns the range (l,r] that this node is responsible for */
void chord_get_range(chordID *l, chordID *r);

/* is_local: Does this ID belong to this server? */
int chord_is_local(chordID *x);

#endif

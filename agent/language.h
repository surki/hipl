/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef LANGUAGE_H
#define LANGUAGE_H

/******************************************************************************/
/* INCLUDES */
#include "debug.h"
#include "str_var.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */

/* This is a template file for new files. */
int lang_init(const char *, const char *);
void lang_quit(void);
char *lang_get(const char *);


#endif /* END OF HEADER FILE */
/******************************************************************************/


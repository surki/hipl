/***************************************************************************
                          i3_misc.c  -  description
                             -------------------
    begin                : Nov 20 2002
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

void panic(char *fmt, ...)
{
    va_list args;
    
    fflush(stdout);
    fprintf(stderr, "FATAL ERROR: ");
    
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    if (fmt[0] != '\0' && fmt[strlen(fmt)-1] == ':')
	fprintf(stderr, " %s", strerror(errno));
    fprintf(stderr, "\n");
										
    exit(2); /* conventional value for failed execution */
}

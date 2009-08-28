/* Copyright (C) 1999 Lucent Technologies */
/* Excerpted from 'The Practice of Programming' */
/* by Brian W. Kernighan and Rob Pike */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "eprintf.h"

/* eprintf: print error message and exit */
void eprintf(char *fmt, ...)
{
	va_list args;

	fflush(stdout);
	if (getprogname() != NULL)
		fprintf(stderr, "%s: ", getprogname());

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	if (fmt[0] != '\0' && fmt[strlen(fmt)-1] == ':')
		fprintf(stderr, " %s", strerror(errno));
	fprintf(stderr, "\n");
	exit(2); /* conventional value for failed execution */
}

/* weprintf: print warning message */
void weprintf(char *fmt, ...)
{
	va_list args;

	fflush(stdout);
	fprintf(stderr, "warning: ");
	if (getprogname() != NULL)
		fprintf(stderr, "%s: ", getprogname());
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	if (fmt[0] != '\0' && fmt[strlen(fmt)-1] == ':')
		fprintf(stderr, " %s\n", strerror(errno));
	else
		fprintf(stderr, "\n");
}

/* emalloc: malloc and report if error */
void *emalloc(size_t n)
{
	void *p;

	p = malloc(n);
	if (p == NULL)
		eprintf("malloc of %u bytes failed:", n);
	return p;
}

/* erealloc: realloc and report if error */
void *erealloc(void *vp, size_t n)
{
	void *p;

	p = realloc(vp, n);
	if (p == NULL)
		eprintf("realloc of %u bytes failed:", n);
	return p;
}

/* ecalloc: calloc and report if error */
void *ecalloc(size_t n, size_t w)
{
        void *p;
	
	p = calloc(n, w);
	if (p == NULL)
	        eprintf("calloc of %u x %u bytes failed:", n, w);
	return p;
}

/* estrdup: duplicate a string, report if error */
char *estrdup(char *s)
{
	char *t;

	t = (char *) malloc(strlen(s)+1);
	if (t == NULL)
		eprintf("estrdup(\"%.20s\") failed:", s);
	strcpy(t, s);
	return t;
}

#ifndef __APPLE__
static const char *progname;

/* setprogname: set name of program */
void setprogname(const char *name)
{
    progname = name;
}

/* getprogname: return name of program */
const char *getprogname(void)
{
    return progname;
}
#endif

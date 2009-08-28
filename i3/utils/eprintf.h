#ifndef _EPRINTF_H
#define _EPRINTF_H

/* Copyright (C) 1999 Lucent Technologies */
/* Excerpted from 'The Practice of Programming' */
/* by Brian W. Kernighan and Rob Pike */

#include <time.h>

/* eprintf.h: error wrapper functions */
extern void eprintf (char *, ...);
extern void weprintf (char *, ...);
extern char *estrdup (char *);
extern void *emalloc (size_t);
extern void *erealloc (void *, size_t);
extern void *ecalloc (size_t, size_t);
extern void setprogname (const char *);
extern const char *getprogname (void);

#ifdef CCURED
#pragma ccuredalloc("emalloc", sizein(1))
#pragma ccuredvararg("eprintf", printf(1))
#pragma ccuredvararg("weprintf", printf(1))
#endif
#endif

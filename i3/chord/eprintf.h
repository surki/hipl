/* Copyright (C) 1999 Lucent Technologies */
/* Excerpted from 'The Practice of Programming' */
/* by Brian W. Kernighan and Rob Pike */

/* eprintf.h: error wrapper functions */
extern	void	eprintf(char *, ...);
extern	void	weprintf(char *, ...);
#ifdef CCURED
#pragma ccuredvararg("eprintf", printf(1))
#pragma ccuredvararg("weprintf", printf(1))
#endif
extern	char	*estrdup(char *);
extern	void	*emalloc(size_t);
extern	void	*erealloc(void *, size_t);
extern  void    *ecalloc(size_t, size_t);
extern	void	setprogname(const char *);
extern	const char*	getprogname(void);

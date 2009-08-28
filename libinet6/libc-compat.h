/* $USAGI: libc-compat.h,v 1.15 2005/12/18 10:32:44 yoshfuji Exp $ */

/*
 * Copyright (C) 2000 USAGI/WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __LIBC_COMPAT_H
#define __LIBC_COMPAT_H

#define internal_function
#define attribute_hidden
#define __builtin_expect

#define __alloca		alloca
#define __close			close
#define __connect		connect
#define __fcntl			fcntl
#define __fxstat64		fxstat64
#define __geteuid		geteuid
#define __gethostbyaddr_r	gethostbyaddr_r
#define __gethostbyname_r	gethostbyname_r
#define __gethostbyname2_r	gethostbyname2_r
#define __gethostname		gethostname
#define __getpid		getpid
#define __getline		getline
#define __getpwnam_r		getpwnam_r
#define __getservbyname_r	getservbyname_r
#define __getservbyport_r	getservbyport_r
#define __gettimeofday		gettimeofday
#define __lxstat64		lxstat64
#define __mempcpy		mempcpy
#define __mkdir			mkdir
#define __open64		open64
#define __poll			poll
#define __read			read
#define __write			write
#define __sigblock		sigblock
#define __sigsetmask		sigsetmask
#define __sleep			sleep
#define __snprintf		snprintf
#define __socket		socket
#define __strdup		strdup
#define __strnlen		strnlen
#define __sysconf		sysconf

extern int __gen_tempname (char *, int);
#define __GT_FILE	0
#define __GT_BIGFILE	1
#define __GT_DIR	2
#define __GT_NOCREATE	3

#define __libc_lock_define_initialized(CLASS,NAME)			\
	CLASS pthread_mutex_t NAME = PTHREAD_MUTEX_INITIALIZER
#define __libc_lock_lock(NAME)						\
	pthread_mutex_lock(&(NAME))
#define __libc_lock_unlock(NAME)					\
	pthread_mutex_unlock(&(NAME))

#if _USAGI_LIBINET6 == 21
# define _LIBC
#else
# define __set_errno(e)		errno = (e)
# define __set_h_errno(h)	h_errno = (h)
#endif
#endif /* __LIBC_COMPAT_H */

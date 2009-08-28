/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_TERMINAL_H
#define GUI_TERMINAL_H

/******************************************************************************/
/* INCLUDES */
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include "debug.h"

#ifndef AGENT_H
#include "exec.h"
#include "tools.h"
#endif

/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* DEFINES */
enum
{
	TERM_MODE_NONE = 0,
	TERM_MODE_SERVER,
	TERM_MODE_CLIENT,
	
	TERM_MODES_N
} TERM_MODES;

/* Select timeouts. */
#define SELECT_TIMEOUT_SEC		1
#define SELECT_TIMEOUT_USEC		0

/** Server port. */
#define TERM_SERVER_PORT 1111


/******************************************************************************/
/* STRUCTS */
/** Command struct. */
typedef struct
{
	char *cmd;
	void (*func)(char *);
} TERMINAL_COMMAND;

/** This stucture holds data which is passed from init to thread. */
typedef struct 
{
	int socket;
} TERM_THREAD_DATA;


/******************************************************************************/
/* FUNCTION DEFINITIONS */

/* file: terminal.c */
void cmd_help(char *);
void cmd_exec(char *);
void cmd_server(char *);
void cmd_connect(char *);

void term_exec_command(char *);
void term_print(const char *, ...);

void term_set_mode(int);
int term_get_mode(void);
void term_set_server_addr(char *);
char *term_get_server_addr(void);

/* file: terminal_server.c */
void *term_server_send_string(void *);
int term_server_init(void);
void term_server_quit(void);

/* file: terminal_server.c */
void *term_client_send_string(void *);
int term_client_init(void);
void term_client_quit(void);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/


/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "terminal.h"


/******************************************************************************/
/* GLOBALS */
/** Command list. */
TERMINAL_COMMAND cmds[] =
{
	{ "help", cmd_help },
	{ "exec", cmd_exec },
	{ "server", cmd_server },
	{ "connect", cmd_connect },
	{ 0, 0 }
};

/** Terminal mode. */
int term_mode = TERM_MODE_NONE;

/** Server address, where client should connect. */
char term_server_addr[MAX_URL_LEN + 1];


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** Help-command. */
void cmd_help(char *x)
{
	term_print("\n"
	           "* HIP GUI terminal help:\n"
	           "*  help          - Prints this help.\n"
	           "*  exec          - Show application execute dialog.\n"
	           "*  server [nick] - Create new server. Close old server/client\n"
	           "                   automatically. Nick is optional.\n"
	           "*  connect server [nick]\n"
	           "*                - Connect to server. Close old server/client\n"
	           "                   automatically. Nick is optional.\n"
	           "\n");
}
/* END OF FUNCTION */


/******************************************************************************/
/** Exec-command. */
void cmd_exec(char *x)
{
	exec_application();
}
/* END OF FUNCTION */


/******************************************************************************/
/** Create server. */
void cmd_server(char *x)
{
	if (strlen(x) > 0) set_nick(x);
	term_mode = TERM_MODE_SERVER;
	term_server_init();
}
/* END OF FUNCTION */


/******************************************************************************/
/** Connect to server. */
void cmd_connect(char *x)
{
	/* Variables. */
	char *server, *nick;

	if (strlen(x) < 1)
	{
		term_print("* No server address specified\n");
		return;
	}
	
	server = x;
	nick = strpbrk(x, " ");
	if (nick)
	{
		while (strlen(nick) > 0 && nick[0] == ' ')
		{
			nick[0] = '\0';
			nick = &nick[1];
		}
		if (strlen(nick) > 0) set_nick(nick);
	}
	
	term_mode = TERM_MODE_CLIENT;
	term_set_server_addr(server);
	term_client_init();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Execute command.
*/
void term_exec_command(char *cmd)
{
	/* Variables. */
	int i;
	int k;
	char b = 0;
	
	/* Check empty command. */
	if (strlen(cmd) < 1)
	{
		return;
	}
	
	/* Find space. */
	for (k = 0;
	     cmd[k] != '\0' && cmd[k] != ' ';
	     k++);

	cmd[k] = '\0';
	k++;
			
	/* Compare commands. */
	for (i = 0; cmds[i].func != 0; i++)
	{
		if (strcmp(cmd, cmds[i].cmd) == 0)
		{
			cmds[i].func(&cmd[k]);
			b = 1;
			break;
		}
	}
	
	/* If command not found. */
	if (!b)
	{
		term_print("* Invalid command.\n");
	}
	
	/* Return. */
	return;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Print string to terminal. Use like printf().
*/
void term_print(const char *string, ...)
{
	/* Variables. */
	GtkTextIter iter;
	va_list args;
	char str[1024];

	/* Get args. */
	va_start(args, string);

	/* Print to terminal. */
	vsprintf(str, string, args);
	gtk_text_buffer_get_end_iter(widget(ID_TERMBUFFER), &iter);
	gtk_text_buffer_insert(widget(ID_TERMBUFFER), &iter, str, -1);
	HIP_DEBUG(str);

	/* End args. */
	va_end(args);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set terminal mode. */
void term_set_mode(int mode)
{
	term_mode = mode;
}
/* END OF FUNCTION */


/******************************************************************************/
/** Get terminal mode. */
int term_get_mode(void)
{
	return (term_mode);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set terminal server address, where client should connect. */
void term_set_server_addr(char *addr)
{
	URLCPY(term_server_addr, addr);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Get terminal server address, where client should connect. */
char *term_get_server_addr(void)
{
	return (term_server_addr);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


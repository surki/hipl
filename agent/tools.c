/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "tools.h"


/******************************************************************************/
/* VARIABLES */
/** This determines whether agent is executing or not. */
int agent_exec_state = 1;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Check whether agent should be executing or not.

	@return 1 if executing, 0 if not.
*/
int agent_exec(void)
{
	/* Return. */
	return (agent_exec_state);
}
/* END OF FUNCTION */

/******************************************************************************/
/**
	Stop and exit agent.
*/
void agent_exit(void)
{
	agent_exec_state = 0;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Prints given hit to buffer as text.
*/
void print_hit_to_buffer(char *buffer, struct in6_addr *hit)
{
	int n, b;
	
	buffer[0] ='\0';
	b = 0;
	
	for (n = 0; n < 16; n++)
	{
		sprintf(&buffer[b], "%02x", (int)hit->s6_addr[n]);
		b += 2;

		if ((n % 2) == 1 && n > 0 && n < 15)
		{
			strcat(buffer, ":");
			b++;
		}
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Read hit from text buffer as hit.
	
	@return 0 on success, -1 on invalid HIT in input buffer.
*/
int read_hit_from_buffer(struct in6_addr *hit, char *buffer)
{
	/* Variables. */
	int n, i, err = 0;
	int v[8];
	
	memset(v, 0, sizeof(int) * 8);
	memset(hit, 0, sizeof(struct in6_addr));
        
	err = sscanf(buffer, "%x:%x:%x:%x:%x:%x:%x:%x",
	             &v[7], &v[6], &v[5], &v[4],
	             &v[3], &v[2], &v[1], &v[0]);
	HIP_IFEL(err != 8, -1, "Invalid HIT in buffer!\n")
	
	n = 0;
	for (i = 7; i >= 0; i--)
	{
		hit->s6_addr[n + 1] = v[i] & 0xff;
		hit->s6_addr[n] = (v[i] >> 8) & 0xff;
		n += 2;
	}
	
	HIP_IFEL(v[7] != 0x2001 && (v[6] & 0xfff0) != 0x0070, -1, "Invalid HIT prefix!\n");
	
	err = 0;

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Read current config.
	
	@param file Config file.
	@return 0 on success, -1 on errors.
*/
int config_read(const char *file)
{
	/* Variables. */
	FILE *f;
	int err = -1, i, n;
	char ch, buf[LONG_STRING], *p1, *p2, *p3, add;

	/* Open file for reading. */
	f = fopen(file, "r");
	HIP_IFEL(!f, -1, "Couldn't open config file: \"%s\"\n", file);

	/* Start parsing. */
	memset(buf, '\0', LONG_STRING); i = 0;
	for (ch = fgetc(f); ch != EOF; ch = fgetc(f))
	{
		p1 = NULL;
		p2 = NULL;
		
		/* Remove whitespaces from line start. */
		if (i == 0 && (ch == ' ' || ch == '\t'))
		{
			continue;
		}
		
		/* Find end of line. */
		if (ch != '\n')
		{
			buf[i] = ch;
			i++;
			continue;
		}

		/*
			Check whether there is carriage return
			in the stream and remove it.
		*/
		ch = fgetc(f);
		
		if (ch != '\r')
		{
			ungetc(ch, f);
		}
		
		/* Check for empty lines and for commented lines. */
		if (strlen(buf) < 1) goto loop_end;
		if (buf[0] == '#') goto loop_end;
		
		/* Find first '=' or '+' character and split string from there. */
		err = sscanf(buf, "%a[^+=]%c%a[^\n]", &p1, &add, &p2);
		if (err != 3) goto loop_end;
/*		p1 = strtok(buf, "+=");
		if (p1 == NULL) goto loop_end;
		p2 = strtok(NULL, "\0");
		if (p2 == NULL) goto loop_end;*/
		
		/* Set values. */
		p3 = strdup(str_var_get(p1));
		if (add == '+' && strlen(p3) > 0) str_var_set(p1, "%s\n%s", p3, p2);
		else str_var_set(p1, p2);
		free(p3);
		HIP_DEBUG("config string read: %s%c%s\n", p1, add, p2);
		
	loop_end:
		/* Clear buffer and free pointers. */
		if (p1) free(p1);
		if (p2) free(p2);
		memset(buf, '\0', LONG_STRING); i = 0;
	}

	err = 0;

out_err:
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "str_var.h"


/******************************************************************************/
/* VARIABLES */
/** String data container. */
StringData *str_data = NULL;
/** Last string data. */
StringData *str_data_last = NULL;
/** Number of strings. */
int str_count = 0;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** Initialize data strings. */
int str_var_init(void)
{
	/* Variables. */
	int err = 0;

	str_data = NULL;
	str_data_last = NULL;
	str_count = 0;
	
	return err;
}
/* END OF FUNCTION */


/******************************************************************************/
/** Deinitalize data strings. */
void str_var_quit(void)
{
	/* Variables. */
	StringData *st = str_data;
	
	while (st)
	{
		st = (StringData *)str_data->next;
		free(str_data);
		str_data = st;
	}
	
	str_data = NULL;
	str_data_last = NULL;
	str_count = 0;
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set or add data string, depending whether string is already defined. */
StringData *str_var_set(const char *name, const char *string, ...)
{
	/* Variables. */
	StringData *err = NULL, *st;
	va_list args;
	
	st = str_var_find(name);
	
	if (!st)
	{
		st = (StringData *)malloc(sizeof(StringData));
		HIP_IFEL(!st, NULL, "malloc()");
		memset(st, 0, sizeof(StringData));
		STRCPY(st->name, name);
		
		if (str_data_last)
		{
			str_data_last->next = (void *)st;
			str_data_last = st;
		}
		else
		{
			str_data = st;
			str_data_last = st;
		}

		str_count++;
	}
	
	va_start(args, string);
	VSPRINTHUGESTR(st->data, string, args);
	va_end(args);

out_err:
	return err;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Get data string.
	@param name Name of data string to get.
	@return Pointer to data string, or pointer to "" (empty string), if
	        no such data exists.
*/
char *str_var_get(const char *name)
{
	/* Variables. */
	StringData *st;
	
	st = str_var_find(name);
	if (st) return st->data;
	
	return "";
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Find data string.
	@param name Name of data string to get.
	@return Pointer to data string struct, or NULL.
*/
StringData *str_var_find(const char *name)
{
	/* Variables. */
	StringData *st = str_data;
	int i;
	
	while (st)
	{
		if (strcmp(name, st->name) == 0) break;
		st = (StringData *)st->next;
	}
	
	return st;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Compare string variables value, and return 1 or 0.
	
	@param name Name of data string to get.
	@param value Value to be compared against.
	@return 1 if value is same, 0 if not.
*/
int str_var_is(const char *name, const char *value)
{
	/* Variables. */
	StringData *st;
	
	st = str_var_find(name);
	if (st)
	{
		if (strcmp(st->data, value) == 0) return (1);
	}
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Check whether string var has some content or is just empty string.
	
	@param name Name of data string to get.
	@return 0 if variable is non-empty string, 1 if it is empty.
*/
int str_var_empty(const char *name)
{
	/* Variables. */
	StringData *st;
	
	st = str_var_find(name);
	if (st)
	{
		if (strlen(st->data) < 1) return (1);
	}
	
	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


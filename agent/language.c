/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "language.h"

/* Languages. */
#include "lang_english.h"
#include "lang_finnish.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
 * Initialize language support.
 */
int lang_init(const char *lang, const char *lang_file)
{
	/* Variables. */
	int err = 0, i;
	char **lang_sel;
	
	/* Check which language is wanted, english is default. */
	if (strcmp(lang_finnish[0], lang) == 0) lang_sel = lang_finnish;
	else lang_sel = lang_english;
	HIP_DEBUG("Loading language \"%s\"...\n", lang_sel[0]);

	for (i = 2; lang_sel[i] != NULL; i += 2)
	{
		str_var_set(lang_sel[i], lang_sel[i + 1]);
	}
	
	/* If language file is given, load it last. */
	if (!lang_file);
	else if (strlen(lang_file) > 0)
	{
		HIP_DEBUG("Loading language file \"%s\"...\n", lang_file);
		HIP_IFEL(config_read(lang_file), -1, "Failed to load language file!\n");
	}

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Deinitialize language support.
*/
void lang_quit(void)
{
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Get specified string from currently selected language.
*/
char *lang_get(const char *name)
{
	return str_var_get(name);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


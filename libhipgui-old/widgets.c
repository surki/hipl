/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "widgets.h"


/******************************************************************************/
/* VARIABLES */
void **gui_widgets = NULL;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize GUI widgets system. This system stores pointers to widgets in
	use.
	
	@return 0 on success, -1 on errors.
*/
int widget_init(void)
{
	/* Variables. */
	int err = 0;

	gui_widgets = (void **)malloc(sizeof(void *) * WIDGET_IDS_N);
	HIP_IFEL(gui_widgets == NULL, -1, "Failed to allocate widgets pointers.\n");
	memset(gui_widgets, sizeof(GtkWidget *) * WIDGET_IDS_N, 0);

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Deinitalize GUI widgets system. */
void widget_quit(void)
{
	if (gui_widgets) free(gui_widgets);
	gui_widgets = NULL;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set pointer for given widget. This function set's pointer of given widget
	ID. This ID should be declared in widgets.h enum WIDGET_IDS.
	
	@param n Widget identifier.
	@param p Pointer to widget.
*/
void widget_set(int n, void *p)
{
	if (n >= 0 && n < WIDGET_IDS_N) gui_widgets[n] = p;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Returns pointer to given widget.
	
	@param n Widget identifier.
	@return Pointer to widget.
*/
void *widget(int n)
{
	if (n < 0 || n >= WIDGET_IDS_N) return (NULL);
	return (gui_widgets[n]);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


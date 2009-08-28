/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_NH_H
#define GUI_NH_H

/******************************************************************************/
/* INCLUDES */
#include <gtk/gtk.h>

#include "events.h"
#include "widgets.h"

/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* FUNCTION DEFINITIONS */

/* file: nh_create.c */
int nhdlg_create_content(void);

/* file: nh_manage.c */
void nh_set_remote_rgroup_info(HIT_Group *);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/


/*
    DNET - Duge's Networking Library

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef TOOLS_H
#define TOOLS_H

/******************************************************************************/
/* INCLUDES */
#include <stdlib.h>
#include <gtk/gtk.h>

#include "debug.h"
#include "hit_db.h"
#include "widgets.h"


/******************************************************************************/
/* DEFINES */
#define NAME_INVALID_CHARS		"<>\""


/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* FUNCTION DEFINITIONS */
char *get_nick(void);
void set_nick(char *);
int find_from_cb(char *, GtkWidget *);
void delete_all_items_from_cb(GtkWidget *);
int check_group_name(char *, HIT_Group *);
int check_hit_name(char *, HIT_Remote *);
int check_lhit_name(char *, HIT_Local *);

int check_apply_group(char *, HIT_Group *);
int check_apply_hit(char *, HIT_Remote *);
int check_apply_hit_move(char *, HIT_Remote *);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/


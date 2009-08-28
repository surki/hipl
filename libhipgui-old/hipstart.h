/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef HIPSTART_H
#define HIPSTART_H

/******************************************************************************/
/* INCLUDES */
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include <stdarg.h>

#include "debug.h"
#include "hit_db.h"
#include "widgets.h"
#include "ife.h"

/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* DEFINES */
#define MAX_HOST_ITEMS		16


/******************************************************************************/
/* STRUCTS */
typedef struct
{
	char name[MAX_NAME_LEN + 1];
	char path[MAX_URL_LEN + 1];
	char addr[MAX_NAME_LEN + 1];
	int server;
} Host_item;


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int exec_application(char *, ...);
gboolean main_delete_event(GtkWidget *, GdkEvent *, gpointer);
void main_destroy(GtkWidget *, gpointer);
gboolean list_select(void *, void *, void *, void *);
int gui_init(void);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/


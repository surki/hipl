/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_EVENTS_H
#define GUI_EVENTS_H

/******************************************************************************/
/* INCLUDES */
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include "debug.h"
#include "hit_db.h"
#include "manage.h"
#include "exec.h"
#include "tools.h"
#include "terminal.h"
#include "widgets.h"

/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* DEFINES */
enum TOOLBAR_IDS
{
	ID_TOOLBAR_RUN = 0,
	ID_TOOLBAR_NEWHIT,
	ID_TOOLBAR_TOGGLETOOLWINDOW,
	ID_TOOLBAR_NEWGROUP,

	TOOLBAR_IDS_N
};

enum BUTTON_IDS
{
	IDB_SEND,
	IDB_TW_RGROUPS,
	IDB_NH_RGROUPS,

	IDB_TW_APPLY,
	IDB_TW_CANCEL,
	IDB_TW_DELETE,
	IDB_TWL_APPLY,
	IDB_TWL_CANCEL,
	IDB_TWL_DELETE,
	
	IDB_OPT_NAT,

	IDB_DBG_RSTALL,
	IDB_DBG_RESTART,

	IDB_SYSTRAY,

	IDM_TRAY_SHOW,
	IDM_TRAY_EXEC,
	IDM_TRAY_EXIT,
	IDM_TRAY_ABOUT,
	
	IDM_RLIST_DELETE,
	
	IDM_RUNAPP,
	IDM_NEWGROUP,
	IDM_NEWHIT,
	IDM_ABOUT,

	IDB_NH_EXPANDER,

	BUTTON_IDS_N
};


/******************************************************************************/
/* FUNCTION DEFINITIONS */
gboolean main_delete_event(GtkWidget *, GdkEvent *, gpointer);
gboolean delete_event(GtkWidget *, GdkEvent *, gpointer);
void main_destroy(GtkWidget *, gpointer);

gboolean list_click(GtkTreeView *, gpointer);
gboolean list_press(GtkTreeView *, GdkEventButton *, gpointer);
gboolean list_double_click(GtkTreeSelection *, GtkTreePath *,
						   GtkTreeViewColumn *, gpointer);

void button_event(GtkWidget *, gpointer);
void toolbar_event(GtkWidget *, gpointer);
void systray_event(void *, guint, guint, gpointer);
void notebook_event(GtkNotebook *, GtkNotebookPage *, guint, gpointer);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/


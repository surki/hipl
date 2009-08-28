/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

#ifndef _EVENTS_H
#define _EVENTS_H

/******************************************************************************/
/* INCLUDES */
#include <gtk/gtk.h>

#include "hitdb.h"
#include "widgets.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */

/******************************************************************************/
/* DEFINES */
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
gboolean e_delete(GtkWidget *, GdkEvent *, gpointer);
gboolean e_delete_main(GtkWidget *, GdkEvent *, gpointer);
void e_destroy_main(GtkWidget *, gpointer);

void e_button(GtkWidget *, gpointer);

void e_cell_data_func(GtkTreeViewColumn *, GtkCellRenderer *,
                      GtkTreeModel *, GtkTreeIter *, gpointer);

gboolean e_cursor_changed(GtkTreeView *, gpointer);
gboolean e_button_press(GtkTreeView *, GdkEventButton *, gpointer);
gboolean e_row_activated(GtkTreeSelection *, GtkTreePath *, GtkTreeViewColumn *, gpointer);

void e_menu_status_icon(void *, guint, guint, gpointer);

void e_local_edit(GtkWidget *, char *);


#endif /* END OF HEADER FILE */
/******************************************************************************/


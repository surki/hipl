/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef RHIT_DND_H
#define RHIT_DND_H

/******************************************************************************/
/* INCLUDES */

#include <gtk/gtk.h>

#include "debug.h"
#include "hit_db.h"
#include "widgets.h"
#include "events.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
void rh_drag_begin(GtkWidget *widget, GdkDragContext *dc, gpointer data);
gboolean rh_drag_motion(GtkWidget *widget, GdkDragContext *dc, gint x, gint y, guint t, gpointer data);
void rh_drag_data_get(GtkWidget *widget, GdkDragContext *dc, GtkSelectionData *selection_data, guint info, guint t, gpointer data);
void rh_drag_data_delete(GtkWidget *widget, GdkDragContext *dc, gpointer data);
gboolean rh_drag_drop(GtkWidget *widget, GdkDragContext *dc, gint x, gint y, guint t, gpointer data);
void rh_drag_end(GtkWidget *widget, GdkDragContext *dc, gpointer data);

void rh_drag_data_received(GtkWidget *widget, GdkDragContext *dc, gint x, gint y, GtkSelectionData *selection_data, guint info, guint t, gpointer data);


#endif /* END OF HEADER FILE */
/******************************************************************************/


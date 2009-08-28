/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

#ifndef DRAGNDROP_H
#define DRAGNDROP_H

/******************************************************************************/
/* INCLUDES */

#include <gtk/gtk.h>

#include "debug.h"
#include "hitdb.h"
#include "widgets.h"
#include "events.h"
#include "tools.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
void dnd_drag_begin(GtkWidget *widget, GdkDragContext *dc, gpointer data);
gboolean dnd_drag_motion(GtkWidget *widget, GdkDragContext *dc, gint x, gint y, guint t, gpointer data);
void dnd_drag_data_get(GtkWidget *widget, GdkDragContext *dc, GtkSelectionData *selection_data, guint info, guint t, gpointer data);
void dnd_drag_data_delete(GtkWidget *widget, GdkDragContext *dc, gpointer data);
gboolean dnd_drag_drop(GtkWidget *widget, GdkDragContext *dc, gint x, gint y, guint t, gpointer data);
void dnd_drag_end(GtkWidget *widget, GdkDragContext *dc, gpointer data);

void dnd_drag_data_received(GtkWidget *widget, GdkDragContext *dc, gint x, gint y, GtkSelectionData *selection_data, guint info, guint t, gpointer data);


#endif /* END OF HEADER FILE */
/******************************************************************************/


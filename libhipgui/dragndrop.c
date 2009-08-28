/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

/******************************************************************************/
/* INCLUDES */
#include "dragndrop.h"


/******************************************************************************/
/* VARIABLES */
char drag_hit_name[MAX_NAME_LEN] = "";
GtkTreePath *drag_hit_path = NULL;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** */
void dnd_drag_begin(GtkWidget *tree, GdkDragContext *dc, gpointer data)
{
	/* Variables. */
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	char *str;
	int depth, *indices;

	strcpy(drag_hit_name, "");
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));

	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		/* Get values for the path. */
		drag_hit_path = gtk_tree_model_get_path(model, &iter);
		depth = gtk_tree_path_get_depth(drag_hit_path);
		indices = gtk_tree_path_get_indices(drag_hit_path);
		gtk_tree_model_get(model, &iter, 0, &str, -1);

		/*
			Only allow drag, if depth is 2. This means, that were
			dragging remote HIT, not group.
		*/
		if (depth == 2 && str[0] != ' ')
		{
			HIP_DEBUG("dnd_drag_begin on %s\n", str);
			NAMECPY(drag_hit_name, str);
			g_free(str);
		}
		else
		{
			gtk_tree_path_free(drag_hit_path);
			drag_hit_path = NULL;
		}
	}
}


/******************************************************************************/
/** */
gboolean dnd_drag_motion(GtkWidget *widget, GdkDragContext *dc,
                        gint x, gint y, guint t, gpointer data)
{
	if (strlen(drag_hit_name) < 1) return TRUE;
	return FALSE;
}


/******************************************************************************/
/** */
void dnd_drag_data_get(GtkWidget *widget, GdkDragContext *dc,
                      GtkSelectionData *selection_data,
                      guint info, guint t, gpointer data)
{
}


/******************************************************************************/
/** */
void dnd_drag_data_delete(GtkWidget *widget, GdkDragContext *dc, gpointer data)
{
}


/******************************************************************************/
/** */
gboolean dnd_drag_drop(GtkWidget *widget, GdkDragContext *dc,
                      gint x, gint y, guint t, gpointer data)
{
	return FALSE;
}


/******************************************************************************/
/** */
void dnd_drag_end(GtkWidget *widget, GdkDragContext *dc, gpointer data)
{
}


/******************************************************************************/
/** */
void dnd_drag_data_received(GtkWidget *tree, GdkDragContext *dc,
                           gint x, gint y, GtkSelectionData *selection_data,
                           guint info, guint t, gpointer data)
{
	/* Variables. */
	GtkTreePath *path;
	GtkTreeViewDropPosition pos;
	GtkTreeModel *model;
	GtkTreeIter iter, parent;
	char *str;
	int depth;
	HIT_Group *g = NULL, *g2 = NULL;
	HIT_Remote *r;
	struct tree_update_data ud;

	/* Bail out, if this was not valid drag&drop operation. */
	if (strlen(drag_hit_name) < 1) return;
	if (!gtk_tree_view_get_dest_row_at_pos(GTK_TREE_VIEW(tree), x, y, &path, &pos)) return;
	
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(tree));
	depth = gtk_tree_path_get_depth(path);
	gtk_tree_model_get_iter(model, &iter, path);
	gtk_tree_model_get(model, &iter, 0, &str, -1);
	
	if (depth == 1) g = hit_db_find_rgroup(str);
	else if (depth == 2)
	{
		if (!gtk_tree_model_iter_parent(model, &parent, &iter)) return;
		gtk_tree_model_get(model, &parent, 0, &str, -1);
		g = hit_db_find_rgroup(str);
	}
	else return;
	r = hit_db_find(drag_hit_name, NULL);
	if (!g || !r) return;
	
	if (!check_apply_hit_move(drag_hit_name, r));
	else if (g && g != r->g)
	{
		r->g->remotec--;
		g2 = r->g;
		r->g = g;
		r->g->remotec++;
		
		/* Delete old remote HIT from list. */
		NAMECPY(ud.old_name, r->name);
		ud.new_name[0] = '\0';
		ud.depth = 2;
		ud.indices_first = -1;
		gtk_tree_model_foreach(widget(ID_RLISTMODEL), update_tree_value, &ud);
		/* Add it to new group in list. */
		hit_remote_add(r->name, g->name);
		if (g2->remotec < 1) hit_remote_add("", g2->name);
	}
}



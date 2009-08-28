/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "events.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
 * When closing the main application window.
 *
 * @return TRUE if don't close or FALSE if close.
 */
gboolean main_delete_event(GtkWidget *w, GdkEvent *event, gpointer data)
{
#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
	gtk_widget_hide(GTK_WIDGET(w));
	return TRUE;
#else
	return FALSE;
#endif
}
/* END OF FUNCTION */


/******************************************************************************/
/**
 * Default window close event. This occurs when user presses that cross
 * usually placed in right top corner of windows.
 *
 * @return TRUE if don't close or FALSE if close.
 */
gboolean delete_event(GtkWidget *w, GdkEvent *event, gpointer data)
{
	gtk_widget_hide(GTK_WIDGET(w));
	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** When main window is destroyed. */
void main_destroy(GtkWidget *w, gpointer data)
{
	connhipd_quit();
	gtk_main_quit();
}
/* END OF FUNCTION */


/******************************************************************************/
/** On HIT list click. */
gboolean list_click(GtkTreeView *tree, gpointer data)
{
	/* Variables. */
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeSelection *selection;
	char *str;
	int depth, *indices;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));

	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		/* Get values for the path. */
		path = gtk_tree_model_get_path(model, &iter);
		depth = gtk_tree_path_get_depth(path);
		indices = gtk_tree_path_get_indices(path);
		gtk_tree_model_get(model, &iter, 0, &str, -1);

		if (data == 0)
		{
			tw_set_mode(TWMODE_NONE);
			if (str[0] == ' ');
			else if (depth == 1)
			{
				tw_set_mode(TWMODE_RGROUP);
				tw_set_rgroup_info(str);
				tw_apply();
			}
			else if (depth == 2)
			{
				tw_set_mode(TWMODE_REMOTE);
				tw_set_remote_info(str);
				tw_apply();
			}
		}
		
		gtk_tree_path_free(path);
		g_free(str);
	}

	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On HIT list click. */
gboolean list_press(GtkTreeView *tree, GdkEventButton *button, gpointer data)
{
	/* Variables. */
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeSelection *selection;
	char *str;
	int depth, *indices;

	if (button->type == GDK_BUTTON_PRESS && button->button == 3)
	{
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));

		if (gtk_tree_selection_get_selected(selection, &model, &iter))
		{
			/* Get values for the path. */
			path = gtk_tree_model_get_path(model, &iter);
			depth = gtk_tree_path_get_depth(path);
			indices = gtk_tree_path_get_indices(path);
			gtk_tree_model_get(model, &iter, 0, &str, -1);
	
			if (depth == 1)
			{
			}
			else if (depth == 2)
			{
			}
			else if (depth == 3 && indices[0] == 1)
			{
/*				gtk_menu_popup(GTK_MENU(widget(ID_RLISTMENU)), NULL, NULL, NULL, NULL,
				               button->button, button->time);
				return (TRUE);*/
			}
	
			gtk_tree_path_free(path);
			g_free(str);
		}
	}
	
	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On HIT list double click. */
gboolean list_double_click(GtkTreeSelection *selection, GtkTreePath *path,
						   GtkTreeViewColumn *column, gpointer data)
{
	//tw_apply();
}
/* END OF FUNCTION */


/******************************************************************************/
/** When button is pressed. */
void button_event(GtkWidget *warg, gpointer data)
{
	/* Variables. */
	HIT_Group *g;
	HIT_Remote *r;
	int id = (int)data, i, err;
	char *ps;
	time_t rawtime;
	struct tm *tinfo;
	pthread_t pt;
	
	switch (id)
	{
	case IDB_SEND:
		ps = (char *)gtk_entry_get_text(GTK_ENTRY(widget(ID_TERMINPUT)));
		if (strlen(ps) < 1) break;
		if (strlen(ps) > (1024 - 128)) ps[1024 - 128] = '\0';

		if (ps[0] == '/' && strlen(ps) < 2);
		else if (ps[0] == '/') term_exec_command(&ps[1]);
		else
		{
			char str[1024];
			HIP_DEBUG("nick is: %s\n", get_nick());
			time(&rawtime);
			tinfo = localtime(&rawtime);
			sprintf(str, "%0.2d:%0.2d <%s> %s\n", tinfo->tm_hour,
			         tinfo->tm_min, get_nick(), ps);
			if (term_get_mode() == TERM_MODE_CLIENT)
			{
				pthread_create(&pt, NULL, term_client_send_string, (void *)str);
			}
			if (term_get_mode() == TERM_MODE_SERVER)
			{
				pthread_create(&pt, NULL, term_server_send_string, (void *)str);
			}
		}
		gtk_entry_set_text(GTK_ENTRY(widget(ID_TERMINPUT)), "");
		gtk_widget_grab_default(GTK_WIDGET(widget(ID_TERMSEND)));
		gtk_entry_set_activates_default(GTK_ENTRY(widget(ID_TERMINPUT)), TRUE);
		gtk_widget_grab_focus(GTK_WIDGET(widget(ID_TERMINPUT)));
		break;

	case IDB_TW_RGROUPS:
		ps = gtk_combo_box_get_active_text(GTK_COMBO_BOX(warg));
		g = hit_db_find_rgroup(ps);
		if (g)
		{
			tw_set_remote_rgroup_info(g);
		}
		else if (strcmp(lang_get("combo-newgroup"), ps) == 0)
		{
			r = tw_get_curitem();
			err = create_remote_group("");
			if (!err) i = 0;
			else i = find_from_cb(r->g->name, widget(ID_TWR_RGROUP));
			gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), i);
		}
		break;

	case IDB_NH_RGROUPS:
		ps = gtk_combo_box_get_active_text(GTK_COMBO_BOX(warg));
		g = hit_db_find_rgroup(ps);
		if (g)
		{
			nh_set_remote_rgroup_info(g);
		}
		else if (strcmp(lang_get("combo-newgroup"), ps) == 0)
		{
			err = create_remote_group("");
			if (!err) i = 0;
			else i = find_from_cb(lang_get("default-group-name"), widget(ID_NH_RGROUP));
			gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), i);
		}
		break;

	case IDB_TW_APPLY:
		tw_apply();
		break;

	case IDB_TW_CANCEL:
		tw_cancel();
		break;

	case IDB_TW_DELETE:
		tw_delete();
		break;
		
	case IDB_TWL_APPLY:
		twl_apply();
		break;

	case IDB_TWL_CANCEL:
		twl_cancel();
		break;

/*	case IDB_SYSTRAY:
		g_object_get(widget(ID_MAINWND), "visible", &i, NULL);
		if (i == TRUE)
		{
			gtk_widget_hide(GTK_WIDGET(widget(ID_MAINWND)));
		}
		else
		{
			gtk_widget_show(GTK_WIDGET(widget(ID_MAINWND)));
		}
		break;*/
		
	case IDM_TRAY_SHOW:
		gtk_widget_show(GTK_WIDGET(widget(ID_MAINWND)));
		break;
		break;

	case IDM_TRAY_ABOUT:
	case IDM_ABOUT:
		about();
		break;

	case IDM_TRAY_EXIT:
		gui_terminate();
		break;
		
	case IDM_RLIST_DELETE:
		HIP_DEBUG("Delete\n");
		break;
	
	case IDM_TRAY_EXEC:
	case IDM_RUNAPP:
		exec_application();
		break;
	
	case IDM_NEWHIT:
		gui_ask_new_hit(NULL, 2);
		break;
	
	case IDM_NEWGROUP:
		create_remote_group("");
		break;
		
	case IDB_NH_EXPANDER:
		break;
	
	case IDB_OPT_NAT:
	case IDB_DBG_RSTALL:
	case IDB_DBG_RESTART:
		opt_handle_action(warg, id);
		break;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** When toolbar button is pressed. */
void toolbar_event(GtkWidget *warg, gpointer data)
{
	/* Variables. */
	static HIT_Remote hit;
	GtkWidget *dialog;
	int id = (int)data;
	pthread_t pt;
	int err;
	char *ps;

	switch (id)
	{
	case ID_TOOLBAR_RUN:
		exec_application();
		break;

	case ID_TOOLBAR_NEWHIT:
		gui_ask_new_hit(NULL, 2);
		break;

	case ID_TOOLBAR_NEWGROUP:
		create_remote_group("");
		break;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** When systray is activated. */
void systray_event(void *warg, guint bid, guint atime, gpointer data)
{
	gtk_menu_popup(GTK_MENU(widget(ID_SYSTRAYMENU)), NULL, NULL, NULL, NULL, 0, atime);
}
/* END OF FUNCTION */


/******************************************************************************/
/** When notebook has some event. */
void notebook_event(GtkNotebook *notebook, GtkNotebookPage *page,
                    guint page_num, gpointer data)
{
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


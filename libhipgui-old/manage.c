/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "manage.h"


/******************************************************************************/
/* EXTERNS */
extern GtkTreeIter local_top, remote_top, process_top;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Tell GUI to add new local HIT into list.

	@param hit New HIT to add.
*/
void gui_add_local_hit(HIT_Local *hit)
{
	/* Variables. */
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to add new remote group into list.

	@param group New group to add.
*/
void gui_add_rgroup(HIT_Group *group)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;
	GtkTreePath *path;

	w = widget(ID_RLISTMODEL);
	gtk_tree_store_append(GTK_TREE_STORE(w), &iter, NULL);
	gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, group->name, -1);
	path = gtk_tree_model_get_path(GTK_TREE_MODEL(w), &iter);
	
	gtk_combo_box_insert_text(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), 0, (gpointer)group);
	gtk_combo_box_insert_text(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), 0, (gpointer)group);
	if (tw_get_mode() == TWMODE_REMOTE_EDIT)
		gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), 0);
	
	gui_add_remote_hit(lang_get("hits-group-emptyitem"), group->name);
	w = widget(ID_RLISTVIEW);
	gtk_tree_view_expand_to_path(GTK_TREE_VIEW(w), path);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to add new remote HIT into list.

	@param hit New HIT to add.
	@param group Group where to add new HIT.
*/
void gui_add_remote_hit(char *hit, char *group)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter, gtop;
	GtkTreePath *path;
	GtkTreeModel *model;
	int err;
	char *str;

//	gdk_threads_enter();
	w = widget(ID_RLISTMODEL);
	err = gtk_tree_model_iter_children(GTK_TREE_MODEL(w), &gtop, NULL);
	HIP_IFEL(err == FALSE, -1, "No remote groups.\n");
	err = -1;

	do
	{
		gtk_tree_model_get(GTK_TREE_MODEL(w), &gtop, 0, &str, -1);
		if (strcmp(str, group) == 0)
		{
			HIP_DEBUG("Found remote group \"%s\", adding remote HIT \"%s\".\n", group, hit);
			/*
				Check that group has some items, if not, then delete "<empty>"
				from the list, before adding new items.
			*/			
			err = gtk_tree_model_iter_children(GTK_TREE_MODEL(w), &iter, &gtop);
			if (err == TRUE)
			{
				gtk_tree_model_get(GTK_TREE_MODEL(w), &iter, 0, &str, -1);
				if (str[0] == ' ') gtk_tree_store_remove(GTK_TREE_STORE(w), &iter);
			}
			else if (err == FALSE && strlen(hit) < 1) hit = lang_get("hits-group-emptyitem");
			else HIP_IFE(strlen(hit) < 1, 1);
			
			gtk_tree_store_append(GTK_TREE_STORE(w), &iter, &gtop);
			gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, hit, -1);
			path = gtk_tree_model_get_path(widget(ID_RLISTMODEL), &iter);
			gtk_tree_view_expand_to_path(GTK_TREE_VIEW(widget(ID_RLISTVIEW)), path);
			err = 0;
			break;
		}
	} while (gtk_tree_model_iter_next(GTK_TREE_MODEL(w), &gtop) != FALSE);

out_err:
//	gdk_threads_leave();
	if (err)
	{
		HIP_DEBUG("Did not find remote group \"%s\", could not show new HIT!\n", group);
	}
	return;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to delete remote HIT from list.

	@param name Name of HIT to be removed.
*/
void gui_delete_remote_hit(char *name)
{
	/* Variables. */
	Update_data ud;

	NAMECPY(ud.old_name, name);
	ud.new_name[0] = '\0';
	ud.depth = 2;
	ud.indices_first = -1;
	gtk_tree_model_foreach(widget(ID_RLISTMODEL), gui_update_tree_value, &ud);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to delete remote group from list.

	@param name Name of group to be removed.
*/
void gui_delete_rgroup(char *name)
{
	/* Variables. */
	Update_data ud;

	NAMECPY(ud.old_name, name);
	ud.new_name[0] = '\0';
	ud.depth = 1;
	ud.indices_first = -1;
	gtk_tree_model_foreach(widget(ID_RLISTMODEL), gui_update_tree_value, &ud);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to add new process to process list.

	@param pid Process ID.
	@param name Process name.
	@param time Time used.
	@param msgs Number of messages.
*/
void gui_add_process(int pid, char *name, int time, int msgs)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;

	w = widget(ID_PLISTMODEL);
	gtk_tree_store_insert(GTK_TREE_STORE(w), &iter, NULL, MAX_EXEC_PIDS);
	gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, pid, 1, name, -1);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to update value from tree store.
*/
gboolean gui_update_tree_value(GtkTreeModel *model, GtkTreePath *path,
                               GtkTreeIter *iter, gpointer data)
{
	/* Variables. */
	Update_data *ud = (Update_data *)data;
	char *str;
	int *indices, depth;

	gtk_tree_model_get(model, iter, 0, &str, -1);
	indices = gtk_tree_path_get_indices(path);
	depth = gtk_tree_path_get_depth(path);

	if ((indices[0] != ud->indices_first && ud->indices_first >= 0)
	    || (depth != ud->depth && ud->depth >= 0));
	else if (strcmp(ud->old_name, str) == 0)
	{
		/* If new name length is less than one, then delete item. */
		if (strlen(ud->new_name) < 1)
		{
			gtk_tree_store_remove(GTK_TREE_STORE(model), iter);
		}
		else
		{
			gtk_tree_store_set(GTK_TREE_STORE(model), iter, 0, ud->new_name, -1);
		}
		return (TRUE);
	}

	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to update value from list store (eg. combo box).
*/
gboolean gui_update_list_value(GtkTreeModel *model, GtkTreePath *path,
                               GtkTreeIter *iter, gpointer data)
{
	/* Variables. */
	Update_data *ud = (Update_data *)data;
	char *str;
	int *indices, depth;

	gtk_tree_model_get(model, iter, 0, &str, -1);
	indices = gtk_tree_path_get_indices(path);
	depth = gtk_tree_path_get_depth(path);

	if ((indices[0] != ud->indices_first || depth != ud->depth)
	    && ud->indices_first >= 0 && ud->depth >= 0);
	else if (strcmp(ud->old_name, str) == 0)
	{
		gtk_list_store_set(GTK_LIST_STORE(model), iter, 0, ud->new_name, -1);
		return (TRUE);
	}

	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Ask for new HIT from user.

	@param hit Information of HIT to be accepted.
	@param inout Whether in or outgoing packet, or manual input.
	       0 in, 1 out, 2 manual.
	@return Returns 0 on add, -1 on drop.
*/
int gui_ask_new_hit(HIT_Remote *hit, int inout)
{
	/* Variables. */
	static int in_use = 0;
	GtkDialog *dialog = (GtkDialog *)widget(ID_NHDLG), *d;
	HIT_Group *group;
	HIT_Remote _hit;
	char phit[128], *ps;
	int err = 0, w, h, i;

	while (in_use != 0) usleep(100 * 1000);
	in_use = 1;

	if (hit_db_count_locals() < 1)
	{
		dialog = (GtkDialog *)
		         gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
		                                GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
		                                (gpointer)lang_get("newhit-error-nolocals"));
		gtk_widget_show(GTK_WIDGET(dialog));
		gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(GTK_WIDGET(dialog));
		return err;
	}

	/* Use thread support, when not adding new HIT manually trough GUI. */
	if (inout != 2) gdk_threads_enter();
	gtk_window_get_size(GTK_WINDOW(dialog), &w, &h);
	gtk_window_move(GTK_WINDOW(dialog), (gdk_screen_width() - w) / 2, (gdk_screen_height() - h) / 2);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	gtk_widget_show(GTK_WIDGET(dialog));
	
	/* Select ungrouped as default group. */
	i = find_from_cb(lang_get("default-group-name"), widget(ID_NH_RGROUP));
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), i);

	/* Close expander as default. */
	gtk_expander_set_expanded(widget(ID_NH_EXPANDER), FALSE);
	
	/* If manual input wanted. */
	if (inout == 2)
	{
		gtk_editable_set_editable(widget(ID_NH_HIT), TRUE);
//		gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_NH_HIT)), TRUE);
		gtk_entry_set_text(GTK_ENTRY(widget(ID_NH_HIT)), "2001:0070:0000:0000:0000:0000:0000:0000");
		gtk_editable_select_region(widget(ID_NH_HIT), 0, -1);
		gtk_entry_set_text(GTK_ENTRY(widget(ID_NH_NAME)), "");
		hit = &_hit;
		memset(hit, 0, sizeof(HIT_Remote));
	}
	else
	{
		gtk_editable_set_editable(widget(ID_NH_HIT), FALSE);
//		gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_NH_HIT)), FALSE);
		print_hit_to_buffer(phit, &hit->hit);
		gtk_entry_set_text(GTK_ENTRY(widget(ID_NH_HIT)), phit);
		gtk_entry_set_text(GTK_ENTRY(widget(ID_NH_NAME)), hit->name);
		gtk_editable_select_region(widget(ID_NH_NAME), 0, -1);
	}
	
	/* Get valid input from user in this loop. */
	do
	{
		i = find_from_cb(lang_get("default-group-name"), widget(ID_NH_RGROUP));
		gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), i);
		gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_YES);
	
		err = gtk_dialog_run(GTK_DIALOG(dialog));
		switch (err)
		{
		case GTK_RESPONSE_YES:
			err = 0;
			break;
		case GTK_RESPONSE_NO:
		default:
			HIP_IFEL(1, -1, "HIT add cancelled\n");
			break;
		}

		ps = gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget(ID_NH_RGROUP)));
		group = hit_db_find_rgroup(ps);
		hit->g = group;
		ps = (char *)gtk_entry_get_text(GTK_ENTRY(widget(ID_NH_NAME)));
		NAMECPY(hit->name, ps);
//		ps = gtk_entry_get_text(GTK_ENTRY(widget(ID_NH_URL)));
		URLCPY(hit->url, "none");
//		ps = gtk_entry_get_text(GTK_ENTRY(widget(ID_NH_PORT)));
		URLCPY(hit->port, "0");
		/* If HIT added manually. */
		if (inout == 2)
		{
			ps = (char *)gtk_entry_get_text(GTK_ENTRY(widget(ID_NH_HIT)));
			err = read_hit_from_buffer(&hit->hit, ps);
			if (err)
			{
				HIP_DEBUG("Failed to parse HIT from buffer!\n");
				d = (GtkDialog *)
				    gtk_message_dialog_new(GTK_WINDOW(dialog), GTK_DIALOG_MODAL,
				                           GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
				                           lang_get("nhdlg-err-hit"));
				gtk_window_set_keep_above(GTK_WINDOW(d), TRUE);
				gtk_widget_show(GTK_WIDGET(d));
				gtk_dialog_run(GTK_DIALOG(d));
				gtk_widget_destroy(GTK_WIDGET(d));
			}
			else if (check_hit_name(hit->name, NULL))
			{
				hit_db_add_hit(hit, 0);
				break;
			}
		}
		else if (check_hit_name(hit->name, NULL)) break;
	} while (1);

	HIP_DEBUG("New hit with parameters: %s, %s, %s.\n", hit->name, hit->g->name,
	          hit->g->accept == HIT_ACCEPT ? lang_get("group-type-accept")
	                                       : lang_get("group-type-deny"));

out_err:
	gtk_widget_hide(GTK_WIDGET(dialog));
	if (inout != 2) gdk_threads_leave();
	in_use = 0;

	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set number of remote HITs in use.
*/
void gui_set_nof_hiu(int n)
{
	/* Variables. */
	char str[320];
	
	gdk_threads_enter();
	sprintf(str, "%s: %d", lang_get("hits-number-of-used"), n);
	gtk_label_set_text(widget(ID_HIUNUM), str);
	gdk_threads_leave();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete all remote HITs in use from list.
*/
void gui_clear_hiu(void)
{
	/* Variables. */
	GtkWidget *w;
	
	gdk_threads_enter();
	w = widget(ID_PHIUMODEL);
	gtk_tree_store_clear(GTK_TREE_STORE(w));
	gdk_threads_leave();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add remote HIT in use.
*/
void gui_add_hiu(HIT_Remote *hit)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;

	gdk_threads_enter();
	w = widget(ID_PHIUMODEL);
	gtk_tree_store_insert(GTK_TREE_STORE(w), &iter, NULL, 99);
	gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, hit->name, -1);
	gdk_threads_leave();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Create new remote group.

	@return Name of new remote group.
*/
int create_remote_group(char *name)
{
	/* Variables. */
	GtkWidget *dialog = (GtkWidget *)widget(ID_NGDLG);
	HIT_Group *g;
	HIT_Local *l;
	int err = -1, accept, lw;
	char *psl, *ps, psn[256];
	pthread_t pt;

	if (hit_db_count_locals() < 1)
	{
		dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
		                                GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
		                                lang_get("newgroup-error-nolocals"));
		gtk_widget_show(GTK_WIDGET(dialog));
		gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(GTK_WIDGET(dialog));
		return (err);
	}
	
	gtk_widget_show(GTK_WIDGET(dialog));
	gtk_widget_grab_focus(GTK_WIDGET(widget(ID_NG_NAME)));
	gtk_entry_set_text(GTK_ENTRY(widget(ID_NG_NAME)), name);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);

	err = gtk_dialog_run(GTK_DIALOG(dialog));
	if (err == GTK_RESPONSE_OK)
	{
		ps = gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget(ID_NG_TYPE1)));
		if (strcmp(lang_get("group-type-accept"), ps) == 0) accept = HIT_ACCEPT;
		else accept = HIT_DENY;
		ps = gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget(ID_NG_TYPE2)));
		if (strcmp(lang_get("group-type2-lightweight"), ps) == 0) lw = 1;
		else lw = 0;

		strcpy(psn, gtk_entry_get_text(GTK_ENTRY(widget(ID_NG_NAME))));
		if (!check_group_name(psn, NULL)) return (create_remote_group(psn));
		psl = gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget(ID_NG_LOCAL)));
		l = NULL;
		if (strlen(psl) > 0)
		{
			l = hit_db_find_local(psl, NULL);
		}
		if (l == NULL)
		{
			HIP_DEBUG("Failed to find local HIT named: %s\n", psl);
			err = -1;
		}
		else if (strlen(psn) > 0)
		{
			g = (HIT_Group *)malloc(sizeof(HIT_Group));
			memset(g, 0, sizeof(HIT_Group));
			NAMECPY(g->name, psn);
			g->l = l;
			g->accept = accept;
			g->lightweight = lw;

			pthread_create(&pt, NULL, create_remote_group_thread, g);
			pthread_join(pt, NULL);
			err = 0;
		}
		else err = -1;
	}
	else err = -1;

out_err:
	gtk_widget_hide(GTK_WIDGET(dialog));
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Thread function for adding new remote group. */
void *create_remote_group_thread(void *data)
{
	/* Variables. */
	HIT_Group *g = (HIT_Group *)data;

	hit_db_add_rgroup(g->name, g->l, g->accept, g->lightweight);

	return (NULL);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add local HITs to all combo boxes and such.
	This is a enumeration callback function.
*/
int all_add_local(HIT_Local *hit, void *p)
{
	/* Variables. */
	GtkWidget *w;
	
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_TWR_LOCAL)), hit->name);
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_TWG_LOCAL)), hit->name);
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_NG_LOCAL)), hit->name);
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_NH_LOCAL)), hit->name);
	
	w = gtk_menu_item_new_with_label(hit->name);
	gtk_menu_shell_append(GTK_MENU_SHELL(widget(ID_LOCALSMENU)), w);
	g_signal_connect(w, "activate", G_CALLBACK(tw_set_local_info), (gpointer)hit->name);
	gtk_widget_show(GTK_WIDGET(w));

	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Update local HITs to all combo boxes and such.
*/
void all_update_local(char *old_name, char *new_name)
{
	/* Variables. */
	GtkTreeModel *model;
	GtkWidget *w;
	GList *gl;
	Update_data ud;

	ud.depth = -1;
	ud.indices_first = -1;
	NAMECPY(ud.old_name, old_name);
	NAMECPY(ud.new_name, new_name);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_TWR_LOCAL)));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_TWG_LOCAL)));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_NG_LOCAL)));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_NH_LOCAL)));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);
	
	gl = gtk_container_get_children(GTK_CONTAINER(widget(ID_LOCALSMENU)));
	while (gl)
	{
		w = gtk_bin_get_child(gl->data);
		if (GTK_IS_LABEL(w) == FALSE);
		else if (strcmp(gtk_label_get_text(GTK_LABEL(w)), old_name) != 0);
		else
		{
			gtk_label_set_text(GTK_LABEL(w), new_name);
			break;
		}
		gl = gl->next;
	}
	g_list_free(gl);
}


/******************************************************************************/
/**
	Update remote groups to all combo boxes and such.
*/
void all_update_rgroups(char *old_name, char *new_name)
{
	/* Variables. */
	GtkTreeModel *model;
	Update_data ud;

	ud.depth = -1;
	ud.indices_first = -1;
	NAMECPY(ud.old_name, old_name);
	NAMECPY(ud.new_name, new_name);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_NH_RGROUP)));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);
}


/******************************************************************************/
/** Show about dialog. */
void about(void)
{
	gtk_show_about_dialog
	(
		GTK_WINDOW(widget(ID_MAINWND)),
		"name", "InfraHIP graphical manager",
		"version", "1.0",
		"website", "http://infrahip.net",
		NULL
	);
}


/******************************************************************************/
/** Show about dialog. */
void opt_handle_action(GtkWidget *w, int type)
{
	int err = 0, argc = 0;
	char *argv[4] = { NULL }, *info = NULL, *arg = NULL;

	argv[0] = "hipagent";
	
	switch (type)
	{
	case IDB_OPT_NAT:
		err = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w));
		argc = 3;
		argv[1] = "nat";
		if (err == TRUE)
			argv[2] = "on";
		else
			argv[2] = "off";
		arg = argv[2];
		info = "NAT extensions";
		break;
	
	case IDB_DBG_RSTALL:
		argc = 3;
		argv[1] = "rst";
		argv[2] = "all";
		info = "reset all SAs";
		break;
		
	case IDB_DBG_RESTART:
		argc = 3;
		argv[1] = "restart";
		argv[2] = "daemon";
		info = "restart daemon";
		break;

	default:
		return;
	}

	err = hip_do_hipconf(argc, argv, 0);

out_err:
	if (info)
	{
		if (arg)
		{
			if (err) gui_set_info("Failed to set %s %s!", info, arg);
			else gui_set_info("Succesfully set %s %s", info, arg);
		}
		else
		{
			if (err) gui_set_info("Failed to %s!", info);
			else gui_set_info("Succesfully %s", info);
		}
	}

	return;
}

/**
 * Update GUI NAT status in options tab.
 * @note Call from outside of gtk_main().
 *
 * @param status 1 if nat extension on, 0 if not.
 */
void hip_gui_update_nat_safe(int status)
{
	GtkWidget *w = widget(ID_OPT_NAT);
	if (status) status = TRUE;
	else status = FALSE;
	gdk_threads_enter();
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), status);
	gdk_threads_leave();
}


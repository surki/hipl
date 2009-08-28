/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

/******************************************************************************/
/* INCLUDES */
#include "tools.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
 * Set statusbar text.
 *
 * @param str Pointer to string to be set.
 * @param safe Set to 0 if called inside gtk_main(), 1 if not.
 */
void _info_set(const char *str, int safe)
{
	static int last = -1;
	GtkWidget *w  = widget(ID_STATUSBAR);
	
	if (safe) gdk_threads_enter();
	if (last >= 0) gtk_statusbar_pop(GTK_STATUSBAR(w), last);
	last = gtk_statusbar_get_context_id(GTK_STATUSBAR(w), "info");
	gtk_statusbar_push(GTK_STATUSBAR(w), last, str);
	if (safe) gdk_threads_leave();
}


/******************************************************************************/
/**
 * Thread function for adding new remote group.
 */
void *_group_remote_add_thread(void *data)
{
	HIT_Group *g = (HIT_Group *)data;
	hit_db_add_rgroup(g->name, g->l, g->accept, g->lightweight);
	return NULL;
}


/******************************************************************************/
/**
 * Thread function for deleting remote group.
 */
void *_group_remote_del_thread(void *data)
{
	hit_db_del_rgroup(data);
	return NULL;
}


/******************************************************************************/
/**
 * Thread function for deleting remote hit.
 */
void *_hit_remote_del_thread(void *data)
{
	hit_db_del(data);
	return NULL;
}


/******************************************************************************/
/**
 * Set GUI statusbar info text.
 * @note Call this function ONLY inside gtk main loop!
 *
 * @param string printf(3) formatted string presentation.
 */
void info_set(const char *string, ...)
{
	char *str = NULL;
	va_list args;
	
	/* Construct string from given arguments. */
	va_start(args, string);
	vasprintf(&str, string, args);
	va_end(args);
	
	/* Set info to statusbar in normal mode. */
	_info_set(str, 0);
	
	/* Free allocated string pointer. */
	if (str) free(str);
}


/******************************************************************************/
/**
 * Show message dialog.
 * 
 * @param string printf(3) formatted message string presentation.
 * @return 1 if user selected "ok"-button, 0 if user selected "cancel"-button.
 */
int message_dialog(const char *string, ...)
{
	GtkDialog *dialog = (GtkDialog *)widget(ID_MSGDLG);
	GtkWidget *label = (GtkWidget *)widget(ID_MSGDLG_MSG);
	int err = 0;
	char *str = NULL;
	va_list args;
	
	/* Construct string from given arguments. */
	va_start(args, string);
	vasprintf(&str, string, args);
	va_end(args);
	
	gtk_label_set_text(GTK_LABEL(label), str);
	gtk_widget_show(GTK_WIDGET(dialog));
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	err = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_hide(GTK_WIDGET(dialog));
	if (err == GTK_RESPONSE_OK) err = 1;
	else err = 0;
	
	/* Free allocated string pointer. */
	if (str) free(str);

	return err;
}


/******************************************************************************/
/**
 * Show about dialog.
 */
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
/**
 * Tell GUI to update value from tree store.
 */
gboolean update_tree_value(GtkTreeModel *model, GtkTreePath *path,
                           GtkTreeIter *iter, gpointer data)
{
	struct tree_update_data *ud = (struct tree_update_data *)data;
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
		return TRUE;
	}

	return FALSE;
}


/******************************************************************************/
/**
 * Tell GUI to update value from list store (eg. combo box).
 */
gboolean update_list_value(GtkTreeModel *model, GtkTreePath *path,
                           GtkTreeIter *iter, gpointer data)
{
	struct tree_update_data *ud = (struct tree_update_data *)data;
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
		return TRUE;
	}

	return FALSE;
}


/******************************************************************************/
/**
 * Add local HIT to all combo boxes and such.
 * This is a enumeration callback function.
 */
int local_add(HIT_Local *hit, void *p)
{
	GtkWidget *w;
	
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_TWR_LOCAL)), hit->name);
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_TWG_LOCAL)), hit->name);
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_NG_LOCAL)), hit->name);
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_NH_LOCAL)), hit->name);
	
	w = gtk_menu_item_new_with_label(hit->name);
	gtk_menu_shell_append(GTK_MENU_SHELL(widget(ID_LOCALSMENU)), w);
	g_signal_connect(w, "activate", G_CALLBACK(e_local_edit), (gpointer)hit->name);
	gtk_widget_show(GTK_WIDGET(w));

	return 0;
}


/******************************************************************************/
/**
 * Update local HIT on all combo boxes and such.
 */
void local_update(char *old_name, char *new_name)
{
	GtkTreeModel *model;
	GtkWidget *w;
	GList *gl;
	struct tree_update_data ud;

	ud.depth = -1;
	ud.indices_first = -1;
	NAMECPY(ud.old_name, old_name);
	NAMECPY(ud.new_name, new_name);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_TWR_LOCAL)));
	gtk_tree_model_foreach(model, update_list_value, &ud);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_TWG_LOCAL)));
	gtk_tree_model_foreach(model, update_list_value, &ud);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_NG_LOCAL)));
	gtk_tree_model_foreach(model, update_list_value, &ud);

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget(ID_NH_LOCAL)));
	gtk_tree_model_foreach(model, update_list_value, &ud);
	
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
 * Find index of given named item from combo box.
 *
 * @param name Name of item to search.
 * @param warg Pointer to GtkWidget type combo box.
 * @return Index of item, or -1 if not found.
 */
int combo_box_find(const char *name, GtkWidget *warg)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	char *str = NULL;
	int err = -1, i = 0;

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(warg));
	HIP_IFE(gtk_tree_model_get_iter_first(model, &iter) == FALSE, -1);

	do
	{
		gtk_tree_model_get(model, &iter, 0, &str, -1);
		if (strcmp(name, str) == 0)
		{
			err = i;
			break;
		}
		g_free(str);
		str = NULL;
		i++;
	} while (gtk_tree_model_iter_next(model, &iter) == TRUE);

out_err:
	if (str) g_free(str);
	if (err < 0) HIP_DEBUG("Didn't find item from combo box: %s\n", name);
	return err;
}


/******************************************************************************/
/**
 * Tell GUI to add new remote HIT into list.
 *
 * @param hit New HIT to add.
 * @param group Group where to add new HIT.
 */
void hit_remote_add(const char *hit, const char *group)
{
	GtkWidget *w;
	GtkTreeIter iter, gtop;
	GtkTreePath *path;
	GtkTreeModel *model;
	int err;
	char *str;

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
			 * Check that group has some items, if not, then delete "<empty>"
			 * from the list, before adding new items.
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
	if (err)
	{
		HIP_DEBUG("Did not find remote group \"%s\", could not show new HIT!\n", group);
	}
	return;
}


/******************************************************************************/
/**
 * Create new remote group.
 *
 * @return Name of new remote group.
 */
int group_remote_create(const char *name)
{
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
		if (!check_name_group(psn, NULL)) return (group_remote_create(psn));
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

			pthread_create(&pt, NULL, _group_remote_add_thread, g);
			//pthread_join(pt, NULL);
			err = 0;
		}
		else err = -1;
	}
	else err = -1;

out_err:
	gtk_widget_hide(GTK_WIDGET(dialog));
	return (err);
}


/******************************************************************************/
/**
 * Check group name.
 */
int check_name_group(const char *name_orig, HIT_Group *ge)
{
	HIT_Group *g;
	int i, err = 1;
	char *msg = lang_get("ngdlg-err-invalid");
	char *pch, *name;

	name = strdup(name_orig);
	HIP_IFE(name == NULL, 0);

	/* Remove whitespaces from start and end. */
	for (i = 0; isspace(name[i]) && i < strlen(name); i++);
	strcpy(name, &name[i]);
	HIP_IFE(strlen(name) < 1, 0);
	for (i = (strlen(name) - 1); isspace(name[i]) && i > 0; i--);
	name[i + 1] = '\0';
	HIP_IFE(strlen(name) < 1, 0);
	
	/* Check for reserved names. */
	msg = lang_get("ngdlg-err-reserved");
	i = strcmp(lang_get("combo-newgroup"), name);
	HIP_IFE(i == 0, 0);

	/* Some characters can be reserved for internal purposes. */
	msg = lang_get("ngdlg-err-invchar");
	pch = strpbrk(name, NAME_INVALID_CHARS);
	HIP_IFE(pch, 0);

	/* Check that group with this name does not already exist. */
	g = hit_db_find_rgroup(name);
	msg = lang_get("ngdlg-err-exists");
	if (g != ge) HIP_IFE(g, 0);

out_err:
	if (name) free(name);
	if (!err)
	{
		GtkDialog *dialog;
		dialog = (GtkDialog *)
		         gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, msg);
		gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
		gtk_widget_show(GTK_WIDGET(dialog));
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(GTK_WIDGET(dialog));
	}
	
	return err;
}


/******************************************************************************/
/**
 * Check hit name.
 */
int check_name_hit(const char *name_orig, HIT_Remote *re)
{
	HIT_Remote *r;
	int i, err = 1;
	char *msg = lang_get("nhdlg-err-invalid");
	char *pch, *name;

	name = strdup(name_orig);
	HIP_IFE(name == NULL, 0);
	
	/* Remove whitespaces from start and end. */
	for (i = 0; isspace(name[i]) && i < strlen(name); i++);
	strcpy(name, &name[i]);
	HIP_IFE(strlen(name) < 1, 0);
	for (i = (strlen(name) - 1); isspace(name[i]) && i > 0; i--);
	name[i + 1] = '\0';
	HIP_IFE(strlen(name) < 1, 0);
	
	/* Some characters can be reserved for internal purposes. */
	msg = lang_get("ngdlg-err-invchar");
	pch = strpbrk(name, NAME_INVALID_CHARS);
	HIP_IFE(pch, 0);
	
	/* Check that HIT with this name does not already exist. */
	r = hit_db_find(name, NULL);
	msg = lang_get("nhdlg-err-exists");
	if (r != re) HIP_IFE(r, 0);

out_err:
	if (name) free(name);
	if (!err)
	{
		GtkDialog *dialog;
		dialog = (GtkDialog *)
		         gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, msg);
		gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
		gtk_widget_show(GTK_WIDGET(dialog));
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(GTK_WIDGET(dialog));
	}
	
	return err;
}


/******************************************************************************/
/**
 * Check local hit name.
 */
int check_name_local(const char *name_orig, HIT_Local *le)
{
	HIT_Local *l;
	int i, err = 1;
	char *msg = lang_get("lhdlg-err-invalid");
	char *pch, *name;

	name = strdup(name_orig);
	HIP_IFE(name == NULL, 0);
	
	/* Remove whitespaces from start and end. */
	for (i = 0; isspace(name[i]) && i < strlen(name); i++);
	strcpy(name, &name[i]);
	HIP_IFE(strlen(name) < 1, 0);
	for (i = (strlen(name) - 1); isspace(name[i]) && i > 0; i--);
	name[i + 1] = '\0';
	HIP_IFE(strlen(name) < 1, 0);
	
	/* Some characters can be reserved for internal purposes. */
	msg = lang_get("lhdlg-err-invchar");
	pch = strpbrk(name, NAME_INVALID_CHARS);
	HIP_IFE(pch, 0);
	
	/* Check that HIT with this name does not already exist. */
	l = hit_db_find_local(name, NULL);
	msg = lang_get("lhdlg-err-exists");
	if (l != le) HIP_IFE(l, 0);

out_err:
	if (name) free(name);
	if (!err)
	{
		GtkDialog *dialog;
		dialog = (GtkDialog *)
		         gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, msg);
		gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
		gtk_widget_show(GTK_WIDGET(dialog));
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(GTK_WIDGET(dialog));
	}
	
	return err;
}


/******************************************************************************/
/**
 * Check apply for group.
 */
int check_apply_group(const char *name, HIT_Group *ge)
{
	GtkDialog *dialog;
	int err = 0;
	
	err = message_dialog(lang_get("ask-apply-group"));

out_err:
	return err;
}


/******************************************************************************/
/**
 * Check apply for hit.
 */
int check_apply_hit(const char *name, HIT_Remote *re)
{
	GtkDialog *dialog;
	int err = 0;

	err = message_dialog(lang_get("ask-apply-hit"));

out_err:
	return err;
}


/******************************************************************************/
/**
 * Check apply hit move.
 */
int check_apply_hit_move(const char *name, HIT_Remote *re)
{
	GtkDialog *dialog;
	int err = 0;

	err = message_dialog(lang_get("ask-apply-hit-move"));

out_err:
	return err;
}

/******************************************************************************/
/**
 * When apply is pressed in locals toolwindow.
 */
int check_apply_local_edit(void)
{
	HIT_Local *l = (HIT_Local *)pointer(ID_EDIT_LOCAL);
	char str[256];
	int err = 0;

	strcpy(str, (char *)gtk_entry_get_text(GTK_ENTRY(widget(ID_TWL_NAME))));
	if (check_name_local(str, l))
	{
		HIP_DEBUG("Updating local HIT %s -> %s.\n", l->name, str);
		local_update(l->name, str);
		NAMECPY(l->name, str);
		gtk_widget_hide(GTK_WIDGET(widget(ID_LOCALDLG)));
		err = 1;
	}
	
out_err:
	return err;
}


/******************************************************************************/
/**
 * Reset HIT/group edit.
 */
void edit_reset(void)
{
	GtkWidget *container = widget(ID_TW_CONTAINER);
	GtkWidget *w;

	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_APPLY)), FALSE);
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_CANCEL)), FALSE);
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_DELETE)), FALSE);
	gtk_widget_hide(GTK_WIDGET(widget(ID_TW_APPLY)));
	gtk_widget_hide(GTK_WIDGET(widget(ID_TW_CANCEL)));
	gtk_widget_hide(GTK_WIDGET(widget(ID_TW_DELETE)));
	
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TWR_NAME)), FALSE);
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TWR_RGROUP)), FALSE);
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TWR_PORT)), FALSE);
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TWG_NAME)), FALSE);
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TWG_TYPE1)), FALSE);
	
	gtk_entry_set_text(GTK_ENTRY(widget(ID_TWR_NAME)), "");
	gtk_entry_set_text(GTK_ENTRY(widget(ID_TWG_NAME)), "");

	w = widget(ID_TWREMOTE);
	if ((void *)w->parent == (void *)container)
		gtk_container_remove(GTK_CONTAINER(container), w);
	w = widget(ID_TWRGROUP);
	if ((void *)w->parent == (void *)container)
		gtk_container_remove(GTK_CONTAINER(container), w);

	str_var_set("edit-mode", "none");
}


/******************************************************************************/
/**
 * Set remote HIT info to edit.
 *
 * @param hit_name Name of HIT.
 */
void edit_hit_remote(char *hit_name)
{
	GtkWidget *container = widget(ID_TW_CONTAINER);
	GtkWidget *w;
	HIT_Remote *hit;
	char str[320], *ps;
	int i;

	hit = hit_db_find(hit_name, NULL);
	if (!hit) return;
	
	gtk_entry_set_text(GTK_ENTRY(widget(ID_TWR_NAME)), hit->name);
	gtk_entry_set_text(GTK_ENTRY(widget(ID_TWR_URL)), hit->url);
	//sprintf(str, "%d", hit->port);
	gtk_entry_set_text(GTK_ENTRY(widget(ID_TWR_PORT)), hit->port);

	print_hit_to_buffer(str, &hit->hit);
	gtk_entry_set_text(GTK_ENTRY(widget(ID_TWR_REMOTE)), str);

	i = combo_box_find(hit->g->name, widget(ID_TWR_RGROUP));
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), i);

//		tw_set_remote_rgroup_info(hit->g);
	
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_APPLY)), TRUE);
	gtk_container_add(GTK_CONTAINER(container), widget(ID_TWREMOTE));
	gtk_widget_show(GTK_WIDGET(widget(ID_TWREMOTE)));
	g_object_set(widget(ID_TW_APPLY), "label", lang_get("tw-button-apply"), NULL);
	
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_APPLY)), TRUE);
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_DELETE)), TRUE);
	gtk_widget_show(GTK_WIDGET(widget(ID_TW_APPLY)));
	gtk_widget_show(GTK_WIDGET(widget(ID_TW_DELETE)));
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TWR_NAME)), TRUE);
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TWR_RGROUP)), TRUE);

	/* Set edit mode as HIT edit. */
	pointer_set(ID_EDIT_REMOTE, hit);
	str_var_set("edit-mode", "hit-remote");
}


/******************************************************************************/
/**
 * Set remote group info to edit.
 *
 * @param group_name Name of group.
 */
void edit_group_remote(char *group_name)
{
	GtkWidget *container = widget(ID_TW_CONTAINER);
	GtkWidget *w;
	HIT_Group *group;
	char str[320], *ps;
	int i;

	group = hit_db_find_rgroup(group_name);
	if (!group) return;
	i = combo_box_find(group->l->name, widget(ID_TWG_LOCAL));
	if (i < 0) return;
		
	gtk_entry_set_text(GTK_ENTRY(widget(ID_TWG_NAME)), group->name);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWG_LOCAL)), i);
	if (group->accept == HIT_ACCEPT) ps = lang_get("group-type-accept");
	else ps = lang_get("group-type-deny");
	i = combo_box_find(ps, widget(ID_TWG_TYPE1));
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWG_TYPE1)), i);
	if (group->lightweight == 1) ps = lang_get("group-type2-lightweight");
	else ps = lang_get("group-type2-normal");
	i = combo_box_find(ps, widget(ID_TWG_TYPE2));
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWG_TYPE2)), i);

	pointer_set(ID_EDIT_GROUP, group);
	
	gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_APPLY)), TRUE);
	gtk_container_add(GTK_CONTAINER(container), widget(ID_TWRGROUP));
	gtk_widget_show(GTK_WIDGET(widget(ID_TWRGROUP)));
	g_object_set(widget(ID_TW_APPLY), "label", lang_get("tw-button-apply"), NULL);
	
	/* Dont allow any modifications to default group. */
	if (strcmp(group->name, lang_get("default-group-name")) == 0);
	else
	{
		gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_APPLY)), TRUE);
		gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_DELETE)), TRUE);
		gtk_widget_show(GTK_WIDGET(widget(ID_TW_APPLY)));
		gtk_widget_show(GTK_WIDGET(widget(ID_TW_DELETE)));
		gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TWG_NAME)), TRUE);
		gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TWG_TYPE1)), TRUE);
	}
	
	/* If group is not empty, do not allow deleting. */
	if (group->remotec > 0)
		gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_TW_DELETE)), FALSE);

	/* Set edit mode as group edit. */
	str_var_set("edit-mode", "group-remote");
}


/******************************************************************************/
/**
 * When apply is pressed in edit.
 */
void edit_apply(void)
{
	HIT_Remote *r = (HIT_Remote *)pointer(ID_EDIT_REMOTE);
	HIT_Group *g = (HIT_Group *)pointer(ID_EDIT_GROUP);
	HIT_Group *g2;
	struct tree_update_data ud;
	char *ps, str[256];
	
	if (str_var_is("edit-mode", "hit-remote"))
	{
		strcpy(str, (char *)gtk_entry_get_text(GTK_ENTRY(widget(ID_TWR_NAME))));
		if (!check_name_hit(str, r));
		else if (!check_apply_hit(str, r));
		else
		{
			NAMECPY(ud.old_name, r->name);
			NAMECPY(ud.new_name, str);
			NAMECPY(r->name, str);
/*			ps = (char *)gtk_entry_get_text(GTK_ENTRY(widget(ID_TWR_URL)));
			URLCPY(r->url, ps);
			ps = (char *)gtk_entry_get_text(GTK_ENTRY(widget(ID_TWR_PORT)));
			URLCPY(r->port, ps);*/

			ud.depth = 2;
			ud.indices_first = -1;
			HIP_DEBUG("Updating remote HIT %s -> %s.\n", ud.old_name, ud.new_name);
			gtk_tree_model_foreach(widget(ID_RLISTMODEL), update_tree_value, &ud);

			/* Change group, if wanted. */
			ps = gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)));
			g = hit_db_find_rgroup(ps);
			if (g && g != r->g)
			{
				r->g->remotec--;
				g2 = r->g;
				r->g = g;
				r->g->remotec++;
				
				/* Delete old remote HIT from list. */
				NAMECPY(ud.old_name, r->name);
				ud.new_name[0] = '\0';
				gtk_tree_model_foreach(widget(ID_RLISTMODEL), update_tree_value, &ud);
				/* Add it to new group in list. */
				hit_remote_add(r->name, g->name);
				if (g2->remotec < 1) hit_remote_add("", g2->name);
			}
			edit_hit_remote(r->name);
		}
	}

	if (str_var_is("edit-mode", "group-remote"))
	{
		strcpy(str, (char *)gtk_entry_get_text(GTK_ENTRY(widget(ID_TWG_NAME))));
		if (!check_name_group(str, g));
		else if (!check_apply_group(str, g));
		else
		{
			NAMECPY(ud.old_name, g->name);
			NAMECPY(ud.new_name, str);
			NAMECPY(g->name, str);
			ps = gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget(ID_TWG_TYPE1)));
			if (strcmp(lang_get("group-type-accept"), ps) == 0) g->accept = HIT_ACCEPT;
			else g->accept = HIT_DENY;
			ud.depth = 1;
			ud.indices_first = -1;
			HIP_DEBUG("Updating remote group %s -> %s.\n", ud.old_name, ud.new_name);
			gtk_tree_model_foreach(widget(ID_RLISTMODEL), update_tree_value, &ud);
//			all_update_rgroups(ud.old_name, ud.new_name);
			//tw_set_mode(TWMODE_RGROUP);
			edit_group_remote(g->name);
		}
	}
}



/******************************************************************************/
/**
 * When delete is pressed in edit.
 */
void edit_delete(void)
{
	HIT_Remote *r = (HIT_Remote *)pointer(ID_EDIT_REMOTE);
	HIT_Group *g = (HIT_Group *)pointer(ID_EDIT_GROUP);
	pthread_t pt;
	int err;

	if (str_var_is("edit-mode", "hit-remote"))
	{
		g = r->g;
		err = message_dialog(lang_get("ask-delete-hit"));
		if (err != 1);
		else
		{
			pthread_create(&pt, NULL, _hit_remote_del_thread, r->name);
			edit_reset();
		}
	}
	
	if (str_var_is("edit-mode", "group-remote"))
	{
		err = message_dialog(lang_get("ask-delete-group"));
		if (err != 1);
		else
		{
			pthread_create(&pt, NULL, _group_remote_del_thread, g->name);
			edit_reset();
		}
	}
}


/******************************************************************************/
/**
 * Set group info to remote editing.
 */
void edit_set_remote_group(HIT_Group *g)
{
	char *ps;
	int i;

	i = combo_box_find(g->l->name, widget(ID_TWR_LOCAL));
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_LOCAL)), i);

	if (g->accept == HIT_ACCEPT) ps = lang_get("group-type-accept");
	else ps = lang_get("group-type-deny");
	i = combo_box_find(ps, widget(ID_TWR_TYPE1));
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_TYPE1)), i);
	if (g->lightweight == 1) ps = lang_get("group-type2-lightweight");
	else ps = lang_get("group-type2-normal");
	i = combo_box_find(ps, widget(ID_TWR_TYPE2));
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_TYPE2)), i);
}


/******************************************************************************/
/**
 * Set group info to new hit dialog.
 */
void hit_dlg_set_remote_group(HIT_Group *g)
{
	char *ps;
	int i;

	i = combo_box_find(g->l->name, widget(ID_NH_LOCAL));
	gtk_combo_box_set_active(widget(ID_NH_LOCAL), i);

	if (g->accept == HIT_ACCEPT) ps = lang_get("group-type-accept");
	else ps = lang_get("group-type-deny");
	i = combo_box_find(ps, widget(ID_NH_TYPE1));
	gtk_combo_box_set_active(widget(ID_NH_TYPE1), i);
	if (g->lightweight == 1) ps = lang_get("group-type2-lightweight");
	else ps = lang_get("group-type2-normal");
	i = combo_box_find(ps, widget(ID_NH_TYPE2));
	gtk_combo_box_set_active(widget(ID_NH_TYPE2), i);
}


/******************************************************************************/
/** Execute new application. */
void exec_application(void)
{
	GtkWidget *dialog;
	int err, cpid, opp, n, i, type;
	char *ps, *ps2, *vargs[32 + 1];

	dialog = widget(ID_EXECDLG);
	gtk_widget_show(GTK_WIDGET(dialog));
	gtk_widget_grab_focus(GTK_WIDGET(widget(ID_EXEC_COMMAND)));

	err = gtk_dialog_run(GTK_DIALOG(dialog));
	if (err == GTK_RESPONSE_OK)
	{
		opp = gtk_toggle_button_get_active(widget(ID_EXEC_OPP));
		ps = (char *)gtk_entry_get_text(GTK_ENTRY(widget(ID_EXEC_COMMAND)));
		
		HIP_IFEL(strlen(ps) < 0, -1, "No command given.\n");
			
		HIP_DEBUG("Exec new application.\n");
			
		memset(vargs, 0, sizeof(char *) * 33);
		ps2 = strpbrk(ps, " ");
		vargs[0] = ps;
		n = 1;
		while (ps2 != NULL)
		{
			if (ps2[1] == '\0') break;
			if (ps2[1] != ' ')
			{
				vargs[n] = &ps2[1];
				n++;
				if (n > 32) break;
			}
			ps2[0] = '\0';
			ps2 = strpbrk(&ps2[1], " ");
		}

		if (opp) type = EXEC_LOADLIB_OPP;
		else type = EXEC_LOADLIB_HIP;
		
		err = hip_handle_exec_application(1, type, n, vargs);
		if (err != 0)
		{
			HIP_DEBUG("Executing new application failed!\n");
			exit(1);
		}
	}

out_err:
	gtk_widget_hide(GTK_WIDGET(dialog));
	return;
}



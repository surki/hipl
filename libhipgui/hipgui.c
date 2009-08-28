/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

/******************************************************************************/
/* INCLUDES */
#include "hipgui.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
 * Add new remote group.
 *
 * @note This function is for internal use, dont touch!
 */
int _hit_remote_add(const char *group, const char *name)
{
	GtkWidget *w;
	GtkTreeIter iter, gtop;
	GtkTreePath *path;
	GtkTreeModel *model;
	int err = 0;
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
			HIP_DEBUG("Found remote group \"%s\", adding remote HIT \"%s\".\n", group, name);
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
			else if (err == FALSE && strlen(name) < 1) name = lang_get("hits-group-emptyitem");
			else HIP_IFE(strlen(name) < 1, 1);
			
			gtk_tree_store_append(GTK_TREE_STORE(w), &iter, &gtop);
			gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, name, -1);
			path = gtk_tree_model_get_path(widget(ID_RLISTMODEL), &iter);
			gtk_tree_view_expand_to_path(GTK_TREE_VIEW(widget(ID_RLISTVIEW)), path);
			err = 0;
			break;
		}
	} while (gtk_tree_model_iter_next(GTK_TREE_MODEL(w), &gtop) != FALSE);

out_err:
	return err;
}


/******************************************************************************/
/**
 * Thread function for adding new remote HIT.
 *
 * @note This function is for internal use, dont touch!
 */
void *_hit_remote_add_thread(void *data)
{
	HIT_Remote *hit = (HIT_Remote *)data;
	hit_db_add_hit(hit, 0);
	return NULL;
}


/******************************************************************************/
/**
 * Initialize GUI for usage.
 *
 * @return 0 if success, -1 on errors.
 */
int gui_init(void)
{
	GtkWidget *w;
	int err = 0;
	char str[320];

#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
	HIP_DEBUG("GTK version is greater or equal to 2.10, status icon should be shown.\n");
#else
	HIP_DEBUG("GTK version is less than 2.10, status icon not shown.\n");
#endif

	/* Initialize libraries. */
	g_thread_init(NULL);
	gdk_threads_init();
	gtk_init(NULL, NULL);
	widget_init();

	/* Set default icon. */
	gtk_window_set_default_icon_from_file(HIP_DEBIAN_DIR_PIXMAPS "/hipmanager.png", NULL);
//	gtk_window_set_default_icon_name("hipmanager.png");
	
	/* Initialize tooltips. */
	widget_set(ID_TOOLTIPS, gtk_tooltips_new());

	/* Create main GUI window. */
	w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	widget_set(ID_MAINWND, w);
	gtk_window_set_title(GTK_WINDOW(w), lang_get("title-main"));

	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete_main), NULL);
	g_signal_connect(w, "destroy", G_CALLBACK(e_destroy_main), NULL);
	
	/* Create toolwindow for local HITs. */
	w = gtk_dialog_new_with_buttons(lang_get("title-locals"), NULL, GTK_DIALOG_MODAL,
	                                lang_get("lhdlg-button-apply"), GTK_RESPONSE_YES,
	                                lang_get("lhdlg-button-cancel"), GTK_RESPONSE_NO, NULL);
	gtk_widget_hide(GTK_WIDGET(w));
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	widget_set(ID_LOCALDLG, w);

	/* Create new hit -dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-newhit"), NULL, GTK_DIALOG_MODAL,
	                                lang_get("nhdlg-button-accept"), GTK_RESPONSE_YES,
	                                lang_get("nhdlg-button-drop"), GTK_RESPONSE_NO, NULL);
	widget_set(ID_NHDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create execute-dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-runapp"), NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_EXECDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create new group -dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-newgroup"), NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_NGDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create own custom message-dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-msgdlg"), NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_MSGDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create window content for all windows. */
	HIP_IFEL(create_content_msgdlg(), -1, "Failed to create message-dialog contents.\n");
	HIP_IFEL(create_content_nhdlg(), -1, "Failed to create accept-dialog contents.\n");
 	HIP_IFEL(create_content_execdlg(), -1, "Failed to create run-dialog contents.\n");
	HIP_IFEL(create_content_ngdlg(), -1, "Failed to create create-dialog contents.\n");
	HIP_IFEL(create_content_local_edit(), -1, "Failed to create local HITs edit -dialog contents.\n");
	HIP_IFEL(create_content_main(), -1, "Failed to create main-window contents.\n");

	info_set("HIP manager started.");

out_err:
	return err;
}


/******************************************************************************/
/**
 * Run the GUI. This function is assumed to block the calling thread here
 * as long as GUI is running.
 */
void gui_main(void)
{
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), lang_get("combo-newgroup"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), lang_get("combo-newgroup"));

	hit_db_enum_locals(local_add, NULL, NULL);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_LOCAL)), 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWG_LOCAL)), 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NG_LOCAL)), 0);
	
	/* Clear HIT/group edit. */
	edit_group_remote(lang_get("default-group-name"));
//	edit_reset();

	/* Close all groups as default. */
	gtk_tree_view_collapse_all(GTK_TREE_VIEW(widget(ID_RLISTVIEW)));

#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
	gtk_widget_hide(GTK_WIDGET(widget(ID_MAINWND)));
#else
	gtk_widget_show(GTK_WIDGET(widget(ID_MAINWND)));
#endif
	
	gtk_main();
}


/******************************************************************************/
/**
 * De-initialize GUI stuff.
 */
void gui_quit(void)
{
	widget_quit();
}


/******************************************************************************/
/**
 * Ask for new HIT from user.
 *
 * @param hit Information of HIT to be accepted.
 * @param inout Whether in or outgoing packet, or manual input.
 *        0 in, 1 out, 2 manual.
 * @return Returns 0 on add, -1 on drop.
 */
int gui_hit_remote_ask(HIT_Remote *hit, int inout)
{
	static int in_use = 0;
	GtkDialog *dialog = (GtkDialog *)widget(ID_NHDLG), *d;
	HIT_Group *group;
	HIT_Remote _hit;
	char phit[128], *ps;
	int err = 0, w, h, i;
	pthread_t pt;

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
	i = combo_box_find(lang_get("default-group-name"), widget(ID_NH_RGROUP));
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), i);

	/* Close expander as default. */
	gtk_expander_set_expanded(widget(ID_NH_EXPANDER), FALSE);
	
	/* If manual input wanted. */
	if (inout == 2)
	{
		gtk_editable_set_editable(widget(ID_NH_HIT), TRUE);
//		gtk_widget_set_sensitive(GTK_WIDGET(widget(ID_NH_HIT)), TRUE);
		gtk_entry_set_text(GTK_ENTRY(widget(ID_NH_HIT)), "2001:0010:0000:0000:0000:0000:0000:0000");
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
		i = combo_box_find(lang_get("default-group-name"), widget(ID_NH_RGROUP));
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
			else if (check_name_hit(hit->name, NULL))
			{
				pthread_create(&pt, NULL, _hit_remote_add_thread, hit);
				//pthread_join(pt, NULL);
				break;
			}
		}
		else if (check_name_hit(hit->name, NULL)) break;
	} while (1);

	HIP_DEBUG("New hit with parameters: %s, %s, %s.\n", hit->name, hit->g->name,
	          hit->g->accept == HIT_ACCEPT ? lang_get("group-type-accept")
	                                       : lang_get("group-type-deny"));

out_err:
	gtk_widget_hide(GTK_WIDGET(dialog));
	if (inout != 2) gdk_threads_leave();
	in_use = 0;

	return err;
}


/******************************************************************************/
/**
 * Tell GUI to add new remote HIT into list.
 * @note Don't call this function inside gtk main loop!
 *
 * @param group Group name where to add new HIT.
 * @param name Name of new HIT to add.
 */
void gui_hit_remote_add(const char *group, const char *name)
{
	int err = 0;

	gdk_threads_enter();
	err = _hit_remote_add(group, name);
	
out_err:
	gdk_threads_leave();
	return;
}


/******************************************************************************/
/**
 * Call this GUI function to delete remote HIT.
 * 
 * @note Don't call this function inside gtk main loop!
 *
 * @param name Pointer to name of remote HIT to be deleted.
 * @param group Name of group where the HIT was in.
 */
void gui_hit_remote_del(const char *name, const char *group)
{
	HIT_Group *g = hit_db_find_rgroup(group);
	struct tree_update_data ud;

	gdk_threads_enter();
	
	NAMECPY(ud.old_name, name);
	ud.new_name[0] = '\0';
	ud.depth = 2;
	ud.indices_first = -1;
	gtk_tree_model_foreach(widget(ID_RLISTMODEL), update_tree_value, &ud);
	
	if (g)
		if (g->remotec < 1)
			hit_remote_add("", g->name);
	
	gdk_threads_leave();
}


/******************************************************************************/
/**
 * Call this GUI function to add new remote HIT visible in GUI.
 * 
 * @note Don't call this function inside gtk main loop!
 *
 * @param name Pointer to name of remote HIT to be added.
 */
void gui_group_remote_add(const char *name)
{
	GtkWidget *w;
	GtkTreeIter iter;
	GtkTreePath *path;

	gdk_threads_enter();
	
	w = widget(ID_RLISTMODEL);
	gtk_tree_store_append(GTK_TREE_STORE(w), &iter, NULL);
	gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, name, -1);
	path = gtk_tree_model_get_path(GTK_TREE_MODEL(w), &iter);
	
	gtk_combo_box_insert_text(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), 0, (gpointer)name);
	gtk_combo_box_insert_text(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), 0, (gpointer)name);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), 0);
	
	_hit_remote_add(name, lang_get("hits-group-emptyitem"));
	w = widget(ID_RLISTVIEW);
	gtk_tree_view_expand_to_path(GTK_TREE_VIEW(w), path);
	
	gdk_threads_leave();
}


/******************************************************************************/
/**
 * 
 * @note Don't call this function inside gtk main loop!
 *
 */
void gui_group_remote_del(const char *name)
{
	struct tree_update_data ud;

	gdk_threads_enter();
	
	NAMECPY(ud.old_name, name);
	ud.new_name[0] = '\0';
	ud.depth = 1;
	ud.indices_first = -1;
	gtk_tree_model_foreach(widget(ID_RLISTMODEL), update_tree_value, &ud);

	gdk_threads_leave();
}


/******************************************************************************/
/**
 * 
 * @note Don't call this function inside gtk main loop!
 *
 */
void gui_hit_local_add(HIT_Local *l)
{
}


/******************************************************************************/
/**
 * Set GUI statusbar info text.
 * @note Don't call this function inside gtk main loop!
 *
 * @param string printf(3) formatted string presentation.
 */
void gui_set_info(const char *string, ...)
{
	char *str = NULL;
	va_list args;
	
	/* Construct string from given arguments. */
	va_start(args, string);
	vasprintf(&str, string, args);
	va_end(args);
	
	/* Set info to statusbar in safe mode. */
	_info_set(str, 1);
	
	/* Free allocated string pointer. */
	if (str) free(str);
}


/******************************************************************************/
/**
 * Update GUI NAT status in options tab.
 * @note Don't call this function inside gtk main loop!
 *
 * @param status 1 if nat extension on, 0 if not.
 */
void gui_update_nat(int status)
{
	GtkWidget *w = widget(ID_OPT_NAT);
	if (status) status = TRUE;
	else status = FALSE;
	gdk_threads_enter();
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), status);
	gdk_threads_leave();
	/* @todo: this does not really work */
}


/******************************************************************************/
/**
 * 
 * @note Don't call this function inside gtk main loop!
 *
 */
void gui_hiu_clear(void)
{
}


/******************************************************************************/
/**
 * 
 * @note Don't call this function inside gtk main loop!
 *
 */
void gui_hiu_add(HIT_Remote *r)
{
}


/******************************************************************************/
/**
 * 
 * @note Don't call this function inside gtk main loop!
 *
 */
void gui_hiu_count(int c)
{
}



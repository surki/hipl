/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "main.h"

/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize GUI for usage.
	
	@return 0 if success, -1 on errors.
*/
int gui_init(void)
{
	/* Variables. */
	GtkWidget *w;
	GtkTooltips *tooltips;
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

	/* Initialize tooltips. */
	tooltips = gtk_tooltips_new();
	widget_set(ID_TOOLTIPS, tooltips);
//	gtk_tooltips_enable(tooltips);
//	gtk_tooltips_set_delay(tooltips, 500);

	/* Create main GUI window. */
	w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	widget_set(ID_MAINWND, w);
//	gtk_widget_show(GTK_WIDGET(w));
	gtk_window_set_title(GTK_WINDOW(w), lang_get("title-main"));

	g_signal_connect(w, "delete_event", G_CALLBACK(main_delete_event), NULL);
	g_signal_connect(w, "destroy", G_CALLBACK(main_destroy), NULL);

	/* Create toolwindow for remote HITs/groups. */
	w = gtk_vbox_new(FALSE, 0);
	widget_set(ID_TOOLWND, w);
	gtk_widget_show(GTK_WIDGET(w));
	
	/* Create toolwindow for local HITs. */
/*	w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_hide(GTK_WIDGET(w));
	gtk_window_set_title(GTK_WINDOW(w), lang_get("title-locals"));*/
	w = gtk_dialog_new_with_buttons(lang_get("title-locals"), NULL, GTK_DIALOG_MODAL,
	                                lang_get("lhdlg-button-apply"), GTK_RESPONSE_YES,
	                                lang_get("lhdlg-button-cancel"), GTK_RESPONSE_NO, NULL);
	gtk_widget_hide(GTK_WIDGET(w));
	g_signal_connect(w, "delete_event", G_CALLBACK(delete_event), NULL);
	widget_set(ID_LTOOLWND, w);

	/* Create new hit -dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-newhit"), NULL, GTK_DIALOG_MODAL,
	                                lang_get("nhdlg-button-accept"), GTK_RESPONSE_YES,
	                                lang_get("nhdlg-button-drop"), GTK_RESPONSE_NO, NULL);
	widget_set(ID_NHDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(delete_event), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create execute-dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-runapp"), NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_EXECDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(delete_event), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create create-dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-newgroup"), NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_NGDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(delete_event), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create own custom message-dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-msgdlg"), NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_MSGDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(delete_event), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create window content for all windows. */
	HIP_IFEL(msgdlg_create_content(), -1, "Failed to create message-dialog contents.\n");
	HIP_IFEL(tw_create_content(), -1, "Failed to create tool-dialog contents.\n");
	HIP_IFEL(nhdlg_create_content(), -1, "Failed to create accept-dialog contents.\n");
	HIP_IFEL(execdlg_create_content(), -1, "Failed to create run-dialog contents.\n");
	HIP_IFEL(ngdlg_create_content(), -1, "Failed to create create-dialog contents.\n");
	HIP_IFEL(main_create_content(), -1, "Failed to create main-window contents.\n");

	gui_set_info("HIP GUI started.");
	cmd_help("");
	term_print("* HIP GUI started.\n");
	
	/* Default nickname. */
	set_nick("user");

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Run the GUI. This function is assumed to block the calling thread here
	as long as GUI is running.
*/
int gui_main(void)
{
	/* Variables. */
	GtkWidget *w;
	
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), lang_get("combo-newgroup"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), lang_get("combo-newgroup"));

	hit_db_enum_locals(all_add_local, NULL);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_LOCAL)), 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWG_LOCAL)), 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NG_LOCAL)), 0);
	
	/* Set default mode. */
	tw_clear();
	tw_set_mode(TWMODE_RGROUP);
 	tw_set_rgroup_info(lang_get("default-group-name"));

	/* Initialize terminal server. */
	if (term_get_mode() == TERM_MODE_SERVER)
	{
		set_nick("server");
		term_server_init();
	}
	else if (term_get_mode() == TERM_MODE_CLIENT)
	{
		set_nick("client");
		term_client_init();
	}

	/* Close all groups as default. */
	gtk_tree_view_collapse_all(GTK_TREE_VIEW(widget(ID_RLISTVIEW)));

#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
	gtk_widget_hide(GTK_WIDGET(widget(ID_MAINWND)));
#else
	gtk_widget_show(GTK_WIDGET(widget(ID_MAINWND)));
#endif
	
	gtk_main();

	gui_quit();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Quit the GUI.
*/
void gui_quit(void)
{
	if (term_get_mode() == TERM_MODE_SERVER) term_server_quit();
	else if (term_get_mode() == TERM_MODE_CLIENT) term_client_quit();
	widget_quit();
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set status bar info text. */
void gui_set_info(const char *string, ...)
{
	/* Variables. */
	static int last = -1;
	GtkWidget *w;
	char *str = NULL;
	va_list args;
	
	va_start(args, string);

	/* Set to status bar. */
	vasprintf(&str, string, args);
	w = widget(ID_STATUSBAR);
	if (last >= 0) gtk_statusbar_pop(GTK_STATUSBAR(w), last);
	last = gtk_statusbar_get_context_id(GTK_STATUSBAR(w), "info");
	gtk_statusbar_push(GTK_STATUSBAR(w), last, str);
	if (str) free(str);
	
	va_end(args);
}
/* END OF FUNCTION */



/******************************************************************************/
/** Set status bar info text. */
void gui_set_info_safe(const char *string, ...)
{
	/* Variables. */
	static int last = -1;
	GtkWidget *w;
	char *str = NULL;
	va_list args;
	
	gdk_threads_enter();
	
	/* Get args. */
	va_start(args, string);

	/* Set to status bar. */
	vasprintf(&str, string, args);
	w = widget(ID_STATUSBAR);
	if (last >= 0) gtk_statusbar_pop(GTK_STATUSBAR(w), last);
	last = gtk_statusbar_get_context_id(GTK_STATUSBAR(w), "info");
	gtk_statusbar_push(GTK_STATUSBAR(w), last, str);
	if (str) free(str);

	/* End args. */
	va_end(args);

	gdk_threads_leave();
}
/* END OF FUNCTION */


/******************************************************************************/
/** Terminate GUI. */
void gui_terminate(void)
{
	gtk_main_quit();
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


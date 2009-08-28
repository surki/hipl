/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "main.h"


/******************************************************************************/
/* VARIABLES */
GtkTreeIter local_top, remote_top, process_top;


/******************************************************************************/
/* FUNCTIONS */

gboolean e(void)
{
	printf("moi\n");
	return FALSE;
}


/******************************************************************************/
/**
 * Tell HIT list cell renderer which icon to show where.
 */
void cell_data_func(GtkTreeViewColumn *tree_column, GtkCellRenderer *cell, GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	GtkTreePath *path = gtk_tree_model_get_path(GTK_TREE_MODEL(model), iter);
	int depth = gtk_tree_path_get_depth(path);
	char *stock_id = GTK_STOCK_ABOUT;
	char *value;
	HIT_Group *g;

	gtk_tree_model_get(GTK_TREE_MODEL(model), iter, 0, &value, -1);
	if (depth == 1)
	{
		g = hit_db_find_rgroup(value);
		if (!g);
		else if (g->remotec > 0) stock_id = GTK_STOCK_OPEN;
		else stock_id = GTK_STOCK_DIRECTORY;
	}
	else if (strcmp(value, lang_get("hits-group-emptyitem")) == 0) stock_id = GTK_STOCK_STOP;
	else stock_id = GTK_STOCK_ORIENTATION_PORTRAIT;
	g_object_set(cell, "stock-id", stock_id, NULL);
	g_free(value);
}


/******************************************************************************/
/**
	Create contents of the gui in here.

	@return 0 if success, -1 on errors.
*/
int main_create_content(void)
{
	GtkWidget *window = (GtkWidget *)widget(ID_MAINWND);
	GtkWidget *pane, *pbox, *notebook, *w, *w2, *w3;
	GtkWidget *button, *scroll, *chat, *div, *hiubox, *optbox;
	GtkWidget *label, *label2, *cframe, *menu_bar;
	GtkTreeStore *model;
	GtkWidget *list;
	GtkWidget *toolbar;
	GtkWidget *iconw;
	GtkWidget *remote_pane, *local_pane;
	PangoFontDescription *font_desc;
	GdkColor color;
	GtkCellRenderer *cell;
	GtkTreeViewColumn *column;
	GtkTreeSelection *select;
	GtkTreeIter top, child;
	GtkTargetEntry dndtarget;
	char str[320];
	int i, err;
	
#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
	{
		GtkStatusIcon *status_icon;
			
//		status_icon = gtk_status_icon_new_from_stock(GTK_STOCK_OPEN);
		status_icon = gtk_status_icon_new_from_file(HIP_DEBIAN_DIR_PIXMAPS "/hipmanager.png");
		gtk_status_icon_set_visible(status_icon, TRUE);
		err = gtk_status_icon_is_embedded(status_icon);
		HIP_DEBUG("Status icon %s.\n", (err ? "is visible" : "could not be shown"));
		
		g_signal_connect(status_icon, "popup-menu", G_CALLBACK(systray_event), (gpointer)"popup-menu");
		g_signal_connect(status_icon, "activate", G_CALLBACK(button_event), (gpointer)IDB_SYSTRAY);
		
		/* Create menu for status icon. */
		w = gtk_menu_new();
		
		label = gtk_image_menu_item_new_with_label(lang_get("systray-show"));
		iconw = gtk_image_new_from_stock(GTK_STOCK_PREFERENCES, GTK_ICON_SIZE_MENU);
		gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
		gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
		g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_TRAY_SHOW);
		gtk_widget_show(GTK_WIDGET(label));
		
		label = gtk_image_menu_item_new_with_label(lang_get("systray-exec"));
		iconw = gtk_image_new_from_stock(GTK_STOCK_EXECUTE, GTK_ICON_SIZE_MENU);
		gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
		gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
		g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_TRAY_EXEC);
		gtk_widget_show(GTK_WIDGET(label));

		label = gtk_separator_menu_item_new();
		gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
		gtk_widget_show(GTK_WIDGET(label));
		
		label = gtk_image_menu_item_new_with_label(lang_get("systray-about"));
		iconw = gtk_image_new_from_stock(GTK_STOCK_ABOUT, GTK_ICON_SIZE_MENU);
		gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
		gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
		g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_TRAY_ABOUT);
		gtk_widget_show(GTK_WIDGET(label));

		label = gtk_separator_menu_item_new();
		gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
		gtk_widget_show(GTK_WIDGET(label));

		label = gtk_image_menu_item_new_with_label(lang_get("systray-exit"));
		iconw = gtk_image_new_from_stock(GTK_STOCK_CLOSE, GTK_ICON_SIZE_MENU);
		gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
		gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
		g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_TRAY_EXIT);
		gtk_widget_show(GTK_WIDGET(label));
		
		widget_set(ID_SYSTRAYMENU, w);
		
/*		w = gtk_message_dialog_new(NULL, GTK_DIALOG_NO_SEPARATOR | GTK_DIALOG_NO_SEPARATOR,
		                           GTK_MESSAGE_OTHER, GTK_BUTTONS_NONE, "testi viesti\nheip�hei");
		gtk_window_set_decorated(GTK_WINDOW(w), FALSE);
		gtk_widget_show(GTK_WIDGET(w));
		gtk_dialog_run(GTK_DIALOG(w));
		gtk_widget_hide(GTK_WIDGET(w));*/
	}
#endif

	gtk_container_set_border_width(GTK_CONTAINER(window), 3);

	/* Create main pain. */
	pane = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(window), pane);
	gtk_widget_show(GTK_WIDGET(pane));

	/* Create menubar. */
	menu_bar = gtk_menu_bar_new();
	gtk_box_pack_start(GTK_BOX(pane), menu_bar, FALSE, FALSE, 0);
	gtk_widget_show(GTK_WIDGET(menu_bar));
	
	/* File-menu. */
	w = gtk_menu_item_new_with_label(lang_get("menu-file"));
	gtk_widget_show(GTK_WIDGET(w));
	w2 = gtk_menu_new();
	
	label = gtk_image_menu_item_new_with_label(lang_get("menu-file-runapp"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_EXECUTE, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_RUNAPP);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_image_menu_item_new_with_label(lang_get("menu-file-exit"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_CLOSE, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(main_destroy), (gpointer)"exit");
	gtk_widget_show(GTK_WIDGET(label));

	gtk_menu_item_set_submenu(GTK_MENU_ITEM(w), w2);
	gtk_menu_bar_append(GTK_MENU_BAR(menu_bar), w);

	/* Edit-menu. */
	w = gtk_menu_item_new_with_label(lang_get("menu-edit"));
	gtk_widget_show(GTK_WIDGET(w));
	w2 = gtk_menu_new();

	label = gtk_image_menu_item_new_with_label(lang_get("menu-edit-newgroup"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_NEW, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_NEWGROUP);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_image_menu_item_new_with_label(lang_get("menu-edit-addhit"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_ADD, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_NEWHIT);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_image_menu_item_new_with_label(lang_get("menu-edit-locals"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_PROPERTIES, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
//	g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_TRAY_HIDE);
	gtk_widget_show(GTK_WIDGET(label));

	/* Submenu for locals. */
	w3 = gtk_menu_new();
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(label), w3);
	widget_set(ID_LOCALSMENU, w3);
	
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(w), w2);
	gtk_menu_bar_append(GTK_MENU_BAR(menu_bar), w);

	
	/* Tools-menu. */
	w = gtk_menu_item_new_with_label(lang_get("menu-help"));
	gtk_widget_show(GTK_WIDGET(w));
	w2 = gtk_menu_new();
	
	label = gtk_image_menu_item_new_with_label(lang_get("menu-help-about"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_ABOUT, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_ABOUT);
	gtk_widget_show(GTK_WIDGET(label));


	gtk_menu_item_set_submenu(GTK_MENU_ITEM(w), w2);
	gtk_menu_bar_append(GTK_MENU_BAR(menu_bar), w);

	/* Create toolbar. */
	toolbar = gtk_toolbar_new();
	gtk_box_pack_start(GTK_BOX(pane), toolbar, FALSE, FALSE, 0);
	/** note: Toolbar was not so usefull, so hidden for now. */
	gtk_widget_hide(GTK_WIDGET(toolbar));
//	gtk_widget_show(GTK_WIDGET(toolbar));
	widget_set(ID_TOOLBAR, toolbar);
	gtk_toolbar_set_style(GTK_TOOLBAR(toolbar), GTK_TOOLBAR_ICONS);

	/* Create toolbar contents. */
/*	sprintf(str, "%s/%s", HIP_GUI_DATADIR, "swtool.png");
	iconw = gtk_image_new_from_file(str);
	w = gtk_toolbar_append_element(toolbar, GTK_TOOLBAR_CHILD_TOGGLEBUTTON,
	                               NULL, "Toolwindow", "Show/hide toolwindow",
	                               "Private", iconw,
	                               GTK_SIGNAL_FUNC(toolbar_event),
	                               ID_TOOLBAR_TOGGLETOOLWINDOW);
	widget_set(ID_TB_TW, w);
	gtk_toggle_button_set_active(w, TRUE);

	gtk_toolbar_append_space(toolbar);*/
	iconw = gtk_image_new_from_stock(GTK_STOCK_NEW, GTK_ICON_SIZE_SMALL_TOOLBAR);
//	iconw = gtk_image_new_from_file(HIP_GUI_DATADIR "/newgroup.png");
	w = gtk_toolbar_append_item(GTK_TOOLBAR(toolbar), lang_get("tb-newgroup"),
	                            lang_get("tb-newgroup-tooltip"),
	                            "Private", iconw,
	                            GTK_SIGNAL_FUNC(toolbar_event), (gpointer)ID_TOOLBAR_NEWGROUP);
	iconw = gtk_image_new_from_stock(GTK_STOCK_ADD, GTK_ICON_SIZE_SMALL_TOOLBAR);
	w = gtk_toolbar_append_item(GTK_TOOLBAR(toolbar), lang_get("tb-newhit"), lang_get("tb-newhit-tooltip"),
	                            "Private", iconw,
	                            GTK_SIGNAL_FUNC(toolbar_event), (gpointer)ID_TOOLBAR_NEWHIT);
	gtk_toolbar_append_space(GTK_TOOLBAR(toolbar));
	iconw = gtk_image_new_from_stock(GTK_STOCK_EXECUTE, GTK_ICON_SIZE_SMALL_TOOLBAR);
	w = gtk_toolbar_append_item(GTK_TOOLBAR(toolbar), lang_get("tb-runapp"), lang_get("tb-runapp-tooltip"),
	                            "Private", iconw,
	                            GTK_SIGNAL_FUNC(toolbar_event), (gpointer)ID_TOOLBAR_RUN);

	/* Create tabbed notebook. */
	notebook = gtk_notebook_new();
	gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
	gtk_box_pack_start(GTK_BOX(pane), notebook, TRUE, TRUE, 0);
	g_signal_connect(notebook, "switch-page", G_CALLBACK(notebook_event), (gpointer)NULL);
	gtk_widget_show(GTK_WIDGET(notebook));

	/* Create status bar. */
	w = gtk_statusbar_new();
	gtk_box_pack_end(GTK_BOX(pane), w, FALSE, FALSE, 0);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_STATUSBAR, w);

	/* Create tabs. */
	remote_pane = gtk_hpaned_new();
	label = gtk_label_new(lang_get("tabs-hits"));
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), remote_pane, label);
	gtk_widget_show(GTK_WIDGET(remote_pane));

/*	label = gtk_label_new("Net");
	label2 = gtk_label_new("Net");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_label_new("Privacy");
	label2 = gtk_label_new("Privacy");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_label_new("Lightweight");
	label2 = gtk_label_new("Lightweight");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(GTK_WIDGET(label));*/

	optbox = gtk_vbox_new(FALSE, 1);
	label2 = gtk_label_new(lang_get("tabs-options"));
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), optbox, label2);
	gtk_widget_show(GTK_WIDGET(optbox));

	hiubox = gtk_vbox_new(FALSE, 1);
	label2 = gtk_label_new(lang_get("tabs-connections"));
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), hiubox, label2);
	gtk_widget_hide(GTK_WIDGET(hiubox));

	pbox = gtk_hbox_new(TRUE, 1);
	label2 = gtk_label_new("Processes");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), pbox, label2);
	//gtk_widget_show(GTK_WIDGET(pbox));

	chat = gtk_vbox_new(FALSE, 1);
	label2 = gtk_label_new("Terminal");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), chat, label2);
	//gtk_widget_show(GTK_WIDGET(chat));

#ifdef CONFIG_HIP_CERT
	label = gtk_hbox_new(TRUE, 1);
	label2 = gtk_label_new("Cert");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(GTK_WIDGET(label));
#endif

	/***************************************
	/* Setup remote HITs. */
	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(1, G_TYPE_STRING);
//	gtk_tree_store_append(GTK_TREE_STORE(model), &local_top, NULL);
//	gtk_tree_store_set(GTK_TREE_STORE(model), &local_top, 0, "Local HITs", -1);
//	gtk_tree_store_append(GTK_TREE_STORE(model), &remote_top, NULL);
//	gtk_tree_store_set(GTK_TREE_STORE(model), &remote_top, 0, "Remote HITs", -1);

	list = gtk_tree_view_new();
	g_signal_connect(list, "row-activated", G_CALLBACK(list_double_click), (gpointer)"double_clicked");
	g_signal_connect(list, "cursor-changed", G_CALLBACK(list_click), (gpointer)0);
	g_signal_connect(list, "button-press-event", G_CALLBACK(list_press), (gpointer)0);
	widget_set(ID_RLISTVIEW, list);
	
	/* Set up for drag n drop. */
	dndtarget.target = "hit";
	dndtarget.flags = GTK_TARGET_SAME_APP;
	dndtarget.info = 0;
	gtk_tree_view_enable_model_drag_source(GTK_TREE_VIEW(list), GDK_MODIFIER_MASK, &dndtarget, 1,
	                                       GDK_ACTION_MOVE | GDK_ACTION_COPY | GDK_ACTION_ASK);
	dndtarget.info = 1;
	gtk_tree_view_enable_model_drag_dest(GTK_TREE_VIEW(list), &dndtarget, 1,
	                                     GDK_ACTION_MOVE | GDK_ACTION_COPY | GDK_ACTION_ASK);
	g_signal_connect(list, "drag_begin", G_CALLBACK(rh_drag_begin), (gpointer)0);
	g_signal_connect(list, "drag_motion", G_CALLBACK(rh_drag_motion), (gpointer)0);
	g_signal_connect(list, "drag_data_get", G_CALLBACK(rh_drag_data_get), (gpointer)0);
	g_signal_connect(list, "drag_data_delete", G_CALLBACK(rh_drag_data_delete), (gpointer)0);
	g_signal_connect(list, "drag_drop", G_CALLBACK(rh_drag_drop), (gpointer)0);
	g_signal_connect(list, "drag_end", G_CALLBACK(rh_drag_end), (gpointer)0);
	g_signal_connect(list, "drag_data_received", G_CALLBACK(rh_drag_data_received), (gpointer)0);
//	gtk_tree_view_set_column_drag_function(GTK_TREE_VIEW(list), e, NULL, NULL);

/*	gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(model));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes(NULL, cell, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));*/

	gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(model));
	column = gtk_tree_view_column_new();
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));
	
	cell = gtk_cell_renderer_pixbuf_new();
//	g_object_set(cell, "stock-id", GTK_STOCK_EXECUTE);
/*	iconw = gtk_image_new_from_stock(GTK_STOCK_EXECUTE, GTK_ICON_SIZE_MENU);
	g_object_set(cell, "pixbuf-expander-closed", iconw);
	iconw = gtk_image_new_from_stock(GTK_STOCK_EXECUTE, GTK_ICON_SIZE_MENU);
	g_object_set(cell, "pixbuf-expander-open", iconw);*/
	gtk_tree_view_column_pack_start(GTK_TREE_VIEW_COLUMN(column), GTK_CELL_RENDERER(cell), FALSE);
	gtk_tree_view_column_set_cell_data_func(GTK_TREE_VIEW_COLUMN(column), GTK_CELL_RENDERER(cell), cell_data_func, NULL, NULL);
	
	cell = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(GTK_TREE_VIEW_COLUMN(column), GTK_CELL_RENDERER(cell), TRUE);
	gtk_tree_view_column_set_attributes(GTK_TREE_VIEW_COLUMN(column), GTK_CELL_RENDERER(cell), "text", 0, NULL);
	
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_widget_set_size_request(GTK_WIDGET(scroll), 200, 0);
	gtk_paned_add1(GTK_PANED(remote_pane), scroll);
	select = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);
	gtk_widget_show(GTK_WIDGET(list));
	gtk_widget_show(GTK_WIDGET(scroll));
	widget_set(ID_RLISTMODEL, model);
	gtk_paned_add2(GTK_PANED(remote_pane), widget(ID_TOOLWND));
	gtk_widget_show(GTK_WIDGET(widget(ID_TOOLWND)));
	widget_set(ID_REMOTEPANE, remote_pane);

	/***************************************
	/* HITs in use -list. */
	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(1, G_TYPE_STRING);
//	gtk_tree_store_append(GTK_TREE_STORE(model), &process_top, NULL);

	list = gtk_tree_view_new();
	widget_set(ID_PHIUVIEW, list);
	gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(model));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("HIT", cell, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));
/*	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Local HIT", cell, "text", 1, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("group", cell, "text", 2, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));*/

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_widget_set_size_request(GTK_WIDGET(scroll), 200, 0);
	gtk_box_pack_start(GTK_BOX(hiubox), scroll, TRUE, TRUE, 1);
	select = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);
	gtk_widget_show(GTK_WIDGET(list));
	gtk_widget_show(GTK_WIDGET(scroll));
	widget_set(ID_PHIUMODEL, model);
	
	w = gtk_label_new("Number of remote HITs in use: 0");
	gtk_misc_set_alignment(GTK_MISC(w), 0.0f, 0.0f);
	gtk_box_pack_end(GTK_BOX(hiubox), w, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_HIUNUM, w);
	
	/***************************************
	/* Options. */
	cframe = gtk_frame_new(lang_get("opt-title"));
	gtk_box_pack_start(GTK_BOX(optbox), cframe, TRUE, TRUE, 1);
	gtk_widget_show(GTK_WIDGET(cframe));

	w = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(cframe), w);
	gtk_widget_show(GTK_WIDGET(w));
	button = gtk_check_button_new_with_label(lang_get("opt-nat"));
	widget_set(ID_OPT_NAT, button);
	g_signal_connect(button, "clicked", G_CALLBACK(button_event), (gpointer)IDB_OPT_NAT);
	gtk_box_pack_start(GTK_BOX(w), button, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(button));
	
	cframe = gtk_frame_new(lang_get("dbg-title"));
	gtk_box_pack_start(GTK_BOX(optbox), cframe, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(cframe));
	
	w = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(cframe), w);
	gtk_widget_show(GTK_WIDGET(w));
	button = gtk_button_new_with_label(lang_get("dbg-rstall"));
	g_signal_connect(button, "clicked", G_CALLBACK(button_event), (gpointer)IDB_DBG_RSTALL);
	gtk_box_pack_start(GTK_BOX(w), button, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(button));
	button = gtk_button_new_with_label(lang_get("dbg-restart-daemon"));
	g_signal_connect(button, "clicked", G_CALLBACK(button_event), (gpointer)IDB_DBG_RESTART);
	gtk_box_pack_start(GTK_BOX(w), button, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(button));

	w = gtk_label_new(lang_get("opt-info"));
	gtk_box_pack_end(GTK_BOX(optbox), w, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(w));
	
	/***************************************
	/* Process list. */
/*	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(4, G_TYPE_INT, G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT);
//	gtk_tree_store_append(GTK_TREE_STORE(model), &process_top, NULL);

	list = gtk_tree_view_new();
	widget_set(ID_PLISTVIEW, list);
	gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(model));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("PID", cell, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("process", cell, "text", 1, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_widget_set_size_request(GTK_WIDGET(scroll), 200, 0);
	gtk_box_pack_start(GTK_BOX(pbox), scroll, TRUE, TRUE, 1);
	select = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);
	gtk_widget_show(GTK_WIDGET(list));
	gtk_widget_show(GTK_WIDGET(scroll));
	widget_set(ID_PLISTMODEL, model);

	/***************************************
	/* Terminal. */
	div = gtk_hpaned_new();
	gtk_box_pack_start(GTK_BOX(chat), div, TRUE, TRUE, 1);
	gtk_widget_show(GTK_WIDGET(div));

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_paned_add1(GTK_PANED(div), scroll);
	gtk_widget_show(GTK_WIDGET(scroll));
	w = gtk_text_view_new();
	widget_set(ID_TERMSCREEN, w);
	w2 = (GtkWidget *)gtk_text_view_get_buffer(GTK_TEXT_VIEW(w));
	widget_set(ID_TERMBUFFER, w2);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(w), FALSE);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), w);
	gtk_widget_show(GTK_WIDGET(w));
	/* Change default font throughout the widget */
	font_desc = pango_font_description_from_string("Monospace 12");
	gtk_widget_modify_font(GTK_WIDGET(w), font_desc);
	pango_font_description_free(font_desc);
	/* Change default color throughout the widget */
	gdk_color_parse("green", &color);
	gtk_widget_modify_text(GTK_WIDGET(w), GTK_STATE_NORMAL, &color);
	gdk_color_parse("black", &color);
	gtk_widget_modify_base(GTK_WIDGET(w), GTK_STATE_NORMAL, &color);

/*	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(1, G_TYPE_STRING);

	list = gtk_tree_view_new();
	widget_set(ID_USERVIEW, list);
	gtk_tree_view_set_model(GTK_TREE_VIEW(list), model);
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Users", cell, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_paned_add2(div, scroll);
	w = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(w, GTK_SELECTION_SINGLE);
	gtk_widget_show(GTK_WIDGET(list));
	gtk_widget_show(GTK_WIDGET(scroll));
	widget_set(ID_USERMODEL, model);
	gtk_paned_set_position(div, 400);*/

	w2 = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(chat), w2, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(w2));

	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "");
	widget_set(ID_TERMINPUT, w);
	gtk_box_pack_start(GTK_BOX(w2), w, TRUE, TRUE, 1);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
	gtk_widget_grab_focus(GTK_WIDGET(w));
	gtk_widget_show(GTK_WIDGET(w));

	w = gtk_button_new_with_label("Send");
	GTK_WIDGET_SET_FLAGS(w, GTK_CAN_DEFAULT);
	gtk_box_pack_end(GTK_BOX(w2), w, FALSE, FALSE, 1);
	gtk_widget_grab_default(GTK_WIDGET(w));
	g_signal_connect(w, "clicked", G_CALLBACK(button_event), IDB_SEND);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TERMSEND, w);

	/* done with notebook tabs. */
	/***************************************/

	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);
	gtk_widget_show(GTK_WIDGET(notebook));
	gtk_widget_show(GTK_WIDGET(window));

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


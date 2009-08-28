/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

/******************************************************************************/
/* INCLUDES */
#include "create.h"


/******************************************************************************/
/* FUNCTIONS */


/******************************************************************************/
/**
 * Create contents for remote HIT information.
 *
 * @return 0 on success, -1 on errors.
 */
int _create_edit_remote(void)
{
	GtkWidget *frame, *w, *vb, *vb1, *vb2, *sw, *hb, *hp, *exp, *label;
	
	/* Create menu for right click popup. */
	w = gtk_menu_new();
	
	label = gtk_menu_item_new_with_label(lang_get("tw-button-delete"));
	gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_button), (gpointer)IDM_RLIST_DELETE);
	gtk_widget_show(GTK_WIDGET(label));
	
	widget_set(ID_RLISTMENU, w);

	/* Create remote HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), lang_get("tw-hit-info"));
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 5);
	gtk_widget_show(GTK_WIDGET(frame));
	widget_set(ID_TWREMOTE, frame);
	g_object_ref(frame);

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(frame), vb);
	gtk_widget_show(GTK_WIDGET(vb));

	/* Now create basic information. */
	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("tw-hit-name"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "NewHIT");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(GTK_ENTRY(w), MAX_NAME_LEN);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWR_NAME, w);

	w = gtk_label_new(lang_get("tw-hit-group"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	widget_set(ID_TWRGROUP, w);
	g_signal_connect(w, "changed", G_CALLBACK(e_button), (gpointer)IDB_TW_RGROUPS);
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWR_RGROUP, w);

	/* Separator between basic and advanced. */
	w = gtk_hseparator_new();
	gtk_box_pack_start(GTK_BOX(vb), w, FALSE, FALSE, 2);
	gtk_widget_show(GTK_WIDGET(w));

	/* Advanced information. */
	exp = gtk_expander_new(lang_get("tw-hit-advanced"));
	gtk_box_pack_start(GTK_BOX(vb), exp, FALSE, TRUE, 2);
	gtk_widget_show(GTK_WIDGET(exp));
	
	vb2 = gtk_vbox_new(FALSE, 2);
	gtk_container_add(GTK_CONTAINER(exp), vb2);
	gtk_widget_show(GTK_WIDGET(vb2));

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb2), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));
	
	w = gtk_label_new(lang_get("tw-hit-hit"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "0");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 5);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWR_REMOTE, w);

	w = gtk_label_new(lang_get("tw-hit-port"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "0");
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, TRUE, 5);
	gtk_widget_set_size_request(GTK_WIDGET(w), 90, -1);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
	gtk_entry_set_max_length(GTK_ENTRY(w), MAX_URL_LEN);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWR_PORT, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb2), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));
	
	w = gtk_label_new(lang_get("tw-hit-url"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
//	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "<notset>");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(GTK_ENTRY(w), MAX_URL_LEN);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
//	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWR_URL, w);

	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), lang_get("tw-hit-groupinfo"));
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 5);
	gtk_box_pack_start(GTK_BOX(vb2), frame, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(frame));

	vb2 = gtk_vbox_new(FALSE, 2);
	gtk_container_add(GTK_CONTAINER(frame), vb2);
	gtk_widget_show(GTK_WIDGET(vb2));

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb2), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));
	
	w = gtk_label_new(lang_get("tw-hit-local"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	widget_set(ID_TWLOCAL, w);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWR_LOCAL, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb2), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("tw-hitgroup-type"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type-accept"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type-deny"));
	gtk_combo_box_set_active(GTK_COMBO_BOX(w), 0);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWR_TYPE1, w);

	w = gtk_label_new(lang_get("tw-hitgroup-lightweight"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type2-normal"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type2-lightweight"));
	gtk_combo_box_set_active(GTK_COMBO_BOX(w), 0);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWR_TYPE2, w);

	return 0;
}


/******************************************************************************/
/**
 * Create contents for remote group information.
 *
 * @return 0 on success, -1 on errors.
 */
int _create_edit_group(void)
{
	GtkWidget *frame, *w, *vb, *vb2, *hb, *exp;
	
	/* Create remote group HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), lang_get("tw-group-info"));
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 5);
	gtk_widget_show(GTK_WIDGET(frame));
	widget_set(ID_TWRGROUP, frame);
	g_object_ref(frame);

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(frame), vb);
	gtk_widget_show(GTK_WIDGET(vb));

	/* Now create basic information. */
	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("tw-group-name"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(GTK_ENTRY(w), MAX_NAME_LEN);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWG_NAME, w);

	/* Separator between basic and advanced. */
	w = gtk_hseparator_new();
	gtk_box_pack_start(GTK_BOX(vb), w, FALSE, FALSE, 2);
	gtk_widget_show(GTK_WIDGET(w));

	/* Advanced information. */
	exp = gtk_expander_new(lang_get("tw-group-advanced"));
	gtk_box_pack_start(GTK_BOX(vb), exp, FALSE, TRUE, 2);
	gtk_widget_show(GTK_WIDGET(exp));
	
	vb2 = gtk_vbox_new(FALSE, 2);
	gtk_container_add(GTK_CONTAINER(exp), vb2);
	gtk_widget_show(GTK_WIDGET(vb2));

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb2), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("tw-group-local"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWG_LOCAL, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb2), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));
	
	w = gtk_label_new(lang_get("tw-hitgroup-type"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type-accept"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type-deny"));
	gtk_combo_box_set_active(GTK_COMBO_BOX(w), 0);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWG_TYPE1, w);

	w = gtk_label_new(lang_get("tw-hitgroup-lightweight"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type2-normal"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type2-lightweight"));
	gtk_combo_box_set_active(GTK_COMBO_BOX(w), 0);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWG_TYPE2, w);

	return 0;
}


/******************************************************************************/
/**
 * Create contents of the group/hit edit in here.
 *
 * @return 0 if success, -1 on errors.
 */
int _create_edit(GtkWidget *parent)
{
	GtkWidget *w, *hb, *vb, *iconw;
	int err = 0;

	/* Create remote -tab content. */
	vb = gtk_vbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(parent), vb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(vb));
	widget_set(ID_TW_CONTAINER, vb);

	HIP_IFE(_create_edit_remote(), -1);
	HIP_IFE(_create_edit_group(), -1);

	hb = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(parent), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));
	
	w = gtk_button_new_with_label(lang_get("tw-button-delete"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_DELETE, GTK_ICON_SIZE_MENU);
	gtk_button_set_image(GTK_BUTTON(w), iconw);
	gtk_box_pack_end(GTK_BOX(hb), w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(e_button), (gpointer)IDB_TW_DELETE);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TW_DELETE, w);
	
	w = gtk_button_new_with_label(lang_get("tw-button-cancel"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_CANCEL, GTK_ICON_SIZE_MENU);
	gtk_button_set_image(GTK_BUTTON(w), iconw);
	gtk_box_pack_end(GTK_BOX(hb), w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(e_button), (gpointer)IDB_TW_CANCEL);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TW_CANCEL, w);

	w = gtk_button_new_with_label(lang_get("tw-button-apply"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_APPLY, GTK_ICON_SIZE_MENU);
	gtk_button_set_image(GTK_BUTTON(w), iconw);
	gtk_box_pack_end(GTK_BOX(hb), w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(e_button), (gpointer)IDB_TW_APPLY);
	GTK_WIDGET_SET_FLAGS(w, GTK_CAN_DEFAULT);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TW_APPLY, w);
	
	gtk_widget_show(GTK_WIDGET(parent));

out_err:
	return err;
}


/******************************************************************************/
/**
 * Show GTK status icon.
 */
int _create_status_icon(void)
{
	int err = 0;
#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
	GtkStatusIcon *status_icon;
	GtkWidget *w, *label, *iconw;
	
//	status_icon = gtk_status_icon_new_from_file(HIP_DEBIAN_DIR_PIXMAPS "/hipmanager.png");
	status_icon = gtk_status_icon_new_from_icon_name("hipmanager");
	gtk_status_icon_set_visible(status_icon, TRUE);
	err = !gtk_status_icon_is_embedded(status_icon);
	HIP_DEBUG("Status icon %s.\n", (err ? "is visible" : "could not be shown"));
	
 	/* When user right clicks status icon. */
 	g_signal_connect(status_icon, "popup-menu", G_CALLBACK(e_menu_status_icon), (gpointer)"popup-menu");
 	/* When user double clicks status icon. */
//	g_signal_connect(status_icon, "activate", G_CALLBACK(e_button), (gpointer)IDB_SYSTRAY);
	
	/* Create menu for status icon. */
	w = gtk_menu_new();
	
	label = gtk_image_menu_item_new_with_label(lang_get("systray-show"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_PREFERENCES, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_button), (gpointer)IDM_TRAY_SHOW);
	gtk_widget_show(GTK_WIDGET(label));
	
	label = gtk_image_menu_item_new_with_label(lang_get("systray-exec"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_EXECUTE, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_button), (gpointer)IDM_TRAY_EXEC);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
	gtk_widget_show(GTK_WIDGET(label));
	
	label = gtk_image_menu_item_new_with_label(lang_get("systray-about"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_ABOUT, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_button), (gpointer)IDM_TRAY_ABOUT);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_image_menu_item_new_with_label(lang_get("systray-exit"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_CLOSE, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_button), (gpointer)IDM_TRAY_EXIT);
	gtk_widget_show(GTK_WIDGET(label));
	
	widget_set(ID_SYSTRAYMENU, w);
#endif

out_err:
	return err;
}

/******************************************************************************/
/**
 * Setup remote HITs.
 */
int _create_remote_list(GtkWidget *parent)
{
	GtkWidget *pane, *label, *list, *scroll, *w;
	GtkTreeViewColumn *column;
	GtkCellRenderer *cell;
	GtkTreeSelection *select;
	GtkTreeStore *model;
	int err = 0;

	pane = gtk_hpaned_new();
	label = gtk_label_new(lang_get("tabs-hits"));
	gtk_notebook_append_page(GTK_NOTEBOOK(parent), pane, label);
	gtk_widget_show(GTK_WIDGET(pane));
	
	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(1, G_TYPE_STRING);

	list = gtk_tree_view_new();
	/* This signal occurs when user double clicks item in list. */
//	g_signal_connect(list, "row-activated", G_CALLBACK(e_row_activated), (gpointer)"remote-hit-list");
	/* Check when user changes selection in list. */
	g_signal_connect(list, "cursor-changed", G_CALLBACK(e_cursor_changed), (gpointer)"remote-hit-list");
	/* This could be used to example popup a menu when user click right mouse button. */
// 	g_signal_connect(list, "button-press-event", G_CALLBACK(e_button_press), (gpointer)"remote-hit-list");
	widget_set(ID_RLISTVIEW, list);
	
	/* Setup list for dragndrop. */
	{
		GtkTargetEntry dndtarget;
		dndtarget.target = "hit";
		dndtarget.flags = GTK_TARGET_SAME_APP;
		dndtarget.info = 0;
		gtk_tree_view_enable_model_drag_source(GTK_TREE_VIEW(list), GDK_MODIFIER_MASK, &dndtarget, 1,
											GDK_ACTION_MOVE | GDK_ACTION_COPY | GDK_ACTION_ASK);
		dndtarget.info = 1;
		gtk_tree_view_enable_model_drag_dest(GTK_TREE_VIEW(list), &dndtarget, 1,
											GDK_ACTION_MOVE | GDK_ACTION_COPY | GDK_ACTION_ASK);
		g_signal_connect(list, "drag_begin", G_CALLBACK(dnd_drag_begin), (gpointer)0);
		g_signal_connect(list, "drag_motion", G_CALLBACK(dnd_drag_motion), (gpointer)0);
		g_signal_connect(list, "drag_data_get", G_CALLBACK(dnd_drag_data_get), (gpointer)0);
		g_signal_connect(list, "drag_data_delete", G_CALLBACK(dnd_drag_data_delete), (gpointer)0);
		g_signal_connect(list, "drag_drop", G_CALLBACK(dnd_drag_drop), (gpointer)0);
		g_signal_connect(list, "drag_end", G_CALLBACK(dnd_drag_end), (gpointer)0);
		g_signal_connect(list, "drag_data_received", G_CALLBACK(dnd_drag_data_received), (gpointer)0);
	}

	gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(model));
	column = gtk_tree_view_column_new();
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));
	
	cell = gtk_cell_renderer_pixbuf_new();
	gtk_tree_view_column_pack_start(GTK_TREE_VIEW_COLUMN(column), GTK_CELL_RENDERER(cell), FALSE);
	gtk_tree_view_column_set_cell_data_func(GTK_TREE_VIEW_COLUMN(column), GTK_CELL_RENDERER(cell), e_cell_data_func, NULL, NULL);
	
	cell = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(GTK_TREE_VIEW_COLUMN(column), GTK_CELL_RENDERER(cell), TRUE);
	gtk_tree_view_column_set_attributes(GTK_TREE_VIEW_COLUMN(column), GTK_CELL_RENDERER(cell), "text", 0, NULL);
	
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_widget_set_size_request(GTK_WIDGET(scroll), 200, 0);
	gtk_paned_add1(GTK_PANED(pane), scroll);
	select = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);
	gtk_widget_show(GTK_WIDGET(list));
	gtk_widget_show(GTK_WIDGET(scroll));
	
	/* Create box where remote editing widgets are added. */
	w = gtk_vbox_new(FALSE, 0);
	gtk_widget_show(GTK_WIDGET(w));
	gtk_paned_add2(GTK_PANED(pane), w);
	gtk_widget_show(GTK_WIDGET(w));
	/* Create and add widgets to remote editing. */
	HIP_IFE(_create_edit(GTK_WIDGET(w)), -1);

	widget_set(ID_RLISTMODEL, model);
	widget_set(ID_REMOTEPANE, pane);

out_err:
	return err;
}


/******************************************************************************/
/**
 * Setup menubar.
 */
int _create_menubar(GtkWidget *parent)
{
	GtkWidget *menubar, *w, *w2, *w3, *label, *iconw;
	int err = 0;

	/* Create menubar. */
	menubar = gtk_menu_bar_new();
	gtk_box_pack_start(GTK_BOX(parent), menubar, FALSE, FALSE, 0);
	gtk_widget_show(GTK_WIDGET(menubar));
	
	/* File-menu. */
	w = gtk_menu_item_new_with_label(lang_get("menu-file"));
	gtk_widget_show(GTK_WIDGET(w));
	w2 = gtk_menu_new();
	
	label = gtk_image_menu_item_new_with_label(lang_get("menu-file-runapp"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_EXECUTE, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_button), (gpointer)IDM_RUNAPP);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_image_menu_item_new_with_label(lang_get("menu-file-exit"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_CLOSE, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_destroy_main), (gpointer)"exit");
	gtk_widget_show(GTK_WIDGET(label));

	gtk_menu_item_set_submenu(GTK_MENU_ITEM(w), w2);
	gtk_menu_bar_append(GTK_MENU_BAR(menubar), w);

	/* Edit-menu. */
	w = gtk_menu_item_new_with_label(lang_get("menu-edit"));
	gtk_widget_show(GTK_WIDGET(w));
	w2 = gtk_menu_new();

	label = gtk_image_menu_item_new_with_label(lang_get("menu-edit-newgroup"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_NEW, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_button), (gpointer)IDM_NEWGROUP);
	gtk_widget_show(GTK_WIDGET(label));

	label = gtk_image_menu_item_new_with_label(lang_get("menu-edit-addhit"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_ADD, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_button), (gpointer)IDM_NEWHIT);
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
	gtk_menu_bar_append(GTK_MENU_BAR(menubar), w);

	
	/* Tools-menu. */
	w = gtk_menu_item_new_with_label(lang_get("menu-help"));
	gtk_widget_show(GTK_WIDGET(w));
	w2 = gtk_menu_new();
	
	label = gtk_image_menu_item_new_with_label(lang_get("menu-help-about"));
	iconw = gtk_image_new_from_stock(GTK_STOCK_ABOUT, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(label), iconw);
	gtk_menu_shell_append(GTK_MENU_SHELL(w2), label);
	g_signal_connect(label, "activate", G_CALLBACK(e_button), (gpointer)IDM_ABOUT);
	gtk_widget_show(GTK_WIDGET(label));


	gtk_menu_item_set_submenu(GTK_MENU_ITEM(w), w2);
	gtk_menu_bar_append(GTK_MENU_BAR(menubar), w);

out_err:
	return err;
}


/******************************************************************************/
/**
	Create contents of the gui in here.

	@return 0 if success, -1 on errors.
*/
int create_content_main(void)
{
	GtkWidget *window = (GtkWidget *)widget(ID_MAINWND);
	GtkWidget *pane, *notebook, *w;
	int err = 0;

	gtk_container_set_border_width(GTK_CONTAINER(window), 3);

	/* Create status icon. */
	HIP_IFE(!_create_status_icon(), -1);

	/* Create main pain. */
	pane = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(window), pane);
	gtk_widget_show(GTK_WIDGET(pane));

	/* Create menubar. */
	HIP_IFE(_create_menubar(pane), -1);

	/* Create tabbed notebook. */
	notebook = gtk_notebook_new();
	gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
	gtk_box_pack_start(GTK_BOX(pane), notebook, TRUE, TRUE, 0);
	gtk_widget_show(GTK_WIDGET(notebook));

	/* Create status bar. */
	w = gtk_statusbar_new();
	gtk_box_pack_end(GTK_BOX(pane), w, FALSE, FALSE, 0);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_STATUSBAR, w);

	/* Create tabs. */
	HIP_IFE(_create_remote_list(notebook), -1);
	
	/* Set default page and show notebook. */
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);
	gtk_widget_show(GTK_WIDGET(notebook));

out_err:
	return err;
}


/******************************************************************************/
/**
 * Create contents for local HIT information dialog.
 *
 * @return 0 on success, -1 on errors.
 */
int create_content_local_edit(void)
{
	GtkWidget *window = (GtkWidget *)widget(ID_LOCALDLG);
	GtkWidget *frame, *w, *vb, *hb;

	/* Create local HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), lang_get("lh-info"));
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 5);
	gtk_widget_show(GTK_WIDGET(frame));
	widget_set(ID_TWLOCAL, frame);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), widget(ID_TWLOCAL), FALSE, FALSE, 1);
	g_object_ref(frame);

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(frame), vb);
	gtk_widget_show(GTK_WIDGET(vb));

	/* Now create basic information. */
	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("lh-name"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(GTK_ENTRY(w), MAX_NAME_LEN);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWL_NAME, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("lh-hit"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "0");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 5);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_TWL_LOCAL, w);

	return 0;
}


/******************************************************************************/
/**
 * Create message-dialog contents.
 *
 * @return 0 if success, -1 on errors.
 */
int create_content_msgdlg(void)
{
	GtkWidget *window = (GtkWidget *)widget(ID_MSGDLG);
	GtkWidget *b, *w;

	gtk_window_set_icon_name(GTK_WINDOW(window), (char *)GTK_STOCK_DIALOG_QUESTION);
	
	/* This box is for adding everything inside previous frame. */
	b = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), b, TRUE, TRUE, 0);
	gtk_widget_show(GTK_WIDGET(b));
	
	w = gtk_image_new_from_stock(GTK_STOCK_DIALOG_QUESTION, GTK_ICON_SIZE_DIALOG);
	gtk_box_pack_start(GTK_BOX(b), w, FALSE, FALSE, 0);
	gtk_widget_show(GTK_WIDGET(w));
	
	w = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(b), w, TRUE, TRUE, 0);
	widget_set(ID_MSGDLG_MSG, w);
	gtk_widget_show(GTK_WIDGET(w));

	/* Add buttons to dialog. */
	w = gtk_dialog_add_button(GTK_DIALOG(window), lang_get("msgdlg-button-ok"), GTK_RESPONSE_OK);
	gtk_widget_grab_default(GTK_WIDGET(w));
	gtk_dialog_add_button(GTK_DIALOG(window), lang_get("msgdlg-button-cancel"), GTK_RESPONSE_CANCEL);

	return 0;
}


/******************************************************************************/
/**
 * Create new group -dialog contents.
 *
 * @return 0 if success, -1 on errors.
 */
int create_content_ngdlg(void)
{
	GtkWidget *window = (GtkWidget *)widget(ID_NGDLG);
	GtkWidget *hb, *w, *vb;

	gtk_container_set_border_width(GTK_CONTAINER(window), 3);

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), vb, TRUE, TRUE, 3);
	gtk_widget_show(GTK_WIDGET(vb));
	
	hb = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(vb), hb, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("ngdlg-name"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(GTK_ENTRY(w), 64);
	gtk_widget_show(GTK_WIDGET(w));
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
	widget_set(ID_NG_NAME, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));
	
	w = gtk_label_new(lang_get("ngdlg-localhit"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NG_LOCAL, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));
	
	w = gtk_label_new(lang_get("ngdlg-type"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type-accept"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type-deny"));
	gtk_combo_box_set_active(GTK_COMBO_BOX(w), 0);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NG_TYPE1, w);

	w = gtk_label_new(lang_get("ngdlg-type2"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type2-normal"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type2-lightweight"));
	gtk_combo_box_set_active(GTK_COMBO_BOX(w), 0);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NG_TYPE2, w);

	/* Add buttons to dialog. */
	w = gtk_dialog_add_button(GTK_DIALOG(window), lang_get("ngdlg-button-create"), GTK_RESPONSE_OK);
	gtk_widget_grab_default(GTK_WIDGET(w));
	gtk_dialog_add_button(GTK_DIALOG(window), lang_get("ngdlg-button-cancel"), GTK_RESPONSE_CANCEL);

	return 0;
}


/******************************************************************************/
/**
 * Create new hit -dialog contents.
 *
 * @return 0 if success, -1 on errors.
 */
int create_content_nhdlg(void)
{
	GtkWidget *window = (GtkWidget *)widget(ID_NHDLG);
	GtkWidget *frame, *w, *vb, *vb1, *vb2, *sw, *hb, *hp, *exp;

	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* Create remote HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), lang_get("nhdlg-newinfo"));
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 5);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), frame, TRUE, TRUE, 3);
	gtk_widget_show(GTK_WIDGET(frame));

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(frame), vb);
	gtk_widget_show(GTK_WIDGET(vb));

	/* Now create basic information. */
	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb), hb, FALSE, FALSE, 3);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("nhdlg-newhit"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 3);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 3);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NH_HIT, w);
	gtk_tooltips_set_tip(widget(ID_TOOLTIPS), w,
                         lang_get("nhdlg-tt-hit"),
                         lang_get("nhdlg-tt-hit-priv"));

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb), hb, FALSE, FALSE, 3);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("nhdlg-name"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 3);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 3);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
	gtk_entry_set_max_length(GTK_ENTRY(w), MAX_NAME_LEN);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NH_NAME, w);

	w = gtk_label_new(lang_get("nhdlg-group"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 3);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	g_signal_connect(w, "changed", G_CALLBACK(e_button), (gpointer)IDB_NH_RGROUPS);
	widget_set(ID_NH_RGROUP, w);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 3);
	gtk_widget_show(GTK_WIDGET(w));

	/* Separator between basic and advanced. */
	w = gtk_hseparator_new();
	gtk_box_pack_start(GTK_BOX(vb), w, FALSE, FALSE, 2);
	gtk_widget_show(GTK_WIDGET(w));

	/* Advanced information. */
	exp = gtk_expander_new(lang_get("nhdlg-advanced"));
	gtk_box_pack_start(GTK_BOX(vb), exp, FALSE, TRUE, 2);
	gtk_widget_show(GTK_WIDGET(exp));
	widget_set(ID_NH_EXPANDER, exp);
	g_signal_connect(exp, "activate", G_CALLBACK(e_button), (gpointer)IDB_NH_EXPANDER);
	g_signal_connect(exp, "check-resize", G_CALLBACK(e_button), (gpointer)IDB_NH_EXPANDER);

	vb2 = gtk_vbox_new(FALSE, 2);
	gtk_container_add(GTK_CONTAINER(exp), vb2);
	gtk_widget_show(GTK_WIDGET(vb2));

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb2), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));

/*	w = gtk_label_new(lang_get("nhdlg-url"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(GTK_ENTRY(w), MAX_URL_LEN);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NH_URL, w);*/

/*	w = gtk_label_new(lang_get("nhdlg-port"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(w), "0");
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, TRUE, 5);
	gtk_widget_set_size_request(GTK_WIDGET(w), 70, -1);
	gtk_entry_set_max_length(GTK_ENTRY(w), 8);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NH_PORT, w);*/

	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), lang_get("nhdlg-g-info"));
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 5);
	gtk_box_pack_start(GTK_BOX(vb2), frame, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(frame));

	vb2 = gtk_vbox_new(FALSE, 2);
	gtk_container_add(GTK_CONTAINER(frame), vb2);
	gtk_widget_show(GTK_WIDGET(vb2));

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb2), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("nhdlg-g-localhit"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NH_LOCAL, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vb2), hb, FALSE, FALSE, 1);
	gtk_widget_show(GTK_WIDGET(hb));

	w = gtk_label_new(lang_get("nhdlg-g-type"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type-accept"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type-deny"));
	gtk_combo_box_set_active(GTK_COMBO_BOX(w), 0);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NH_TYPE1, w);

	w = gtk_label_new(lang_get("nhdlg-g-lightweight"));
	gtk_box_pack_start(GTK_BOX(hb), w, FALSE, FALSE, 5);
	gtk_widget_show(GTK_WIDGET(w));
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type2-normal"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(w), lang_get("group-type2-lightweight"));
	gtk_combo_box_set_active(GTK_COMBO_BOX(w), 0);
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(GTK_WIDGET(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_NH_TYPE2, w);

	return 0;
}


/******************************************************************************/
/**
 * Create execute-dialog contents.
 *
 * @return 0 if success, -1 on errors.
 */
int create_content_execdlg(void)
{
	GtkWidget *window = (GtkWidget *)widget(ID_EXECDLG);
	GtkWidget *hbox, *w, *vbox;

	gtk_container_set_border_width(GTK_CONTAINER(window), 3);

	/* Create main widget for adding subwidgets to window. */
	vbox = gtk_vbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), vbox, TRUE, TRUE, 3);
	gtk_widget_show(GTK_WIDGET(vbox));

	/* Create command-input widget. */
	hbox = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 3);
	gtk_widget_show(GTK_WIDGET(hbox));
	w = gtk_label_new("Command:");
	gtk_widget_show(GTK_WIDGET(w));
	gtk_box_pack_start(GTK_BOX(hbox), w, FALSE, TRUE, 1);
	w = gtk_entry_new();
	widget_set(ID_EXEC_COMMAND, w);
	gtk_entry_set_text(GTK_ENTRY(w), "firefox");
	gtk_box_pack_start(GTK_BOX(hbox), w, FALSE, TRUE, 1);
	gtk_widget_show(GTK_WIDGET(w));
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);

	/* Create opportunistic environment option. */
	w = gtk_check_button_new_with_label("Use opportunistic mode");
	gtk_box_pack_start(GTK_BOX(vbox), w, FALSE, FALSE, 1);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), FALSE);
	gtk_widget_show(GTK_WIDGET(w));
	widget_set(ID_EXEC_OPP, w);
	
	/* Add buttons to dialog. */
	w = gtk_dialog_add_button(GTK_DIALOG(window), "Run", GTK_RESPONSE_OK);
	gtk_widget_grab_default(GTK_WIDGET(w));
	gtk_dialog_add_button(GTK_DIALOG(window), "Cancel", GTK_RESPONSE_CANCEL);

	return 0;
}


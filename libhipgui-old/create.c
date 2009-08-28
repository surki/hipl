/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "create.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
 * Create "new remote group"-dialog contents.
 *
 * @return 0 if success, -1 on errors.
 */
int ngdlg_create_content(void)
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

	return (0);
}


/******************************************************************************/
/**
 * Create message-dialog contents.
 *
 * @return 0 if success, -1 on errors.
 */
int msgdlg_create_content(void)
{
	GtkWidget *window = (GtkWidget *)widget(ID_MSGDLG);
	GtkWidget *vb, *w;

	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), vb, FALSE, FALSE, 0);
	gtk_widget_show(GTK_WIDGET(vb));
	
	w = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(vb), w, FALSE, FALSE, 0);
	widget_set(ID_MSGDLG_MSG, w);
	gtk_widget_show(GTK_WIDGET(w));

	/* Add buttons to dialog. */
	w = gtk_dialog_add_button(GTK_DIALOG(window), lang_get("msgdlg-button-ok"), GTK_RESPONSE_OK);
	gtk_widget_grab_default(GTK_WIDGET(w));
	gtk_dialog_add_button(GTK_DIALOG(window), lang_get("msgdlg-button-cancel"), GTK_RESPONSE_CANCEL);

	return 0;
}



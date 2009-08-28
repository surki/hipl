/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "nh.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Create contents of the accept dialog in here.

	@return 0 if success, -1 on errors.
*/
int nhdlg_create_content(void)
{
	/* Variables. */
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
	g_signal_connect(w, "changed", G_CALLBACK(button_event), (gpointer)IDB_NH_RGROUPS);
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
	g_signal_connect(exp, "activate", G_CALLBACK(button_event), (gpointer)IDB_NH_EXPANDER);
	g_signal_connect(exp, "check-resize", G_CALLBACK(button_event), (gpointer)IDB_NH_EXPANDER);

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

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "exec.h"


/******************************************************************************/
/* DEFINES */


/******************************************************************************/
/* VARIABLES */


/******************************************************************************/
/* FUNCTIONS */

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


/******************************************************************************/
/**
	Create execute-dialog contents.

	@return 0 if success, -1 on errors.
*/
int execdlg_create_content(void)
{
	/* Variables. */
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

	return (0);
}


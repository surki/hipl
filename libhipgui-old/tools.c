/*
    DNET - Duge's Networking Library

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "tools.h"


/******************************************************************************/
/* VARIABLES */
char nickname[MAX_NAME_LEN + 1];


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** Get current nickname. */
char *get_nick(void)
{
	return (nickname);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set current nickname. */
void set_nick(char *newnick)
{
	NAMECPY(nickname, newnick);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Find index of given named item from combo box.

	@param name Name of item to search.
	@param warg Pointer to GtkWidget type combo box.
	@return Index of item, or -1 if not found.
*/
int find_from_cb(char *name, GtkWidget *warg)
{
	/* Variables. */
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
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete all items from combo box.

	@param warg Pointer to GtkWidget type combo box.
 */
void delete_all_items_from_cb(GtkWidget *warg)
{
	/* Variables. */
	GtkTreeModel *model;
	GtkTreeIter iter;

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(warg));
	if (gtk_tree_model_get_iter_first(model, &iter) == TRUE)
	{
		while (gtk_list_store_remove(GTK_LIST_STORE(model), &iter) != FALSE);
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** Check group name. */
int check_group_name(char *name, HIT_Group *ge)
{
	/* Variables. */
	HIT_Group *g;
	int i, err = 1;
	char *msg = lang_get("ngdlg-err-invalid");
	char *pch;

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
	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Check hit name. */
int check_hit_name(char *name, HIT_Remote *re)
{
	/* Variables. */
	HIT_Remote *r;
	int i, err = 1;
	char *msg = lang_get("nhdlg-err-invalid");
	char *pch;

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
	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Check local hit name. */
int check_lhit_name(char *name, HIT_Local *le)
{
	/* Variables. */
	HIT_Local *l;
	int i, err = 1;
	char *msg = lang_get("lhdlg-err-invalid");
	char *pch;

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
	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Check apply for group. */
int check_apply_group(char *name, HIT_Group *ge)
{
	/* Variables. */
	GtkDialog *dialog;
	int err = 0;
	
	err = message_dialog(lang_get("ask-apply-group"));

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Check apply for hit. */
int check_apply_hit(char *name, HIT_Remote *re)
{
	/* Variables. */
	GtkDialog *dialog;
	int err = 0;

	err = message_dialog(lang_get("ask-apply-hit"));

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Check apply hit move. */
int check_apply_hit_move(char *name, HIT_Remote *re)
{
	/* Variables. */
	GtkDialog *dialog;
	int err = 0;

	err = message_dialog(lang_get("ask-apply-hit-move"));

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
 * Show message dialog.
 * 
 * @param msg Message to be shown in dialog.
 * @return 1 if user selected "ok"-button, 0 if user selected "cancel"-button.
 */
int message_dialog(char *msg)
{
	/* Variables. */
	GtkDialog *dialog = (GtkDialog *)widget(ID_MSGDLG);
	GtkWidget *label = (GtkWidget *)widget(ID_MSGDLG_MSG);
	int err = 0;
	
	gtk_label_set_text(GTK_LABEL(label), msg);
	gtk_widget_show(GTK_WIDGET(dialog));
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	err = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_hide(GTK_WIDGET(dialog));
	if (err == GTK_RESPONSE_OK) err = 1;
	else err = 0;
	
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


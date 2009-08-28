/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "hipstart.h"


/******************************************************************************/
/* VARIABLES */
const char *start_info =
	"Here is a list of predefined HIP hosts. "
	"Select one by double clicking it to continue executing "
	"HIP daemon and agent/GUI if selected.";

Host_item host_items[MAX_HOST_ITEMS];
int host_items_n = 0;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Execute new application.

	@param exe Executable name.
	@return Return 0 on success, -1 on errors.
*/
int exec_application(char *exe, ...)
{
	/* Variables. */
	va_list args;
	int err = 0;

	if (strlen(exe) > 0) err = fork();
	else err = -1;

	if (err < 0) HIP_DEBUG("Failed to exec new application.\n");
	else if (err > 0) err = 0;
	else if(err == 0)
	{
		HIP_DEBUG("Exec new application.\n");
		va_start(args, exe);
		err = execvp(exe, args);
		if (err != 0)
		{
			HIP_DEBUG("Executing new application failed!\n");
			exit(1);
		}
	}

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	What to do when user example tries to close the application?

	@return TRUE if don't close or FALSE if close.
*/
gboolean main_delete_event(GtkWidget *w, GdkEvent *event, gpointer data)
{
	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On window destroy. */
void main_destroy(GtkWidget *w, gpointer data)
{
	gtk_main_quit();
}
/* END OF FUNCTION */


/******************************************************************************/
/** Create GUI. */
int gui_init(void)
{
	/* Variables. */
	GtkWidget *w, *window, *box, *scroll, *list;
	GtkTreeStore *model;
	GtkCellRenderer *cell;
	GtkTreeViewColumn *column;
	GtkTreeSelection *select;
	int err = 0;

	/* Initialize libraries. */
	gtk_init(NULL, NULL);
	widget_init();

	/* Initialize libraries. */
	gtk_init(NULL, NULL);
	widget_init();

	/* Create main GUI window. */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	widget_set(ID_HS_MAIN, window);
	gtk_widget_show(window);
	gtk_window_set_title(window, "HIP start");
	gtk_container_set_border_width(window, 10);
	g_signal_connect(window, "delete_event", G_CALLBACK(main_delete_event), NULL);
	g_signal_connect(window, "destroy", G_CALLBACK(main_destroy), NULL);

	/* Create contents. */
	box = gtk_vbox_new(FALSE, 5);
	gtk_container_add(window, box);
	gtk_widget_show(box);

	/* Create info. */
	w = gtk_label_new(start_info);
	gtk_label_set_line_wrap(w, TRUE);
	gtk_box_pack_start(box, w, FALSE, FALSE, 1);
	gtk_widget_show(w);

	/* Create agent execute option. */
	w = gtk_check_button_new_with_label("execute agent/GUI");
	gtk_box_pack_start(box, w, FALSE, FALSE, 1);
	gtk_toggle_button_set_active(w, TRUE);
	gtk_widget_show(w);
	widget_set(ID_HS_EXECAGENT, w);
	w = gtk_check_button_new_with_label("clear agent database file (/etc/hip/agentdb)");
	gtk_box_pack_start(box, w, FALSE, FALSE, 1);
	gtk_toggle_button_set_active(w, TRUE);
	gtk_widget_show(w);
	widget_set(ID_HS_CLEARDB, w);
	/* Create server/client execute option. */
	w = gtk_check_button_new_with_label("run server/client in agent");
	gtk_box_pack_start(box, w, FALSE, FALSE, 1);
	gtk_toggle_button_set_active(w, TRUE);
	gtk_widget_show(w);
	widget_set(ID_HS_EXECSERVER, w);

	/* Create host list. */
	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(1, G_TYPE_STRING);


	list = gtk_tree_view_new();
	g_signal_connect(list, "row-activated", G_CALLBACK(list_select), (gpointer)"list");
	widget_set(ID_HS_VIEW, list);
	gtk_tree_view_set_model(list, model);
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Name", cell, "text", 0, NULL);
	gtk_tree_view_append_column(list, column);

	gtk_scrolled_window_add_with_viewport(scroll, list);
	gtk_widget_set_size_request(scroll, 200, 0);
	gtk_box_pack_start(box, scroll, TRUE, TRUE, 1);
	select = gtk_tree_view_get_selection(list);
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);
	gtk_widget_show(list);
	gtk_widget_show(scroll);
	widget_set(ID_HS_MODEL, model);

	gtk_window_resize(window, 100, 260);

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On list select. */
gboolean list_select(void *w1, void *w2, void *w3, void *w4)
{
	/* Variables. */
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	FILE *f;
	char str[2048];
	int b, s, err, *indices, n, i;

	selection = gtk_tree_view_get_selection(w1);

	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		/* Get values for the path. */
		indices = gtk_tree_path_get_indices(w2);
		n = indices[0];

		HIP_DEBUG("Selected host: \"%s\"\n", host_items[n].name);

		b = gtk_toggle_button_get_active(widget(ID_HS_EXECAGENT));
		if (b == TRUE && gtk_toggle_button_get_active(widget(ID_HS_CLEARDB)) == TRUE)
		{
			f = fopen("/etc/hip/agentdb", "w");
			fclose(f);
		}
		
		s = gtk_toggle_button_get_active(widget(ID_HS_EXECSERVER));

		/* Copy right identity files to /etc/hip. */
		sprintf(str, "cp -f %s/hip_host_* /etc/hip/", host_items[n].path);
		system(str);

		/* Change right inet6 address to eth0. */
		for (i = 0; i < host_items_n; i++)
		{
			sprintf(str, "ifconfig eth0 inet6 del %s", host_items[i].addr);
			system(str);
		}
		sprintf(str, "ifconfig eth0 inet6 add %s", host_items[n].addr);
		system(str);

		/* Execute daemon. */
		err = exec_application("xterm", "xterm", "-T", "HIP daemon", "-e", "hipd", NULL);
		
		/* Execute agent as server, client or plain. */
		if (b == TRUE)
		{
			if (s == TRUE)
			{
				if (host_items[n].server) exec_application("hipagent", "hipagent", "-server", NULL);
				else exec_application("hipagent", "hipagent", "-client", "hip3", NULL);
			}
			else exec_application("hipagent", "hipagent", NULL);
		}

		/* Quit application. */
		gtk_main_quit();
	}

	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Add one new host to list. */
void host_add(char *name)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;

	w = widget(ID_HS_MODEL);
	gtk_tree_store_insert(w, &iter, NULL, 999);
	gtk_tree_store_set(w, &iter, 0, name, -1);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Read settings from file. */
int settings_read(char *file)
{
	/* Variables. */
	FILE *f;
	char str[2048], server;
	char name[MAX_NAME_LEN + 1], path[MAX_URL_LEN + 1], addr[MAX_URL_LEN + 1];
	int err = 0, i, n;

	HIP_DEBUG("Loading settings from %s.\n", file);

	f = fopen(file, "r");
	HIP_IFEL(!f, -1, "Failed to open settings file \"%s\" for reading!\n", file);

	n = 0;
	while (fgets(str, 2048, f) && n < MAX_HOST_ITEMS)
	{
		i = sscanf(str, "\"%64[^\"]\" %64s %1024s %c", name, addr, path, &server);
		if (i != 4) continue;
		NAMECPY(host_items[n].name, name);
		NAMECPY(host_items[n].addr, addr);
		URLCPY(host_items[n].path, path);
		host_items[n].server = (server == 's') ? 1 : 0;
		host_add(name);
		n++;
	}

	HIP_IFEL(n < 1, -1, "Settings file is empty!\n");
	host_items_n = n;

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Execute new application. */
int main(void)
{
	/* Variables. */
	int err = 0;
	char str[320];
	
	HIP_IFEL(gui_init() < 0, -1, "Failed to initialize GUI!\n");
	sprintf(str, "%s/hipstart.conf", HIP_GUI_DATADIR);
	HIP_IFE(settings_read(str), -1);

	gtk_main();

out_err:
	widget_quit();
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


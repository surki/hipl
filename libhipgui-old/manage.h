/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_MANAGE_H
#define GUI_MANAGE_H


/******************************************************************************/
/* INCLUDES */
#include "main.h"
#include "hit_db.h"
#include "widgets.h"

/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* STRUCTS */

/** Structure for tree update function. */
typedef struct
{
	char old_name[MAX_NAME_LEN + 1];
	char new_name[MAX_NAME_LEN + 1];
	int depth;
	int indices_first;
} Update_data;


/******************************************************************************/
/* FUNCTION DEFINITIONS */
void gui_add_local_hit(HIT_Local *);
void gui_add_rgroup(HIT_Group *);

void gui_add_remote_hit(char *, char *);
void gui_delete_remote_hit(char *);
void gui_delete_rgroup(char *);

void gui_add_process(int, char *, int, int);

gboolean gui_update_tree_value(GtkTreeModel *, GtkTreePath *,
                               GtkTreeIter *, gpointer);
gboolean gui_update_list_value(GtkTreeModel *, GtkTreePath *,
                               GtkTreeIter *, gpointer);

int gui_ask_new_hit(HIT_Remote *, int);

void gui_set_nof_hui(int);
void gui_clear_hiu(void);
void gui_add_hiu(HIT_Remote *hit);

int tooldlg_add_rgroups(HIT_Group *, void *);
int tooldlg_add_lhits(HIT_Remote *, void *);
int askdlg_add_rgroups(HIT_Group *, void *);
int askdlg_add_lhits(HIT_Remote *, void *);

int create_remote_group(char *);
void *create_remote_group_thread(void *);

int all_add_local(HIT_Local *, void *);
void all_update_local(char *, char *);
void all_update_rgroups(char *, char *);

void about(void);

void opt_handle_action(GtkWidget *, int);

void hip_gui_update_nat_safe(int);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/


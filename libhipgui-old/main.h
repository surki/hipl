/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_MAIN_H
#define GUI_MAIN_H

/******************************************************************************/
/* INCLUDES */
#include <gtk/gtk.h>

#include "events.h"
#include "nh.h"
#include "tw.h"
#include "widgets.h"
#include "str_var.h"
#include "language.h"
#include "rhit_dnd.h"


/******************************************************************************/
/* DEFINES */
#define HIP_DEBIAN_DIR_PIXMAPS "/usr/share/pixmaps/"
#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
#else
#define GTK_STOCK_ORIENTATION_PORTRAIT GTK_STOCK_FILE
#endif

/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* FUNCTION DEFINITIONS */

/* file: main.c */
int gui_init(void);
int gui_main(void);
void gui_quit(void);
void gui_set_info(const char *, ...);
void gui_set_info_safe(const char *, ...);
void gui_terminate(void);

/* file: main_create.c */
int main_create_content(void);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/


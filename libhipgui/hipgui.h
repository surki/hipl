/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

#ifndef _GUIAPI_H
#define _GUIAPI_H

/******************************************************************************/
/* INCLUDES */
#include <stdlib.h>
#include <string.h>

#include "hitdb.h"
#include "widgets.h"
#include "tools.h"
#include "events.h"


/******************************************************************************/
/* DEFINES */
#define HIP_DEBIAN_DIR_PIXMAPS "/usr/share/pixmaps/"
#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
#else
#define GTK_STOCK_ORIENTATION_PORTRAIT GTK_STOCK_FILE
#endif


/******************************************************************************/
/* FUNCTION DEFINITIONS */

/*!
 * \addtogroup libhipgui
 * @{
 */

/* Basic funtions. */
int gui_init(void);
void gui_main(void);
void gui_quit(void);

/* About HITs. */
int gui_hit_remote_ask(HIT_Remote *, int);
void gui_hit_remote_add(const char *, const char *);
void gui_hit_remote_del(const char *, const char *);
void gui_group_remote_add(const char *);
void gui_group_remote_del(const char *);
void gui_hit_local_add(HIT_Local *);

/* Status update. */
void gui_set_info(const char *, ...);
void gui_update_nat(int);

/* HITs in use. */
void gui_hiu_clear(void);
void gui_hiu_add(HIT_Remote *);
void gui_hiu_count(int);

/*! @} addtogroup libhipgui */


#endif /* END OF HEADER FILE */
/******************************************************************************/


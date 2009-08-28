/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_WIDGETS_H
#define GUI_WIDGETS_H

#include "ife.h"

/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* DEFINES */
enum WIDGET_IDS
{
	/* Windows. */
	ID_MAINWND = 0,
	ID_TOOLWND,
	ID_LTOOLWND,
	ID_NHDLG,
	ID_EXECDLG,
	ID_NGDLG,
	ID_MSGDLG,
	ID_ABOUTDLG,
 
	/* Main window IDs. */
	ID_RLISTMODEL,
	ID_RLISTVIEW,
	ID_STATUSBAR,
	ID_TOOLBAR,
	ID_PLISTMODEL,
	ID_PLISTVIEW,
	ID_PHIUMODEL,
	ID_PHIUVIEW,
	ID_TERMSCREEN,
	ID_TERMINPUT,
	ID_TERMBUFFER,
	ID_TERMSEND,
	ID_USERVIEW,
	ID_USERMODEL,
	ID_TB_TW,
	ID_HIUNUM,
	ID_REMOTEPANE,
	ID_LOCALPANE,

	/* Tool dialog IDs. */
	ID_TW_CONTAINER,
	ID_TWLOCAL,
	ID_TWREMOTE,
	ID_TWRGROUP,
	ID_TWR_NAME,
	ID_TWR_URL,
	ID_TWR_PORT,
	ID_TWR_TYPE1,
	ID_TWR_TYPE2,
	ID_TWR_LOCAL,
	ID_TWR_RGROUP,
	ID_TWR_REMOTE,
	ID_TWG_NAME,
	ID_TWG_LOCAL,
	ID_TWG_TYPE1,
	ID_TWG_TYPE2,
	ID_TWG_LW,
	ID_TWL_CONTAINER,
	ID_TWL_NAME,
	ID_TWL_LOCAL,
	ID_TW_APPLY,
	ID_TW_CANCEL,
	ID_TW_DELETE,

	/* Options. */
	ID_OPT_NAT,

	/* New hit dialog IDs. */
	ID_NH_HIT,
	ID_NH_RGROUP,
	ID_NH_NAME,
	ID_NH_URL,
	ID_NH_PORT,
	ID_NH_LOCAL,
	ID_NH_TYPE1,
	ID_NH_TYPE2,
	ID_NH_EXPANDER,

	/* Exec dialog IDs. */
	ID_EXEC_COMMAND,
	ID_EXEC_OPP,

	/* New group dialog IDs. */
	ID_NG_NAME,
	ID_NG_LOCAL,
	ID_NG_TYPE1,
	ID_NG_TYPE2,

	/* Some misc. */
	ID_SYSTRAYMENU,
	ID_RLISTMENU,
	ID_LOCALSMENU,
	ID_MSGDLG_MSG,
	ID_TOOLTIPS,

	/* IDs for hipstart. */
	ID_HS_MAIN,
	ID_HS_MODEL,
	ID_HS_VIEW,
	ID_HS_EXECAGENT,
	ID_HS_EXECSERVER,
	ID_HS_CLEARDB,

	WIDGET_IDS_N
};


/******************************************************************************/
/* INCLUDES */
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "debug.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int widget_init(void);
void widget_quit(void);
void widget_set(int, void *);
void *widget(int);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/


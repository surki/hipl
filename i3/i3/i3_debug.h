#ifndef I3_DEBUG_H
#define I3_DEBUG_H 1

#ifdef _WIN32
#include <stdio.h>
#	ifdef __cplusplus
		extern "C" FILE* i3DebugFD;
#	else
		extern FILE* i3DebugFD;
#	endif
#endif


/**
  * The current debug level.
  * Only debug messages with level less than or equal to this value will
  * be printed.
  */
#define I3_CURRENT_DEBUG_LEVEL 100

/**
  * The current info level. This is used to restrict the amount of
  * informational messages displayed to the user.
  * Only those messages whose level is less than or equal to the
  * CURRENT_INFO_LEVEL will be displayed.
  */
#define I3_CURRENT_INFO_LEVEL  100


/**
  * This file defines the constants used as debugging levels
  * in the i3 specific code.
  */

/**
  * This info level is used for displaying fatal error messages.
  * Always displayed.
  */
#define I3_INFO_LEVEL_FATAL_ERROR 0

/**
  * This info level is used for messages which are very essential.
  * Messages at this level will always be displayed.
  */
#define I3_INFO_LEVEL_MINIMAL  50

/**
  * This info level is used for warning messages.
  */
#define I3_INFO_LEVEL_WARNING  60

/**
  * The messages at this level are not critical.  So they may not be
  * displayed (depends on CURRENT_INFO_LEVEL).
  */
#define I3_INFO_LEVEL_VERBOSE  70

/**
  * This is used for error messages which are probably caused due to bugs in the 
  * code.  i.e. they are not INFO_LEVEL_WARNINGs
  */
#define I3_DEBUG_LEVEL_WARNING   20

/**
 * This level is used temporarily while debugging to emphasize
 * certain parts of the code.
 */
#define I3_DEBUG_LEVEL_SUPER   -1

/**
  * This is used for messages describing fatal errors.
  */
#define I3_DEBUG_LEVEL_FATAL   0

/**
  * This is used for messages that are not fatal, but quite important
  * or high level.
  */
#define I3_DEBUG_LEVEL_MINIMAL     30

/**
  * This is used for messages that are not very important.
  */
#define I3_DEBUG_LEVEL_VERBOSE     90

#include "debug_fns.h"

#endif


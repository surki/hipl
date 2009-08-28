#ifndef I3_DEBUG_FNS_H
#define I3_DEBUG_FNS_H 1
#include "debug.h"


/**
 *  This macro is used to terminate the program when some fatal error
 *  occurs.
 */
#define EXIT_ON_ERROR   exit(-1)

//#define I3_DEBUG


#ifndef I3_PRINT_DEBUG
	/**
   	 * This macro is used to print debugging information. 
	 * The message is printed only if the current debugging level is
	 * greater than that of the level specified in the macro call.
	 */
      #if 0 // We turn off the i3 debuging instead we will use HIP_DEBUG
         #define I3_PRINT_DEBUG(debugLevel, msg, ... )  if(debugLevel <= I3_CURRENT_DEBUG_LEVEL) { printf("[Line:%d in file:%s] ", __LINE__, __FILE__); printf(msg, ##__VA_ARGS__);}
      #endif 

      #define I3_PRINT_DEBUG(debugLevel, ... ) if(debugLevel <= I3_CURRENT_DEBUG_LEVEL) HIP_DEBUG(__VA_ARGS__)


      #define I3_PRINT_DEBUG0	I3_PRINT_DEBUG
      #define I3_PRINT_DEBUG1	I3_PRINT_DEBUG
      #define I3_PRINT_DEBUG2	I3_PRINT_DEBUG
      #define I3_PRINT_DEBUG3	I3_PRINT_DEBUG
      #define I3_PRINT_DEBUG4	I3_PRINT_DEBUG
      #define I3_PRINT_DEBUG5	I3_PRINT_DEBUG
      #define I3_PRINT_DEBUG6	I3_PRINT_DEBUG
      #define I3_PRINT_DEBUG7	I3_PRINT_DEBUG

#endif  //I3_PRINT_DEBUG

/**
  * This macro is used to print messages irrespective of debug level.
  * These are messages are not for debugging, but for giving information
  * to the user.
  */
#ifndef I3_PRINT_INFO

   #if 0
      #define I3_PRINT_INFO(infoLevel, msg, ...) if(infoLevel <= I3_CURRENT_INFO_LEVEL) printf(msg, ##__VA_ARGS__)
   #endif

   #define I3_PRINT_INFO(infoLevel, ... ) if(infoLevel <= I3_CURRENT_INFO_LEVEL) HIP_INFO(__VA_ARGS__) 

   #define I3_PRINT_INFO0       I3_PRINT_INFO
   #define I3_PRINT_INFO1	I3_PRINT_INFO
   #define I3_PRINT_INFO2	I3_PRINT_INFO
   #define I3_PRINT_INFO3	I3_PRINT_INFO
   #define I3_PRINT_INFO4	I3_PRINT_INFO
   #define I3_PRINT_INFO5	I3_PRINT_INFO
   #define I3_PRINT_INFO6	I3_PRINT_INFO
   #define I3_PRINT_INFO7	I3_PRINT_INFO

#endif //I3_PRINT_INFO


#endif

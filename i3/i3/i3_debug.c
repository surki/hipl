#ifdef _WIN32


// All the i3 debug and info messages go into this file.
#	include <stdio.h>
	// NOTE: the i3DebugFD should NOT be called debugFD.
	// This causes a weird conflict with the debugging messages
	// associated with the proxy
	FILE* i3DebugFD = NULL;
#endif

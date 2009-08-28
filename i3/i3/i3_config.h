#ifndef I3_CONFIG

#define I3_CONFIG

#define MAX_CONFIG_PARM_LEN 200
#define VER_CONFIG "0.1"

void read_parameters(const char* filename);
void release_params();
/* You need to preallocate str */
void read_string_par(char* path,char* str,int required);
/* You need to preallocate us */
void read_ushort_par(char* path,unsigned short* us,int required);
/* You need to deallocate the returned char** by first deallocating #num char* pointers, and then char** */
char **read_strings_par(char* path,int* num);

/** Read the (string) value of the attribute (attribName) of the element specificed by elementPath */
void read_string_attribute(char* elementPath, char *attribName, char* str, int required);

/** Read the (unsigned short) value of the attribute (attribName) of the element specificed by elementPath */
void read_ushort_attribute(char* elementPath, char *attribName,unsigned short* us,int required);

/** Read the list of i3 servers.  The number of servers is returned in the parameter num.
 */
char **read_i3server_list(int* num);

#endif

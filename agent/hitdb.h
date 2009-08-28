/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef HIT_DB_H
#define HIT_DB_H


/******************************************************************************/
/* INCLUDES */
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
//#include <socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include "debug.h"
#include "ife.h"
#include "language.h"
#include "sqlitedbapi.h"

/******************************************************************************/
/* DEFINES */
/*#define HIT_DB_TYPE_NONE				0
#define HIT_DB_TYPE_ACCEPT				1
#define HIT_DB_TYPE_DENY				2
#define HIT_DB_TYPE_ALL					0xffffffff*/
#define HIT_ACCEPT				1
#define HIT_DENY				2

/**
	Maximum length for name-strings. Notice that this and the max URL length
	are statically set when reading values from database-file. So if these
	values here are changed, they should be manually changed to database-file
	loading routines.

	example: sscanf(buf, "\"%64[^\"]\" %s", name, hit);
	                         ^^
*/
/* NOTE these two values affect the db create tbl queries in sqlitedbapi.h */
#define MAX_NAME_LEN	64
/** Maximum length for URLs. */
#define MAX_URL_LEN		1024

/**
	This macro is for copying name string. It sets NULL characters and so on.
	strncpy() does not always do this properly, so this macro is here.
	Actually, when using this macro, the buffer being destination, must
	have MAX_NAME_LEN + 1 size.
*/
#define NAMECPY(dst, src) \
{ \
	strncpy(dst, src, MAX_NAME_LEN); \
	dst[MAX_NAME_LEN - 1] = '\0'; \
}

/** This macro is for copying url string, see NAMECPY for more info. */
#define URLCPY(dst, src) \
{ \
	strncpy(dst, src, MAX_URL_LEN); \
	dst[MAX_URL_LEN - 1] = '\0'; \
}


/******************************************************************************/
/* STRUCT DEFINITIONS */

/** This structure stores one local HIT and information needed for it. */
typedef struct
{
	/* Local HIT name. */
	char name[MAX_NAME_LEN + 1];
	/** HIT. */
	struct in6_addr lhit;
	/* Next group item. */
	void *next;
} HIT_Local;

/** This structure stores one group information. */
typedef struct
{
	/* Group name. */
	char name[MAX_NAME_LEN + 1];
	/** Stores pointer to local HIT with which this group is associated. */
	HIT_Local *l;
	/** Style of this group, 1 for accept, 0 for deny. */
	int accept;
	/** Is group lightweight or not. */
	int lightweight;
	/** Number of remote HITs in this group. */
	int remotec;
	/* Next group item. */
	void *next;
} HIT_Group;

/** This structure stores one remote HIT and information needed for it. */
typedef struct 
{
	/**
		Stores HIT item 'human' identifier, it's name.
		Maximum length for this is 64 + null.
	*/
	char name[MAX_NAME_LEN + 1];
	/** Stores HIT of this item. */
	struct in6_addr hit;
	/**
		Stores url of this item.
		Used for accepting connections for this HIT.
	*/
	char url[MAX_URL_LEN + 1];
	/**
		Stores port information for this item.
		Used for accepting connections for this HIT.
		This should be able to contain different forms of
		port info, like range, single, descriptive strings and so on.
		Example string: "80,443,7780-7790,ftp,ntp"
	*/
	char port[MAX_URL_LEN + 1];
	/** Remote HIT group. */
	HIT_Group *g;
	/* Next remote item. */
	void *next;
} HIT_Remote;




/******************************************************************************/
/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************/


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int hit_db_init(char *);
void hit_db_quit(char *);
void hit_db_clear(void);

HIT_Remote *hit_db_add_hit(HIT_Remote *, int);
HIT_Remote *hit_db_add(char *, struct in6_addr *, char *, char *, HIT_Group *, int);
int hit_db_del(char *);
HIT_Remote *hit_db_find(char *, struct in6_addr *);
int hit_db_enum(int (*)(HIT_Remote *, void *, void *), void *, void *);

int hit_db_save_to_file(char *);
int hit_db_save_rgroup_to_file(HIT_Group *, void *, void *);
int hit_db_save_local_to_file(HIT_Local *, void *, void *);
int hit_db_save_remote_to_file(HIT_Remote *, void *, void *);

int hit_db_load_from_file(char *);
int hit_db_parse_hit(char *);
int hit_db_parse_rgroup(char *);
int hit_db_parse_local(char *);

HIT_Group *hit_db_add_rgroup(char *, HIT_Local *, int, int);
int hit_db_del_rgroup(char *);
HIT_Group *hit_db_find_rgroup(char *);
int hit_db_enum_rgroups(int (*)(HIT_Group *, void *, void *), void *, void *);

HIT_Local *hit_db_add_local(char *, struct in6_addr *);
int hit_db_del_local(char *);
HIT_Local *hit_db_find_local(char *, struct in6_addr *);
int hit_db_enum_locals(int (*)(HIT_Local *, void *, void *), void *, void *);

int hit_db_count_locals(void);
HIT_Local *hit_db_default_local(void);


/******************************************************************************/
/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif
/******************************************************************************/


#endif /* END OF HEADER FILE */
/******************************************************************************/


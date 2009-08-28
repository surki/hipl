#ifndef HIP_SQLITEDBAPI_H
#define HIP_SQLITEDBAPI_H

/** @file
 * A header file for sqlitedbapi.c
 *
 * All functions needed for the sqlite usage in HIPL
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */

#include <stdio.h>
#include <sqlite3.h>
#include "debug.h"
#include "ife.h"

#ifdef ANDROID
#    define HIP_CERT_DB_PATH_AND_NAME "/system/etc/hip/certdb.db"
#else
#    define HIP_CERT_DB_PATH_AND_NAME "/etc/hip/certdb.db"
#endif

#define HIP_CERT_DB_CREATE_TBLS "CREATE TABLE hits (" \
                                 "lhit VARCHAR(41), " \
                                 "rhit VARCHAR(41), " \
                                 "cert VARCHAR(1048) " \
                                 "); " \

#define HIP_CERT_DB_SELECT_HITS "SELECT * FROM hits;"
                                 
#define HIP_AGENT_DB_CREATE_TBLS "CREATE TABLE local (" \
                                 "lname VARCHAR(65), " \
                                 "lhit VARCHAR(41)" \
                                 "); " \
                                 "CREATE TABLE remote (" \
                                 "rname VARCHAR(65), " \
                                 "rhit VARCHAR(41), " \
                                 "url VARCHAR(1025), " \
                                 "port VARCHAR(1025), " \
                                 "gname VARCHAR(65)" \
                                 "); " \
                                 "CREATE TABLE groups (" \
                                 "gname VARCHAR(65), " \
                                 "lhitname VARCHAR(65), " \
                                 "accept INTEGER, " \
                                 "lightweight INTEGER" \
                                 ");" \

#define HIP_AGENT_DB_DELETE_ALL "DELETE FROM local;" \
                                "DELETE FROM remote;" \
                                "DELETE FROM groups;"

#define HIP_AGENT_DB_SELECT_REMOTE "SELECT * FROM remote;"

#define HIP_AGENT_DB_SELECT_LOCAL "SELECT * FROM local;"

#define HIP_AGENT_DB_SELECT_GROUPS "SELECT * FROM groups;"

sqlite3 * hip_sqlite_open_db(const char *, const char *);
int hip_sqlite_close_db(sqlite3 *);
int hip_sqlite_select(sqlite3 *, const char *, 
                             int (*callback)(void*,int,char**,char**));
int hip_sqlite_execute_into_db(sqlite3 *, const char *);
/* These three functions are just wrappers for the one in above */
int hip_sqlite_delete_from_table(sqlite3 *, const char *);
int hip_sqlite_insert_into_table(sqlite3 *, const char *);
int hip_sqlite_create_table(sqlite3 *, const char *);
#endif /* HIP_SQLITEDBAPI_H */

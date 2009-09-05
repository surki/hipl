/** @file
 * This file defines the api for sqlite to use with HIPL
 *
 * @author Samu Varjonen
 *
 */

#ifdef CONFIG_HIP_AGENT

#include "sqlitedbapi.h"

/**
 * a sample callback function. Used from sqliteteststub. Meant to be an 
 * an example on how to use the info gathered by theh query.
 *
 * @return 0 if created and/or opened OK otherwise negative
 *
 * @note Notice that the parameters are allways the same
 */
static int hip_sqlite_callback(void *NotUsed, int argc, char **argv, char **azColName) {
        int i;
        for(i=0; i<argc; i++) {
                HIP_DEBUG("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        }
        return 0;
}

/**
 * Function that opens the database, can also create the database 
 *
 * @param db_path is a char pointer pointing telling where the db is
 * @param create_table_sql SQL create sequence to create table for the db 
 *
 * @returns pointer to db otherwise NULL
 *
 * @note Always remember to close the db, even if it did return error!
 */
sqlite3 * hip_sqlite_open_db(const char * db_path, const char * create_table_sql) {
        int err = 0, existed = 0;
        FILE * db_file = NULL;
        sqlite3 * p_db = NULL;

        db_file = fopen(db_path, "r");
        if (!db_file) {
                HIP_DEBUG("Database %s did NOT exist, it will be created\n", db_path);
                existed = -1;
        } else {
                HIP_DEBUG("Database existed so just opening it\n");
                fclose(db_file);
        }
        HIP_DEBUG("Opening the db\n");
	HIP_IFEL(sqlite3_open(db_path, &p_db),
			-1, "Can't open database: %s\n", sqlite3_errmsg(p_db));

        /* Tables need to be created */
        if (existed == -1) {
                HIP_DEBUG("Database did not exist so it needs tables too\n");
                HIP_IFEL(hip_sqlite_create_table(p_db, create_table_sql), 
                         -1, "Failed to create tables\n");
                HIP_DEBUG("Table creation returned OK\n");
        }

 out_err:

	if (err && p_db) {
	    if (sqlite3_close(p_db))
		HIP_ERROR("Error closing database: %s\n", sqlite3_errmsg(p_db));
	    p_db = NULL;
	}
        return(p_db);
}

/**
 * Function that closes the database 
 *
 * @param db a pointer to the database
 *
 * @return 0 if closed ok
 *
 * @note may be useless function
 */
int hip_sqlite_close_db(sqlite3 * db) {
        int err = 0;
        err = sqlite3_close(db);
        if (err != SQLITE_OK) 
                HIP_IFEL(-1, -1, "Failed to close the db\n");
 out_err:
        return(err);
}

/**
 * Function that executes SQL queries agenst the database 
 *
 * @param db a pointer to the database
 * @param sql points to SQL query to be executed
 * @param callback points to callback function to be used with the results
 *
 * @return 0 on success otherwise negative
 *
 * @note Check out the hip_sqlite_callback for an example of callback function
 *       May work in funny way with INSERT INTO or CREATE TABLE use
 *       hip_sqlite_execute_to_db with them instead.
 */
int hip_sqlite_select(sqlite3 * db, const char *sql, 
                             int (*callback)(void*,int,char**,char**)) {
        int err = 0, rc = 0;
        char *zErrMsg = 0;
        
        _HIP_DEBUG("Executing %s\n", sql); 
        rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);                
        if (rc != SQLITE_OK) {
                _HIP_DEBUG("Failed to run SQL query against the database\n");
                err = -1;
                HIP_DEBUG("SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
        }
 out_err:
        return(err);
}
 
/**
 * Function that executes queries against the db and does not take callback 
 *
 * @param db a pointer to the database
 * @param sql points to the SQL create
 * @param errormsg contains the error message shown on error cases
 *
 * @return 0 on success otherwise negative
 *
 * @note do NOT use with SELECT
 */
int hip_sqlite_execute_into_db(sqlite3 * db, const char *sql) {
        int err = 0, rc = 0;
        char *zErrMsg = 0;
        
        _HIP_DEBUG("Executing \"%s\"\n", sql); 
        rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);                
        if (rc != SQLITE_OK) {
                err = -1;
                HIP_DEBUG("RC = %d, SQL error: %s\n", rc, zErrMsg);
                sqlite3_free(zErrMsg);
        } 
 out_err:
        return(err);
}

/**
 * Function that executes queries against the db and does not take callback 
 *
 * @param db a pointer to the database
 * @param sql points to the CREATE query
 *
 * @return 0 on success otherwise negative
 *
 * @note Remember to use correct query with this
 */
int hip_sqlite_create_table(sqlite3 * db, const char *sql) {
        int err = 0;
        HIP_IFEL(hip_sqlite_execute_into_db(db, sql), -1,  
                 "Failed to create table\n");
 out_err:
        return(err);
}

/**
 * Function that executes queries against the db and does not take callback 
 *
 * @param db a pointer to the database
 * @param sql points to the INSERT INTO query
 *
 * @return 0 on success otherwise negative
 *
 * @note Remember to use correct query with this
 */
int hip_sqlite_insert_into_table(sqlite3 * db, const char *sql) {
        int err = 0;
        HIP_IFEL(hip_sqlite_execute_into_db(db, "BEGIN;"), -1,  
                 "Failed to BEGIN\n");
        HIP_IFEL(hip_sqlite_execute_into_db(db, sql), -1,  
                 "Failed to insert into table\n");
        HIP_IFEL(hip_sqlite_execute_into_db(db, "END;"), -1,  
                 "Failed to END\n");
 out_err:
        return(err);
} 

/**
 * Function that executes queries against the db and does not take callback 
 *
 * @param db a pointer to the database
 * @param sql points to the DELETE query
 *
 * @return 0 on success otherwise negative
 *
 * @note Remember to use correct query with this
 */
int hip_sqlite_delete_from_table(sqlite3 * db, const char *sql) {
        int err = 0;
        HIP_IFEL(hip_sqlite_execute_into_db(db, sql), -1,  
                 "Failed to delete from table\n");
 out_err:
        return(err);
}

#endif /* CONFIG_HIP_AGENT */

/** @file
 * A teststub for certtools.c/h
 *
 * File for testing the main operations of certtools.
 * First this test takes the default HIT and the corresponding key.
 * Secondly it creates a certificate where itself is the issuer and the subject.
 * Then it tries to verify it. If it succeeds everything should be OK :)
 *
 * @author Samu Varjonen
 *
 */

#ifdef CONFIG_HIP_AGENT

#include "utils.h"
#include "sqlitedbapi.h"
 
static int hip_sqlite_callback(void *NotUsed, int argc, char **argv, char **azColName) {
        int i;
        for(i=0; i<argc; i++){
                HIP_DEBUG("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        }
        return 0;
}

int main(int argc, char *argv[]) {
        int err = 0, i = 0;
        sqlite3 * db = NULL;
        char dbpath[] = "/tmp/hip_sqltest.db";
        char table_sql[] = "CREATE TABLE test (num INTEGER, value VARCHAR(128));";
        char insert_sql[256];
        char delete_sql[] = "DELETE FROM test WHERE num = 3;";
        char select_sql[] = "SELECT * FROM test;";
        
        db = hip_sqlite_open_db(dbpath, table_sql);
        HIP_IFEL((db == NULL), -1, "Failed to open/create the database\n");
        for(i = 1; i < 10; i++) {
                memset(insert_sql, '\0', sizeof(insert_sql));
                sprintf(insert_sql, "INSERT INTO test VALUES(%d, "
                        "'Hi to you. #%d times said');", i,i); 
                HIP_IFEL(hip_sqlite_insert_into_table(db, insert_sql),
                         -1, "Failed to execute insert into query\n"); 
        }
        HIP_IFEL(hip_sqlite_select(db, select_sql, hip_sqlite_callback), -1,
                 "Failed to execute select query on the db\n");
        HIP_DEBUG("Removing row where num is 3\n");
        HIP_IFEL(hip_sqlite_delete_from_table(db, delete_sql),
                         -1, "Failed to execute delete query\n"); 
        HIP_IFEL(hip_sqlite_select(db, select_sql, hip_sqlite_callback), -1,
                 "Failed to execute select query on the db\n");
        HIP_DEBUG("Did the num 3 disappear?\n");
        HIP_IFEL(hip_sqlite_close_db(db), -1, "Failed to close the db\n");
       
 out_err:
        return(err);
}

#else

int main(int argc, char *argv[]) {
	printf("You need to configure HIP with agent support\n");
	return -1;
}

#endif /* sqlitedbapi.h */


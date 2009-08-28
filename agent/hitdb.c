/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "hitdb.h"


/******************************************************************************/
/* DEFINES */
/**
	Define minimum amount of allocated space for database items and amount
	of memory allocated more, when not enough space for new items.
*/
#define HIT_DB_ITEMS_REALLOC			8

#define HIT_DB_LOCK() { while (hit_db_lock); hit_db_lock = 1; }
#define HIT_DB_UNLOCK() { hit_db_lock = 0; }


/******************************************************************************/
/* VARIABLES */
/** All HIT-data in the database is stored in here. */
HIT_Remote *remote_db = NULL, *remote_db_last = NULL;
/** All groups in database are stored in here. */
HIT_Group *group_db = NULL, *group_db_last = NULL;
/** All local HITs in database are stored in here. */
HIT_Local *local_db = NULL, *local_db_last = NULL;
/** Counts items in database. */
int remote_db_n = 0;
/** Count groups in database. */
int group_db_n = 0;
/** Count local HITs in database. */
int local_db_n = 0;

/** Almost atomic lock. */
int hit_db_lock = 1;


/******************************************************************************/
/* Callback functions for the database functions to use to handle all the data
   from queries */
/******************************************************************************/

/**
 * Callback function to get the data from the db table local
 *
 * @return 0 if created and/or opened OK otherwise negative
 *
 * @note Notice that the parameters are allways the same
 */
static int hip_agent_db_local_callback(void *NotUsed, int argc, 
                                       char **argv, char **azColName) {
        int i;
        char buf[118]; // sum of the ones below and some more
        char lname[66];
        char lhit[42];

        for(i=0; i<argc; i++) {
                _HIP_DEBUG("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
                if (!strcmp(azColName[i], "lname")) 
                        sprintf(lname,"%s", argv[i] ? argv[i] : "NULL"); 
                if (!strcmp(azColName[i], "lhit")) 
                        sprintf(lhit,"%s", argv[i] ? argv[i] : "NULL");
        }
        if ((i % 2) == 0 && (i > 0)) {
                sprintf(buf, "\"%s\" %s", 
                        lname, lhit);
                _HIP_DEBUG("HIT BUF %s\n", buf);
                hit_db_parse_local(&buf);
                memset(lname, '\0', sizeof(lname));
                memset(lhit, '\0', sizeof(lhit));   
        } 
        return 0;
}

/**
 * Callback function to get the data from the db table remote
 *
 * @return 0 if created and/or opened OK otherwise negative
 *
 * @note Notice that the parameters are allways the same
 */
static int hip_agent_db_remote_callback(void *NotUsed, int argc, 
                                        char **argv, char **azColName) {
        int i, err = 0;
        char buf[2236]; // should be the sum of the below + 10 or more :) 
        char rname[66];
        char rhit[42];
        char url[1026];
        char port[1026];
        char gname[66];
       
        for(i=0; i<argc; i++) {
                _HIP_DEBUG("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
                if (!strcmp(azColName[i], "rname"))  
                        err = sprintf(rname,"%s", argv[i] ? argv[i] : "NULL"); 
                if (!strcmp(azColName[i], "rhit")) 
                        err = sprintf(rhit,"%s", argv[i] ? argv[i] : "NULL");  
                if (!strcmp(azColName[i], "url")) 
                        err = sprintf(url,"%s", argv[i] ? argv[i] : "NULL");  
                if (!strcmp(azColName[i], "port")) 
                        err = sprintf(port,"%s", argv[i] ? argv[i] : "NULL");
                if (!strcmp(azColName[i], "gname")) 
                        err = sprintf(gname,"%s", argv[i] ? argv[i] : "NULL");
        }
        if ((i % 5) == 0 && (i > 0)) {
                sprintf(buf, "\"%s\" \"%s\" \"%s\" \"%s\" \"%s\"", 
                        rname, rhit, url, port, gname);
                hit_db_parse_hit(&buf);
                memset(rname, '\0', sizeof(rname));
                memset(rhit, '\0', sizeof(rhit));
                memset(port, '\0', sizeof(port));
                memset(url, '\0', sizeof(url));
                memset(gname, '\0', sizeof(gname));
        }
        return 0;
}

/**
 * Callback function to get the data from the db table groups
 *
 * @return 0 if created and/or opened OK otherwise negative
 *
 * @note Notice that the parameters are allways the same
 */
static int hip_agent_db_groups_callback(void *NotUsed, int argc, 
                                        char **argv, char **azColName) {
        int i, accept = 0, lw = 0;
        char buf[118]; // sum of the ones below + some more
        char name[66];
        char lhit[42];

        memset(name, '\0', sizeof(name));
        memset(lhit, '\0', sizeof(lhit));
        accept = lw = 0;

        for(i=0; i<argc; i++) {
                _HIP_DEBUG("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
                if (!strcmp(azColName[i], "gname")) 
                        sprintf(name,"%s", argv[i] ? argv[i] : "NULL"); 
                if (!strcmp(azColName[i], "lhitname")) 
                        sprintf(lhit,"%s", argv[i] ? argv[i] : "NULL");  
                if (!strcmp(azColName[i], "accept")) 
                        accept = argv[i] ? argv[i] : "NULL"; 
                if (!strcmp(azColName[i], "lightweight"))  
                        lw = argv[i] ? argv[i] : "NULL";
        }
        if ((i % 4) == 0 && (i > 0)) {
                sprintf(buf, "\"%s\" \"%s\" %d %d", name, lhit, accept, lw);
                hit_db_parse_rgroup(&buf);
                memset(name, '\0', sizeof(name));
                memset(lhit, '\0', sizeof(lhit));
                accept = lw = 0;
        }
        return 0;
}

/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/

/**
	Initialize HIP agent HIT database. This function must be called before
	using database at all.
	
	@param file If not NULL, database is initialized from here.
	@return 0 on success, -1 on errors.
*/
int hit_db_init(char *file)
{
	/* Variables. */
	int err = 0;
        extern int init_in_progress;
	
	hit_db_lock = 0;
	hit_db_clear();
        init_in_progress = 0;

	if (file) HIP_IFE(hit_db_load_from_file(file), -1);
        init_in_progress = 1;
out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Deinitialize HIP agent HIT database. This function must be called when
	closing application and stopping using database.

	@param file If not NULL, database saved to here.
*/
void hit_db_quit(char *file)
{
	if (file) hit_db_save_to_file(file);
	hit_db_clear();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Clear HIT database.

	@return 0 on success, -1 on errors.
*/
void hit_db_clear(void)
{
	/* Variables. */
	HIT_Remote *r1, *r2;
	HIT_Group *g1, *g2;
	HIT_Local *l1, *l2;
	
	HIT_DB_LOCK();

	/* Free remote. */
	r1 = remote_db;
	remote_db = NULL;
	remote_db_n = 0;
	while (r1)
	{
		r2 = r1->next;
		free(r1);
		r1 = r2;
	}
	
	/* Free groups. */
	g1 = group_db;
	group_db = NULL;
	group_db_n = 0;
	while (g1)
	{
		g2 = g1->next;
		free(g1);
		g1 = g2;
	}

	/* Free locals. */
	l1 = local_db;
	local_db = NULL;
	local_db_n = 0;
	while (l1)
	{
		l2 = l1->next;
		free(l1);
		l1 = l2;
	}
	
	HIT_DB_UNLOCK();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Adds new HIT to database.
*/
HIT_Remote *hit_db_add_hit(HIT_Remote *hit, int nolock)
{
	return (hit_db_add(hit->name, &hit->hit, hit->url, hit->port, hit->g, nolock));
}
/* END OF FUNCTION */

	
/******************************************************************************/
/**
	Adds new HIT to database.
	
	@param name 'Human' identifier for this item: it's name.
	@param hit HIT of this item.
	@param url URL, which is connected to this item, can be NULL.
	@param port Port, which is connected to this item, can be 0 if not needed.
	@param type HIT type, accept or deny.
	@param nolock Set to one if no database lock is needed.

	@return Pointer to new remote HIT on success, NULL on errors.
*/
HIT_Remote *hit_db_add(char *name, struct in6_addr *hit, char *url,
                       char *port, HIT_Group *group, int nolock)
{
	/* Variables. */
	HIT_Remote *r, *err = NULL;
	char hitb[128];
	struct in6_addr lhit;
        char rhit[128];
        char insert_into[256];
        int ret = 0;
        extern sqlite3 *agent_db;
        extern int init_in_progress;

	if (!nolock) HIT_DB_LOCK();

	/* Check group name length. */
	HIP_IFEL(strlen(name) < 1, NULL, "Remote HIT name too short.\n");
 
	/* Check database for group already with same name. */
	r = hit_db_find(name, NULL);
	HIP_IFEL(r != NULL, r, "Remote HIT already found from database with same"
	                       " name, returning it, could not add new.\n");
	r = hit_db_find(NULL, hit);
	HIP_IFEL(r != NULL, r, "Remote HIT already found from database, returning it.\n");

	/* Allocate new remote HIT. */
	r = (HIT_Remote *)malloc(sizeof(HIT_Remote));
	HIP_IFEL(r == NULL, NULL, "Failed to allocate new remote HIT.\n");

	/* Copy info. */
	memset(r, 0, sizeof(HIT_Remote));
	NAMECPY(r->name, name);
	memcpy(&r->hit, hit, sizeof(struct in6_addr));
	URLCPY(r->port, port);
	URLCPY(r->url, url);
	
	/* Check that group is not NULL and set group. */
	if (group == NULL)
	{
		group = group_db;
	}
	r->g = group;
	r->g->remotec++;

	/* Add remote group item to database. */
	if (remote_db == NULL) remote_db = r;
	else remote_db_last->next = (void *)r;

	remote_db_last = r;
	remote_db_n++;

        /* Add it to the db on disk too */
        if (init_in_progress == 1) {
                print_hit_to_buffer(hit, &r->hit);
                sprintf(insert_into, "INSERT INTO remote VALUES("
                        "'%s', '%s', '%s', '%s', '%s');", 
                        r->name, hit, "x", r->port, r->g->name);
                ret = hip_sqlite_insert_into_table(agent_db, insert_into);        
        }
	/* Then call GUI to show new HIT. */
	if (group->name[0] != ' ')
	{
		_HIP_DEBUG("Calling GUI to show new HIT %s...\n", r->name);
		gui_hit_remote_add(group->name, r->name);
	}

	_HIP_DEBUG("%d items in database.\n", remote_db_n);

	err = !r;

out_err:
	if (!nolock) HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete hit with given index.
	
	@param name Name of remote HIT to be removed.
	@return 0 if hit removed, -1 on errors.
*/
int hit_db_del(char *n)
{
	/* Variables. */
	HIT_Remote *r1, *r2;
	char name[MAX_NAME_LEN + 1], group_name[MAX_NAME_LEN + 1];
	int err = 0;
        char delete_from[256];        
	extern sqlite3 * agent_db;

	/* Check that database is not empty. */
	HIP_IFEL(remote_db_n < 1, -1, "Remote database is empty, should not happen!\n");
	
	NAMECPY(name, n);
	_HIP_DEBUG("Deleting remote HIT: %s\n", name);

	/* Check whether this HIT is the first. */
	if (strncmp(remote_db->name, name, MAX_NAME_LEN) == 0)
	{
		r1 = remote_db;
		r1->g->remotec--;
		NAMECPY(group_name, r1->g->name);
		remote_db = (HIT_Remote *)remote_db->next;
		free(r1);
		remote_db_n--;
		if (remote_db_n < 1)
		{
			remote_db = NULL;
			remote_db_last = NULL;
		}
	}
	else
	{
		/* Find previous HIT first. */
		r1 = remote_db;
		while (r1 != NULL)
		{
			r2 = (HIT_Remote *)r1->next;
			if (r2 == NULL) break;
		
			if (strncmp(r2->name, name, MAX_NAME_LEN) == 0) break;
			
			r1 = r2;
		}
	
		/* Then delete, if found. */
		if (r2 != NULL)
		{
			r1->next = r2->next;
			r2->g->remotec--;
			NAMECPY(group_name, r2->g->name);
			if (remote_db_last == r2) remote_db_last = r1;
			free(r2);
		}
		else err = -1;
	}
        /* Mirror the delete to the db on disk */
        sprintf(delete_from,"DELETE FROM remote WHERE rname = %s;",name);
        _HIP_DEBUG("DEL :: %s\n",delete_from);
        HIP_IFEL(hip_sqlite_delete_from_table(agent_db, delete_from),
                 -1, "Failed to execute delete query on remote table\n"); 

out_err:
	if (err) _HIP_DEBUG("Deleting remote HIT failed: %s\n", name);
	else gui_hit_remote_del(name, group_name);

	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Find a remote HIT from database.
	
	@param name Name of HIT to be searched.
	@param hit HIT to be searched.
	@return Pointer to HIT found, or NULL if none found.
*/
HIT_Remote *hit_db_find(char *name, struct in6_addr *hit)
{
	/* Variables. */
	HIT_Remote *r;
	int err;
	
	r = remote_db;
	while (r != NULL)
	{
		err = 0;
		if (name == NULL) err++;
		else if (strncmp(r->name, name, MAX_NAME_LEN) == 0) err++;
		if (hit == NULL) err++;
		else if (memcmp(&r->hit, hit, sizeof(struct in6_addr)) == 0) err++;
		
		if (err == 2) break;
		r = (HIT_Remote *)r->next;
	}
	
	return (r);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Enumerate all remote HITs in database. This function locks the database.
	
	@param f Function to call for every remote HIT in database. This function
	         should return 0 if continue enumeration and something else, if
	         enumeration should be stopped.
	@param p Pointer to user data.
	@return Number of HITs enumerated.
*/
int hit_db_enum(int (*f)(HIT_Remote *, void *, void *), void *p, void * pdb)
{
	/* Variables. */
	HIT_Remote *r;
	int err = 0, n = 0;

	r = remote_db;
	while (r != NULL && err == 0)
	{
		err = f(r, p, pdb);
		n++;
		r = (HIT_Remote *)r->next;
	}

	_HIP_DEBUG("Enumerated %d remote HITs.\n", n);
	
	return (n);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Save database to file.
	
	@param file Filename for saving database.
	@return 0 on success, -1 on errors.
*/
int hit_db_save_to_file(char *file)
{
	/* Variables. */
	HIT_Remote *items = NULL;
	FILE *f = NULL;
	int err = 0, i;
	char hit[128];
        extern sqlite3 *agent_db;
	
	HIT_DB_LOCK();
	
	_HIP_DEBUG("Saving HIT database to %s.\n", file);

        /* 
           XX Save everything to the sqlite db 
           Clear it first then insert stuff into it
           Should it be cleared always or just checked the changes against
           the lists in memory? -- SAMU
           
           Disabled this because trying to save info to the db as we go --SAMU
        */
        /*
        db = hip_sqlite_open_db(file, HIP_AGENT_DB_CREATE_TBLS);
        HIP_IFEL(hip_sqlite_delete_from_table(db, HIP_AGENT_DB_DELETE_ALL),
                 -1, "Failed to execute delete query\n");
        */
	/* Write all local HITs to file. */
	//hit_db_enum_locals(hit_db_save_local_to_file, f, db);
	/* Write all remote groups to file. */
	//hit_db_enum_rgroups(hit_db_save_rgroup_to_file, f, db);
	/* Write all remote HITs to file. */
	//hit_db_enum(hit_db_save_remote_to_file, f, db);
              
out_err:        
        HIP_IFEL(hip_sqlite_close_db(agent_db), -1, "Failed to close the db\n");        
	if (f) fclose(f);
	HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Write remote group to agent database -file.
	This is a enumeration callback function used by hit_db_enum_rgroups().
*/
int hit_db_save_rgroup_to_file(HIT_Group *g, void *p, void * pdb)
{
	/* Variables. */
        char insert_into[256];
        int ret = 0;
        sqlite3 * db;
	
        db = (sqlite3 *)pdb;
	
	if (g->name[0] == ' ' || !g->l) return (0); 

        sprintf(insert_into, "INSERT INTO groups VALUES("
                 "'%s', '%s', %d, %d);", 
                 g->name, g->l->name, g->accept, g->lightweight);
        ret = hip_sqlite_insert_into_table(db, insert_into);
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Write local HIT to agent database -file.
	This is a enumeration callback function used by hit_db_enum_locals().
*/
int hit_db_save_local_to_file(HIT_Local *local, void *p, void * pdb)
{
	/* Variables. */
	char hit[128];
        char insert_into[256];
        int ret = 0;
        sqlite3 * db;
	
        db = (sqlite3 *)pdb;

	HIP_DEBUG("l \"%s\" %s\n", local->name, hit); 
	print_hit_to_buffer(hit, &local->lhit);
	
        sprintf(insert_into, "INSERT INTO local VALUES("
                 "'%s', '%s');", 
                 local->name, hit); 
        ret = hip_sqlite_insert_into_table(db, insert_into);

	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Write remote HIT to agent database -file.
	This is a enumeration callback function used by hit_db_enum_locals().
*/
int hit_db_save_remote_to_file(HIT_Remote *r, void *p, void * pdb)
{
	/* Variables. */
	//FILE *f = (FILE *)p;
	char hit[128];
        char insert_into[256];
        int ret = 0;
        sqlite3 * db;
	
        db = (sqlite3 *)pdb;
	
	if (r->g->name[0] == ' ') return (0);

	print_hit_to_buffer(hit, &r->hit);
        sprintf(insert_into, "INSERT INTO remote VALUES("
                 "'%s', '%s', '%s', '%s', '%s');", 
                r->name, hit, "x", r->port, r->g->name);
        ret = hip_sqlite_insert_into_table(db, insert_into);

	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Load database from file.
	
	@param file Filename for saving database.
	@return 0 on success, -1 on errors.
*/
int hit_db_load_from_file(char *file)
{
	/* Variables. */
        FILE * db_file = NULL;
	char buf[2048], ch;
	int err = 0, i, n;
	struct in6_addr hit;
        extern sqlite3 * agent_db;
        extern int init_in_progress;

	hit_db_clear();
	HIT_DB_LOCK();

	_HIP_DEBUG("Loading HIT database from %s.\n", file);
      
        db_file = fopen(file, "r");
        if (!db_file) {
                /* first time creation has to add local info */
                HIP_DEBUG("Adding local info on this run\n");
                init_in_progress = 1;
        }
        agent_db = hip_sqlite_open_db(file, HIP_AGENT_DB_CREATE_TBLS);
	HIP_IFE(!agent_db, -1);

        HIP_IFEL(hip_sqlite_select(agent_db, HIP_AGENT_DB_SELECT_LOCAL,
                                   hip_agent_db_local_callback), -1,
                 "Failed to execute select query (local) on the db\n");
        HIP_IFEL(hip_sqlite_select(agent_db, HIP_AGENT_DB_SELECT_GROUPS,
                                   hip_agent_db_groups_callback), -1,
                 "Failed to execute select query (groups) on the db\n");
        HIP_IFEL(hip_sqlite_select(agent_db, HIP_AGENT_DB_SELECT_REMOTE,
                                   hip_agent_db_remote_callback), -1,
                 "Failed to execute select query (remote) on the db\n");
	
out_err:
	if (db_file) fclose(db_file);
	HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Load one HIT from given string.
	
	@param buf String containing HIT information.
	@return 0 on success, -1 on errors.
*/
int hit_db_parse_hit(char *buf)
{
	/* Variables. */
	HIT_Remote item;
	struct in6_addr slhit, srhit;
	int err = 0, n;
	char lhit[128], group[320];

	/* Parse values from current line. */
	n = sscanf(buf, "%s \"%1024[^\"]\" \"%64[^\"]\"  \"%1024[^\"]\" \"%64[^\"]\"",
	           item.name, lhit,  item.url, item.port, group);

	HIP_IFEL(n != 5, -1, "Broken line in database file: %s\n", buf);
	read_hit_from_buffer(&item.hit, lhit);
	item.g = hit_db_find_rgroup(group);
	HIP_IFEL(item.g == NULL, -1, "Invalid group for HIT in database file!\n");

	hit_db_add_hit(&item, 1);

out_err:	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Load one remote group from given string.
	
	@param buf String containing remote group information.
	@return 0 on success, -1 on errors.
*/
int hit_db_parse_rgroup(char *buf)
{
	/* Variables. */
	HIT_Local *l;
	HIT_Group *g;
	int err = 0, n;
	char name[MAX_NAME_LEN + 1], hit[128];
	int accept, lightweight;
	
	/* Parse values from current line. */
        
	n = sscanf(buf, "\"%64[^\"]\" \"%64[^\"]\" %d %d",
	           name, hit, &accept, &lightweight);
	HIP_IFEL(n != 4, -1, "Broken line in database file: %s\n", buf);
	l = hit_db_find_local(hit, NULL);
	HIP_IFEL(!l, -1, "Failed to find local HIT for remote group!\n");
	g = hit_db_add_rgroup(name, l, accept, lightweight);
	if (g && strncmp(lang_get("default-group-name"), name, MAX_NAME_LEN) == 0)
	{
		g->l = l;
		g->accept = accept;
		g->lightweight = lightweight;
	}


out_err:	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Load one local HIT from given string.
	
	@param buf String containing local HIT information.
	@return 0 on success, -1 on errors.
*/
int hit_db_parse_local(char *buf)
{
	/* Variables. */
	int err = 0, n;
	char name[MAX_NAME_LEN + 1], hit[128];
	struct in6_addr lhit;

	/* Parse values from current line. */
	n = sscanf(buf, "\"%64[^\"]\" %s", name, hit);
	HIP_IFEL(n != 2, -1, "Broken line in database file: %s\n", buf);
	read_hit_from_buffer(&lhit, hit);
	hit_db_add_local(name, &lhit);
	
out_err:	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add new remote group to HIT group database. Notice that this function don't
	lock the database!
	
	@return Returns pointer to new group or if group already existed, pointer
	        to old one. Returns NULL on errors.
*/
HIT_Group *hit_db_add_rgroup(char *name, HIT_Local *lhit,
                             int accept, int lightweight)
{
	/* Variables. */
	HIT_Group *g, *err = NULL;
        char insert_into[256];
        int ret = 0;
        extern sqlite3 *agent_db;
        extern int init_in_progress;

	/* Check group name length. */
	HIP_IFEL(strlen(name) < 1, NULL, "Remote group name too short.\n");
 
	/* Check database for group already with same name. */
	g = hit_db_find_rgroup(name);
	HIP_IFE(g != NULL, g);

	/* Allocate new remote group item. */
	g = (HIT_Group *)malloc(sizeof(HIT_Group));
	HIP_IFEL(g == NULL, NULL, "Failed to allocate new remote group item.\n");
	
	/* Setup remote group item. */
	memset(g, 0, sizeof(HIT_Group));
	NAMECPY(g->name, name);
	g->l = lhit;
	g->accept = accept;
	g->lightweight = lightweight;
	g->remotec = 0;

	/* Add remote group item to database. */
	if (group_db == NULL) group_db = g;
	else group_db_last->next = (void *)g;

	group_db_last = g;
	group_db_n++;

        /* add the group also to the db on disk 
         " deny" group is not necessary on disk?*/
        if (init_in_progress == 1 && strcmp(" deny", g->name)) {
                sprintf(insert_into, "INSERT INTO groups VALUES("
                        "'%s', '%s', %d, %d);", 
                        g->name, g->l->name, g->accept, g->lightweight);
                ret = hip_sqlite_insert_into_table(agent_db, insert_into);
        }
	/* Tell GUI to show new group item. */
	if (g->name[0] != ' ')
	{
		_HIP_DEBUG("New group added with name \"%s\", calling GUI to show it.\n", name);
		gui_group_remote_add(g->name);
	}
	err = g;

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete remote group from HIT group database.

	@return 0 on success, -1 on errors.
*/
int hit_db_del_rgroup(char *name)
{
	/* Variables. */
	HIT_Group *g, *g2;
	int err = 0;
        char delete_from[256];
	extern sqlite3 * agent_db;

	/* Find group from database first. */
	g = hit_db_find_rgroup(name);
	HIP_IFEL(!g, -1, "Tried to delete unexisting group \"%s\" from database", name);
	
	/* If group is first group.. */
	if (g == group_db)
	{
		group_db = (HIT_Group *)g->next;
		if (g == group_db_last) group_db_last = NULL;
	}
	else
	{
		/* Find previous group from database. */
		g2 = group_db;
		while (g2->next != (void *)g && g2) g2 = (HIT_Group *)g2->next;
		HIP_IFEL(!g2, -1, "Could not find previous group for group \"%s\"!\n", 
                         name);
		g2->next = g->next;
		if (g == group_db_last) group_db_last = g2;
	}
	/* Mirror the delete to the db on disk */
        sprintf(delete_from,"DELETE FROM groups WHERE gname = '%s';",name);
        _HIP_DEBUG("DEL :: %s\n",delete_from);
        HIP_IFEL(hip_sqlite_delete_from_table(agent_db, delete_from),
                 -1, "Failed to execute delete query group table\n"); 

	gui_group_remote_del(name);
	free(g);
	group_db_n--;

	/* If this was last group, (re-)create default group. */
	if (group_db_n < 1) 
                hit_db_add_rgroup(lang_get("default-group-name"), local_db, HIT_ACCEPT, 0);
	
out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Find a group from remote group database.
	
	@param group Name of remote group to be searched.
	@return Pointer to group found, or NULL if none found.
*/
HIT_Group *hit_db_find_rgroup(char *name)
{
	/* Variables. */
	HIT_Group *g;
	
	g = group_db;
	while (g != NULL)
	{
		if (strncmp(g->name, name, MAX_NAME_LEN) == 0) break;
		g = (HIT_Group *)g->next;
	}
	
	return (g);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Enumerate all remote groups in database. This function does not lock the
	database!

	@param f Function to call for every group in database. This function should
	         return 0 if continue enumeration and something else, if enumeration
	         should be stopped.
	@param p Pointer to user data.
	@return Number of groups enumerated.
*/
int hit_db_enum_rgroups(int (*f)(HIT_Group *, void *, void *), void *p, void *pdb)
{
	/* Variables. */
	HIT_Group *g;
	int err = 0, n = 0;
	
	g = group_db;
	while (g != NULL && err == 0)
	{
		err = f(g, p, pdb);
		n++;
		g = (HIT_Group *)g->next;
	}

	_HIP_DEBUG("Enumerated %d groups.\n", n);
	
	return (n);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add new local HIT database. Notice that this function don't
	lock the database!
	
	@return Returns pointer to new HIT or if HIT already existed, pointer
	        to old one. Returns NULL on errors.
*/
HIT_Local *hit_db_add_local(char *name, struct in6_addr *hit)
{
	/* Variables. */
	HIT_Local *h, *err = NULL;
        char lhit[128];
        char insert_into[256];
        int ret = 0;
        extern sqlite3 * agent_db;
        extern int init_in_progress;

	/* Check HIT name length. */
	HIP_IFEL(strlen(name) < 1, NULL, "Local HIT name too short.\n");
 
	/* Check database for HIT already with same name. */
	h = hit_db_find_local(name, NULL);
	HIP_IFE(h != NULL, h);
	h = hit_db_find_local(NULL, hit);
	HIP_IFE(h != NULL, h);

	/* Allocate new remote group item. */
	h = (HIT_Local *)malloc(sizeof(HIT_Local));
	HIP_IFEL(h == NULL, NULL, "Failed to allocate new local HIT.\n");
	
	/* Setup local HIT. */
	memset(h, 0, sizeof(HIT_Local));
	NAMECPY(h->name, name);
	memcpy(&h->lhit, hit, sizeof(struct in6_addr));

	/* Add local HIT to database. */
	if (local_db == NULL) local_db = h;
	else local_db_last->next = (void *)h;

	local_db_last = h;
	local_db_n++;

        /* Add it also to the db on disk */
        if (init_in_progress == 1) {
                HIP_DEBUG("Saving local value to disk\n");
                print_hit_to_buffer(lhit, hit);	
                sprintf(insert_into, "INSERT INTO local VALUES("
                        "'%s', '%s');", name, lhit); 
                ret = hip_sqlite_insert_into_table(agent_db, insert_into);
        }
//	if (group_db_n < 2)
	{
		_HIP_DEBUG("Group database empty, adding default group.\n");
		hit_db_add_rgroup(lang_get("default-group-name"), h, HIT_ACCEPT, 0);
	}        

	_HIP_DEBUG("New local HIT added with name \"%s\", calling GUI to show it.\n", name);

	/* Tell GUI to show local HIT. */
        /* XX Useless to call empty function --Samu*/
        //gui_hit_local_add(h);
	err = h;

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete local HIT from database.

	@return 0 on success, -1 on errors.
*/
int hit_db_del_local(char *name)
{
	/* Variables. */
	int err = -1;

	/*! \todo Implement! */
	_HIP_DEBUG("Local HIT delete not implemented yet!!!\n");
	
out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Find a local HIT from database.
	
	@param name Name of HIT to be searched.
	@param hit HIT to be searched.
	@return Pointer to HIT found, or NULL if none found.
*/
HIT_Local *hit_db_find_local(char *name, struct in6_addr *hit)
{
	/* Variables. */
	HIT_Local *h;
	int err;
	
	h = local_db;
	while (h != NULL)
	{
		err = 0;
		if (name == NULL) err++;
		else if (strncmp(h->name, name, MAX_NAME_LEN) == 0) err++;
		if (hit == NULL) err++;
		else if (memcmp(&h->lhit, hit, sizeof(struct in6_addr)) == 0) err++;
		
		if (err == 2) break;
		h = (HIT_Local *)h->next;
	}
	
	return (h);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Enumerate all local HITs in database. This function locks the database.
	
	@param f Function to call for every local HIT in database. This function
	         should return 0 if continue enumeration and something else, if
	         enumeration should be stopped.
	@param p Pointer to user data.
	@return Number of HITs enumerated.
*/
int hit_db_enum_locals(int (*f)(HIT_Local *, void *, void *), void *p, void *pdb)
{
	/* Variables. */
	HIT_Local *h;
	int err = 0, n = 0;
	
	h = local_db;
	while (h != NULL && err == 0)
	{
		err = f(h, p, pdb);
		n++;
		h = (HIT_Local *)h->next;
	}

	_HIP_DEBUG("Enumerated %d local HITs.\n", n);
	
	return (n);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Return number of local HITs in database. */
int hit_db_count_locals(void)
{
	return (local_db_n);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Return default local HIT. */
HIT_Local *hit_db_default_local(void)
{
	return (local_db);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


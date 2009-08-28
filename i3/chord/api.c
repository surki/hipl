/* Common API functions */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "chord.h"

#define RUNTIME_DIR "/var/run/chord"
#ifndef PATH_MAX
#define PATH_MAX 256
#endif
static char shmid_filename[PATH_MAX];

#ifndef SIM_CHORD
static int sp[2];  /* Socket pair for communication between the two layers */
static chordID *shared_data;
static int shmid;
#else
static chordID LeftId, RightId;
#endif

#ifndef SIM_CHORD 

/* route: forward message M towards the root of key K. */
void chord_route(chordID *k, char *data, int len)
{
  byte buf[BUFSIZE];

  if (send(sp[0], buf, pack_data(buf, CHORD_ROUTE, 
				 DEF_TTL, k, len, data), 0) < 0)
    weprintf("send failed:");  /* ignore errors */
}

/**********************************************************************/

/* init: initialize chord server, return socket descriptor */
int chord_init(char *conf_file)
{
  FILE *fp;
  struct stat stat_buf;
    
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) < 0)
    eprintf("socket_pair failed:");

  if ((shmid = shmget(IPC_PRIVATE, 1024, 0644 | IPC_CREAT)) == -1)
    eprintf("shmget failed:");

#ifndef CCURED  
  shared_data = (chordID *) shmat(shmid, (void *) 0, 0);
  if ((char *) shared_data == (char *) -1)
    eprintf("shmate failed:");
#else
  {
    void * shared_data_ret = shmat(shmid, (void *) 0, 0);
    if ((ulong) shared_data_ret == (ulong) -1)
      eprintf("shmate failed:");
    shared_data = (chordID *)__trusted_cast(__mkptr_size(shared_data_ret,
                                                         1024));
  }
#endif

  /* Write out PID, shmid for monitor */
  memset( &stat_buf, 0, sizeof(struct stat) );
  if( stat( RUNTIME_DIR, &stat_buf ) || !S_ISDIR(stat_buf.st_mode) ) {
    weprintf( "Could not open %s; not writing shmid\n", RUNTIME_DIR );

  } else {
    sprintf( shmid_filename, "%s/chord.%u.shmid", RUNTIME_DIR,
	     getpid() ); 
    fp = fopen( shmid_filename, "w");
    if (fp == NULL) {
      weprintf("Could not write %s\n", shmid_filename);
    } else {
      if( (fprintf( fp, "%d\n", shmid ) <= 0) ||
	  fflush( fp ) || fclose( fp ) ) {
	eprintf("Could not write %s\n", shmid_filename );
      }
    }
  }
  
  /* Catch all crashes/kills and cleanup */
  signal(SIGHUP, chord_cleanup);
  signal(SIGINT, chord_cleanup);
  signal(SIGILL, chord_cleanup);
  signal(SIGABRT, chord_cleanup);
  signal(SIGALRM, chord_cleanup);
  signal(SIGFPE, chord_cleanup);
  signal(SIGSEGV, chord_cleanup);
  signal(SIGPIPE, chord_cleanup);
  signal(SIGTERM, chord_cleanup);
  signal(SIGCHLD, chord_cleanup); /* If Chord process dies, exit */
  signal(SIGBUS, chord_cleanup);

  if (!fork()) {  /* child */
    chord_main(conf_file, sp[1]);
  }

  return sp[0];
}

/**********************************************************************/

void chord_cleanup(int signum)
{
  shmdt(shared_data);
  shmctl(shmid, IPC_RMID, NULL);
  unlink(shmid_filename);
  signal(SIGABRT, SIG_DFL);
  abort();
}

/**********************************************************************/

/* deliver: upcall */
void chord_deliver(int n, uchar *data)
{
  /* Convert to I3 format... by stripping off the Chord header */
  send(sp[1], data, n, 0);
}

#endif

/**********************************************************************/

/* get_range: returns the range (l,r] that this node is responsible for */
void chord_get_range(chordID *l, chordID *r)
{
#ifndef SIM_CHORD
  *l = shared_data[0];
  *r = shared_data[1];
#else
  *l = LeftId;
  *r = RightId;
#endif
}



/**********************************************************************/

void chord_update_range(chordID *l, chordID *r)
{
  //printf("update_range(");
  //print_chordID(l);
  //printf(" - ");
  //print_chordID(r);
  //printf(")\n");
#ifndef SIM_CHORD
  shared_data[0] = *l;
  shared_data[1] = *r;
#else
  LeftId = *l;
  RightId = *r;
#endif
}

/**********************************************************************/

int chord_is_local(chordID *x)
{
  chordID l, r;

  chord_get_range(&l, &r);
  return equals(x, &r) || is_between(x, &l, &r);
}

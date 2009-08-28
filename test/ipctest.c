#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

void sigh(int sig)
{
	int tmp;

	printf("Signal %d\n",sig);
	if (sig == SIGCHLD) {
		wait(&tmp); // collect the remains of the child
	}
	return;
}

int ipcid;

void child_func()
{
	char buffer[100];
	struct msgbuf *mbuf;
	struct timeval *tv;

	mbuf = (struct msgbuf *)buffer;
	tv = (struct timeval *)mbuf->mtext;
	while(1) {
		msgrcv(ipcid, mbuf, sizeof(struct timeval), 1, 0);
		gettimeofday(tv,NULL);
		mbuf->mtype = 2;
		msgsnd(ipcid, mbuf, sizeof(struct timeval), 0);
	}
}


int main(void)
{
	pid_t child;
	char buffer[100];
	struct timeval t_start, t_stop;
	struct msgbuf *mbuf;
	int i;

	mbuf = (struct msgbuf *)buffer;

	/* Get an IPC mesage queue ID */
	ipcid = msgget(IPC_PRIVATE,IPC_CREAT|S_IRWXU|S_IRWXG|S_IRWXO);
	if (ipcid == -1) {
		perror("ipcget ");
		return 0;
	}

	
	/* set signal handler */
	signal(SIGCHLD,sigh); 

	/* create a child */
	child = fork();
	if (child == 0)
		child_func();

        /* we are parent */
	/* wait for child's message */


	for(i=0;i<100;i++) {
		long a,b;
		struct timespec ts;

		mbuf->mtype = 1;
		gettimeofday(&t_start,NULL);

		msgsnd(ipcid, mbuf, sizeof(struct timeval), 0);

		msgrcv(ipcid, mbuf, sizeof(struct timeval), 2, 0);
		
		memcpy((char *)&t_stop,mbuf->mtext,sizeof(struct timeval));
		a = t_stop.tv_sec - t_start.tv_sec;
		b = t_stop.tv_usec - t_start.tv_usec;
		b = b + (a * 1000000);
		printf("%ld micros\n",b);

		ts.tv_nsec = 1000; /* 1 ms */
		ts.tv_sec = 0;
		nanosleep(&ts,NULL);
	}

	kill(child,SIGTERM);

	/* remove IPC message queue */
	msgctl(ipcid, IPC_RMID, NULL);
	return 1;
}

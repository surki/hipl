/*
	Player for OUBS ruutukehae.

	This file is part of Player.

	You can contact:
	antti.e.partanen@hut.fi
	Duge @ IRCNet (#teinidexi)
*/

/******************************************************************************/
/* INCLUDES */
#include "terminal.h"


/******************************************************************************/
/* DEFINES */

/** Maximum number of unlogged and open connections. */
#define MAX_SOCKETS 4


/******************************************************************************/
/* VARIABLES */

/** Connections that have not been logged in yet. */
int server_socks[MAX_SOCKETS];

/** Terminal pthread keeper. */
pthread_t server_pthread;

/** Whether to run or not. */
int server_run = 0;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** Send message to socket. */
void send_string(int sockfd, char *msg)
{
	send(sockfd, msg, strlen(msg), 0);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Send message to socket. */
void *term_server_send_string(void *msg)
{
	/* Variables. */
	int i;
	
	for (i = 0; i < MAX_SOCKETS; i++)
	{
		if (server_socks[i] > -1)
		{
			send_string(server_socks[i], msg);
		}
	}
	term_print(msg);

	return NULL;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Print welcome message.
*/
void term_server_welcome(int sockfd)
{
	send_string(sockfd, "* You just connected to HIP GUI server\n");
	term_print("* New client\n");
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Print full message.
*/
void term_server_full(int sockfd)
{
	send_string(sockfd, "Server full.\n");
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Receive packets.
*/
int term_server_recv_packet(int sockfd)
{
	/* Variables. */
	int numbytes, i, j, err;
	char msg[1600];
	
	memset(msg, 0, 1600);
	
	/* Receive packet from socket. */
	numbytes = recv(sockfd, msg, 1600, 0);
	
	/* If socket was closed. */
	if (numbytes < 1)
	{
		close(sockfd);
		for (i = 0; i < MAX_SOCKETS; i++)
		{
			if (server_socks[i] == sockfd) server_socks[i] = -1;
		}
		term_print("* Client quit\n");
		return (1);
	}

	/* Echo the packet back to everyone. */
	term_server_send_string(msg);

	/* Return OK. */
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Terminal interface thread.
	
	@param data Data for the thread.
*/
void *term_server_thread(void *data)
{
	/* Variables. */
	int sockfd;
	int max_fd;
	int new_fd;
	fd_set read_fds;
	fd_set sock_fds;
	struct timeval tv;
	int err = 0, i, j, x;
	struct sockaddr_storage addr;
	TERM_THREAD_DATA *tdtd = (TERM_THREAD_DATA *)data;

	/* Get data and free it. */
	sockfd = tdtd->socket;
	free(tdtd);

	/* Clear fd-sets. */
	FD_ZERO(&read_fds);
	FD_ZERO(&sock_fds);

	/* Set datagram-socket to fd-set. */
	FD_SET(sockfd, &sock_fds);
	max_fd = sockfd;
	
	HIP_DEBUG("Terminal server thread started, listening connections...\n");
	term_print("* Started as server\n");

	/* Listen and do things as long as... */
	while (server_run)
	{
		/* Reset read_fds. */
		read_fds = sock_fds;
		tv.tv_sec = SELECT_TIMEOUT_SEC;
		tv.tv_usec = SELECT_TIMEOUT_USEC;

		/* Wait for incoming packets. */
		err = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
		HIP_IFEL(err < 0, 1, "select() failed!\n");
		err = 0;

		/*
			See, if there is incoming packet,
			or was this just a timeout.
		*/
		for (i = 0; i <= max_fd; i++)
		{
			/* Check if fd is set. */
			if (FD_ISSET(i, &read_fds))
			{
				/* Check if set fd is the socket. */
				if (i == sockfd)
				{
					/* New incoming connection. Accept it. */
					x = sizeof(addr);

					new_fd = (int)accept(sockfd,
						                 (struct sockaddr *)&addr,
						                 (socklen_t *)&x);

					/* If accept ok. */
					if (new_fd >= 0)
					{
						for (j = 0; j < MAX_SOCKETS; j++)
						{
							if (server_socks[j] < 0)
							{
								server_socks[j] = new_fd;
								break;
							}
						}
						
						if (j < MAX_SOCKETS)
						{
							/* Add new connection to fd set. */
							FD_SET(new_fd, &sock_fds);

							/* If new fd bigger than old max. */
							if (new_fd > max_fd)
							{
								max_fd = new_fd;
							}

							term_server_welcome(new_fd);
							//server_new_connection()
						}
						else
						{
							term_server_full(new_fd);
							close(new_fd);
						}
					}
				}
				/* Packet received trough stream socket. */
				else
				{
					/* Handle incoming. */
					err = term_server_recv_packet(i);

					/* If socket was just closed. */
					if (err == 1)
					{
						/* Remove socket. */
						FD_CLR((unsigned int)i, &sock_fds);
						err = 0;
					}
					/* If some real error. */
					else if (err != 0)
					{
						break;
					}
				}
			}
		}

		/* If some error, then break out. */
		if (err != 0)
		{
			break;
		}
	}

out_err:
	server_run = 0;
	HIP_DEBUG("Terminal server thread exiting!\n");
	close(sockfd);
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Initialize terminal interface.
	
	@return 0 on success, -1 on errors.
*/
int term_server_init(void)
{
	/* Variables. */
	TERM_THREAD_DATA *tdtd;
	struct sockaddr_in6 addr;
	int err, i;
	int sockfd = -1;
	char yes = 1;

	/* Close client/server just for sure. */
	term_server_quit();
	term_client_quit();
	
	/* Create socket. */
	sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	HIP_IFEL(sockfd == -1, -1, "socket() failed!\n");
	
	err = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	HIP_IFEL(err < 0, -1, "setsockopt() failed!\n");
	
	/* Try bind. */
	bzero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(TERM_SERVER_PORT);
	addr.sin6_addr = in6addr_any;
	addr.sin6_flowinfo = 0;
	err = bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6));
	HIP_IFEL(err != 0, -1, "bind() failed!\n");

	/* Clear not logged sockets. */
	for (i = 0; i < MAX_SOCKETS; i++) server_socks[i] = -1;
	
	/* Start listening. */
	HIP_IFEL(listen(sockfd, 3) < 0, -1, "listen() failed!\n");

	/* Create new data and set data contents. */
	tdtd = (TERM_THREAD_DATA *)malloc(sizeof(TERM_THREAD_DATA));
	tdtd->socket = sockfd;
	
	/* Create thread for processing terminal. */
	server_run = 1;
	err = pthread_create(&server_pthread, NULL, term_server_thread, (void *)tdtd);
	HIP_IFEL(err, -1, "Failed to create terminal server thread!\n");

out_err:
	if (err && sockfd != -1) close(sockfd);
	if (err) term_print("* Failed to create server\n");
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Quit terminal server. */
void term_server_quit(void)
{
	if (server_run == 0) return;
	HIP_DEBUG("Stopping terminal server...\n");
	server_run = 0;
	pthread_join(server_pthread, NULL);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


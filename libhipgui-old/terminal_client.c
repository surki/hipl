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
/* VARIABLES */

/** Terminal pthread keeper. */
pthread_t client_pthread;

/** Whether to run or not. */
int client_run = 0;

/** Client socket. */
int client_sockfd = -1;


/******************************************************************************/
/* FUNCTIONS */


/******************************************************************************/
/** Send message to socket. */
void *term_client_send_string(void *msg)
{
	int n;
	n = send(client_sockfd, msg, strlen(msg), 0);
	return NULL;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Receive packets.
*/
int term_client_recv_packet(int sockfd)
{
	/* Variables. */
	int numbytes;
	char msg[1600];
	
	memset(msg, 0, 1600);
	
	/* Receive packet from socket. */
	numbytes = recv(sockfd, msg, 1600, 0);
	
	/* If socket was closed. */
	if (numbytes < 1)
	{
		term_print("* Server closed connection\n");
		close(sockfd);
		return (1);
	}

	term_print(msg);
	
	/* Return OK. */
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Terminal interface thread.
	
	@param data Data for the thread.
*/
void *term_client_thread(void *data)
{
	/* Variables. */
	int max_fd;
	int new_fd;
	fd_set read_fds;
	fd_set sock_fds;
	struct timeval tv;
	int err = 0, i, j, x;
	struct sockaddr_storage addr;
	struct sockaddr_in6 *addr6;
	struct addrinfo hints, *ai_list = NULL;
	char port_string[32];

	/* Clear struct. */
	memset(&hints, 0, sizeof(hints));

	/* Set up struct. */
	hints.ai_flags = AI_HIP;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	sprintf(port_string, "%d", TERM_SERVER_PORT);

	/* Get the host info. */
	err = getaddrinfo(term_get_server_addr(), port_string, &hints, &ai_list);
	if (err)
	{
		HIP_DEBUG("getaddrinfo() failed!\n");
		term_print("* Failed to resolve given address\n");
		err = -1;
		goto out_err;
	}
		
	/* Convert address. */
	addr6 = (struct sockaddr_in6 *)ai_list->ai_addr;

	/* Create socket. */
	client_sockfd = socket(PF_INET6, SOCK_STREAM, 0);
	HIP_IFEL(client_sockfd == -1, -1, "socket() failed!\n");

	/* Try to connect to resolved address. */
	err = connect(client_sockfd, (struct sockaddr *)addr6, sizeof(struct sockaddr_in6));
	if (err)
	{
		HIP_DEBUG("connect() failed!\n");
		term_print("* Failed to connect to server\n");
		err = -1;
		goto out_err;
	}

	/* Clear fd-sets. */
	FD_ZERO(&read_fds);
	FD_ZERO(&sock_fds);

	/* Set datagram-socket to fd-set. */
	FD_SET(client_sockfd, &sock_fds);
	max_fd = client_sockfd;
	
	HIP_DEBUG("Terminal client thread started...\n");
	term_print("* Started as client\n");

	/* Listen and do things as long as... */
	while (client_run)
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
		if (FD_ISSET(client_sockfd, &read_fds))
		{
			/* Handle incoming. */
			err = term_client_recv_packet(client_sockfd);

			/* If some error. */
			if (err != 0)
			{
				break;
			}
		}
	}

out_err:
	client_run = 0;
	HIP_DEBUG("Terminal client thread exiting!\n");
	close(client_sockfd);
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Initialize terminal interface.
	
	@return 0 on success, -1 on errors.
*/
int term_client_init(void)
{
	/* Variables. */
	int err = 0;

	/* Close client/server just for sure. */
	term_server_quit();
	term_client_quit();
	
	/* Create thread for processing terminal. */
	client_run = 1;
	err = pthread_create(&client_pthread, NULL, term_client_thread, NULL);
	HIP_IFEL(err, -1, "Failed to create terminal client thread!\n");

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Quit terminal client. */
void term_client_quit(void)
{
	if (client_run == 0) return;
	HIP_DEBUG("Stopping terminal client...\n");
	client_run = 0;
	pthread_join(client_pthread, NULL);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/


/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "connhipd.h"
#include "builder.h"

/******************************************************************************/
/* VARIABLES */
/** This socket is used for communication between agent and HIP daemon. */
int hip_agent_sock = 0;
/** This is just for waiting the connection thread to start properly. */
int hip_agent_thread_started = 0;
/** Connection pthread holder. */
pthread_t connhipd_pthread;
/** Determine whether we are connected to daemon or not. */
int hip_agent_connected = 0;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize connection to hip daemon.

	@return 0 on success, -1 on errors.
*/
int connhipd_init_sock(void)
{
	int err = 0;
	struct sockaddr_in6 agent_addr;

	hip_agent_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL(hip_agent_sock < 0, -1, "Failed to create socket.\n");

	memset(&agent_addr, 0, sizeof(agent_addr));
        agent_addr.sin6_family = AF_INET6;
        agent_addr.sin6_addr = in6addr_loopback;
	agent_addr.sin6_port = htons(HIP_AGENT_PORT);

	HIP_IFEL(hip_daemon_bind_socket(hip_agent_sock, &agent_addr), -1,
		 "bind failed\n");

	HIP_IFEL(hip_daemon_connect(hip_agent_sock), -1, "connect");

  out_err:
	return err;
}
	

int connhipd_run_thread(void)
{
	int err = 0;
	struct hip_common *msg = NULL;

	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "Failed to Allocate message.\n");

	hip_agent_thread_started = 0;
	pthread_create(&connhipd_pthread, NULL, connhipd_thread, msg);

	while (hip_agent_thread_started == 0)
		usleep(100 * 1000);
	usleep(100 * 1000);

out_err:
	if (err && hip_agent_sock)
		close(hip_agent_sock);
	if (err && msg)
		HIP_FREE(msg);

	return err;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Handle message from agent socket.
*/
int connhipd_handle_msg(struct hip_common *msg,
                        struct sockaddr_un *addr)
{
	/* Variables. */
	struct hip_tlv_common *param = NULL, *param2 = NULL;
	struct hip_common *emsg;
	hip_hdr_type_t type;
	HIT_Remote hit, *r;
	HIT_Local *l;
	socklen_t alen;
	struct in6_addr *lhit, *rhit;
	int err = 0, ret, n, direction, check;
	char chit[128], *type_s;
	
	struct in6_addr hitr ;
	type = hip_get_msg_type(msg);

	if (type == SO_HIP_AGENT_PING_REPLY)
	{
		HIP_DEBUG("Received ping reply from daemon. Connection to daemon established.\n");
		gui_set_info(lang_get("gui-info-000"));
		hip_agent_connected = 1;
	}
	else if (type == SO_HIP_SET_NAT_ON)
	{
		gui_update_nat(1);
		HIP_DEBUG("NAT extensions on.\n");
	}
	else if (type == SO_HIP_SET_NAT_OFF)
	{
		gui_update_nat(0);
		HIP_DEBUG("NAT extensions off.\n");
	}
	else if (type == SO_HIP_DAEMON_QUIT)
	{
		HIP_DEBUG("Daemon quit. Waiting daemon to wake up again...\n");
		gui_set_info(lang_get("gui-info-001"));
		hip_agent_connected = 0;
	}
	else if (type == SO_HIP_ADD_DB_HI)
	{
		HIP_DEBUG("Message received successfully from daemon with type"
		          " HIP_ADD_DB_HI (%d).\n", type);
		n = 0;

		while((param = hip_get_next_param(msg, param)))
		{
			if (hip_get_param_type(param) == HIP_PARAM_HIT)
			{
				lhit = (struct in6_addr *)hip_get_param_contents_direct(param);
				HIP_HEXDUMP("Adding local HIT:", lhit, 16);
				print_hit_to_buffer(chit, lhit);
				hit_db_add_local(chit, lhit);
				n++;
			}
		}
	}
	else if (type == SO_HIP_UPDATE_HIU)
	{
		n = 0;
		
		gui_hiu_clear();
		
		while((param = hip_get_next_param(msg, param)))
		{
			/*param2 = hip_get_next_param(msg, param);
			if (param2 == NULL) break;*/
			
			if (hip_get_param_type(param) == HIP_PARAM_HIT)/* &&
			    hip_get_param_type(param2) == HIP_PARAM_HIT)*/
			{
				rhit = (struct in6_addr *)hip_get_param_contents_direct(param);
				//lhit = hip_get_param_contents_direct(param2);
				r = hit_db_find(NULL, rhit);
				if (r)
				{
					gui_hiu_add(r);
					n++;
				}
			}
		}
		
		gui_hiu_count(n);
	}
	else if (type == HIP_I1 || type == HIP_R1)
	{
		NAMECPY(hit.name, "");
		URLCPY(hit.url, "<notset>");
		URLCPY(hit.port, "");

		HIP_DEBUG("Message from daemon, %d bytes.\n", hip_get_msg_total_len(msg));

		/* Get original message, which is encapsulated inside received one. */
		emsg = (struct hip_common *)hip_get_param_contents(msg, HIP_PARAM_ENCAPS_MSG);
		HIP_IFEL(!emsg, -1, "Could not get msg parameter!\n");

		HIP_HEXDUMP("msg->hits: ", &emsg->hits, 16);
		HIP_HEXDUMP("msg->hitr: ", &emsg->hitr, 16);

		/* Find out, which of the HITs in the message is local HIT. */
		l = hit_db_find_local(NULL, &emsg->hits);
		if (!l)
		{
			l = hit_db_find_local(NULL, &emsg->hitr);
			if (l)
			{
				memcpy(&hit.hit, &emsg->hits, sizeof(hit.hit));
			}
			HIP_IFEL(!l, -1, "Did not find local HIT for message!\n");
		}
		else
		{
			memcpy(&hit.hit, &emsg->hitr, sizeof(hit.hit));
		}

		HIP_DEBUG("Received %s %s from daemon.\n", "incoming",
		          type == HIP_I1 ? "I1" : "R1");

		/* Check the remote HIT from database. */
		if (l) 
		{
			memcpy(&hitr,&hit.hit, sizeof(struct in6_addr));
			ret = check_hit(&hit, 0);
			/*Send our hits -- peer hit to daemon*/
			if (ret == 1)
				ret = 0; /*hit already exist in the database and is accepted
							so no need to send it to daemon*/
			else if (ret == 0)
				connhipd_send_hitdata_to_daemon (msg, &hitr, &hit.g->l->lhit) ;
			/* Reset local HIT, if outgoing I1. */
			/*HIP_HEXDUMP("Old local HIT: ", &msg->hits, 16);
			HIP_HEXDUMP("New local HIT: ", &hit.g->l->lhit, 16);
			HIP_HEXDUMP("Old remote HIT: ", &msg->hitr, 16);
			HIP_HEXDUMP("New remote HIT: ", &hit.hit, 16);*/
		}
		/* If neither HIT in message was local HIT, then drop the packet! */
		else
		{
			HIP_DEBUG("Failed to find local HIT from database for packet."
			          " Rejecting packet automatically.\n");
			HIP_HEXDUMP("msg->hits: ", &msg->hits, 16);
			HIP_HEXDUMP("msg->hitr: ", &msg->hits, 16);
			ret = -1;
		}
		
		/*
			Now either reject or accept the packet,
			according to previous results.
		*/
		if (ret == 0)
		{
			HIP_DEBUG("Message accepted, sending back to daemon, %d bytes.\n",
                      hip_get_msg_total_len(msg));
			n = hip_send_recv_daemon_info((char *)msg, 1, hip_agent_sock);
			HIP_IFEL(n < 0, -1, "Could not send message back to daemon"
			                    " (%d: %s).\n", errno, strerror(errno));
			HIP_DEBUG("Reply sent successfully.\n");
		}
		else if (type == HIP_R1)
		{
			HIP_DEBUG("Message rejected.\n");
			n = 1;
			HIP_IFE(hip_build_param_contents(msg, &n, HIP_PARAM_AGENT_REJECT, sizeof(n)), -1);
			n = hip_send_recv_daemon_info((char *)msg, 1, hip_agent_sock);
			HIP_IFEL(n < 0, -1, "Could not send message back to daemon"
			                    " (%d: %s).\n", errno, strerror(errno));
			HIP_DEBUG("Reply sent successfully.\n");
		}
		else
		{
			HIP_DEBUG("Message rejected.\n");
		}
	}

out_err:
//	HIP_DEBUG("Message handled.\n");
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	This thread keeps the HIP daemon connection alive.
*/
void *connhipd_thread(void *data)
{
	/* Variables. */
	int err = 0, n, len, ret, max_fd;
	struct sockaddr_in6 agent_addr;
	struct hip_common *msg = (struct hip_common *)data;
	socklen_t alen;
	fd_set read_fdset;
	struct timeval tv;

	HIP_DEBUG("Waiting messages...\n");

	/* Start handling. */
	hip_agent_thread_started = 1;
	while (hip_agent_thread_started)
	{
		FD_ZERO(&read_fdset);
		FD_SET(hip_agent_sock, &read_fdset);
		max_fd = hip_agent_sock;
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		if (hip_agent_connected < 1)
		{
			/* Test connection. */
			//HIP_IFEL(hip_agent_connected < -60, -1, "Could not connect to daemon.\n");
			//HIP_DEBUG("Pinging daemon...\n");
			hip_build_user_hdr(msg, SO_HIP_AGENT_PING, 0);
			n = hip_send_recv_daemon_info((char *)msg, 1, hip_agent_sock);
			//if (n < 0) HIP_DEBUG("Could not send ping to daemon, waiting.\n");
			hip_agent_connected--;
		}
		
		/* Wait for incoming packets. */
		if (select(max_fd + 1, &read_fdset, NULL,NULL, &tv) == -1)
		{
			HIP_ERROR("select() error: %s.\n", strerror(errno));
			err = -1;
			goto out_err;
		}

		if (!hip_agent_thread_started) continue;
		if (!FD_ISSET(hip_agent_sock, &read_fdset)) continue;

		memset(&agent_addr, 0, sizeof(agent_addr));
		alen = sizeof(agent_addr);
		n = recvfrom(hip_agent_sock, msg, sizeof(struct hip_common), MSG_PEEK,
		             (struct sockaddr *)&agent_addr, &alen);
		if (n < 0)
		{
			HIP_ERROR("Error receiving message header from daemon.\n");
			err = -1;
			goto out_err;
		}

//		HIP_DEBUG("Header received successfully\n");
		alen = sizeof(agent_addr);
		len = hip_get_msg_total_len(msg);

		n = recvfrom(hip_agent_sock, msg, len, 0,
		             (struct sockaddr *)&agent_addr, &alen);

		if (n < 0)
		{
			HIP_ERROR("Error receiving message parameters from daemon.\n");
			err = -1;
			goto out_err;
		}

		//HIP_DEBUG("Received message from daemon (%d bytes)\n", n);

		//HIP_ASSERT(n == len);
		if (n != len) {
			HIP_ERROR("Received packet length and HIP msg len dont match %d != %d!!!\n", n, len);
			continue;
		}

		if (agent_addr.sin6_port != ntohs(HIP_DAEMON_LOCAL_PORT)) {
			HIP_DEBUG("Drop, message not from hipd");
			continue;
		}

		connhipd_handle_msg(msg, &agent_addr);
	}


out_err:
	/* Send quit message to daemon. */
	hip_build_user_hdr(msg, SO_HIP_AGENT_QUIT, 0);
	n = hip_send_recv_daemon_info((char *)msg, 1, hip_agent_sock);
	if (n < 0)
		HIP_ERROR("Could not send quit message to daemon.\n");

	if (hip_agent_sock)
		close(hip_agent_sock);
	if (msg != NULL)
		HIP_FREE(msg);

	hip_agent_thread_started = 0;
	agent_exit();

	HIP_DEBUG("Connection thread exit.\n");

	/* This function cannot have a returning value */
	/*return (err);*/

}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Quits connection thread. Function agent_exit() should be called before
	calling this.
*/
void connhipd_quit(void)
{
	if (!hip_agent_thread_started) return;
	HIP_DEBUG("Stopping connection thread...\n");
	hip_agent_thread_started = 0;
	pthread_join(connhipd_pthread, NULL);
}
/* END OF FUNCTION */

/**
 * connhipd_send_hitdata_to_daemon - builds a param containing hits to be
 * sent to the daemon
 * @param *msg packet to be sent to daemon
 * @param *hitr remote hit accepted
 * @param *hitl local hit used
 * @return 0 on success, -1 on error
 */
int connhipd_send_hitdata_to_daemon(struct hip_common * msg , struct in6_addr * hitr, struct in6_addr * hitl)
{
	int err = 0;
	struct hip_uadb_info uadb_info ;
	char hittest[40];
	HIP_DEBUG("Building User Agent DB info message to be sent to daemon.\n");
	memcpy(&uadb_info.hitr,hitr, sizeof(struct in6_addr)) ;
	memcpy(&uadb_info.hitl,hitl, sizeof(struct in6_addr)) ;
	hip_in6_ntop(&uadb_info.hitr, hittest);
    HIP_DEBUG("Value: %s\n", hittest);
	
	memcpy(uadb_info.cert,"certificate\0",sizeof("certificate\0"));
	
	hip_build_param_hip_uadb_info(msg, &uadb_info);
	HIP_DUMP_MSG (msg);
out_err:
	return (err);
}




/* END OF SOURCE FILE */
/******************************************************************************/


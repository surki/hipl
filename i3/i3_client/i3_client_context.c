/***************************************************************************
                          i3_client_context.c  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu

    changes: 
      Nov 10, 2004: - handle the anycast triggers inserted by the same node
                      (in cl_context_select)
             
 ***************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>   /* basic system data types */
#include <time.h>        /* timespec{} for pselect() */
#ifndef _WIN32
    #include <unistd.h>
    #include <sys/errno.h>
#else
    #include <errno.h>
#endif
#include "../utils/netwrap.h"

#include "../utils/utils.h"
#include "../utils/gen_utils.h"
#include "i3.h"
#include "i3_fun.h"
#include "i3_client.h"
#include "i3_client_fun.h"
#include "i3_config.h"
#include "i3_debug.h"
#include "i3_client_api_ctx.h"
#include "ping_thread.h"

#include "aes.h"

int tval_zero(struct timeval *t);
void tval_min(struct timeval *tmin, struct timeval *t1, struct timeval *t2);
int tval_equal(struct timeval *t1, struct timeval *t2);
uint64_t tval_to_uint64(struct timeval *tv);
void uint64_to_tval(struct timeval *tv, uint64_t time);
void tval_normalize(struct timeval *t);
void cl_update_to(struct timeval *cl_to, uint64_t diff);
struct in_addr get_local_addr_cl();
int check_addr_change(struct in_addr *ia);
void timeout_server_update(cl_context *ctx);

int does_id_match(ID *id1, ID *id2, int prefix_len);

void close_tcp(cl_context *ctx) {

  printf ("\nClosing fd = %d\n", ctx->tcp_fd);
  nw_close(ctx->tcp_fd);
 
  ctx->init_tcp_ctx_flag = 0; //TCP socket is not initialized.
}

/**
  * This function initializes the TCP socket used to communicate
  * with the first hop i3 server, if UseTCP is set in the configuration file
  * @author Dilip
  */
void init_tcp_ctx(cl_context* ctx) {
  int idx;
  struct sockaddr_in server_addr;
  
  if (ctx->is_tcp) {
    fprintf(stderr, "Warning: Mobility using TCP unsupported\n");
    
    if (ctx->init_tcp_ctx_flag)
      close_tcp(ctx); // make sure that there isn't a TCP connection
                      // in inconsistent state
    if ((ctx->tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket");
      I3_PRINT_INFO1(I3_INFO_LEVEL_WARNING, 
		 "Failed to create TCP socket (errno = %d)\n", errno);
      ctx->init_tcp_ctx_flag = 0;
      return;
    }
        
    printf("open TCP socket = %d\n", ctx->tcp_fd); // XXX
    if (bind(ctx->tcp_fd, (struct sockaddr *) &ctx->local, 
	     sizeof(struct sockaddr_in)) < 0) { 
      I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, 
		  "cl_init_context: TCP bind (errno = %d)\n", errno);
      close_tcp(ctx);
      return;
    }

    /* Get server from the list and connect to it
     * For now, it is assumed that there is only one server on the
     * list and (obviously) that is the first hop i3 server 
     */
    idx = get_i3_server(ctx->num_servers, ctx->s_array);
    if (idx < 0) {
      if (!ctx->use_ping) {
	I3_PRINT_INFO0 (I3_INFO_LEVEL_FATAL_ERROR, 
		    "There are no known i3 servers specified in the configuration file "
		    "and UsePing is deactivated.  So there is no way I can get to know "
		    "about an i3 server.\nPlease turn on UsePing or specify i3 server "
		    "details in the i3 configuration file.\n"
                    );
	EXIT_ON_ERROR;
      }
      close_tcp(ctx);
      return;

      //TODO fix i3 client API to include timer to reattempt tcp init later.
    }
    
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(ctx->s_array[idx].addr.s_addr);
    server_addr.sin_port = htons(ctx->s_array[idx].port);
       
    I3_PRINT_INFO1 (I3_INFO_LEVEL_MINIMAL,
                "I3 OC-D trying to connect to %s via TCP.\n", 
                inet_ntoa (((struct sockaddr_in *) &server_addr)->sin_addr));
                
    if (connect(ctx->tcp_fd, (struct sockaddr *)&server_addr, 
		sizeof(struct sockaddr_in)) < 0) {
      I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_MINIMAL, 
		  "cl_init_context: TCP connect error (errno = %d)\n", errno);
      close_tcp(ctx);; 
    } else {
      I3_PRINT_INFO1(I3_INFO_LEVEL_MINIMAL,
		 "I3 OC-D connected to %s via TCP.\n", 
		 inet_ntoa (((struct sockaddr_in *) &server_addr)->sin_addr));
      ctx->init_tcp_ctx_flag = 1; //TCP socket was initialized.
    }
  }
} 


/***************************************************************************
 *  cl_create_context - allocate and initialize i3 client context. the context 
 *                      maintains the address of a default i3 server and the 
 *                      list of the triggers inserted by the client
 *
 *  input:
 *    local_ip_addr, local_port - local IP address and port where 
 *       i3 packets are to be received (in host format)
 *
 *  return:
 *    allocated context
 ***************************************************************************/

cl_context *cl_create_context(struct in_addr *local_ip_addr,
			      uint16_t local_port)
{
  cl_context	*ctx;
  uint8_t	opt_mask;
  int bind_ret_val;
  
  aeshash_init();

  if (local_port == 0) {
    local_port = unif_rand(MIN_PORT_NUM, MAX_PORT_NUM);
    I3_PRINT_DEBUG1(I3_DEBUG_LEVEL_VERBOSE, "i3 port number: %d\n", local_port);
  }

  if (!(ctx = (cl_context *)calloc(1, sizeof(cl_context))))
        I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_init_context: memory allocation error (1)\n");

  uint64_to_tval(&ctx->now, wall_time());

  if (!(ctx->s_array = (srv_address *)calloc(MAX_NUM_SRV,sizeof(srv_address))))
        I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_init_context: memory allocation error (2)\n");

  /* read the list of i3 server addreses from the configuration file */
  read_srv_list(ctx);

  /* create field descriptor and address data structure to 
   * receive i3 traffic */

  {
	int tmpFD = socket (AF_INET, SOCK_DGRAM, 0);
	char*tmp;
	if (tmpFD < 0) {
		perror ("socket");
		I3_PRINT_DEBUG1 ( I3_DEBUG_LEVEL_WARNING,
				"Unable to open i3 UDP socket: %s.\n",
				strerror (errno)
			);
		tmp = strerror (errno);

			  switch (errno) {
					case EBADF:
						printf ("EBADF\n");
					break;
					case EINVAL:
						printf ("EINVAL\n");
					break;
					case EACCES:
						printf ("EACCES\n");
					break;
					case ENOTSOCK:
						printf ("ENOTSOCK\n");
					break;
					case EROFS:
						printf ("EROFS	\n");
					break;
		
					case EFAULT:
						printf ("EFAULT\n");
					break;

					case ENAMETOOLONG:
						printf ("ENAMETOOLONG\n");
					break;	
					case ENOENT:
						printf ("ENOENT\n");
					break;
					case ENOMEM:
						printf ("ENOMEME\n");
					break;
			  }
			exit(-1);
	} else {
		ctx->fd = tmpFD;
	}
  }

  

  memset(&ctx->local, 0, sizeof(struct sockaddr_in));
  ctx->local.sin_family = AF_INET;
  ctx->local.sin_addr.s_addr = htonl(INADDR_ANY);
  ctx->local.sin_port = htons(local_port);
    
  /* bind to the port */

  if ((bind_ret_val = bind(ctx->fd, (struct sockaddr *) &ctx->local,  sizeof(struct sockaddr_in))) < 0) {
		
	  switch (bind_ret_val) {
		case EBADF:
		    printf ("EBADF\n");
		break;
		case EINVAL:
			printf ("EINVAL\n");
		break;
		case EACCES:
			printf ("EACCES\n");
		break;
		case ENOTSOCK:
			printf ("ENOTSOCK\n");
		break;
		case EROFS:
			printf ("EROFS	\n");
		break;
		
		case EFAULT:
			printf ("EFAULT\n");
		break;

		case ENAMETOOLONG:
			printf ("ENAMETOOLONG\n");
		break;	
		case ENOENT:
			printf ("ENOENT\n");
		break;
		case ENOMEM:
			printf ("ENOMEME\n");
		break;
	}
	I3_PRINT_INFO1 (
				I3_INFO_LEVEL_WARNING,
				"Critical Error: Unable to bind i3 socket while creating context: %s.\n",
				strerror (errno)
				);
	return NULL;
		//panic("cl_init_context: bind\n");
  }

  I3_PRINT_DEBUG3(
            I3_DEBUG_LEVEL_VERBOSE,
            "Bound i3 fd=%d to %d : %s\n", 
            ctx->fd, 
            ctx->local.sin_port, 
            inet_ntoa(ctx->local.sin_addr)
        );


  if (local_ip_addr)
    ctx->local_ip_addr = *local_ip_addr;
  else
    ctx->local_ip_addr = get_local_addr_cl(); // keep it in host format 

  ctx->local_port = local_port;

  /* PRIORITY QUEUE Initialization */
#define MAX_TRIGGERS 100000

  /* precompute option part of headers */
  for (opt_mask = 0; opt_mask < MAX_OPTS_MASK_SIZE; opt_mask++)
    make_data_opt(ctx, opt_mask, &ctx->precomputed_opt[opt_mask]);

  /* Ping list initialization */
  ctx->list = NULL;

  /* init timer heap */
  init_timer_heap(ctx);

  /* allocate data structure for file descriptors that the user may register */
  ctx->i3fds = alloc_i3_fds();

  return ctx;
}

/* close sockets and re-open them */
void cl_reinit_context(cl_context *ctx)
{
  static int so_reuseaddr = 1;
  uint8_t opt_mask;
  
  if (ctx->fd)
    nw_close(ctx->fd);
  if (ctx->init_tcp_ctx_flag && ctx->is_tcp)
    close_tcp(ctx);

  if ((ctx->fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror ("socket recreation");
    
    exit(-1);
  }

  memset(&ctx->local, 0, sizeof(struct sockaddr_in));
  ctx->local.sin_family = AF_INET;
  ctx->local.sin_addr.s_addr = htonl(INADDR_ANY);
  ctx->local.sin_port = htons(ctx->local_port);

  if ((setsockopt(ctx->fd, SOL_SOCKET, SO_REUSEADDR,
	  (char *)&so_reuseaddr, sizeof(so_reuseaddr))) < 0) {
    perror("setsockopt");
  }
  
  if (bind(ctx->fd, (struct sockaddr *) &ctx->local, 
	   sizeof(struct sockaddr_in)) < 0) 
        I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "cl_reinit_context: bind\n");

  /* precompute option part of headers */
  for (opt_mask = 0; opt_mask < MAX_OPTS_MASK_SIZE; opt_mask++) {
    if (ctx->precomputed_opt[opt_mask].p)
      free(ctx->precomputed_opt[opt_mask].p);
    make_data_opt(ctx, opt_mask, &ctx->precomputed_opt[opt_mask]);
  }

  if (ctx->is_tcp) {
    init_tcp_ctx(ctx);
    fprintf(stderr, "Warning: Mobility using TCP unsupported\n");  
  }
}


void cl_destroy_context(cl_context *ctx)
{
  int i;
  uint8_t opt_mask;

  for (i = 0; i < CL_HTABLE_SIZE; i++) {
    if (ctx->trigger_htable[i])
      cl_free_trigger_list(ctx->trigger_htable[i]);
    if (ctx->id_htable[i])
      cl_free_id_list(ctx->id_htable[i]);
  }

  free_timer_heap(ctx);
  free_i3_fds(ctx->i3fds);   
  ctx->i3fds = NULL;

  for (opt_mask = 0; opt_mask < MAX_OPTS_MASK_SIZE; opt_mask++)
      if (ctx->precomputed_opt[opt_mask].p)
	  free(ctx->precomputed_opt[opt_mask].p);

  free(ctx->s_array);

  // close the connections assocatied with the context
  nw_close (ctx->fd);
  if (ctx->init_tcp_ctx_flag) {
      close_tcp(ctx); 
  }

  free (ctx); //deallocate the memory
}

#define MAX_PACKET_SIZE 4096

int cl_context_select(cl_context *ctx, int n, 
		      fd_set *readfds, fd_set *writefds, fd_set *exceptfds, 
		      struct timeval *cl_to)
{  
  int			max_fd, rc;
  static struct timeval to, tv;
  uint64_t              now, crt_time;
  struct timeval 	next_to, sel_to;
  static cl_buf	       *clb = NULL;
  char		        packet_received;
  assert(readfds);

  /* initialize vars when this method is called for the first time */
  if (NULL == clb) {
    now = wall_time();
    clb = cl_alloc_buf(MAX_PACKET_SIZE);
    
    /* set timeout to check whether the refresh has changed */
    tv.tv_sec  = ADDR_CHECK_PERIOD;
    tv.tv_usec = random_sec();
    cl_set_timer(&tv, timeout_address_change, ctx);
    
    /* set timeout refresh the server list */
    tv.tv_sec  = SERVER_UPDATE_PERIOD;
    tv.tv_usec = random_sec();
    cl_set_timer(&tv, timeout_server_update, ctx);
  }
  
  /* There are three types of file descriptors:
   *  1) Descriptors on which the client receives i3 packets from
   *     the i3 servers (ctx->fd and ctx->fd_tcp)
   *  2) Descriptors for which the application has registered callbacks
   *  3) Descriptors which application has passed as arguments in 
   *     the cl_select() function    
   */
  max_fd = MAX(ctx->fd + 1, n);
  // printf("------------------ ctx->tcp_fd=%d, max_fd=%d\n", 
  //	 ctx->tcp_fd, max_fd);
  if (ctx->is_tcp && ctx->init_tcp_ctx_flag) {
    max_fd = MAX(ctx->tcp_fd + 1, max_fd);
  }
  max_fd = MAX(max_fd, ctx->i3fds->max_fd + 1);
  
  for (;;) {
    /* update current time */
    now = wall_time();
    uint64_to_tval(&ctx->now, now);
    
    /* set socket descriptors for i3 traffic and for the callbacks
     * inserted by the applications
     */
    /* if another tcp connection or user connection have been opened,
     * update max_fd
     */
    if (ctx->is_tcp && ctx->init_tcp_ctx_flag && ctx->tcp_fd >= max_fd) {
      max_fd = MAX(ctx->tcp_fd + 1, max_fd);
    }
    if (ctx->i3fds->max_fd >= max_fd) {
      max_fd = MAX(max_fd, ctx->i3fds->max_fd + 1);
    }

    FD_SET(ctx->fd, readfds); 
    
    if (ctx->is_tcp && ctx->init_tcp_ctx_flag) {
      FD_SET(ctx->tcp_fd, readfds);
    }
    
    set_i3_fds(ctx->i3fds, readfds, writefds, exceptfds);
    
    /* invoke timer callbacks inserted by the application */
    invoke_timers(ctx, now);

    /* compute timeout (to) for select() as minimum between
     * (1) the timeout (cl_to) pased by application are argument of 
     *     cl_context_select() 
     * (2) time to next event set by application via cl_set_timer()
     *     system call
     */
    if (get_next_timer(ctx, &next_to, now)) {
      tval_min(&to, &next_to, cl_to);
    } else {
      to = *cl_to;
    }

    /* remember timeout of select, because some slect implementations
     * may update timeout "to" to indicate how much time has passed
     */
    sel_to = to;
    packet_received = 0;
    /* select() */
    
    if ((rc = select(max_fd, readfds, writefds, exceptfds, &to)) < 0) {
      int err = nw_error();
      if ((err == EINTR) || (err == EBADF)) {
	if (cl_to) {
	  /* update cl_to with the time spent in select() */
	  crt_time = wall_time();
	  cl_update_to(cl_to, crt_time - now);
	  if (cl_to->tv_sec == 0 && cl_to->tv_usec == 0) {
	    /* check whether any timers expired while in select, before
	     * returning
	     */
	    invoke_timers(ctx, crt_time);
	    /* client's timout has expired; tell client to try again... */
	    errno = EINTR;
	    return rc;
	  }
	}
	/* check client's callbacks before continuing... */
	invoke_i3_fds(ctx->i3fds, readfds, writefds, exceptfds);
	continue;
      } else {
	err_sys("select_error\n");
      }
    }
    
    //printf("(3)\n");
    if (rc > 0) {
      /* at least one packet has been received, thus
       * timeout "to" probably didn't expire 
       */
      packet_received = 1;
    }
    
    /* check whether a packet hasn't been received on any of the 
     * callback file descriptors
     */
    rc -= invoke_i3_fds(ctx->i3fds, readfds, writefds, exceptfds);
    
    /* i3 packet has been received */
    if (FD_ISSET(ctx->fd, readfds) || 
	(ctx->is_tcp && ctx->init_tcp_ctx_flag &&
	 FD_ISSET(ctx->tcp_fd, readfds))) {
      int retVal;
      
      rc -= 1;

      //ADDED_DILIP
      retVal = cl_process_recd_i3_pkt(ctx, clb);
      
      if (retVal == CL_CONTINUE) {
	if (cl_to)
	  /* update cl_to with the time spent in select */
	  cl_update_to(cl_to, wall_time() - now);
	continue;
      } 
    }  
    
    /* either cl_to expired or a packet on another socket 
     * has been received*/
    /* --- WARNING: This can lead to EXTREMELY subtle bugs --- TODO! */
    if (!packet_received && cl_to && tval_equal(cl_to, &sel_to)) {
      /* if no packet has been received, then the select 
       * timeout must have been expired. Check whether
       * this timeout was equal to the client timeout, and if
       * yes return 
       */
      cl_to->tv_sec = cl_to->tv_usec = 0;
      invoke_timers(ctx, wall_time());
      return rc;
    }
    
    if (rc > 0) {
      /* there is a packet received on a socket descriptor passed by the
       * client in the cl_select function 
       */
      /* update cl_to with the time spent in select,
       * and check whether any other timeouts expired during
       * this period; then return
       */      
      crt_time = wall_time();
      if (cl_to)
	cl_update_to(cl_to, crt_time - now);
      invoke_timers(ctx, crt_time);
      return rc;
    }
    /* continue, after updating cl_to... */
    if (cl_to)
      cl_update_to(cl_to, wall_time() - now);
  }
}

/**
  * This function is called when an i3 packet is received.
  * The received i3 packet is processed here.  
  * This function is usually called from within a select loop.
  */
int cl_process_recd_i3_pkt (cl_context * ctx, cl_buf *clb) {
	  
  struct sockaddr_in fromaddr;
  i3_header *hdr;
  cl_trigger *ctr, *ctr_next;
  
  int recv_ret_val;
  
  /* hdr is allocated in cl_receive_packet; remember to free it ... */
  recv_ret_val = cl_receive_packet_from (ctx, &hdr, clb, &fromaddr);
  
  if (recv_ret_val == 0) {
    //Some error occurred while reading packet
    
    if (ctx->is_tcp)
      close_tcp(ctx);
    
    return CL_RECV_ERROR;
  }
  
  if (hdr == NULL)
    return CL_CONTINUE;
  
  if (hdr->option_list) {
    /* process option list received in the packet header */
    cl_process_option_list (ctx, hdr, &fromaddr);
  }
  
  if (hdr->stack && hdr->stack->len) {
    
    /* the packet may match multiple triggers;
     * implement anycast, by getting the longest prefix match 
     */
    int max_prefix_len;
    max_prefix_len =
      cl_get_max_prefix_len_from_list(
	ctx->trigger_htable[CL_HASH_TRIG(hdr->stack-> ids)], hdr->stack->ids);
    
    /* get trigger's data structure */
    ctr = cl_get_trigger_by_id(
      ctx->trigger_htable[CL_HASH_TRIG (hdr->stack->ids)],
      hdr->stack->ids);

    for (; ctr;) {
      if ((does_id_match (&ctr->t->id,
			  hdr->stack->ids,
			  max_prefix_len) == FALSE)
	  || (ctr->t->to->type != I3_ADDR_TYPE_IPv4)) {
	ctr = ctr->next;
	continue;
      }
      
      ctr_next = ctr->next;
      
      if (ctr->cbk_receive_packet.fun != NULL)
	cl_trigger_callback (ctx, ctr, CL_CBK_RECEIVE_PACKET, hdr, clb);
      else if (hdr->flags & I3_DATA)
	cl_trigger_callback (ctx, ctr, CL_CBK_RECEIVE_PAYLOAD, NULL, clb);
      else
	printf
	  ("Invalid i3 packet type in cl_context_select()\n");
      /* ctr pointer shouldn'be used after this call because the ctr
       * might have been deleted in the callback 
       */
      
      if (ctr_next)
	ctr = cl_get_trigger_by_id (ctr_next, hdr->stack->ids);
      else
	break;
    }
  }
  /* ... here we free the header */
  free_i3_header (hdr);
  
  return CL_NO_CONTINUE;
}



int get_i3_server(int num_servers, srv_address *s_array)
{
  int num = 0;
  int i;

  //printf("In get_i3_server, num_servers = %d\n\n", num_servers);
  
  if (num_servers == 0)
      return -1;

  for (i = 0; i < 2 * num_servers; i++) {
    num = n_rand(num_servers);
    if (s_array[num].status == ID_UP)
      return num;
  }

  num = 0;
  for (i = 0; i < num_servers; i++) {
    if (s_array[i].status == ID_UP)
      return i;
    if (s_array[i].status == ID_DOWN)
      num++;
  }
  /* there are known servers in the list, but all of them are down;
   * select a random one */
  if (num) {
    num = n_rand(num);
    for (i = 0; i < num_servers; i++) {
      if (s_array[i].status == ID_DOWN) {
	if (num == 0)
	  return i;
	else
	  num--;
      }
    }
  }

  panic("Likely bug in get_i3_server\n");
  return -1;
}


srv_address *set_i3_server_status(srv_address *s_array, 
				  uint32_t ip_addr, uint16_t port,
				  int status)
{
  int i;

  for (i = 0; i < MAX_NUM_SRV; i++) {
    if ((s_array[i].port == port) &&
	(s_array[i].addr.s_addr == ip_addr)) {
      s_array[i].status = status;
      return &s_array[i];
    }
  }

  return NULL;
}



/* read the list of server addresses and their port numbers
 * from the configuration files */
void read_srv_list(cl_context *ctx)
{
  int  i = 0, port, ret;
  char addrstr[MAX_BUF_SIZE];
  char idstr[MAX_BUF_SIZE];
  char** addrs = read_i3server_list(&ctx->num_servers);

  for (i = 0; i < ctx->num_servers; i++)
  {
    ret = sscanf(addrs[i], "%s %d %s\n", addrstr, &port, idstr);
    free(addrs[i]);

    I3_PRINT_DEBUG2(I3_DEBUG_LEVEL_VERBOSE,"Using i3 server at %s %d\n",addrstr,port);

    if (i >= MAX_NUM_SRV)
      continue;

    if (ret >= 3)
	ctx->s_array[i].id = atoi3id(idstr);
    else
	fprintf(stderr, "Warning: proxy configuration file has incomplete <addr> field\n");
    ctx->s_array[i].port = port;
//#ifdef _WIN32
//    if (inet_aton(addrstr, &ctx->s_array[i].addr) < 0)
//#else
    if (inet_pton(AF_INET, addrstr, &ctx->s_array[i].addr) < 0)
//#endif
	    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "client_init: inet_pton error\n");

    /* inet_pton returns the address in network format;
     * convert it in host format */
    ctx->s_array[i].addr.s_addr = ntohl(ctx->s_array[i].addr.s_addr);
    ctx->s_array[i].status = ID_DOWN;

  }

  free(addrs);

  printf("Number of i3 servers = %d\n", ctx->num_servers);
}

void update_srv_list(cl_context *ctx)
{
  int i, k = MAX_NUM_SRV;
  uint16_t port[MAX_NUM_SRV];
  uint32_t addr[MAX_NUM_SRV];
  uint64_t rtt[MAX_NUM_SRV];
  
  if (cl_ctx_get_top_k_servers(ctx, &k, addr, port, rtt) == CL_RET_OK) {
    for (i = 0; i < k; i++) {
	    //printf("in update_srv_list i=%d port[i] = %d \n", i, port[i]);
      ctx->s_array[i].addr.s_addr = addr[i];
      ctx->s_array[i].port = port[i];
      ctx->s_array[i].status = ID_UP;	//ADDED by dilip
    }
    if (k > 0)
      ctx->num_servers = k;
  }
}
  

/* function used to process timeval data structures */
int tval_zero(struct timeval *t)
{
  if (t->tv_sec || t->tv_usec)
    return FALSE;
  else
    return TRUE;
}

void tval_min(struct timeval *tmin, struct timeval *t1, struct timeval *t2)
{
  if (!t1)
    *tmin = *t2;
  else if (!t2)
    *tmin = *t1;
  else {
    tval_normalize(t1);
    tval_normalize(t2);

    if (t1->tv_sec < t2->tv_sec)
      *tmin = *t1;
    else if (t1->tv_sec > t2->tv_sec)
      *tmin = *t2;
    else if (t1->tv_usec < t2->tv_usec)
      *tmin = *t1;
    else
      *tmin = *t2;
  }
}

void cl_update_to(struct timeval *cl_to, uint64_t diff) 
{
  diff = tval_to_uint64(cl_to) - diff;
  if ((int64_t)diff < 0) {
    diff = 0;
  }
  uint64_to_tval(cl_to, diff); 
}


int tval_equal(struct timeval *t1, struct timeval *t2)
{
  if (t1->tv_sec == t2->tv_sec && t1->tv_usec == t2->tv_usec)
    return TRUE;
  else
    return FALSE;
}
      

uint64_t tval_to_uint64(struct timeval *tv)
{
  return tv->tv_sec*UMILLION + tv->tv_usec;
}


void uint64_to_tval(struct timeval *tv, uint64_t time)
{
  tv->tv_sec = time/UMILLION;
  tv->tv_usec = time % UMILLION;
}


void tval_normalize(struct timeval *t)
{
  if (t->tv_usec >= UMILLION) {
    t->tv_sec += t->tv_usec/UMILLION;
    t->tv_usec = t->tv_usec % UMILLION;
  }
}


/* get local address -- use fn in utils/ */  
struct in_addr get_local_addr_cl()
{
  struct in_addr ia;
  ia.s_addr = ntohl(get_local_addr());
  return ia;
}

int check_addr_change(struct in_addr *ia)
{
  struct in_addr newAddr;

  newAddr.s_addr = ntohl(get_local_addr());

  if (ia->s_addr != newAddr.s_addr) {
    ia->s_addr = newAddr.s_addr;
    return 1;
  } else {
    return 0;
  }
}

void timeout_address_change(cl_context *ctx)
{
  struct timeval tv;

  if (check_addr_change(&(ctx->local_ip_addr))) {
    struct in_addr temp;
    temp.s_addr = htonl(ctx->local_ip_addr.s_addr);
    fprintf(stderr, "Detected address change to %s: updating triggers\n",
	    inet_ntoa(temp));
    cl_reinit_context(ctx);
    cl_update_triggers(ctx);
    
    // inform ping process
    set_status(ctx->ping_start_time, wall_time());
  }
  tv.tv_sec  = ADDR_CHECK_PERIOD;
  tv.tv_usec = random_sec();
  cl_set_timer(&tv, timeout_address_change, ctx);
}

void timeout_server_update(cl_context *ctx)
{
    struct timeval tv;

    update_srv_list(ctx);
    tv.tv_sec  = SERVER_UPDATE_PERIOD;
    tv.tv_usec = random_sec();
    cl_set_timer(&tv, timeout_server_update, ctx);
    
    // If TCP socket had not been previous initialized, try again.
    if ( ctx->is_tcp && ! ctx->init_tcp_ctx_flag) {
        I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_VERBOSE,
                "Retrying TCP socket initialization\n"
                );
        init_tcp_ctx(ctx);
    }
}


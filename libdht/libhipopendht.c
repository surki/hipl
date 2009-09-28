/* opendht_xml_interface.c supports put/get XML RPC interface */
/* NOTE: you must use port 5851 because openDHT accepts XML RPC only on that port */
/* TODO: support for put_removable and rm */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <openssl/sha.h>
#include <errno.h>
#include <signal.h>
#include "debug.h"
#include <fcntl.h>
#include "ife.h"
#include "icomm.h"
#include "misc.h"
#include "libhipandroid/getendpointinfo.h"

#include "libhipopendht.h"
#include "libhipopendhtxml.h"

#include "libhipopendht.h"
#include "libhipopendhtxml.h"


/**
 *  For interrupting the connect in gethosts_hit 
 *  @param signo signal number
 *
 *  @return void
 */
static void 
connect_alarm(int signo)
{
    return; 
}

/**
 * init_dht_gateway_socket_gw - Initializes socket for the openDHT
				communications based on gateway address family
 * @param sockfd	Socket descriptor to be initialized.
 * @param af		Address family
 *
 * @return Returns positive if socket creation was ok negative on error.
 */
int init_dht_gateway_socket_gw(int sockfd, struct addrinfo *gateway) {
    //default address family
    int af = AF_INET;

    if(gateway)
	af = gateway->ai_family;

    if ((sockfd = socket(af, SOCK_STREAM, IPPROTO_TCP)) < 0)
        HIP_PERROR("OpenDHT socket\n");
    
    return(sockfd);      
}


/** 
 * resolve_dht_gateway_info - Resolves the gateway address
 * @param gateway_name	FQDN of the gateway
 * @param gateway	Addrinfo struct where the result will be stored
 * @param af		address family
 * 
 * @return Returns 0 on success otherwise -1
 */
int resolve_dht_gateway_info(char *gateway_name, 
			     struct addrinfo ** gateway,
			     in_port_t gateway_port,
			     int af) {
    struct addrinfo hints;
    struct sockaddr_in  *sa_v4 = NULL;
    struct sockaddr_in6 *sa_v6 = NULL;
    int error;
    char opendht_serving_gateway_port_str[7];

    if ((af != AF_INET) && (af != AF_INET6)) {
	error = -1;
	HIP_DEBUG("Wrong address family!\n");
	return error;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    /* For some reason this does not work anymore -samu */
    //hints.ai_flags = AI_NODHT;
    error = 0;
    
    sprintf(opendht_serving_gateway_port_str, "%d", gateway_port);
    error = getaddrinfo(gateway_name, opendht_serving_gateway_port_str, &hints, gateway);
    if (error != 0) {
        HIP_DEBUG("OpenDHT gateway resolving failed %s\n", gateway_name);
	HIP_DEBUG("%s\n",gai_strerror(error));
    } else {
	if (af == AF_INET) {
	    sa_v4 = (struct sockaddr_in *) (*gateway)->ai_addr;
	    HIP_DEBUG_INADDR("OpenDHT gateway IPv4", &(sa_v4->sin_addr));
	} else if (af == AF_INET6) {
	    sa_v6 = (struct sockaddr_in6 *) (*gateway)->ai_addr;
	    HIP_DEBUG_IN6ADDR("OpenDHT gateway IPv6", &(sa_v6->sin6_addr));
	}
    }

    return error;
}


/**
 *  connect_dht_gateway - Connects to given v6 gateway
 *  @param sockfd
 *  @param addrinfo Address to connect to 
 *  @param blocking 1 for blocking connect 0 for nonblocking
 *
 *  @return Returns 0 on success -1 otherwise, if nonblocking can return EINPRGORESS
 */
int connect_dht_gateway(int sockfd,
			   struct addrinfo * gateway,
			   int blocking){
    int flags = 0, error = 0;
    struct sockaddr_in *sa_v4;
    struct sockaddr_in6 *sa_v6;

    struct sigaction act, oact;
    act.sa_handler = connect_alarm;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    
    if(gateway == NULL){
            HIP_ERROR("No OpenDHT Serving Gateway Address.\n");
            return(-1);
    }
    
    if(blocking == 0)
        goto unblock;

    // blocking connect
    if(sigaction(SIGALRM, &act, &oact) < 0){
            HIP_DEBUG("Signal error before OpenDHT connect, "
                      "connecting without alarm\n");
            error = connect(sockfd, gateway->ai_addr, gateway->ai_addrlen);
    }else {
            HIP_DEBUG("Connecting to OpenDHT with alarm\n");
            if (alarm(DHT_CONNECT_TIMEOUT) != 0)
                HIP_DEBUG("Alarm was already set, connecting without\n");
            error = connect(sockfd, gateway->ai_addr, gateway->ai_addrlen);
            alarm(0);
            if (sigaction(SIGALRM, &oact, &act) <0 ) 
                HIP_DEBUG("Signal error after OpenDHT connect\n");
    }
    
    if(error < 0){
            HIP_PERROR("OpenDHT connect:");
            if (errno == EINTR)
                HIP_DEBUG("Connect to OpenDHT timedout\n");
            return(-1);
    }else{
	if(gateway->ai_family == AF_INET){
	    sa_v4 = (struct sockaddr_in *)gateway->ai_addr;
	    HIP_DEBUG_INADDR("Connected to OpenDHT v4 gateway", &(sa_v4->sin_addr));
	}
	else if(gateway->ai_family == AF_INET6){
            sa_v6 = (struct sockaddr_in6 *)gateway->ai_addr;
            HIP_DEBUG_IN6ADDR("Connected to OpenDHT v6 gateway", &(sa_v6->sin6_addr));
	}
	else{
	    HIP_DEBUG("Wrong address family for OPENDHT gateway %d\n", gateway->ai_family);
	}
	return(0);
    }
        
 unblock:
    // unblocking connect
    flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK); 
    
    if(gateway->ai_family == AF_INET){
	    sa_v4 = (struct sockaddr_in *)gateway->ai_addr;
	    HIP_DEBUG_INADDR("Connecting to OpenDHT v4 gateway", &(sa_v4->sin_addr));
    }
    else if(gateway->ai_family == AF_INET6){
            sa_v6 = (struct sockaddr_in6 *)gateway->ai_addr;
            HIP_DEBUG_IN6ADDR("Connecting to OpenDHT v6 gateway", &(sa_v6->sin6_addr));
    }
    else{
	    HIP_DEBUG("Wrong address family for OPENDHT gateway %d\n", gateway->ai_family);
    }

    if(connect(sockfd, gateway->ai_addr, gateway->ai_addrlen) < 0){
            if (errno == EINPROGRESS)
                return(EINPROGRESS);
            else{
                    HIP_PERROR("OpenDHT connect:");
                    return(-1);
            }
    }else{
            // connect ok
            return(0);
    }
}


/** 
 * opendht_put_rm - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send 
 * @param key Key for the openDHT
 * @param value Value to be stored to the openDHT
 * @param secret Value to be used as a secret in remove
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_put_rm(int sockfd, 
                   unsigned char * key,
                   unsigned char * value, 
                   unsigned char * secret,
                   unsigned char * host,
                   int opendht_port,
                   int opendht_ttl)
{
    int key_len = 0;
    char put_packet[HIP_MAX_PACKET];
    char tmp_key[21];
    
    key_len = opendht_handle_key(key, tmp_key);
    
    /* Put operation FQDN->HIT */
    memset(put_packet, '\0', sizeof(put_packet));
    if (build_packet_put_rm((unsigned char *)tmp_key,
                         key_len,
                         (unsigned char *)value,
	                 strlen((char *)value),
                         (unsigned char *)secret,
                         strlen((char *)secret),
                         opendht_port,
                         (unsigned char *)host,
                         put_packet, opendht_ttl) != 0)
        {
            HIP_DEBUG("Put(rm) packet creation failed.\n");
            return(-1);
        }
    _HIP_DEBUG("Host address in OpenDHT put(rm) : %s\n", host); 
    HIP_DEBUG("Actual OpenDHT send starts here\n");
    send(sockfd, put_packet, strlen(put_packet), 0);
    return(0);
}

/** 
 * opendht_put - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send
 * @param key Key for the openDHT
 * @param value Value to be stored to the openDHT
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_put(unsigned char * key,
                unsigned char * value, 
                unsigned char * host,
                int opendht_port,
                int opendht_ttl, void *put_packet)
{
    int key_len = 0;
    int value_len = 0;
    char tmp_key[21];   
    char tmp_value[21];
        
    key_len = opendht_handle_key(key, tmp_key);   
    value_len = opendht_handle_value(value, tmp_value);
           
    /* Put operation FQDN->HIT */
    if (key_len > 0) {
            if (build_packet_put((unsigned char *)tmp_key,
                                 key_len,
                                 (unsigned char *)tmp_value,
                                 value_len,
                                 opendht_port,
                                 (unsigned char *)host,
                                 (char*)put_packet, opendht_ttl) != 0)
                    {
                            HIP_DEBUG("Put packet creation failed.\n");
                            return(-1);
                    }
    }  else {
            if (build_packet_put((unsigned char *)tmp_key,
                                 key_len,
                                 (unsigned char *)value,
                                 strlen((char *)value),
                                 opendht_port,
                                 (unsigned char *)host,
                                 (char*)put_packet, opendht_ttl) != 0)
                    {
                            HIP_DEBUG("Put packet creation failed.\n");
                            return(-1);
                    }
    }
    _HIP_DEBUG("HTTP packet for put is ready to be sent to queue\n"); 
    return(0);
}

int opendht_send(int sockfd, void *packet)
{
	int err = 0, len = strlen((char *)packet); 
  
	_HIP_DEBUG("Packet: %s\n",put_packet);
	_HIP_DEBUG("OpenDHT send: packet length: %d\n", len);
	
	if (len > 0)
		err = send(sockfd, (char *) packet, len, 0);

	if (err < 1)
		HIP_PERROR("Error opendht_send: ");

    return 0;
}
/** 
 * opendht_rm - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send
 * @param key Key for the openDHT
 * @param value Value to be removed to the openDHT
 * @param secret Value to be used as a secret in remove
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_rm(int sockfd, 
                   unsigned char * key,
                   unsigned char * value, 
                   unsigned char * secret,
                   unsigned char * host,
                   int opendht_port,
                   int opendht_ttl)
{
    int key_len = 0;
    char put_packet[HIP_MAX_PACKET];
    char tmp_key[21];
    
    key_len = opendht_handle_key(key, tmp_key);
    
    /* Rm operation */
    memset(put_packet, '\0', sizeof(put_packet));
    if (build_packet_rm((unsigned char *)tmp_key,
                         key_len,
                         (unsigned char *)value,
	                 strlen((char *)value),
                         (unsigned char *)secret,
                         strlen((char *)secret),
                         opendht_port,
                         (unsigned char *)host,
                         put_packet, opendht_ttl) != 0)
        {
            HIP_DEBUG("Rm packet creation failed.\n");
            return(-1);
        }
    _HIP_DEBUG("Host address in OpenDHT rm : %s\n", host); 
    HIP_DEBUG("Actual OpenDHT send starts here\n");
    send(sockfd, put_packet, strlen(put_packet), 0);
    return(0);
}

/** 
 * opendht_get - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send
 * @param key Key for the openDHT
 * @param value Value to be stored to the openDHT
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_get(int sockfd, 
                unsigned char * key, 
                unsigned char * host,
                int port)
{
    int key_len = 0;
    char get_packet[HIP_MAX_PACKET];
    char tmp_key[21];

    key_len = opendht_handle_key(key, tmp_key);
    
    /* Get operation */
    memset(get_packet, '\0', sizeof(get_packet));
    if (build_packet_get((unsigned char *)tmp_key,
                         key_len,
                         port,
                         (unsigned char *)host,
                         get_packet) !=0)
        {
            HIP_DEBUG("Get packet creation failed.\n");  
            return(-1);
        }
    
    send(sockfd, get_packet, strlen(get_packet), 0);
    return(0);
}

/**
 * opendht_handle_value Modifies the key to suitable format for OpenDHT
 *
 * @param value Value to be handled
 * @param out_value Where the value will be saved
 *
 * @return larger than 0 if value was in IPv6 format (len of out_value)
 */
int opendht_handle_value(char * value, char * out_value) 
{
    int err = 0, value_len = 0;
    char tmp_value[21];
    struct in6_addr addrvalue;

    /* check for too long keys and convert HITs to numeric form */
    memset(tmp_value, '\0', sizeof(tmp_value));

    if (inet_pton(AF_INET6, (char *)value, &addrvalue.s6_addr) == 0)
        {
            /* inet_pton failed because of invalid IPv6 address */
            /*copy data to value as it is*/
            /*restricting length to 21, data after it will be lost*/
            memcpy(out_value, value, sizeof(tmp_value)); 
            value_len = sizeof(tmp_value);
            err = value_len;
        } 
    else 
        {
            /* value was in IPv6 format so propably is a HIT */
            memcpy(tmp_value, addrvalue.s6_addr, sizeof(addrvalue.s6_addr));
            value_len = sizeof(addrvalue.s6_addr);
            err = value_len;
            memcpy(out_value, tmp_value, sizeof(tmp_value));
        }
 out_err:
    return(err);
}

/**
 * opendht_handle_key Modifies the key to suitable format for OpenDHT
 *
 * @param key Key to be handled
 * @param out_key Where the key will be saved
 *
 * @return -1 if false otherwise it will be len of out_key
 */
int opendht_handle_key(char * key, char * out_key) 
{
    int err = 0, key_len = 0, i = 0 ;
    unsigned char tmp_key[21];
    struct in6_addr addrkey;
    unsigned char *sha_retval;
	int key_len_specified_in_bytes = 20;
	unsigned char *paddedkey = NULL;
	/* Below three variables are used for key padding logic*/
	int k = 0;
	unsigned char tempChar1 =' ';
	unsigned char tempChar2 =' ';
		
	/* check for too long keys and convert HITs to numeric form */
    memset(tmp_key, '\0', sizeof(tmp_key));

	if (inet_pton(AF_INET6, (char *)key, &addrkey.s6_addr) == 0)
	{
 		/* inet_pton failed because of invalid IPv6 address */
		memset(tmp_key,'\0',sizeof(tmp_key));
		/* strlen works now but maybe not later */
		for (i = 0; i < strlen(key); i++ )
            key[i] = tolower(key[i]);
        if (key[strlen(key)] == '.')
            key[strlen(key)] == '\0';
        sha_retval = SHA1(key, strlen(key), tmp_key); 
        key_len = 20;
		err = key_len;
        _HIP_HEXDUMP("KEY FOR OPENDHT", tmp_key, key_len);
        if (!sha_retval)
        {
        	HIP_DEBUG("SHA1 error when creating key for OpenDHT.\n");
            return(-1);
        }                
    }
    else 
    {
		/* We require only last 100 bits of the HIT. That is to say
		to ignore first 28 bits we need to shift 28 bits left the HIT.
		Follwoing logic does it and zero padding is already done in memset
		above for tmp_key to make it 160 bit long key */
		paddedkey = malloc(key_len_specified_in_bytes +4);
		memset(paddedkey, '\0', key_len_specified_in_bytes +4);
    	memcpy(paddedkey, addrkey.s6_addr, sizeof(addrkey.s6_addr));		
		paddedkey = paddedkey + 3;
		while (k <13)
		{ 	/*We get the MSB hex byte from tempchar1 and LSB temchar2 */
			tempChar1 = *(paddedkey+k);
		 	tempChar2 = *(paddedkey+k+1);
		 	tempChar1 = tempChar1 << 4 ;
		 	tempChar2 = tempChar2 >> 4 ;
		 	*(paddedkey+k) = tempChar1 | tempChar2 ;
		 	k++;
		 }
		_HIP_DEBUG("New key value:  %d.\n", k);
		memcpy(tmp_key, paddedkey, k+1);
		key_len = key_len_specified_in_bytes ;
		err = key_len;
	}
	memcpy(out_key, tmp_key, sizeof(tmp_key));
out_err:
	if(paddedkey)
	{
		paddedkey = paddedkey -3 ;
		free(paddedkey);
	}
	return(err);
}

/** 
 * opendht_read_response - Reads from the given socket and parses the XML RPC response
 * @param sockfd Socket to be used with the send
 * @param answer Buffer where the response value will be saved
 *
 * @return Returns integer, same as in read_packet_content
 * TODO: see read_packet_content
 */
int opendht_read_response(int sockfd, char * answer)
{
    int ret = 0, pton_ret = 0;
    int bytes_read = 0, total = 0;
    char read_buffer[HIP_MAX_PACKET];
    //char tmp_buffer[HIP_MAX_PACKET];
    struct in_addr ipv4;
    struct in6_addr ipv6 = {0};

    if (sockfd <= 0 || answer == NULL) {
	    HIP_ERROR("sockfd=%p, answer=%p\n", sockfd, answer);
	    return -1;
    }

    memset(read_buffer, '\0', sizeof(read_buffer));
    do
        {
            bytes_read = recv(sockfd, &read_buffer[total],
			      sizeof(read_buffer), 0);
	    total += bytes_read;
        }
    while (bytes_read > 0 && total < sizeof(read_buffer) - 1);

    /* Parse answer */
    memset(answer, '\0', 1);
    ret = 0;
    ret = read_packet_content(read_buffer, answer);

    /* If answer was IPv4 address mapped to IPv6 revert to IPv4 format*/
    pton_ret = inet_pton(AF_INET6, answer, &ipv6);

    if (pton_ret && IN6_IS_ADDR_V4MAPPED(&ipv6)) {
	    IPV6_TO_IPV4_MAP(&ipv6, &ipv4);
	    sprintf(answer, "%s", inet_ntoa(ipv4));
    }

 out_err:

    return ret;
}

    
/**
 * hip_opendht_get_key - creates socket, connects to OpenDHT and gets the value under given key
 *
 * @param *value_handler(), a pointer function which treats different values from openDHT based
 * on the function assigned to it by the caller
 * @param gateway A addrinfo struct containing the gateway address
 * @param key Pointer to key to be fetched
 * @param opaque_answer Pointer to memory area where the corresponding value will be saved
 *  	  opaque_answer is set by poiner function sent as param
 * @param dont_verify_hdrr if passed 0 HDRR sig and hostid verification is done, otherwise skipped 
 * @return integer -1 on error, on success 0
 */
int hip_opendht_get_key(int (*value_handler)(unsigned char * packet,
             void * answer),struct addrinfo * gateway, 
                       const unsigned char * key, void * opaque_answer, int dont_verify_hdrr)
{
	int err = 0, sfd = -1;
	char hostname[256];
	char *host_addr = NULL;
	struct hostent *hoste = NULL;
	struct in6_addr hit_key; /* To convert DHT key (HIT) to in6_addr structure */
        
	memset(hostname,'\0',sizeof(hostname));
	HIP_IFEL((gethostname(hostname, sizeof(hostname))),-1,"Error getting hostname\n");
	HIP_IFEL(!(hoste = gethostbyname(hostname)),-1,
		"Encountered an error when getting host address\n");
	if (hoste->h_addrtype == AF_INET)
		host_addr = inet_ntoa(*(struct in_addr *)*hoste->h_addr_list);
	else if (hoste->h_addrtype == AF_INET6) {
		HIP_IFEL(inet_ntop(AF_INET6, &hoste->h_addr_list, 
			host_addr, sizeof(INET6_ADDRSTRLEN)),
			-1,"Error converting host IPv6 address\n");
	}
	else {
		HIP_DEBUG("Unknown host address family\n");
		goto out_err;
	}

	host_addr = OPENDHT_GATEWAY;
	_HIP_DEBUG("Host addresss %s\n", host_addr);
	sfd = init_dht_gateway_socket_gw(sfd, gateway);
 	HIP_IFEL((err = connect_dht_gateway(sfd, gateway, 1))
			,-1,"OpenDHT connect error\n");
	HIP_IFEL((err = opendht_get(sfd, (unsigned char *)key, 
				    (unsigned char *)host_addr, OPENDHT_PORT)),
		-1, "Opendht_get error");
	HIP_IFEL(opendht_read_response(sfd, opaque_answer), 
		 -1, "Opendht_read_response error\n"); 
	_HIP_DUMP_MSG((struct hip_common *)opaque_answer);

	/* Check if we found the key from lookup service or not */
	HIP_IFEL((((struct hip_common *)opaque_answer)->payload_len == NULL),
		 -1, "NULL response\n");

	/* Call the hdrr verification function, in case of hdrr
	   if key for lookup is hit, it has to be hdrr */
	
	if ((inet_pton(AF_INET6, key, &hit_key.s6_addr) == 0) || dont_verify_hdrr) { 
		_HIP_DEBUG("lookup is not for HDRR or " 
			   "HDRR verification flag not set so skipping verification \n");
	} else {
		err = verify_hddr_lib ((struct hip_common *)opaque_answer,&hit_key);
		if (err != 0) {
			/*HDRR verification failed*/
			opaque_answer = NULL ;
			HIP_DEBUG("HDRR verification failed \n");
			err = -1 ;
		} else HIP_DEBUG("HDRR verification was successful\n");
					
	}

out_err:
 	if (sfd)
		close(sfd); 

	return(err);
}

/**
 * handle_hdrr_value - This function gets the HDRR from packet returned from lookup
 * @param *packet response returned from the lookup service
 * @param *hdrr opaque pointer passed to point to the hdrr result
 * @return status of the operation 0 on success, -1 on failure
 */
int 
handle_hdrr_value (unsigned char *packet, void *hdrr)
{       
	struct hip_locator *locator;
	
	locator = hip_get_param((struct hip_common *)packet, HIP_PARAM_LOCATOR);
	if (locator)
	{ 
		memcpy(hdrr, packet, HIP_MAX_PACKET);
		return 0 ;
	}
	else		return -1 ;		
}

/**
 * handle_locator_all_values - This function copies the locator from packet returned from lookup
 * @param *packet response returned from the lookup service
 * @param *locator_complete opaque pointer passed to point to the locator result
 * @return status of the operation 0 on success, -1 on failure
 */
int handle_locator_all_values (unsigned char *packet, void *locator_complete)
{
	struct hip_locator *locator;
	locator = hip_get_param((struct hip_common *)packet, HIP_PARAM_LOCATOR);
	if (locator)
    { 
		memcpy(locator_complete, locator, HIP_MAX_PACKET);
		return 0 ;
	}
	else
		return -1 ;		
}

/**
 * handle_locator_value - This function copies the 2nd address (ipv4) from
 * the locator from packet returned from lookup
 * 
 * @param *packet response returned from the lookup service
 * @param *locator_ipv4 opaque pointer passed to point to the ipv4 address
 * @return status of the operation 0 on success, -1 on failure
 */
int handle_locator_value (unsigned char *packet, void *locator_ipv4)
{
	struct hip_locator *locator;
	struct hip_locator_info_addr_item *locator_address_item = NULL;
	int locator_item_count = 0;
	struct in6_addr addr6;
	struct in_addr addr4;
   
	locator = hip_get_param((struct hip_common *)packet, HIP_PARAM_LOCATOR);

	if (locator) {
		locator_item_count = hip_get_locator_addr_item_count(locator);
		locator_item_count--;
		locator_address_item = hip_get_locator_first_addr_item(locator);
		memcpy(&addr6, 
			(struct in6_addr*)&locator_address_item[locator_item_count].address, 
				sizeof(struct in6_addr));
		if (IN6_IS_ADDR_V4MAPPED(&addr6)) {
			IPV6_TO_IPV4_MAP(&addr6, &addr4);
			sprintf((char*)locator_ipv4, "%s", inet_ntoa(addr4));
		} else {
			hip_in6_ntop(&addr6, (char*)locator_ipv4);
			_HIP_DEBUG("Value: %s\n", (char*)locator_ipv4);
		}
		return 0 ;
	} else
		return -1;	
}

/**
 * handle_hit_value - This function copies the hit returned from the lookup service
 *
 * @param *packet response returned from the lookup service
 * @param *hit opaque pointer passed to point to the HIT
 * @return status of the operation 0 on success, -1 on failure
 */
int handle_hit_value (unsigned char *packet, void *hit)
{
	if (ipv6_addr_is_hit((struct in6_addr*)packet)) {
		hip_in6_ntop((struct in6_addr *)packet, (char*)hit);
		return 0 ;
	} else 
		return -1 ;
}

/**
 * handle_hit_value - handles just IP (not locator) returned by lookup services
 *
 * @param *packet response returned from the lookup service
 * @param *hit opaque pointer passed to point to the ip
 * @return status of the operation 0 on success, -1 on failure
 */
int handle_ip_value (unsigned char *packet, void *ip)
{
	hip_in6_ntop((struct in6_addr *)packet, (char*)ip);
	if ((char*)ip)
		return 0 ;
	else 
		return -1 ;
}

/**
 * verify_hddr_lib - It sends the dht response to hipdaemon
 * first appending one more user param for holding a structure hdrr_info
 * hdrr_info is used by daemon to mark signature and host id verification results to flags
 * Then adding user header for recognizing the message at daemon side
 * 
 * @param *hipcommonmsg packet returned from the lookup service
 * @param *addrkey key used for the lookup
 * @return OR of the signature and host id verification, 0 in case of success
 */
int verify_hddr_lib (struct hip_common *hipcommonmsg,struct in6_addr *addrkey)
{
	struct hip_hdrr_info hdrr_info;	
	struct hip_hdrr_info *hdrr_info_response; 
	int err = 0 ;
	
	memcpy(&hdrr_info.dht_key, addrkey, sizeof(struct in6_addr));
	hdrr_info.sig_verified = -1;
	hdrr_info.hit_verified = -1;
	hip_build_param_hip_hdrr_info(hipcommonmsg, &hdrr_info);
	_HIP_DUMP_MSG (hipcommonmsg);

	HIP_INFO("Asking signature verification info from daemon...\n");
	HIP_IFEL(hip_build_user_hdr(hipcommonmsg, SO_HIP_VERIFY_DHT_HDRR_RESP,0),-1,
			"Building daemon header failed\n");
	HIP_IFEL(hip_send_recv_daemon_info(hipcommonmsg, 0, 0), 
		 -1, "Send recv daemon info failed\n");
      
	hdrr_info_response = hip_get_param (hipcommonmsg, HIP_PARAM_HDRR_INFO);
	_HIP_DUMP_MSG (hipcommonmsg);
	HIP_DEBUG ("Sig verified (0=true): %d\nHit Verified (0=true): %d \n"
		,hdrr_info_response->sig_verified, hdrr_info_response->hit_verified);
	return (hdrr_info_response->sig_verified | hdrr_info_response->hit_verified);

out_err:
	return err;
}

/**
 * handle_cert_key - It prepares the key for publishing certificates
 
 * @param *lhit local hit used
 * @param *rhit hit of the remote host
 * @param *final_key resulting key value after processing
 * @return length of the key or -1 in case of error
 */
int handle_cert_key(struct in6_addr *lhit, struct in6_addr *rhit, void *final_key)
{
	void *result = NULL ;
	unsigned char *sha_retval;
	int key_len = sizeof(rhit->s6_addr)*2;
	
	result = malloc (key_len);
		/*concatenate both*/	
	memcpy(result,&rhit->s6_addr,sizeof(rhit->s6_addr));
	memcpy(result+sizeof(rhit->s6_addr),
				&lhit->s6_addr,sizeof(lhit->s6_addr));
	sha_retval = SHA1(result, key_len, final_key); 
	key_len = 20;
	_HIP_HEXDUMP("KEY FOR OPENDHT", final_key, key_len);
	if (!sha_retval)
	{
     	HIP_DEBUG("SHA1 error when creating key for OpenDHT.\n");
		key_len = -1;
	}
	if(result)
		free (result);
	return key_len ;
}

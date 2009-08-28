/** @file
 * Functions for getting address information. 
 * 
 * \$USAGI: getaddrinfo.c,v 1.10 2003/01/07 10:22:52 yoshfuji Exp \$
 *
 * The Inner Net License, Version 2.00
 *
 * The author(s) grant permission for redistribution and use in source and
 * binary forms, with or without modification, of the software and documentation
 * provided that the following conditions are met:
 *
 * 0. If you receive a version of the software that is specifically labelled
 * as not being for redistribution (check the version message and/or README),
 * you are not permitted to redistribute that version of the software in any
 * way or form.
 * 1. All terms of the all other applicable copyrights and licenses must be
 * followed.
 * 2. Redistributions of source code must retain the authors' copyright
 * notice(s), this list of conditions, and the following disclaimer.
 * 3. Redistributions in binary form must reproduce the authors' copyright
 * notice(s), this list of conditions, and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 4. All advertising materials mentioning features or use of this software
 * must display the following acknowledgement with the name(s) of the
 * authors as specified in the copyright notice(s) substituted where
 * indicated:
 *
 *	This product includes software developed by <name(s)>, The Inner
 * 	Net, and other contributors.
 *
 * 5. Neither the name(s) of the author(s) nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY ITS AUTHORS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * If these license terms cause you a real problem, contact the author.
 *
 * This software is Copyright 1996 by Craig Metz, All Rights Reserved.
 * 
 * @author Craig Metz
 * @note: HIPU: libinet6 requires LD_PRELOAD which is "dylib" on BSD. Miika:
 * we are going to get rid of the LD_PRELOAD stuff in HIPL anyway.
 * @note: HIPU: the include headers should be excluded on MAC OS X
 */
#ifdef _USAGI_LIBINET6
#include "libc-compat.h"
#endif

#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <net/if.h>

#include <ctype.h>
#include <signal.h>
#include "builder.h"
#include "debug.h"
#include "message.h"
#include "util.h"
#include "libhipopendht.h"
#include "bos.h"

#define GAIH_OKIFUNSPEC 0x0100
#define GAIH_EAI        ~(GAIH_OKIFUNSPEC)

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX  108
#endif

#ifndef NUM_MAX_HITS
#define NUM_MAX_HITS 50
#endif

// extern u32 opportunistic_mode;
struct gaih_service
  {
    const char *name;
    int num;
  };

struct gaih_servtuple
  {
    struct gaih_servtuple *next;
    int socktype;
    int protocol;
    int port;
  };

static const struct gaih_servtuple nullserv;
static int enable_hit_lookup = 1;

/* Moved to util.h, used in getendpointinfo.c
struct gaih_addrtuple
  {
    struct gaih_addrtuple *next;
    int family;
    char addr[16];
    uint32_t scopeid;
  };
*/

struct gaih_typeproto
  {
    int socktype;
    int protocol;
    char name[4];
    int protoflag;
  };

/* Values for `protoflag'.  */
#define GAI_PROTO_NOSERVICE	1
#define GAI_PROTO_PROTOANY	2

static const struct gaih_typeproto gaih_inet_typeproto[] =
{
  { 0, 0, "", 0 },
  { SOCK_STREAM, IPPROTO_TCP, "tcp", 0 },
  { SOCK_DGRAM, IPPROTO_UDP, "udp", 0 },
  { SOCK_RAW, 0, "raw", GAI_PROTO_PROTOANY|GAI_PROTO_NOSERVICE },
  { 0, 0, "", 0 }
};

struct gaih
  {
    int family;
    int (*gaih)(const char *name, const struct gaih_service *service,
		const struct addrinfo *req, struct addrinfo **pai,
		int hip_transparent_mode);
  };

#if PF_UNSPEC == 0
static const struct addrinfo default_hints;
#else
static const struct addrinfo default_hints =
	{ 0, PF_UNSPEC, 0, 0, 0, NULL, NULL, NULL };
#endif

int max_line_etc_hip = 500;

void getaddrinfo_disable_hit_lookup(void) {
  enable_hit_lookup = 0;
}

void getaddrinfo_enable_hit_lookup(void) {
  enable_hit_lookup = 1;
}

static int addrconfig (sa_family_t af)
{
  int s;
  int ret;
  int saved_errno = errno;

  _HIP_DEBUG("af=%d", af);
  
  s = socket(af, SOCK_DGRAM, 0);
  if (s < 0)
    ret = (errno == EMFILE) ? 1 : 0;
  else
    {
      close(s);
      ret = 1;
    }
  __set_errno (saved_errno);
  return ret;
}

void free_gaih_servtuple(struct gaih_servtuple *tuple) {
  struct gaih_servtuple *tmp;

  while(tuple) {
    tmp = tuple;
    tuple = tmp->next;
    free(tmp);
  }
}

void dump_pai (struct gaih_addrtuple *at){
	struct gaih_addrtuple *a;

	if (at == NULL)
		HIP_DEBUG("dump_pai: input NULL!\n");
  
	for(a = at; a != NULL; a = a->next) {        
		//HIP_DEBUG("scope_id=%lu\n", (long unsigned int)ai->scopeid);
		if (a->family == AF_INET6) {
			struct in6_addr *s = (struct in6_addr *)a->addr;
			int i = 0;
			HIP_DEBUG("AF_INET6\tin6_addr=0x");
			for (i = 0; i < 16; i++)
				HIP_DEBUG("%02x", (unsigned char) (s->in6_u.u6_addr8[i]));
			HIP_DEBUG("\n");
		} else if (a->family == AF_INET) {
			struct in_addr *s = (struct in_addr *)a->addr;
			long unsigned int ad = ntohl(s->s_addr);
			HIP_DEBUG("AF_INET\tin_addr=0x%lx (%s)\n", ad, inet_ntoa(*s));
		} else 
			HIP_DEBUG("Unknown family\n");
	}
}


static int gaih_local (const char *name,
			const struct gaih_service *service,
			const struct addrinfo *req,
			struct addrinfo **pai, int unused){
  struct utsname utsname;

  if(service)
    _HIP_DEBUG("name='%s' service->name='%s' service->num=%d\n",
		name, service->name, service->num);
  else
    _HIP_DEBUG("name='%s'\n", name);

  _HIP_DEBUG("req:ai_flags=0x%x ai_family=%d ai_socktype=%d ai_protocol=%d\n\n",
		req->ai_flags, req->ai_family, req->ai_socktype, req->ai_protocol);
  if(*pai)
    _HIP_DEBUG("pai:ai_flags=0x%x ai_family=%d ai_socktype=%d ai_protocol=%d\n\n",
		(*pai)->ai_flags, (*pai)->ai_family, (*pai)->ai_socktype, (*pai)->ai_protocol);

  if((name != NULL) && (req->ai_flags & AI_NUMERICHOST))
    return GAIH_OKIFUNSPEC | -EAI_NONAME;

  if((name != NULL) || (req->ai_flags & AI_CANONNAME))
    if (uname (&utsname) < 0)
      return -EAI_SYSTEM;

  if(name != NULL){
    if ( strcmp(name, "localhost") &&
	 strcmp(name, "local")     &&
	 strcmp(name, "unix")      &&
	 strcmp(name, utsname.nodename) )
      return GAIH_OKIFUNSPEC | -EAI_NONAME;
  }

  if(req->ai_protocol || req->ai_socktype){
    const struct gaih_typeproto *tp = gaih_inet_typeproto + 1;

    while( tp->name[0]
	     && ((tp->protoflag & GAI_PROTO_NOSERVICE) != 0
		 || (req->ai_socktype != 0 && req->ai_socktype != tp->socktype)
		 || (req->ai_protocol != 0
		     && !(tp->protoflag & GAI_PROTO_PROTOANY)
		     && req->ai_protocol != tp->protocol)))
      ++tp;

      if(! tp->name[0]){
        if(req->ai_socktype)
	  return (GAIH_OKIFUNSPEC | -EAI_SOCKTYPE);
	else
	  return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
      }
  }

  *pai = malloc (sizeof (struct addrinfo) + sizeof (struct sockaddr_un)
		 + ((req->ai_flags & AI_CANONNAME)
		    ? (strlen(utsname.nodename) + 1): 0));
  if (*pai == NULL)
    return -EAI_MEMORY;

  (*pai)->ai_next = NULL;
  (*pai)->ai_flags = req->ai_flags;
  (*pai)->ai_family = AF_LOCAL;
  (*pai)->ai_socktype = req->ai_socktype ? req->ai_socktype : SOCK_STREAM;
  (*pai)->ai_protocol = req->ai_protocol;
  (*pai)->ai_addrlen = sizeof (struct sockaddr_un);
  (*pai)->ai_addr = (void *) (*pai) + sizeof (struct addrinfo);
#ifdef _HAVE_SA_LEN
  ((struct sockaddr_un *) (*pai)->ai_addr)->sun_len =
         sizeof (struct sockaddr_un);
#endif /* _HAVE_SA_LEN */
  ((struct sockaddr_un *)(*pai)->ai_addr)->sun_family = AF_LOCAL;
  memset(((struct sockaddr_un *)(*pai)->ai_addr)->sun_path, 0, UNIX_PATH_MAX);

  if (service){
    struct sockaddr_un *sunp = (struct sockaddr_un *) (*pai)->ai_addr;

    if (strchr (service->name, '/') != NULL){
      if (strlen (service->name) >= sizeof (sunp->sun_path))
        return GAIH_OKIFUNSPEC | -EAI_SERVICE;

      strcpy (sunp->sun_path, service->name);
    }else{
      if(strlen (P_tmpdir "/") + 1 + strlen (service->name) >=
            sizeof (sunp->sun_path))
        return GAIH_OKIFUNSPEC | -EAI_SERVICE;

      stpcpy (stpcpy (sunp->sun_path, P_tmpdir "/"), service->name);
    }
  }else{
    /* This is a dangerous use of the interface since there is a time
	window between the test for the file and the actual creation
	(done by the caller) in which a file with the same name could
	be created.  */
    char *buf = ((struct sockaddr_un *) (*pai)->ai_addr)->sun_path;

    if(__builtin_expect (__path_search (buf, L_tmpnam, NULL, NULL, 0),
			    0) != 0
	  || __builtin_expect (__gen_tempname (buf, __GT_NOCREATE), 0) != 0)
      return -EAI_SYSTEM;
  }

  if(req->ai_flags & AI_CANONNAME)
    (*pai)->ai_canonname = strcpy ((char *) *pai + sizeof (struct addrinfo)
				   + sizeof (struct sockaddr_un),
				   utsname.nodename);
  else
    (*pai)->ai_canonname = NULL;
  return 0;
}


static int gaih_inet_serv(const char *servicename,
			const struct gaih_typeproto *tp,
			const struct addrinfo *req,
			struct gaih_servtuple *st){
  struct servent *s;
  size_t tmpbuflen = 1024;
  struct servent ts;
  char *tmpbuf;
  int r;

  if(tp)
    _HIP_DEBUG("servicename='%s' tp->socktype=%d tp->protocol=%d tp->name=%s tp->protoflag=%d\n", servicename, tp->socktype, tp->protocol, tp->name, tp->protoflag);
  else 
    _HIP_DEBUG("servicename='%s' tp=NULL\n", servicename);

  _HIP_DEBUG("req:ai_flags=0x%x ai_family=%d ai_socktype=%d ai_protocol=%d\n", req->ai_flags, req->ai_family, req->ai_socktype, req->ai_protocol);
  if(st)
    _HIP_DEBUG("st:socktype=%d protocol=%d port=%d\n", st->socktype, st->protocol, st->port);

  do{
    tmpbuf = __alloca (tmpbuflen);

    r = __getservbyname_r (servicename, tp->name, &ts, tmpbuf, tmpbuflen,
			     &s);
    if (r != 0 || s == NULL){
      if (r == ERANGE)
        tmpbuflen *= 2;
      else
        return GAIH_OKIFUNSPEC | -EAI_SERVICE;
    }
  }
  while (r);

  st->next = NULL;
  st->socktype = tp->socktype;
  st->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
		  ? req->ai_protocol : tp->protocol);
  st->port = s->s_port;

  return 0;
}


int gethosts(const char *name, int _family, 
	     struct gaih_addrtuple ***pat){								
  int i, herrno;						
  size_t tmpbuflen = 512;					       
  struct hostent th;						
  char *tmpbuf;							
  int no_data = 0;							
  int rc = 0;
  struct hostent *h = NULL;
  struct gaih_addrtuple *aux = NULL;

  /* freeing the already allocated structure if it si empty
     Warning: Not good practice, may cause problems */
  if(**pat != NULL && (**pat)->next == NULL && (**pat)->family == 0){
    free(**pat);
    **pat = NULL;
  }

  do{								
    tmpbuflen *= 2;						
    tmpbuf = __alloca (tmpbuflen);				
    rc = __gethostbyname2_r (name, _family, &th, tmpbuf,	
         tmpbuflen, &h, &herrno);				
  } while (rc == ERANGE && herrno == NETDB_INTERNAL);		
  if (rc != 0){								
    if (herrno == NETDB_INTERNAL){
      __set_h_errno (herrno);				
      return -EAI_SYSTEM;					
    }							
    if (herrno == TRY_AGAIN)
      no_data = EAI_AGAIN;					
    else							
      no_data = herrno == NO_DATA;				
  }								
  else if (h != NULL){
    for (i = 0; h->h_addr_list[i]; i++){
      if ((aux = (struct gaih_addrtuple *) malloc(sizeof(struct gaih_addrtuple))) == NULL){
        HIP_ERROR("Memory allocation error\n");
	return (-EAI_MEMORY);
      }
      //Placing the node at the beginning of the list
      aux->next = (**pat);
      (**pat) = aux;
      aux->scopeid = 0;    					
      aux->family = _family;				
      memcpy(aux->addr, h->h_addr_list[i],		
		(_family == AF_INET6)
		 ? sizeof(struct in6_addr)
		 : sizeof(struct in_addr));					
    }								
  }								
  return no_data;
}


static void 
connect_alarm(int signo)
{
  return; /* for interrupting the connect in gethosts_hit */
}


/**
 * Gets a HIT for a host.
 * 
 * @param  name  a pointer to a hostname for which are get the HIT.
 * @param  pat   a triple pointer to a ...
 * @param  flags ...
 * @return       Number of found HITs on success or a negative error value
 *               on error.
 */
int gethosts_hit(const char *name,
		struct gaih_addrtuple ***pat,
		int flags){
	int c, ret, is_lsi, found_hit_from_dht = 0;	
	int lineno = 0, err = 0, i = 0, found_hits = 0;
	hip_hit_t hit;
	hip_lsi_t lsi;
	struct in6_addr lsi_ip6;
	char line[500];
        char *fqdn_str = NULL;
	hip_common_t *msg = NULL;
	struct gaih_addrtuple *aux = NULL;
	FILE *fp = NULL;				
	List list;
	hip_tlv_type_t         param_type = 0;
	struct hip_tlv_common *current_param = NULL;
	struct in6_addr *reply_ipv6;

   	errno = 0;

	/* Fix to bug id 668 */
	if (!enable_hit_lookup)
	  goto out_err;

   /* Can't use the IFE macros here, since labe skip_dht is under label
      out_err. */

   /* This should be the other way around. I.e. look first from 
      /etc/hip/hosts and only then from DHT server. */
   if (flags & AI_NODHT) {
      HIP_INFO("Distributed Hash Table (DHT) is not in use.\n");
      goto out_err;
   }

   HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed.\n");
   memset(msg, 0, HIP_MAX_PACKET);

   err = hip_build_param_contents(msg, (void *) name,
				HIP_PARAM_HOSTNAME,
				HIP_HOST_ID_HOSTNAME_LEN_MAX);
   if(err){
      HIP_ERROR("build param hostname failed: %s\n", strerror(err));
      goto out_err;
   }

   if(hip_build_user_hdr(msg, SO_HIP_DHT_SERVING_GW, 0) != 0){
      HIP_ERROR("Error when building HIP daemon message header.\n");
      return -EHIP;
   }


   // Send the message to the daemon. Wait for reply
   HIP_INFO("Asking serving Distributed Hash Table (DHT) gateway "\
	   "information\nfrom the HIP daemon...\n");
   HIP_IFE(hip_send_recv_daemon_info(msg, 0, 0), -ECOMM);
   //hip_send_recv_daemon_info(msg);
   found_hit_from_dht = 0;
   // Loop through all the parameters in the message just filled.
   while((current_param = hip_get_next_param(msg, current_param)) != NULL){
      param_type = hip_get_param_type(current_param);
      if(param_type == HIP_PARAM_SRC_ADDR){

         reply_ipv6 = (struct in6_addr *)hip_get_param_contents_direct(
						current_param);
         HIP_DEBUG_HIT("HIT ", reply_ipv6);

         if(!found_hit_from_dht){

            //now creating gaih_addrtuple
            if(**pat == NULL){						
               if((**pat = (struct gaih_addrtuple *)
			malloc(sizeof(struct gaih_addrtuple))) == NULL){
                  HIP_ERROR("Memory allocation error\n");
                  return(-EAI_MEMORY);
               }	  
               (**pat)->scopeid = 0;				
            }
            (**pat)->family = AF_INET6;				
            memcpy((**pat)->addr, reply_ipv6, sizeof(struct in6_addr));		
            (**pat)->next = NULL;

            //mark that at least one hit has been saved
            found_hit_from_dht = 1;
         }else{
            if((**pat = (struct gaih_addrtuple *)
			malloc(sizeof(struct gaih_addrtuple))) == NULL){
               HIP_ERROR("Memory allocation error\n");
               return(-EAI_MEMORY);
            }	  
            (**pat)->scopeid = 0;				
                        	//(**pat)->next = NULL;						
            (**pat)->family = AF_INET6;
            memcpy((**pat)->addr, reply_ipv6, sizeof(struct in6_addr));

            (**pat)->next = NULL;
            *pat = &((**pat)->next);
         }
      }else if(param_type == HIP_PARAM_INT){
         //TO DO, get int that indicates error 
         //output some msg for different error types
         ret = *(int *)hip_get_param_contents_direct(current_param);

         switch(ret){
         case 1: HIP_INFO("Connection to the DHT gateway did not succeed.\n");
         break;
         case 2: HIP_INFO("Getting a response DHT gateway failed.\n");
         break;
         case 3: HIP_INFO("Entry not found at DHT gateway.\n");
         break;
         case 4: HIP_INFO("DHT gateway not configured yet.\n");
         break;
         case 5: HIP_INFO("DHT support not turned on.\n");
         break;
         }
      }
   }

   if(found_hit_from_dht)
      return 1;

out_err:

   /* Open the file containing HIP hosts for reading. */
   fp = fopen(_PATH_HIP_HOSTS, "r");
   if(fp == NULL){
      HIP_ERROR("Error opening file '%s' for reading.\n",
		_PATH_HIP_HOSTS);
   }

   HIP_INFO("Searching for a HIT value for host '%s' from file '%s'.\n",
		 name, _PATH_HIP_HOSTS);

   /* Loop through all lines in the file. */
   /** @todo check return values */
   while(fp && getwithoutnewline(line, 500, fp) != NULL){		
      c = ret = is_lsi = 0;
	
      /* Keep track of line number for debuging purposes. */
      lineno++;
      /* Skip empty and single character lines. */
      if(strlen(line) <= 1) 
         continue;
      /* Init a list for the substrings of the line. Note that this is
         done for every line. Break the line into substrings next. */
      initlist(&list);
      extractsubstrings(line,&list);
		
      /* Loop through the substrings just created. We check if the 
         list item is an IPv6 or IPv4 address. If the conversion is NOT
         successful, we assume that the substring represents a fully
         qualified domain name. Note that this omits the possible
         aliases that the hosts has. */
      for(i = 0; i < length(&list); i++){
         err = inet_pton(AF_INET6, getitem(&list,i), &hit);  
         if(err == 0){
            err = inet_pton(AF_INET, getitem(&list,i), &lsi);				
            if(err && IS_LSI32(lsi.s_addr))
               is_lsi = 1;
         }
         if(err != 1)
            fqdn_str = getitem(&list,i);
      }
      /* Here we have the domain name in "fqdn" and the HIT in "hit" or the LSI in "lsi". */
      if( (strlen(name) == strlen(fqdn_str)) &&
          strcmp(name, fqdn_str) == 0           ){
         HIP_INFO("Found a HIT/LSI value for host '%s' on line "\
		  "%d of file '%s'.\n", name, lineno, _PATH_HIP_HOSTS);
         if (is_lsi && (flags & AI_HIP))
            continue;           
         else
            found_hits = 1;
                        
                        /* "add every HIT to linked list"
			   What do you mean by "every"? We only have one HIT per
			   line, don't we? Also, why do we loop through the list
			   again when we already have the hit stored from the
			   previous loop?
			   18.01.2008 16:49 -Lauri. */				
                        for(i = 0; i <length(&list); i++) {
                                struct gaih_addrtuple *last_pat;	

				aux = (struct gaih_addrtuple *)
					malloc(sizeof(struct gaih_addrtuple));
                                if (aux == NULL){
                                        HIP_ERROR("Memory allocation error\n");
                                        return -EAI_MEMORY;
                                }
				memset(aux, 0, sizeof(struct gaih_addrtuple));

				/* Get the last element in the list */
				if (**pat) {
					for (last_pat = **pat; last_pat->next != NULL;
								last_pat = last_pat->next)
						;
				}

                                /* Place the HIT/LSI to the end of the list.*/                                

				if (inet_pton(AF_INET6, getitem(&list,i), &hit)) {
				        /* It's a HIT */
                                        aux->scopeid = 0;
				        aux->family = AF_INET6;
					memcpy(aux->addr, &hit, sizeof(struct in6_addr));
					if (**pat)
						last_pat->next = aux;
					else
						**pat = aux;
				}
				else if (inet_pton(AF_INET, getitem(&list,i), &lsi)){
				        /* IPv4 to IPV6 in order to be supported by the daemon */
					aux->scopeid = 0;
					aux->family = AF_INET;
					HIP_DEBUG_LSI(" lsi to add", &lsi);
					//IPV4_TO_IPV6_MAP(&lsi, &lsi_ip6);
					memcpy(aux->addr, &lsi, sizeof(lsi));
					if (**pat)
						last_pat->next = aux;
					else
						**pat = aux;
				} else {
					free(aux);
				}

         }
      } // end of if
                
      destroy(&list);
   } // end of while
	
   if (fp)                                                               
      fclose(fp);
		
   return found_hits;
}


/* perform HIT-IPv6 mapping if both are found 
   AG: now the loop also takes in IPv4 addresses */
void send_hipd_addr(struct gaih_addrtuple * orig_at, const char *peer_hostname){
	struct gaih_addrtuple *at_ip, *at_hit, *at_lsi = orig_at;
	struct hip_common *msg = NULL;
	char hit_string[INET6_ADDRSTRLEN];
	char ipv6_string[INET6_ADDRSTRLEN];
	int i, lsi_found, err = 0;
	hip_lsi_t lsi;

	HIP_IFE(!(msg = malloc(HIP_MAX_PACKET)), -1);

  	if (orig_at == NULL) {
		_HIP_DEBUG("NULL orig_at sent\n"); 
	}

	for(at_hit = orig_at; at_hit != NULL; at_hit = at_hit->next) {
 		struct sockaddr_in6 *s;
	        struct in6_addr addr6;
   
	        if (at_hit->family != AF_INET6)
    	        	continue;
   
    		s = (struct sockaddr_in6 *) at_hit->addr;
   
		if (!ipv6_addr_is_hit((struct in6_addr *) at_hit->addr))
		        continue;

		/* This guarantees that there is always one HIT per LSI (for the same hostname) */
		lsi_found = 0;

		/* Scan for an LSI. Notice that this handles also multiple LSIs corresponding
		   to the same hostname */
		while(at_lsi != NULL) {
			lsi.s_addr = ((hip_lsi_t *) at_lsi->addr)->s_addr;
			if (at_lsi->family == AF_INET && IS_LSI32(lsi.s_addr)) {
				lsi_found = 1;
				_HIP_DEBUG_LSI("lsi found", &lsi);
				break;
			}
			at_lsi = at_lsi->next;
		}

		for(at_ip = orig_at; at_ip != NULL; at_ip = at_ip->next) {
			if (at_ip->family == AF_INET6){
				if (ipv6_addr_is_hit((struct in6_addr *) at_ip->addr)) {
					continue;
				} else {
			        	addr6 = *(struct in6_addr *) at_ip->addr;
		   		        _HIP_DEBUG_IN6ADDR("addr6\n", (struct in6_addr *)at_hit->addr);
		   		}
	    		} else if (at_ip->family == AF_INET) {
				if (IS_LSI32(((hip_lsi_t *) at_ip->addr)->s_addr)) {
					continue;
				} else {
					_HIP_DEBUG_IN6ADDR("AF_INET ",(struct in_addr *) at_ip->addr);
					IPV4_TO_IPV6_MAP(((struct in_addr *) at_ip->addr), &addr6);
				}
	    		} else {
				continue;
			}

	    		hip_msg_init(msg);
			memset(hit_string, 0, INET6_ADDRSTRLEN);
			memset(ipv6_string, 0, INET6_ADDRSTRLEN);
	      
		    	HIP_DEBUG_IN6ADDR("HIT", (struct in6_addr *)at_hit->addr);
		    	HIP_DEBUG_IN6ADDR("IP", &addr6);

		    	hip_build_param_contents(msg, (void *) at_hit->addr, HIP_PARAM_HIT, sizeof(struct in6_addr));
		    	hip_build_param_contents(msg, (void *) &addr6, HIP_PARAM_IPV6_ADDR, sizeof(struct in6_addr));

		    	inet_ntop(AF_INET6, (struct in6_addr *)at_hit->addr, hit_string,
				  INET6_ADDRSTRLEN);

		    	if (IN6_IS_ADDR_V4MAPPED(&addr6)) {
		      		struct in_addr in_addr;
		   	        IPV6_TO_IPV4_MAP(&addr6, &in_addr);
		      		inet_ntop(AF_INET, &in_addr, ipv6_string, INET6_ADDRSTRLEN);
		      		HIP_INFO("Mapped a HIT to an IPv4 address:\n"\
					"%s -> %s.\n", hit_string, ipv6_string);
		    	} else {
		      		inet_ntop(AF_INET6, &addr6, ipv6_string, INET6_ADDRSTRLEN);
		      		HIP_INFO("Mapped a HIT to an IPv6 address:\n"\
			       		 "%s -> %s.\n", hit_string, ipv6_string);
		    	}

			if (lsi_found) {
		      		HIP_DEBUG_LSI("LSI", &lsi);
				hip_build_param_contents(msg, (void *) &lsi, HIP_PARAM_LSI, sizeof(hip_lsi_t));
		    	}
			//attach hostname to message
			if(peer_hostname){
				HIP_DEBUG("Peer hostname %s\n", peer_hostname);
				hip_build_param_contents(msg, (void *) peer_hostname, HIP_PARAM_HOSTNAME, HIP_HOST_ID_HOSTNAME_LEN_MAX);
			}
				
		    	hip_build_user_hdr(msg, SO_HIP_ADD_PEER_MAP_HIT_IP, 0);
		    	hip_send_recv_daemon_info(msg, 0, 0);
		}//for at_ip
	}//for at_hit

out_err:
	if (msg)
		free(msg);
}

void
get_ip_from_gaih_addrtuple(struct gaih_addrtuple *orig_at, struct in6_addr *ip)
{
	HIP_ASSERT(orig_at != NULL );
  	struct gaih_addrtuple *at_ip;
	struct in6_addr addr6;

  	for(at_ip = orig_at; at_ip != NULL; at_ip = at_ip->next) {
    		if (at_ip->family == AF_INET && 
		    IS_LSI32(ntohl(((struct in_addr *) at_ip->addr)->s_addr)))
      			continue;
		if (at_ip->family == AF_INET6 &&
		    ipv6_addr_is_hit((struct in6_addr *) at_ip->addr)) 
			continue;
    		
    		if (at_ip->family == AF_INET) {
	      		IPV4_TO_IPV6_MAP(((struct in_addr *) at_ip->addr), &addr6);
	      		continue;
	      		memcpy(ip, &addr6, sizeof(struct in6_addr));
	      		_HIP_DEBUG_HIT("IPV4_TO_IPV6_MAP addr=", &addr6);
			_HIP_HEXDUMP("IPV4_TO_IPV6_MAP HEXDUMP ip=", ip, sizeof(struct in6_addr));
    		}
    		else 
      			addr6 = *(struct in6_addr *) at_ip->addr;
	      	_HIP_DEBUG_HIT("get_ip_from_gaih_addrtuple addr=", &addr6);
	      	memcpy(ip, &addr6, sizeof(struct in6_addr));
	      	_HIP_HEXDUMP("get_ip_from_gaih_addrtuple HEXDUMP ip=", ip, sizeof(struct in6_addr));
	}  
}


int gaih_inet_result(struct gaih_addrtuple *at, struct gaih_servtuple *st, 
			const struct addrinfo *req, struct addrinfo **pai){
  int rc;
  int v4mapped = (req->ai_family == PF_UNSPEC || req->ai_family == PF_INET6) &&
		 (req->ai_flags & AI_V4MAPPED);
  const char *c = NULL;
  struct gaih_servtuple *st2;
  struct gaih_addrtuple *at2 = at;
  size_t socklen, namelen;
  sa_family_t family;

  /*
    buffer is the size of an unformatted IPv6 address in printable format.
  */
  char buffer[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
  
  _HIP_DEBUG("Generating answer\n");
  //dump_pai(at);
  while (at2 != NULL){
    if(req->ai_flags & AI_CANONNAME){
      struct hostent *h = NULL;
	   
      int herrno = 0;
      struct hostent th;
      size_t tmpbuflen = 512;
      char *tmpbuf;

      do{
        tmpbuflen *= 2;
        tmpbuf = __alloca (tmpbuflen);
	       
        if(tmpbuf == NULL)
          return -EAI_MEMORY;

        /* skip if at2->addr is HIT ? */
        rc = __gethostbyaddr_r (at2->addr,
				((at2->family == AF_INET6)
				? sizeof(struct in6_addr)
				: sizeof(struct in_addr)),
				at2->family, &th, tmpbuf, tmpbuflen,
				&h, &herrno);

      }
      while (rc == errno && herrno == NETDB_INTERNAL);

      if (rc != 0 && herrno == NETDB_INTERNAL){
        __set_h_errno (herrno);
        return -EAI_SYSTEM;
      }
	   
      if(h == NULL)
        c = inet_ntop (at2->family, at2->addr, buffer, sizeof(buffer));
      else
        c = h->h_name;
	   
      if (c == NULL)
        return GAIH_OKIFUNSPEC | -EAI_NONAME;
	   
      namelen = strlen (c) + 1;
    }else
      namelen = 0;
       
    if (at2->family == AF_INET6 || v4mapped){
      family = AF_INET6;
      socklen = sizeof (struct sockaddr_in6);
    }else{
      family = AF_INET;
      socklen = sizeof (struct sockaddr_in);
    }

    for (st2 = st; st2 != NULL; st2 = st2->next){
      *pai = malloc (sizeof (struct addrinfo) + socklen + namelen);
      if (*pai == NULL)
        return -EAI_MEMORY;
	    
      (*pai)->ai_flags = req->ai_flags;
      (*pai)->ai_family = family;
      (*pai)->ai_socktype = st2->socktype;
      (*pai)->ai_protocol = st2->protocol;
      (*pai)->ai_addrlen = socklen;
      (*pai)->ai_addr = (void *) (*pai) + sizeof(struct addrinfo);
#ifdef _HAVE_SA_LEN
      ((struct sockaddr_un *) (*pai)->ai_addr)->sa_len = socklen;
#endif /* _HAVE_SA_LEN */
      (*pai)->ai_addr->sa_family = family;
	    
      if (family == AF_INET6){
        struct sockaddr_in6 *sin6p =
		  (struct sockaddr_in6 *) (*pai)->ai_addr;

        sin6p->sin6_flowinfo = 0;
        if(at2->family == AF_INET6){
          memcpy(&sin6p->sin6_addr, at2->addr,
		 sizeof (struct in6_addr));
        }else{
          sin6p->sin6_addr.s6_addr32[0] = 0;
          sin6p->sin6_addr.s6_addr32[1] = 0;
          sin6p->sin6_addr.s6_addr32[2] = htonl(0x0000ffff);
          memcpy(&sin6p->sin6_addr.s6_addr32[3],at2->addr,
		 sizeof (sin6p->sin6_addr.s6_addr32[3]));
        }
        sin6p->sin6_port = st2->port;
        sin6p->sin6_scope_id = at2->scopeid;
      }else{
        struct sockaddr_in *sinp =
		  (struct sockaddr_in *) (*pai)->ai_addr;

        memcpy (&sinp->sin_addr, at2->addr, sizeof(struct in_addr));
        sinp->sin_port = st2->port;
        memset (sinp->sin_zero, '\0', sizeof(sinp->sin_zero));
      }

      if(c){
        (*pai)->ai_canonname = ((void *) (*pai) +
					sizeof(struct addrinfo) + socklen);
        strcpy((*pai)->ai_canonname, c);
      }else
        (*pai)->ai_canonname = NULL;

      (*pai)->ai_next = NULL;
      pai = &((*pai)->ai_next);
    } /* for (st2 = st; st2 != NULL; st2 = st2->next) */
	
    at2 = at2->next;
  }
  /* changed __alloca:s for the linked list 'at' to mallocs, 
     free malloced memory from at */
  if(at){
    free_gaih_addrtuple(at);
    /* In case the caller of tries to free at again */
    at = NULL;
  }
  if(st){
    free_gaih_servtuple(st);
    /* In case the caller of tries to free at again */
    st = NULL;
  }
  return 0;
}


int gaih_inet_get_serv(const struct addrinfo *req, const struct gaih_service *service,
		       const struct gaih_typeproto *tp, struct gaih_servtuple **st){
  int rc;  

  if((tp->protoflag & GAI_PROTO_NOSERVICE) != 0)
    return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
  
  if(service->num < 0){
    if(tp->name[0]){
      *st = (struct gaih_servtuple *)
	    malloc (sizeof (struct gaih_servtuple));
	  
      if ((rc = gaih_inet_serv (service->name, tp, req, *st)))
        return rc;
    }else{
      struct gaih_servtuple **pst = st;
      for (tp++; tp->name[0]; tp++){
        struct gaih_servtuple *newp;
	      
        if((tp->protoflag & GAI_PROTO_NOSERVICE) != 0)
          continue;
	      
        if(req->ai_socktype != 0
              && req->ai_socktype != tp->socktype)
          continue;
        if (req->ai_protocol != 0
              && !(tp->protoflag & GAI_PROTO_PROTOANY)
              && req->ai_protocol != tp->protocol)
          continue;
	      
        newp = (struct gaih_servtuple *)
               malloc (sizeof (struct gaih_servtuple));
	      
        if((rc = gaih_inet_serv (service->name, tp, req, newp))){
          if(rc & GAIH_OKIFUNSPEC)
            continue;
          return rc;
        }
	      
        *pst = newp;
        pst = &(newp->next);
      }
      if (*st == (struct gaih_servtuple *) &nullserv)
        return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
    }
  }else{
    *st = malloc(sizeof (struct gaih_servtuple));
    (*st)->next = NULL;
    (*st)->socktype = tp->socktype;
    (*st)->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
			 ? req->ai_protocol : tp->protocol);
    (*st)->port = htons (service->num);
  }
  return 0;
}


/**
 * Retrieves host information?
 *
 * @param  name                host name. 
 * @param  reg                  a pointer to... 
 * @param  tp                   a pointer to...
 * @param  st                   a pointer to...
 * @param  at                   a pointer to...
 * @param  hip_transparent_mode ... 
 * @return zero on success, negative on error.
 */ 
int gaih_inet_get_name(const char *name, const struct addrinfo *req,
		       const struct gaih_typeproto *tp, 
		       struct gaih_servtuple *st, struct gaih_addrtuple **at,
		       int hip_transparent_mode) 
{
        int err = 0, rc = 0;
	int v4mapped = (req->ai_family == PF_UNSPEC ||
			req->ai_family == PF_INET6) &&
		(req->ai_flags & AI_V4MAPPED);
	char *namebuf = strdupa(name);
	struct gaih_addrtuple **pat;
	struct gaih_addrtuple *at_dns;
	int no_data = 0;
	int no_inet6_data = 0;
	int old_res_options = _res.options;
	int found_hits = 0;
	struct gaih_addrtuple *a = NULL, *p = NULL, *aux = NULL, *plast = NULL;
	int lsi_count = 0, hit_count = 0;
	
	_HIP_DEBUG("gaih_inet_get_name() invoked.\n");

	*at = malloc (sizeof (struct gaih_addrtuple));
	
	(*at)->family = AF_UNSPEC;
	(*at)->scopeid = 0;
	(*at)->next = NULL;
	
	/* Is ipv4 address? */
	if (inet_pton (AF_INET, name, (*at)->addr) > 0)
	{
		_HIP_DEBUG("The name to resolve is an IPv4.\n");
		if (req->ai_family == AF_UNSPEC ||
		    req->ai_family == AF_INET || v4mapped)
		{
			(*at)->family = AF_INET;
			if (IS_LSI32(((struct in_addr *)(*at)->addr)->s_addr)) {
				HIP_DEBUG("Resolve LSI\n");
			}
		}
		else
		{
			return -EAI_FAMILY;
		}
	}
  
	/* If the address is not an IPv4 and the family is not specified. */
	if ((*at)->family == AF_UNSPEC)
	{
		char *namebuf = strdupa (name);
		char *scope_delim;
		
		_HIP_DEBUG("The name to resolve is NOT an IPv4.\n");
		
		scope_delim = strchr (namebuf, SCOPE_DELIMITER);
		if (scope_delim != NULL)
		{
			*scope_delim = '\0';
		}
		
		/* Check if the addredd is an IPv6 address. */
		if (inet_pton (AF_INET6, namebuf, (*at)->addr) > 0)
		{
			_HIP_DEBUG("The name to resolve is an IPv6.\n");
			
			if (req->ai_family == AF_UNSPEC ||
			    req->ai_family == AF_INET6)
			{
				(*at)->family = AF_INET6;
			}
			else
			{
				return -EAI_FAMILY;
			}

			if (scope_delim != NULL)
			{
				int try_numericscope = 0;
				if (IN6_IS_ADDR_LINKLOCAL ((*at)->addr)
				    || IN6_IS_ADDR_MC_LINKLOCAL ((*at)->addr))
				{
					(*at)->scopeid =
						if_nametoindex(scope_delim + 1);
					if ((*at)->scopeid == 0)
					{
						try_numericscope = 1;
					}
				} 
				else
				{
					try_numericscope = 1;
				}
				if (try_numericscope != 0)
				{
					char *end;
					unsigned long scopeid =
						strtoul(scope_delim + 1, &end, 10);
					if (*end != '\0' ||
					    (sizeof((*at)->scopeid) <
					     sizeof(scopeid) &&
					     scopeid > 0xffffffff))
					{
						return GAIH_OKIFUNSPEC |
							-EAI_NONAME;
					}
					(*at)->scopeid = (uint32_t) scopeid;
				}
			}
		}
	}
	
	/* host name is not an IP address */

	/* Note: Due to problems in some platforms (FC7), it is not possible 
	   to use the flag AI_NUMERICHOST to identify whether the name is a 
	   numeric address. */

	pat = at;
	a = *at, p = NULL, aux = NULL;
      
	if (!((*at)->family == AF_UNSPEC &&
	      inet_pton (AF_INET, name, (*at)->addr) <= 0 &&
	      inet_pton (AF_INET6, namebuf, (*at)->addr) <= 0))
		return 0;
	
	/* Commented these debug lines since conntest-client-hip outputs
	   all this. Perhaps conntest-client-hip should be modified to
	   output only INFO and ERROR prints... */
	_HIP_DEBUG("The name is not an IPv4 or IPv6 address, resolve name " \
		   "(!AI_NUMERICHOST)\n");
	_HIP_DEBUG("&pat=%p pat=%p *pat=%p **pat=%p\n", &pat, pat, *pat, **pat);
	
#ifdef UNDEF_CONFIG_HIP_AGENT
	if ((hip_transparent_mode || req->ai_flags & AI_HIP) &&
	    hip_agent_is_alive()) {
		/* Communicate the name and port output to the agent
		   synchronously with netlink. First send the name + port
		   and then wait for answer (select). The agent filters
		   or modifies the list. The agent implements gethosts_hit
		   with some filtering. */
	}
#endif
	
	/* If we are looking for both IPv4 and IPv6 address we don't
	   want the lookup functions to automatically promote IPv4
	   addresses to IPv6 addresses.  Currently this is decided
	   by setting the RES_USE_INET6 bit in _res.options.  */
	if (req->ai_family == AF_UNSPEC)
		_res.options &= ~RES_USE_INET6;
	
	if (req->ai_family == AF_UNSPEC || req->ai_family == AF_INET6 
	    || hip_transparent_mode || req->ai_flags & AI_HIP || req->ai_flags & AI_NODHT)
		no_inet6_data = gethosts (name, AF_INET6, &pat);
	
	if (req->ai_family == AF_UNSPEC)
		_res.options = old_res_options;
	
	if (req->ai_family == AF_INET ||
	    (!v4mapped && req->ai_family == AF_UNSPEC) ||
	    (v4mapped && (no_inet6_data != 0 || (req->ai_flags & AI_ALL)))
	    || hip_transparent_mode || req->ai_flags & AI_HIP & AI_NODHT)
		no_data = gethosts (name, AF_INET, &pat);
	
	if (hip_transparent_mode) {
		_HIP_DEBUG("HIP_TRANSPARENT_API: fetch HIT addresses\n");
		
		_HIP_DEBUG("found_hits before gethosts_hit: %d\n", found_hits);
		
		/* What is the point to bitwise OR from a function return value that
		   can implicate also an error value? Anyhows, had to fix this a little
		   to allow the error value to be passed to the caller of this function.
		   -Lauri 07.05.2008. */
		err = gethosts_hit(name, &pat, req->ai_flags);
		if((err) < 0) {
			return err;
		}
		
		found_hits |= err;
		err = 0;
		
		_HIP_DEBUG("found_hits after gethosts_hit: %d\n", found_hits);
		
		if (req->ai_flags & AI_HIP) {
			_HIP_DEBUG("HIP_TRANSPARENT_API: AI_HIP set: strictly HITs are " \
				   "returned\n");
		} else {
			_HIP_DEBUG("HIP_TRANSPARENT_API: AI_HIP unset: if any HITs are " \
				   "found only HITs will be returned; if not, IPs will be " \
				   "returned\n");
		}
	} else /* not hip_transparent_mode */ {
		if (req->ai_flags & AI_HIP) {
			_HIP_DEBUG("no HIP_TRANSPARENT_API: AI_HIP set: strictly HITs are " \
				   "returned\n");
			found_hits |= gethosts_hit(name, &pat, req->ai_flags);
		} else {
			_HIP_DEBUG("no HIP_TRANSPARENT_API: AI_HIP unset: strictly IPs are " \
				   "returned\n");
		}
	}
	
	//dump_pai(*at);
	
	/* perform HIT-IPv6 mapping if both are found 
	   AG: now the loop also takes in IPv4 addresses */
	if (found_hits) 
		send_hipd_addr(*at, name);
	
	/* Check if DNS returned HITs in case hosts file and DHT checks
	   didn't contain HITs. */
	if (!found_hits)
	{
		for (at_dns = *at; at_dns != NULL; at_dns = at_dns->next)
		{
			if (ipv6_addr_is_hit((struct in6_addr *)at_dns->addr)) 
			{
				found_hits = 1;
				send_hipd_addr(*at, name);
				break;
			}
		}
	} 
	
	if (no_data != 0 && no_inet6_data != 0)
	{
		_HIP_DEBUG("nodata\n");
		/* If both requests timed out report this.  */
		if (no_data == EAI_AGAIN && no_inet6_data == EAI_AGAIN)
			return -EAI_AGAIN;
		
		/* We made requests but they turned out no data.  The name
		   is known, though.  */
		return (GAIH_OKIFUNSPEC | -EAI_AGAIN);
	}
	/* If there isn't any node in the list or the first node is unspecified, exit */ 
	if (*at == NULL || (*at)->family == AF_UNSPEC)
		return (GAIH_OKIFUNSPEC | -EAI_NONAME);
	
	_HIP_DEBUG("req->ai_flags: %d   AI_HIP: %d  AF_UNSPEC: %d\n", req->ai_flags, AI_HIP, AF_UNSPEC);
	
	_HIP_DEBUG("found_hits: %d\n", found_hits);
	
	/* Remove IP addresses from the list if needed. Return either HITs or LSI, but not both,
	   depending on which was first on the list (lsi/hit_count variables). */ 
	
	_HIP_DEBUG("(*at)->addr: %s  (*at)->family: %d\n", (*at)->addr, (*at)->family);

	a = *at, p = NULL, aux = NULL;
	
	while (a != NULL) {
		struct gaih_addrtuple *nxt = a->next;
		int is_hit = 0, is_lsi = 0;
	
		if (a->family == AF_INET6 &&
		    ipv6_addr_is_hit((struct in6_addr *)a->addr))
			is_hit = 1;
		else if (a->family == AF_INET &&
			 IS_LSI32(((struct in_addr *) a->addr)->s_addr))
			is_lsi = 1;

		_HIP_DEBUG("req->ai_family: %d   a->family: %d  hit: %d  lsi: %d\n", 
			  req->ai_family, a->family, 
			  is_hit, is_lsi);

		if (a->family == AF_INET) {
			_HIP_DEBUG_INADDR("a->addr",a->addr);
		}

		if (a->family == AF_INET6) {
			_HIP_DEBUG_HIT("a->addr",a->addr);
		}

		/* Include HITs only if asking for unspec or ipv6 addresses,
		   and there were no LSIs (return only LSIs or HITs, but no both) */
		if ((req->ai_family == AF_UNSPEC || req->ai_family == AF_INET6) &&
		    is_hit && lsi_count == 0) {
			hit_count++;
			goto leave;
		}
		
		/* Include LSIs only if asking for unspec or ipv4 addresses,
		   and there were no HITs (return only LSIs or HITs, but no both) */
		if ((req->ai_family == AF_UNSPEC || req->ai_family == AF_INET) &&
		    is_lsi && hit_count == 0) {
			lsi_count++;
			goto leave;
		}
		
		/* Remove normal IP addresses only when AI_HIP is unset */
		if (!(is_lsi || is_hit) && !(req->ai_flags & AI_HIP)) {
			goto leave;
		}

		if (p != NULL){
			while (aux->next != a)
				aux = aux->next;
			aux->next = a->next;
		}
		_HIP_DEBUG("freeing IP address\n");
		free(a);
		a = nxt;
		_HIP_DEBUG("pointer a: %p\tpointer p: %p\n", a, p);
		continue;
	leave:
		if (p == NULL)
			p = aux = a;
		a = a->next;
		_HIP_DEBUG("pointer a: %p\tpointer p: %p\n", a, p);	
	}
	if (p == NULL){  /* no HITs or LSIs were found */
		HIP_INFO("No HITs or LSIs were found.\n");
		return (GAIH_OKIFUNSPEC | -EAI_NONAME);
	}
	
	*at = p;
	
	/* Order the link list so HITs/LSIs are first and then IPs. */
	a = *at, p = NULL, plast = NULL, aux = *at;
	_HIP_DEBUG("Order IP addresses. (*at)->addr: %s (*at)->family: %d\n", (*at)->addr, (*at)->family);  
	while (a != NULL) {
		struct gaih_addrtuple *nxt = a->next;
		
		_HIP_DEBUG("req->ai_family: %d    a->family: %d    ipv6_addr_is_hit: %d a->addr: %s\n", 
			   req->ai_family, a->family, ipv6_addr_is_hit((struct in6_addr *)a->addr), a->addr);
		
		/* do not move HITs if request is not IPv4 */
		if (req->ai_family != AF_INET && 
		    a->family == AF_INET6 && 
		    ipv6_addr_is_hit((struct in6_addr *)a->addr)){
			a = aux = nxt;
			continue;
		}
		
		/* do not move the LSI if request is IPv4 */
		if (req->ai_family != AF_INET6 && 
		    a->family == AF_INET && IS_LSI32(((struct in_addr *) a->addr)->s_addr)) {
			a = aux = nxt;
			continue;
		}
		
		/* inserting the IPs to the linked list *p */
		if (p == NULL){
			p = plast = a;
			a->next = NULL;
		} else {
			plast->next = a;
			plast = plast->next;
			a->next = NULL;
		}
		if (aux == *at) {
			*at = aux = nxt;
		} else { 
			aux = *at;
			while (aux->next != a)
				aux = aux->next;
			aux->next = nxt;
		}
		
		a = aux = nxt;
		_HIP_DEBUG("pointer a: %p\tpointer p: %p\n", a, p);
	}//while
	
	/* Appending linked list *p (IPs) after HITs */
	if (p != NULL) {
		aux = *at;
		if (aux == NULL) {
			*at = p;
		} else {
			while (aux->next != NULL)
				aux = aux->next;
			aux->next = p;
		}
	}
	
	_HIP_DEBUG("Dumping the structure after removing IP addreses\n");
	//dump_pai(*at);

	return 0;
}


static int gaih_inet (const char *name, const struct gaih_service *service,
	   		const struct addrinfo *req, struct addrinfo **pai,
	   		int hip_transparent_mode){
  const struct gaih_typeproto *tp = gaih_inet_typeproto;
  struct gaih_servtuple *st = (struct gaih_servtuple *) &nullserv;
  struct gaih_addrtuple *at = NULL;
  int rc;

  _HIP_DEBUG("Family %d and Flags %d\n", req->ai_family, req->ai_flags);

  if (req->ai_protocol || req->ai_socktype){
    ++tp;

    while(tp->name[0]
	     && ((req->ai_socktype != 0 && req->ai_socktype != tp->socktype)
		 || (req->ai_protocol != 0
		     && !(tp->protoflag & GAI_PROTO_PROTOANY)
		     && req->ai_protocol != tp->protocol)))
	++tp;

    if(! tp->name[0]){
      if(req->ai_socktype)
        return (GAIH_OKIFUNSPEC | -EAI_SOCKTYPE);
      else
	return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
    }
  }

  if(service != NULL){
    rc = gaih_inet_get_serv(req, service, tp, &st);
    if (rc) 
      return rc;
  }else if(req->ai_socktype || req->ai_protocol){
    st = malloc (sizeof (struct gaih_servtuple));
    st->next = NULL;
    st->socktype = tp->socktype;
    st->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
		      ? req->ai_protocol : tp->protocol);
    st->port = 0;
  }else{
    /* Neither socket type nor protocol is set.  Return all socket types
	 we know about.  */
    struct gaih_servtuple **lastp = &st;
    for(++tp; tp->name[0]; ++tp){
      struct gaih_servtuple *newp;

      newp = malloc (sizeof (struct gaih_servtuple));
      newp->next = NULL;
      newp->socktype = tp->socktype;
      newp->protocol = tp->protocol;
      newp->port = 0;

      *lastp = newp;
      lastp = &newp->next;
    }
  }

  if(name != NULL){
    rc = gaih_inet_get_name(name, req, tp, st, &at, hip_transparent_mode);
    if(rc)
      return rc;
  }else /* name == NULL */{
    struct gaih_addrtuple **pat = &at;
    struct gaih_addrtuple *atr, *attr;
    atr = at = malloc (sizeof (struct gaih_addrtuple));
    memset (at, '\0', sizeof (struct gaih_addrtuple));
      
      _HIP_DEBUG(">> name == NULL\n");
      /* Find the local HIs here and add the HITs to atr */
      if (req->ai_flags & AI_HIP) {
	_HIP_DEBUG("AI_HIP set: get only local hits.\n");     
	get_local_hits(service->name, pat);
      } 
      /* Transparent mode and !AI_HIP -> hits before ipv6 addresses? */
      if (hip_transparent_mode && !(req->ai_flags & AI_HIP)) {
	HIP_DEBUG("HIP_TRANSPARENT_MODE, AI_HIP not set:\n"); 
	HIP_DEBUG("get HITs before IPv6 address\n");
	get_local_hits(service->name, pat); 
	attr = at;
	while(attr->next != NULL) {
	  attr = attr->next;
	}
	attr->next = malloc(sizeof (struct gaih_addrtuple));
	memset (attr->next, '\0', sizeof (struct gaih_addrtuple));
	attr->next->family = AF_INET6;
      }

    if(req->ai_family == 0){
      at->next = malloc(sizeof (struct gaih_addrtuple));
      memset (at->next, '\0', sizeof (struct gaih_addrtuple));
    }
      
    if(req->ai_family == 0 || req->ai_family == AF_INET6){
      at->family = AF_INET6;
      if((req->ai_flags & AI_PASSIVE) == 0)
        memcpy (at->addr, &in6addr_loopback, sizeof (struct in6_addr));
      atr = at->next;
    }

    if(req->ai_family == 0 || req->ai_family == AF_INET){
      atr->family = AF_INET;
      if((req->ai_flags & AI_PASSIVE) == 0)
        *(uint32_t *) atr->addr = htonl (INADDR_LOOPBACK);
    }
  }

  if(pai == NULL){
    _HIP_DEBUG("pai == NULL\n");
    return 0;
  }
  _HIP_DEBUG("Dumping the structure before returning results\n");
  //dump_pai(at);
  return gaih_inet_result(at, st, req, pai);  
}

static struct gaih gaih[] =
  {
    { PF_INET6, gaih_inet },
    { PF_INET, gaih_inet },
    { PF_LOCAL, gaih_local },
    { PF_UNSPEC, NULL }
  };

/**
 * Retrieves a socket address structure for specified host. Retrieves a addrinfo
 * linked list for a host using host name @c name and/or portnumber @c service
 * as a search key.
 * 
 * @param name    a pointer to a host name.
 * @param service a pointer to port number as a string.
 * @param hints   a pointer to a socket address structure that is used as a
 *                search key.
 * @param pai     a pointer to a target buffer list where the info is to be
 *                stored. 
 * @return        zero on success, or negative error value on failure. If the
 *                flags are set to AI_KERNEL_LIST, the number of the elements
 *                found in the database is returned on success.
 */
int getaddrinfo(const char *name, const char *service,
		const struct addrinfo *hints, struct addrinfo **pai)
{
	int i = 0, j = 0, last_i = 0, hip_transparent_mode = 0;
	struct addrinfo *p = NULL, **end = NULL;
	struct gaih *g = gaih, *pg = NULL;
	struct gaih_service gaih_service, *pservice = NULL;

	_HIP_DEBUG("------------------GETADDRINFO--------------------\n");
	/* These will segfault if lenght of name is one, but since this
	   is well defined standard function, there must be a good reason
	   for this behavior? */
	if (name != NULL && name[0] == '*' && name[1] == 0)
		name = NULL;
	if (service != NULL && service[0] == '*' && service[1] == 0)
		service = NULL;
	
	/* Return "NAME or SERVICE is unknown." error value. */
	if (name == NULL && service == NULL)
		return EAI_NONAME;

	/* If no search key is given, we use the global default address
	   structure as a searh key. */
	if (hints == NULL) {
		hints = &default_hints;
	}
	
	/* Check if the search key has flags that are not allowed. The flags
	   that are ORed are the allowed flags. */
	if (hints->ai_flags &
	    ~(AI_PASSIVE|AI_CANONNAME|AI_NUMERICHOST|AI_ADDRCONFIG|AI_V4MAPPED|
	      AI_ALL|AI_HIP|AI_HIP_NATIVE|AI_KERNEL_LIST|AI_NODHT)) {
		return EAI_BADFLAGS;
	}
	/* A canonical name is a properly denoted host name of a computer or
	   network server. If the flag is set, a name must have been provided. */
	if ((hints->ai_flags & AI_CANONNAME) && name == NULL)
		return EAI_BADFLAGS;
	/* A socket address structure is either HIP or HIP native. */
	if ((hints->ai_flags & AI_HIP) && (hints->ai_flags & AI_HIP_NATIVE))
		return EAI_BADFLAGS;

#ifdef HIP_TRANSPARENT_API
	/* Transparent mode does not work with HIP native resolver */
	hip_transparent_mode = !(hints->ai_flags & AI_HIP_NATIVE);
#else
	hip_transparent_mode = 0;
#endif
	if (service != NULL) {
		char *c = NULL;
				
		gaih_service.name = service;
		gaih_service.num = strtoul(gaih_service.name, &c, 10);
		
		if (*c)
			gaih_service.num = -1;
		else
			/* Can't specify a numerical socket unless a protocol family was
			   given. */
			if (hints->ai_socktype == 0 && hints->ai_protocol == 0)
				return EAI_SERVICE;
		pservice = &gaih_service;
	}
	else
		pservice = NULL;

	if (name == NULL && (hints->ai_flags & AI_KERNEL_LIST)) {
		socklen_t msg_len = NUM_MAX_HITS * sizeof(struct addrinfo);
		int err = 0, port, i;
    
		*pai = calloc(NUM_MAX_HITS, sizeof(struct addrinfo));
		if (*pai == NULL) {
			HIP_ERROR("Unable to allocated memory\n");
			err = -EAI_MEMORY;
			return err;
		}

		if (!pservice)
			port = 0;
		else
			port = pservice->num;
		/* This is the case which is used after BOS packet is processed,
		   as a second parameter instead of the IPPROTO_HIP we put the
		   port number because it is needed to fill in the struct
		   sockaddr_in6 list. */
		err = hip_recv_daemon_info(NULL, 0);
		HIP_ASSERT(0); /** @todo fix recv_daemon_msg */
		if (err < 0) {
			HIP_ERROR("getsockopt failed (%d)\n", err);
		}
		return err;
	}

	if (pai)
		end = &p;
	else
		end = NULL;
	
	/* What does this freaky loop do? */
	while (g->gaih) {
		
		if (hints->ai_family == g->family ||
		    hints->ai_family == AF_UNSPEC) {
			
			if ((hints->ai_flags & AI_ADDRCONFIG)
			    && !addrconfig(g->family)) {
				continue;
			}
			
			j++;
			if (pg == NULL || pg->gaih != g->gaih) {
				pg = g;
				i = g->gaih(name, pservice, hints, end,
					    hip_transparent_mode);
				if (i != 0) {
					last_i = i;
					if (hints->ai_family == AF_UNSPEC &&
					    (i & GAIH_OKIFUNSPEC)) {
						continue;
					}
					if (p != NULL) {
						freeaddrinfo(p);
					}
					return -(i & GAIH_EAI);
				}
				if (end != NULL) {
					while(*end) end = &((*end)->ai_next);
				}
			}
		}
		++g;
	}
	
	if (j == 0) {
		return EAI_FAMILY;
	}
	
	if (p != NULL) // here should be true
	{
		*pai = p;
		return 0;
	}

	if (pai == NULL && last_i == 0)
		return 0;

	if (p != NULL) {
		freeaddrinfo (p);
	}
	
	/* Okay... What exactly are we returning here? An error value? */
	return last_i ? -(last_i & GAIH_EAI) : EAI_NONAME;
}


/**
 * Frees memory allocated for a addrinfo structure. The addrinfo @c ai is
 * actually a linked list. This function frees all of the addrinfo elements in
 * the list @c ai.
 *
 * @param   ai a pointer to a addrinfo structure to be freed. 
 */ 
void freeaddrinfo (struct addrinfo *ai)
{
	struct addrinfo *p = NULL;
	
	while (ai != NULL)
	{
		p = ai;
		ai = ai->ai_next;
		free (p);
	}
}

/* Teststub for the openDHT interface  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include "libhipopendht.h"
#include "debug.h"

int main(int argc, char *argv[])
{
    int s, ret, error;
    int ttl = 240;
    /*
    struct in6_addr val_hit_addr;
    struct in6_addr val_ip_addr; 
    */
    char opendht[] = "193.167.187.134";
    //char opendht[] = "193.167.187.130";
    //char opendht[] = "opendht.nyuld.net";
    //char opendht[] = "openlookup.net";
    /* both responses were 1024 before */
    /* now more because base64 lengthens the message */
    char dht_response[2048]; 
    char dht_response2[2048];
    char put_packet[2048]; 
    /* Test values */  
    char val_bogus[] = "BogusKey";
    char val_host[] = "testhostname";
    char val_hosti[] = "testhostname2";
    char val_host_test[] = "hosttestname2";
    char val_something[] = "hi-to-everyone";
    char secret_str[] = "secret_str_is_secret";
    char key_test[] = "Testiavain"; 
    char key_rand[] = "random_key";
    char val_tenbyte[] = "1234567890";
    /* smaller than 1K actually because any larger will bounce from DHT */
    char val_onekilo[985]; 
    char val_hit[] = "2001:001a:3aa1:3a84:5b38:de59:28ff:41ea";
    char val_ip[] = "2001:0708:0140:0220:0213:a9ff:fec0:58f6";
    /* TODO change this to something smarter :) */
    char host_addr[] = "127.0.0.1";//"openlookup.net"; 
    int n = 0, iter = 0;
    struct timeval conn_before, conn_after; 
    struct timeval stat_before, stat_after;
    struct timeval put_rm_before, put_rm_after;
    struct timeval put_rm2_before, put_rm2_after;
    struct timeval rm_before, rm_after;
    unsigned long conn_diff_sec, conn_diff_usec;
    unsigned long stat_diff_sec, stat_diff_usec;
    unsigned long put_rm_diff_sec, put_rm_diff_usec;
    unsigned long put_rm2_diff_sec, put_rm2_diff_usec;
    unsigned long rm_diff_sec, rm_diff_usec;
    iter = atoi(argv[2]);
    struct addrinfo * serving_gateway;
    int port = 5851; //5851 for opendht 80 for openlookup v1

    if (argc != 3) {
        HIP_DEBUG("Usage: %s num iterations\n", argv[0]);
        HIP_DEBUG("Num = 0 for regular testing of functions "
               "(iterations not used just give 1)\n"
               "Num = 1 get test times when value not found\n"
               "Num = 2 get test times when value is found\n"
               "Num = 3 put test times with 10 byte value (same key)\n"
               "Num = 4 put test times with 10 byte value, "
               "waiting 5 sec in between puts(same key)\n"
               "Num = 5 put test times with 10 byte value (random key, short TTL)\n"
               "Num = 6 put test times with 10 byte value, waiting 5 sec "
               "in between puts(random key, short TTL)\n"
               "Num = 7 put test times with consecutive keys and 985 byte values\n"
               "Num = 8 put test times with consecutive keys and 985 byte values "
               "with 5 sec sleep in between puts\n"
               "Num = 9 get test times with consecutive keys (do number 7 or 8 first)\n"
               "Num = 'a' remove testing\n"
               "Iterations, just as it says\n"
               "Connect errors will print 999 999\n");
        exit(EXIT_SUCCESS);
    }

    /* resolve the gateway address */
    error = resolve_dht_gateway_info (opendht, &serving_gateway, port, AF_INET);
    if (error < 0) {
        HIP_DEBUG("Resolving error\n");
        exit(0);
    }

    if (argv[1][0] == '0') 
        {
            HIP_DEBUG("Starting to test the openDHT interface.\n");
            HIP_DEBUG("Using test mapping\n'%s (FQDN) -> %s (HIT) -> %s (IP)'.\n",
                   val_host, val_hit, val_ip);
            
            /*!!!! put fqdn->hit !!!!*/
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = 0;
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(put_packet, '\0', sizeof(put_packet));
            ret = opendht_put( 
                              (unsigned char *)val_host,
                              (unsigned char *)val_hit, 
                              (unsigned char *)host_addr,port,ttl,put_packet);   
            ret = opendht_send (s,put_packet);
            if (ret == -1) exit(1);
            ret = opendht_read_response(s, dht_response);
            if (ret == -1) exit(1);
            HIP_DEBUG("Put packet (fqdn->hit) sent and ...\n");
            HIP_DEBUG("Put was success\n");
            close(s);
            /*!!!! put hit->ip !!!!*/ 
            
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(put_packet, '\0', sizeof(put_packet));
            ret = opendht_put( 
                              (unsigned char *)val_hit,
                              (unsigned char *)val_ip, 
                              (unsigned char *)host_addr,port,ttl,put_packet);
			ret = opendht_send (s,put_packet);
            if (ret == -1) exit(1);
            ret = opendht_read_response(s, dht_response); 
            if (ret == -1) exit(1);
            HIP_DEBUG("Put packet (hit->ip) sent and ...\n");
            HIP_DEBUG("Put was success\n", dht_response);
            close(s);
            
            /*!!!! get fqdn !!!!*/
            
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response, '\0', sizeof(dht_response));
            ret = opendht_get(s, (unsigned char *)val_host, (unsigned char *)host_addr, port);
            ret = opendht_read_response(s, dht_response); 
            ret = handle_hit_value(&dht_response, (void *)dht_response2);
            // if (ret == -1) exit (1);
            HIP_DEBUG("Get packet (fqdn) sent and ...\n");
            if (ret == 0) 
                {
                    HIP_DEBUG("Teststub: Value received from DHT: %s\n", dht_response2);
                    if (!strcmp(dht_response2, val_hit)) 
                        HIP_DEBUG("Did match the sent value.\n");
                    else
                        HIP_DEBUG("Did NOT match the sent value!\n");
                }
            close(s);
            
            /*!!!! get hit !!!!*/
   
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_get(s, (unsigned char *)val_hit, (unsigned char *)host_addr, port); 
            ret = opendht_read_response(s, dht_response2);
            memset(dht_response, '\0', sizeof(dht_response));
            hip_in6_ntop((struct in6_addr *)dht_response2, dht_response);
            HIP_DEBUG("Value: %s\n", (char*)dht_response);
            if (ret == -1) exit (1);
            HIP_DEBUG("Get packet (hit) sent and ...\n");
            if (ret == 0)
                {
                    HIP_DEBUG("Teststub: Value received from DHT: %s\n",dht_response);
                    if (!strcmp(dht_response, val_ip))
                        HIP_DEBUG("Did match the sent value.\n");
                    else
                        HIP_DEBUG("Did NOT match the sent value!\n");
                }
            close(s);
            
            /* Finally let's try to get a key that doesn't exist */
            
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_get(s, (unsigned char *)val_bogus, (unsigned char *)host_addr, port); 
            ret = opendht_read_response(s, dht_response2); 
            // if (ret == -1) exit (1);
            HIP_DEBUG("Get packet (bogus, will not be found (hopefully)) sent and ...\n");
            HIP_DEBUG("Teststub: Value received from DHT: %s\n",dht_response2);   
            close(s);

            /* put_removable and rm tests */
      
            /* put_removable */
            HIP_DEBUG("\n\nPut removable starts\n");
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_put_rm(s, 
                                 (unsigned char *)val_host_test,
                                 (unsigned char *)val_something,
                                 (unsigned char *)secret_str,
                                 (unsigned char *)host_addr,port,ttl);   
            ret = opendht_read_response(s, dht_response2); 
            if (ret == -1) exit(1);
            HIP_DEBUG("Put(rm) packet (fqdn->hit) sent and ...\n");
            HIP_DEBUG("Put(rm) was success\n");
            close(s);
            /* check that value exists */
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_get(s, (unsigned char *)val_host_test, 
                              (unsigned char *)host_addr, port); 
            ret = opendht_read_response(s, dht_response2); 
            // if (ret == -1) exit (1);
            HIP_DEBUG("Get packet sent and (value should be found, just sent it)...\n");
            HIP_DEBUG("Value received from DHT: %s\n",dht_response2);   
            close(s);
            /* send remove */
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_rm(s, 
                                 (unsigned char *)val_host_test,
                                 (unsigned char *)val_something,
                                 (unsigned char *)secret_str,
                                 (unsigned char *)host_addr,port,ttl);   
            ret = opendht_read_response(s, dht_response2); 
            if (ret == -1) exit(1);
            HIP_DEBUG("Rm packet sent and ...\n");
            HIP_DEBUG("Rm was success\n");
            close(s);
            /* can you get it anymore */
      
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_get(s, (unsigned char *)val_host_test, 
                              (unsigned char *)host_addr, port); 
            ret = opendht_read_response(s, dht_response2); 
            // if (ret == -1) exit (1);
            HIP_DEBUG("Get packet (was removed, will not be found (hopefully)) sent and ...\n");
            HIP_DEBUG("Teststub: Value received from DHT: %s\n",dht_response2);   
            close(s);
            
            /* testing a wrapper for blocking dht call */
            memset(dht_response, '\0', sizeof(dht_response));
            ret = 0;
            HIP_DEBUG("\n\nTrying out get wrapper\n");
            ret = hip_opendht_get_key(&handle_ip_value, serving_gateway, val_hit, dht_response);

            if (!ret)
                HIP_DEBUG("DHT get succeeded\n");
            else
                HIP_DEBUG("DHT get was unsuccesfull\n");
            
            /* basic testing done */
            exit(EXIT_SUCCESS);
        }
    else if (argv[1][0] == '1') 
        {            
            HIP_DEBUG("Get test times when value not found\n");
            HIP_DEBUG("Printing \"connection time; get time; DHT answer (should be empty here)\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);
            
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            ret = opendht_get(s, (unsigned char *)val_bogus, 
                                              (unsigned char *)host_addr, 5851); 
                            ret = opendht_read_response(s, dht_response2); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f %.6f %s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response2);
                        }
                }
        }
    else if (argv[1][0] == '2')
        {
            HIP_DEBUG("Get test times when value is found\n");
            HIP_DEBUG("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);
            
            s = init_dht_gateway_socket_gw(s, serving_gateway);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            /* iterations by estimate seconds, so the value is there long enough */
            memset(put_packet, '\0', sizeof(put_packet));
            ret = opendht_put( (unsigned char *)val_hit,
                              (unsigned char *)val_ip, 
                              (unsigned char *)host_addr,5851,(iter * 3),put_packet);
			ret = opendht_send (s,put_packet); 
            ret = opendht_read_response(s, dht_response); 
            if (ret == -1) exit(1);
            HIP_DEBUG("Put packet (hit->ip) sent and ...\n");
            HIP_DEBUG("Put was success\n", dht_response);
            close(s);

            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n); 
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            ret = opendht_get(s, (unsigned char *)val_hit, 
                                              (unsigned char *)host_addr, 5851); 
                            ret = opendht_read_response(s, dht_response2); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f %.6f %s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response2);
                        }
                }
        }
    else if (argv[1][0] == '3')
        {
            HIP_DEBUG("Put test times with 10 byte value (same key)\n");
            HIP_DEBUG("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);
            
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just 20 secs */
                            memset(put_packet, '\0', sizeof(put_packet));
                            ret = opendht_put( (unsigned char *)key_test,
                                              (unsigned char *)val_tenbyte, 
                                              (unsigned char *)host_addr,5851,20,put_packet);
                            ret = opendht_send (s,put_packet); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f %.6f %s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                        }
                }
        }
    else if (argv[1][0] == '4')
        {
            HIP_DEBUG("Put test times with 10 byte value, waiting "
                   "5 sec in between puts (same key)\n");
            HIP_DEBUG("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);
            
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just 20 secs */
                            memset(put_packet, '\0', sizeof(put_packet));
                            ret = opendht_put( (unsigned char *)key_test,
                                              (unsigned char *)val_tenbyte, 
                                              (unsigned char *)host_addr,5851,20,put_packet);
                            ret = opendht_send (s,put_packet); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f %.6f %s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                            sleep(5);
                        }
                }
        }
    else if (argv[1][0] == '5')
        {
            HIP_DEBUG("Put test times with 10 byte value (random key, short TTL)\n");
            HIP_DEBUG("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);

            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    ra= rand() % 1000000000;
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("random key  %s\n", key_rand);
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just 20 secs */
                            memset(put_packet, '\0', sizeof(put_packet));
                            ret = opendht_put((unsigned char *)key_rand,
                                              (unsigned char *)val_tenbyte, 
                                              (unsigned char *)host_addr,5851,20,put_packet);
                            ret = opendht_send (s,put_packet); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f %.6f %s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                        }
                }
        }
    else if (argv[1][0] == '6')
        {
            HIP_DEBUG("Put test times with 10 byte value, waiting 5 sec in "
                   "between puts(random key, short TTL)\n");
            HIP_DEBUG("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);
            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    ra= rand() % 1000000000;
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("random key  %s\n", key_rand);
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just 20 secs */
                            memset(put_packet, '\0', sizeof(put_packet));
                            ret = opendht_put( (unsigned char *)key_rand,
                                              (unsigned char *)val_tenbyte, 
                                              (unsigned char *)host_addr,5851,20,put_packet);
                            ret = opendht_send (s,put_packet); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f %.6f %s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                            sleep(5);
                        }
                }
        }
    else if (argv[1][0] == '7')
        {
            memset(val_onekilo,'a',sizeof(val_onekilo));
            HIP_DEBUG("Put test times with consecutive keys and 985 byte values\n");
            HIP_DEBUG("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);
            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    /* consecutive key instead of random as the variable says */
                    ra= (n + 1) * 1000000; 
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("Consecutive key  %s\n", key_rand);
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
			    memset(dht_response, '\0', sizeof(dht_response));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just iter * 60 secs so values can be found in get test */
                            memset(put_packet, '\0', sizeof(put_packet));
                            ret = opendht_put( (unsigned char *)key_rand,
                                              (unsigned char *)val_onekilo, 
                                              (unsigned char *)host_addr,5851,(iter* 60),put_packet);
                            ret = opendht_send (s,put_packet); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f %.6f %s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                        }
                }
        }
    else if (argv[1][0] == '8')
        {
            memset(val_onekilo,'a',sizeof(val_onekilo));
            HIP_DEBUG("Put test times with consecutive keys and 985 byte values"
                   " with 5 sec sleep between puts\n");
            HIP_DEBUG("Printing \"connection time; get time; DHT answer\n");
            HIP_DEBUG("(0 = OK, 1 = error, 2 = retry, or some value)\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);
            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    /* consecutive key instead of random as the variable says */
                    ra= (n + 1 ) * 1000000; 
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("Consecutive key  %s\n", key_rand);
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            memset(dht_response, '\0', sizeof(dht_response));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just iter * 60 secs so values can be found in get test */
                            memset(put_packet, '\0', sizeof(put_packet));
                            ret = opendht_put((unsigned char *)key_rand,
                                              (unsigned char *)val_onekilo, 
                                              (unsigned char *)host_addr,5851,(iter * 60),put_packet);
                            ret = opendht_send (s,put_packet); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f %.6f %s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                            sleep(5);
                        }
                }
        }        
    else if (argv[1][0] == '9')
        {     
            HIP_DEBUG("Get test times with consecutive keys (do number 7 or 8 first,"
                   " otherwise it will be num 2)\n");
            HIP_DEBUG("Printing \"connection time; get time; DHT answer\n");
            HIP_DEBUG("(0 = OK, 1 = error, 2 = retry, or some value "
                   "(printing just first character, its just 985 'a's))\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);
            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    /* consecutive key instead of random as the variable says */
                    ra= (n + 1) * 1000000; 
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("Consecutive key  %s\n", key_rand);
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            memset(dht_response, '\0', sizeof(dht_response));
                            gettimeofday(&stat_before, NULL);
                            ret = opendht_get(s, (unsigned char *)key_rand, 
                                              (unsigned char *)host_addr, 5851); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f %.6f %s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                        }
                }

        }
    else if (argv[1][0] == 'a')
        {
            HIP_DEBUG("Rm test times, put_removable, rm, put_removable\n"
                   "get (check that it is the new one you get)\n"
                   "sleep for rm ttl again...\n");
            HIP_DEBUG("Printing \"put time; rm time; put time; DHT answer\n");
            HIP_DEBUG("(0 = OK, 1 = error, 2 = retry, or some value)\n");
            HIP_DEBUG("Doing %s iterations\n", argv[2]);
            
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    /* first put removabe */
                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                    gettimeofday(&put_rm_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    if (error < 0)
                        {
                            printf("9999 999 999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            ret = opendht_put_rm(s, 
                                                 (unsigned char *)val_host_test,
                                                 (unsigned char *)val_something,
                                                 (unsigned char *)secret_str,
                                                 (unsigned char *)host_addr,5851,20);   
                            ret = opendht_read_response(s, dht_response2); 
                            gettimeofday(&put_rm_after, NULL);
                            if (ret == -1) exit(1);
                            close(s);
                            /* removing the value */
                            s = init_dht_gateway_socket_gw(s, serving_gateway);
                            gettimeofday(&rm_before, NULL);
                            error = connect_dht_gateway(s, serving_gateway, 1);
                            if (error < 0) 
                                {
                                    printf("999 9999 999\n");
                                    close(s);
                                }
                            else
                                {
                                    ret = 0;
                                    memset(dht_response2, '\0', sizeof(dht_response2));
                                    ret = opendht_rm(s, 
                                                     (unsigned char *)val_host_test,
                                                     (unsigned char *)val_something,
                                                     (unsigned char *)secret_str,
                                                     (unsigned char *)host_addr,5851,20);   
                                    ret = opendht_read_response(s, dht_response2); 
                                    gettimeofday(&rm_after, NULL);
                                    if (ret == -1) exit(1);
                                    close(s);
                                    /* putting a new value */
          
                                    s = init_dht_gateway_socket_gw(s, serving_gateway);
                                    gettimeofday(&put_rm2_before, NULL);
                                    error = connect_dht_gateway(s, serving_gateway, 1);
                                    if (error < 0)
                                        {
                                            printf("999 999 9999\n");
                                            close(s);
                                        }
                                    else 
                                        {
                                            ret = 0;
                                            memset(dht_response2, '\0', sizeof(dht_response2));
                                            ret = opendht_put_rm(s, 
                                                                 (unsigned char *)val_host_test,
                                                                 (unsigned char *)val_something,
                                                                 (unsigned char *)secret_str,
                                                                 (unsigned char *)host_addr,
                                                                 5851,20);   
                                            ret = opendht_read_response(s, dht_response2); 
                                            gettimeofday(&put_rm2_after, NULL);
                                            if (ret == -1) exit(1);
                                            close(s);

                                            /* Print findings*/
                                            put_rm_diff_sec = (put_rm_after.tv_sec 
                                                               - put_rm_before.tv_sec) *1000000;
                                            put_rm_diff_usec = (put_rm_after.tv_usec 
                                                                - put_rm_before.tv_usec);
                                            
                                            rm_diff_sec = (rm_after.tv_sec 
                                                           - rm_before.tv_sec) *1000000;
                                            rm_diff_usec = (rm_after.tv_usec 
                                                            - rm_before.tv_usec);

                                            put_rm2_diff_sec = (put_rm2_after.tv_sec 
                                                                - put_rm2_before.tv_sec) *1000000;
                                            put_rm2_diff_usec = (put_rm2_after.tv_usec 
                                                         - put_rm2_before.tv_usec);
                                            
                                            printf("%.6f %.6f %.6f %s\n", 
                                                   ((put_rm_diff_sec + put_rm_diff_usec)
                                                    /1000000.0),
                                                   ((rm_diff_sec + rm_diff_usec)/1000000.0),
                                                   ((put_rm2_diff_sec + 
                                                    put_rm2_diff_usec)/1000000.0),
                                                   dht_response2);
                                            HIP_DEBUG("sleeping for 30 secs to get rid off "
                                                      "old values and removes\n"); 
                                            sleep(30);
                                        }
                                }
                        }
                }

        }
    else
        {
            HIP_DEBUG("Unknown parameter, %s\n", argv[1]);
        }
}

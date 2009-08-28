#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <libxml2/libxml/tree.h>
#include "libhipopendhtxml.h"
#include "debug.h"
#include "netdev.h"

xmlNodePtr xml_new_param(xmlNodePtr node_parent, char *type, char *value);
 
/** 
 * build_packet_put_rm - Builds HTTP XML packet for removable put
 * @param key Key that is used in to the openDHT
 * @param key_len Length of the key in bytes
 * @param value Value to be stored in to the openDHT 
 * @param value_len Lenght of value in bytes
 * @param secret Secret used in remove
 * @param secret_len Length of the secret used in remove
 * @param port Port for the openDHT (5851)
 * @param host_ip Host IP
 * @param out_buffer Completed packet will be in this buffer
 *
 * @return integer 0
 */
int build_packet_put_rm(unsigned char * key, 
                     int key_len,
		     unsigned char * value,
                     int value_len, 
                     unsigned char *secret,
                     int secret_len,
                     int port,
                     unsigned char * host_ip,
		     char * out_buffer,
                     int ttl) 
{
    char *key64 = NULL;
    char *value64 = NULL;
    char *secret64 = NULL;
    
    key64 = (char *)base64_encode((unsigned char *)key, 
                                  (unsigned int)key_len);
    value64 = (char *)base64_encode((unsigned char *)value, 
                                    (unsigned int)value_len);

    unsigned char *sha_retval;
    char secret_hash[21];
    memset(secret_hash, '\0', sizeof(secret_hash));

    sha_retval = SHA1(secret, secret_len, secret_hash);
    if (!sha_retval)
        {
            HIP_DEBUG("SHA1 error when creating hash of the secret for the removable put\n");
            return(-1);
        }
    secret64 = (char *)base64_encode((unsigned char *)secret_hash, (unsigned int)20);

    char ttl_str[10];
    memset(ttl_str, '\0', sizeof(char[10]));
    sprintf(&ttl_str, "%d", ttl);
    _HIP_DEBUG("TTL STR %s INT %d\n",ttl_str, ttl);

    /* Create a XML document */
    xmlDocPtr xml_doc = NULL;
    xmlNodePtr xml_root = NULL;
    xmlNodePtr xml_node;
    xmlNodePtr xml_node_skip;
    unsigned char *xml_buffer = NULL;
    int xml_len = 0;

    xml_doc = xmlNewDoc(BAD_CAST "1.0");
    xml_root = xmlNewNode(NULL, BAD_CAST "methodCall");
    xmlDocSetRootElement(xml_doc, xml_root);
    if (secret_len > 0)
        xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "methodName", BAD_CAST "put_removable");
    else
        xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "methodName", BAD_CAST "put");
    xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "params", NULL);
    xml_new_param(xml_node, "base64", (char *)key64);
    xml_new_param(xml_node, "base64", (char *)value64);

    xml_node_skip = xml_node;
    if (secret_len > 0)
        {
            xml_new_param(xml_node, "string", "SHA");
            xml_new_param(xml_node, "base64", (char *)secret64);
        }

    xml_new_param(xml_node_skip, "int", &ttl_str);  
    xml_new_param(xml_node_skip, "string", BAD_CAST "HIPL");
    xmlDocDumpFormatMemory(xml_doc, &xml_buffer, &xml_len, 0);

    memset(out_buffer, '\0', sizeof(out_buffer));
    sprintf(out_buffer, 
            "POST / HTTP/1.0\r\nHost: %s:%d\r\nUser-Agent: "
            "hipl\r\nContent-Type: "
            "text/xml\r\nContent-length: %d\r\n\r\n", 
            host_ip, port, xml_len);
    memcpy(&out_buffer[strlen(out_buffer)], xml_buffer, xml_len);
  
    _HIP_DEBUG("\n\n%s\n\n", out_buffer);
    
    xmlFree(xml_buffer);
    xmlFreeDoc(xml_doc);
    free(key64);
    free(secret64);
    free(value64); 
    return(0);
}

/** 
 * build_packet_put - Builds HTTP XML packet for put
 * @param key Key that is used in to the openDHT
 * @param key_len Length of the key in bytes
 * @param value Value to be stored in to the openDHT 
 * @param value_len Lenght of value in bytes
 * @param secret Secret used in remove
 * @param secret_len Length of the secret used in remove
 * @param port Port for the openDHT (5851)
 * @param host_ip Host IP
 * @param out_buffer Completed packet will be in this buffer
 *
 * @return integer 0
 */
int build_packet_put(unsigned char * key, 
                     int key_len,
		     unsigned char * value,
                     int value_len, 
                     int port,
                     unsigned char * host_ip,
		     char * out_buffer,
                     int ttl) 
{
    int ret = 0;
    ret = build_packet_put_rm(key,
                              key_len,
                              value,
                              value_len,
                              "",
                              0,
                              port,
                              host_ip,
                              out_buffer,
                              ttl);
    return(ret);
}

/** 
 * build_packet_get - Builds HTTP XML packet for get
 * @param key Key that is used in to the openDHT
 * @param key_len Length of the key in bytes
 * @param port Port for the openDHT (5851)
 * @param host_ip Host IP
 * @param out_buffer Completed packet will be in this buffer
 *
 * @return integer 0
 */
int build_packet_get(unsigned char * key,
                     int key_len,
                     int port,
                     unsigned char * host_ip,
		     char * out_buffer) 
{
    char *key64 = NULL; 
    key64 = (char *)base64_encode((unsigned char *)key, (unsigned int)key_len);

    /* Create a XML document */
    xmlDocPtr xml_doc = NULL;
    xmlNodePtr xml_root = NULL;
    xmlNodePtr xml_node;
    unsigned char *xml_buffer = NULL;
    int xml_len = 0;

    xml_doc = xmlNewDoc(BAD_CAST "1.0");
    xml_root = xmlNewNode(NULL, BAD_CAST "methodCall");
    xmlDocSetRootElement(xml_doc, xml_root);
    xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "methodName", BAD_CAST "get");
    xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "params", NULL);
    xml_new_param(xml_node, "base64", (char *)key64);
    xml_new_param(xml_node, "int", "10");	/* maxvals */
    xml_new_param(xml_node, "base64", "");	/* placemark */ 
    xml_new_param(xml_node, "string", BAD_CAST "HIPL");
    xmlDocDumpFormatMemory(xml_doc, &xml_buffer, &xml_len, 0);

    memset(out_buffer, '\0', sizeof(out_buffer));
    sprintf(out_buffer, 
            "POST / HTTP/1.0\r\nHost: %s:%d\r\nUser-Agent: "
            "hipl\r\nContent-Type: "
            "text/xml\r\nContent-length: %d\r\n\r\n", 
            host_ip, port, xml_len);
    memcpy(&out_buffer[strlen(out_buffer)], xml_buffer, xml_len);
    
    _HIP_DEBUG("\n\n%s\n\n", out_buffer);
    
    xmlFree(xml_buffer);
    xmlFreeDoc(xml_doc);  
    free(key64);
    return(0);
}

/** 
 * build_packet_rm - Builds HTTP XML packet for rm
 * @param key Key that is used in to the openDHT
 * @param key_len Length of the key in bytes
 * @param value Value to be removed in to the openDHT 
 * @param value_len Lenght of value in bytes
 * @param secret Plain text secret (has of which sent earlier)
 * @param secret_len Length of the secret
 * @param port Port for the openDHT (5851)
 * @param host_ip Host IP
 * @param out_buffer Completed packet will be in this buffer
 *
 * @return integer 0
 */
int build_packet_rm(unsigned char * key, 
                    int key_len,
                    unsigned char * value,
                    int value_len, 
                    unsigned char * secret,
                    int secret_len,
                    int port,
                    unsigned char * host_ip,
                    char * out_buffer,
                    int ttl) 
{
    char *key64 = NULL;
    char *value64 = NULL;
    char *secret64 = NULL;
    key64 = (char *)base64_encode((unsigned char *)key, (unsigned int)key_len);
    secret64 = (char *)base64_encode((unsigned char *)secret, (unsigned int)secret_len);

    unsigned char *sha_retval;
    char value_hash[21];
    memset(value_hash, '\0', sizeof(value_hash));
    sha_retval = SHA1(value, value_len, value_hash);
    if (!sha_retval)
        {
            HIP_DEBUG("SHA1 error when creating hash of the value for rm msg\n");
            return(-1);
        }
    value64 = (char *)base64_encode((unsigned char *)value_hash, 20);

    char ttl_str[10];
    memset(ttl_str, '\0', sizeof(char[10]));
    sprintf(&ttl_str, "%d", ttl);

    /* Create a XML document */
    xmlDocPtr xml_doc = NULL;
    xmlNodePtr xml_root = NULL;
    xmlNodePtr xml_node;
    unsigned char *xml_buffer = NULL;
    int xml_len = 0;

    xml_doc = xmlNewDoc(BAD_CAST "1.0");
    xml_root = xmlNewNode(NULL, BAD_CAST "methodCall");
    xmlDocSetRootElement(xml_doc, xml_root);
    xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "methodName", BAD_CAST "rm");
    xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "params", NULL);
    xml_new_param(xml_node, "base64", (char *)key64);
    xml_new_param(xml_node, "base64", (char *)value64);
    xml_new_param(xml_node, "string", BAD_CAST "SHA");
    xml_new_param(xml_node, "base64", (char *)secret64);
    xml_new_param(xml_node, "int", &ttl_str);  
    xml_new_param(xml_node, "string", BAD_CAST "HIPL");
    xmlDocDumpFormatMemory(xml_doc, &xml_buffer, &xml_len, 0);

    memset(out_buffer, '\0', sizeof(out_buffer));
    sprintf(out_buffer, 
            "POST / HTTP/1.0\r\nHost: %s:%d\r\nUser-Agent: "
            "hipl\r\nContent-Type: "
            "text/xml\r\nContent-length: %d\r\n\r\n", 
            host_ip, port, xml_len);
    memcpy(&out_buffer[strlen(out_buffer)], xml_buffer, xml_len);
    
    _HIP_DEBUG("\n\n%s\n\n", out_buffer);
    
    xmlFree(xml_buffer);
    xmlFreeDoc(xml_doc);
    free(key64);
    free(secret64);
    free(value64); 
    return(0);
}

/** 
 * read_packet_content - Builds HTTP XML packet for put
 * @param in_buffer Should contain packet to be parsed including the HTTP header
 * @param out_value Value received is stored here
 *
 * @return Integer -1 if error, on success 0, len if LOCATOR or other binary
 */
int read_packet_content(char * in_buffer, char * out_value)
{
    int ret = 0, i = 0, ii = 0;
    int evpret = 0;
    char * place = NULL;
    char tmp_tmp_buffer[2048];
    char tmp_buffer[2048]; 
    xmlDocPtr xml_doc = NULL;
    xmlNodePtr xml_node;
    xmlNodePtr xml_node_value;
    xmlChar *xml_data;
    struct opendht_answers answers;

    memset(tmp_buffer, '\0', sizeof(tmp_buffer));
    memset(out_value, '\0', sizeof(out_value));
    answers.count = 0;
    answers.addrs[0] = '\0';
      
    _HIP_DEBUG("\n\nXML Parser got this input\n\n%s\n\n",in_buffer);
    
    /* To be on the safe side, let's remove 0x0a's from in_buffer */
    while (in_buffer[i] != '\0') {
        if (in_buffer[i] != '\n') {
            tmp_tmp_buffer[ii] = in_buffer[i];
            ii++;
        }
        i++;
    }
    tmp_tmp_buffer[ii] = '\0';
    
    _HIP_DEBUG("\n\nAfter clean up\n\n%s\n\n",tmp_tmp_buffer);
       
    /*!!!! is there a http header !!!!*/
    if (strncmp(tmp_tmp_buffer, "HTTP", 4) !=0) 
    { 
        HIP_DEBUG("Parser error: no HTTP header in the packet.\n");
        ret = -1;
        goto out_err;
    }
    
    /* is there a xml document */
    if ((place = strstr(tmp_tmp_buffer, "<?xml")) == NULL)
    {
        HIP_DEBUG("Parser error: no XML content in the packet.\n");
        ret = -1;
        goto out_err;
    }

    /* copy the xml part to tmp_buffer */
    sprintf(tmp_buffer, "%s\n", place);

    if ((xml_doc = xmlParseMemory(tmp_buffer, strlen(tmp_buffer))) == NULL)    
    { 
        HIP_DEBUG("Libxml2 encountered error while parsing content.\n");
        ret = -1;
        goto out_err;
    }

    xml_node = xmlDocGetRootElement(xml_doc);
    if (xml_node->children) /* params or fault */
    {
        xml_node = xml_node->children;
        /* check if error from DHT 
           <fault><value><struct><member><name>faultString</name><value>java...
        */
        if (!strcmp((char *)xml_node->name, "fault"))
        {
             if (xml_node->children)
                  xml_node = xml_node->children; /* value */
             if (xml_node->children) 
                  xml_node = xml_node->children; /* struct */
             if (xml_node->children)
                  xml_node = xml_node->children; /* member */
             if (xml_node->children)
                  xml_node = xml_node->children; /* name */
             if (xml_node->next)
             {
                  xml_node_value = xml_node->next; /* value */
                  xml_data = xmlNodeGetContent(xml_node_value);
                  /* strcpy((char *)out_value, (char *)xml_data); */
                  xmlFree(xml_data);
                  HIP_DEBUG("Error from the openDHT: %s\n", xml_data);
                  ret = -1;
                  goto out_err;
             }
        }
    }

    if (xml_node->children) /* param */
        xml_node = xml_node->children;
    if (!xml_node)
    {
        HIP_DEBUG("Parser error: unknown XML format.\n");
        ret = -1;
        goto out_err;
    }
    xml_node_value = NULL;
    if (!strcmp((char *)xml_node->name, "param") &&
        xml_node->children &&
        !strcmp((char *)xml_node->children->name, "value"))
        xml_node_value = xml_node->children->children;
    if(!xml_node_value)
    {
        HIP_DEBUG("Parser error: element has no content.\n");
        ret = -1;
        goto out_err;
    }    

    /* If there is a string "<int>" in the response, 
       then there is only status code */
    place = NULL;
    if ((place = strstr(tmp_buffer, "<int>")) != NULL)
    {
        /* retrieve status code only */
        xml_data = xmlNodeGetContent(xml_node_value);
        if (strcmp((char *)xml_node_value->name, "int")==0)
        {
            sscanf((const char *)xml_data, "%d", &ret);
            xmlFree(xml_data);
            if (ret == 0) /* put success */
                goto out_err;
            if (ret == 1);
            {
                HIP_DEBUG("OpenDHT error: over capacity.\n");
                ret = -1;
                goto out_err;
            }
            if (ret == 2)
            {
                HIP_DEBUG("OpenDHT error: try again.\n");
                ret = -1;
                goto out_err;
            }
        }
        else
        {
            HIP_DEBUG("Parser error: did not find status code.\n");
            ret = -1;
            goto out_err;
        }
    }
    else
    {
         /* retrieve the first value in array */
         if (!strcmp((char *)xml_node_value->name, "array") &&
            xml_node_value->children &&
            !strcmp((char *)xml_node_value->children->name, "data"))
            xml_node = xml_node_value->children->children;

         if (!strcmp((char *)xml_node->name, "value") &&
            xml_node->children &&
            !strcmp((char *)xml_node->children->name, "array"))
            xml_node = xml_node->children->children; /* inner data element */

         /* check if there was no corresponging data for the key (<data> has no children) */
         if (!xml_node->children && !strcmp((char *)xml_node->name, "data")) 
         {
            HIP_DEBUG("Key was not found from the DHT\n");
            out_value[0] = '\0';
            ret = 0;
            goto out_err;
         }   

         for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
           if (!strcmp((char *)xml_node->children->name, "base64"))
             {         
               xml_node_value = xml_node->children->children;

               xml_data = xmlNodeGetContent(xml_node_value);

               _HIP_DEBUG("XML_DATA %s len = %d\n", (char *)xml_data, strlen((char *)xml_data));

               evpret = EVP_DecodeBlock((unsigned char *)out_value, xml_data, 
                                        strlen((char *)xml_data));
               _HIP_HEXDUMP("LOC from DHT", out_value, evpret);
               out_value[evpret] = '\0';
               memcpy(answers.addrs, out_value, strlen(out_value));
               _HIP_DEBUG("Values under the key in DHT: %s\n",out_value);
               answers.count = 1;

               if (evpret > 1) 
                   hip_print_locator_addresses((struct hip_common *)out_value);
               ret = 0;
             } 
           else 
             {
               HIP_DEBUG("Parser error: couldn't parse response value.\n");
               ret = -1;
               goto out_err;
             }
         }
    }

 out_err:
    if (xml_doc != NULL) 
        xmlFreeDoc(xml_doc);
    if (answers.count > 0)
      xmlFree(xml_data);
    return(ret);
}

/* build_packet_get and build_packet_put helper function*/
xmlNodePtr xml_new_param(xmlNodePtr node_parent, char *type, char *value)
{
    xmlNodePtr xml_node_param;
    xmlNodePtr xml_node_value;
    xml_node_param = xmlNewChild(node_parent, NULL, BAD_CAST "param", NULL);
    xml_node_value = xmlNewChild(xml_node_param, NULL, BAD_CAST "value", NULL);
    return(xmlNewChild(xml_node_value, NULL, BAD_CAST type, BAD_CAST value)); 
}

/** 
 * base64_encode - Encodes given content to Base64
 * @param buf Pointer to contents to be encoded
 * @param len How long is the first parameter in bytes
 *
 * @return Returns a pointer to encoded content or -1 on error
 */
unsigned char * base64_encode(unsigned char * buf, unsigned int len)
{
    unsigned char * ret;
    unsigned int b64_len;

    b64_len = (((len + 2) / 3) * 4) + 1;
    ret = (unsigned char *)malloc(b64_len);
    if (ret == NULL) goto out_err;
    EVP_EncodeBlock(ret, buf, len);
    return ret;
 out_err:
    if (ret) free(ret);
    return(-1);
}

/** 
 * base64_decode - Dencodes given base64 content
 * @param buf Pointer to contents to be decoded
 * @param len How long is the first parameter in bytes
 *
 * @return Returns a pointer to decoded content or -1 on error
 */
unsigned char * base64_decode(unsigned char * bbuf, unsigned int *len)
{
    unsigned char * ret = NULL;
    unsigned int bin_len;
  
    bin_len = (((strlen((char *)bbuf) + 3) / 4) * 3);
    ret = (unsigned char *)malloc(bin_len);
    if (ret == NULL) goto out_err;   
    *len = EVP_DecodeBlock(ret, bbuf, strlen((char *)bbuf));
    return ret;
 out_err:
    if(ret) free(ret);
    return(-1);
}

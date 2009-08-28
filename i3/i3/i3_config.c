#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <ctype.h>
#include "i3_debug.h"
#include "i3_config.h"

static xmlDocPtr i3_config_doc;
char cfilename[200]="";

void read_parameters(const char* filename)
{
  char version[200];
  xmlNodePtr root;
  strcpy(cfilename,filename);

  i3_config_doc = xmlParseFile(filename);

  if (i3_config_doc == NULL )
  {
    I3_PRINT_INFO1(
	    I3_INFO_LEVEL_FATAL_ERROR,
	    "%s: XML configuration in not parsed successfully"
	    "check whether all tags are terminated etc). \n",
	    filename
	);
    exit(-1);
  }

  root = xmlDocGetRootElement(i3_config_doc);

  if (root == NULL)
  {
    I3_PRINT_INFO1(
	    I3_INFO_LEVEL_FATAL_ERROR,
	    "%s: Empty XML configuration file\n",
	    filename
	    );
    exit(-1);
  }

  if (xmlStrcmp(root->name, (const xmlChar *) "I3ConfigFile")) {
    I3_PRINT_INFO1(
	    I3_INFO_LEVEL_FATAL_ERROR,
	    "%s: Document of the wrong type, root node != I3ConfigFile\n",
	    filename
	);
    exit(-1);
  }

  read_string_attribute("//I3ConfigFile", "version",version,1);

  if ( strcmp(version,VER_CONFIG))
  {
    I3_PRINT_INFO3(
	    I3_INFO_LEVEL_FATAL_ERROR,
	    "%s: Incorrect version of configuration file. "
	    "This code uses version %s configuration file, your configuration "
	    "file has version %s, please update.\n",
	    filename,VER_CONFIG,version
	);
    exit(-1);
  }

}

void release_params()
{
  xmlFreeDoc(i3_config_doc);
  //xmlCleanupParser();
}

xmlXPathObjectPtr getnodeset(xmlChar *xpath)
{
  xmlXPathContextPtr context;
  xmlXPathObjectPtr result;

  context = xmlXPathNewContext(i3_config_doc);
  result = xmlXPathEvalExpression(xpath, context);
  
  if(xmlXPathNodeSetIsEmpty(result->nodesetval)) {
    xmlXPathFreeObject(result);
    xmlXPathFreeContext(context);
    return NULL;
  }

  xmlXPathFreeContext(context);
  return result;
}

void strip_ws(char* str)
{
  char tstr[200];
  int lindex = 0;
  int rindex = 0;

  while ( str[lindex] != 0 && isspace(str[lindex]))
    lindex++;

  rindex = ((int) strlen(str)) -1;
  while ( rindex >= 0 && isspace(str[rindex]) )
    rindex--;

  if ( lindex == strlen(str))
  {
    strcpy(str,"");
    return;
  }

  str[rindex+1] = 0;
  strcpy(tstr,str+lindex);
  strcpy(str,tstr);
}


void read_string_attribute(char* elementPath, char *attribName, char* str, int required)
{
  xmlChar *xpath;
  xmlXPathObjectPtr result;
  xmlNodeSetPtr nodeset;
  xmlChar* resultstr;
  char tmpBuf[1000];
  sprintf(tmpBuf, "%s[@%s]", elementPath, attribName);

  xpath = xmlCharStrdup(tmpBuf);
  result = getnodeset(xpath);
  xmlFree(xpath);

  required=1;

  if ( required && result == NULL )
  {
    printf("%s: %s required in configuration file\n",cfilename, elementPath);
    exit(-1);
  }

  if ( result == NULL )
    return;
  nodeset = result->nodesetval;

  if ( nodeset->nodeNr >= 2 )
  {
    I3_PRINT_INFO2(
	    I3_INFO_LEVEL_FATAL_ERROR,
	    "%s: %s should appear atmost once in configuration file\n",
	    cfilename, elementPath
	);
    exit(-1);
  }

  resultstr = xmlGetProp(nodeset->nodeTab[0], (xmlChar*)attribName);
  strcpy(str,(char*)resultstr);
  strip_ws(str);
  xmlFree(resultstr);
  xmlXPathFreeObject(result);
}

void read_string_par(char* path,char* str,int required)
{
  xmlNodeSetPtr nodeset;
  xmlChar* resultstr;
  xmlChar *xpath = xmlCharStrdup(path);
  xmlXPathObjectPtr result = getnodeset(xpath);
  xmlFree(xpath);

  required=1;

  if ( required && result == NULL )
  {
    printf("%s: %s required in configuration file\n",cfilename,path);
    exit(-1);
  }

  if ( result == NULL )
    return;

  nodeset = result->nodesetval;

  if ( nodeset->nodeNr >= 2 )
  {
    I3_PRINT_INFO2(
	    I3_INFO_LEVEL_FATAL_ERROR,
	    "%s: %s should appear atmost once in configuration file\n",
	    cfilename,path
	);
    exit(-1);
  }

  resultstr = xmlNodeListGetString(i3_config_doc, nodeset->nodeTab[0]->xmlChildrenNode, 1);
  strcpy(str,(char*)resultstr);
  strip_ws(str);
  xmlFree(resultstr);
  xmlXPathFreeObject(result);
}

void read_ushort_attribute(char* elementPath, char *attribName,unsigned short* us,int required)
{
  char str[200];
  read_string_attribute(elementPath, attribName, str,required);
  *us = (unsigned short) atoi(str);
}

void read_ushort_par(char* path,unsigned short* us,int required)
{
  char str[200];
  read_string_par(path,str,required);
  *us = (unsigned short) atoi(str);
}

char **read_i3server_list(int* num)
{
  xmlNodeSetPtr nodeset;
  char** toret;
  int i;
  xmlChar *xpath = xmlCharStrdup("//I3Server");
  xmlXPathObjectPtr result = getnodeset(xpath);
  xmlFree(xpath);

  if ( result == NULL )
  {
    *num=0;
    return NULL;
  }

  nodeset = result->nodesetval;
  toret = (char**) malloc(nodeset->nodeNr * sizeof(char*));
  *num=nodeset->nodeNr;

  for(i=0;i<nodeset->nodeNr;i++)
  {
    xmlChar* ipStr = xmlGetProp(nodeset->nodeTab[i], (xmlChar*) "IPAddress");
    xmlChar* portStr = xmlGetProp(nodeset->nodeTab[i], (xmlChar*) "PortNum");
    xmlChar* i3IdStr = xmlGetProp(nodeset->nodeTab[i], (xmlChar*) "I3Id");

    toret[i] = (char *) malloc(1000);	/* TODO */
    sprintf(toret[i], "%s %s %s\n", (char *) ipStr, (char *) portStr, (char *) i3IdStr);

    strip_ws(toret[i]);
    xmlFree(ipStr);
    xmlFree(portStr);
    xmlFree(i3IdStr);
  }

  xmlXPathFreeObject (result);
  return toret;
}

char **read_strings_par(char* path,int* num)
{
  xmlNodeSetPtr nodeset;
  char** toret;
  int i;
  xmlChar *xpath = xmlCharStrdup(path);
  xmlXPathObjectPtr result = getnodeset(xpath);
  xmlFree(xpath);

  if ( result == NULL )
  {
    *num=0;
    return NULL;
  }

  nodeset = result->nodesetval;
  toret = (char**) malloc(nodeset->nodeNr * sizeof(char*));
  *num=nodeset->nodeNr;

  for(i=0;i<nodeset->nodeNr;i++)
  {
    xmlChar* resultstr = xmlNodeListGetString(i3_config_doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
    toret[i] = strdup((char*)resultstr);
    strip_ws(toret[i]);
    xmlFree(resultstr);
  }

  xmlXPathFreeObject (result);
  return toret;
}

int test_main()
{
  char fake[200];
  char** fakes;
  int num;
  int i;

  read_parameters("i3-proxy.xml");
  read_string_par("/parameters/proxy/server_proxy_trigger/server_proxy[@name='sp1']",fake,1);
  printf("%s\n",fake);

  fakes = read_strings_par("/parameters/proxy/public_triggers/trigger",&num);
  printf("Num: %d\n",num);
  for(i=0;i<num;i++)
    printf("%s\n",fakes[i]);

  return 0;
}

/** @file
 * A header file for configfilereader.c
 *
 * This is a general purpose configurationfilereader. The configurationfile
 * consists of stanzas of the following form: 
 * <pre>
 * parametername = "value1", "value2", "value3", ..., "valueN"
 * </pre>
 * where there can be as many values as needed per line with the exception that
 * the total line length may not exceed @c HIP_RELAY_MAX_LINE_LEN characters.
 * <code>parametername</code> is at most @c HIP_RELAY_MAX_PAR_LEN characters
 * long and <code>value</code> is at most @c HIP_RELAY_MAX_VAL_LEN characters
 * long. A value itself may not contain a @c HIP_RELAY_VAL_SEP character.
 *
 * There is no need to use any other function from this file than
 * hip_cf_get_line_data().
 * 
 * Usage:
 * <ol>
 * <li>Declare integers <code>lineerr</code> and <code>parseerr</code> and set
 * them zero</li>
 * <li>Declare a char array for the parameter's name
 * <code>parameter[HIP_RELAY_MAX_PAR_LEN + 1]</code></li>
 * <li>Declare a linked list <code>hip_configvaluelist_t values</code> for values</li>
 * <li>Open the configfile using <code>fopen()</code></li>
 * <li>Go through the configuration file using hip_cf_get_line_data()
 * inside a <code>do{ }while()</code> -loop:
 * <pre>
 * do {
 *     parseerr = 0;
 *     memset(parameter, '\0', sizeof(parameter));
 *     hip_cvl_init(&values);
 *     lineerr = hip_cf_get_line_data(fp, parameter, &values, &parseerr);
 * 				
 *     if(parseerr == 0){
 *        
 *       ... parameter has now the parameter name ...
 * 
 *        hip_configfilevalue_t *current = NULL;
 * 	  while((current = hip_cvl_get_next(&values, current)) != NULL) {
 * 
 *           ... do stuff with the current value ...
 *	  
 *        }
 *    }
 *    hip_cvl_uninit(&values);
 * } while(lineerr != EOF);
 * </pre>
 * </li>
 * <li>Close the configfile using <code>close()</code></li>
 * </ol>
 * 
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    14.02.2008
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef CONFIGFILEREADER_H
#define CONFIGFILEREADER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "misc.h" /* For debuging macros. */

/** Maximum number of characters per line in HIP relay config file. */
#define HIP_RELAY_MAX_LINE_LEN 2048
/** Maximum number of characters in a HIP relay config file parameter. */
#define HIP_RELAY_MAX_PAR_LEN  32
/** Maximum number of characters in a HIP relay config file value. */
#define HIP_RELAY_MAX_VAL_LEN  64
/** HIP relay config file parameter separator as a char. */
#define HIP_RELAY_PAR_SEP      '='
/** HIP relay config file value separator as a char. */
#define HIP_RELAY_VAL_SEP      ','
/** HIP relay config file value container as a char. */
#define HIP_RELAY_VAL_CON      '"'
/** HIP relay config file commented line mark as a char. */
#define HIP_RELAY_COMMENT      '#'
/** Error value for generic config file error. (Everything but -EIO and EOF are
    acceptable here.) */
#define HIP_EINPUT             -EIO
/** Error value for generic config file error. (Everything but -EIO and EOF are
    acceptable here.) */
#define HIP_EVAL               -10
/** Error value for too long config file line. (Everything but -EIO and EOF are
    acceptable here.) */
#define HIP_ELONG              -11

/** Linked list node. */
typedef struct hip_cvl_node{
	char data[HIP_RELAY_MAX_VAL_LEN + 1]; /**< Node data. */
	struct hip_cvl_node *next; /**< A pointer to next item. */ 
}hip_configfilevalue_t;

/** Linked list. */
typedef struct{
	hip_configfilevalue_t *head; /**< A pointer to the first item of the list. */
}hip_configvaluelist_t;

/**
 * Gets parameter and values from a config file line. This is the main function
 * of the configfilereader. This is the only function the user needs to use from
 * this file to retrieve data from a configuration file. To go through all the
 * lines in the file, the user should call this function inside a
 * <code>do{ }while(lineerr != EOF)</code> loop where <code>lineerr</code> is
 * the return value of this function. If parseerr is zero, the line was parsed
 * successfully and @c parameter and @c values have content.
 *
 * @param  fp        a pointer to the source file.
 * @param  parameter a target buffer where to put the parameter.
 * @param  values    a target linked list where the values are stored.
 * @param  parseerr  zero on success, HIP_EINPUT if an illegal control character
 *                   was encountered, HIP_ELONG if maximum number of characters
 *                   per line (@c HIP_RELAY_MAX_LINE_LEN) was exceed.              
 * @return           EOF if the end of file was reached or if @c fp,
 *                   @c parameter, @c values or @c parseerr is NULL, otherwise
 *                   the number of succesfully read characters.
 */ 
int hip_cf_get_line_data(FILE *fp, char *parameter, hip_configvaluelist_t *values,
			 int *parseerr);

/**
 * Reads one line from a file. Reads one line from parameter @c fp file into
 * target buffer @c buf. One input line is terminated to '\n' or EOF. The
 * target buffer must be preallocated and must be at least @c
 * HIP_RELAY_MAX_LINE_LEN + 1 bytes long. The target buffer @c buf is not
 * terminated with '\0' thus it should be initialized with '\0' before calling
 * this function. The return value is the number of characters read or EOF if
 * the line ends the file. The return value is therefore always EOF, zero or
 * positive. The return values does <b>not</b> indicate whether there was an
 * error or not. One should use the value of @c parseerr to check if the line was
 * read succesfully.
 * 
 * @param  fp       a pointer to the source file.
 * @param  buf      a target buffer where to put the line.
 * @param  parseerr zero on success, HIP_EINPUT if an illegal control character
 *                  was encountered, HIP_ELONG if maximum number of characters
 *                  per line (@c HIP_RELAY_MAX_LINE_LEN) was exceed.              
 * @return          EOF if the end of file was reached or if @c fp or @c buf is
 *                  NULL, otherwise the number of succesfully read characters.
 * @note            This function is not meant to be called outside this file.
 *                  Use hip_cf_get_line_data() to get data from lines.
 */ 
int hip_cf_readline(FILE *fp, char *buf, int *parseerr);

/**
 * Checks whether the parameter line is commented. A commented line has
 * @c HIP_RELAY_COMMENT character as the first non-blank character on the line.
 *
 * @param  line the line to check. 
 * @return 1 if the line is a comment, zero otherwise.
 */ 
int hip_cf_is_comment(char *line);

/**
 * Parses parameter from a line. Parses parameter from the parameter @c line and
 * stores the value into @c parameter. The target buffer @c parameter is not
 * terminated with '\0' thus it should be initialized with '\0' before calling
 * this function. The source buffer must terminate to '\0'.
 * 
 * Parameter is the string on the lefthandside of @c HIP_RELAY_PAR_SEP. The
 * parameter may <b>NOT</b> contain spaces and it can be at most
 * @c HIP_RELAY_MAX_PAR_LEN characters long.
 *
 * @param  line      the line from where to read the parameter.
 * @param  parameter a target buffer where the parameter is stored.
 * @return           zero on success, HIP_EVAL otherwise.
 * @note             This function is not meant to be called outside this file.
 *                   Use hip_cf_get_line_data() to get data from lines.
 */ 
int hip_cf_parse_par(char *line, char *parameter);

/**
 * Parses values from a line. Parses values from the parameter @c line and
 * stores the values into the linked list of @c values. The target buffer @c
 * values must be initialized with hip_cvl_init() before calling this function.
 * 
 * Values are in the string on the righthandside of @c HIP_RELAY_PAR_SEP.
 * Values may contain spaces and they must be at most @c HIP_RELAY_MAX_VAL_LEN
 * characters long each. The parameters must be separated with
 * @c HIP_RELAY_VAL_SEP characters from each other and each parameter must be
 * limited with @c HIP_RELAY_VAL_CON characters. The actual value cannot contain
 * @c HIP_RELAY_VAL_SEP character.
 *
 * @param  line   the line from where to read the parameter.
 * @param  values a target linked list where the values are stored.
 * @return        zero on success, HIP_EVAL otherwise.
 * @note          This function is not meant to be called outside this file. Use
 *                hip_cf_get_line_data() to get data from lines.
 */
int hip_cf_parse_val(char *line, hip_configvaluelist_t *values);

/**
 * Initializes a linked list. Sets the parameter @c linkedlist head to NULL if
 * the list itself is not NULL.
 *
 * @param linkedlist the list to init.
 */ 
void hip_cvl_init(hip_configvaluelist_t *linkedlist);

/**
 * Uninitializes a linked list. Removes each element from the parameter
 * @c linkedlist and frees the memory allocated to the elements. The parameter
 * @c linkedlist is not itself freed.
 *
 * @param linkedlist the list to uninitialize.  
 */ 
void hip_cvl_uninit(hip_configvaluelist_t *linkedlist);

/**
 * Adds a new element to a linked list. Adds a new element to the end of the
 * parameter @c linkedlist.
 *
 * @param  linkedlist the list where to add the new element.
 * @param  data       the data that is stored to the new element. 
 * @return            zero on success, HIP_EVAL if @c linkedlist or @c data is
 *                    NULL or if there was an error when allocating memory to
 *                    the new element.
 */ 
int hip_cvl_add(hip_configvaluelist_t *linkedlist, const void *data);

/**
 * Gets the next element from a linked list. Gets the next element from 
 * parameter @c linkedlist or NULL if the list end has been reached or if
 * @c linkedlist itself is NULL. If you need to get the first element of the
 * list, call this function with @c current set as NULL.
 *
 * @param  linkedlist the linked list from where to retrieve the element.  
 * @param  current    the current element or NULL if the first item from the
 *                    list is to be retrieved.
 * @return            the next element or NULL if the list end has been reached
 *                    or @c linkedlist is NULL.
 */ 
hip_configfilevalue_t *hip_cvl_get_next(hip_configvaluelist_t *linkedlist,
				       hip_configfilevalue_t *current);

/**
 * Prints node data to stdout. This function is intended for debug use.
 *
 * @param the node whose contents are to be printed.
 */ 
void print_node(hip_configfilevalue_t *node);

#endif /* CONFIGFILEREADER_H */

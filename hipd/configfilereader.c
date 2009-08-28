/** @file
 * This file defines an all-round configurationfilereader.
 * 
 * @author  Lauri Silvennoinen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see     configfilereader.h for usage instructions.
 */
#include "configfilereader.h"

int hip_cf_get_line_data(FILE *fp, char *parameter, hip_configvaluelist_t *values,
			 int *parseerr)
{
	
	if(fp == NULL || parameter == NULL || values == NULL || parseerr == NULL)
		return EOF;
	
	int lineerr = 0;
	char line[HIP_RELAY_MAX_LINE_LEN + 1];
		
	memset(line, '\0', sizeof(line));
	
	lineerr = hip_cf_readline(fp, line, parseerr);
	
	/* If there was no error on the line, let's try to parse the data. */
	if(*parseerr == 0) {
		if(hip_cf_is_comment(line)) {
			*parseerr = HIP_EVAL;
		} else {
			*parseerr = hip_cf_parse_par(line, parameter);
			if(*parseerr == 0) {
				*parseerr = hip_cf_parse_val(line, values);
			}
		}
	}
	
	return lineerr;
}

int hip_cf_readline(FILE *fp, char *buf, int *parseerr)
{
	int ch = 0, i = 0;
	*parseerr = 0;

	/* Read characters from the file until EOF or a control character is
	   confronted, or a maximum line length is exceed. */
	while((ch = fgetc(fp)) != EOF && iscntrl(ch) == 0 &&
	      i < HIP_RELAY_MAX_LINE_LEN) {
		buf[i] = ch;
		i++;
	}
	
	if(ch == EOF) {
		return EOF;
	} else if(iscntrl(ch) != 0 && ch != '\n') {
		/*printf("Error on reading input. Control character "\
		  "encountered.\n");*/
		*parseerr = HIP_EINPUT; 
		/* If an illegal control character is confronted, we omit the
		   rest of the line. */
		while((ch = fgetc(fp)) != EOF && ch != '\n') {}
		if(ch == EOF)
			return EOF;
	} else if (i >= HIP_RELAY_MAX_LINE_LEN) {
		/*printf("Error on reading input. Maximum line length (%d "\
		  "characters) exceeded.\n", HIP_RELAY_MAX_LINE_LEN);*/
		*parseerr = HIP_ELONG;
		/* If maximum line length is exceeded, we omit the rest of the
		   line. */
		while((ch = fgetc(fp)) != EOF && ch != '\n') {}
		if(ch == EOF)
			return EOF;
	} 
	return i;
}

int hip_cf_is_comment(char *line)
{
	int i = 0;

	/* Clean leading white space. */
	while(isspace(line[i]) && i <  HIP_RELAY_MAX_LINE_LEN) { i++; }

	/* The firts non-blank character is a comment mark. */
	if(line[i] == HIP_RELAY_COMMENT)
		return 1;

	return 0;
}

int hip_cf_parse_par(char *line, char *parameter)
{	
	int i = 0, j = 0, k = 0, l = 0;
	
	/* Search for the parameter separator */
	while(line[i] != HIP_RELAY_PAR_SEP && line[i] != '\0' &&
	      i < HIP_RELAY_MAX_LINE_LEN) { i++; }

	/* If found, parse parameter. */
	if(line[i] == HIP_RELAY_PAR_SEP) {
		
		/* Clean leading white space. */
		while(isspace(line[j]) && j < i) { j++; }
		
		l = j;

		/* Copy characters until space is encountered. */
		while(!isspace(line[j]) && j < i &&
		      (j - l) <= (HIP_RELAY_MAX_PAR_LEN + 1)) {
			parameter[k] = line[j];
			j++;
			k++;
		}

		if(j - l > HIP_RELAY_MAX_PAR_LEN) {
			/* Parameter maximum length exceeded. */
			return HIP_EVAL;
		}
		
		/* Clean the trailing white space. */
		while(isspace(line[j]) && j <= i) { j++; }
		
		/* Check if there was trash between the parameter and the
		   parameter separator. */
		if(j != i) {
			return HIP_EVAL;
		}
		
		/* Parameter read succesfully. */
		return 0;
	}

	/* No parameter separator found. */
	return HIP_EVAL;
}

int hip_cf_parse_val(char *line, hip_configvaluelist_t *values)
{
	int i = 0, j = 0, k = 0, l = 0, end = 0;
	char value[HIP_RELAY_MAX_VAL_LEN + 1];

	/* Search for the line end. */
	while(line[end] != '\0' && end < HIP_RELAY_MAX_LINE_LEN) { end++; }
	
	/* Check that the line ends with HIP_RELAY_VAL_CON. */
	i = end -1;
	if(i < 0) { i = 0; }
	while(isspace(line[i]) && i >= 0) { i--; }
	
	if(line[i] != HIP_RELAY_VAL_CON) { return HIP_EVAL; }

	i = 0;

	/* Search for the parameter separator. */
	while(line[i] != HIP_RELAY_PAR_SEP && i < end) { i++; }
	
	/* If found, we can start parsing the values. */
	if(line[i] == HIP_RELAY_PAR_SEP) {
		/* Move to the next character after parameter separator. */
		i++;
		j = i;

		/* Read the input until the end is reached. */
		do{
			/* Search for the value separator or the end of line */
			while(line[j] != HIP_RELAY_VAL_SEP && j < end) { j++; }

			/* Search for the leading value container mark. */
			while(line[i] != HIP_RELAY_VAL_CON && i < j) {
				/* Check for trash before the leading container
				   mark or if there is no more room for the
				   actual value. */
				if(!isspace(line[i]) || (j - i) < 2){
					return HIP_EVAL;
				}
				i++;
			}
			
			/* A special case of illegal input where there are
			   multiple HIP_RELAY_VAL_SEP characters between the
			   values and no space between these HIP_RELAY_VAL_SEP
			   characters. */
			if(line[i] == HIP_RELAY_VAL_SEP &&
			   line[j] == HIP_RELAY_VAL_SEP) {
				return HIP_EVAL;
			}
			
			/* If found, we now have the value including the value
			   container marks between i (inclusive) and j
			   (exclusive). I.e. we have:
			   "value"   , 
			   ^         ^
			   i         j (or alternatively j can be at "end"). */

			if(line[i] == HIP_RELAY_VAL_CON &&
			   (line[j] == HIP_RELAY_VAL_SEP || j == end)) {
				
				i++;
				memset(value, '\0', sizeof(value));
				k = i;
				l = 0;
			
				/* Search for the trailing value container. */
				while(line[k] != HIP_RELAY_VAL_CON && k < j) {
					value[l] = line[k];
					k++; 
					l++;
					if(l >= HIP_RELAY_MAX_VAL_LEN){
						/* Too long value. */
						return HIP_EVAL;
					}
				}
				
				/* Check for trash after the trailing container
				   mark. */
				l = k;
				l++;
				while(l < j) {
					if(!isspace(line[l])) {
						return HIP_EVAL;
					}
					l++; 
				}
				
				/* If no trash is found and the trailing
				   container mark is found, we have succesfully
				   read one value. */
				if(line[k] == HIP_RELAY_VAL_CON) {
					hip_cvl_add(values, value);
				} else {
					/* Closing value container was not
					   found. */
					return HIP_EVAL;
				}
			}
			/* We have now read one value between the value
			   separators (or parameter and value separator), let's
			   move to next character. */
			j++;
			i = j;
		} while(j < end);
		/* All values were read succesfully. */
		return 0;
	}
	
	/* We didn't find the parameter separator at all. */
	return HIP_EVAL;
}

void hip_cvl_init(hip_configvaluelist_t *linkedlist)
{
	if(linkedlist != NULL)
		linkedlist->head = NULL;
}

void hip_cvl_uninit(hip_configvaluelist_t *linkedlist)
{
	if(linkedlist == NULL || linkedlist->head == NULL)
		return;

	hip_configfilevalue_t *pointer = NULL;
	pointer = linkedlist->head;

	/* Free the item currently at list head and move the next item to list
	   head. Continue this until the item at list head is NULL. */
	while(linkedlist->head != NULL) {
		pointer = linkedlist->head->next;
		free(linkedlist->head);
		linkedlist->head = pointer;
	}
}

int hip_cvl_add(hip_configvaluelist_t *linkedlist, const void *data)
{
	if (linkedlist == NULL || data == NULL)
		return HIP_EVAL;

	hip_configfilevalue_t *newnode =
		(hip_configfilevalue_t*) malloc(sizeof(hip_configfilevalue_t));
	
	if(newnode == NULL) {
		HIP_ERROR("Error on allocating memory for a linked list node.\n");
		return HIP_EVAL;
	}
	
	memcpy(newnode->data, data, sizeof(newnode->data));
	newnode->next = NULL;

	/* Item to add is the first item of the list. */
	if(linkedlist->head == NULL) {
		linkedlist->head = newnode;
		return 0;
	} else {
		hip_configfilevalue_t *pointer = linkedlist->head;
		
		while(pointer->next != NULL) {
			pointer = pointer->next;
		}

		pointer->next = newnode;
		
		return 0;
	}

	return 0;
}

hip_configfilevalue_t *hip_cvl_get_next(hip_configvaluelist_t *linkedlist,
					hip_configfilevalue_t *current)
{
	if (linkedlist == NULL)
		return NULL;
	if(current == NULL)
		return linkedlist->head;
	
	return current->next;
}

void print_node(hip_configfilevalue_t *node)
{
	if(node == NULL){
		HIP_INFO("Node NULL.\n");
		return;
	}
	HIP_INFO(" '%s'\n", (node->data == NULL) ? "NULL" : node->data);
}

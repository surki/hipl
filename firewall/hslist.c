#include "hslist.h"

SList * alloc_slist (void) {
	SList * list = (SList *) malloc (sizeof (SList));
	list->next = NULL;	
	list->data = NULL;
	return list;
}

void free_slist (SList * list) {
	SList * tmp_list = NULL;

	while (list)
	{
		tmp_list = list;
		free (list->data);
		list = list->next;
		free(tmp_list);
	}
}

SList * append_to_slist (SList * list,
					   void * data) {

	SList *new_list;
  	SList *last;

	new_list = alloc_slist();
  	new_list->data = data;	
  	new_list->next = NULL;

  	if (list) {
      last = slist_last(list);
      last->next = new_list;
      return list;
    } else { 
    	return new_list;
  	}
}

SList * slist_last (SList * list) {
	if (list) {
		while (list->next) {
			list = list->next;
		}
	}
  	return list;
}

SList* remove_link_slist (SList *list,
	   			 		  SList *link) {
	SList *tmp;
	SList *prev;

	prev = NULL;
	tmp = list;

	while (tmp) {
		if (tmp == link) {
			if (prev) { 
				prev->next = tmp->next;
			}
			
			if (list == tmp) {
	    		list = list->next;
			}

			tmp->next = NULL;
			break;
		}

		prev = tmp;
		tmp = tmp->next;
	}

	return list;
}


SList *remove_from_slist (SList *  list,
				   const void  *  data) {
	SList *tmp, *prev = NULL;

	tmp = list;
	while (tmp) {
		if (tmp->data == data) {
			if (prev) {
	    		prev->next = tmp->next;
			} else {
	    		list = tmp->next;
			}
	  		free_slist (tmp);
	  		break;
		}
      	prev = tmp;
      	tmp = prev->next;
    }
  	return list;
}

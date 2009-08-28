/** @file
 * This file defines a linked list for storing pointers.
 * 
 * @author  Lauri Silvennoinen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see     linkedlist.h for usage instructions.
 */
#include "linkedlist.h"

void hip_ll_init(hip_ll_t *linkedlist)
{
	if(linkedlist != NULL) {
		linkedlist->head = NULL;
		linkedlist->element_count = 0;
	}
}

void hip_ll_uninit(hip_ll_t *linkedlist, free_elem_fn_t free_element)
{
	if(linkedlist == NULL || linkedlist->head == NULL)
		return;

	hip_ll_node_t *pointer = NULL;
	
	/* Free the node currently at list head and move the next item to list
	   head. Continue this until the item at list head is NULL. If
	   free_element() is non-NULL we also free the memory allocated for the
	   actual element. */
	if(free_element != NULL) {
		while(linkedlist->head != NULL) {
			pointer = linkedlist->head->next;
			free_element(linkedlist->head->ptr);
			free(linkedlist->head);
			linkedlist->head = pointer;
		}
	} else {
		while(linkedlist->head != NULL) {
			pointer = linkedlist->head->next;
			free(linkedlist->head);
			linkedlist->head = pointer;
		}
	}

	linkedlist->element_count = 0;
}

unsigned int hip_ll_get_size(const hip_ll_t *linkedlist)
{
	if(linkedlist == NULL)
		return 0;
	
	return linkedlist->element_count;
}

int hip_ll_add(hip_ll_t *linkedlist, const unsigned int index, void *ptr)
{
	if (linkedlist == NULL || ptr == NULL)
		return -1;
	
	hip_ll_node_t *newnode = NULL, *pointer = NULL;
	unsigned int current_index = 0;
	
	if ((newnode =
	     (hip_ll_node_t*) malloc(sizeof(hip_ll_node_t))) == NULL) {
		HIP_ERROR("Error on allocating memory for a linked list "\
			  "node.\n");
		return -1;
	}

	newnode->ptr = ptr;
	pointer = linkedlist->head;
		
	/* Item to add is the first item of the list or it is to be added as the
	   first one. */
	if(pointer == NULL || index == 0) {
		newnode->next = pointer;
		linkedlist->head = newnode;
		linkedlist->element_count++;
	} 
	/* There exist at least one element in the list and the new element is
	   not to be added as the first one. */
	else {
		hip_ll_node_t *previous = pointer;
		
		/* Loop until "pointer" is at the last item. */
		while(pointer->next != NULL) {

			previous = pointer;
			pointer = pointer->next;
			current_index++;
			
			/* We have reached the target index and the index is not
			   the index of the last item in the list. */
			if(current_index == index) {
				
				newnode->next = pointer;
				previous->next = newnode;
				linkedlist->element_count++;
				return 0;
			}
		}
		/* The node is to be added as the last item of the list. */
		newnode->next = NULL;
		pointer->next = newnode;
		linkedlist->element_count++;
	}

	return 0;
}

void *hip_ll_del(hip_ll_t *linkedlist, const unsigned int index, 
		 free_elem_fn_t free_element)
{
	if(linkedlist == NULL || linkedlist->head == NULL) {
		return NULL;
	} else if(index > (linkedlist->element_count -1)) { 
		return NULL;
	}
	
	hip_ll_node_t *pointer = NULL, *previous = NULL;
	void *ptr = NULL;
	unsigned int current_index = 0;
	
	if(index == 0) {
		ptr = linkedlist->head->ptr;
		pointer = linkedlist->head->next;
		if(free_element != NULL) {
			free_element(ptr);
			ptr = NULL;
		}
		free(linkedlist->head);
		linkedlist->head = pointer;
		linkedlist->element_count--;
		return ptr;
	}
	
	pointer = previous = linkedlist->head;
	
	while(pointer->next != NULL) {
		previous = pointer;
		pointer = pointer->next;
		current_index++;
		
		/* We have reached the target index. */
		if(current_index == index) {
			if(pointer == NULL) {
				previous->next = NULL;
			} else {
				previous->next = pointer->next;
			}
			ptr = pointer->ptr;
			if(free_element != NULL) {
				free_element(ptr);
				ptr = NULL;
			}
			free(pointer);
			linkedlist->element_count--;
			break;
		}
	}
	
	return ptr;
}

void *hip_ll_get(hip_ll_t *linkedlist, const unsigned int index)
{
	if(linkedlist == NULL || linkedlist->head == NULL) {
		return NULL;
	} else if(index > (linkedlist->element_count -1)) { 
		return NULL;
	}
	
	hip_ll_node_t *pointer = linkedlist->head;
	unsigned int current_index = 0;
	
	while(pointer != NULL) {
		if(current_index == index) {
			break;
		}
		
		pointer = pointer->next;
		current_index++;
	}
	
	return pointer->ptr;
}

hip_ll_node_t *hip_ll_iterate(const hip_ll_t *linkedlist,
			      hip_ll_node_t *current)
{
	if(linkedlist == NULL)
		return NULL;
	if(current == NULL)
		return linkedlist->head;
	
	return current->next;
}

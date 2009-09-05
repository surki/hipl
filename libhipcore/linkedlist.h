/** @file
 * A header file for linkedlist.c
 *
 * We are using following notation in this file:
 * <pre>
 * +------------+   head   +---------+   next   +---------+
 * | linkedlist |--------->|   node  |--------->|   node  |--  ...  --> NULL
 * +------------+          +--------+-          +---------+
 *                              |                    |
 *                              | ptr                | ptr
 *                              v                    v
 *                         +---------+          +---------+
 *                         | element |          | element |
 *                         +---------+          +---------+
 * </pre>where element contains the payload data.
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    21.04.2008
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_LL_H
#define HIP_LL_H

#include <stdlib.h> /* For malloc(). */
#include "misc.h" /* For debuging macros. */

/** Linked list node. */
typedef struct hip_ll_node{
	void *ptr; /**< A pointer to node payload data. */
	struct hip_ll_node *next; /**< A pointer to next node. */ 
}hip_ll_node_t;

/** Linked list. */
typedef struct{
	unsigned int element_count; /**< Total number of nodes in the list. */
	hip_ll_node_t *head; /**< A pointer to the first node of the list. */
}hip_ll_t;

/** Linked list element memory deallocator function pointer. */
typedef void (*free_elem_fn_t)(void *ptr);

/**
 * Initializes a linked list. Sets the parameter @c linkedlist head to NULL if
 * the list itself is not NULL. If the list @c linkedlist is NULL, this function
 * does nothing.
 *
 * @param linkedlist the list to init.
 */ 
void hip_ll_init(hip_ll_t *linkedlist);

/**
 * Uninitializes a linked list. Removes each node from the parameter
 * @c linkedlist and frees the memory allocated for the nodes. The parameter
 * @c linkedlist is not itself freed.
 *
 * <ul><li>When @c free_element is <b>non-NULL</b> the memory allocated for the
 * elements itself is also freed by calling the @c free_element function for
 * each node. Make sure that there are no duplicate entries (i.e. nodes whose
 * @c ptr is pointing to the same memory region) in the @c list.</li>
 * <li>When @c free_element is <b>NULL</b> the memory allocated for the elements
 * is not freed, but only the nodes are freed.</li>
 * </ul>
 * 
 * @param linkedlist   the list to uninitialize.
 * @param free_element a function pointer to a function for freeing the memory
 *                     allocated for an element stored in a node.
 * @note               If you're storing elements that have different memory
 *                     deallocator functions in the list, you should deallocate
 *                     the memory allocated for the elements manually before
 *                     invoking this function, and then call this function with
 *                     NULL as @c free_element.
 */ 
void hip_ll_uninit(hip_ll_t *linkedlist, free_elem_fn_t free_element);

/**
 * Returns the number of nodes in the list.
 *
 * @param  linkedlist the list whose node count is to be returned.
 * @return number of nodes in the list.
 */ 
unsigned int hip_ll_get_size(const hip_ll_t *linkedlist);

/**
 * Adds a new node to a linked list. Adds a new node at @c index to the
 * parameter @c linkedlist with payload data @c ptr. If there are less than
 * (<code>index  -1</code>) elements in the list, the element will be added as
 * the last element of the list.
 * 
 * <b>Example:</b>
 * 
 * <code>hip_ll_add(&mylist, 2, mydata);</code> will add @c mydata as the
 * third item of the list when there are more than two elements in @c mylist.
 * When there are less than two items in the list @c mydata will be added as
 * the last element of @c mylist.
 * 
 * @param  linkedlist the list where to add the new node.
 * @param  index      the list index where to store the node. Indexing starts
 *                    from zero.
 * @param  ptr        a pointer to the data to be stored.
 * @return            zero on success, -1 if @c linkedlist or @c ptr is NULL or
 *                    if there was an error when allocating memory to the new
 *                    node.
 */
int hip_ll_add(hip_ll_t *linkedlist, const unsigned int index, void *ptr);

/**
 * Adds a new node to a linked list. Adds a new node as the first item of
 * the @c linkedlist with payload data @c ptr.
 *
 * @param  linkedlist the list where to add the new node.
 * @param  ptr        a pointer to the data to be stored.
 * @return            zero on success, -1 if @c linkedlist or @c ptr is NULL or
 *                    if there was an error when allocating memory to the new
 *                    node.
 */
static inline int hip_ll_add_first(hip_ll_t *linkedlist, void *ptr)
{
	return hip_ll_add(linkedlist, 0, ptr);
}

/**
 * Adds a new node to a linked list. Adds a new node as the last item of
 * the @c linkedlist with payload data @c ptr.
 *
 * @param  linkedlist the list where to add the new node.
 * @param  ptr        a pointer to the data to be stored.
 * @return            zero on success, -1 if @c linkedlist or @c ptr is NULL or
 *                    if there was an error when allocating memory to the new
 *                    node.
 */
static inline int hip_ll_add_last(hip_ll_t *linkedlist, void *ptr)
{
	return hip_ll_add(linkedlist, linkedlist->element_count, ptr);
}

/**
 * Deletes a node from a linked list. Deletes a node at @c index and frees the
 * memory allocated for the node from the parameter @c linkedlist. If there are
 * less than (<code>index  -1</code>) nodes in the list no action will be taken. If
 * @c free_element is non-NULL the memory allocated for the element itself is
 * also freed. When @c free_element is non-NULL, make sure that the element
 * being freed is included in the list only once. When there are duplicate entries
 * (i.e. nodes whose @c ptr is pointing to the same memory region) in the
 * @c linkedlist, you will end up having nodes that have NULL pointer as
 * payload. This will mess up further calls of this function.
 *
 * @param linkedlist   the list where from to remove the element.
 * @param index        the list index of the @c node to be deleted. Indexing
 *                     starts from zero.
 * @param free_element a function pointer to a function for freeing the memory
 *                     allocated for an element at a node or NULL if the element
 *                     itself is not to be freed.
 * @return             a pointer to the data stored at the deleted node or NULL
 *                     if there are less than (<code>index  -1</code>) nodes in the list.
 *                     NULL is returned when @c free_element is not NULL i.e. the
 *                     element itself is deleted. NULL is also returned when
 *                     the list @c linkedlist itself is NULL.
 */
void *hip_ll_del(hip_ll_t *linkedlist, const unsigned int index,
		 free_elem_fn_t free_element);


/**
 * Deletes the first node from a linked list. If there are no nodes in the list,
 * no action will be taken. If @c free_element is non-NULL the memory allocated
 * for the element itself is also freed. When @c free_element is non-NULL, make
 * sure that the element being freed is included in the list only once. When there
 * are duplicate entries (i.e. nodes whose @c ptr is pointing to the same memory
 * region) in the @c linkedlist, you will end up having nodes that have NULL
 * pointer as payload. This will mess up further calls of this function.
 *
 * @param linkedlist   the list where from to remove the element.
 * @param free_element a function pointer to a function for freeing the memory
 *                     allocated for an element at a node or NULL if the element
 *                     itself is not to be freed.
 * @return             a pointer to the data stored at the deleted node or NULL
 *                     if there are no nodes in the list. NULL is returned when
 *                     @free_element is not NULL i.e. the element itself is
 *                     deleted. NULL is also returned when the list
 *                     @c linkedlist itself is NULL.
 */
static inline void *hip_ll_del_first(hip_ll_t *linkedlist,
				     free_elem_fn_t free_element)
{
	return hip_ll_del(linkedlist, 0, free_element);
}

/**
 * Deletes the last node from a linked list. If there are no nodes in the list,
 * no action will be taken. If @c free_element is non-NULL the memory allocated
 * for the element itself is also freed. When @c free_element is non-NULL, make
 * sure that the element being freed is included in the list only once. When there
 * are duplicate entries (i.e. nodes whose @c ptr is pointing to the same memory
 * region) in the @c linkedlist, you will end up having nodes that have NULL
 * pointer as payload. This will mess up further calls of this function.
 *
 * @param linkedlist   the list where from to remove the element.
 * @param free_element a function pointer to a function for freeing the memory
 *                     allocated for an element at a node or NULL if the element
 *                     itself is not to be freed.
 * @return             a pointer to the data stored at the deleted node or NULL
 *                     if there are no nodes in the list. NULL is returned when
 *                     @free_element is not NULL i.e. the element itself is
 *                     deleted. NULL is also returned when the list
 *                     @c linkedlist itself is NULL.
 */
static inline void *hip_ll_del_last(hip_ll_t *linkedlist,
				    free_elem_fn_t free_element)
{
	return hip_ll_del(linkedlist, linkedlist->element_count - 1,
			  free_element);
}

/**
 * Gets an element from a linked list. Returns a pointer to the payload data
 * stored in node at @c index. When there are less than (<code>index  -1</code>)
 * nodes in the list, no action will be taken.
 *
 * @param linkedlist the linked list from where to retrieve the element.  
 * @param index      the list index of the @c node from where the element is to
 *                   be retrieved. Indexing starts from zero.
 * @return           the next element or NULL if the list end has been reached
 *                   or if @c linkedlist is NULL.
 */
void *hip_ll_get(hip_ll_t *linkedlist, const unsigned int index);

/**
 * Enumerate each element in the list. Returns a pointer to the next linked list
 * node in the @c linkedlist or NULL if the list end has been reached. If
 * @c current is NULL, the first node in the list is returned. Do not delete
 * items from the list using this function or you will break the list.
 *
 * <pre>
 * hip_ll_node_t *iter = NULL;
 * while((iter = hip_ll_iterate(&list, iter)) != NULL) {
 *         ... Do stuff with iter ... 
 * } 
 * </pre>
 * 
 * @param  linkedlist the linked list from where to retrieve the node.
 * @param  current    the current node or NULL if the first node from the list
 *                    is to be retrieved.
 * @return            the next node or NULL if the list end has been reached
 *                    or if @c linkedlist is NULL.
 * @note              <span style="color:#f00;">Do not delete nodes from the list
 *                    using this function.</span> Consider hip_ll_del() or
 *                    hip_ll_uninit() for deleting nodes and elements.
 */
hip_ll_node_t *hip_ll_iterate(const hip_ll_t *linkedlist,
			      hip_ll_node_t *current);

#endif /* HIP_LL_H */

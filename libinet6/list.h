#ifndef QLIST_H
#define QLIST_H

#include <openssl/lhash.h>
//#include "kerncompat.h"

#if 0
#define LIST_HEAD_INIT(name) { 0 } /* XX FIXME */

#define INIT_LIST_HEAD(ptr) /* XX FIXME */
#endif

typedef LHASH_NODE hip_list_t;


/**
 * list_entry - get the struct for this entry
 * @param ptr the &hip_list_t pointer.
 * @param type the type of the struct this is embedded in.
 * @param member the name of the list_struct within the struct.
 */
#define list_entry(ptr) (ptr->data)

/**
 * list_for_each - iterate over list of given type
 * @param pos the type * to use as a loop counter.
 * @param head the head for your list.
 * @param member the name of the list_struct within the struct.
 */
#define list_for_each(pos, head, counter) \
		for (counter = (head->num_nodes - 1); counter >= 0; counter--) \
			for (pos = head->b[counter]; pos != NULL; pos = pos->next)

/**
 * list_for_each_safe
 * Iterates over a list of given type safe against removal of list entry.
 * @param pos the type * to use as a loop counter.
 * @param head the head for your list.
 * @param member the name of the list_struct within the struct.
 */
#define list_for_each_safe(pos, iter, head, counter) \
	for (counter = ((head)->num_nodes - 1); counter >= 0; counter--) \
	for (pos = (head)->b[counter], (iter = pos ? pos->next : NULL); \
	     pos != NULL; pos = iter, (iter = pos ? pos->next : NULL))

/**
 * list_add - add a new entry
 * @param lnew new entry to be added
 * @param lhead list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
#define list_add(entry, head) lh_insert(head, entry)

/**
 * list_del - deletes entry from list.
 * @param entry the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
#define list_del(entry, head) lh_delete(head, entry)

/**
 * list_add_tail - add a new entry
 * @param lnew new entry to be added
 * @param lhead list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
//static inline void list_add_tail(hip_list_t *lnew, hip_list_t *lhead)
//{
  /* XX FIXME */
//}

/**
 * list_empty - tests whether a list is empty
 * @param head the list to test.
 */
//static inline int list_empty(const hip_list_t *head)
//{
  /* XX FIXME */
//}

#endif /* QLIST_H */

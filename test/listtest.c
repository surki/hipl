#include <stdlib.h>
#include <sys/queue.h>
#include <stdio.h>

int main(int argc, char **argv) {
     LIST_HEAD(listhead, entry) head;
     struct listhead *headp;         /* List head. */
     struct entry {
             LIST_ENTRY(entry) entries;      /* List. */
	     int myval;
     } *n1, *n2, *np;

     LIST_INIT(&head);                       /* Initialize the list. */

     n1 = malloc(sizeof(struct entry));      /* Insert at the head. */
     LIST_INSERT_HEAD(&head, n1, entries);

     n2 = malloc(sizeof(struct entry));      /* Insert after. */
     LIST_INSERT_AFTER(n1, n2, entries);

     n2 = malloc(sizeof(struct entry));      /* Insert before. */
     LIST_INSERT_AFTER(n1, n2, entries);
                                             /* Forward traversal. */
     for (np = head.lh_first; np != NULL; np = np->entries.le_next)
	     printf("entry found\n");

     while (head.lh_first != NULL)           /* Delete. */
             LIST_REMOVE(head.lh_first, entries);
     return 0;
}

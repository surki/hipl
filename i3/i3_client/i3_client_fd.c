/***************************************************************************
                          i3_client_fd.c  -  description
                             -------------------
    begin                :  July 22 2004
    email                : istoica@cs.berkeley.edu

    This file contains functions to manipulate a list of file descriptors.
    This list contains file descriptors for which the application has inserted
    a callback CL_CBK_READ_FD. 

 ***************************************************************************/

#include <stdlib.h>
#include <sys/types.h>
#include "../utils/gen_utils.h"

#include "../i3/i3.h"
#include "i3_client_fd.h"
#include "i3_debug.h"
#include "i3_misc.h"

i3_fds *alloc_i3_fds()
{
  i3_fds *n;

  if ((n = (i3_fds *)calloc(1, sizeof(i3_fds))) != NULL) {
    return n;
  }
  I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "alloc_i3_fds: memory allocation error.\n");
  return NULL;
}

void free_i3_fds(i3_fds *fds)
{
  free_fd_list(fds->readfd_list);
  free_fd_list(fds->writefd_list);
  free_fd_list(fds->exceptfd_list);
  free(fds);
}


int invoke_i3_fds(i3_fds *fds, 
		  fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
  int fd_cnt;

  fd_cnt = invoke_fd_callbacks(fds->readfd_list, readfds);
  fd_cnt += invoke_fd_callbacks(fds->writefd_list, writefds);
  fd_cnt += invoke_fd_callbacks(fds->exceptfd_list, exceptfds);

  return fd_cnt;
}

void set_i3_fds(i3_fds *fds, 
		fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
  fd_set_list(fds->readfd_list, readfds);
  fd_set_list(fds->writefd_list, writefds);
  fd_set_list(fds->exceptfd_list, exceptfds);
}

void compute_max_i3_fds(i3_fds *fds) 
{
  fds->max_fd =  max_fd_list(fds->readfd_list);
  fds->max_fd =  MAX(fds->max_fd, max_fd_list(fds->writefd_list));
  fds->max_fd =  MAX(fds->max_fd, max_fd_list(fds->exceptfd_list));
}


fd_node *alloc_fd_node(int fd, void (*fun)(), void *params)
{
  fd_node *n;

  if ((n = (fd_node *)calloc(1, sizeof(fd_node))) != NULL) {
    n->fd = fd;
    n->params = params;
    n->fun = fun;
    return n;
  }
  panic("alloc_fd_node: memory allocation error.\n");
  return NULL;
}


void insert_fd_node_in_list(fd_node **list, fd_node *n)
{
  if (!n) 
    /* not really needed, because alloc_fd_node panics in this case;
     * just to make the compiler happy! 
     */
    *list = NULL;
    
  /* insert at the head of the list */
  n->next = *list;
  *list = n;
}


fd_node *get_fd_node(fd_node *n, int fd)
{
  if (!n)
    return NULL;

  for (; n; n = n->next)
    if (n->fd == fd)
      return n;

  return NULL;
}


void remove_fd_node_from_list(fd_node **list, fd_node *n)
{
  fd_node *n1;

  if (!(*list))
    return;
   
  if (*list == n) {
    *list = (*list)->next;
    free(n);
    return;
  }

  for (n1 = *list; n1->next; n1 = n1->next) {
    if (n1->next == n) {
      n1->next = n1->next->next;
      free(n);
      break;
    }
  }
}
	

void free_fd_list(fd_node *list)
{
  fd_node *n;

  while (list) {
    n = list;
    list = list->next;
    free(n);
  }
}

void fd_set_list(fd_node *n, fd_set *fds)
{
  for (; n; n = n->next)
    FD_SET(n->fd, fds);
}


int max_fd_list(fd_node *n)
{
  int max = 0;

  for (; n; n = n->next)
    if (max < n->fd)
      max = n->fd;

  return max;
}

void set_fd_list(fd_node *n, fd_set *fds)
{
  for (; n; n = n->next)
    FD_SET(n->fd, fds);
}

int invoke_fd_callbacks(fd_node *n, fd_set *fds)
{
  int fd_cnt = 0;

  for (; n; n = n->next) 
    if (FD_ISSET(n->fd, fds)) {
      if (n->fun) {
	fd_cnt++;
	n->fun(n->fd, n->params);
      }
    }
    
  return fd_cnt;
}

void print_fd_list(fd_node *n)
{
  for (; n; n = n->next)
    printf("%d, ", n->fd);
  printf("\n");
}



  

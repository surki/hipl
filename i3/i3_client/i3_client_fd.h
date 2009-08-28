/***************************************************************************
                          i3_client_fd.h  -  description
                             -------------------
    begin                : Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_FD_H
#define I3_CLIENT_FD_H 

#include <sys/types.h>

typedef struct fd_ {
  void        (*fun)();
  void        *params;
  int         fd;
  struct fd_ *next;
} fd_node;

typedef struct i3_fds_ {
  int max_fd;
  fd_node *readfd_list;
  fd_node *writefd_list;
  fd_node *exceptfd_list;
} i3_fds;

 
/* functions implemented in i3_client_fd.c */
i3_fds *alloc_i3_fds();
void free_i3_fds(i3_fds *fds);
int invoke_i3_fds(i3_fds *fds, 
		  fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
void set_i3_fds(i3_fds *fds, 
		fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
void compute_max_i3_fds(i3_fds *fds);

fd_node *alloc_fd_node(int fd, void (*fun)(), void *params);
void insert_fd_node_in_list(fd_node **list, fd_node *n);
fd_node *get_fd_node(fd_node *n, int fd);
void remove_fd_node_from_list(fd_node **list, fd_node *n);
void free_fd_list(fd_node *list);
void fd_set_list(fd_node *n, fd_set *fds);
int max_fd_list(fd_node *n);
void set_fd_list(fd_node *n, fd_set *fds);
int invoke_fd_callbacks(fd_node *n, fd_set *fds);
void print_fd_list(fd_node *n);


#endif

#ifndef RULE_MANAGEMENT_H
#define RULE_MANAGEMENT_H 

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libipq.h>

#include <stdio.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <limits.h>
#include <linux/netfilter_ipv6.h>

#include "builder.h"
#include "crypto.h"
#include "debug.h"
#include "dlist.h"

//string tokens for rule parsing
#define SRC_HIT_STR "-src_hit"
#define DST_HIT_STR "-dst_hit"
#define TYPE_STR "-type"
#define IN_IF_STR "-i"
#define OUT_IF_STR "-o"
#define STATE_STR "-state"
#define SRC_HI_STR "--hi"
#define VERIFY_RESPONDER_STR "--verify_responder"
#define ACCEPT_MOBILE_STR "--accept_mobile"
#define DECRYPT_CONTENTS_STR "--decrypt_contents" 
#define NEGATE_STR "!"
#define INPUT_STR "INPUT"
#define OUTPUT_STR "OUTPUT"
#define FORWARD_STR "FORWARD"
#define NEW_STR "NEW"
#define ESTABLISHED_STR "ESTABLISHED"
//filename needs to contain either to be valid HI file
#define RSA_FILE "_rsa_"
#define DSA_FILE "_dsa_"

//rule
#define DROP 0;
#define ACCEPT 1;

enum {
  NO_OPTION,
  SRC_HIT_OPTION,
  DST_HIT_OPTION,
  SRC_HI_OPTION,
  DST_HI_OPTION,
  TYPE_OPTION,
  STATE_OPTION,
  IN_IF_OPTION,
  OUT_IF_OPTION,
  HOOK
    };

/*-------------- RULES ------------*/

//states for the connection, hip state machine states from hip.h
enum {
  CONN_NEW,
  CONN_ESTABLISHED
};

struct hit_option{
  struct in6_addr value; //hit value
  int boolean; //0 if negation, else 1
};

struct int_option{
  int value; //int value
  int boolean; // 0 if negation, else 1
};

struct state_option{
  struct int_option int_opt;
  int verify_responder; //1 if responder signatures are verified
  int accept_mobile; //1 if state can be established from updates signalling 
  int decrypt_contents;
};

// can be turned to more generic string option if necessary
// 
struct string_option{
  char * value;
  int boolean;
};

//Pointer values must be NULL if option is not specified.
//Use alloc_empty_rule() to allocate rule with pointers set to NULL!!  
//when updating rule structure, update also (at least) free_rule(), 
//print_rule(), rules_equal(), copy_rule (), alloc_empty_rule() functions
struct rule{
  struct hit_option * src_hit;
  struct hit_option * dst_hit;
  struct hip_host_id * src_hi;
  struct int_option * type;
  struct state_option * state; 
  struct string_option * in_if; 
  struct string_option * out_if; 
  unsigned int hook;
  int accept;
};

/*-------------- RULES ------------*/

void print_rule(const struct rule * rule);
void free_rule(struct rule * rule);
struct rule * alloc_empty_rule();
void print_rule_table();

struct rule * parse_rule(char * string);
void read_file(char * file_name);
struct DList * read_rules(int hook);
void read_rules_exit(int hook);

//rule management functions
void insert_rule(const struct rule * rule, int hook);
int delete_rule(const struct rule * rule, int hook);
struct _DList * list_rules(int hook);
int flush(int hook);

void test_rule_management();
void test_parse_copy();
#endif 

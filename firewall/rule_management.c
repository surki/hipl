#include "rule_management.h"

DList * input_rules;
DList * output_rules;
DList * forward_rules;

struct _DList * get_rule_list(int hook)
{
  if(hook == NF_IP6_LOCAL_IN)
    return input_rules;
  else if(hook == NF_IP6_LOCAL_OUT)
    return output_rules;
  else 
    return forward_rules;
}

void set_rule_list(struct DList * list, int hook)
{
  if(hook == NF_IP6_LOCAL_IN)
    input_rules = list;
  else if(hook == NF_IP6_LOCAL_OUT)
    output_rules = list;
  else 
    forward_rules = list;
}
/*------------- PRINTING -----------------*/

void print_rule(const struct rule * rule){
  if(rule != NULL)
    {
      HIP_DEBUG("rule: ");
      //filtering firewall, so no other hooks supported
      if(rule->hook == NF_IP6_LOCAL_IN)
	HIP_DEBUG("%s ", INPUT_STR);
      else if(rule->hook == NF_IP6_LOCAL_OUT)
	HIP_DEBUG("%s ", OUTPUT_STR);
      else
	HIP_DEBUG("%s ", FORWARD_STR);
      
      if(rule->src_hit != NULL)
	{
	  HIP_DEBUG("%s ", SRC_HIT_STR);
	  if (!rule->src_hit->boolean)
	    HIP_DEBUG("%s ", NEGATE_STR); 
	  HIP_DEBUG("%s ", addr_to_numeric(&rule->src_hit->value));
	}
      if(rule->dst_hit != NULL)
	{
	  HIP_DEBUG("%s ", DST_HIT_STR);
	  if (!rule->dst_hit->boolean)
	    HIP_DEBUG("%s ", NEGATE_STR); 
	  HIP_DEBUG("%s ", addr_to_numeric(&rule->dst_hit->value));
	}
      if(rule->src_hi != NULL)
	{
	  HIP_DEBUG("src_hi exists ");
	  _HIP_HEXDUMP("hi ", 
		      rule->src_hi, 
		      hip_get_param_total_len(rule->src_hi));
	}
      if(rule->type != NULL)
	{
	  HIP_DEBUG(" %s ", TYPE_STR);
	  if (!rule->type->boolean)
	    HIP_DEBUG("%s ", NEGATE_STR); 
	  HIP_DEBUG("%d ", rule->type->value);
	}
      if(rule->state != NULL)
	{
	  HIP_DEBUG("%s ", STATE_STR);
	  if (!rule->state->int_opt.boolean)
	    HIP_DEBUG("%s ", NEGATE_STR); 
	  HIP_DEBUG("%d ", rule->state->int_opt.value);
	  if (rule->state->verify_responder)
	    HIP_DEBUG("%s ", VERIFY_RESPONDER_STR); 
	  if (rule->state->accept_mobile)
	    HIP_DEBUG("%s ", ACCEPT_MOBILE_STR); 
	  if (rule->state->decrypt_contents)
	    HIP_DEBUG("%s ", DECRYPT_CONTENTS_STR);  
	}
      if(rule->in_if != NULL)
	{
	  HIP_DEBUG("%s ", IN_IF_STR);
	  if (!rule->in_if->boolean)
	    HIP_DEBUG("%s ", NEGATE_STR); 
	  HIP_DEBUG("%s ", rule->in_if->value);
	}
      if(rule->out_if != NULL)
	{
	  HIP_DEBUG("%s ", OUT_IF_STR);
	  if (!rule->out_if->boolean)
	    HIP_DEBUG("%s ", NEGATE_STR); 
	  HIP_DEBUG("%s ", rule->out_if->value);
	}
      if(rule->accept)
	HIP_DEBUG("ACCEPT\n");
      else
	HIP_DEBUG("DROP\n");
    }
}

/**
 * used for debugging purposes 
 * caller should take care of synchronization
 */
void print_rule_tables(){
  struct _DList * list = (struct _DList *) input_rules;
  struct rule * rule = NULL;
  while(list != NULL)
    {
      rule = (struct rule *)list->data;
      print_rule(rule);
      list = list->next;
    }
  list = (struct _DList *) output_rules;
  while(list != NULL)
    {
      rule = (struct rule *)list->data;
      print_rule(rule);
      list = list->next;
    }
  list = (struct _DList *) forward_rules;
  while(list != NULL)
    {
      rule = (struct rule *)list->data;
      print_rule(rule);
      list = list->next;
    }
  _HIP_DEBUG("stateful filtering %d\n", get_stateful_filtering());
}

/*------------- COPYING -----------------*/
/**
 * Allocates a new hit_option structure and copies the 
 * contents of the argument. Copy of the argument 
 * is returned. (if hit_option is NULL, returns NULL)
 */
struct hit_option * copy_hit_option(const struct hit_option * hit)
{
  struct hit_option * copy = NULL;
  if(hit)
    {
      copy = (struct hit_option *) malloc(sizeof(struct hit_option));
      memcpy(&copy->value, &hit->value, sizeof(struct in6_addr));
      copy->boolean = hit->boolean;
    }
  return copy;
}

/**
 * Allocates a new int_option structure and copies the 
 * contents of the argument. Copy of the argument 
 * is returned. (if int_option is NULL, returns NULL)
 */
struct int_option * copy_int_option(const struct int_option * int_option)
{
  struct int_option * copy = NULL;
  if(int_option)
    {
      copy = (struct int_option *) malloc(sizeof(struct int_option));
      copy->value = int_option->value;
      copy->boolean = int_option->boolean;
    }
  return copy;
}

/**
 * Allocates a new state_option structure and copies the 
 * contents of the argument. Copy of the argument 
 * is returned. (if int_option is NULL, returns NULL)
 */
struct state_option * copy_state_option(const struct state_option * state)
{
  struct state_option * copy = NULL;
  if(state)
    {
      copy = (struct state_option *) malloc(sizeof(struct state_option));
      copy->int_opt.value = state->int_opt.value; 
      copy->int_opt.boolean = state->int_opt.boolean; 
      copy->verify_responder = state->verify_responder;
      copy->accept_mobile = state->accept_mobile;
    }
  return copy;
}

/**
 * Allocates a new if_option structure and copies the 
 * contents of the argument. Copy of the argument 
 * is returned. (if if_option is NULL, returns NULL)
 */
struct string_option * copy_string_option(const struct string_option * string_option)
{
  struct string_option * copy = NULL;
  if(string_option)
    {
      copy = (struct string_option *) malloc(sizeof(struct string_option));
      copy->value = malloc(sizeof(string_option->value));
      strcpy(copy->value, string_option->value);
      copy->boolean = string_option->boolean;
    }
  return copy;
}

/**
 * Allocates a new rule structure and copies the 
 * contents of the rule. Copy of the argument rule 
 * is returned. (if rule is NULL, returns NULL)
 */
struct rule * copy_rule(const struct rule * rule)
{
  struct rule * copy = NULL;
  if(rule)
  {
    copy = alloc_empty_rule();
    copy->hook = rule->hook;
    copy->accept = rule->accept;
    if(rule->src_hit != NULL)
      copy->src_hit = copy_hit_option(rule->src_hit);
    if(rule->dst_hit != NULL)
      copy->dst_hit = copy_hit_option(rule->dst_hit);
    if(rule->src_hi != NULL)
      {
	copy->src_hi = malloc(hip_get_param_total_len(rule->src_hi)); 
	memcpy(copy->src_hi, 
	       rule->src_hi,
	       hip_get_param_total_len(rule->src_hi)); 
      }
    if(rule->type != NULL)
      copy->type = copy_int_option(rule->type);
    if(rule->state != NULL)
      copy->state = copy_state_option(rule->state);
    if(rule->in_if != NULL)
      copy->in_if = copy_string_option(rule->in_if);
    if(rule->out_if != NULL)
      copy->out_if = copy_string_option(rule->out_if);
    }
  HIP_DEBUG("copy_rule: original ");
  print_rule(rule);
  HIP_DEBUG("copy_rule: copy ");
  print_rule(copy);
  return copy;
}

/*------------- COMPARISON -----------------*/

/**
 * returns 1 if hit options are equal otherwise 0
 * hit_options may also be NULL
 */
int hit_options_equal(const struct hit_option * hit1, 
		      const struct hit_option * hit2)
{
  if(hit1 == NULL && hit2 == NULL)
    return 1;
  else if(hit1 == NULL || hit2 == NULL) //only one is NULL
    return 0;
  else{
    if(IN6_ARE_ADDR_EQUAL(&hit1->value, &hit2->value) && 
       hit1->boolean == hit2->boolean)
      return 1;
    return 0;
  }
}

/**
 * returns 1 if hit options are equal otherwise 0
 * hit_options may also be NULL
 */
int int_options_equal(const struct int_option * int_option1, 
		      const struct int_option * int_option2)
{
  if(int_option1 == NULL && int_option2 == NULL)
    return 1;
  else if(int_option1 == NULL || int_option2 == NULL) //only one is NULL
    return 0;
  else{
    if(int_option1->value == int_option2->value && 
       int_option1->boolean == int_option2->boolean)
      return 1;
    return 0;
  }
}

/**
 * returns 1 if hit options are equal otherwise 0
 * hit_options may also be NULL
 */
int state_options_equal(const struct state_option * state_option1, 
			const struct state_option * state_option2)
{
  if(state_option1 == NULL && state_option2 == NULL)
    return 1;
  else if(state_option1 == NULL || state_option2 == NULL) //only one is NULL
    return 0;
  else{
    if(int_options_equal(&state_option1->int_opt, 
			 &state_option2->int_opt)
       && 
       state_option1->verify_responder == state_option2->verify_responder && 
       state_option1->accept_mobile == state_option2->accept_mobile && 
       state_option1->decrypt_contents == state_option2->decrypt_contents)
      return 1;
    return 0;
  }
}

/**
 * returns 1 if hit options are equal otherwise 0
 * hit_options may also be NULL
 */
int string_options_equal(const struct string_option * string_option1, 
			 const struct string_option * string_option2)
{
  if(string_option1 == NULL && string_option2 == NULL)
    return 1;
  else if(string_option1 == NULL || string_option2 == NULL) //only one is NULL
    return 0;
  else{
    if(!strcmp(string_option1->value, string_option2->value) && 
       string_option1->boolean == string_option2->boolean)
      return 1;
    return 0;
  }
}

/**
 *returns boolean value depending whether rules match
 */
int rules_equal(const struct rule* rule1, 
		const struct rule* rule2)
{
  int value = 1;
  if(rule1->hook != rule2->hook)
    return 0;
  if(rule1->accept != rule2->accept)
    return 0;
  if(!hit_options_equal(rule1->src_hit, rule2->src_hit))
    return 0;
  if(!hit_options_equal(rule1->dst_hit, rule2->dst_hit))
    return 0;
  //no need to compare HIs as src_hits have been compared
  if((rule1->src_hi != NULL && rule2->src_hi == NULL)||
     (rule1->src_hi == NULL && rule2->src_hi != NULL))
    return 0;
  if(!int_options_equal(rule1->type, rule2->type))
    return 0;
  if(!state_options_equal(rule1->state, rule2->state))
    return 0;
  if(!string_options_equal(rule1->in_if, rule2->in_if))
    return 0;
  if(!string_options_equal(rule1->out_if, rule2->out_if))
    return 0;
  return 1;
}

/*------------- ALLOCATING & FREEING -----------------*/

/**
 * Allocates empty rule structure and sets elements to NULL
 *
 */
struct rule * alloc_empty_rule(){
  struct rule * rule = (struct rule *)malloc(sizeof(struct rule));
  rule->src_hit = NULL;
  rule->dst_hit = NULL;
  rule->src_hi = NULL;
  rule->type = NULL;
  rule->state = NULL; 
  rule->in_if = NULL; 
  rule->out_if = NULL;
  rule->hook = -1;
  rule->accept = -1;
  return rule;
}

/**
 * frees char * and the tring option
 */
void free_string_option(struct string_option * string){
  if(string)
    {
      free(string->value);
      free(string);
    }
}

/**
 * free rule structure and all non NULL members
 */

void free_rule(struct rule * rule){
  if(rule)
    {
      HIP_DEBUG("freeing ");
      print_rule(rule);
      if(rule->src_hit != NULL)
	free(rule->src_hit);
      if(rule->dst_hit != NULL)
	free(rule->dst_hit);
      if(rule->src_hi != NULL)
	free(rule->src_hi);
      if(rule->type != NULL)
	free(rule->type);
      if(rule->state != NULL)
	free(rule->state);
      if(rule->in_if != NULL)
	free_string_option(rule->in_if);
      if(rule->out_if != NULL)
	free_string_option(rule->out_if);
      free(rule);
    }
}

/*---------------PARSING---------------*/

/**
 * parse hit option and return allocated hit_option
 * structure or NULL if parsing fails. If hit in question is source hit
 * also possible hi parameter is parsed. Most hi file loading code is 
 * from libinet6/getendpointinfo.c
 */
struct hit_option * parse_hit(char * token)
{
  struct hit_option * option = (struct hit_option *)malloc(sizeof(struct hit_option));
  struct in6_addr * hit = NULL; 
  FILE * fp = NULL;
  char first_key_line[30];
  int err;
  DSA dsa;
  RSA rsa;
	option->boolean = 1;

  if(!strcmp(token, NEGATE_STR)){
    _HIP_DEBUG("found ! \n");
    option->boolean = 0;
    token = (char *)strtok(NULL, " ");
  }
  else
    option->boolean = 1;
  hit = (struct in6_addr *)numeric_to_addr(token);
  if(hit == NULL)
    {
      HIP_DEBUG("parse_hit error\n");
      free(option);
      return NULL;
    }
  option->value = *hit;
  HIP_DEBUG_HIT("hit ok: ", hit);
  return option;
}

struct hip_host_id * load_rsa_file(FILE * fp)
{
  struct hip_host_id * hi = NULL;
  RSA * rsa = NULL;
  unsigned char *rsa_key_rr = NULL;
  int rsa_key_rr_len;
  struct endpoint_hip endpoint_hdr;
    
  _HIP_DEBUG("load_rsa_file: \n");  
  rsa = RSA_new();
  rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
  if(!rsa)
      {
	HIP_DEBUG("reading RSA file failed \n"); 
	RSA_free(rsa);
	return NULL;
      }
  _HIP_HEXDUMP("load_rsa_file: rsa : ", rsa,
	      RSA_size(rsa));
  _HIP_DEBUG("load_rsa_file: \n");
  rsa_key_rr = malloc(sizeof(struct hip_host_id) + RSA_size(rsa));
  _HIP_DEBUG("load_rsa_file: size allocated\n");
  rsa_key_rr_len = rsa_to_dns_key_rr(rsa, &rsa_key_rr);
  hi = malloc(sizeof(struct hip_host_id) + rsa_key_rr_len);
  _HIP_DEBUG("load_rsa_file: rsa_key_len %d\n", rsa_key_rr_len);
  hip_build_param_host_id_hdr(hi, NULL, rsa_key_rr_len, HIP_HI_RSA);
  _HIP_DEBUG("load_rsa_file: build param hi hdr \n");
  hip_build_param_host_id_only(hi, rsa_key_rr, NULL);
  _HIP_HEXDUMP("load_rsa_file: host identity : ", hi,
	      hip_get_param_total_len(hi));

  return hi;  
}


struct hip_host_id * load_dsa_file(FILE * fp)
{
  struct hip_host_id * hi = NULL;
  DSA * dsa = NULL;
  unsigned char *dsa_key_rr = NULL;
  int dsa_key_rr_len;
  struct endpoint_hip endpoint_hdr;
  
  _HIP_DEBUG("load_dsa_file: \n");  
  dsa = DSA_new();
  _HIP_DEBUG("load_dsa_file: new\n");  
  dsa = PEM_read_DSA_PUBKEY(fp, &dsa, NULL, NULL);
  if(!dsa)
      {
	HIP_DEBUG("reading RSA file failed \n"); 
	DSA_free(dsa);
	return NULL;
      }
  _HIP_HEXDUMP("load_dsa_file: dsa : ", dsa,
	      DSA_size(dsa));
  _HIP_DEBUG("load_dsa_file: \n");
  dsa_key_rr = malloc(sizeof(struct hip_host_id) + DSA_size(dsa));
  _HIP_DEBUG("load_dsa_file: size allocated\n");
  dsa_key_rr_len = dsa_to_dns_key_rr(dsa, &dsa_key_rr);
  hi = malloc(sizeof(struct hip_host_id) + dsa_key_rr_len);
  _HIP_DEBUG("load_dsa_file: dsa_key_len %d\n", dsa_key_rr_len);
  hip_build_param_host_id_hdr(hi, NULL, dsa_key_rr_len, HIP_HI_DSA);
  _HIP_DEBUG("load_dsa_file: build param hi hdr \n");
  hip_build_param_host_id_only(hi, dsa_key_rr, NULL);
  _HIP_HEXDUMP("load_dsa_file: host identity : ", hi,
	      hip_get_param_total_len(hi));
  return hi;  
}


/**
 * parse hit option and return allocated hit_option
 * structure or NULL if parsing fails. If hit in question is source hit
 * also possible hi parameter is parsed. Most hi file loading code is 
 * from libinet6/getendpointinfo.c
 *
 * Public keys must have _dsa_ or _rsa_ in the file name so algorithm is known
 */
struct hip_host_id * parse_hi(char * token, const struct in6_addr * hit){
  FILE * fp = NULL;
  int err, algo;
  struct hip_host_id * hi = NULL;
  struct in6_addr temp_hit;
  
  HIP_DEBUG("parse_hi: hi file: %s\n", token);
  fp = fopen(token, "rb");
  if(!fp){
    HIP_DEBUG("Invalid filename for HI \n"); 
    return NULL;
  }
  if(strstr(token, RSA_FILE))
    algo = HIP_HI_RSA;
  else if(strstr(token, DSA_FILE))
    algo = HIP_HI_DSA;
  else
    {
      HIP_DEBUG("Invalid filename for HI: missing _rsa_ or _dsa_ \n"); 
      return NULL;
    }
  _HIP_DEBUG("parse_hi: algo found %d\n", algo);
  if(algo == HIP_HI_RSA)
   {
     hi = load_rsa_file(fp);
   }
  else
    {
      hi = load_dsa_file(fp);
    }
  if(!hi)
    {
      HIP_DEBUG("file loading failed \n"); 
      return NULL;
    }

  //verify hi => hit
  hip_host_id_to_hit(hi, &temp_hit, HIP_HIT_TYPE_HASH100);
  if(!ipv6_addr_cmp(&temp_hit, hit))
    _HIP_DEBUG("parse hi: hi-hit match\n");
  else
    {
    HIP_DEBUG("HI in file %s does not match hit %s \n", 
	      token, addr_to_numeric(hit));
    free(hi);
    return NULL;
    }
  return hi;
}


/**
 * parse type option and return allocated int_option
 * structure or NULL if parsing fails
 */
struct int_option * parse_type(char * token)
{
  char * string = NULL;
  struct int_option * option = (struct int_option *) malloc(sizeof(struct int_option));

  if(!strcmp(token, NEGATE_STR)){
    option->boolean = 0;
    token = (char *) strtok(NULL, " ");
  }
  else
    option->boolean = 1;
  HIP_DEBUG("type token %s \n", token);
  if(!strcmp(token, "I1"))
      option->value = HIP_I1;
  else if(!strcmp(token, "R1"))
      option->value = HIP_R1;
  else if(!strcmp(token, "I2"))
      option->value = HIP_I2;
  else if(!strcmp(token, "R2"))
      option->value = HIP_R2;
  else if(!strcmp(token, "CER"))
      option->value = HIP_CER;
  else if(!strcmp(token, "UPDATE"))
      option->value = HIP_UPDATE;
  else if(!strcmp(token, "NOTIFY"))
      option->value = HIP_NOTIFY;
  else if(!strcmp(token, "CLOSE"))
      option->value = HIP_CLOSE;
  else if(!strcmp(token, "CLOSE_ACK"))
      option->value = HIP_CLOSE_ACK;
  else if(!strcmp(token, "PAYLOAD"))
      option->value = HIP_PAYLOAD;
  else
    {
      HIP_DEBUG("parse_type error\n");
      free(option);
      return NULL;
    }
  return option;
}



/**
 * parse state option and return allocated int_option
 * structure or NULL if parsing fails
 */
struct state_option * parse_state(char * token)
{
  char * string = NULL;
  struct state_option * option = (struct state_option *) malloc(sizeof(struct state_option));

  if(!strcmp(token, NEGATE_STR)){
    option->int_opt.boolean = 0;
    token = (char *) strtok(NULL, " ");
  }
  else
    option->int_opt.boolean = 1;
  if(!strcmp(token, NEW_STR))
      option->int_opt.value = CONN_NEW;
  else if(!strcmp(token, ESTABLISHED_STR))
      option->int_opt.value = CONN_ESTABLISHED;
  else
    {
      HIP_DEBUG("parse_state error\n");
      free(option);
      return NULL;
    }
  option->verify_responder = 0;
  option->accept_mobile = 0;
  option->decrypt_contents = 0;
  return option;
}

struct string_option * parse_if(char * token)
{
  char * string = NULL;
  struct string_option * option = (struct string_option *) malloc(sizeof(struct string_option));

  if(!strcmp(token, NEGATE_STR)){
    option->boolean = 0;
    token = (char *) strtok(NULL, " ");
  }
  else
    option->boolean = 1;
  if(strlen(token) > IFNAMSIZ)
    {
      HIP_DEBUG("parse_if error: invalid length interface name\n");
      free(option);
      return NULL;
    }
  else
    {
      option->value = (char *) malloc(IFNAMSIZ);
      strcpy(option->value, token);
    }
  return option;  
}

/** 
 * parses argument sring into a rule structure,
 * returns pointer to allocated rule structure or NULL if
 * syntax error
 */
struct rule * parse_rule(char * string)
{
  struct rule * rule = NULL;
  int i = 0;
  char * token;
  int option_found = NO_OPTION;
  
  _HIP_DEBUG("parse rule string: %s\n", string);
  token = (char *) strtok(string, " ");
  if(token == NULL)
    return NULL;
  rule = alloc_empty_rule();
  //rule needs to start with a hook
  if(!strcmp(token, INPUT_STR))
    {
      rule->hook = NF_IP6_LOCAL_IN;
      _HIP_DEBUG("INPUT found \n");
    }
  else if(!strcmp(token, OUTPUT_STR))
    {
      rule->hook = NF_IP6_LOCAL_OUT;
      _HIP_DEBUG("OUTPUT found \n");
    }
  else if(!strcmp(token, FORWARD_STR))
    {
      rule->hook = NF_IP6_FORWARD;
      _HIP_DEBUG("FORWARD found \n");
    }
  else
    {
      HIP_DEBUG("rule is missing netfilter hook\n");
      free_rule(rule);
      return NULL;
    }
  while(strlen(string) > 0) 
    {
      token = (char *) strtok(NULL, " ");
      if(token == NULL)
	{
	  //empty string
	  if(i = 0){
	    HIP_DEBUG("error parsing rule: empty rule\n");
	    free_rule(rule);
	    return NULL;
	  }
	  break;
	}
      //matching new option
      else if(option_found == NO_OPTION)
	{
	  if(!strcmp(token, SRC_HIT_STR))
	    {
	      //option already defined
	      if(rule->src_hit != NULL)
		{
		  HIP_DEBUG("error parsing rule: src_hit option \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = SRC_HIT_OPTION;
	      _HIP_DEBUG("src_hit found\n");
	    }
	  else if(!strcmp(token, DST_HIT_STR))
	    {  
	      //option already defined
	      if(rule->dst_hit != NULL)
		{
		  HIP_DEBUG("error parsing rule: dst_hit option \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = DST_HIT_OPTION;
	      _HIP_DEBUG("dst_hit found\n");
	    }
	  else if(!strcmp(token, SRC_HI_STR))
	    {  
	      //option already defined
	      if(rule->src_hit == NULL || //no hit for hi 
		 !rule->src_hit->boolean || // negated hit
		 rule->src_hi != NULL) //hi already defined
		{
		  HIP_DEBUG("error parsing rule: src_hi option \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = SRC_HI_OPTION;
	      _HIP_DEBUG("src_hi found\n");
	    }
	  else if(!strcmp(token, TYPE_STR))
	    {
	      //option already defined
	      if(rule->type != NULL)
		{
		  HIP_DEBUG("error parsing rule: type option \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = TYPE_OPTION;
	      _HIP_DEBUG("type found\n");
	    }
	  else if(!strcmp(token, STATE_STR))
	    {
	      //option already defined
	      if(rule->state != NULL)
		{
		  HIP_DEBUG("error parsing rule: state option \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = STATE_OPTION;	
	      _HIP_DEBUG("state found\n");
	    }
	  else if(!strcmp(token, VERIFY_RESPONDER_STR))
	    {
	      //related state option must be defined
	      if(rule->state == NULL)
		{
		  HIP_DEBUG("error parsing rule: %s without %s\n", 
			    VERIFY_RESPONDER_STR, STATE_STR);
		  free_rule(rule);
		  return NULL;
		}
	      rule->state->verify_responder = 1;
	      _HIP_DEBUG("%s found\n", VERIFY_RESPONDER_STR);
	    }
	  else if(!strcmp(token, ACCEPT_MOBILE_STR))
	    {
	      //related state option must be defined
	      if(rule->state == NULL)
		{
		  HIP_DEBUG("error parsing rule: %s without %s\n", 
			    ACCEPT_MOBILE_STR, STATE_STR);
		  free_rule(rule);
		  return NULL;
		}
	      rule->state->accept_mobile = 1;
	      _HIP_DEBUG("%s found\n", ACCEPT_MOBILE_STR);
	    }
	  else if(!strcmp(token, DECRYPT_CONTENTS_STR))
	    {
	      //related state option must be defined
	      if(rule->state == NULL)
		{
		  HIP_DEBUG("error parsing rule: %s without %s\n", 
			    DECRYPT_CONTENTS_STR, STATE_STR);
		  free_rule(rule);
		  return NULL;
		}
	      rule->state->decrypt_contents = 1;
	      _HIP_DEBUG("%s found\n", DECRYPT_CONTENTS_STR);
	    }  
	  else if(!strcmp(token, IN_IF_STR))
	    {
	      //option already defined
	      //rule in output hook can't have incoming if
	      if(rule->in_if != NULL || rule->hook == NF_IP6_LOCAL_OUT)
		{
		  HIP_DEBUG("error parsing rule: i option \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = IN_IF_OPTION;	
	      _HIP_DEBUG("-i found\n");
	    }
	  else if(!strcmp(token, OUT_IF_STR))
	    {
	      //option already defined
	      //rule in input hook can't have outcoming if
	      if(rule->in_if != NULL || rule->hook == NF_IP6_LOCAL_IN)
		{
		  HIP_DEBUG("error parsing rule: o option \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = OUT_IF_OPTION;	
	      _HIP_DEBUG("-o found\n");
	    }
	  else if(!strcmp(token, "ACCEPT"))
	    {
	      //target already defined
	      if(rule->accept > -1)
		{
		  HIP_DEBUG("error parsing rule: target \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      rule->accept = 1;
	      _HIP_DEBUG("accept found \n");
	      break;
	    }
	  else if(!strcmp(token, "DROP"))
	    {
	      //target already defined
	      if(rule->accept > -1)
		{
		  HIP_DEBUG("error parsing rule: target \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      rule->accept = 0;
	      _HIP_DEBUG("drop found \n");
	      break;
	    }
	  else 
	    {
	      //invalid option
	      HIP_DEBUG("error parsing rule: invalid option %s\n", token);
	      free_rule(rule);
	      return NULL;
	    }
	}
      //matching value for previous option
      else
	{
	  if(option_found == SRC_HIT_OPTION)
	    {
	      rule->src_hit = parse_hit(token);
	      _HIP_DEBUG("parse_rule : src hit %d %s \n", rule->src_hit, addr_to_numeric(&rule->src_hit->value));
	      if(rule->src_hit == NULL)
		{
		  HIP_DEBUG("error parsing rule: src_hit value \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }
	  else if(option_found == DST_HIT_OPTION)
	    {
	      rule->dst_hit = parse_hit(token);
	      if(rule->dst_hit == NULL)
		{
		  HIP_DEBUG("error parsing rule: dst_hit value \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }
	  if(option_found == SRC_HI_OPTION)
	    {
	      _HIP_DEBUG("parse_rule: src hi \n");
	      rule->src_hi = parse_hi(token, &rule->src_hit->value);
	      if(rule->src_hi == NULL)
		{
		  HIP_DEBUG("error parsing rule: src_hi value \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }
	  else if(option_found == TYPE_OPTION)
	    {
	      rule->type = parse_type(token);
	      if(rule->type == NULL)
		{
		  HIP_DEBUG("error parsing rule: type value \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }
	  else if(option_found == STATE_OPTION)
	    {
	      rule->state = parse_state(token);
	      if(rule->state == NULL)
		{
		  HIP_DEBUG("error parsing rule: state value \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }
	  else if(option_found == IN_IF_OPTION)
	    {
	      rule->in_if = parse_if(token);
	      if(rule->in_if == NULL)
		{
		  HIP_DEBUG("error parsing rule: i value \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }

	  else if(option_found == OUT_IF_OPTION)
	    {
	      rule->out_if = parse_if(token);
	      if(rule->out_if == NULL)
		{
		  HIP_DEBUG("error parsing rule: o value \n"); 
		  free_rule(rule);
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }
	}
      i++; 
    }
  //rule must have a verdict
  if(rule->accept == -1)
    {
      free_rule(rule);
      HIP_DEBUG("error parsing rule: rule is missing ACCEPT/DROP\n");
      return NULL;
    }
  //verdict must be the last part
  if(strtok(NULL, " ") != NULL)
    {
      free_rule(rule);
      HIP_DEBUG("error parsing rule: ACCEPT/DROP must be last part of rule\n");
      return NULL;
    }
  
  _HIP_DEBUG("done with parsing rule ");
  //print_rule(rule);
  return rule;
}


/*-----------PARSING ----------*/

/**
 * mainly for the use of the firewall itself
 * !!! read_rules_exit must be called after done with reading
 */
struct DList * read_rules(int hook){
  _HIP_DEBUG("read_rules\n");
//  read_enter(hook);
  return get_rule_list(hook);
}

/**
 * releases rules after reading. must be called
 * after read_rules.
 */
void read_rules_exit(int hook){
  _HIP_DEBUG("read_rules_exit\n");
//  read_exit(hook);
}

/*----------- RULE MANAGEMENT -----------*/
//when rules are changed also statefulFiltering value in
//firewall.c must be updated with set_stateful_filtering()

/**
 * Reads rules from file specified and parses them into rule
 * list.
 * TODO: Fix reading of empty lines (memory problems)  
 */
void read_file(char * file_name)
{
	struct DList * input = NULL;
	struct DList * output = NULL;
	struct DList * forward = NULL;
	FILE *file = fopen(file_name, "r");
	struct rule * rule = NULL;
	char * line = NULL;
	char * original_line = NULL;
	size_t s = 0;
	int state = 0;

	HIP_DEBUG("read_file: file %s\n", file_name);
	if(file != NULL)
	{
		while(getline(&line, &s, file ) > 0)
		{
			char *comment;
			original_line = (char *) malloc(strlen(line) + sizeof(char) + 1);
			original_line = strcpy(original_line, line);
			_HIP_DEBUG("line read: %s", line);

			/* terminate the line to comment sign */
			comment = index(line, '#');
			if (comment)
				*comment = 0;

			if (strlen(line) == 0) {
				free(original_line);
				continue;
			}

			//remove trailing new line
			line = (char *) strtok(line, "\n");

			if (line)
				rule = parse_rule(line);

			if(rule)
			{
				if(rule->state)
					state = 1;

				if(rule->hook == NF_IP6_LOCAL_IN)
				{
					input = (struct DList *)append_to_list((struct _DList *) input,
							(void *) rule);
					print_rule((struct rule *)((struct _DList *) input)->data);
				}
				else if(rule->hook == NF_IP6_LOCAL_OUT)
				{
					output = (struct DList *)append_to_list((struct _DList *) output,
							(void *) rule);
					print_rule((struct rule *)((struct _DList *) output)->data);
				}
				else if(rule->hook == NF_IP6_FORWARD)
				{
					forward = (struct DList *)append_to_list((struct _DList *) forward,
							(void *) rule);
					print_rule((struct rule *)((struct _DList *) forward)->data);
				}

				// this leads to getline to malloc new memory and the current block is lost
				//rule = NULL;
			}
			else if (line)
			{
				HIP_DEBUG("unable to parse rule: %s\n", original_line);
			}
			free(original_line);
			original_line = NULL;
		}
		free(line);
		line = NULL;
		fclose(file);
	}
	else
	{
		HIP_DEBUG("Can't open file %s \n", file_name );
	}

	//write_enter(NF_IP6_LOCAL_IN);
	input_rules = input;
	set_stateful_filtering(state);
	//write_exit(NF_IP6_LOCAL_IN);
	//write_enter(NF_IP6_LOCAL_OUT);
	output_rules = output;
	//write_exit(NF_IP6_LOCAL_OUT);
	//write_enter(NF_IP6_FORWARD);
	forward_rules = forward;
	//write_exit(NF_IP6_FORWARD);
}


/**
 * makes a local copy of the arguments rule 
 * and inserts rule at the end of the list.
 * rule validity be checked by the caller 
 * (parsing from string)
 * some validity check function could be useful, 
 * but rule validity is ensured when rule is parsed from string
 */
void insert_rule(const struct rule * rule, int hook){
  HIP_DEBUG("insert_rule\n");
  if(!rule)
    return;
  struct rule * copy = copy_rule(rule);  
//  write_enter(hook);
  set_rule_list(append_to_list(get_rule_list(hook), 
  					(void *) copy),
					hook);

  if(rule->state)
    set_stateful_filtering(1);
//  write_exit(hook);
}

/**
 * deletes rule in the rule list that is equal to the
 * argument rule. returns 0 if deleted succefully, -1 
 * if rule was not found
 */
int delete_rule(const struct rule * rule, int hook){
  HIP_DEBUG("delete_rule\n");
  struct _DList * temp;
  struct rule * r;
  int val = -1, state = 0;
//  write_enter(hook);
  temp = get_rule_list(hook);
  while(temp)
    {
      //delete first match
  	  if(rules_equal((struct rule *)temp->data, rule))
		{
	  free_rule((struct rule *) temp->data);
	  HIP_DEBUG("delete_rule freed\n");
	  set_rule_list((struct _DList *)remove_from_list((struct _DList *)get_rule_list(hook), 
						      temp->data),
			hook);
	  HIP_DEBUG("delete_rule removed\n");
	  val = 0;
	  break;
	}
    temp = temp->next;
    }
  HIP_DEBUG("delete_rule looped\n");
  set_stateful_filtering(state);
//  write_exit(hook);
  HIP_DEBUG("delete_rule exit\n");
  return val;
}
/**
 * create local copy of the rule list and return
 * caller is responsible for freeing rules
 */
struct _DList * list_rules(int hook)
{
  HIP_DEBUG("list_rules\n");
  struct _DList * temp = NULL, * ret = NULL;
  //read_enter(hook);
  temp = (struct _DList *) get_rule_list(hook);
  while(temp)
    {
      ret = append_to_list(ret, 
			  	(void *) copy_rule((struct rule *) temp->data)); 
      temp = temp->next;
    }
  //read_exit(hook);
  return ret;
}

int flush(int hook)
{
  HIP_DEBUG("flush\n");
  struct _DList * temp = (struct _DList *) get_rule_list(hook);
//  write_enter(hook);
  set_rule_list(NULL, hook);
  set_stateful_filtering(0);
//  write_exit(hook);
  while(temp)
    {
      free_rule((struct rule *) temp->data);
      temp = temp->next;
    }
  free_list(temp);

  return 0;
}

void test_rule_management(){
  struct _DList * list = NULL,  * orig = NULL;
  HIP_DEBUG("\n\ntesting rule management functions\n");
  list = (struct _DList *) list_rules(NF_IP6_FORWARD);
  orig = list;
  HIP_DEBUG("ORIGINAL \n");
  print_rule_tables();
  flush(NF_IP6_FORWARD);
  HIP_DEBUG("FLUSHING \n");
  print_rule_tables();
  while(list)  
    {
      insert_rule((struct rule *) list->data, NF_IP6_FORWARD);
      list = list->next;
    }
  HIP_DEBUG("INSERTING \n");
  print_rule_tables();

  list = orig;
  HIP_DEBUG("INSERTING AND DELETING\n");
  while(list)  
    {
      insert_rule((struct rule *) list->data, NF_IP6_FORWARD);
      print_rule_tables();
      delete_rule((struct rule *) list->data, NF_IP6_FORWARD);
      list = list->next;
    }
  HIP_DEBUG("FINAL \n");
  print_rule_tables();
  
}

void test_parse_copy(){
  char rule_str1[200] = "FORWARD -src_hit 7dac:74f2:8b16:ca1c:f96c:bae6:c61f:c7 --hi ../oops_rsa_key.pub ACCEPT";
  char rule_str2[200] = "FORWARD -src_hit 7dac:74f2:8b16:ca1c:f96c:bae6:c61f:c7 -dst_hit 7dac:74f2:8b16:ca1c:f96c:bae6:c61f:c7 -type I2 DROP"; 
  char rule_str3[200] = "FORWARD -src_hit 7dac:74f2:8b16:ca1c:f96c:bae6:c61f:c7 -state NEW -type I2 ACCEPT";
  struct rule * rule = NULL, * copy = NULL;
  HIP_DEBUG("\n\n\ntest_parse_copy \n");
  HIP_DEBUG("rule string 1 %s \n", &rule_str1);
  rule = parse_rule(rule_str1);
  HIP_DEBUG("PARSED ");
  print_rule(rule);
  copy = copy_rule(rule);
  HIP_DEBUG("COPIED ");
  print_rule(copy);
  free_rule(rule);
  free_rule(copy);

  HIP_DEBUG("rule string 2 %s \n", &rule_str2);
  rule = parse_rule(rule_str2);
  HIP_DEBUG("PARSED ");
  print_rule(rule);
  copy = copy_rule(rule);
  HIP_DEBUG("COPIED ");
  print_rule(copy);
  free_rule(rule);
  free_rule(copy);

  HIP_DEBUG("rule string 3 %s \n", &rule_str3);
  rule = parse_rule(rule_str3);
  HIP_DEBUG("PARSED ");
  print_rule(rule);
  copy = copy_rule(rule);
  HIP_DEBUG("COPIED ");
  print_rule(copy);
  free_rule(rule);
  free_rule(copy);
}

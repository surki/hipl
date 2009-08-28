/***************************************************************************
                          i3_trigger.h  -  description
                             -------------------
    begin                : Fre Jun 20 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef I3_TRIGGER_H
#define I3_TRIGGER_H

 
/* functions implemented in i3_trigger.c */
i3_trigger *alloc_i3_trigger();
void init_i3_trigger(i3_trigger *t, ID *id, uint16_t prefix_len, 
		     struct i3_addr *to, Key *key, uint8_t flags);
void free_i3_trigger(i3_trigger *trigger);
void pack_i3_trigger(char *p, i3_trigger *trigger, unsigned short *length);
unsigned short get_i3_trigger_len(i3_trigger *trigger);
i3_trigger *unpack_i3_trigger(char *p, unsigned short *length);
int check_i3_trigger(char *p, unsigned short *length);
int trigger_equal(i3_trigger *t1, i3_trigger *t2);
void printf_i3_trigger(i3_trigger *trigger, int indent);
void update_nonce(i3_trigger *t);
int check_nonce(i3_trigger *t);
i3_trigger *duplicate_i3_trigger(i3_trigger *t);

void generate_constraint_id(ID *id, Key *key, int type);
#define generate_r_constraint_id(id, key) generate_constraint_id(id, key, R_CONSTRAINT)
#define generate_r_constraint(id, key) generate_constraint_id(id, key, R_CONSTRAINT)
#define generate_l_constraint_id(id, key) generate_constraint_id(id, key, L_CONSTRAINT)
void generate_l_constraint_addr(Key *rkey, Key *lkey);
int check_constraint(i3_trigger *t);
void set_key_id(ID *id, Key *key);
void set_key_addr(Key *dst, Key *src);

void l_constrain_path(ID *id, int path_len);
void r_constrain_path(ID *id, int path_len);

void printf_i3_key(uint8_t *k,int indent);

#endif

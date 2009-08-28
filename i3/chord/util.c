#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "chord.h"
#include "../utils/gen_utils.h"

#if 0
/* f_rand: return a random double between 0.0 and 1.0 */
double f_rand(void)
{
    int64_t l, r;

    l = (int64_t) (random() & ((1 << 26) - 1));
    r = (int64_t) (random() & ((1 << 27) - 1));
    return ((l << 27) + r) / (double)(1LL << 53);
}

/**********************************************************************/

/* funif_rand: Return a random number between a and b */
double funif_rand(double a, double b)
{
    return a + (b - a) * f_rand();
}

/**********************************************************************/

/* n_rand: return a random integer in [0, n),
   borrowed from Java Random class */
int n_rand(int n)
{
    int bits, val;

    assert(n > 0);   /* n must be positive */

    /* Special case: power of 2 */
    if ((n & -n) == n)
	return random() & (n - 1);

    do {
	bits = random();
	val = bits % n;
    } while (bits - val + (n - 1) < 0);
    return val;
}

/**********************************************************************/

/* unif_rand: return a random integer number in the interval [a, b) */
int unif_rand(int a, int b)
{
    return a + n_rand(b - a);
}

/**********************************************************************/

/* getusec: return wall time in usec */
uint64_t wall_time(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/**********************************************************************/
#endif
void update_rtt(long *rtt_avg, long *rtt_dev, long new_rtt)
{
  long err;

  if (*rtt_avg == 0) {
    *rtt_avg = new_rtt;
    *rtt_dev = 0;
    return;
  }

  /* use TCP's rtt estimation algorithm */
  err = new_rtt - *rtt_avg;
  *rtt_avg += err >> 3;
  if (err < 0) err = -err;
  *rtt_dev += (err - *rtt_dev) >> 2;
}
    

/**********************************************************************/

/* randID: return a random ID */
chordID rand_ID(void)
{
    chordID id;
    int i;

    for (i = 0; i < ID_LEN; i++)
	id.x[i] = (byte)(random() & 0xff);
    return id;
}

/**********************************************************************/

/* successorID: id + (1 << n) */
chordID successor(chordID id, int n)
{
    byte old;
    int i, start;

    assert(n >= 0 && n < NBITS);
    /* Note id.x[0] is most significant bit */
    start = ID_LEN-1 - n/8;
    old = id.x[start];
    id.x[start] += 1 << (n%8);
    if (id.x[start] < old)
	for (i = start-1; i >= 0; i--) {
	    id.x[i]++;
	    if (id.x[i]) break;
	}
    return id;
}

/**********************************************************************/

/* predecessorID: id - (1 << n) */
chordID predecessor(chordID id, int n)
{
    byte old;
    int i, start;

    assert(n >= 0 && n < NBITS);
    start = ID_LEN-1 - n/8;
    old = id.x[start];
    id.x[start] -= 1 << (n%8);
    if (id.x[start] > old)
	for (i = start-1; i >= 0; i--) {
	    if (id.x[i]) {
		id.x[i]--;
		break;
	    } else
		id.x[i]--;
	}
    return id;
}

/**********************************************************************/

/* add: res = a + b (mod 2^n) */
void add(chordID *a, chordID *b, chordID *res)
{
    int carry, i;

    carry = 0;
    for (i = ID_LEN - 1; i >= 0; i--) {
	res->x[i] = (a->x[i] + b->x[i] + carry) & 0xff;
	carry = (a->x[i] + b->x[i] + carry) >> 8;
    }
}

/**********************************************************************/

/* subtract: res = a - b (mod 2^n) */
void subtract(chordID *a, chordID *b, chordID *res)
{
    int borrow, i;

    borrow = 0;
    for (i = ID_LEN - 1; i >= 0; i--) {
	if (a->x[i] - borrow < b->x[i]) {
	    res->x[i] = 256 + a->x[i] - borrow - b->x[i];
	    borrow = 1;
	} else {
	    res->x[i] = a->x[i] - borrow - b->x[i];
	    borrow = 0;
	}
    }
}

/**********************************************************************/

chordID random_from(chordID *a)
{
    chordID b;
    int     i, m = random()%10 + 1;

    for (i = 0; i < ID_LEN; i++) {
        b.x[i] = a->x[i]*m/11;
    }
    return b;
}

/**********************************************************************/

void random_between(chordID *a, chordID *b, chordID *res)
{
  chordID r;

  subtract(b, a, res);

  r = random_from(res);

  add(a, &r, res);
}

/**********************************************************************/

static int msb_tab[256] = {
    0,0,1,1,2,2,2,2,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
    5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7
};

/* msb: most significant bit */
int
msb(chordID *x)
{
    int i;

    for (i = 0; i < ID_LEN; i++)
	if (x->x[i])
	    return 8 * i + msb_tab[x->x[i]];
    return 0;
}

/**********************************************************************/

/* equals: a == b? */
int equals(chordID *a, chordID *b)
{
    return memcmp(a->x, b->x, sizeof(chordID)) == 0;
}

/* equals: a == b? */
int equals_id_str(chordID *a, char *b)
{
  chordID idb = atoid(b);

  return memcmp(a->x, idb.x, sizeof(chordID)) == 0;
}

/**********************************************************************/

int is_zero(chordID *x)
{
    static chordID zero;
    return memcmp(x->x, zero.x, sizeof(chordID)) == 0;
}

/**********************************************************************/

/* greater: a>b? */
static int is_greater(chordID *a, chordID *b)
{
    return memcmp(a->x, b->x, sizeof(chordID)) > 0;
}

/* less: a<b? */
static int is_less(chordID *a, chordID *b)
{
    return memcmp(a->x, b->x, sizeof(chordID)) < 0;
}

/* between: is x in (a,b) on circle? */
int is_between(chordID *x, chordID *a, chordID *b)
{
    if (equals(a, b))
	return !equals(x, a);   /* x is only node not in (x,x) */
    else if (is_less(a, b))
	return is_less(a, x) && is_less(x, b);
    else
	return is_less(a, x) || is_less(x, b);
}

/***********************************************/
int copy_id( chordID *a, chordID *b)
{
    int i = 0;

    assert(a);
    assert(b);
    for (i = 0; i < sizeof(chordID); i++)
        a->x[i] = b->x[i];
    return 1;
}

/**********************************************************************/

void print_id(FILE *f, chordID *id)
{
    int i;

    for (i = 0; i < ID_LEN; i++)
	fprintf(f, "%02x", id->x[i]);
}

/**********************************************************************/


/**********************************************************************/

static unsigned char todigit(char ch)
{
    if (isdigit((int) ch))
	return (ch - '0');
    else
	return (10 + ch - 'a');
}

chordID atoid(const char *str)
{
    chordID id;
    int i;
    
    assert(strlen(str) == 2*ID_LEN);
    for (i = 0; i < ID_LEN; i++)
       id.x[ i ] = (todigit(str[2*i]) << 4) | todigit(str[2*i+1]);
    return id;
}

/**********************************************************************/

enum {
    MULTIPLIER = 31       /* for hash() */
};

/* hash: compute hash value for ID */
unsigned hash(chordID *id, unsigned n)
{
    unsigned h;
    int i;

    h = 0;
    for (i = 0; i < ID_LEN; i++)
	h = MULTIPLIER * h + id->x[ i ];

    return h % n;
}


/* hash: compute hash value for ID */
int match_key(Key *key)
{
  int i;

  for (i = 0; i < NumKeys; i++) {
    if (memcmp((char *)&key->x[0], (char *)&KeyArray[i].x[0], KEY_LEN) == 0) {
      return 1;
    }
  }
  return 0;
}

/***********************************************************************/

void print_chordID(chordID *id)
{
  int i;

  for (i = 0; i < ID_LEN; i++)
    printf("%02x", id->x[i]);
}

/***********************************************************************/

void print_two_chordIDs(char *preffix, chordID *id1, char *middle,
			chordID *id2, char *suffix)
{
  assert(preffix && id1 && middle && id2 && suffix);
  printf("%s", preffix);
  print_chordID(id1);
  printf("%s", middle); 
  print_chordID(id2);
  printf("%s", suffix); 
}

/***********************************************************************/

void print_three_chordIDs(char *preffix, chordID *id1, 
			  char *middle1, chordID *id2, 
			  char *middle2, chordID *id3,
			  char *suffix)
{
  assert(preffix && id1 && middle1 && id2 && middle2 && id3 && suffix);
  printf("%s", preffix);
  print_chordID(id1);
  printf("%s", middle1); 
  print_chordID(id2);
  printf("%s", middle2); 
  print_chordID(id3);
  printf("%s", suffix); 
}


/***********************************************************************/

void print_node(Node *node, char *prefix, char *suffix)
{
  struct in_addr ia;

  printf("%s", prefix);
  print_chordID(&node->id);
  ia.s_addr = htonl(node->addr);
  printf(", %s, %d%s", inet_ntoa(ia), node->port, suffix);
}

void print_finger(Finger *f, char *prefix, char *suffix)
{
  printf("%sFinger:", prefix);
  print_node(&f->node, "<", ">");
#ifndef CIL 
  printf(" (status = %d, npings = %d, rtt = %ld/%ld) %s", 
	 f->status, f->npings, f->rtt_avg, f->rtt_dev, suffix);
#else
  printf(" (status = %d, npings = %d, rtt = %ld/%ld)%s", 
	 f->status, f->npings, f->rtt_avg, f->rtt_dev, suffix);
#endif  
}


void print_finger_list(Finger *fhead, char *prefix, char *suffix)
{
  int i;
  Finger *f;

  printf("%s", prefix);
  for (f = fhead, i = 0; f; f = f->next, i++) {
    printf("  [%d] ", i);
    print_finger(f, "", "\n");
  }
  printf("%s", suffix);
}

void print_server(Server *s, char *prefix, char *suffix)
{
  printf("---------------%s---------------\n", prefix);
  print_node(&s->node, "[", "]\n");
  print_finger_list(s->head_flist, "  Finger list:\n", "\n");
  printf("---------------%s---------------\n", suffix);
}


void print_process(Server *srv, char *process_type, chordID *id,
		   ulong addr, ushort port)
{
#define TYPE_LEN 16
  int i = TYPE_LEN - strlen(process_type);

  printf("[%s]", process_type);
  if (i > 0) for (; i; i--) printf(" ");

  printf(" (");
   if (id)
    print_chordID(id);
  else
    printf("null");
   printf(") ");
  print_node(&srv->node, " <", ">");
  if (addr == -1)
    printf(" <----- <,>");
  else
    printf(" <----- <%ld, %d>", addr, port);
  print_current_time(" Time:", "\n");
}

void print_send(Server *srv, char *send_type, chordID *id,
		ulong addr, ushort port)
{
  int i = TYPE_LEN - strlen(send_type);

  printf("[%s]", send_type);
  if (i > 0) for (; i; i--) printf(" ");

  printf(" (");
   if (id)
    print_chordID(id);
  else
    printf("null");
   printf(") ");
  print_node(&srv->node, " <", ">");
  if (addr == -1)
    printf(" -----> <,>");
  else
    printf(" -----> <%ld, %d>", addr, port);
  print_current_time(" Time:", "\n");
}

void print_fun(Server *srv, char *fun_name, chordID *id)
{
  printf("%s: ", fun_name);
  print_chordID(&srv->node.id);
  printf(" > ");
  print_chordID(id);
  print_current_time(" @ ", "\n");
}

ulong get_current_time()
{
#ifdef SIM_CHORD
  return (ulong)sim_get_time();
#else
  return (ulong)wall_time();
#endif
}

void print_current_time(char *prefix, char *suffix)
{
#ifdef SIM_CHORD
  printf("%s%f%s", prefix, sim_get_time(), suffix);
#else
  printf("%s%lld%s", prefix, wall_time(), suffix);
#endif
}

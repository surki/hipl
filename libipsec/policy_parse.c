#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#include <stdlib.h>

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20050813

#define YYEMPTY (-1)
#define yyclearin    (yychar = YYEMPTY)
#define yyerrok      (yyerrflag = 0)
#define YYRECOVERING (yyerrflag != 0)

extern int yyparse(void);

static int yygrowstack(void);
#define yyparse __libipsecparse
#define yylex __libipseclex
#define yyerror __libipsecerror
#define yychar __libipsecchar
#define yyval __libipsecval
#define yylval __libipseclval
#define yydebug __libipsecdebug
#define yynerrs __libipsecnerrs
#define yyerrflag __libipsecerrflag
#define yyss __libipsecss
#define yyssp __libipsecssp
#define yyvs __libipsecvs
#define yyvsp __libipsecvsp
#define yylhs __libipseclhs
#define yylen __libipseclen
#define yydefred __libipsecdefred
#define yydgoto __libipsecdgoto
#define yysindex __libipsecsindex
#define yyrindex __libipsecrindex
#define yygindex __libipsecgindex
#define yytable __libipsectable
#define yycheck __libipseccheck
#define yyname __libipsecname
#define yyrule __libipsecrule
#define YYPREFIX "__libipsec"
#line 64 "policy_parse.y"
#ifdef CONFIG_HIP_PFKEY

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include PATH_IPSEC_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>

#include <errno.h>

/*#include "config.h"*/

#include "ipsec_strerror.h"
#include "libpfkey.h"

#ifndef INT32_MAX
#define INT32_MAX	(0xffffffff)
#endif

#ifndef INT32_MIN
#define INT32_MIN	(-INT32_MAX-1)
#endif

#define ATOX(c) \
  (isdigit(c) ? (c - '0') : (isupper(c) ? (c - 'A' + 10) : (c - 'a' + 10) ))

static u_int8_t *pbuf = NULL;		/* sadb_x_policy buffer */
static int tlen = 0;			/* total length of pbuf */
static int offset = 0;			/* offset of pbuf */
static int p_dir, p_type, p_protocol, p_mode, p_level, p_reqid;
static u_int32_t p_priority = 0;
static long p_priority_offset = 0;
static struct sockaddr *p_src = NULL;
static struct sockaddr *p_dst = NULL;

struct _val;
extern void yyerror __P((char *msg));
static struct sockaddr *parse_sockaddr __P((struct _val *addrbuf,
    struct _val *portbuf));
static int rule_check __P((void));
static int init_x_policy __P((void));
static int set_x_request __P((struct sockaddr *, struct sockaddr *));
static int set_sockaddr __P((struct sockaddr *));
static void policy_parse_request_init __P((void));
static void *policy_parse __P((const char *, int));

extern void __policy__strbuffer__init__ __P((const char *));
extern void __policy__strbuffer__free__ __P((void));
extern int yyparse __P((void));
extern int yylex __P((void));

extern char *__libipsectext;	/*XXX*/

#line 133 "policy_parse.y"
typedef union {
	u_int num;
	u_int32_t num32;
	struct _val {
		int len;
		char *buf;
	} val;
} YYSTYPE;
#line 123 "policy_parse.c"
#define DIR 257
#define PRIORITY 258
#define PLUS 259
#define PRIO_BASE 260
#define PRIO_OFFSET 261
#define ACTION 262
#define PROTOCOL 263
#define MODE 264
#define LEVEL 265
#define LEVEL_SPECIFY 266
#define IPADDRESS 267
#define PORT 268
#define ME 269
#define ANY 270
#define SLASH 271
#define HYPHEN 272
#define YYERRCODE 256
short __libipseclhs[] = {                                        -1,
    2,    0,    3,    0,    4,    0,    5,    0,    6,    0,
    7,    0,    0,    1,    1,    8,    8,    8,    8,    8,
    8,    8,    8,    9,   10,   12,   12,   13,   11,   14,
   11,   11,   11,
};
short __libipseclen[] = {                                         2,
    0,    4,    0,    6,    0,    7,    0,    6,    0,    8,
    0,    8,    1,    0,    2,    7,    6,    5,    4,    6,
    3,    2,    1,    1,    1,    1,    1,    0,    4,    0,
    6,    3,    3,
};
short __libipsecdefred[] = {                                      0,
    0,    0,    0,    1,    0,    0,    0,   14,    0,    7,
    0,    3,    0,    0,    0,   14,    0,   14,    5,   24,
   15,    0,    9,    0,   11,    0,   14,    0,   14,   14,
    0,   25,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   30,    0,    0,    0,   26,   27,   20,    0,    0,
    0,   32,   33,   16,    0,   29,    0,   31,
};
short __libipsecdgoto[] = {                                       2,
   14,    8,   18,   27,   16,   29,   30,   21,   22,   33,
   41,   48,   43,   50,
};
short __libipsecsindex[] = {                                   -257,
 -250,    0, -246,    0, -249, -251, -245,    0, -244,    0,
 -239,    0, -243, -231, -238,    0, -229,    0,    0,    0,
    0, -237,    0, -231,    0, -231,    0, -228,    0,    0,
 -231,    0, -236, -231, -231, -242, -230, -233, -232, -235,
 -234,    0, -227, -226, -223,    0,    0,    0, -235, -225,
 -224,    0,    0,    0, -219,    0, -218,    0,
};
short __libipsecrindex[] = {                                      0,
   41,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   42,    0,    0,    0,    0,    0,    0,
    0,    1,    0,   49,    0,   51,    0,    2,    0,    0,
   52,    0,    3,   53,   54,    4, -217,    0,    0,    0,
    5,    0,    0,    0,    0,    0,    0,    0,    6,    0,
    0,    0,    0,    0,    0,    0,    0,    0,
};
short __libipsecgindex[] = {                                      0,
   -9,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    7,    0,    0,
};
#define YYTABLESIZE 269
short __libipsectable[] = {                                       1,
   23,   22,   21,   19,   18,   17,   24,    3,   26,    9,
   12,    4,   10,    5,    6,   13,   15,   31,   19,   34,
   35,   17,   11,   23,   37,    7,   38,   39,   40,   46,
   47,   20,   25,   28,   36,   32,   49,   42,   44,   45,
   13,    2,   56,   52,   51,   53,   55,   57,    8,   58,
    4,    6,   10,   12,   28,   54,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   23,   22,   21,   19,   18,   17,
};
short __libipseccheck[] = {                                     257,
    0,    0,    0,    0,    0,    0,   16,  258,   18,  259,
  262,  262,  262,  260,  261,  261,  261,   27,  262,   29,
   30,  261,  272,  262,  267,  272,  269,  270,  271,  265,
  266,  263,  262,  271,  271,  264,  271,  268,  272,  272,
    0,    0,  267,  270,  272,  269,  272,  267,    0,  268,
    0,    0,    0,    0,  272,   49,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  263,  263,  263,  263,  263,  263,
};
#define YYFINAL 2
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 272
#if YYDEBUG
char *__libipsecname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"DIR","PRIORITY","PLUS",
"PRIO_BASE","PRIO_OFFSET","ACTION","PROTOCOL","MODE","LEVEL","LEVEL_SPECIFY",
"IPADDRESS","PORT","ME","ANY","SLASH","HYPHEN",
};
char *__libipsecrule[] = {
"$accept : policy_spec",
"$$1 :",
"policy_spec : DIR ACTION $$1 rules",
"$$2 :",
"policy_spec : DIR PRIORITY PRIO_OFFSET ACTION $$2 rules",
"$$3 :",
"policy_spec : DIR PRIORITY HYPHEN PRIO_OFFSET ACTION $$3 rules",
"$$4 :",
"policy_spec : DIR PRIORITY PRIO_BASE ACTION $$4 rules",
"$$5 :",
"policy_spec : DIR PRIORITY PRIO_BASE PLUS PRIO_OFFSET ACTION $$5 rules",
"$$6 :",
"policy_spec : DIR PRIORITY PRIO_BASE HYPHEN PRIO_OFFSET ACTION $$6 rules",
"policy_spec : DIR",
"rules :",
"rules : rules rule",
"rule : protocol SLASH mode SLASH addresses SLASH level",
"rule : protocol SLASH mode SLASH addresses SLASH",
"rule : protocol SLASH mode SLASH addresses",
"rule : protocol SLASH mode SLASH",
"rule : protocol SLASH mode SLASH SLASH level",
"rule : protocol SLASH mode",
"rule : protocol SLASH",
"rule : protocol",
"protocol : PROTOCOL",
"mode : MODE",
"level : LEVEL",
"level : LEVEL_SPECIFY",
"$$7 :",
"addresses : IPADDRESS $$7 HYPHEN IPADDRESS",
"$$8 :",
"addresses : IPADDRESS PORT $$8 HYPHEN IPADDRESS PORT",
"addresses : ME HYPHEN ANY",
"addresses : ANY HYPHEN ME",
};
#endif
#if YYDEBUG
#include <stdio.h>
#endif

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

int      yydebug;
int      yynerrs;
int      yyerrflag;
int      yychar;
short   *yyssp;
YYSTYPE *yyvsp;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* variables for the parser stack */
static short   *yyss;
static short   *yysslim;
static YYSTYPE *yyvs;
static int      yystacksize;
#line 384 "policy_parse.y"

void
yyerror(msg)
	char *msg;
{
	fprintf(stderr, "libipsec: %s while parsing \"%s\"\n",
		msg, __libipsectext);

	return;
}

static struct sockaddr *
parse_sockaddr(addrbuf, portbuf)
	struct _val *addrbuf;
	struct _val *portbuf;
{
	struct addrinfo hints, *res;
	char *addr;
	char *serv = NULL;
	int error;
	struct sockaddr *newaddr = NULL;

	if ((addr = malloc(addrbuf->len + 1)) == NULL) {
		yyerror("malloc failed");
		__ipsec_set_strerror(strerror(errno));
		return NULL;
	}

	if (portbuf && ((serv = malloc(portbuf->len + 1)) == NULL)) {
		free(addr);
		yyerror("malloc failed");
		__ipsec_set_strerror(strerror(errno));
		return NULL;
	}

	strncpy(addr, addrbuf->buf, addrbuf->len);
	addr[addrbuf->len] = '\0';

	if (portbuf) {
		strncpy(serv, portbuf->buf, portbuf->len);
		serv[portbuf->len] = '\0';
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(addr, serv, &hints, &res);
	free(addr);
	if (serv != NULL)
		free(serv);
	if (error != 0) {
		yyerror("invalid IP address");
		__ipsec_set_strerror(gai_strerror(error));
		return NULL;
	}

	if (res->ai_addr == NULL) {
		yyerror("invalid IP address");
		__ipsec_set_strerror(gai_strerror(error));
		return NULL;
	}

	newaddr = malloc(res->ai_addrlen);
	if (newaddr == NULL) {
		__ipsec_errcode = EIPSEC_NO_BUFS;
		freeaddrinfo(res);
		return NULL;
	}
	memcpy(newaddr, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return newaddr;
}

static int
rule_check()
{
	if (p_type == IPSEC_POLICY_IPSEC) {
		if (p_protocol == IPPROTO_IP) {
			__ipsec_errcode = EIPSEC_NO_PROTO;
			return -1;
		}

		if (p_mode != IPSEC_MODE_TRANSPORT
		 && p_mode != IPSEC_MODE_TUNNEL) {
			__ipsec_errcode = EIPSEC_INVAL_MODE;
			return -1;
		}

		if (p_src == NULL && p_dst == NULL) {
			 if (p_mode != IPSEC_MODE_TRANSPORT) {
				__ipsec_errcode = EIPSEC_INVAL_ADDRESS;
				return -1;
			}
		}
		else if (p_src->sa_family != p_dst->sa_family) {
			__ipsec_errcode = EIPSEC_FAMILY_MISMATCH;
			return -1;
		}
	}

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static int
init_x_policy()
{
	struct sadb_x_policy *p;

	if (pbuf) {
		free(pbuf);
		tlen = 0;
	}
	pbuf = malloc(sizeof(struct sadb_x_policy));
	if (pbuf == NULL) {
		__ipsec_errcode = EIPSEC_NO_BUFS;
		return -1;
	}
	tlen = sizeof(struct sadb_x_policy);

	memset(pbuf, 0, tlen);
	p = (struct sadb_x_policy *)pbuf;
	p->sadb_x_policy_len = 0;	/* must update later */
	p->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	p->sadb_x_policy_type = p_type;
	p->sadb_x_policy_dir = p_dir;
	p->sadb_x_policy_id = 0;
#ifdef HAVE_PFKEY_POLICY_PRIORITY
	p->sadb_x_policy_priority = p_priority;
#else
    /* fail if given a priority and libipsec was not compiled with 
	   priority support */
	if (p_priority != 0)
	{
		__ipsec_errcode = EIPSEC_PRIORITY_NOT_COMPILED;
		return -1;
	}
#endif

	offset = tlen;

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static int
set_x_request(src, dst)
	struct sockaddr *src, *dst;
{
	struct sadb_x_ipsecrequest *p;
	int reqlen;
	caddr_t n;

	reqlen = sizeof(*p)
		+ (src ? sysdep_sa_len(src) : 0)
		+ (dst ? sysdep_sa_len(dst) : 0);
	tlen += reqlen;		/* increment to total length */

	n = realloc(pbuf, tlen);
	if (n == NULL) {
		__ipsec_errcode = EIPSEC_NO_BUFS;
		return -1;
	}
	pbuf = n;

	p = (struct sadb_x_ipsecrequest *)&pbuf[offset];
	p->sadb_x_ipsecrequest_len = reqlen;
	p->sadb_x_ipsecrequest_proto = p_protocol;
	p->sadb_x_ipsecrequest_mode = p_mode;
	p->sadb_x_ipsecrequest_level = p_level;
	p->sadb_x_ipsecrequest_reqid = p_reqid;
	offset += sizeof(*p);

	if (set_sockaddr(src) || set_sockaddr(dst))
		return -1;

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static int
set_sockaddr(addr)
	struct sockaddr *addr;
{
	if (addr == NULL) {
		__ipsec_errcode = EIPSEC_NO_ERROR;
		return 0;
	}

	/* tlen has already incremented */

	memcpy(&pbuf[offset], addr, sysdep_sa_len(addr));

	offset += sysdep_sa_len(addr);

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static void
policy_parse_request_init()
{
	p_protocol = IPPROTO_IP;
	p_mode = IPSEC_MODE_ANY;
	p_level = IPSEC_LEVEL_DEFAULT;
	p_reqid = 0;
	if (p_src != NULL) {
		free(p_src);
		p_src = NULL;
	}
	if (p_dst != NULL) {
		free(p_dst);
		p_dst = NULL;
	}

	return;
}

static void *
policy_parse(msg, msglen)
	const char *msg;
	int msglen;
{
	int error;

	pbuf = NULL;
	tlen = 0;

	/* initialize */
	p_dir = IPSEC_DIR_INVALID;
	p_type = IPSEC_POLICY_DISCARD;
	policy_parse_request_init();
	__policy__strbuffer__init__(msg);

	error = yyparse();	/* it must be set errcode. */
	__policy__strbuffer__free__();

	if (error) {
		if (pbuf != NULL)
			free(pbuf);
		return NULL;
	}

	/* update total length */
	((struct sadb_x_policy *)pbuf)->sadb_x_policy_len = PFKEY_UNIT64(tlen);

	__ipsec_errcode = EIPSEC_NO_ERROR;

	return pbuf;
}

ipsec_policy_t
ipsec_set_policy(msg, msglen)
	__ipsec_const char *msg;
	int msglen;
{
	caddr_t policy;

	policy = policy_parse(msg, msglen);
	if (policy == NULL) {
		if (__ipsec_errcode == EIPSEC_NO_ERROR)
			__ipsec_errcode = EIPSEC_INVAL_ARGUMENT;
		return NULL;
	}

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return policy;
}

#endif /* CONFIG_HIP_PFKEY */ 
#line 606 "policy_parse.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(void)
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = yyssp - yyss;
    newss = (yyss != 0)
          ? (short *)realloc(yyss, newsize * sizeof(*newss))
          : (short *)malloc(newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    yyss  = newss;
    yyssp = newss + i;
    newvs = (yyvs != 0)
          ? (YYSTYPE *)realloc(yyvs, newsize * sizeof(*newvs))
          : (YYSTYPE *)malloc(newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse(void)
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

#ifdef lint
    goto yyerrlab;
#endif

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 1:
#line 155 "policy_parse.y"
{
			p_dir = yyvsp[-1].num;
			p_type = yyvsp[0].num;

#ifdef HAVE_PFKEY_POLICY_PRIORITY
			p_priority = PRIORITY_DEFAULT;
#else
			p_priority = 0;
#endif

			if (init_x_policy())
				return -1;
		}
break;
case 3:
#line 170 "policy_parse.y"
{
			char *offset_buf;

			p_dir = yyvsp[-3].num;
			p_type = yyvsp[0].num;

			/* buffer big enough to hold a prepended negative sign */
			offset_buf = malloc(yyvsp[-1].val.len + 2);
			if (offset_buf == NULL) 
			{
				__ipsec_errcode = EIPSEC_NO_BUFS;
				return -1;
			}

			/* positive input value means higher priority, therefore lower
			   actual value so that is closer to the beginning of the list */
			sprintf (offset_buf, "-%s", yyvsp[-1].val.buf);

			errno = 0;
			p_priority_offset = atol(offset_buf);

			free(offset_buf);

			if (errno != 0 || p_priority_offset < INT32_MIN)
			{
				__ipsec_errcode = EIPSEC_INVAL_PRIORITY_OFFSET;
				return -1;
			}

			p_priority = PRIORITY_DEFAULT + (u_int32_t) p_priority_offset;

			if (init_x_policy())
				return -1;
		}
break;
case 5:
#line 206 "policy_parse.y"
{
			p_dir = yyvsp[-4].num;
			p_type = yyvsp[0].num;

			errno = 0;
			p_priority_offset = atol(yyvsp[-1].val.buf);

			if (errno != 0 || p_priority_offset > INT32_MAX)
			{
				__ipsec_errcode = EIPSEC_INVAL_PRIORITY_OFFSET;
				return -1;
			}

			/* negative input value means lower priority, therefore higher
			   actual value so that is closer to the end of the list */
			p_priority = PRIORITY_DEFAULT + (u_int32_t) p_priority_offset;

			if (init_x_policy())
				return -1;
		}
break;
case 7:
#line 228 "policy_parse.y"
{
			p_dir = yyvsp[-3].num;
			p_type = yyvsp[0].num;

			p_priority = yyvsp[-1].num32;

			if (init_x_policy())
				return -1;
		}
break;
case 9:
#line 239 "policy_parse.y"
{
			p_dir = yyvsp[-5].num;
			p_type = yyvsp[0].num;

			errno = 0;
			p_priority_offset = atol(yyvsp[-1].val.buf);

			if (errno != 0 || p_priority_offset > PRIORITY_OFFSET_NEGATIVE_MAX)
			{
				__ipsec_errcode = EIPSEC_INVAL_PRIORITY_BASE_OFFSET;
				return -1;
			}

			/* adding value means higher priority, therefore lower
			   actual value so that is closer to the beginning of the list */
			p_priority = yyvsp[-3].num32 - (u_int32_t) p_priority_offset;

			if (init_x_policy())
				return -1;
		}
break;
case 11:
#line 261 "policy_parse.y"
{
			p_dir = yyvsp[-5].num;
			p_type = yyvsp[0].num;

			errno = 0;
			p_priority_offset = atol(yyvsp[-1].val.buf);

			if (errno != 0 || p_priority_offset > PRIORITY_OFFSET_POSITIVE_MAX)
			{
				__ipsec_errcode = EIPSEC_INVAL_PRIORITY_BASE_OFFSET;
				return -1;
			}

			/* subtracting value means lower priority, therefore higher
			   actual value so that is closer to the end of the list */
			p_priority = yyvsp[-3].num32 + (u_int32_t) p_priority_offset;

			if (init_x_policy())
				return -1;
		}
break;
case 13:
#line 283 "policy_parse.y"
{
			p_dir = yyvsp[0].num;
			p_type = 0;	/* ignored it by kernel */

			p_priority = 0;

			if (init_x_policy())
				return -1;
		}
break;
case 15:
#line 296 "policy_parse.y"
{
			if (rule_check() < 0)
				return -1;

			if (set_x_request(p_src, p_dst) < 0)
				return -1;

			policy_parse_request_init();
		}
break;
case 22:
#line 314 "policy_parse.y"
{
			__ipsec_errcode = EIPSEC_FEW_ARGUMENTS;
			return -1;
		}
break;
case 23:
#line 318 "policy_parse.y"
{
			__ipsec_errcode = EIPSEC_FEW_ARGUMENTS;
			return -1;
		}
break;
case 24:
#line 325 "policy_parse.y"
{ p_protocol = yyvsp[0].num; }
break;
case 25:
#line 329 "policy_parse.y"
{ p_mode = yyvsp[0].num; }
break;
case 26:
#line 333 "policy_parse.y"
{
			p_level = yyvsp[0].num;
			p_reqid = 0;
		}
break;
case 27:
#line 337 "policy_parse.y"
{
			p_level = IPSEC_LEVEL_UNIQUE;
			p_reqid = atol(yyvsp[0].val.buf);	/* atol() is good. */
		}
break;
case 28:
#line 344 "policy_parse.y"
{
			p_src = parse_sockaddr(&yyvsp[0].val, NULL);
			if (p_src == NULL)
				return -1;
		}
break;
case 29:
#line 350 "policy_parse.y"
{
			p_dst = parse_sockaddr(&yyvsp[0].val, NULL);
			if (p_dst == NULL)
				return -1;
		}
break;
case 30:
#line 355 "policy_parse.y"
{
			p_src = parse_sockaddr(&yyvsp[-1].val, &yyvsp[0].val);
			if (p_src == NULL)
				return -1;
		}
break;
case 31:
#line 361 "policy_parse.y"
{
			p_dst = parse_sockaddr(&yyvsp[-1].val, &yyvsp[0].val);
			if (p_dst == NULL)
				return -1;
		}
break;
case 32:
#line 366 "policy_parse.y"
{
			if (p_dir != IPSEC_DIR_OUTBOUND) {
				__ipsec_errcode = EIPSEC_INVAL_DIR;
				return -1;
			}
		}
break;
case 33:
#line 372 "policy_parse.y"
{
			if (p_dir != IPSEC_DIR_INBOUND) {
				__ipsec_errcode = EIPSEC_INVAL_DIR;
				return -1;
			}
		}
break;
#line 1028 "policy_parse.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    return (1);

yyaccept:
    return (0);
}


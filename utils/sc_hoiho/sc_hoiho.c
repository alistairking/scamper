/*
 * sc_hoiho: Holistic Orthography of Internet Hostname Observations
 *
 * $Id: sc_hoiho.c,v 1.29 2024/04/26 06:52:24 mjl Exp $
 *
 *         Matthew Luckie
 *         mjl@luckie.org.nz
 *
 *         Marianne Fletcher added code to infer ASN and geo regexes.
 *
 * Copyright (C) 2017-2021 The University of Waikato
 * Copyright (C) 2022-2023 Matthew Luckie
 * Copyright (C) 2023      The Regents of the University of California
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
#include <pcre.h>
#endif

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include "scamper/scamper_addr.h"

#include "mjl_threadpool.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct sc_router sc_router_t;
typedef struct sc_routerinf sc_routerinf_t;
typedef struct sc_routerdom sc_routerdom_t;
typedef struct sc_regex sc_regex_t;
typedef struct sc_regex_sn sc_regex_sn_t;
typedef struct sc_geohint sc_geohint_t;
typedef struct sc_state sc_state_t;

typedef struct sc_css
{
  char           *css;     /* common substrings, each null terminated */
  int             cssc;    /* number of common substrings */
  size_t          len;     /* total length of the common substrings */
  int             count;   /* count variable for counting matches */
} sc_css_t;

typedef struct sc_domain
{
  char           *domain;  /* the domain */
  char           *escape;  /* escaped domain suffix */
  size_t          escapel; /* length of escaped suffix */
  slist_t        *routers; /* of sc_routerdom_t: training routers with an iface in the domain */
  slist_t        *appl;    /* of sc_routerdom_t: other interfaces we can't train from */
  slist_t        *regexes; /* of sc_regex_t: set of regexes built */
  uint32_t        ifacec;  /* number of training interfaces in the domain */
  uint32_t        tpmlen;  /* how wide the tp_mask variable is */
  uint32_t        rtmlen;  /* how wide a mask for router tags should be */

  sc_geohint_t  **geohints; /* domain-specific geohints */
  size_t          geohintc; /* how many domain-specific geohints */

#ifdef HAVE_PTHREAD
  pthread_mutex_t mutex;   /* lock the domain */
  uint8_t         mutex_o; /* mutex is initialised */
#endif
} sc_domain_t;

typedef struct sc_regexn
{
  /* these parameters are properties of the regex node */
  char           *str;      /* the regex */
  uint8_t        *plan;     /* what each extraction corresponds to */
  uint8_t         capc;     /* number of capture elements */

  /* these parameters are set during evaluation */
  uint32_t        matchc;   /* how many times this regex matched */
  uint32_t        tp_c;     /* number of TPs from this regex */
  uint32_t        rt_c;     /* number of routers this regex matched */
} sc_regexn_t;

struct sc_regex
{
  /* these parameters are properties of the regex set */
  sc_regexn_t   **regexes; /* the regexes */
  int             regexc;  /* number of regexes */
  int             score;   /* regex specificity score */
  uint8_t         class;   /* classification */
  sc_domain_t    *dom;     /* the domain this regex is for */

  sc_geohint_t  **geohints; /* learned geohints */
  size_t          geohintc; /* how many learned geohints */

  /* these parameters are set during evaluation */
  uint32_t        matchc;  /* number of matches */
  uint32_t        namelen; /* lengths of names */
  uint32_t        tp_c;    /* true positives */
  uint32_t        fp_c;    /* false positives */
  uint32_t        fne_c;   /* false negatives, matched */
  uint32_t        fnu_c;   /* false negatives, not matched */
  uint32_t        unk_c;   /* unknown extractions */
  uint32_t        ip_c;    /* matches including IP address string */
  uint32_t        sp_c;    /* true positives involving single iface routers */
  uint32_t        sn_c;    /* false negatives involving single iface routers */
  uint32_t        rt_c;    /* router count */
  uint32_t       *tp_mask; /* which interfaces in training set are TPs */
};

typedef struct sc_regex_css
{
  sc_regex_t     *regex;   /* a more specific regex with a literal component */
  sc_css_t       *css;     /* the literal that made it more specific */
  sc_regex_t     *work;    /* current working version */
} sc_regex_css_t;

struct sc_geohint
{
  char           *code;    /* string for the location */
  size_t          codelen; /* length of code via strlen */
  uint32_t        index;   /* unique id for the code */
  uint8_t         type;    /* type: iata, icao, clli, locode, place, facility */
  uint8_t         learned; /* was this geohint learned? or from dictionary */
  uint8_t         flags;   /* flags */
  double          lat;
  double          lng;
  double          latr;
  double          lngr;
  char           *place;   /* place name */
  char            cc[3];   /* two letter country code */
  char            st[4];   /* up to three letters of state code */
  uint32_t        popn;    /* population */
  char           *street;  /* street address */
  char           *facname; /* facility name */
  sc_geohint_t   *head;    /* head when multiple locations have same code */
  sc_geohint_t   *next;    /* next location with the same name */
};

/*
 * sc_clligp
 *
 * map of CLLI geopolitical codes to country codes / state codes
 */
typedef struct sc_clligp
{
  char            gp[3];
  char            cc[3];
  char            st[4];
} sc_clligp_t;

/*
 * sc_country
 *
 */
typedef struct sc_country
{
  char            cc[3];
  char            iso3[4];
  char           *name;
  sc_geohint_t  **hints;
  size_t          hintc;
} sc_country_t;

/*
 * sc_state
 *
 */
struct sc_state
{
  char            st[4];   /* state code */
  char            cc[2];   /* country code */
  char           *name;    /* name of the state */
  sc_state_t     *head;    /* head when multiple states have the same code */
  sc_state_t     *next;    /* next state with the same code */
  sc_geohint_t  **hints;   /* places with this st/cc combination */
  size_t          hintc;   /* number of entries in hints array */
};

/*
 * sc_rtt_t:
 *
 * An RTT sample from a given location.
 */
typedef struct sc_rtt
{
  sc_geohint_t   *vp;  /* where the RTT measurement was from */
  uint16_t        rtt; /* rtt, in milliseconds */
} sc_rtt_t;

typedef struct sc_geotagn
{
  uint8_t         type;
  int16_t         start;
  int16_t         end;
} sc_geotagn_t;

typedef struct sc_geotag
{
  sc_geohint_t   *hint;
  sc_geotagn_t   *tags;
  size_t          tagc;
} sc_geotag_t;

/*
 * sc_geomap
 *
 * structure to store geolocation extracted from a hostname in a consistent
 * form.
 */
typedef struct sc_geomap
{
  char            code[128];
  size_t          codelen;
  char            st[4];
  char            cc[3];
  uint8_t         type;
} sc_geomap_t;

typedef struct sc_geomap2hint
{
  sc_geomap_t     map;
  sc_geohint_t   *hint;
  uint32_t        tp_c;
  uint32_t        fp_c;
} sc_geomap2hint_t;

/*
 * sc_georef
 *
 * structure to help with refinement of the geocode dictionary for a given
 * suffix.
 */
typedef struct sc_georef
{
  sc_geomap_t     map;
  size_t         *offs;
  char            class;
  slist_t        *rd_list;
  slist_t        *ifi_list;
  uint32_t        ifi_tp_c;
  uint32_t       *t_mask;
  uint32_t       *f_mask;
} sc_georef_t;

typedef struct sc_geoeval
{
  sc_geohint_t   *hint;
  uint32_t        tp_c;
  uint8_t         round;
  uint8_t         alloc;
} sc_geoeval_t;

typedef struct sc_iface
{
  char           *name;    /* hostname */
  size_t          len;     /* length of hostname */
  scamper_addr_t *addr;    /* corresponding IP address */
  sc_router_t    *rtr;     /* backpointer to router */
  uint16_t        ip_s;    /* possible start of IP address */
  uint16_t        ip_e;    /* possible end of IP address */
  uint16_t        as_s;    /* possible start of ASN */
  uint16_t        as_e;    /* possible end of ASN */
  int16_t        *asnames; /* possible locations of AS names */
  uint8_t         asnamec; /* number of possible name tags */
  sc_geotag_t    *geos;    /* possible locations of geo tags */
  uint8_t         geoc;    /* number of possible geo tags */
  uint8_t         flags;   /* flags for the interface */
} sc_iface_t;

struct sc_router
{
  sc_iface_t    **ifaces;  /* interfaces inferred to be part of the router */
  size_t          ifacec;  /* number of interfaces involved */
  uint32_t        id;      /* node id */
  uint32_t        asn;     /* inferred owner */
  sc_rtt_t       *rtts;    /* RTT samples */
  size_t          rttc;    /* count of RTT samples */
  uint8_t         flags;   /* flags */
};

typedef struct sc_ifacedom
{
  char           *label;   /* label excluding domain suffix */
  size_t          len;     /* length of the label */
  sc_iface_t     *iface;   /* pointer to the interface */
  sc_routerdom_t *rd;      /* backpointer to the router */
  sc_domain_t    *dom;     /* pointer to the domain */
  uint32_t        id;      /* unique ID for the interface in this domain */
} sc_ifacedom_t;

struct sc_routerdom
{
  sc_ifacedom_t **ifaces;  /* interfaces within domain */
  int             ifacec;  /* number of interfaces within domain */
  sc_router_t    *rtr;     /* complete router */
  sc_css_t       *css;     /* longest common substring within router */
  uint32_t        id;      /* unique ID for the router in this domain */
};

typedef struct sc_routercss
{
  sc_routerdom_t *rd;      /* pointer to router */
  sc_css_t       *css;     /* inferred name, if there was one */
  int             matchc;  /* largest frequency */
} sc_routercss_t;

typedef struct sc_routerload
{
  slist_t        *ifaces;  /* list of sc_iface_t */
  uint32_t        asn;     /* inferred owner */
  uint32_t        id;      /* node id */
  uint8_t         flags;   /* flags */
} sc_routerload_t;

typedef struct sc_ifaceinf
{
  sc_ifacedom_t  *ifd;     /* interface from training */
  sc_css_t       *css;     /* inferred name/ASN */
  sc_routerinf_t *ri;      /* pointer to inferred router */
  sc_geohint_t   *geohint; /* pointer to associated geohint */
  size_t          rtrc;    /* how many interfaces from training routers */
  int             regex;   /* regex id */
  char            class;   /* classification */
  uint8_t         ipm;     /* do we believe extraction contains IP literal */
} sc_ifaceinf_t;

struct sc_routerinf
{
  sc_ifaceinf_t **ifaces;  /* interfaces inferred to belong to the router */
  size_t          ifacec;  /* number of inferred interfaces */
  size_t          maxrtrc; /* max number of interfaces from a training rtr */
  int             ip;      /* name includes IP string */
};

typedef struct sc_as2org
{
  uint32_t        asn;     /* ASN */
  uint32_t        org;     /* org id */
} sc_as2org_t;

typedef struct sc_as2tag
{
  uint32_t        asn;     /* ASN */
  char           *tag;     /* tag */
  splaytree_t    *sxes;    /* suffixes with the ASN/tag mapping */
} sc_as2tag_t;

/*
 * sc_rttload_t:
 *
 * a structure to help load RTT samples into sc_router_t.
 */
typedef struct sc_rttload
{
  sc_router_t   **routers;
  size_t          routerc;
  sc_router_t    *rtr;
  uint32_t        id;
  sc_rtt_t       *rtts;
  size_t          rttc;
  size_t          rttm;
  char          **unknown;
  size_t          unknownc;
} sc_rttload_t;

/*
 * sc_regex_sn
 *
 * a structure to help decide how to merge regexes into sets
 */
struct sc_regex_sn
{
  sc_regex_t     *re;      /* regex that we might improve on */
  sc_regex_sn_t  *refn;    /* pointer to a related refn */
  sc_regex_t     *base;    /* the original regex */
  slist_t        *snis;    /* list of sc_regex_sni_t structures to fill */
  int             snic;    /* number of sni's left to process */
  int             done;    /* whether or not we're done with this regex */

#ifdef HAVE_PTHREAD
  pthread_mutex_t mutex;   /* lock the sn */
  uint8_t         mutex_o; /* mutex is initialised */
#endif
};

/*
 * sc_regex_sni
 *
 * structure that each thread that permutes the regexes uses
 */
typedef struct sc_regex_sni
{
  sc_regex_sn_t  *work;    /* pointer to the parent sc_regex_sn_t */
  sc_regex_t     *re;      /* a regex to consider */
  sc_regex_t     *out;     /* the "best" regex among the permutations */
} sc_regex_sni_t;

/*
 * sc_regex_mn
 *
 * a structure to help decide how to merge regexes that differ by a
 * single simple string
 */
typedef struct sc_regex_mn
{
  sc_regex_t     *re;
  slist_node_t   *sn;
} sc_regex_mn_t;

typedef struct sc_domain_sn
{
  slist_t        *work;    /* of sc_regex_sn: current working list of regexes */
  slist_t        *base;    /* of sc_regex_sn: base list of all regexes */
  int             done;    /* whether or not we're done with this domain */
} sc_domain_fn_t;

typedef struct sc_ifdptr
{
  sc_ifacedom_t  *ifd;     /* interface */
  void           *ptr;     /* tag */
} sc_ifdptr_t;

typedef struct sc_ptrc
{
  void           *ptr;
  size_t          c;
} sc_ptrc_t;

typedef struct sc_uint32c
{
  uint32_t        num;
  size_t          c;
} sc_uint32c_t;

typedef struct sc_strlist
{
  char           *str;
  slist_t        *list;
} sc_strlist_t;

/*
 * sc_charpos_t:
 *
 * a string representation of an IP address in hexadecimal.
 */
typedef struct sc_charpos
{
  char            c[32];   /* the character for the nibble */
  int             pos[32]; /* the position of the character in the string */
  int             left;    /* the left-most digit in the string */
  int             right;   /* the right-most digit in the string */
  int             digits;  /* the number of digits in the string */
} sc_charpos_t;

typedef struct sc_charposl
{
  int            *pos;
  int             posc;
} sc_charposl_t;

typedef struct sc_rework
{
  size_t             c;          /* number of regexes in the set */
  size_t             k;          /* which regex matched */
  size_t             m;          /* number of elements in ovector */
#ifdef HAVE_PCRE2
  pcre2_code       **pcre;
  pcre2_match_data  *match_data;
  PCRE2_SIZE        *ovector;
#else
  pcre             **pcre;
  pcre_extra       **study;
  int               *ovector;
  int                n;          /* max elements in ovector */
#endif
} sc_rework_t;

typedef struct sc_suffix
{
  struct sc_suffix  *parent;
  char              *label;
  int                end;
  struct sc_suffix **suffixes;
  size_t             suffixc;
} sc_suffix_t;

/*
 * sc_lcs_pt
 *
 */
typedef struct sc_lcs_pt
{
  int S_start, S_end;
  int T_start, T_end;
} sc_lcs_pt_t;

typedef struct sc_rebuild
{
  char   buf[2048]; /* regex built so far */
  size_t off;       /* length of regex built so far */
  int    score;     /* specificity score so far */
  size_t f;         /* which of the builder functions should run next */
  int    x;         /* where in the bits array we are up to */
  int    o;         /* where in the hostname string we are up to */
  int    any;       /* have we used .+ in this regex yet? */
  int    capc;      /* the number of capture elements so far */
} sc_rebuild_t;

/*
 * sc_rebuild_p
 *
 * parameters passed in to sc_regex_build that do not change
 */
typedef struct sc_rebuild_p
{
  sc_domain_t *dom;
  const int   *bits;
  int          bitc;
  char        *buf;
  size_t       len;
} sc_rebuild_p_t;

typedef struct sc_remerge
{
  sc_css_t    *css;  /* the part of the regex in common among all regexes */
  slist_t     *list; /* list of strings that differ between the regexes */
  int          opt;  /* whether or not the diff strings are required */
} sc_remerge_t;

typedef struct sc_reasn
{
  splaytree_t  *org;
  splaytree_t  *inf;
  splaytree_t **infs;
  splaytree_t  *ext;
  splaytree_t **exts;
  uint32_t      sib;
} sc_reasn_t;

typedef struct sc_segscore
{
  char         *seg;
  int           score;
  splaytree_t  *tree;
} sc_segscore_t;

typedef struct sc_dump4
{
  char          *render;
  char          *rtt;
  char           class;
  int            regex;
  sc_geohint_t  *vp;
  sc_iface_t    *iface;
} sc_dump4_t;

typedef struct sc_dump
{
  char  *descr;
  char  *label;
  int  (*func)(void);
} sc_dump_t;

#define BIT_TYPE_SKIP          0
#define BIT_TYPE_CAPTURE       1
#define BIT_TYPE_SKIP_LIT      2
#define BIT_TYPE_CAPTURE_LIT   3
#define BIT_TYPE_SKIP_DIGIT    4
#define BIT_TYPE_CAPTURE_DIGIT 5
#define BIT_TYPE_IP_DEC        6
#define BIT_TYPE_IP_HEX        7
#define BIT_TYPE_GEO_FACILITY  8
#define BIT_TYPE_GEO_IATA      9
#define BIT_TYPE_GEO_ICAO      10
#define BIT_TYPE_GEO_CLLI      11
#define BIT_TYPE_GEO_LOCODE    12
#define BIT_TYPE_GEO_PLACE     13
#define BIT_TYPE_GEO_CC        14
#define BIT_TYPE_GEO_ST        15

#define BIT_TYPE_MIN         0
#define BIT_TYPE_MAX         15

#define GEOHINT_TYPE_FACILITY 1
#define GEOHINT_TYPE_IATA     2
#define GEOHINT_TYPE_ICAO     3
#define GEOHINT_TYPE_CLLI     4
#define GEOHINT_TYPE_LOCODE   5
#define GEOHINT_TYPE_PLACE    6
#define GEOHINT_TYPE_CC       7
#define GEOHINT_TYPE_ST       8
#define GEOHINT_TYPE_COUNTRY  9
#define GEOHINT_TYPE_STATE    10
#define GEOHINT_TYPE_VP       11

#define GEOHINT_FLAG_FACILITY 0x01

#define FUDGE_DEF 1
#define FUDGE_MAX 3

#define CLOSE_DEF 2

#define LIGHT_SPEED_DEF      204.190477 /* kilometres per millisecond */
#define LIGHT_SPEED_MAX      299792458  /* metres per second */

#define SC_IFACE_FLAG_AS     0x01
#define SC_IFACE_FLAG_AS_ED1 0x02
#define SC_IFACE_FLAG_IP     0x04
#define SC_IFACE_FLAG_IP_HEX 0x08

#define SC_ROUTER_FLAG_ID  0x01
#define SC_ROUTER_FLAG_ASN 0x02

#define RE_CLASS_POOR      0
#define RE_CLASS_GOOD      1
#define RE_CLASS_PROM      2
#define RE_CLASS_SINGLE    3

#define STOP_ASN_MAX       4
#define STOP_ASNAMES_MAX   6
#define STOP_ALIAS_MAX     8
#define STOP_GEO_MAX       5
#define STOP_IP_MAX        1

#define REFINE_TP    0x001
#define REFINE_FNE   0x002
#define REFINE_CLASS 0x004
#define REFINE_FNU   0x008
#define REFINE_SETS  0x010
#define REFINE_IP    0x020
#define REFINE_FP    0x040
#define REFINE_MERGE 0x080
#define REFINE_DICT  0x100

#define REFINE_ALL   (REFINE_TP | REFINE_FNE | REFINE_CLASS | REFINE_FNU | \
		      REFINE_SETS | REFINE_IP | REFINE_FP | REFINE_MERGE | \
		      REFINE_DICT)

static int dump_1(void);
static int dump_2(void);
static int dump_3(void);
static int dump_4(void);

typedef size_t (*sc_regex_build_t)(const char *,           /* name */
				   const sc_rebuild_p_t *, /* build params */
				   const sc_rebuild_t *,   /* build state */
				   int *,                  /* score */
				   int *);                 /* name offset */

static char            *router_file  = NULL;
static char            *suffix_file  = NULL;
static sc_suffix_t     *suffix_root  = NULL;
static splaytree_t     *domain_tree  = NULL;    /* of sc_domain_t */
static slist_t         *domain_list  = NULL;    /* of sc_domain_t */
static slist_t         *router_list  = NULL;    /* of sc_router_t */
static char            *domain_eval  = NULL;
static const char      *regex_eval   = NULL;
static char            *sibling_file = NULL;
static sc_as2org_t    **siblings     = NULL;
static size_t           siblingc     = 0;
static uint32_t         sibling_id   = 1;
static const char      *rtt_file     = NULL;
static uint8_t          rtt_fudge    = FUDGE_DEF;
static uint8_t          rtt_close    = CLOSE_DEF;
static double           light_speed  = LIGHT_SPEED_DEF;
static sc_as2tag_t    **tag2ass      = NULL;
static size_t           tag2asc      = 0;
static slist_t         *dicts        = NULL;
static sc_geohint_t   **geohints     = NULL;
static size_t           geohintc     = 0;
static sc_geohint_t   **geohint_facs = NULL;
static size_t           geohint_facc = 0;
static sc_geohint_t   **geohint_pls[26];
static size_t           geohint_plc[26];
static sc_country_t   **geohint_cous = NULL; /* countries, sorted by cc */
static size_t           geohint_couc = 0;
static sc_state_t     **geohint_stas = NULL; /* states, sorted by st/cc */
static size_t           geohint_stac = 0;
static sc_geohint_t   **geohint_vps  = NULL;
static size_t           geohint_vpc  = 0;
static sc_clligp_t    **clligps      = NULL;
static size_t           clligpc      = 0;
static uint16_t         refine_mask  = 0;
static int              thin_same    = 1;
static int              thin_matchc  = 1;
static int              thin_mask    = 1;
static int              do_debug     = 0;
static int              do_ri        = 0;
static int              do_appl      = 0;
static int              do_showclass = 0;
static int              do_show      = 0;
static int              do_jit       = 1;
static int              do_json      = 0;
static int              do_learnalias = 0;
static int              do_learnasn  = 0;
static int              do_learnasnames = 0;
static int              do_learngeo  = 0;
static int              do_loadonly  = 0;
static int              do_ed1       = 1;
static int              do_ip        = 1;
static int              do_splitlocode = 0;
static int              no_clli      = 0;
static int              ip_v         = 4;
static int              stop_id      = 0;
static long             threadc      = -1;
static threadpool_t    *threadp      = NULL;
static long             dump_id      = 1;
static const sc_dump_t  dump_funcs[] = {
  {NULL, NULL, NULL},
  {"dump working set of regexes", "working-set", dump_1},
  {"apply best regexes to routers", "routers", dump_2},
  {"dump best regex for each domain", "best-regex", dump_3},
  {"apply best regexes to interfaces", "interfaces", dump_4},
};
static int              dump_funcc = sizeof(dump_funcs) / sizeof(sc_dump_t);

#define OPT_THREADC   0x0001
#define OPT_DUMPID    0x0002
#define OPT_DOMAIN    0x0004
#define OPT_REGEX     0x0008
#define OPT_OPTION    0x0010
#define OPT_IPV6      0x0020
#define OPT_STOPID    0x0040
#define OPT_SIBLINGS  0x0080
#define OPT_DICT      0x0100
#define OPT_RTTS      0x0200
#define OPT_FUDGE     0x0400
#define OPT_LIGHTSPEED 0x0800

static void usage(uint32_t opts)
{
  int i;

  fprintf(stderr,
	  "usage: sc_hoiho [-6] [-d dumpid] [-D domain] [-f rtt-fudge]\n"
	  "                [-g dict] [-l light-speed] [-O options]\n"
	  "                [-r regex] [-R rtts] [-s stopid] [-S siblings]\n"
	  "                [-t threadc]\n"
	  "                <public-suffix-list> <router-file>\n");

  if(opts == 0)
    {
      fprintf(stderr, "\n       sc_hoiho -?\n\n");
      return;
    }
  fprintf(stderr, "\n");

  if(opts & OPT_IPV6)
    fprintf(stderr, "       -6: input files are IPv6\n");
  if(opts & OPT_DUMPID)
    {
      fprintf(stderr, "       -d: dump id\n");
      for(i=1; i<dump_funcc; i++)
	{
	  fprintf(stderr, "           %d", i);
	  if(dump_funcs[i].label != NULL)
	    fprintf(stderr, " / %s", dump_funcs[i].label);
	  fprintf(stderr, ": %s\n", dump_funcs[i].descr);
	}
    }

  if(opts & OPT_DOMAIN)
    fprintf(stderr, "       -D: the domain suffix to operate on\n");

  if(opts & OPT_FUDGE)
    fprintf(stderr, "       -f: fudge factor for RTTs, def %ds max %dms\n",
	    FUDGE_DEF, FUDGE_MAX);

  if(opts & OPT_DICT)
    fprintf(stderr, "       -g: a dictionary file with geo / asnames\n");

  if(opts & OPT_LIGHTSPEED)
    fprintf(stderr, "       -l: metres covered in one second, max %u\n",
	    LIGHT_SPEED_MAX);

  if(opts & OPT_OPTION)
    {
      fprintf(stderr,
	      "       -O: options\n"
	      "           application: show outcome of regexes\n"
	      "           debug: output debugging information\n"
	      "           json: output inferences in json format\n"
	      "           learnalias: learn when hostnames embed router names\n"
	      "           learnasn: learn when hostnames embed ASN\n"
	      "           learnasnames: learn when hostnames embed AS names\n"
	      "           learngeo: learn when hostnames embed geo codes\n"
	      "           loadonly: stop after loading data\n"
	      "           noclli: do not load CLLI codes from dictionary\n"
	      "           noed1: skip ASNs w edit distance of one\n"
	      "           noip: do not infer embedded IP literals\n"
	      "           nojit: do not use PCRE JIT complication\n"
	      "           norefine: do not refine regexes\n"
	      "           norefine-tp: do not do TP refinement\n"
	      "           refine-tp: do TP refinement\n"
	      "           norefine-fne: do not do FNE refinement\n"
	      "           refine-fne: do FNE refinement\n"
	      "           norefine-class: do not do class refinement\n"
	      "           refine-class: do class refinement\n"
	      "           norefine-fnu: do not do FNU refinement\n"
	      "           refine-fnu: do FNU refinement\n"
	      "           norefine-sets: do not build sets\n"
	      "           refine-sets: build sets\n"
	      "           norefine-ip: do not build IP filters\n"
	      "           refine-ip: build IP filters\n"
	      "           norefine-fp: do not build FP filters\n"
	      "           refine-fp: build FP filters\n"
	      "           norefine-dict: do not refine the learned dictionary\n"
	      "           refine-dict: refine the learned dictionary\n"
	      "           nothin: do not thin redundant regexes\n"
	      "           nothin-matchc: do not thin regexes with few matches\n"
	      "           thin-matchc: thin regexes with few matches\n"
	      "           nothin-same: do not thin equivalent regexes\n"
	      "           thin-same: thin equivalent regexes\n"
	      "           randindex: compute the Rand Index metric\n"
	      "           show-class: only show classified names\n"
	      "           show-good: show good conventions\n"
	      "           show-prom: show promising conventions\n"
	      "           show-poor: show poor conventions\n"
	      "           split-locode: allow split locode\n");
    }

  if(opts & OPT_REGEX)
    fprintf(stderr, "       -r: the regex (or file of regexes) to apply\n");
  if(opts & OPT_RTTS)
    fprintf(stderr, "       -R: RTT file\n");
  if(opts & OPT_STOPID)
    fprintf(stderr, "       -s: stop at specified step #\n");
  if(opts & OPT_SIBLINGS)
    fprintf(stderr, "       -S: siblings file\n");
  if(opts & OPT_THREADC)
    fprintf(stderr, "       -t: the number of threads to use\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  char *opts = "6d:D:f:g:l:O:r:R:s:S:t:?";
  char *opt_threadc = NULL, *opt_dumpid = NULL, *opt_stopid = NULL;
  char *opt_fudge = NULL, *opt_lightspeed = NULL;
  uint16_t refine = 0, norefine = 0;
  struct stat sb;
  long lo;
  int ch, x;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case '6':
	  ip_v = 6;
	  break;

	case 'd':
	  opt_dumpid = optarg;
	  break;

	case 'D':
	  domain_eval = optarg;
	  break;

	case 'f':
	  opt_fudge = optarg;
	  break;

	case 'g':
	  if((dicts == NULL && (dicts = slist_alloc()) == NULL) ||
	     slist_tail_push(dicts, optarg) == NULL)
	    return -1;
	  break;

	case 'l':
	  opt_lightspeed = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "application") == 0)
	    do_appl = 1;
	  else if(strcasecmp(optarg, "debug") == 0)
	    do_debug = 1;
	  else if(strcasecmp(optarg, "json") == 0)
	    do_json = 1;
	  else if(strcasecmp(optarg, "learnalias") == 0)
	    do_learnalias = 1;
	  else if(strcasecmp(optarg, "learnasn") == 0)
	    do_learnasn = 1;
	  else if(strcasecmp(optarg, "learnasnames") == 0)
	    do_learnasnames = 1;
	  else if(strcasecmp(optarg, "learngeo") == 0)
	    do_learngeo = 1;
	  else if(strcasecmp(optarg, "loadonly") == 0)
	    do_loadonly = 1;
	  else if(strcasecmp(optarg, "noclli") == 0)
	    no_clli = 1;
	  else if(strcasecmp(optarg, "noed1") == 0)
	    do_ed1 = 0;
	  else if(strcasecmp(optarg, "noip") == 0)
	    do_ip = 0;
	  else if(strcasecmp(optarg, "nojit") == 0)
	    do_jit = 0;
	  else if(strcasecmp(optarg, "norefine") == 0)
	    norefine = REFINE_ALL;
	  else if(strcasecmp(optarg, "norefine-ip") == 0)
	    norefine |= REFINE_IP;
	  else if(strcasecmp(optarg, "refine-ip") == 0)
	    refine |= REFINE_IP;
	  else if(strcasecmp(optarg, "norefine-sets") == 0)
	    norefine |= REFINE_SETS;
	  else if(strcasecmp(optarg, "refine-sets") == 0)
	    refine |= REFINE_SETS;
	  else if(strcasecmp(optarg, "norefine-fp") == 0)
	    norefine |= REFINE_FP;
	  else if(strcasecmp(optarg, "refine-fp") == 0)
	    refine |= REFINE_FP;
	  else if(strcasecmp(optarg, "norefine-fne") == 0)
	    norefine |= REFINE_FNE;
	  else if(strcasecmp(optarg, "refine-fne") == 0)
	    refine |= REFINE_FNE;
	  else if(strcasecmp(optarg, "norefine-fnu") == 0)
	    norefine |= REFINE_FNU;
	  else if(strcasecmp(optarg, "refine-fnu") == 0)
	    refine |= REFINE_FNU;
	  else if(strcasecmp(optarg, "norefine-tp") == 0)
	    norefine |= REFINE_TP;
	  else if(strcasecmp(optarg, "refine-tp") == 0)
	    refine |= REFINE_TP;
	  else if(strcasecmp(optarg, "norefine-class") == 0)
	    norefine |= REFINE_CLASS;
	  else if(strcasecmp(optarg, "refine-class") == 0)
	    refine |= REFINE_CLASS;
	  else if(strcasecmp(optarg, "norefine-merge") == 0)
	    norefine |= REFINE_MERGE;
	  else if(strcasecmp(optarg, "refine-merge") == 0)
	    refine |= REFINE_MERGE;
	  else if(strcasecmp(optarg, "norefine-dict") == 0)
	    norefine |= REFINE_DICT;
	  else if(strcasecmp(optarg, "refine-dict") == 0)
	    refine |= REFINE_DICT;
	  else if(strcasecmp(optarg, "nothin") == 0)
	    {
	      thin_matchc = 0;
	      thin_same = 0;
	      thin_mask = 0;
	    }
	  else if(strcasecmp(optarg, "thin-matchc") == 0)
	    thin_matchc = 1;
	  else if(strcasecmp(optarg, "nothin-matchc") == 0)
	    thin_matchc = 0;
	  else if(strcasecmp(optarg, "thin-same") == 0)
	    thin_same = 1;
	  else if(strcasecmp(optarg, "nothin-same") == 0)
	    thin_same = 0;
	  else if(strcasecmp(optarg, "thin-mask") == 0)
	    thin_mask = 1;
	  else if(strcasecmp(optarg, "nothin-mask") == 0)
	    thin_mask = 0;
	  else if(strcasecmp(optarg, "randindex") == 0)
	    do_ri = 1;
	  else if(strcasecmp(optarg, "show-class") == 0)
	    do_showclass = 1;
	  else if(strcasecmp(optarg, "show-good") == 0)
	    do_show |= (1 << RE_CLASS_GOOD);
	  else if(strcasecmp(optarg, "show-prom") == 0 ||
		  strcasecmp(optarg, "show-promising") == 0)
	    do_show |= (1 << RE_CLASS_PROM);
	  else if(strcasecmp(optarg, "show-poor") == 0)
	    do_show |= (1 << RE_CLASS_POOR);
	  else if(strcasecmp(optarg, "split-locode") == 0)
	    do_splitlocode = 1;
	  else
	    {
	      usage(0);
	      return -1;
	    }
	  break;

	case 'r':
	  regex_eval = optarg;
	  break;

	case 'R':
	  rtt_file = optarg;
	  break;

	case 's':
	  opt_stopid = optarg;
	  break;

	case 'S':
	  sibling_file = optarg;
	  break;

	case 't':
	  opt_threadc = optarg;
	  break;

	case '?':
	  usage(0xffffffff);
	  return -1;

	default:
	  usage(0);
	  return -1;
	}
    }

  if(argc - optind != 2)
    {
      usage(0);
      return -1;
    }

  /* only one of -O norefine-* or -O refine-* can be used */
  if(refine != 0 && norefine != 0)
    {
      usage(OPT_OPTION);
      return -1;
    }

  if(regex_eval != NULL)
    {
      /*
       * -r can be either a single regex, or a file.  if its a single
       * regex (cannot stat the regex file), the user must specify a
       * domain.
       */
      if(stat(regex_eval, &sb) != 0 && domain_eval == NULL)
	{
	  usage(OPT_REGEX|OPT_DOMAIN);
	  return -1;
	}

      /*
       * by default, we will not refine the supplied regexes, so
       * we should not expect any use of norefine-*
       */
      if(norefine != 0 && norefine != REFINE_ALL)
	{
	  usage(OPT_REGEX | OPT_OPTION);
	  return -1;
	}

      refine_mask = refine;
    }
  else
    {
      if(refine != 0)
	refine_mask = refine;
      else
	refine_mask = REFINE_ALL & (~norefine);
    }

  if(opt_dumpid != NULL)
    {
      if(string_isnumber(opt_dumpid) != 0)
	{
	  if(string_tolong(opt_dumpid, &lo) != 0 || lo < 1 || lo >= dump_funcc)
	    {
	      usage(OPT_DUMPID);
	      return -1;
	    }
	  dump_id = lo;
	}
      else
	{
	  for(x=1; x<dump_funcc; x++)
	    {
	      if(dump_funcs[x].label == NULL)
		continue;
	      if(strcasecmp(dump_funcs[x].label, opt_dumpid) == 0)
		break;
	    }
	  if(x == dump_funcc)
	    {
	      usage(OPT_DUMPID);
	      return -1;
	    }
	  dump_id = x;
	}
    }

  if(opt_threadc != NULL)
    {
      if(string_tolong(opt_threadc, &lo) != 0 || lo < 0)
	{
	  usage(OPT_THREADC);
	  return -1;
	}
#ifndef HAVE_PTHREAD
      if(lo > 1)
	{
	  usage(OPT_THREADC);
	  return -1;
	}
#endif
      threadc = lo;
    }

  if(do_learnalias == 0 && do_learnasn == 0 && do_learnasnames == 0 &&
     do_learngeo == 0)
    do_learnalias = 1;

  if(opt_stopid != NULL)
    {
      if(string_tolong(opt_stopid, &lo) != 0 || lo < 0 ||
	 (do_learnasn != 0 && lo > STOP_ASN_MAX) ||
	 (do_learnasnames != 0 && lo > STOP_ASNAMES_MAX) ||
	 (do_learnalias != 0 && lo > STOP_ALIAS_MAX) ||
	 (do_learngeo != 0 && lo > STOP_GEO_MAX))
	{
	  usage(OPT_STOPID);
	  return -1;
	}
      stop_id = lo;
    }
  else
    {
      if(do_learnasn != 0) stop_id = STOP_ASN_MAX;
      else if(do_learnasnames != 0) stop_id = STOP_ASNAMES_MAX;
      else if(do_learnalias != 0) stop_id = STOP_ALIAS_MAX;
      else if(do_learngeo != 0) stop_id = STOP_GEO_MAX;
    }

  if(do_learngeo != 0)
    {
      if(dicts == NULL)
	{
	  usage(OPT_DICT);
	  return -1;
	}
      if(rtt_file == NULL)
	{
	  usage(OPT_RTTS);
	  return -1;
	}

      if(opt_fudge != NULL)
	{
	  if(string_isdigit(opt_fudge) == 0 ||
	     string_tolong(opt_fudge, &lo) != 0 || lo < 0 || lo > FUDGE_MAX)
	    {
	      usage(OPT_FUDGE);
	      return -1;
	    }
	  rtt_fudge = (uint8_t)lo;
	}

      if(opt_lightspeed != NULL)
	{
	  if(string_isdigit(opt_lightspeed) == 0 ||
	     string_tolong(opt_lightspeed, &lo) != 0 ||
	     lo < 0 || lo > LIGHT_SPEED_MAX)
	    {
	      usage(OPT_LIGHTSPEED);
	      return -1;
	    }
	  light_speed = ((double)lo) / 1000000; /* meters per millisecond */
	}
    }

  suffix_file = argv[optind + 0];
  router_file = argv[optind + 1];
  return 0;
}

static int ptrcmp(const void *a, const void *b)
{
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int cceq(const char *cc, const sc_geohint_t *hint)
{
  if(strcasecmp(cc, hint->cc) == 0 ||
     (strcasecmp(cc, "cn") == 0 && strcasecmp(hint->cc, "hk") == 0) ||
     (strcasecmp(cc, "uk") == 0 && strcasecmp(hint->cc, "gb") == 0) ||
     (strcasecmp(cc, "sa") == 0 && strcasecmp(hint->cc, "za") == 0))
    return 1;
  return 0;
}

static uint32_t mask_cnt(uint32_t *mask, uint32_t len)
{
  uint32_t i, c = 0;
  for(i=0; i<len; i++)
    c += countbits32(mask[i]);
  return c;
}

static int class_cmp(uint8_t a, uint8_t b)
{
  /*
   * rank order:
   * good = 0
   * promising = 1
   * poor = 2
   * single = 3
   */
  static const uint8_t rank[] = {2, 0, 1, 3};
  uint8_t ar, br;
  assert(a <= 3);
  assert(b <= 3);
  ar = rank[a]; br = rank[b];
  if(ar < br) return -1;
  if(ar > br) return  1;
  return 0;
}

static int mask_isset(uint32_t *mask, uint32_t len, uint32_t bit)
{
  uint32_t x, i;
  assert(bit > 0);
  x = (bit - 1) / 32;
  i = (bit - 1) % 32;
  assert(x < len);
  if(mask[x] & (0x1 << i))
    return 1;
  return 0;
}

static void mask_set(uint32_t *mask, uint32_t len, uint32_t bit)
{
  uint32_t x, i;
  assert(bit > 0);
  x = (bit - 1) / 32;
  i = (bit - 1) % 32;
  assert(x < len);
  mask[x] |= (0x1 << i);
  return;
}

static void sc_dump4_free(sc_dump4_t *d4)
{
  if(d4->render != NULL) free(d4->render);
  if(d4->rtt != NULL) free(d4->rtt);
  free(d4);
  return;
}

static int sc_domain_lock(sc_domain_t *dom)
{
#ifdef HAVE_PTHREAD
  if(pthread_mutex_lock(&dom->mutex) != 0)
    return -1;
#endif
  return 0;
}

static void sc_domain_unlock(sc_domain_t *dom)
{
#ifdef HAVE_PTHREAD
  pthread_mutex_unlock(&dom->mutex);
#endif
  return;
}

static int sc_uint32c_num_cmp(const sc_uint32c_t *a, const sc_uint32c_t *b)
{
  if(a->num < b->num) return -1;
  if(a->num > b->num) return  1;
  return 0;
}

static int sc_uint32c_c_cmp(const sc_uint32c_t *a, const sc_uint32c_t *b)
{
  if(a->c > b->c) return -1;
  if(a->c < b->c) return  1;
  return 0;
}

static sc_uint32c_t *sc_uint32c_get(splaytree_t *tree, uint32_t num)
{
  sc_uint32c_t *ptr, fm;
  fm.num = num;
  if((ptr = splaytree_find(tree, &fm)) != NULL)
    return ptr;
  if((ptr = malloc(sizeof(sc_uint32c_t))) == NULL)
    return NULL;
  ptr->num = num;
  ptr->c = 0;
  if(splaytree_insert(tree, ptr) == NULL)
    {
      free(ptr);
      return NULL;
    }
  return ptr;
}

static int tree_mincount(splaytree_t *a, splaytree_t *b)
{
  int ac, bc;
  ac = splaytree_count(a);
  bc = splaytree_count(b);
  if(ac <= bc) return ac;
  return bc;
}

static int slist_to_dlist(void *entry, void *ptr)
{
  if(dlist_tail_push((dlist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static int dlist_to_slist(void *entry, void *ptr)
{
  if(slist_tail_push((slist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static int tree_to_slist(void *ptr, void *entry)
{
  if(slist_tail_push((slist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static int tree_to_dlist(void *ptr, void *entry)
{
  if(dlist_tail_push((dlist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static int dlx(int al, int bl, int i, int j)
{
  assert(al >= 0); assert(bl >= 0);
  assert(i >= -1); assert(j >= -1);
  assert(i <= al); assert(j <= bl);
  return ((i + 1) * (bl + 2)) + (j + 1);
}

/*
 * dled
 *
 * implement Damerau-Levenshtein distance calculation, based off wikipedia's
 * description of the solution.
 */
static int dled(const char *a, const char *b)
{
  int al, bl, maxdist, i, j, ma[4], k, l, da[256], db, cost, *d = NULL;

  al = strlen(a);
  bl = strlen(b);
  maxdist = al + bl;
  memset(da, 0, sizeof(da));

  if((d = malloc(sizeof(int) * (al + 2) * (bl + 2))) == NULL)
    return -1;
  d[dlx(al, bl, -1, -1)] = maxdist;
  for(i=0; i<=al; i++)
    {
      d[dlx(al, bl, i, -1)] = maxdist;
      d[dlx(al, bl, i, 0)] = i;
    }
  for(j=0; j<=bl; j++)
    {
      d[dlx(al, bl, -1, j)] = maxdist;
      d[dlx(al, bl, 0, j)] = j;
    }

  for(i=1; i<=al; i++)
    {
      db = 0;
      for(j=1; j<=bl; j++)
	{
	  k = da[(int)b[j-1]];
	  l = db;

	  if(a[i-1] == b[j-1])
	    {
	      cost = 0;
	      db = j;
	    }
	  else cost = 1;

	  /* substitution */
	  ma[0] = d[dlx(al, bl, i-1, j-1)] + cost;
	  /* insertion */
	  ma[1] = d[dlx(al, bl, i, j-1)] + 1;
	  /* deletion */
	  ma[2] = d[dlx(al, bl, i-1, j)] + 1;
	  /* transposition */
	  ma[3] = d[dlx(al, bl, k-1, l-1)] + (i-k-1) + 1 + (j-l-1);

	  d[dlx(al, bl, i, j)] = min_array(ma, 4);
	}

      da[(int)a[i-1]] = i;
    }

#if 0
  printf("%s %s\n", a, b);
  for(i=-1; i<=al; i++)
    {
      for(j=-1; j<=bl; j++)
	{
	  printf(" %2d", d[dlx(al,bl,i,j)]);
	}
      printf("\n");
    }
#endif

  k = d[dlx(al, bl, al, bl)];
  assert(k >= 0);
  free(d);
  return k;
}

static int str_tojson(const char *str, char *buf, size_t len)
{
  size_t off = 0;

  if(str == NULL || *str == '\0')
    {
      if(len < 1)
	return -1;
      buf[0] = '\0';
      return 0;
    }

  while(*str != '\0')
    {
      if(*str == '\\' || *str == '#')
	{
	  if(len - off < 3)
	    return -1;
	  buf[off++] = '\\';
	}
      else
	{
	  if(len - off < 2 || isprint((unsigned char)*str) == 0)
	    return -1;
	}
      buf[off++] = *str;
      str++;
    }

  assert(len - off > 0);
  buf[off] = '\0';
  return 0;
}

static void json_print(const char *str)
{
  if(str == NULL)
    return;
  while(*str != '\0')
    {
      if(*str == '\\')
	printf("\\\\");
      else if(*str == '"')
	printf("\\\"");
      else
	printf("%c", *str);
      str++;
    }
  return;
}

static int sc_ptrc_ptr_cmp(const sc_ptrc_t *a, const sc_ptrc_t *b)
{
  if(a->ptr < b->ptr) return -1;
  if(a->ptr > b->ptr) return  1;
  return 0;
}

static sc_ptrc_t *sc_ptrc_find(splaytree_t *tree, void *ptr)
{
  sc_ptrc_t fm; fm.ptr = ptr;
  return splaytree_find(tree, &fm);
}

static void sc_ptrc_free2(sc_ptrc_t *ptrc)
{
  if(ptrc != NULL)
    {
      if(ptrc->ptr != NULL) free(ptrc->ptr);
      free(ptrc);
    }
  return;
}

static void sc_ptrc_free(sc_ptrc_t *ptrc)
{
  free(ptrc);
  return;
}

static sc_ptrc_t *sc_ptrc_get(splaytree_t *tree, void *ptr)
{
  sc_ptrc_t *ptrc;
  if((ptrc = sc_ptrc_find(tree, ptr)) != NULL)
    return ptrc;
  if((ptrc = malloc(sizeof(sc_ptrc_t))) == NULL)
    goto err;
  ptrc->ptr = ptr;
  ptrc->c = 0;
  if(splaytree_insert(tree, ptrc) == NULL)
    goto err;
  return ptrc;

 err:
  if(ptrc != NULL) free(ptrc);
  return NULL;
}

static void sc_strlist_free(sc_strlist_t *sl)
{
  if(sl->str != NULL) free(sl->str);
  if(sl->list != NULL) slist_free(sl->list);
  free(sl);
  return;
}

static int sc_strlist_cmp(const sc_strlist_t *a, const sc_strlist_t *b)
{
  return strcmp(a->str, b->str);
}

static sc_strlist_t *sc_strlist_find(splaytree_t *tree, char *str)
{
  sc_strlist_t fm; fm.str = str;
  return splaytree_find(tree, &fm);
}

static sc_strlist_t *sc_strlist_get(splaytree_t *tree, char *str)
{
  sc_strlist_t *sl;
  if((sl = sc_strlist_find(tree, str)) != NULL)
    return sl;
  if((sl = malloc_zero(sizeof(sc_strlist_t))) == NULL ||
     (sl->str = strdup(str)) == NULL || (sl->list = slist_alloc()) == NULL ||
     splaytree_insert(tree, sl) == NULL)
    goto err;
  return sl;

 err:
  if(sl != NULL) sc_strlist_free(sl);
  return NULL;
}

static int sc_as2org_cmp(const sc_as2org_t *a, const sc_as2org_t *b)
{
  if(a->asn < b->asn) return -1;
  if(a->asn > b->asn) return  1;
  return 0;
}

static sc_as2org_t *sc_as2org_find(uint32_t asn)
{
  sc_as2org_t fm;
  if(siblings == NULL)
    return NULL;
  fm.asn = asn;
  return array_find((void **)siblings,siblingc,&fm,(array_cmp_t)sc_as2org_cmp);
}

static int sc_as2org_siblings(uint32_t a, uint32_t b)
{
  sc_as2org_t *ao, *bo;
  if(a == b)
    return 1;
  if((ao = sc_as2org_find(a)) == NULL || (bo = sc_as2org_find(b)) == NULL ||
     ao->org != bo->org)
    return 0;
  return 1;
}

static int sc_as2tag_cmp(sc_as2tag_t *a, sc_as2tag_t *b)
{
  int i;
  if((i = strcmp(a->tag, b->tag)) != 0)
    return i;
  if(a->asn < b->asn) return -1;
  if(a->asn > b->asn) return  1;
  return 0;
}

static int sc_as2tag_tag_cmp(sc_as2tag_t *a, sc_as2tag_t *b)
{
  return strcmp(a->tag, b->tag);
}

static int sc_as2tag_sxes_cmp(sc_as2tag_t *a, sc_as2tag_t *b)
{
  int ac, bc;
  ac = splaytree_count(a->sxes);
  bc = splaytree_count(b->sxes);
  if(ac > bc) return -1;
  if(ac < bc) return  1;
  return 0;
}

static int sc_as2tag_tagrank_cmp(sc_as2tag_t *a, sc_as2tag_t *b)
{
  int i, j;
  if((i = strcmp(a->tag, b->tag)) != 0)
    return i;
  i = splaytree_count(a->sxes);
  j = splaytree_count(b->sxes);
  if(i > j) return -1;
  if(i < j) return  1;
  if(a->asn < b->asn) return -1;
  if(a->asn > b->asn) return  1;
  return 0;
}

static void sc_as2tag_free(sc_as2tag_t *a2t)
{
  if(a2t->tag != NULL) free(a2t->tag);
  if(a2t->sxes != NULL) splaytree_free(a2t->sxes, NULL);
  free(a2t);
  return;
}

static sc_as2tag_t *sc_as2tag_find(char *tag)
{
  sc_as2tag_t fm; fm.tag = tag;
  return array_find((void **)tag2ass, tag2asc, &fm,
		    (array_cmp_t)sc_as2tag_tag_cmp);
}

#ifndef DMALLOC
static sc_as2tag_t *sc_as2tag_get(splaytree_t *tree, uint32_t asn, char *tag)
#else
#define sc_as2tag_get(tree,asn,tag) sc_as2tag_get_dm((tree),(asn),(tag), \
						     __FILE__, __LINE__)
static sc_as2tag_t *sc_as2tag_get_dm(splaytree_t *tree, uint32_t asn, char *tag,
				     const char *file, const int line)
#endif
{
  sc_as2tag_t *a2t, fm;

  fm.asn = asn;
  fm.tag = tag;
  if((a2t = splaytree_find(tree, &fm)) != NULL)
    return a2t;

#ifndef DMALLOC
  a2t = malloc(sizeof(sc_as2tag_t));
#else
  a2t = dmalloc_malloc(file,line,sizeof(sc_as2tag_t),DMALLOC_FUNC_MALLOC,0,0);
#endif
  if(a2t == NULL)
    goto err;
  a2t->asn = asn;
  a2t->tag = NULL;
  a2t->sxes = NULL;

  if((a2t->tag = strdup(tag)) == NULL ||
     (a2t->sxes = splaytree_alloc((splaytree_cmp_t)strcmp)) == NULL ||
     splaytree_insert(tree, a2t) == NULL)
    goto err;

  return a2t;

 err:
  if(a2t != NULL) sc_as2tag_free(a2t);
  return NULL;
}

static int char_within(const char *name, int l, int r, char c)
{
  int i;
  for(i=l; i<=r; i++)
    if(name[i] == c)
      return 1;
  return 0;
}

static int dotcount(const char *ptr)
{
  int c = 0;
  while(*ptr != '\0')
    {
      if(*ptr == '.')
	c++;
      ptr++;
    }
  return c;
}

/*
 * re_escape_c:
 *
 * should the character be escaped?
 */
static int re_escape_c(char c)
{
  if(c == '.' || c == '{' || c == '}' || c == '(' || c == ')' ||
     c == '^' || c == '$' || c == '|' || c == '?' || c == '*' ||
     c == '+' || c == '[' || c == ']' || c == '\\')
    return 1;
  return 0;
}

/*
 * re_escape
 *
 * return an escaped character in the buffer.  return zero if there is
 * not enough space, otherwise return the number of characters for the
 * sequence, excluding the null termination.
 */
static size_t re_escape(char *buf, size_t len, char c)
{
  if(re_escape_c(c) != 0)
    {
      if(len < 3)
	return 0;
      buf[0] = '\\';
      buf[1] = c;
      buf[2] = '\0';
      return 2;
    }

  if(len < 2)
    return -1;
  buf[0] = c;
  buf[1] = '\0';
  return 1;
}

static char *re_escape_str(char *buf, size_t len, char *in)
{
  size_t r, off = 0;
  char tmp[4];

  while(*in != '\0')
    {
      if((r = re_escape(tmp, sizeof(tmp), *in)) == 0)
	return NULL;
      /* string_concat(buf, len, &off, "%s", tmp); */
      if(len - off < r + 1)
	return NULL;
      memcpy(buf+off, tmp, r + 1); off += r;
      in++;
    }

  return buf;
}

static void hex_toascii(char *buf, size_t len, const char *str)
{
  size_t off = 0;
  size_t x = 0;
  int c;

  assert(len > 0);

  while(str[x] != '\0')
    {
      if(str[x] == '\\' && str[x+1] == 'x')
	{
	  if(str[x+2] >= '0' && str[x+2] <= '9')
	    c = (str[x+2] - '0') * 16;
	  else
	    c = (str[x+2] - 'a' + 10) * 16;
	  if(str[x+3] >= '0' && str[x+3] <= '9')
	    c += (str[x+3] - '0');
	  else
	    c += (str[x+3] - 'a' + 10);
	  if(isprint(c) && c != ' ')
	    {
	      if(off >= len)
		goto empty;
	      buf[off++] = c;
	      x += 4;
	    }
	  else goto empty;
	}
      else
	{
	  if(off >= len)
	    goto empty;
	  buf[off++] = str[x++];
	}
    }

  if(off >= len)
    goto empty;
  buf[off] = '\0';
  return;

 empty:
  buf[0] = '\0';
  return;
}

static int overlap(size_t a, size_t b, size_t x, size_t y)
{
  if((a <= x && y <= b) || (a >= x && y >= b) ||
     (a < x && b >= x) || (x < a && y >= a))
    return 1;
  return 0;
}

static uint8_t bits_to_geohint_type(int k)
{
  switch(k)
    {
    case BIT_TYPE_GEO_IATA:     return GEOHINT_TYPE_IATA;
    case BIT_TYPE_GEO_ICAO:     return GEOHINT_TYPE_ICAO;
    case BIT_TYPE_GEO_CLLI:     return GEOHINT_TYPE_CLLI;
    case BIT_TYPE_GEO_PLACE:    return GEOHINT_TYPE_PLACE;
    case BIT_TYPE_GEO_LOCODE:   return GEOHINT_TYPE_LOCODE;
    case BIT_TYPE_GEO_FACILITY: return GEOHINT_TYPE_FACILITY;
    case BIT_TYPE_GEO_CC:       return GEOHINT_TYPE_CC;
    case BIT_TYPE_GEO_ST:       return GEOHINT_TYPE_ST;
    }
  return 0;
}

static int geohint_to_bits_type(uint8_t k)
{
  switch(k)
    {
    case GEOHINT_TYPE_IATA:     return BIT_TYPE_GEO_IATA;
    case GEOHINT_TYPE_ICAO:     return BIT_TYPE_GEO_ICAO;
    case GEOHINT_TYPE_CLLI:     return BIT_TYPE_GEO_CLLI;
    case GEOHINT_TYPE_PLACE:    return BIT_TYPE_GEO_PLACE;
    case GEOHINT_TYPE_LOCODE:   return BIT_TYPE_GEO_LOCODE;
    case GEOHINT_TYPE_FACILITY: return BIT_TYPE_GEO_FACILITY;
    case GEOHINT_TYPE_CC:       return BIT_TYPE_GEO_CC;
    case GEOHINT_TYPE_ST:       return BIT_TYPE_GEO_ST;
    }
  return -1;
}

static int pt_to_bits_trip(slist_t *list, int m, int x, int y)
{
  int *trip = NULL;

  assert(x <= y);
  assert(m >= BIT_TYPE_MIN);
  assert(m <= BIT_TYPE_MAX);

  if((trip = malloc(sizeof(int) * 3)) == NULL ||
     slist_tail_push(list, trip) == NULL)
    goto err;
  trip[0] = m;
  trip[1] = x;
  trip[2] = y;
  return 0;

 err:
  if(trip != NULL) free(trip);
  return -1;
}

static int pt_xor(size_t len, size_t *m, size_t mc, int **outn, int *outc)
{
  int x = 0, *n = NULL, nc = 0;
  size_t i;

  if(m[0] > 0) nc += 2;
  if(m[mc-1] + 1 < len) nc += 2;

  for(i=0; i<mc-2; i+=2)
    if(m[i+1] + 1 < m[i+2])
      nc += 2;

  if(nc == 0)
    goto done;

  if((n = malloc(sizeof(int) * nc)) == NULL)
    return -1;

  if(m[0] > 0)
    {
      n[x++] = 0;
      n[x++] = m[0] - 1;
    }

  for(i=0; i<mc-2; i+=2)
    {
      if(m[i+1] + 1 < m[i+2])
	{
	  n[x++] = m[i+1] + 1;
	  n[x++] = m[i+2] - 1;
	}
    }

  if(m[mc-1] + 1 < len)
    {
      n[x++] = m[mc-1] + 1;
      n[x++] = len - 1;
    }

  assert(x == nc);

 done:
  *outn = n;
  *outc = nc;
  return 0;
}

static void pt_s_flatten(slist_t *list, size_t *out, size_t *outc)
{
  sc_lcs_pt_t *pt;
  slist_node_t *sn;
  size_t i = 0;

  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      out[i++] = pt->S_start;
      out[i++] = pt->S_end;
    }
  *outc = i;

  return;
}

static void pt_t_flatten(slist_t *list, size_t *out, size_t *outc)
{
  sc_lcs_pt_t *pt;
  slist_node_t *sn;
  size_t i = 0;

  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      out[i++] = pt->T_start;
      out[i++] = pt->T_end;
    }
  *outc = i;

  return;
}

/*
 * pt_list_to_bits
 *
 * reduce code duplication among the pt_to_bits_* functions
 */
static int pt_list_to_bits(slist_t *trip_list, int **out, int *bitc)
{
  int i, *bits, *trip;
  if((bits = malloc(slist_count(trip_list) * sizeof(int) * 3)) == NULL)
    return -1;
  i = 0;
  while((trip = slist_head_pop(trip_list)) != NULL)
    {
      bits[i++] = trip[0];
      bits[i++] = trip[1];
      bits[i++] = trip[2];
      free(trip);
    }
  *out = bits; bits = NULL;
  *bitc = i;
  return 0;
}

/*
 * pt_to_bits_ip:
 *
 * plan out the matches and literals given the input constraints.
 */
static int pt_to_bits_ip(const sc_ifacedom_t *ifd, size_t *l, size_t lc,
			 int **bits, int *bitc)
{
  slist_t *list = NULL;
  size_t i, j, k, x; int z;
  uint16_t ip_s = ifd->iface->ip_s;
  uint16_t ip_e = ifd->iface->ip_e;
  int rc = -1;
  int type;

  assert((ifd->iface->flags & SC_IFACE_FLAG_IP) != 0);

  if((list = slist_alloc()) == NULL)
    goto done;

  if((ifd->iface->flags & SC_IFACE_FLAG_IP_HEX) == 0)
    type = BIT_TYPE_IP_DEC;
  else
    type = BIT_TYPE_IP_HEX;

  j = 0;

  /* the first match doesn't begin at the start of the string */
  if(ip_s != 0 && lc != 0 && l[0] != 0)
    {
      k = (ip_s < l[0] ? ip_s : l[0]);
      if(pt_to_bits_trip(list, BIT_TYPE_SKIP, 0, k-1) != 0)
	goto done;
      j = k;
    }

  while(j < ifd->len)
    {
      /* IP match */
      if(j == ip_s)
	{
	  if(pt_to_bits_trip(list, type, ip_s, ip_e) != 0)
	    goto done;
	  j = ip_e + 1;
	  continue;
	}

      /* is there a literal match starting here? */
      for(i=0; i<lc; i+=2)
	if(j == l[i])
	  break;
      if(i != lc)
	{
	  if(pt_to_bits_trip(list, BIT_TYPE_SKIP_LIT, l[i], l[i+1]) != 0)
	    goto done;
	  j = l[i+1] + 1;
	  continue;
	}

      /* figure out the start of the next literal */
      for(i=0; i<lc; i+=2)
	if(j < l[i])
	  break;
      if(i != lc)
	{
	  if(l[i] < ip_s)
	    k = ip_s - 1;
	  else
	    k = l[i] - 1;
	}
      else if(j < ip_s)
	k = ip_s - 1;
      else
	k = ifd->len - 1;

      /* skip over punctuation */
      while(j < k && isalnum((unsigned char)ifd->label[j]) == 0)
	j++;
      x = k;
      while(x > 0 && x >= j && isalnum((unsigned char)ifd->label[x]) == 0)
	x--;
      if(x >= j && pt_to_bits_trip(list, BIT_TYPE_SKIP, j, x) != 0)
	goto done;
      j = k + 1;
    }

  if(pt_list_to_bits(list, bits, bitc) != 0)
    goto done;

  if(do_debug != 0 && threadc <= 1)
    {
      printf("%s %d | %d %d", ifd->label, (int)ifd->len, ip_s, ip_e);
      if(lc > 0)
	{
	  printf(" |");
	  for(i=0; i<lc; i++)
	    printf(" %d", (int)l[i]);
	}
      printf(" |");
      for(z=0; z < *bitc; z++)
	printf(" %d", (*bits)[z]);
      printf("\n");
    }

  rc = 0;

 done:
  if(list != NULL) slist_free_cb(list, free);
  return rc;
}

static void pt_merge(size_t *LA, size_t *L, size_t Lc, size_t *LX, size_t LXc)
{
  size_t a = 0, l = 0, x = 0;

  while(l < Lc || x < LXc)
    {
      if(l < Lc && x < LXc)
	{
	  if(L[2*l] < LX[2*x])
	    {
	      LA[a++] = L[2*l];
	      LA[a++] = L[(2*l)+1];
	      l++;
	    }
	  else
	    {
	      LA[a++] = LX[2*x];
	      LA[a++] = LX[(2*x)+1];
	      x++;
	    }
	}
      else if(l < Lc)
	{
	  LA[a++] = L[2*l];
	  LA[a++] = L[(2*l)+1];
	  l++;
	}
      else
	{
	  LA[a++] = LX[2*x];
	  LA[a++] = LX[(2*x)+1];
	  x++;
	}
    }

  return;
}

static int pt_overlap(const size_t *X, size_t Xc, const size_t *L, size_t Lc)
{
  size_t x, l;

  assert(Xc % 2 == 0);
  assert(Lc % 2 == 0);
  for(x=0; x<Xc-1; x++)
    assert(X[x+1] >= X[x]);
  for(l=0; l<Lc-1; l++)
    assert(L[l+1] >= L[l]);

  for(x=0; x<Xc; x+=2)
    {
      for(l=0; l<Lc; l+=2)
	{
	  if(overlap(X[x], X[x+1], L[l], L[l+1]) != 0)
	    return 1;
	}
    }

  return 0;
}

/*
 * pt_to_bits_ctype
 *
 * plan out a base regex, with a capture part of the specified type.
 * the ctype allows this function to be re-used for different captures.
 */
static int pt_to_bits_ctype(const sc_ifacedom_t *ifd, int *ctypes,
			    int16_t *c, int cc, int **bits, int *bitc)
{
  const char *s = ifd->label;
  slist_t *list = NULL; /* list contains triples */
  int i, j, k, d, e;
  int rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;

  /* if the first capture doesn't begin at the start of the string */
  if(c[0] != 0)
    {
      k = c[0]-1;

      /*
       * if there are digits immediately before the first capture,
       * figure out the extent of the digits, and shift the skip
       * boundary in.
       */
      d = e = -1;
      if(isdigit((unsigned char)s[k]) != 0)
	{
	  d = e = k;
	  while(d > 0 && isdigit((unsigned char)s[d-1]) != 0)
	    d--;
	  k = d - 1;
	}

      /* calculate boundaries of skip, skipping over punctuation */
      if(k >= 0)
	{
	  while(k > 0 && isalnum((unsigned char)s[k]) == 0)
	    k--;
	  if(pt_to_bits_trip(list, BIT_TYPE_SKIP, 0, k) != 0)
	    goto done;
	}

      /* emit \d+ if there are digits after the skip */
      if(d != -1 && pt_to_bits_trip(list, BIT_TYPE_SKIP_DIGIT, d, e) != 0)
	goto done;
    }

  for(i=0; i<cc; i+=2)
    {
      /* capture portion */
      if(pt_to_bits_trip(list, ctypes[i/2], c[i+0], c[i+1]) != 0)
	goto done;

      /* if there are digits immediately following the capture */
      j = c[i+1] + 1;
      if(isdigit((unsigned char)s[j]) != 0)
	{
	  k = j;
	  while(isdigit((unsigned char)s[k+1]) != 0)
	    k++;
	  if(pt_to_bits_trip(list, BIT_TYPE_SKIP_DIGIT, j, k) != 0)
	    goto done;
	  j = k + 1;
	}

      /* open the next skip portion, skipping over dashes and dots */
      while(s[j] != '\0' && isalnum((unsigned char)s[j]) == 0)
	j++;

      /* skip portion */
      if(s[j] != '\0' && (i+2==cc || c[i+2] != j))
	{
	  if(i+2<cc)
	    {
	      k = c[i+2]-1;
	      while(k > c[i+1] && isalnum((unsigned char)s[k]) == 0)
		k--;
	    }
	  else
	    {
	      k = c[i+1];
	      while(s[k+1] != '\0')
		k++;
	    }

	  if(pt_to_bits_trip(list, BIT_TYPE_SKIP, j, k) != 0)
	    goto done;
	}
    }

  if(pt_list_to_bits(list, bits, bitc) != 0)
    goto done;

  if(do_debug != 0 && threadc <= 1)
    {
      printf("%s |", s);
      for(i=0; i<cc; i++)
	printf(" %d", c[i]);
      printf(" |");
      for(i=0; i < *bitc; i++)
	printf(" %d", (*bits)[i]);
      printf("\n");
    }

  rc = 0;

 done:
  if(list != NULL) slist_free_cb(list, free);
  return rc;
}

/*
 * pt_to_bits:
 *
 * plan out the matches, captures, literals, and digits given the input
 * constraints.
 *
 * the approach makes two passes: planning how the captures, literals, and
 * digits interact, and then emiting triplets that specify the boundaries
 * of each mode.
 *
 * c:    input capture tuples.  each tuple consists of where the match
 *       begins, and where the match ends.
 *
 * l:    input literal tuples.  each tuple consists of where the literal
 *       begins, and where the literal ends.
 *
 * d:    input digit tuples.  each tuple consists of where the digit
 *       begins, and where the digit ends.
 *
 * bits: output triples.  the first value in the triple specifies the mode,
 *       and the next values specify the scope (beginning and end).
 *       mode 0: skip
 *       mode 1: capture.
 *       mode 2: skip, literal.
 *       mode 3: capture, literal.
 *       mode 4: skip, digit.
 *       mode 5: capture, digit.
 *
 */
static int pt_to_bits(const char *str, size_t len, size_t *c, size_t cc,
		      size_t *l, size_t lc, size_t *d, size_t dc, int **bits, int *bitc)
{
  static const uint8_t cap = 0x4;
  static const uint8_t dig = 0x2;
  static const uint8_t lit = 0x1;
  slist_t *list = NULL;
  uint8_t *plan = NULL;
  size_t i, j, k, m; int rc = -1;

  if((plan = malloc_zero(sizeof(uint8_t) * len)) == NULL ||
     (list = slist_alloc()) == NULL)
    goto done;

  for(i=0; i<cc; i+=2)
    {
      for(j=c[i]; j<=c[i+1]; j++)
	{
	  assert(j < len);
	  plan[j] |= cap;
	}
    }
  for(i=0; i<lc; i+=2)
    {
      for(j=l[i]; j<=l[i+1]; j++)
	{
	  assert(j < len);
	  plan[j] |= lit;
	}
    }
  for(i=0; i<dc; i+=2)
    {
      for(j=d[i]; j<=d[i+1]; j++)
	{
	  assert(j < len);
	  plan[j] |= dig;
	}
    }

  i = 0;
  while(i < len)
    {
      j = i+1;
      while(j < len && plan[i] == plan[j])
	j++;
      j--;

      /* I and J are the ranges of this particular segment */
      if((plan[i] & cap) != 0)
	{
	  if((plan[i] & dig) != 0)
	    m = BIT_TYPE_CAPTURE_DIGIT;
	  else if((plan[i] & lit) != 0)
	    m = BIT_TYPE_CAPTURE_LIT;
	  else
	    m = BIT_TYPE_CAPTURE;
	  if(pt_to_bits_trip(list, m, i, j) != 0)
	    goto done;
	}
      else if(plan[i] != 0)
	{
	  if((plan[i] & dig) != 0)
	    m = BIT_TYPE_SKIP_DIGIT;
	  else if((plan[i] & lit) != 0)
	    m = BIT_TYPE_SKIP_LIT;
	  else
	    goto done;
	  if(pt_to_bits_trip(list, m, i, j) != 0)
	    goto done;
	}
      else
	{
	  while(i <= j && isalnum((unsigned char)str[i]) == 0)
	    i++;
	  k = j;
	  while(i <= k && isalnum((unsigned char)str[k]) == 0)
	    k--;

	  if(i <= k && isalnum((unsigned char)str[i]) != 0)
	    {
	      m = BIT_TYPE_SKIP;
	      if(pt_to_bits_trip(list, m, i, k) != 0)
		goto done;
	    }
	}

      i = j + 1;
    }

  if(pt_list_to_bits(list, bits, bitc) != 0)
    goto done;

  rc = 0;

 done:
  if(list != NULL) slist_free_cb(list, free);
  if(plan != NULL) free(plan);
  return rc;
}

/*
 * pt_to_bits_noip
 *
 * the capture portion is known to overlap with an IP address literal.
 * adjust the capture so it doesn't.
 */
static int pt_to_bits_noip(const sc_ifacedom_t *ifd,
			   size_t *c, size_t cc, int **out, int *bitc)
{
  uint16_t ip_s = ifd->iface->ip_s;
  uint16_t ip_e = ifd->iface->ip_e;
  size_t *d = NULL;
  size_t dc = 0;
  size_t i, x;

  /*
   * we might need more space in the output incase the ip_s and ip_e
   * fall within a capture portion
   */
  if((d = malloc(sizeof(size_t) * (cc + 2))) == NULL)
    return -1;

  for(i=0; i<cc; i+=2)
    {
      assert(c[i+1] >= c[i]);

      /*
       * if the capture portion is entirely contained within the
       * apparent IP address literal, then skip it
       */
      if(ip_s <= c[i] && c[i+1] <= ip_e)
	continue;

      /*
       * if there is no overlap at all, then copy the capture portion
       * across
       */
      if(ip_s > c[i+1] || ip_e < c[i])
	{
	  assert(dc < cc + 2);
	  d[dc++] = c[i];
	  d[dc++] = c[i+1];
	  continue;
	}

      if(ip_s > c[i])
	{
	  x = ip_s-1;
	  while(x > c[i] && isalpha((unsigned char)ifd->label[x]) == 0)
	    x--;
	  assert(dc < cc + 2);
	  d[dc++] = c[i];
	  d[dc++] = x;
	}

      if(ip_e < c[i+1])
	{
	  x = ip_e+1;
	  while(x < c[i+1] && isalpha((unsigned char)ifd->label[x]) == 0)
	    x++;
	  assert(dc < cc + 2);
	  d[dc++] = x;
	  d[dc++] = c[i+1];
	}
    }

  if(dc == 0)
    {
      free(d);
      *out = NULL;
      *bitc = 0;
      return 0;
    }

  x = pt_to_bits(ifd->label, ifd->len, d, dc, NULL, 0, NULL, 0, out, bitc);
  free(d);
  return x;
}

static int sc_clligp_3cmp(const sc_clligp_t *a, const sc_clligp_t *b)
{
  int rc;
  if((rc = strcmp(a->gp, b->gp)) != 0) return rc;
  if((rc = strcmp(a->cc, b->cc)) != 0) return rc;
  if((rc = strcmp(a->st, b->st)) != 0) return rc;
  return 0;
}

static int sc_clligp_cmp(const sc_clligp_t *a, const sc_clligp_t *b)
{
  return strcmp(a->gp, b->gp);
}

static sc_clligp_t *sc_clligp_get(splaytree_t *tree, const char *gp,
				  const char *cc, const char *st)
{
  sc_clligp_t fm, *clligp;

  strncpy(fm.gp, gp, 3); fm.gp[2] = '\0';
  strncpy(fm.cc, cc, 3); fm.cc[2] = '\0';
  strncpy(fm.st, st, 4); fm.st[3] = '\0';

  if((clligp = splaytree_find(tree, &fm)) != NULL)
    return clligp;

  if((clligp = memdup(&fm, sizeof(sc_clligp_t))) == NULL ||
     splaytree_insert(tree, clligp) == NULL)
    {
      if(clligp != NULL) free(clligp);
      return NULL;
    }

  return clligp;
}

static sc_clligp_t *sc_clligp_find(const char *gp)
{
  sc_clligp_t fm;
  strncpy(fm.gp, gp, 3); fm.gp[2] = '\0';
  return array_find((void **)clligps,clligpc,&fm,(array_cmp_t)sc_clligp_cmp);
}

static int sc_geomap_code(sc_geomap_t *map, sc_ptrc_t *x, size_t xc)
{
  char *cptr;
  size_t i, j;

  if(xc == 2)
    {
      if(x[0].c + x[1].c > sizeof(map->code))
	return -1;
      if(map->type == GEOHINT_TYPE_CLLI)
	{
	  if(x[0].c == 4 && x[1].c == 2) {
	    memcpy(map->code,   x[0].ptr, 4);
	    memcpy(map->code+4, x[1].ptr, 2);
	  } else if(x[0].c == 2 && x[1].c == 4) {
	    memcpy(map->code,   x[1].ptr, 4);
	    memcpy(map->code+4, x[0].ptr, 2);
	  } else return -1;
	  map->code[6] = '\0';
	  map->codelen = 6;
	}
      else if(map->type == GEOHINT_TYPE_LOCODE)
	{
	  if(x[0].c == 2 && x[1].c == 3) {
	    memcpy(map->code,   x[0].ptr, 2);
	    memcpy(map->code+2, x[1].ptr, 3);
	  } else if(x[0].c == 3 && x[1].c == 2) {
	    memcpy(map->code,   x[1].ptr, 2);
	    memcpy(map->code+2, x[0].ptr, 3);
	  } else return -1;
	  map->code[5] = '\0';
	  map->codelen = 5;
	}
      else return -1;
    }
  else if(xc == 1)
    {
      if(x[0].c > sizeof(map->code))
	return -1;
      j = 0; cptr = x[0].ptr;
      for(i=0; i<x[0].c; i++)
	{
	  if(isalnum((unsigned char)cptr[i]) == 0)
	    continue;
	  map->code[j++] = cptr[i];
	}
      map->code[j] = '\0';
      map->codelen = j;
    }
  else
    {
      return -1;
    }

  return 0;
}

static char *sc_geomap_tostr(const sc_geomap_t *map, char *buf, size_t len)
{
  size_t off = 0;
  string_concat(buf, len, &off, "%s", map->code);
  if(map->st[0] != '\0')
    string_concat(buf, len, &off, "|%s", map->st);
  if(map->cc[0] != '\0')
    string_concat(buf, len, &off, "|%s", map->cc);
  return buf;
}

static int sc_geomap_cmp(const sc_geomap_t *a, const sc_geomap_t *b)
{
  int x;
  if(a->type < b->type) return -1;
  if(a->type > b->type) return  1;
  if((x = strcmp(a->cc, b->cc)) != 0) return x;
  if((x = strcmp(a->st, b->st)) != 0) return x;
  if((x = strcmp(a->code, b->code)) != 0) return x;
  return 0;
}

static int sc_geotagn_cmp(const void *va, const void *vb)
{
  const sc_geotagn_t *a = (const sc_geotagn_t *)va;
  const sc_geotagn_t *b = (const sc_geotagn_t *)vb;
  if(a->start < b->start) return -1;
  if(a->start > b->start) return  1;
  return 0;
}

static void sc_geotag_free(sc_geotag_t *tag)
{
  if(tag->tags != NULL) free(tag->tags);
  free(tag);
  return;
}

static int sc_geotag_place_cmp(const sc_geotag_t *a, const sc_geotag_t *b)
{
  size_t i, a_st = 0, b_st = 0, a_cc = 0, b_cc = 0;

  for(i=0; i<a->tagc; i++)
    {
      if(a->tags[i].type == GEOHINT_TYPE_CC)
	a_cc = 1;
      else if(a->tags[i].type == GEOHINT_TYPE_ST)
	a_st = 1;
    }
  for(i=0; i<b->tagc; i++)
    {
      if(b->tags[i].type == GEOHINT_TYPE_CC)
	b_cc = 1;
      else if(b->tags[i].type == GEOHINT_TYPE_ST)
	b_st = 1;
    }

  if(a_st > b_st) return -1;
  if(a_st < b_st) return  1;
  if(a_cc > b_cc) return -1;
  if(a_cc < b_cc) return  1;
  return 0;
}

static int sc_georef_cmp(const sc_georef_t *a, const sc_georef_t *b)
{
  return sc_geomap_cmp(&a->map, &b->map);
}

static void sc_georef_free(sc_georef_t *gr)
{
  if(gr->rd_list != NULL) slist_free(gr->rd_list);
  if(gr->ifi_list != NULL) slist_free(gr->ifi_list);
  if(gr->t_mask != NULL) free(gr->t_mask);
  if(gr->f_mask != NULL) free(gr->f_mask);
  if(gr->offs != NULL) free(gr->offs);
  free(gr);
  return;
}

static sc_georef_t *sc_georef_find(splaytree_t *tree, const sc_geomap_t *map)
{
  sc_georef_t fm;
  memcpy(&fm.map, map, sizeof(sc_geomap_t));
  return splaytree_find(tree, &fm);
}

static sc_georef_t *sc_georef_get(splaytree_t *tree, const sc_geomap_t *map)
{
  sc_georef_t *gr;
  if((gr = sc_georef_find(tree, map)) != NULL)
    return gr;
  if((gr = malloc_zero(sizeof(sc_georef_t))) == NULL ||
     (gr->rd_list = slist_alloc()) == NULL ||
     (gr->ifi_list = slist_alloc()) == NULL)
    goto err;
  memcpy(&gr->map, map, sizeof(sc_geomap_t));
  if(splaytree_insert(tree, gr) == NULL)
    goto err;
  return gr;

 err:
  if(gr != NULL) sc_georef_free(gr);
  return NULL;
}

static uint16_t dist2rtt(double dist)
{
  double d = floor((dist * 2) / light_speed);
  return ((uint16_t)d);
}

static int sc_state_sort_cmp(const sc_state_t *a, const sc_state_t *b)
{
  int i;
  if((i = strcmp(a->st, b->st)) != 0)
    return i;
  return strcmp(a->cc, b->cc);
}

static int sc_state_sort_findpos(const char *st, const char *cc, size_t *pos)
{
  sc_state_t fm;
  memcpy(fm.st, st, sizeof(fm.st));
  memcpy(fm.cc, cc, sizeof(fm.cc));
  return array_findpos((void **)geohint_stas, geohint_stac, &fm,
		       (array_cmp_t)sc_state_sort_cmp, pos);
}

static void sc_state_sort(void)
{
  sc_state_t *hint, *prev, *head;
  size_t i;

  array_qsort((void **)geohint_stas, geohint_stac,
	      (array_cmp_t)sc_state_sort_cmp);
  prev = NULL; head = geohint_stas[0];
  for(i=0; i<geohint_stac; i++)
    {
      hint = geohint_stas[i];
      if(strcmp(head->st, hint->st) == 0)
	{
	  if(prev != NULL)
	    prev->next = hint;
	}
      else head = hint;
      hint->head = head;
      prev = hint;
    }

  return;
}

static int sc_state_cmp(const sc_state_t *a, const sc_state_t *b)
{
  return strcmp(a->st, b->st);
}

static void sc_state_free(sc_state_t *state)
{
  if(state->name != NULL) free(state->name);
  if(state->hints != NULL) free(state->hints);
  free(state);
  return;
}

static sc_state_t *sc_state_find(const char *st)
{
  sc_state_t fm, *sta;
  memcpy(fm.st, st, sizeof(fm.st));
  sta = array_find((void **)geohint_stas, geohint_stac, &fm,
		   (array_cmp_t)sc_state_cmp);
  if(sta != NULL)
    return sta->head;
  return NULL;
}

static int sc_country_cmp2(const sc_country_t *a, const sc_country_t *b)
{
  return strcmp(a->cc, b->cc);
}

static int sc_country_cmp3(const sc_country_t *a, const sc_country_t *b)
{
  return strcmp(a->iso3, b->iso3);
}

static void sc_country_free(sc_country_t *country)
{
  if(country->name != NULL) free(country->name);
  if(country->hints != NULL) free(country->hints);
  free(country);
  return;
}

static int sc_country_findpos(const char *cc, size_t *pos)
{
  sc_country_t fm;
  memcpy(fm.cc, cc, sizeof(fm.cc));
  return array_findpos((void **)geohint_cous, geohint_couc, &fm,
		       (array_cmp_t)sc_country_cmp2, pos);
}

static sc_country_t *sc_country_find3(const char *iso3)
{
  sc_country_t fm;
  memcpy(fm.iso3, iso3, sizeof(fm.iso3));
  return array_find((void **)geohint_cous, geohint_couc, &fm,
		    (array_cmp_t)sc_country_cmp3);
}

static void sc_geohint_free(sc_geohint_t *hint)
{
  if(hint->code != NULL) free(hint->code);
  if(hint->place != NULL) free(hint->place);
  if(hint->street != NULL) free(hint->street);
  if(hint->facname != NULL) free(hint->facname);
  free(hint);
  return;
}

static sc_geohint_t *sc_geohint_alloc(uint8_t type,
				      const char *code, const char *place,
				      const char *st, const char *cc,
				      double lat, double lng, long popn)
{
  sc_geohint_t *hint;
  if((hint = malloc_zero(sizeof(sc_geohint_t))) == NULL ||
     (hint->code = strdup(code)) == NULL ||
     (place != NULL && place[0] != '\0' &&
      (hint->place = strdup(place)) == NULL))
    goto err;
  hint->codelen = strlen(code);
  hint->type = type;
  hint->lat = lat;
  hint->lng = lng;
  hint->popn = popn;
  hint->latr = lat * (M_PI / 180.0);
  hint->lngr = lng * (M_PI / 180.0);
  if(cc != NULL)
    memcpy(hint->cc, cc, sizeof(hint->cc));
  if(st != NULL)
    memcpy(hint->st, st, sizeof(hint->st));
  return hint;

 err:
  if(hint != NULL) sc_geohint_free(hint);
  return NULL;
}

/*
 * sc_geoeval_cmp
 *
 * this function ranks candidate locations when learning geocodes.
 * prefer locations with known colocation facilities, and
 * with higher populations.
 */
static int sc_geoeval_cmp(const sc_geoeval_t *a, const sc_geoeval_t *b)
{
  int x;

  /* rank order */
  if((a->hint->flags & GEOHINT_FLAG_FACILITY) != 0 &&
     (b->hint->flags & GEOHINT_FLAG_FACILITY) == 0)
    return -1;
  if((a->hint->flags & GEOHINT_FLAG_FACILITY) == 0 &&
     (b->hint->flags & GEOHINT_FLAG_FACILITY) != 0)
    return 1;
  if(a->round < b->round) return -1;
  if(a->round > b->round) return  1;
  if(a->hint->popn > b->hint->popn) return -1;
  if(a->hint->popn < b->hint->popn) return  1;
  if(a->tp_c > b->tp_c) return -1;
  if(a->tp_c < b->tp_c) return  1;

  /* tie breaks */
  if((x = strcmp(a->hint->code, b->hint->code)) != 0)
    return x;
  if((x = strcmp(a->hint->cc, b->hint->cc)) != 0)
    return x;
  if((x = strcmp(a->hint->st, b->hint->st)) != 0)
    return x;

  return 0;
}

static void sc_geoeval_free(sc_geoeval_t *ge)
{
  if(ge->alloc != 0 && ge->hint != NULL)
    sc_geohint_free(ge->hint);
  free(ge);
  return;
}

static sc_geoeval_t *sc_geoeval_add(slist_t *geoeval_list, sc_geohint_t *hint,
				    uint32_t tp_c, uint8_t round)
{
  sc_geoeval_t *ge;
  if((ge = malloc(sizeof(sc_geoeval_t))) == NULL ||
     slist_tail_push(geoeval_list, ge) == NULL)
    {
      if(ge != NULL) free(ge);
      return NULL;
    }
  ge->hint = hint;
  ge->tp_c = tp_c;
  ge->round = round;
  ge->alloc = 0;
  return ge;
}

static int sc_geohint_street_tostr2(const char *in, char *out, size_t len)
{
  static const char *digit2string[] = {
    "One", "Two", "Three", "Four", "Five",
    "Six", "Seven", "Eight", "Nine", "Ten"};
  size_t off = 0;
  char *endptr;
  long lo;

  if(isdigit((unsigned char)*in) == 0)
    return -1;
  lo = strtol(in, &endptr, 10);
  if(lo > 0 && lo < 10)
    string_concat(out, len, &off, "%s ", digit2string[lo-1]);
  else
    return -1;

  in = endptr;
  while(*in != '\0')
    {
      if(isalpha((unsigned char)*in) != 0)
	break;
      if(isspace((unsigned char)*in) == 0)
	return -1;
      in++;
    }
  if(*in == '\0')
    return -1;

  string_concat(out, len, &off, "%s", in);
  return 0;
}

static int sc_geohint_street_tostr(const char *in, char *out, size_t len)
{
  static const char *ones[] = {"fir", "seco", "thi", "four", "fif", "six",
			       "seven", "eigh", "nin", "ten", "eleven",
			       "twelf", "thirteen", "fourteen", "fifteen",
			       "sixteen", "seventeen", "eighteen", "nineteen"};
  static const char *tens[] = {"twent", "thirt", "fort", "fift",
			       "sixt", "sevent", "eight", "ninet"};
  size_t off = 0;
  char tmp[32], *endptr;
  long lo;
  int x;

  while(*in != '\0')
    {
      if(isdigit((unsigned char)*in) != 0)
	{
	  lo = strtol(in, &endptr, 10);
	  if(lo == 0 || lo >= 100 ||
	     (strncasecmp(endptr, "st", 2) != 0 &&
	      strncasecmp(endptr, "nd", 2) != 0 &&
	      strncasecmp(endptr, "rd", 2) != 0 &&
	      strncasecmp(endptr, "th", 2) != 0))
	    return -1;
	  if(lo < 20)
	    snprintf(tmp, sizeof(tmp), "%s", ones[lo-1]);
	  else if((lo % 10) == 0)
	    snprintf(tmp, sizeof(tmp), "%sie", tens[(lo / 10) - 2]);
	  else
	    snprintf(tmp, sizeof(tmp), "%sy%s",
		     tens[(lo / 10) - 2], ones[(lo % 10) - 1]);
	  tmp[0] = toupper((unsigned char)tmp[0]);

	  x = 0;
	  while(tmp[x] != '\0')
	    out[off++] = tmp[x++];
	  out[off++] = *endptr; endptr++;
	  out[off++] = *endptr;
	  in = endptr;
	}
      else if(*in == ' ' || isalpha((unsigned char)*in) != 0)
	{
	  out[off++] = *in;
	}
      in++;
    }

  out[off] = '\0';
  return 0;
}

static char *sc_geohint_place_tostr(const sc_geohint_t *hint,
				    char *buf, size_t len)
{
  size_t off = 0;
  char uc[8];

  if(hint->facname != NULL)
    string_concat(buf, len, &off, "%s%s", off != 0 ? ", " : "",
		  hint->facname);
  if(hint->street != NULL)
    string_concat(buf, len, &off, "%s%s", off != 0 ? ", " : "",
		  hint->street);
  if(hint->place != NULL)
    string_concat(buf, len, &off, "%s%s", off != 0 ? ", " : "",
		  hint->place);
  if(hint->st[0] != '\0')
    string_concat(buf, len, &off, "%s%s", off != 0 ? ", " : "",
		  string_toupper(uc, sizeof(uc), hint->st));
  if(hint->cc[0] != '\0')
    string_concat(buf, len, &off, "%s%s", off != 0 ? ", " : "",
		  string_toupper(uc, sizeof(uc), hint->cc));
  return buf;
}

static int sc_geohint_place_tojson(const sc_geohint_t *hint,
				   char *buf, size_t len)
{
  size_t off = 0;
  char tmp[512], *comma = "";

  string_concat(buf, len, &off, "{");
  if(hint->facname != NULL)
    {
      if(str_tojson(hint->facname, tmp, sizeof(tmp)) != 0)
	return -1;
      string_concat(buf, len, &off, "\"facname\":\"%s\"", tmp);
      comma = ", ";
    }
  if(hint->street != NULL)
    {
      if(str_tojson(hint->street, tmp, sizeof(tmp)) != 0)
	return -1;
      string_concat(buf, len, &off, "%s\"street\":\"%s\"", comma, tmp);
      comma = ", ";
    }
  if(hint->place != NULL)
    {
      if(str_tojson(hint->place, tmp, sizeof(tmp)) != 0)
	return -1;
      string_concat(buf, len, &off, "%s\"place\":\"%s\"", comma, tmp);
      comma = ", ";
    }
  if(hint->st[0] != '\0')
    {
      string_concat(buf, len, &off, "%s\"st\":\"%s\"", comma,
		    string_toupper(tmp, sizeof(tmp), hint->st));
      comma = ", ";
    }
  if(hint->cc[0] != '\0')
    {
      string_concat(buf, len, &off, "%s\"cc\":\"%s\"", comma,
		    string_toupper(tmp, sizeof(tmp), hint->cc));
    }
  string_concat(buf, len, &off, "}");

  return 0;
}

/*
 * sc_geohint_distance
 *
 * compute the Haversine distance between two geohints
 */
static double sc_geohint_dist(const sc_geohint_t *a, const sc_geohint_t *b)
{
  /* radius of earth is 6,371 km */
  double radius = 6371.0, ave_lat, ave_lon, squared;
  ave_lat = (b->latr - a->latr) / 2.0;
  ave_lon = (b->lngr - a->lngr) / 2.0;
  squared =
    pow(sin(ave_lat), 2) + cos(a->latr) * cos(b->latr) * pow(sin(ave_lon), 2);
  return 2 * radius * asin(sqrt(squared));
}

/*
 * sc_geohint_checkrtt
 *
 * check if the RTT samples for the router are consistent with the hint
 */
static int sc_geohint_checkrtt(const sc_geohint_t *hint, const sc_router_t *rtr)
{
  sc_rtt_t *sample;
  double distance;
  uint16_t rtt;
  int ok = 0;
  size_t i;

  for(i=0; i<rtr->rttc; i++)
    {
      sample = &rtr->rtts[i];
      distance = sc_geohint_dist(hint, sample->vp);
      rtt = dist2rtt(distance);
      if(rtt > sample->rtt && rtt - sample->rtt > rtt_fudge)
	return 0;
      ok++;
    }

  return ok;
}

/*
 * sc_geohint_rank_cmp
 *
 * rank geohints in dictionary order, then
 * prefer iata > icao > clli > locode > place > facility, then
 * by population.
 */
static int sc_geohint_rank_cmp(const sc_geohint_t *a, const sc_geohint_t *b)
{
  int x;

  if((x = strcmp(a->code, b->code)) != 0)
    return x;

  /* this has the effect of ranking places, facilities last */
  if(a->type < b->type) return -1;
  if(a->type > b->type) return  1;

  /* prefer places with larger populations */
  if(a->popn > b->popn) return -1;
  if(a->popn < b->popn) return  1;
  return 0;
}

static int sc_geohint_cmp(const sc_geohint_t *a, const sc_geohint_t *b)
{
  return strcmp(a->code, b->code);
}

static int sc_geohint_popn_cmp(const sc_geohint_t *a, const sc_geohint_t *b)
{
  if(a->popn > b->popn) return -1;
  if(a->popn < b->popn) return  1;
  return 0;
}

static int sc_geohint_checkmap(const sc_geohint_t *hint, const sc_geomap_t *map)
{
  assert(strcmp(map->code, hint->code) == 0);
  if((map->type == 0 || map->type == hint->type) &&
     (map->cc[0] == '\0' || cceq(map->cc, hint) != 0) &&
     (map->st[0] == '\0' || strcmp(map->st, hint->st) == 0))
    return 1;
  return 0;
}

static void sc_geohint_sort(sc_geohint_t **in_geohints, size_t in_geohintc)
{
  sc_geohint_t *hint, *prev, *head;
  size_t i;

  array_qsort((void **)in_geohints, in_geohintc,
	      (array_cmp_t)sc_geohint_rank_cmp);
  prev = NULL; head = in_geohints[0];
  for(i=0; i<in_geohintc; i++)
    {
      hint = in_geohints[i];
      if(strcmp(head->code, hint->code) == 0)
	{
	  if(prev != NULL)
	    prev->next = hint;
	}
      else head = hint;
      hint->head = head;
      prev = hint;
    }

  return;
}

static sc_geohint_t *sc_geohint_findx(sc_geohint_t **in_geohints,
				      size_t in_geohintc,
				      const sc_geomap_t *map)
{
  sc_geohint_t fm, *hint = NULL;
  fm.code = (char *)map->code;

  if((hint = array_find((void **)in_geohints, in_geohintc, (void *)&fm,
			(array_cmp_t)sc_geohint_cmp)) == NULL)
    return NULL;

  hint = hint->head;
  while(hint != NULL)
    {
      if(strcmp(map->code, hint->code) != 0)
	break;
      if(sc_geohint_checkmap(hint, map) != 0)
	return hint;
      hint = hint->next;
    }

  return NULL;
}

static sc_geohint_t *sc_geohint_find(const sc_regex_t *re,
				     const sc_geomap_t *map)
{
  sc_geohint_t *hint;

  /* check the per-regex learned geohints first */
  if(re != NULL && re->geohints != NULL &&
     (hint = sc_geohint_findx(re->geohints, re->geohintc, map)) != NULL)
    return hint;

  /* check the per-domain learned geohints next */
  if(re != NULL && re->dom->geohints != NULL &&
     (hint = sc_geohint_findx(re->dom->geohints,re->dom->geohintc,map)) != NULL)
    return hint;

  /* check the global geohint array */
  return sc_geohint_findx(geohints, geohintc, map);
}

static sc_geohint_t *sc_geohint_vpfind(const char *code)
{
  sc_geohint_t fm, *hint;
  sc_geomap_t map;

  /* check the VP array first */
  fm.code = (char *)code;
  if((hint = array_find((void **)geohint_vps, geohint_vpc, (void *)&fm,
			(array_cmp_t)sc_geohint_cmp)) != NULL)
    return hint;

  /* otherwise check the general geohint array */
  memset(&map, 0, sizeof(map));
  snprintf(map.code, sizeof(map.code), "%s", code);
  return sc_geohint_find(NULL, &map);
}

static int sc_geohint_fudgepre(const sc_geohint_t *hint,const sc_geomap_t *map)
{
  /* make the CC / ST match, if these are part of the map */
  if(map->cc[0] != '\0' && cceq(map->cc, hint) == 0)
    return 0;
  if(map->st[0] != '\0' && strcmp(map->st, hint->st) != 0)
    return 0;
  return 1;
}

static uint32_t sc_geohint_fudgeeval(const sc_geohint_t *hint,
				     const sc_georef_t *gr,
				     const sc_regex_t *re, uint16_t *tp_rtt)
{
  sc_routerdom_t *rd;
  sc_ifaceinf_t *ifi;
  uint32_t rt_tp_c, tp_c;
  slist_node_t *sn;

  /* check that we have more TP routers than the current hint */
  rt_tp_c = gr->t_mask != NULL ? mask_cnt(gr->t_mask, re->dom->rtmlen) : 0;
  *tp_rtt = 65535;
  tp_c = 0;
  for(sn=slist_head_node(gr->rd_list); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      if(sc_geohint_checkrtt(hint, rd->rtr) != 0)
	{
	  tp_c++;
	  if(rd->rtr->rtts[0].rtt < *tp_rtt)
	    *tp_rtt = rd->rtr->rtts[0].rtt;
	}
    }
  if(tp_c <= rt_tp_c)
    return 0;

  /*
   * check that if the current hint is in here for a FP, that
   * the replacement hint isn't better for just one additional
   * FP, unless the RTT of to the closest VP is close.
   */
  if(gr->class == '!' && tp_c - rt_tp_c == 1 && *tp_rtt > rtt_close)
    return 0;

  /*
   * check that the PPV of the replacement hint is at least 80%
   * and more than the current hint
   */
  tp_c = 0;
  for(sn=slist_head_node(gr->ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if(sc_geohint_checkrtt(hint, ifi->ifd->rd->rtr) != 0)
	tp_c++;
    }
  if(tp_c <= gr->ifi_tp_c || tp_c * 100 / slist_count(gr->ifi_list) < 80)
    return 0;

  return tp_c;
}

/*
 * sc_geohint_abbrv:
 *
 * simple check to see if map->code could be an abbreviation of hint->place.
 */
static int sc_geohint_abbrv(const char *hint_p, const char *map_c,
			    size_t *offs, size_t len,
			    int (*ok)(const char *, const size_t *, size_t))
{
  size_t mo = 0, ho = 0;

  for(;;)
    {
      for(;;)
	{
	  /*
	   * when we cross a non-alnum character (say a space in "New
	   * York") then require the first letter of the next word to
	   * match
	   */
	  if(hint_p[ho] != '\0' && isalnum((unsigned char)hint_p[ho]) == 0)
	    {
	      ho++;
	      for(;;)
		{
		  while(hint_p[ho] != '\0' &&
			isalnum((unsigned char)hint_p[ho]) == 0)
		    ho++;
		  if(hint_p[ho] == '\0' ||
		     tolower((unsigned char)hint_p[ho]) == map_c[mo])
		    break;
		  while(isalnum((unsigned char)hint_p[ho]) != 0)
		    ho++;
		}
	    }

	  /* if the characters match, move onto the next one */
	  if(tolower((unsigned char)hint_p[ho]) == map_c[mo])
	    {
	      offs[mo] = ho;
	      ho++;
	      mo++;
	      break;
	    }

	  if(hint_p[ho] == '\0')
	    {
	      /* if we reach the end and the off-stack is empty, we're done */
	      if(mo == 0)
		return 0;

	      /* try to find another instance of the char later in string */
	      ho = offs[mo-1] + 1;
	      mo--;
	      break;
	    }

	  ho++;
	}

      if(mo == len)
	{
	  if(ok == NULL || ok(hint_p, offs, len) != 0)
	    return 1;
	  ho = offs[mo-1] + 1;
	  mo--;
	}
    }

  return 0;
}

/*
 * sc_geohint_fudge_state
 *
 */
static int sc_geohint_fudge_state(const sc_georef_t *gr,const sc_regex_t *re,
				  const sc_state_t *state,
				  slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  uint32_t tp_c; uint16_t tp_rtt;
  sc_geohint_t *hint, *gh;
  sc_geoeval_t *ge;
  size_t i;

  if(state->hintc < 1)
    return 0;

  for(i=0; i<state->hintc; i++)
    {
      hint = state->hints[i];
      if((tp_c = sc_geohint_fudgeeval(hint, gr, re, &tp_rtt)) == 0)
	continue;
      break;
    }

  if(i != state->hintc)
    {
      if((gh = sc_geohint_alloc(map->type, map->code, state->name, state->st,
				state->cc, hint->lat, hint->lng, 0)) == NULL ||
	 (ge = sc_geoeval_add(geoeval_list, gh, tp_c, 0)) == NULL)
	{
	  if(gh != NULL) sc_geohint_free(gh);
	  return -1;
	}
      ge->alloc = 1;
    }

  return 0;
}

/*
 * sc_geohint_fudge_country
 *
 */
static int sc_geohint_fudge_country(const sc_georef_t *gr,const sc_regex_t *re,
				    const sc_country_t *country,
				    slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  uint32_t tp_c; uint16_t tp_rtt;
  sc_geohint_t *hint, *gh;
  sc_geoeval_t *ge;
  size_t i;

  if(country->hintc < 1)
    return 0;

  for(i=0; i<country->hintc; i++)
    {
      hint = country->hints[i];
      if((tp_c = sc_geohint_fudgeeval(hint, gr, re, &tp_rtt)) == 0)
	continue;
      break;
    }

  if(i != country->hintc)
    {
      if((gh = sc_geohint_alloc(map->type, map->code, country->name, NULL,
				country->cc,hint->lat,hint->lng,0)) == NULL ||
	 (ge = sc_geoeval_add(geoeval_list, gh, tp_c, 0)) == NULL)
	{
	  if(gh != NULL) sc_geohint_free(gh);
	  return -1;
	}
      ge->alloc = 1;
    }

  return 0;
}

static int sc_geohint_fudge_iata_do(const sc_georef_t *gr, sc_geohint_t *hint,
				    const sc_regex_t *re, splaytree_t *gh_tree,
				    slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  uint32_t tp_c; uint16_t tp_rtt;
  int round = -1;

  if(hint->code[0] != map->code[0])
    return 0;
  if(sc_geohint_fudgepre(hint, map) == 0)
    return 0;

  /* three adjacent letters */
  if(strncmp(hint->code, map->code, 3) == 0)
    round = 0;
  /* three letters in order */
  else if(sc_geohint_abbrv(hint->place, map->code, gr->offs, 3, NULL) != 0)
    round = 1;
  /* first letter of city + state */
  else if((map->cc[0] != '\0' || strcmp(hint->cc, "us") == 0) &&
	  strcmp(hint->st, map->code+1) == 0)
    round = 1;
  else
    return 0;

  if((tp_c = sc_geohint_fudgeeval(hint, gr, re, &tp_rtt)) == 0)
    return 0;

  if(mask_cnt(gr->f_mask, re->dom->rtmlen) >= 3 ||
     map->cc[0] != '\0' || map->st[0] != '\0' ||
     tp_rtt <= rtt_close)
    {
      if(sc_geoeval_add(geoeval_list, hint, tp_c, round) == NULL)
	return -1;
    }

  return 0;
}

static int sc_geohint_fudge_iata(const sc_georef_t *gr, const sc_regex_t *re,
				 splaytree_t *gh_tree, slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  sc_geohint_t *hint;
  sc_country_t *country;
  sc_state_t *state;
  size_t i;
  int x;

  /* is the code a possible iso 3166 3-letter country code? */
  if(map->st[0] == '\0' &&
     (country = sc_country_find3(map->code)) != NULL && country->hintc > 0 &&
     (map->cc[0] == '\0' || strcasecmp(map->cc, country->cc) == 0))
    {
      /* evaluate the plausability of the country */
      if(sc_geohint_fudge_country(gr, re, country, geoeval_list) != 0)
	return -1;

      /*
       * if the country matches, early return without considering
       * states or place name acronyms
       */
      if(slist_count(geoeval_list) > 0)
	return 0;
    }

  /* is the code a possible iso 3166 3-letter state code? */
  if(map->st[0] == '\0')
    {
      for(state = sc_state_find(map->code);
	  state != NULL && strcmp(state->st, map->code) == 0;
	  state = state->next)
	{
	  if(map->cc[0] != '\0' && strcasecmp(map->cc, state->cc) != 0)
	    continue;

	  /* evaluate the plausability of the state */
	  if(sc_geohint_fudge_state(gr, re, state, geoeval_list) != 0)
	    return -1;

	  /*
	   * if the state matches, early return without considering
	   * place name acronyms
	   */
	  if(slist_count(geoeval_list) > 0)
	    return 0;
	}
    }

  x = gr->map.code[0] - 'a'; assert(x >= 0 && x < 26);
  for(i=0; i<geohint_plc[x]; i++)
    {
      hint = geohint_pls[x][i]; assert(hint->type == GEOHINT_TYPE_PLACE);
      if(sc_geohint_fudge_iata_do(gr, hint, re, gh_tree, geoeval_list) != 0)
	return -1;
    }

  return 0;
}

static int sc_geohint_fudge_locode_do(const sc_georef_t *gr,
				      sc_geohint_t *hint, const sc_regex_t *re,
				      splaytree_t *gh_tree,
				      slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  uint32_t tp_c; uint16_t tp_rtt;
  int round = -1;
  char cc[3];

  if(hint->code[0] != map->code[2])
    return 0;
  if(sc_geohint_fudgepre(hint, map) == 0)
    return 0;

  /* the CC must match in a locode */
  cc[0] = map->code[0];
  cc[1] = map->code[1];
  cc[2] = '\0';
  if(cceq(cc, hint) == 0)
    return 0;

  /* check if the next three characters match */
  if(strncmp(hint->code, map->code+2, 3) == 0)
    round = 0;
  /* three letters in order */
  else if(sc_geohint_abbrv(hint->place, map->code+2, gr->offs, 3, NULL) != 0)
    round = 1;
  /* first letter of city + state */
  else if((map->cc[0] != '\0' || strcmp(hint->cc, "us") == 0) &&
	  strcmp(hint->st, map->code+3) == 0)
    round = 1;
  else
    return 0;

  if((tp_c = sc_geohint_fudgeeval(hint, gr, re, &tp_rtt)) == 0)
    return 0;
  if(sc_geoeval_add(geoeval_list, hint, tp_c, round) == NULL)
    return -1;

  return 0;
}

static int sc_geohint_fudge_locode(const sc_georef_t *gr, const sc_regex_t *re,
				   splaytree_t *gh_tree, slist_t *geoeval_list)
{
  sc_geohint_t *hint;
  size_t i;
  int x;

  x = gr->map.code[2] - 'a'; assert(x >= 0 && x < 26);
  for(i=0; i<geohint_plc[x]; i++)
    {
      hint = geohint_pls[x][i]; assert(hint->type == GEOHINT_TYPE_PLACE);
      if(sc_geohint_fudge_locode_do(gr, hint, re, gh_tree, geoeval_list) != 0)
	return -1;
    }

  return 0;
}

static int sc_geohint_fudge_clli_do(const sc_georef_t *gr, sc_geohint_t *hint,
				    const sc_regex_t *re, splaytree_t *gh_tree,
				    slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  uint32_t tp_c; uint16_t tp_rtt;
  sc_clligp_t *gp;
  int round = -1;
  int state = 0;

  if(hint->code[0] != map->code[0])
    return 0;
  if(sc_geohint_fudgepre(hint, map) == 0)
    return 0;

  /*
   * if the geopolitical code is a US or CA state, then ensure the
   * hint is in that state/country
   */
  if((gp = sc_clligp_find(map->code+4)) != NULL &&
     (strcmp(gp->cc, "us") == 0 || strcmp(gp->cc, "ca") == 0) &&
     (strcmp(hint->cc, gp->cc) != 0 || strcmp(hint->st, gp->st) != 0))
    return 0;

  /*
   * if the hint we are considering is within the US or CA, then
   * ensure the state matches
   */
  if((strcmp(hint->cc, "us") == 0 || strcmp(hint->cc, "ca") == 0))
    {
      if(strcmp(hint->st, map->code+4) != 0)
	return 0;
      state = 1;
    }

  /* check if the next four characters match */
  if(strncmp(hint->code, map->code, 4) == 0)
    round = 0;
  else if(sc_geohint_abbrv(hint->place, map->code, gr->offs, 4, NULL) != 0)
    round = 1;
  else
    return 0;

  if((tp_c = sc_geohint_fudgeeval(hint, gr, re, &tp_rtt)) == 0)
    return 0;

  if(mask_cnt(gr->f_mask, re->dom->rtmlen) < 3 &&
     state == 0 && map->cc[0] == '\0' && map->st[0] == '\0')
    return 0;

  if(sc_geoeval_add(geoeval_list, hint, tp_c, round) == NULL)
    return -1;

  return 0;
}

static int sc_geohint_fudge_clli(const sc_georef_t *gr, const sc_regex_t *re,
				 splaytree_t *gh_tree, slist_t *geoeval_list)
{
  sc_geohint_t *hint;
  size_t i;
  int x;

  x = gr->map.code[0] - 'a'; assert(x >= 0 && x < 26);
  for(i=0; i<geohint_plc[x]; i++)
    {
      hint = geohint_pls[x][i]; assert(hint->type == GEOHINT_TYPE_PLACE);
      if(sc_geohint_fudge_clli_do(gr, hint, re, gh_tree, geoeval_list) != 0)
	return -1;
    }

  return 0;
}

/*
 * sc_geohint_fudge_place0:
 *
 * check if the place has a state or country code appended.
 */
static int sc_geohint_fudge_place0(const sc_geohint_t *hint,
				   const sc_geomap_t *map)
{
  /* check if the place has the state or country appended */
  if(strncmp(hint->code, map->code, hint->codelen) == 0 &&
     map->code[hint->codelen] != '\0' &&
     ((hint->st[0]!='\0' && strcmp(&map->code[hint->codelen],hint->st) == 0) ||
      (hint->cc[0]!='\0' && cceq(&map->code[hint->codelen],hint) != 0)))
    return 1;
  return 0;
}

/*
 * sc_geohint_fudge_place1:
 *
 * look for apparent typos in hostnames, or placenames that are
 * abbreviations of an existing element in the dictionary.
 */
static int sc_geohint_fudge_place1(const sc_georef_t *gr,
				   const sc_geohint_t *hint,
				   splaytree_t *gh_tree)
{
  const sc_geomap_t *map = &gr->map;

  if(map->codelen < 3)
    return 0;

  if(splaytree_find(gh_tree, hint) == NULL)
    return 0;

  if(map->codelen == 3 &&
     sc_geohint_abbrv(hint->place, map->code, gr->offs, 3, NULL) != 0)
    return 1;
  if(map->codelen > 3 && dled(hint->code, map->code) < 2)
    return 1;

  return 0;
}

static int sc_geohint_fudge_runlen(const char *hint_p, const size_t *offs,
				   size_t len, size_t min)
{
  size_t x, last, cur, max = 0;

  last = offs[0]; cur = 1;
  for(x=1; x<len; x++)
    {
      if(offs[x] - 1 != last)
	{
	  if(isalnum((unsigned char)hint_p[offs[x]-1]) == 0)
	    {
	      last = offs[x];
	      cur++;
	      continue;
	    }
	  if(max < cur)
	    max = cur;
	  cur = 0;
	}
      last = offs[x];
      cur++;
    }
  if(max < cur)
    max = cur;
  if(max >= min)
    return 1;

  return 0;
}

static int sc_geohint_fudge_runlen_codelen(const char *hint_p,
					   const size_t *offs, size_t codelen)
{
  return sc_geohint_fudge_runlen(hint_p, offs, codelen, codelen);
}

static int sc_geohint_fudge_fac_ok(const char *hint_p,
				   const size_t *offs, size_t codelen)
{
  /* if we're dealing with a 3-letter acronym, then we're less picky */
  if(codelen == 3)
    return 1;

  /*
   * anything longer requires at least one segment where there are five
   * characters in order.
   */
  return sc_geohint_fudge_runlen(hint_p, offs, codelen, 4);
}

static int sc_geohint_fudge_place2_ok(const char *hint_p,
				      const size_t *offs, size_t codelen)
{
  /* if we're dealing with a 3-letter acronym, then we're less picky */
  if(codelen == 3)
    return 1;

  /*
   * anything longer requires at least one segment where there are four
   * characters in order.
   */
  return sc_geohint_fudge_runlen(hint_p, offs, codelen, 4);
}

/*
 * sc_geohint_fudge_place2:
 *
 * check if map->code could be an abbreviation of hint->place.
 * for example, is "frankfurt" an abbreviation of "Frankfurt am Main"?
 */
static int sc_geohint_fudge_place2(const sc_georef_t *gr,
				   const sc_geohint_t *hint)
{
  const sc_geomap_t *map = &gr->map;

  if(map->codelen < 3 || hint->codelen <= map->codelen)
    return 0;

  return sc_geohint_abbrv(hint->place, map->code, gr->offs, map->codelen,
			  sc_geohint_fudge_place2_ok);
}

static int sc_geohint_fudge_place_do(const sc_georef_t *gr, sc_geohint_t *hint,
				     const sc_regex_t *re,
				     splaytree_t *gh_tree,
				     slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  uint32_t tp_c; uint16_t tp_rtt;
  int round = -1;

  if(map->code[0] != hint->code[0])
    return 0;
  if(sc_geohint_fudgepre(hint, map) == 0)
    return 0;

  if(sc_geohint_fudge_place0(hint, map) != 0)
    round = 0;
  else if(sc_geohint_fudge_place1(gr, hint, gh_tree) != 0)
    round = 1;
  else if(sc_geohint_fudge_place2(gr, hint) != 0)
    round = 2;
  else
    return 0;

  if((tp_c = sc_geohint_fudgeeval(hint, gr, re, &tp_rtt)) == 0)
    return 0;

  /*
   * need at least three routers to match the geo code,
   * or a CC/ST extraction,
   * or a CC/ST as part of the extracted code (round == 0),
   * or be a contraction of an existing geocode (round == 1).
   */
  if(mask_cnt(gr->f_mask, re->dom->rtmlen) >= 3 ||
     map->cc[0] != '\0' || map->st[0] != '\0' ||
     round == 0 || round == 1)
    {
      if(sc_geoeval_add(geoeval_list, hint, tp_c, round) == NULL)
	return -1;
    }

  return 0;
}

static int sc_geohint_fudge_place_fac_ok(const char *hint_p,
					 const size_t *offs, size_t codelen)
{
  return sc_geohint_fudge_runlen(hint_p, offs, codelen, 6);
}

static int sc_geohint_fudge_place_fac(const sc_georef_t *gr,
				      sc_geohint_t *hint, const sc_regex_t *re,
				      slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  uint32_t tp_c; uint16_t tp_rtt;
  char buf[256];

  if(map->codelen < 5 || (map->cc[0] == '\0' && map->st[0] == '\0') ||
     sc_geohint_fudgepre(hint, map) == 0)
    return 0;

  /* facility names expressed as in "RagingWire" */
  if(hint->facname != NULL &&
     map->code[0] == tolower((unsigned char)hint->facname[0]) &&
     (tp_c = sc_geohint_fudgeeval(hint, gr, re, &tp_rtt)) > 0 &&
     sc_geohint_abbrv(hint->facname, map->code, gr->offs, map->codelen,
		      sc_geohint_fudge_place2_ok) != 0)
    {
      if(sc_geoeval_add(geoeval_list, hint, tp_c, 0) == NULL)
	return -1;
      return 0;
    }

  /* facility streets expressed as in "One Summer" */
  if(hint->street != NULL &&
     (tp_c = sc_geohint_fudgeeval(hint, gr, re, &tp_rtt)) > 0 &&
     sc_geohint_street_tostr2(hint->street, buf, sizeof(buf)) == 0 &&
     map->code[0] == tolower((unsigned char)buf[0]) &&
     sc_geohint_abbrv(buf, map->code, gr->offs, map->codelen,
		      sc_geohint_fudge_place_fac_ok) != 0)
    {
      if(sc_geoeval_add(geoeval_list, hint, tp_c, 1) == NULL)
	return -1;
    }

  return 0;
}

static int sc_geohint_fudge_place(const sc_georef_t *gr,
				  const sc_regex_t *re, splaytree_t *gh_tree,
				  slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  sc_country_t *country;
  sc_geohint_t *hint;
  size_t i;
  int x;

  /* check if the place name is actually a country */
  if(geohint_couc > 0 && map->st[0] == '\0' && map->codelen >= 5)
    {
      for(i=0; i<geohint_couc; i++)
	{
	  country = geohint_cous[i];
	  if(sc_geohint_abbrv(country->name, map->code, gr->offs, map->codelen,
			      sc_geohint_fudge_runlen_codelen) != 0 &&
	     (map->cc[0] == '\0' || strcasecmp(map->cc, country->cc) == 0))
	    break;
	}
      if(i != geohint_couc)
	{
	  if(sc_geohint_fudge_country(gr, re, country, geoeval_list) < 0)
	    return -1;
	  if(slist_count(geoeval_list) > 0)
	    return 0;
	}
    }

  if(gr->class != '?')
    return 0;

  x = gr->map.code[0] - 'a'; assert(x >= 0 && x < 26);
  for(i=0; i<geohint_plc[x]; i++)
    {
      hint = geohint_pls[x][i]; assert(hint->type == GEOHINT_TYPE_PLACE);
      if(sc_geohint_fudge_place_do(gr, hint, re, gh_tree, geoeval_list) != 0)
	return -1;
    }

  /* check for named facilities */
  if(slist_count(geoeval_list) < 1 && gr->map.st[0] != '\0')
    {
      for(i=0; i<geohint_facc; i++)
	{
	  hint = geohint_facs[i];
	  if(sc_geohint_fudge_place_fac(gr, hint, re, geoeval_list) != 0)
	    return -1;
	}
    }

  return 0;
}

static int sc_geohint_fudge_facility(const sc_georef_t *gr,
				     const sc_regex_t *re, splaytree_t *gh_tree,
				     slist_t *geoeval_list)
{
  const sc_geomap_t *map = &gr->map;
  uint32_t tp_c; uint16_t tp_rtt;
  sc_geohint_t *hint;
  size_t i;

  /* only guess facilities where we have a state mapping */
  if(map->codelen < 5 || (map->cc[0] == '\0' && map->st[0] == '\0'))
    return 0;

  for(i=0; i<geohint_facc; i++)
    {
      hint = geohint_facs[i];
      if(hint->street == NULL ||
	 sc_geohint_fudgepre(hint, map) == 0 ||
	 (tp_c = sc_geohint_fudgeeval(hint, gr, re, &tp_rtt)) == 0)
	continue;

      if(sc_geohint_abbrv(hint->street, map->code, gr->offs, map->codelen,
			  sc_geohint_fudge_runlen_codelen) == 0)
	continue;

      if(sc_geoeval_add(geoeval_list, hint, tp_c, 0) == NULL)
	return -1;
      break;
    }

  return 0;
}

static sc_lcs_pt_t *sc_lcs_pt_alloc(int S_s, int S_e, int T_s, int T_e)
{
  sc_lcs_pt_t *pt = NULL;
  if((pt = malloc(sizeof(sc_lcs_pt_t))) == NULL)
    goto err;
  pt->S_start = S_s;
  pt->S_end = S_e;
  pt->T_start = T_s;
  pt->T_end = T_e;
  return pt;
 err:
  if(pt != NULL) free(pt);
  return NULL;
}

static void sc_lcs_pt_free(sc_lcs_pt_t *pt)
{
  free(pt);
  return;
}

static int sc_lcs_pt_cmp(const sc_lcs_pt_t *a, const sc_lcs_pt_t *b)
{
  if(a->S_start < b->S_start) return -1;
  if(a->S_start > b->S_start) return  1;
  return 0;
}

static int sc_lcs_pt_push(slist_t *X, int S_s, int S_e, int T_s, int T_e)
{
  sc_lcs_pt_t *pt = NULL;
  if((pt = sc_lcs_pt_alloc(S_s, S_e, T_s, T_e)) == NULL ||
     slist_tail_push(X, pt) == NULL)
    goto err;
  return 0;
 err:
  if(pt != NULL) free(pt);
  return -1;
}

static int lcs_check(slist_t *X)
{
  sc_lcs_pt_t *last = NULL, *pt;
  slist_node_t *sn;

  for(sn=slist_head_node(X); sn != NULL; sn=slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      if(last != NULL && pt->T_start < last->T_start)
	return 0;
      last = pt;
    }

  return 1;
}

#if 0
static void lcs_print(const char *S, const char *T, slist_t *X)
{
  slist_node_t *sn;
  sc_lcs_pt_t *pt;
  char buf[512];
  int x = 0;

  printf("%s %s ", S, T);
  for(sn = slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      if(x != 0)
	printf("|");
      pt = slist_node_item(sn);
      memcpy(buf, &S[pt->S_start], pt->S_end - pt->S_start + 1);
      buf[pt->S_end - pt->S_start + 1] = '\0';
      printf("%s", buf);
      x++;
    }

  for(sn = slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      printf(" %d,%d", pt->S_start, pt->S_end);
    }
  printf(" :");
  for(sn = slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      printf(" %d,%d", pt->T_start, pt->T_end);
    }
  printf("\n");
  return;
}
#endif

static int idx(int S_len, int T_len, int S_i, int T_i)
{
  assert(S_i >= 0); assert(S_i < S_len);
  assert(T_i >= 0); assert(T_i < T_len);
  return ((S_i * T_len) + T_i);
}

static int char_class(char c)
{
  if(isalpha((unsigned char)c))
    return 0;
  else if(isdigit((unsigned char)c))
    return 1;
  return 2;
}

static int lcs_trim_class(slist_t *X, const char *S, const char *T)
{
  slist_t *Y = NULL;
  sc_lcs_pt_t *pt;
  int class;

  if((Y = slist_alloc()) == NULL)
    return -1;
  while((pt = slist_head_pop(X)) != NULL)
    {
      /* shift start offset */
      class = char_class(S[pt->S_start]);
      while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	{
	  if((pt->S_start > 0 && char_class(S[pt->S_start-1]) == class) ||
	     (pt->T_start > 0 && char_class(T[pt->T_start-1]) == class))
	    {
	      pt->S_start++;
	      pt->T_start++;
	    }
	  else break;
	}

      /*
       * if the class we ended on is non-alphanum, then continue
       * shifting
       */
      if(isalnum((unsigned char)S[pt->S_start]) == 0)
	{
	  while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	    {
	      if(isalnum((unsigned char)S[pt->S_start]) == 0)
		{
		  pt->S_start++;
		  pt->T_start++;
		}
	      else break;
	    }
	}

      /* shift end offset */
      if(S[pt->S_end+1] != '\0' && T[pt->T_end+1] != '\0')
	{
	  class = char_class(S[pt->S_end+1]);
	  while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	    {
	      if(char_class(S[pt->S_end]) == class ||
		 char_class(T[pt->T_end]) == class)
		{
		  pt->S_end--;
		  pt->T_end--;
		}
	      else break;
	    }
	}

      /*
       * if the class we ended on is non-alphanum, then continue
       * shifting
       */
      if(isalnum((unsigned char)S[pt->S_end]) == 0)
	{
	  while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	    {
	      if(isalnum((unsigned char)S[pt->S_end]) == 0)
		{
		  pt->S_end--;
		  pt->T_end--;
		}
	      else break;
	    }
	}

      if(isalnum((unsigned char)S[pt->S_start]) != 0 &&
	 (pt->S_start == 0 ||
	  char_class(S[pt->S_start-1]) != char_class(S[pt->S_start])) &&
	 (pt->T_start == 0 ||
	  char_class(T[pt->T_start-1]) != char_class(T[pt->T_start])) &&
	 (S[pt->S_end+1] == '\0' ||
	  char_class(S[pt->S_end]) != char_class(S[pt->S_end+1])) &&
	 (T[pt->T_end+1] == '\0' ||
	  char_class(T[pt->T_end]) != char_class(T[pt->T_end+1])))
	{
	  if(slist_tail_push(Y, pt) == NULL)
	    goto err;
	}
      else
	{
	  sc_lcs_pt_free(pt);
	}
    }
  slist_concat(X, Y);
  slist_free(Y);
  return 0;

 err:
  if(Y != NULL) slist_free_cb(Y, (slist_free_t)sc_lcs_pt_free);
  return -1;
}

static int lcs_trim(slist_t *X, const char *S, const char *T)
{
  slist_t *Y = NULL;
  sc_lcs_pt_t *pt;

  if((Y = slist_alloc()) == NULL)
    return -1;
  while((pt = slist_head_pop(X)) != NULL)
    {
      /* shift start offset */
      while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	{
	  if((pt->S_start > 0 &&
	     isalnum((unsigned char)S[pt->S_start-1]) != 0) ||
	     (pt->T_start > 0 &&
	      isalnum((unsigned char)T[pt->T_start-1]) != 0) ||
	     isalnum((unsigned char)S[pt->S_start]) == 0)
	    {
	      pt->S_start++;
	      pt->T_start++;
	    }
	  else break;
	}

      /* shift end offset */
      if(S[pt->S_end+1] != '\0' && T[pt->T_end+1] != '\0')
	{
	  while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	    {
	      if(isalnum((unsigned char)S[pt->S_end+1]) != 0 ||
		 isalnum((unsigned char)T[pt->T_end+1]) != 0 ||
		 isalnum((unsigned char)S[pt->S_end]) == 0) 
		{
		  pt->S_end--;
		  pt->T_end--;
		}
	      else break;
	    }
	}

      if((pt->S_start == 0 || isalnum((unsigned char)S[pt->S_start-1]) == 0) &&
	 (pt->T_start == 0 || isalnum((unsigned char)T[pt->T_start-1]) == 0) &&
	 isalnum((unsigned char)S[pt->S_end+1]) == 0 &&
	 isalnum((unsigned char)T[pt->T_end+1]) == 0)
	{
	  if(slist_tail_push(Y, pt) == NULL)
	    goto err;
	}
      else
	{
	  sc_lcs_pt_free(pt);
	}
    }
  slist_concat(X, Y);
  slist_free(Y);
  return 0;

 err:
  if(Y != NULL) slist_free_cb(Y, (slist_free_t)sc_lcs_pt_free);
  return -1;
}

/*
 * lcs_asn
 *
 * Return a list of sc_lcs_pt_t which contains the longest common substring
 * that surrounds the ASN between two strings.
 * param S: First interface to compare.
 * param T: Second interface to compare.
 */
static slist_t *lcs_asn(sc_ifacedom_t *S, sc_ifacedom_t *T)
{
  slist_t *L = NULL;
  int s_start, s_end, t_start, t_end;

  assert((S->iface->flags & SC_IFACE_FLAG_AS) != 0);
  assert((T->iface->flags & SC_IFACE_FLAG_AS) != 0);
  assert(S->iface->as_s <= S->iface->as_e);
  assert(T->iface->as_s <= T->iface->as_e);

  if((L = slist_alloc()) == NULL)
    goto err;

  if(S->iface->as_s > 0 && T->iface->as_s > 0 &&
     S->label[S->iface->as_s-1] == T->label[T->iface->as_s-1] &&
     isalnum((unsigned char)S->label[S->iface->as_s-1]) != 0)
    {
      /*
       * Expand capture before the ASN to see how much of the
       * structure is shared between the two interfaces, stopping at
       * the first separator
       */
      s_start = s_end = S->iface->as_s - 1;
      t_start = t_end = T->iface->as_s - 1;
      while(s_start != 0 && t_start != 0)
	{
	  if(S->label[s_start-1] != T->label[t_start-1] ||
	     isalnum((unsigned char)S->label[s_start-1]) == 0)
	    break;
	  s_start--; t_start--;
	}
      if(sc_lcs_pt_push(L, s_start, s_end, t_start, t_end) != 0)
	goto err;
    }

  if(S->label[S->iface->as_e+1] == T->label[T->iface->as_e+1] &&
     isalnum((unsigned char)S->label[S->iface->as_e+1]) != 0)
    {
      /*
       * Expand capture after the ASN to see how much of the
       * structure is shared between the two interfaces, stopping at
       * the first separator
       */
      s_start = s_end = S->iface->as_e + 1;
      t_start = t_end = T->iface->as_e + 1;
      while(S->label[s_end+1] != '\0' && T->label[t_end+1] != '\0')
	{
	  if(S->label[s_end+1] != T->label[t_end+1] ||
	     isalnum((unsigned char)T->label[s_end+1]) == 0)
	    break;
	  s_end++; t_end++;
	}
      if(sc_lcs_pt_push(L, s_start, s_end, t_start, t_end) != 0)
	goto err;
    }

  return L;

 err:
  if(L != NULL) slist_free_cb(L, (slist_free_t)sc_lcs_pt_free);
  return NULL;
}

/*
 * lcs
 *
 * longest common substring, based off wikipedia's description of the
 * dynamic programming solution.
 *
 * Return a list of sc_lcs_pt_t which contains the longest common substring(s)
 * of two strings.
 * param S: First string to search.
 * param r: Length of S. If 0, the length will be calculated by strlen.
 * param T: Second string to search.
 * param n: Length of T. If 0, the length will be calculated by strlen.
 * param min_z: May not be 0.
 * returns:
 */
static slist_t *lcs(const char *S, int r, const char *T, int n, int min_z)
{
  slist_t *bits = NULL;
  slist_t *X = NULL; /* of sc_lcs_pt_t */
  sc_lcs_pt_t *pt;
  int *L = NULL;
  int x, z;
  int i, j, rc = -1;

  assert(min_z > 0);

  if(r == 0) r = strlen(S);
  if(n == 0) n = strlen(T);

  if((X = slist_alloc()) == NULL ||
     (bits = slist_alloc()) == NULL ||
     (L = malloc(sizeof(int) * (r * n))) == NULL)
    goto done;

  /* Iterate over S */
  x = 0;
  for(i=0; i<r; i++)
    {
      /* Iterate over T */
      for(j=0; j<n; j++)
	{
	  if(S[i] == '\0' || T[j] == '\0')
	    {
	      L[x] = 0;
	    }
	  else if(S[i] == T[j])
	    {
	      if(i == 0 || j == 0)
		L[x] = 1;
	      else
		L[x] = L[x-n-1] + 1; /* L[x] = L[((i-1) * n) + (j-1)] + 1; */
	    }
	  else
	    {
	      L[x] = 0;
	    }
	  x++; /* x = (i * n) + j; */
	}
    }

#if 0
  for(i=1; i<r; i++)
    for(j=1; j<n; j++)
      if(L[(i * n) + j] != 0 && L[(i * n) + j] - 1 != L[((i-1) * n) + (j-1)])
	printf(" ***");
  printf("\n");
  printf("%s %s\n", S, T);
  printf("  |");
  for(i=0; i<n; i++)
    printf(" %2c", T[i] != '\0' ? T[i] : ' ');
  printf("\n");
  for(i=0; i<r; i++)
    {
      printf("%c |", S[i] != '\0' ? S[i] : ' ');
      for(j=0; j<n; j++)
	{
	  printf(" %2d", L[(i * n) + j]);
	}
      printf("\n");
    }
#endif

  for(;;)
    {
      x = 0; z = 0;
      for(i=0; i<r; i++)
	{
	  for(j=0; j<n; j++)
	    {
	      if(L[x] > z)
		{
		  z = L[x];
		  slist_empty_cb(bits, (slist_free_t)sc_lcs_pt_free);
		  sc_lcs_pt_push(bits, i-L[x]+1, i, j-L[x]+1, j);
		}
	      else if(L[x] == z && z > 0)
		{
		  sc_lcs_pt_push(bits, i-L[x], i, j-L[x], j);
		}
	      x++;
	    }
	}

      if(z < min_z)
	break;

      pt = slist_head_pop(bits);
      slist_empty_cb(bits, (slist_free_t)sc_lcs_pt_free);
      slist_tail_push(X, pt);

      for(i=pt->S_start; i<pt->S_end; i++)
	{
	  for(j=0; j<n; j++)
	    L[(i * n) + j] = 0;
	}
      for(j=0; j<n; j++)
	{
	  if((z = L[idx(r,n,pt->S_end,j)]) == 0)
	    continue;
	  for(i=0;j+i<n&&(pt->S_end+i)<r && L[idx(r,n,pt->S_end+i,j+i)]>0;i++)
	    L[((pt->S_end + i) * n) + (j + i)] -= z;
	}

      for(j=pt->T_start; j<pt->T_end; j++)
	{
	  for(i=0; i<r; i++)
	    L[(i * n) + j] = 0;
	}
      for(i=0; i<r; i++)
	{
	  if((z = L[idx(r,n,i,pt->T_end)]) == 0)
	    continue;
	  for(j=0;pt->T_end+j<n&&(i+j)<r && L[idx(r,n,i+j,pt->T_end+j)]>0;j++)
	    L[((i+j) * n) + (pt->T_end + j)] -= z;
	}
    }

  slist_qsort(X, (slist_cmp_t)sc_lcs_pt_cmp);
  //lcs_print(S, T, X);

  rc = 0;

 done:
  if(rc != 0 && X != NULL)
    {
      slist_free_cb(X, (slist_free_t)sc_lcs_pt_free);
      X = NULL;
    }
  if(bits != NULL) slist_free_cb(bits, (slist_free_t)sc_lcs_pt_free);
  if(L != NULL) free(L);
  return X;
}

static void sc_css_free(sc_css_t *css)
{
  if(css->css != NULL) free(css->css);
  free(css);
  return;
}

static sc_css_t *sc_css_alloc0(void)
{
  sc_css_t *css;
  if((css = malloc(sizeof(sc_css_t))) == NULL)
    return NULL;
  css->css = NULL;
  css->cssc = 0;
  css->len = 0;
  css->count = 0;
  return css;
}

static sc_css_t *sc_css_alloc(size_t len)
{
  sc_css_t *css;
  if((css = malloc(sizeof(sc_css_t))) == NULL)
    goto err;
  if(len > 0)
    {
      if((css->css = malloc(len)) == NULL)
	goto err;
    }
  else css->css = NULL;
  css->cssc = 0;
  css->len = 0;
  css->count = 0;
  return css;

 err:
  if(css != NULL) sc_css_free(css);
  return NULL;
}

static int sc_css_hasalpha(const sc_css_t *css)
{
  char *ptr = css->css;
  int i;

  for(i=0; i<css->cssc; i++)
    {
      while(*ptr != '\0')
	{
	  if(isalpha((unsigned char)*ptr) != 0)
	    return 1;
	  ptr++;
	}
      ptr++;
    }

  return 0;
}

static char *sc_css_tostr(const sc_css_t *css,char delim,char *out,size_t len)
{
  size_t off = 0;
  char *ptr = css->css;
  int i;

  for(i=0; i<css->cssc; i++)
    {
      if(off + 1 >= len)
	break;
      if(i > 0)
	{
	  if(delim != '\0')
	    out[off++] = delim;
	  ptr++;
	}
      while(*ptr != '\0')
	{
	  if(off + 1 >= len)
	    break;
	  out[off++] = *ptr;
	  ptr++;
	}
    }
  out[off++] = '\0';
  assert(off <= len);

  return out;
}

/*
 * sc_css_morespecific
 *
 * try and determine if the evaluated css contains the string in base, plus
 * a bit extra.
 */
static int sc_css_morespecific(const sc_css_t *base, const sc_css_t *eval)
{
  const char *base_p = base->css, *eval_p = eval->css;
  int base_i = 0, eval_i = 0;

  if(eval->len <= base->len)
    return 0;

  while(eval_i < eval->cssc)
    {
      if(strcmp(base_p, eval_p) == 0)
	{
	  base_i++;
	  if(base_i == base->cssc)
	    return 1;
	  while(*base_p != '\0')
	    base_p++;
	  base_p++;

	  eval_i++;
	  while(*eval_p != '\0')
	    eval_p++;
	  eval_p++;
	}
      else
	{
	  eval_i++;
	  if(eval_i == eval->cssc)
	    break;
	  while(*eval_p != '\0')
	    eval_p++;
	  eval_p++;
	}
    }

  return 0;
}

/*
 * sc_css_morespecific_ex
 *
 * return the "bit extra" in the out css.
 */
static int sc_css_morespecific_ex(const sc_css_t *base, const sc_css_t *eval,
				  sc_css_t **out)
{
  const char *base_p = base->css, *eval_p = eval->css;
  int base_i = 0, eval_i = 0;
  sc_css_t *tmp = NULL;
  size_t len;

  *out = NULL;

  /* nothing to return if eval is not more specific than base */
  if(sc_css_morespecific(base, eval) == 0)
    return 0;

  /* alloc a css structure to contain the more specific part */
  if((tmp = sc_css_alloc(eval->len + 1)) == NULL)
    return -1;

  while(eval_i < eval->cssc)
    {
      if(base_i < base->cssc && strcmp(base_p, eval_p) == 0)
	{
	  base_i++;
	  if(base_i < base->cssc)
	    {
	      while(*base_p != '\0')
		base_p++;
	      base_p++;
	    }
	}
      else
	{
	  len = strlen(eval_p) + 1;
	  memcpy(tmp->css, eval_p, len);
	  tmp->cssc++;
	  tmp->len += len;
	}

      eval_i++;
      if(eval_i == eval->cssc)
	break;
      while(*eval_p != '\0')
	eval_p++;
      eval_p++;
    }

  *out = tmp;
  return 0;
}

/*
 * sc_css_morespecific_ov
 *
 * which output vector, if any, contains the "bit extra" specified in the
 * css structure.
 */
static int sc_css_morespecific_ov(sc_rework_t *rew, sc_css_t *ex,
				  const sc_iface_t *iface, int *cap)
{
  int i, m, start;
  size_t len;

  *cap = 0;

#ifdef HAVE_PCRE2
  m = pcre2_match(rew->pcre[0], (PCRE2_SPTR)iface->name, iface->len, 0, 0,
		  rew->match_data, NULL);
#else
  m = pcre_exec(rew->pcre[0], rew->study[0], iface->name, iface->len, 0, 0,
		rew->ovector, rew->n);
#endif

  assert(m != 0);
  if(m <= 0)
    return -1;

#ifdef HAVE_PCRE2
  rew->ovector = pcre2_get_ovector_pointer(rew->match_data);
#endif

  for(i=1; i<m; i++)
    {
      start = rew->ovector[2*i];
      len = rew->ovector[(2*i)+1] - start;
      if(len != ex->len-1)
	continue;
      if(memcmp(iface->name + start, ex->css, len) == 0)
	{
	  *cap = i;
	  return 1;
	}
    }

  return 0;
}

static uint32_t sc_css_strlen(const sc_css_t *css)
{
  char *ptr = css->css;
  uint32_t len = 0;
  int i;

  for(i=0; i<css->cssc; i++)
    {
      while(*ptr != '\0')
	{
	  ptr++;
	  len++;
	}
      ptr++;
    }

  return len;
}

static int sc_css_css_cmp(const sc_css_t *a, const sc_css_t *b)
{
  int x;
  if((x = memcmp(a->css, b->css, a->len <= b->len ? a->len : b->len)) != 0)
    return x;
  if(a->len < b->len) return -1;
  if(a->len > b->len) return  1;
  return 0;
}

static int sc_css_count_cmp(const sc_css_t *a, const sc_css_t *b)
{
  if(a->count > b->count) return -1;
  if(a->count < b->count) return  1;
  return sc_css_css_cmp(a, b);
}

static int sc_css_count_min_cmp(const sc_css_t *a, const sc_css_t *b)
{
  if(a->count < b->count) return -1;
  if(a->count > b->count) return  1;
  return 0;
}

static sc_css_t *sc_css_alloc_pt(const char *str, int *m, int mc)
{
  sc_css_t *css = NULL;
  size_t off = 0;
  int i;

  for(i=0; i<mc; i+=2)
    off += m[i+1] - m[i] + 1 + 1;

  if((css = sc_css_alloc(off)) == NULL)
    return NULL;
  for(i=0; i<mc; i+=2)
    {
      memcpy(css->css+css->len, &str[m[i]], m[i+1] - m[i] + 1);
      css->len += m[i+1] - m[i] + 1;
      css->css[css->len++] = '\0';
      css->cssc++;
    }

  return css;
}

static sc_css_t *sc_css_alloc_xor(const char *str, size_t len, size_t *m, size_t mc)
{
  sc_css_t *css = NULL;
  int *n = NULL, nc;
  if(pt_xor(len, m, mc, &n, &nc) == 0)
    css = sc_css_alloc_pt(str, n, nc);
  if(n != NULL) free(n);
  return css;
}

/*
 * sc_css_alloc_lcs
 *
 * Allocate an sc_css_t struct containing the common substrings for
 * a pair of strings.
 * param X: A list of sc_lcs_pt_t.
 * param S: The label excluding the suffix.
 * returns: An sc_css_t struct containing the common substrings.
 */
static sc_css_t *sc_css_alloc_lcs(const slist_t *X, const char *S)
{
  sc_css_t *css = NULL;
  slist_node_t *sn;
  sc_lcs_pt_t *pt;
  size_t off = 0;

  assert(slist_count(X) > 0);

  for(sn=slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      off += pt->S_end - pt->S_start + 1 + 1;
    }

  if((css = sc_css_alloc(off)) == NULL)
    goto err;
  for(sn=slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      memcpy(css->css+css->len, &S[pt->S_start], pt->S_end - pt->S_start + 1);
      css->len += pt->S_end - pt->S_start + 1;
      css->css[css->len++] = '\0';
      css->cssc++;
    }

  return css;

 err:
  if(css != NULL) sc_css_free(css);
  return NULL;
}

static sc_css_t *sc_css_alloc_tags(const char *str)
{
  sc_css_t *css = NULL;
  int x = 0, i = 0;

  if((css = sc_css_alloc(strlen(str) + 1)) == NULL)
    return NULL;

  /* skip over any training non-alnum characters */
  while(str[i] != '\0' && isalnum((unsigned char)str[i]) == 0)
   i++;
  if(str[i] == '\0')
    return css;

  while(str[i] != '\0')
    {
      if(isalnum((unsigned char)str[i]) != 0)
	{
	  css->css[css->len++] = str[i++];
	  x++;
	  continue;
	}
      css->css[css->len++] = '\0';
      css->cssc++;
      x = 0;

      while(str[i] != '\0')
	{
	  if(isalnum((unsigned char)str[i]) != 0)
	    break;
	  i++;
	}
    }

  if(x > 0)
    {
      css->css[css->len++] = '\0';
      css->cssc++;
    }

  return css;
}

static sc_css_t *sc_css_dup(const sc_css_t *css)
{
  sc_css_t *x;
  if((x = malloc(sizeof(sc_css_t))) == NULL ||
     (x->css = memdup(css->css, css->len)) == NULL)
    {
      /* not sc_css_free because x is not malloc_zero */
      if(x != NULL) free(x);
      return NULL;
    }
  x->len = css->len;
  x->cssc = css->cssc;
  x->count = css->count;
  return x;
}

static sc_css_t *sc_css_find(splaytree_t *tree, const sc_css_t *css)
{
  assert(css->cssc > 0);
  return splaytree_find(tree, css);
}

static int sc_css_insert(splaytree_t *tree, const sc_css_t *css)
{
  assert(css->cssc > 0);
  if(splaytree_insert(tree, css) == NULL)
    return -1;
  return 0;
}

static sc_css_t *sc_css_get(splaytree_t *tree, const sc_css_t *css)
{
  sc_css_t *x;
  assert(css->cssc > 0);
  if((x = sc_css_find(tree, css)) != NULL)
    return x;
  if((x = sc_css_dup(css)) == NULL ||
     splaytree_insert(tree, x) == NULL)
    goto err;
  return x;

 err:
  if(x != NULL) sc_css_free(x);
  return NULL;
}

static sc_css_t *sc_css_get_str(splaytree_t *tree, const char *str)
{
  sc_css_t fm;

  fm.css = (char *)str;
  fm.cssc = 1;
  fm.len = strlen(str) + 1;
  fm.count = 0;

  return sc_css_get(tree, &fm);
}

/*
 * sc_css_match
 *
 * is all of the common substring in the input string?
 */
static int sc_css_match(const sc_css_t *css,const char *S,size_t *out,int alnum)
{
  int i, c, x, y;

  assert(css->cssc != 0);

  c = 0; x = 0; i = 0;
  while(i < css->cssc)
    {
      /* end of string, no match */
      if(S[x] == '\0')
	return 0;
      if(S[x] != css->css[c])
	{
	  x++;
	  continue;
	}

      /* go through and see if this part matches this substring portion */
      y = 0;
      while(S[x+y] == css->css[c+y] && css->css[c+y] != '\0')
	y++;

      /* this part matched */
      if(css->css[c+y] == '\0' &&
	 (alnum == 0 ||
	  ((x == 0 || isalnum((unsigned char)S[x-1]) == 0) &&
	   isalnum((unsigned char)S[x+y]) == 0)))
	{
	  if(out != NULL)
	    {
	      out[(i*2)+0] = x;
	      out[(i*2)+1] = x+y-1;
	    }

	  i++;
	  c = c + y + 1;
	  x = x + y;
	}
      else x++;
    }

  return 1;
}

static sc_css_t *sc_css_matchxor(const sc_css_t *css, const sc_ifacedom_t *ifd)
{
  sc_css_t *out = NULL;
  size_t l, r, *X_array = NULL;
  int Xc;
  int rc = -1;

  Xc = css->cssc * 2;
  if((out = sc_css_alloc(ifd->len + 1)) == NULL ||
     (X_array = malloc_zero(Xc * sizeof(size_t))) == NULL ||
     sc_css_match(css, ifd->label, X_array, 1) != 1)
    goto done;

  if(X_array[0] > 0)
    {
      l = 0;
      r = X_array[0] - 1;
      while(l < r && isalnum((unsigned char)ifd->label[l]) == 0)
	l++;
      while(r > l && isalnum((unsigned char)ifd->label[r]) == 0)
	r--;

      if(l != r)
	{
	  memcpy(out->css+out->len, ifd->label+l, r - l + 1);
	  out->len += r - l + 1;
	  out->css[out->len++] = '\0';
	  out->cssc++;
	}
    }
  rc = 0;

 done:
  if(rc != 0 && out != NULL)
    {
      sc_css_free(out);
      out = NULL;
    }
  if(X_array != NULL) free(X_array);
  return out;
}

static int sc_css_geomap(const sc_css_t *css, const uint8_t *geotypes,
			 sc_geomap_t *map)
{
  size_t off, len, xi;
  sc_ptrc_t x[2];
  char *ptr = css->css;
  char *out;
  int i;

  map->code[0] = map->st[0] = map->cc[0] = '\0';
  map->type = 0; map->codelen = 0;
  memset(x, 0, sizeof(x));
  xi = 0;

  for(i=0; i<css->cssc; i++)
    {
      /* skip over the null pointer */
      if(i > 0)
	{
	  assert(*ptr == '\0');
	  ptr++;
	}

      if(geotypes[i] == GEOHINT_TYPE_CC || geotypes[i] == GEOHINT_TYPE_ST)
	{
	  if(geotypes[i] == GEOHINT_TYPE_CC)
	    {
	      len = sizeof(map->cc);
	      out = map->cc;
	    }
	  else
	    {
	      len = sizeof(map->st);
	      out = map->st;
	    }

	  /* copy the cc/st into place */
	  off = 0;
	  while(*ptr != '\0')
	    {
	      if(off + 1 >= len)
		return -1;
	      out[off++] = *ptr;
	      ptr++;
	    }
	  out[off] = '\0';
	}
      else
	{
	  if(xi >= sizeof(x) / sizeof(sc_ptrc_t))
	    return -1;
	  x[xi].ptr = ptr;
	  while(*ptr != '\0')
	    ptr++;
	  x[xi].c = ptr - (char *)x[xi].ptr;
	  map->type = geotypes[i];
	  xi++;
	}
    }

  return sc_geomap_code(map, x, xi);
}

static const char *geotype_tostr(uint8_t type)
{
  switch(type)
    {
    case GEOHINT_TYPE_IATA:     return "iata";
    case GEOHINT_TYPE_ICAO:     return "icao";
    case GEOHINT_TYPE_CLLI:     return "clli";
    case GEOHINT_TYPE_PLACE:    return "place";
    case GEOHINT_TYPE_LOCODE:   return "locode";
    case GEOHINT_TYPE_FACILITY: return "facility";
    case GEOHINT_TYPE_CC:       return "cc";
    case GEOHINT_TYPE_ST:       return "st";
    case GEOHINT_TYPE_VP:       return "vp";
    }
  return NULL;
}

static uint8_t geotype_uint8(const char *type)
{
  if(strcasecmp(type, "iata") == 0)     return GEOHINT_TYPE_IATA;
  if(strcasecmp(type, "icao") == 0)     return GEOHINT_TYPE_ICAO;
  if(strcasecmp(type, "clli") == 0)     return GEOHINT_TYPE_CLLI;
  if(strcasecmp(type, "place") == 0)    return GEOHINT_TYPE_PLACE;
  if(strcasecmp(type, "locode") == 0)   return GEOHINT_TYPE_LOCODE;
  if(strcasecmp(type, "facility") == 0) return GEOHINT_TYPE_FACILITY;
  if(strcasecmp(type, "cc") == 0)       return GEOHINT_TYPE_CC;
  if(strcasecmp(type, "st") == 0)       return GEOHINT_TYPE_ST;
  return 0;
}

static int sc_geomap2hint_tojson(const sc_geomap2hint_t *m2h,
				 char *buf, size_t len)
{
  char place[512];
  sc_geohint_t *gh;
  size_t off = 0;

  string_concat(buf, len, &off,
		"{\"code\":\"%s\", \"type\":\"%s\"",
		m2h->map.code, geotype_tostr(m2h->map.type));
  if(m2h->map.st[0] != '\0')
    string_concat(buf, len, &off, ", \"st\":\"%s\"", m2h->map.st);
  if(m2h->map.cc[0] != '\0')
    string_concat(buf, len, &off, ", \"cc\":\"%s\"", m2h->map.cc);

  if(m2h->hint != NULL)
    {
      gh = m2h->hint;
      if(sc_geohint_place_tojson(gh, place, sizeof(place)) != 0)
	return -1;

      string_concat(buf, len, &off, ", \"learned\":%u, \"tp\":%u, \"fp\":%u",
		    gh->learned, m2h->tp_c, m2h->fp_c);

      if(gh->type != GEOHINT_TYPE_CLLI || no_clli == 0)
	string_concat(buf, len, &off,
		      ", \"location\":%s, \"lat\":\"%.6f\", \"lng\":\"%.6f\"",
		      place, gh->lat, gh->lng);
    }
  string_concat(buf, len, &off, "}");
  return 0;
}

static int sc_geomap2hint_cmp(const sc_geomap2hint_t *a,
			      const sc_geomap2hint_t *b)
{
  int x;
  if((x = sc_geomap_cmp(&a->map, &b->map)) != 0) return x;
  return ptrcmp(a->hint, b->hint);
}

static sc_geomap2hint_t *sc_geomap2hint_get(splaytree_t *tree,
					    sc_geomap_t *map,sc_geohint_t *hint)
{
  sc_geomap2hint_t fm, *m2h;
  memcpy(&fm.map, map, sizeof(sc_geomap_t));
  fm.hint = hint;
  if((m2h = splaytree_find(tree, &fm)) != NULL)
    return m2h;
  if((m2h = malloc_zero(sizeof(sc_geomap2hint_t))) == NULL)
    return NULL;
  memcpy(&m2h->map, map, sizeof(sc_geomap_t));
  m2h->hint = hint;
  if(splaytree_insert(tree, m2h) == NULL)
    {
      free(m2h);
      return NULL;
    }
  return m2h;
}

static slist_t *sc_geomap2hint_make(sc_regex_t *re, slist_t *ifi_list)
{
  splaytree_t *tree = NULL;
  slist_node_t *sn;
  slist_t *list = NULL;
  sc_ifaceinf_t *ifi;
  sc_geomap2hint_t *m2h;
  sc_geomap_t map;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_geomap2hint_cmp)) == NULL ||
     (list = slist_alloc()) == NULL)
    goto err;

  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if(ifi->css == NULL ||
	 (ifi->class != '+' && ifi->class != '!' && ifi->class != '?'))
	continue;
      sc_css_geomap(ifi->css, re->regexes[ifi->regex]->plan, &map);
      if((m2h = sc_geomap2hint_get(tree, &map, ifi->geohint)) == NULL)
	goto err;
      if(ifi->class == '+')
	m2h->tp_c++;
      else if(ifi->class == '!')
	m2h->fp_c++;
    }
  splaytree_inorder(tree, tree_to_slist, list);
  splaytree_free(tree, NULL); tree = NULL;
  return list;

 err:
  if(tree != NULL) splaytree_free(tree, free);
  if(list != NULL) slist_free_cb(list, free);
  return NULL;
}

/*
 * sc_remerge_cmp
 *
 */
static int sc_remerge_cmp(const sc_remerge_t *a, const sc_remerge_t *b)
{
  return sc_css_css_cmp(a->css, b->css);
}

static void sc_remerge_free(sc_remerge_t *rem)
{
  if(rem->css != NULL) sc_css_free(rem->css);
  if(rem->list != NULL) slist_free_cb(rem->list, free);
  free(rem);
  return;
}

static sc_remerge_t *sc_remerge_get(splaytree_t *tree, sc_css_t *css)
{
  sc_remerge_t fm, *rem;

  fm.css = css;
  if((rem = splaytree_find(tree, &fm)) != NULL)
    return rem;

  if((rem = malloc_zero(sizeof(sc_remerge_t))) == NULL ||
     (rem->css = sc_css_dup(css)) == NULL ||
     (rem->list = slist_alloc()) == NULL ||
     splaytree_insert(tree, rem) == NULL)
    goto err;

  return rem;

 err:
  if(rem != NULL) sc_remerge_free(rem);
  return NULL;
}

static int sc_regex_show(const sc_regex_t *re)
{
  if(do_show == 0 || (do_show & (1 << re->class)) != 0)
    return 1;
  return 0;
}

/*
 * sc_regex_caprep
 *
 * substitute the strings from the css into the capture portions of
 * the regex
 */
static char *sc_regex_caprep_css(const char *in, const sc_css_t *css)
{
  const char *ptr = in;
  const char *css_ptr = css->css;
  int css_i = 0;
  char *out = NULL, *dup;
  size_t off = 0, len;

  /* allocate a temporary buffer that should be large enough */
  len = strlen(in) + sc_css_strlen(css) + 1;
  if((out = malloc(len)) == NULL)
    goto err;

  while(*ptr != '\0')
    {
      if(ptr[0] == '\\')
	{
	  if(ptr[1] == '\0')
	    goto err;
	  out[off++] = *ptr; ptr++;
	  out[off++] = *ptr; ptr++;
	}
      else if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  out[off++] = *ptr;
	  ptr++;
	}
      else if(*ptr == '(')
	{
	  if(css_i == css->cssc)
	    goto err;
	  out[off++] = *ptr; ptr++;
	  while(*css_ptr != '\0')
	    {
	      out[off++] = *css_ptr;
	      css_ptr++;
	    }
	  css_i++;
	  while(*ptr != '\0')
	    {
	      if(*ptr == ')')
		break;
	      else if(ptr[0] == '\\')
		{
		  if(ptr[1] == '\0')
		    goto err;
		  ptr += 2;
		}
	      ptr++;
	    }
	  if(*ptr != ')')
	    goto err;
	  out[off++] = *ptr; ptr++;
	}
      else
	{
	  out[off++] = *ptr;
	  ptr++;
	}
    }

  /* return a string only just large enough */
  out[off++] = '\0';
  if((dup = memdup(out, off)) == NULL)
    return out;
  free(out);
  return dup;

 err:
  if(out != NULL) free(out);
  return NULL;
}

/*
 * sc_regex_caprep
 *
 * replace the specified capture element in the regex with the string
 * in lit.
 */
static char *sc_regex_caprep(const char *in, int rep, int cap, const char *lit)
{
  const char *ptr = in;
  char *out, *dup;
  int element = 0;
  size_t off = 0, len;

  /* allocate a temporary buffer that should be large enough */
  len = strlen(in) + strlen(lit) + 1;
  if((out = malloc(len)) == NULL)
    return NULL;

  while(*ptr != '\0')
    {
      if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  out[off++] = *ptr;
	  ptr++;
	}
      else if(*ptr == '(' && ++element == rep)
	{
	  if(cap != 0) out[off++] = '(';
	  while(*lit != '\0')
	    {
	      out[off++] = *lit;
	      lit++;
	    }
	  if(cap != 0) out[off++] = ')';
	  while(*ptr != ')')
	    ptr++;
	  ptr++;
	}
      else
	{
	  out[off++] = *ptr;
	  ptr++;
	}
    }

  /* return a string only just large enough */
  out[off++] = '\0';
  if((dup = memdup(out, off)) == NULL)
    return out;
  free(out);
  return dup;
}

/*
 * sc_regex_caprep_list
 *
 * replace the specified capture element in the regex with the elements
 * in the list, using an or statement in the regex syntax, i.e.,
 * (?:foo|bar)
 */
static char *sc_regex_caprep_list(const char *in, int rep, dlist_t *list)
{
  const char *ptr = in;
  const char *litp;
  dlist_node_t *dn;
  sc_css_t *lit;
  char *out, *dup;
  int cap = 0;
  size_t off, len;
  int i = 0;

  /* compute the upper bound on the string size necessary */
  len = 0;
  dlist_qsort(list, (dlist_cmp_t)sc_css_css_cmp);
  for(dn=dlist_head_node(list); dn != NULL; dn=dlist_node_next(dn))
    {
      lit = dlist_node_item(dn);
      len += lit->len + 1;
    }
  len += strlen(in) + 3;
  if((out = malloc(len)) == NULL)
    return NULL;

  off = 0;
  while(*ptr != '\0')
    {
      if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  out[off++] = *ptr;
	  ptr++;
	}
      else if(*ptr == '(' && ++cap == rep)
	{
	  if(dlist_count(list) > 1)
	    {
	      out[off++] = '('; out[off++] = '?'; out[off++] = ':';
	    }
	  for(dn=dlist_head_node(list); dn != NULL; dn=dlist_node_next(dn))
	    {
	      if(i > 0) out[off++] = '|';
	      lit = dlist_node_item(dn);
	      litp = lit->css;
	      while(*litp != '\0')
		{
		  out[off++] = *litp;
		  litp++;
		}
	      i++;
	    }
	  if(dlist_count(list) > 1)
	    out[off++] = ')';
	  while(*ptr != ')')
	    ptr++;
	  ptr++;
	}
      else
	{
	  out[off++] = *ptr;
	  ptr++;
	}
    }

  out[off++] = '\0';
  if((dup = memdup(out, off)) == NULL)
    return out;
  free(out);
  return dup;
}

static char *sc_regex_caponly(const char *in, int only)
{
  const char *ptr = in;
  char *out = NULL;
  int cap = 0;
  size_t off = 0;
  char ch;

  if((out = malloc(strlen(in) + 1)) == NULL)
    return NULL;

  while(*ptr != '\0')
    {
      ch = *ptr; ptr++;
      if(ch == '(')
	{
	  cap++;
	  if(cap != only)
	    continue;
	}
      else if(ch == ')')
	{
	  if(cap != only)
	    continue;
	}
      out[off++] = ch;
    }

  out[off] = '\0';
  return out;
}

static int sc_regex_capget_css_lit2(char *buf, size_t len, size_t *off_in,
				    const char *start, const char *end)
{
  const char *litend = end;
  const char *ptr = start;
  size_t off = *off_in;

  while(litend >= start && isalnum((unsigned char)*litend) == 0)
    litend--;

  buf[off++] = '(';

  if(litend < start)
    {
      while(ptr <= end)
	{
	  buf[off++] = *ptr;
	  ptr++;
	}
      buf[off++] = ')';
      goto done;
    }

  while(ptr <= litend)
    {
      buf[off++] = *ptr;
      ptr++;
    }
  buf[off++] = ')';
  while(ptr <= end)
    {
      buf[off++] = *ptr;
      ptr++;
    }

 done:
  *off_in = off;
  return 0;
}

static int sc_regex_capget_css(const char *in, sc_css_t **out)
{
  const char *start = NULL, *ptr;
  sc_css_t *css = NULL;
  slist_t *list = NULL;
  size_t len = 0, tmp;
  char *dup = NULL;
  int rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;

  ptr = in;
  while(*ptr != '\0')
    {
      if(ptr[0] == '(' && ptr[1] != '?')
	{
	  start = ptr + 1;
	}
      else if(ptr[0] == ')' && start != NULL)
	{
	  tmp = ptr - start + 1;
	  if((dup = memdup(start, tmp)) == NULL)
	    goto done;
	  dup[tmp-1] = '\0';
	  if(slist_tail_push(list, dup) == NULL)
	    goto done;
	  dup = NULL;
	  start = NULL;
	  len += tmp;
	}
      ptr++;
    }

  if((css = sc_css_alloc(len)) == NULL)
    goto done;
  while((dup = slist_head_pop(list)) != NULL)
    {
      len = strlen(dup);
      memcpy(css->css + css->len, dup, len);
      css->len += len;
      free(dup); dup = NULL;
      css->cssc++;
      css->css[css->len++] = '\0';
    }
  *out = css; css = NULL;
  slist_free(list); list = NULL;
  rc = 0;

 done:
  if(list != NULL) slist_free_cb(list, (slist_free_t)free);
  if(css != NULL) sc_css_free(css);
  return rc;
}

static int sc_regex_capget(const char *in, int capitem, char *out, size_t len)
{
  const char *ptr = in;
  size_t off = 0;
  int cap = 0;

  while(*ptr != '\0')
    {
      if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  ptr++;
	}
      else if(ptr[0] == '(' && ++cap == capitem)
	{
	  ptr++;
	  while(*ptr != ')' && *ptr != '\0')
	    {
	      out[off++] = *ptr;
	      ptr++;
	    }
	  if(*ptr != ')')
	    return -1;
	  out[off] = '\0';
	  return 0;
	}
      else
	{
	  ptr++;
	}
    }
  return -1;
}

static int sc_regex_pt_decons2(slist_t *list, size_t *c, size_t cc, size_t co,
			       size_t *o, size_t oo, int use)
{
  sc_ptrc_t *ptrc = NULL;

  if(use != 0)
    {
      o[oo++] = c[co];
      o[oo++] = c[co+1];
    }

  co += 2;

  if(co == cc)
    {
      if(oo == 0)
	return 0;
      if((ptrc = malloc_zero(sizeof(sc_ptrc_t))) == NULL ||
	 (ptrc->ptr = memdup(o, sizeof(size_t) * oo)) == NULL ||
	 slist_tail_push(list, ptrc) == NULL)
	goto err;
      ptrc->c = oo;
      ptrc = NULL;
    }
  else
    {
      if(sc_regex_pt_decons2(list, c, cc, co, o, oo, 0) != 0 ||
	 sc_regex_pt_decons2(list, c, cc, co, o, oo, 1) != 0)
	goto err;
    }

  return 0;

 err:
  if(ptrc != NULL) sc_ptrc_free2(ptrc);
  return -1;
}

static int sc_regex_pt_decons(slist_t *list, size_t *c, size_t cc)
{
  size_t *dup = NULL;
  int rc = -1;

  if(cc < 4)
    return 0;

  if((dup = memdup(c, sizeof(size_t) * cc)) == NULL ||
     sc_regex_pt_decons2(list, c, cc, 0, dup, 0, 0) != 0 ||
     sc_regex_pt_decons2(list, c, cc, 0, dup, 0, 1) != 0)
    goto done;
  rc = 0;

 done:
  if(dup != NULL) free(dup);
  return rc;
}

/*
 * sc_css_reduce_ls
 *
 * given a set of literal values in the tree, escape them as necessary,
 * and build less-specific versions of digit classes with \d* and \d+.
 * return the literal values in a new list.
 */
static dlist_t *sc_css_reduce_ls(splaytree_t *tree)
{
  dlist_t *out_list = NULL;
  splaytree_t *out = NULL;
  slist_t *list = NULL;
  slist_node_t *sn;
  sc_css_t *css, fm;
  char *ptr;
  char buf[512], tmp[8];
  int al, num, skip;
  size_t r, off;

  if((out = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL ||
     (list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(tree, tree_to_slist, list);

  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
    {
      css = slist_node_item(sn);
      if(css->cssc != 1)
	continue;

      /* make a copy of the literal on the out list, properly escaped */
      if(re_escape_str(buf, sizeof(buf), css->css) == NULL)
	goto done;
      fm.css = buf;
      fm.cssc = 1;
      fm.count = 3;
      fm.len = strlen(buf) + 1;
      if(sc_css_get(out, &fm) == NULL)
	goto done;

      /*
       * check to see if we are going to use \d in the literal.  the
       * rule with this part of the code is that we are only allowed
       * digits after the first occurance of a digit in the string.
       * i.e, we allow ae2.
       *
       * the next block of code handles cases like ae-1-2.
       */
      al = 0; num = 0; skip = 0;
      for(ptr = css->css; *ptr != '\0' && skip == 0; ptr++)
	{
	  if(isdigit((unsigned char)*ptr) == 0)
	    {
	      if(num != 0)
		skip = 1;
	      else if(al == 0)
		al = 1;
	    }
	  else
	    {
	      if(num == 0)
		num = 1;
	    }
	}

      /* if we are skipping, or there are no digits here, move on */
      if(skip != 0 || num == 0)
	continue;

      /* do proper off / len comparisons to prevent buffer overflow */
      off = 0;
      if(al != 0)
	{
	  for(ptr = css->css; *ptr != '\0'; ptr++)
	    {
	      if(isdigit((unsigned char)*ptr) != 0)
		break;
	      if((r = re_escape(tmp, sizeof(tmp), *ptr)) == 0)
		goto done;
	      if(sizeof(buf) - off < r)
		goto done;
	      /* string_concat(buf, sizeof(buf), &off, tmp); */
	      memcpy(buf+off, tmp, r); off += r;
	    }
	}
      buf[off++] = '\\';
      buf[off++] = 'd';
      buf[off++] = '+';
      buf[off++] = '\0';

      fm.css = buf;
      fm.cssc = 1;
      fm.len = off;
      fm.count = 2;
      if(sc_css_get(out, &fm) == NULL)
	goto done;

      /* don't allow a regex that is just \d* */
      if(off == 4)
	continue;

      /* the last character and the score changes, but nothing else */
      buf[off-2] = '*';
      fm.count = 1;
      if(sc_css_get(out, &fm) == NULL)
	goto done;
    }

  /* this block of code takes ae-1-2 and outputs ae-\d+-\d+ */
  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
    {
      css = slist_node_item(sn);
      if(css->cssc != 1)
	continue;

      off = 0;
      ptr = css->css;
      while(*ptr != '\0')
	{
	  if(isdigit((unsigned char)*ptr) != 0)
	    {
	      buf[off++] = '\\';
	      buf[off++] = 'd';
	      buf[off++] = '+';
	      ptr++;
	      while(isdigit((unsigned char)*ptr) != 0)
		ptr++;
	    }
	  else
	    {
	      if((r = re_escape(tmp, sizeof(tmp), *ptr)) == 0)
		goto done;
	      /* string_concat(buf, sizeof(buf), &off, tmp); */
	      memcpy(buf+off, tmp, r); off += r;
	      ptr++;
	    }
	}
      buf[off++] = '\0';

      fm.css = buf;
      fm.cssc = 1;
      fm.len = off;
      fm.count = 1;
      if(sc_css_get(out, &fm) == NULL)
	goto done;
    }

  if((out_list = dlist_alloc()) == NULL)
    goto done;
  splaytree_inorder(out, tree_to_dlist, out_list);
  splaytree_free(out, NULL); out = NULL;

 done:
  if(out != NULL) splaytree_free(out, (splaytree_free_t)sc_css_free);
  if(list != NULL) slist_free(list);
  return out_list;
}

static int sc_css_reduce_pair(sc_css_t *a, sc_css_t *b, int trim, int min_z,
			      sc_css_t **out)
{
  sc_css_t *css = NULL;
  slist_t *X = NULL;
  int rc = -1;

  *out = NULL;
  if((X = lcs(a->css, a->len, b->css, b->len, min_z)) == NULL)
    goto done;
  if(trim == 1)
    lcs_trim(X, a->css, b->css);
  else if(trim == 2)
    lcs_trim_class(X, a->css, b->css);
  if(slist_count(X) == 0 || lcs_check(X) == 0)
    {
      rc = 0;
      goto done;
    }

  if((css = sc_css_alloc_lcs(X, a->css)) == NULL)
    goto done;
  *out = css;
  rc = 0;

 done:
  if(X != NULL) slist_free_cb(X, (slist_free_t)sc_lcs_pt_free);
  return rc;
}

/*
 * sc_css_reduce
 *
 * trim mode 0: no trim
 * trim mode 1: trim non non-alpha
 * trim mode 2: trim on character class change
 *
 * note: the code uses the count variable to prevent comparison between
 * two css structures that have already been compared.
 */
static int sc_css_reduce(splaytree_t *tree, int trim, int min_z)
{
  sc_css_t *css, *css2, *cssa = NULL;
  slist_node_t *sn;
  slist_t *list = NULL;
  int i, rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;

  /*
   * work through the longest common substrings until we converge on
   * candidate longest common substrings
   */
  do
    {
      splaytree_inorder(tree, tree_to_slist, list);
      slist_qsort(list, (slist_cmp_t)sc_css_count_min_cmp);
      i = 0;
      while((css = slist_head_pop(list)) != NULL)
	{
	  if(css->count != 0)
	    {
	      slist_empty(list);
	      break;
	    }
	  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
	    {
	      /* determine if there are any common substrings within */
	      css2 = slist_node_item(sn);
	      if(sc_css_reduce_pair(css, css2, trim, min_z, &cssa) != 0)
		goto done;
	      if(cssa == NULL)
		continue;

	      /* if we already have this css in the tree, move on */
	      if(sc_css_find(tree, cssa) != NULL)
		{
		  sc_css_free(cssa); cssa = NULL;
		  continue;
		}

	      /* put the css in the tree */
	      if(sc_css_insert(tree, cssa) != 0)
		goto done;
	      cssa = NULL;
	      i++;
	    }
	  css->count = 1;
	}
    }
  while(i != 0);
  rc = 0;

  /* reset the count variables to zero */
  splaytree_inorder(tree, tree_to_slist, list);
  while((css = slist_head_pop(list)) != NULL)
    css->count = 0;

 done:
  if(cssa != NULL) sc_css_free(cssa);
  if(list != NULL) slist_free(list);
  return rc;
}

/*
 * label_get:
 *
 * return a pointer to the start of a label in a domain name.  x is
 * numbered from zero, starting at the right of the string -- i.e.,
 * the TLD is zero.
 */
static const char *label_get(const char *string, int x)
{
  const char *ptr;
  int off = 0;

  if(string[0] == '\0')
    return NULL;

  ptr = string;
  while(*ptr != '\0')
    ptr++;
  ptr--;

  while(ptr != string)
    {
      if(*ptr == '.')
	{
	  if(off == x)
	    return ptr + 1;
	  off++;
	}
      ptr--;
    }

  if(off == x)
    return string;

  return NULL;
}

static int capcount(const char *str)
{
  int rc = -1;
#ifdef HAVE_PCRE2
  pcre2_code *pcre;
  uint32_t n;
  PCRE2_SIZE erroffset;
  int errnumber;
  if((pcre = pcre2_compile((PCRE2_SPTR)str, PCRE2_ZERO_TERMINATED, 0,
			   &errnumber, &erroffset, NULL)) == NULL ||
     pcre2_pattern_info(pcre, PCRE2_INFO_CAPTURECOUNT, &n) != 0)
    goto done;
  rc = n;
 done:
  if(pcre != NULL) pcre2_code_free(pcre);
#else
  const char *error;
  int erroffset, n;
  pcre *re;
  if((re = pcre_compile(str, 0, &error, &erroffset, NULL)) == NULL ||
     pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &n) != 0)
    goto done;
  rc = n;
 done:
  if(re != NULL) pcre_free(re);
#endif
  return rc;
}

static int sc_rework_matchk(sc_rework_t *rew, size_t k, const char *str)
{
  int rc;

  assert(k < rew->c);

#ifdef HAVE_PCRE2
  rc = pcre2_match(rew->pcre[k], (PCRE2_SPTR)str, strlen(str), 0, 0,
		   rew->match_data, NULL);
  if(rc <= 0)
    {
      if(rc == PCRE2_ERROR_NOMATCH)
	return 0;
      return -1;
    }
  rew->ovector = pcre2_get_ovector_pointer(rew->match_data);
#else
  rc = pcre_exec(rew->pcre[k], rew->study[k], str, strlen(str), 0, 0,
		 rew->ovector, rew->n);
  if(rc <= 0)
    {
      if(rc == PCRE_ERROR_NOMATCH)
	return 0;
      return -1;
    }
#endif

  rew->m = (size_t)rc;
  rew->k = k;

  return 1;
}

/*
 * sc_rework_match:
 *
 * apply the regex to the string.
 *  returns -1 on error
 *  returns  0 if the regex didn't match
 *  returns  1 if the regex matches, with whatever was captured in the css.
 */
static int sc_rework_match(sc_rework_t *rew, sc_iface_t *iface, sc_css_t **out)
{
  sc_css_t *css = NULL;
  size_t off, k;
  int i, l, rc;

  if(out != NULL)
    *out = NULL;

  assert(rew->c > 0);
  for(k=0; k<rew->c; k++)
    {
#ifdef HAVE_PCRE2
      rc = pcre2_match(rew->pcre[k], (PCRE2_SPTR)iface->name, iface->len,
		       0, 0, rew->match_data, NULL);
#else
      rc = pcre_exec(rew->pcre[k], rew->study[k], iface->name, iface->len,
		     0, 0, rew->ovector, rew->n);
#endif
      assert(rc != 0);
      if(rc <= 0)
	{
#ifdef HAVE_PCRE2
	  if(rc == PCRE2_ERROR_NOMATCH)
	    continue;
#else
	  if(rc == PCRE_ERROR_NOMATCH)
	    continue;
#endif
	  return -1;
	}
      else break;
    }
  if(k == rew->c)
    return 0;

  rew->m = (size_t)rc;
  rew->k = k;

#ifdef HAVE_PCRE2
  rew->ovector = pcre2_get_ovector_pointer(rew->match_data);
#endif

  if(out == NULL)
    return 1;

  /* calc the size of the matched portion */
  off = 0;
  for(i=1; i<rc; i++)
    {
      off += rew->ovector[(2*i)+1] - rew->ovector[2*i];
      off++;
    }
  if(off == 0)
    return 1;

  /* allocate a css for the matched portion */
  if((css = sc_css_alloc(off)) == NULL)
    goto err;

  /* fill the css */
  off = 0;
  for(i=1; i<rc; i++)
    {
      l = rew->ovector[(2*i)+1] - rew->ovector[2*i];
      memcpy(css->css+off, iface->name + rew->ovector[2*i], l);
      off += l;
      css->css[off++] = '\0';
      css->cssc++;
    }
  css->len = off;
  *out = css;

  return 1;

 err:
  if(css != NULL) sc_css_free(css);
  return -1;
}

static void sc_rework_free(sc_rework_t *rew)
{
  size_t i;

  if(rew->pcre != NULL)
    {
      for(i=0; i<rew->c; i++)
	if(rew->pcre[i] != NULL)
#ifdef HAVE_PCRE2
	  pcre2_code_free(rew->pcre[i]);
#else
	  pcre_free(rew->pcre[i]);
#endif
      free(rew->pcre);
    }

#ifdef HAVE_PCRE2
  if(rew->match_data != NULL)
    pcre2_match_data_free(rew->match_data);
#else
  if(rew->study != NULL)
    {
      for(i=0; i<rew->c; i++)
	if(rew->study[i] != NULL)
	  pcre_free_study(rew->study[i]);
      free(rew->study);
    }
  if(rew->ovector != NULL)
    free(rew->ovector);
#endif

  free(rew);

  return;
}

static int sc_rework_capcount(const sc_rework_t *rew, int i)
{
  int n;
#ifdef HAVE_PCRE2
  uint32_t x;
  if(pcre2_pattern_info(rew->pcre[i], PCRE2_INFO_CAPTURECOUNT, &x) != 0)
    return -1;
  n = x;
#else
  if(pcre_fullinfo(rew->pcre[i],rew->study[i],PCRE_INFO_CAPTURECOUNT,&n)!=0)
    return -1;
#endif
  return n;
}

static sc_rework_t *sc_rework_alloc(sc_regex_t *re)
{
  sc_rework_t *rew;
  const char *str;
  int i, k, n;

#ifdef HAVE_PCRE2
  PCRE2_SIZE erroffset;
  int errnumber;
#else
  int erroffset, options = 0;
  const char *error;
#endif

  if((rew = malloc_zero(sizeof(sc_rework_t))) == NULL)
    goto err;
  rew->c = re->regexc;

#ifdef HAVE_PCRE2
  if((rew->pcre = malloc_zero(sizeof(pcre2_code *) * rew->c)) == NULL)
    goto err;
#else
  if((rew->pcre = malloc_zero(sizeof(pcre *) * rew->c)) == NULL ||
     (rew->study = malloc_zero(sizeof(struct pcre_extra *) * rew->c)) == NULL)
    goto err;
#endif

  k = 0;
  for(i=0; i<re->regexc; i++)
    {
      str = re->regexes[i]->str;

#ifdef HAVE_PCRE2
      if((rew->pcre[i] = pcre2_compile((PCRE2_SPTR)str, PCRE2_ZERO_TERMINATED,
				       0,&errnumber,&erroffset,NULL)) == NULL)
	goto err;
      if(do_jit != 0)
	pcre2_jit_compile(rew->pcre[i], PCRE2_JIT_COMPLETE);
#else
      if((rew->pcre[i] = pcre_compile(str,0,&error,&erroffset,NULL)) == NULL)
	goto err;
#ifdef PCRE_STUDY_JIT_COMPILE
      if(do_jit != 0)
	options |= PCRE_STUDY_JIT_COMPILE;
#endif
      rew->study[i] = pcre_study(rew->pcre[i], options, &error);
#endif

      /* figure out how large the ovector has to be for this regex */
      if((n = sc_rework_capcount(rew, i)) < 0)
	goto err;
      if(n <= k)
	continue;
      k = n;
    }

#ifdef HAVE_PCRE2
  if((rew->match_data = pcre2_match_data_create(k + 1, NULL)) == NULL)
    goto err;
#else
  n = ((k + 1) * 3);
  if((rew->ovector = malloc_zero(sizeof(int) * n)) == NULL)
    goto err;
  rew->n = n;
#endif

  return rew;

 err:
  if(rew != NULL) sc_rework_free(rew);
  return NULL;
}

static void sc_suffix_free(sc_suffix_t *suffix)
{
  size_t i;
  if(suffix->label != NULL)
    free(suffix->label);
  if(suffix->suffixes != NULL)
    {
      for(i=0; i<suffix->suffixc; i++)
	sc_suffix_free(suffix->suffixes[i]);
      free(suffix->suffixes);
    }
  free(suffix);
  return;
}

static int sc_suffix_label_cmp(const sc_suffix_t *a, const sc_suffix_t *b)
{
  return strcmp(a->label, b->label);
}

static int suffix_file_line(char *line, void *param)
{
  slist_t *list = param;
  static int end_icann = 0;
  char *ptr;

  if(line[0] == '\0')
    return 0;

  if(end_icann != 0)
    return 0;

  if(line[0] == '/')
    {
      if(strncmp(line, "// ===END", 9) == 0)
	end_icann = 1;
      return 0;
    }
  if(line[0] == '!')
    return 0;

  if(line[0] == '*' && line[1] == '.')
    line = line + 2;

  for(ptr=line; *ptr != '\0'; ptr++)
    {
      if(*ptr == '.' || *ptr == '-' ||
	 (*ptr >= '0' && *ptr <= '9') ||
	 (*ptr >= 'a' && *ptr <= 'z'))
	continue;
      break;
    }
  if(*ptr != '\0')
    {
      // fprintf(stderr, "skipping %s\n", line);
      return 0;
    }

  if((ptr = strdup(line)) == NULL ||
     slist_tail_push(list, ptr) == NULL)
    return -1;

  return 0;
}

static sc_suffix_t *sc_suffix_get(const char *suffix)
{
  const char *ptr, *end = NULL;
  sc_suffix_t *ss = suffix_root;
  sc_suffix_t fm, *s = NULL;
  char buf[256];
  int i, c, dc;

  dc = dotcount(suffix);
  for(i=0; i<=dc; i++)
    {
      ptr = label_get(suffix, i);
      if(end == NULL)
	{
	  snprintf(buf, sizeof(buf), "%s", ptr);
	}
      else
	{
	  c = end - ptr - 1;
	  memcpy(buf, ptr, c);
	  buf[c] = '\0';
	}
      end = ptr;
      fm.label = buf;

      /* If the suffix fm is not in the suffix tree insert it. */
      if((s = array_find((void **)ss->suffixes, ss->suffixc, &fm,
			 (array_cmp_t)sc_suffix_label_cmp)) == NULL)
	{
	  if((s = malloc_zero(sizeof(sc_suffix_t))) == NULL ||
	     (s->label = strdup(buf)) == NULL)
	    {
	      if(s != NULL) free(s);
	      return NULL;
	    }
	  s->parent = ss;
	  array_insert((void ***)&ss->suffixes, &ss->suffixc, s,
		       (array_cmp_t)sc_suffix_label_cmp);
	}

      ss = s;
    }

  /* domains can be registered with this suffix */
  if(s != NULL)
    s->end = 1;

  return s;
}

static const char *sc_suffix_find(const char *domain)
{
  const char *ptr, *m = NULL, *end = NULL;
  sc_suffix_t *ss = suffix_root, *s = NULL, fm;
  char buf[256];
  int i, c, dc;

  if(domain == NULL)
    return NULL;

  dc = dotcount(domain);
  for(i=0; i<=dc; i++)
    {
      ptr = label_get(domain, i);
      if(end == NULL)
	{
	  snprintf(buf, sizeof(buf), "%s", ptr);
	}
      else
	{
	  c = end - ptr - 1;
	  memcpy(buf, ptr, c);
	  buf[c] = '\0';
	}
      end = ptr;
      fm.label = buf;

      if((s = array_find((void **)ss->suffixes, ss->suffixc, &fm,
			 (array_cmp_t)sc_suffix_label_cmp)) == NULL)
	break;

      if(s->end == -1)
	return NULL;

      if(s->end == 1)
	m = ptr;

      ss = s;
    }

  if(m == NULL || m-2 <= domain)
    return NULL;
  m = m - 2;
  while(m >= domain)
    {
      if(*m == '.')
	return m + 1;
      m--;
    }

  return NULL;
}

static int sc_iface_geomap(const sc_iface_t *iface, sc_geomap_t *map)
{
  sc_ptrc_t x[2];
  sc_geotagn_t *gt;
  size_t xi = 0, i;
  int s;

  for(i=0; i<iface->geos[0].tagc; i++)
    {
      if(iface->geos[0].tags[i].type == GEOHINT_TYPE_CC)
	{
	  memcpy(map->cc, iface->name + iface->geos[0].tags[i].start, 2);
	  map->cc[2] = '\0';
	}
      else if(iface->geos[0].tags[i].type == GEOHINT_TYPE_ST)
	{
	  s = iface->geos[0].tags[i].end + 1 - iface->geos[0].tags[i].start;
	  memcpy(map->st, iface->name + iface->geos[0].tags[i].start, s);
	  map->st[s] = '\0';
	}
      else
	{
	  if(xi >= sizeof(x) / sizeof(sc_ptrc_t))
	    return -1;
	  gt = &iface->geos[0].tags[i];
	  x[xi].ptr = iface->name + gt->start;
	  x[xi].c = gt->end + 1 - gt->start;
	  xi++;
	  map->type = iface->geos[0].hint->type;
	}
    }

  return sc_geomap_code(map, x, xi);
}

static int sc_iface_cmp(const sc_iface_t *a, const sc_iface_t *b)
{
  int i;
  if(a->name != NULL && b->name != NULL)
    {
      if((i = strcmp(a->name, b->name)) != 0)
	return i;
    }
  else
    {
      if(a->name == NULL) return 1;
      if(b->name == NULL) return -1;
    }
  return scamper_addr_human_cmp(a->addr, b->addr);
}

static int sc_iface_suffix_cmp(const sc_iface_t *a, const sc_iface_t *b)
{
  const char *as = sc_suffix_find(a->name);
  const char *bs = sc_suffix_find(b->name);
  int i;
  if(as != NULL || bs != NULL)
    {
      if(as == NULL) return 1;
      if(bs == NULL) return -1;
      if((i = strcmp(as, bs)) != 0)
	return i;
    }
  return sc_iface_cmp(a, b);
}

static int sc_segscore_cmp(const sc_segscore_t *a, const sc_segscore_t *b)
{
  return strcmp(a->seg, b->seg);
}

static void sc_segscore_free(sc_segscore_t *ss)
{
  if(ss->tree != NULL) splaytree_free(ss->tree, free);
  if(ss->seg != NULL) free(ss->seg);
  free(ss);
  return;
}

static sc_segscore_t *sc_segscore_alloc(const char *seg, int score)
{
  sc_segscore_t *ss = NULL;
  if((ss = malloc_zero(sizeof(sc_segscore_t))) == NULL ||
     (ss->seg = strdup(seg)) == NULL)
    {
      if(ss != NULL) sc_segscore_free(ss);
      return NULL;
    }
  ss->score = score;
  return ss;
}

static sc_segscore_t *sc_segscore_get(splaytree_t *tree, char *seg, int score)
{
  sc_segscore_t fm, *ss;
  fm.seg = seg;
  fm.score = score;
  if((ss = splaytree_find(tree, &fm)) != NULL)
    return ss;
  if((ss = sc_segscore_alloc(seg, score)) == NULL ||
     splaytree_insert(tree, ss) == NULL)
    {
      if(ss != NULL) sc_segscore_free(ss);
      return NULL;
    }
  return ss;
}

static int sc_segscore_switch2(sc_segscore_t *ss, char *alpha)
{
  char buf[256], *dup;
  size_t i = 0;

  /* keep track of literals in [a-z]\d+ / \d+[a-z] */
  if(ss->tree == NULL &&
     (ss->tree = splaytree_alloc((splaytree_cmp_t)strcmp)) == NULL)
    return -1;

  while(isalpha((unsigned int)alpha[i]) != 0)
    {
      if(i+1 >= sizeof(buf))
	return 0;
      buf[i] = alpha[i];
      i++;
    }
  buf[i] = '\0';
  if(splaytree_find(ss->tree, buf) != NULL)
    return 0;
  if((dup = strdup(buf)) == NULL || splaytree_insert(ss->tree, dup) == NULL)
    {
      if(dup != NULL) free(dup);
      return -1;
    }

  return 0;
}

static int sc_regexn_plan_cmp(const sc_regexn_t *a, const sc_regexn_t *b)
{
  int i;
  if(a->plan == b->plan) return 0;
  if(a->plan != NULL && b->plan == NULL) return -1;
  if(a->plan == NULL && b->plan != NULL) return  1;
  if(a->capc < b->capc) return -1;
  if(a->capc > b->capc) return  1;
  for(i=0; i<a->capc; i++)
    {
      if(a->plan[i] < b->plan[i])
	return -1;
      if(a->plan[i] > b->plan[i])
	return 1;
    }
  return 0;
}

static void sc_regexn_clean_digits(sc_regexn_t *ren)
{
  char *ptr;
  size_t len;
  if((ptr = strstr(ren->str, "\\d+\\d+")) != NULL)
    {
      len = strlen(ren->str);
      memmove(ptr+3, ptr+6, len + 1 - ((ptr + 6) - ren->str));
    }
  return;
}

static uint8_t sc_regexn_geotype(const sc_regexn_t *ren)
{
  int i;
  for(i=0; i<ren->capc; i++)
    assert(ren->plan[i] != 0);
  for(i=0; i<ren->capc; i++)
    if(ren->plan[i] == GEOHINT_TYPE_IATA ||
       ren->plan[i] == GEOHINT_TYPE_ICAO ||
       ren->plan[i] == GEOHINT_TYPE_CLLI ||
       ren->plan[i] == GEOHINT_TYPE_PLACE ||
       ren->plan[i] == GEOHINT_TYPE_LOCODE ||
       ren->plan[i] == GEOHINT_TYPE_FACILITY)
      return ren->plan[i];
  return 0;
}

static void sc_regexn_free(sc_regexn_t *ren)
{
  if(ren->str != NULL) free(ren->str);
  if(ren->plan != NULL) free(ren->plan);
  free(ren);
  return;
}

static sc_regexn_t *sc_regexn_dup(sc_regexn_t *in)
{
  sc_regexn_t *out = NULL;
  if((out = malloc_zero(sizeof(sc_regexn_t))) == NULL ||
     (out->str = strdup(in->str)) == NULL)
    goto err;
  out->capc = in->capc;

  if(in->plan != NULL && in->capc > 0)
    {
      out->plan = memdup(in->plan, sizeof(uint8_t) * in->capc);
      if(out->plan == NULL)
	goto err;
    }

  return out;

 err:
  if(out != NULL) sc_regexn_free(out);
  return NULL;
}

static sc_regexn_t *sc_regexn_alloc(char *str)
{
  sc_regexn_t *ren = NULL;
  if((ren = malloc_zero(sizeof(sc_regexn_t))) == NULL ||
     (ren->str = strdup(str)) == NULL)
    {
      if(ren != NULL) sc_regexn_free(ren);
      return NULL;
    }
  return ren;
}

/*
 * sc_regex_findnew
 *
 * Return the index of the first regex in the candidate set which is not
 * in the current set.
 * The number of regexes in the candidate set must be exactly one more than
 * the current set.
 */
static int sc_regex_findnew(const sc_regex_t *cur, const sc_regex_t *can)
{
  int i;

  assert(cur->regexc < can->regexc);
  assert(cur->regexc + 1 == can->regexc);

  for(i=0; i<cur->regexc; i++)
    if(strcmp(cur->regexes[i]->str, can->regexes[i]->str) != 0)
      return i;

  return can->regexc-1;
}

/*
 * sc_regex_score_fp
 *
 * count how many things we infer as "false positives"
 */
static uint32_t sc_regex_score_fp(const sc_regex_t *re)
{
  assert(do_learnalias != 0 || do_learnasn != 0 || do_learnasnames != 0 ||
	 do_learngeo != 0);
  return re->fp_c + re->ip_c;
}

/*
 * sc_regex_score_f
 *
 * count how many things we infer as "false".  we include fnu_c to
 * penalise NCs that do not extract something we believe they should.
 * see also sc_regex_score_fp above.
 */
static uint32_t sc_regex_score_f(const sc_regex_t *re)
{
  assert(do_learnalias != 0 || do_learnasn != 0 || do_learnasnames != 0 ||
	 do_learngeo != 0);
  if(do_learnasnames != 0)
    return re->fp_c + re->ip_c;
  else if(do_learngeo != 0)
    return re->fp_c + re->fnu_c + re->unk_c + re->ip_c;
  return re->fp_c + re->fnu_c + re->ip_c;
}

static int sc_regex_score_atp(const sc_regex_t *re)
{
  return (int)re->tp_c - sc_regex_score_f(re);
}

static float sc_regex_score_tpr(const sc_regex_t *re)
{
  return (float)re->tp_c / (sc_regex_score_fp(re) + 1);
}

static void sc_regex_score_reset(sc_regex_t *re)
{
  int i;
  for(i=0; i<re->regexc; i++)
    {
      re->regexes[i]->matchc = 0;
      re->regexes[i]->tp_c = 0;
      re->regexes[i]->rt_c = 0;
    }
  if(re->tp_mask != NULL)
    {
      free(re->tp_mask);
      re->tp_mask = NULL;
    }
  re->matchc = 0;
  re->namelen = 0;
  re->tp_c = 0;
  re->fp_c = 0;
  re->fne_c = 0;
  re->fnu_c = 0;
  re->unk_c = 0;
  re->ip_c = 0;
  re->sp_c = 0;
  re->sn_c = 0;
  re->rt_c = 0;
  return;
}

static char *sc_regex_tostr(const sc_regex_t *re, char *buf, size_t len)
{
  size_t off = 0;
  int i;
  string_concat(buf, len, &off, "%s", re->regexes[0]->str);
  for(i=1; i<re->regexc; i++)
    string_concat(buf, len, &off, " %s", re->regexes[i]->str);
  return buf;
}

static char *sc_regex_plan_tostr(const sc_regex_t *re, char *buf, size_t len)
{
  sc_regexn_t *ren;
  size_t off = 0;
  int i, j;

  string_concat(buf, len, &off, "[");
  for(i=0; i<re->regexc; i++)
    {
      ren = re->regexes[i];
      string_concat(buf, len, &off, "%s[", (i > 0) ? ", " : "");
      for(j=0; j<ren->capc; j++)
	string_concat(buf, len, &off, "%s%s", (j > 0) ? ", " : "",
		      geotype_tostr(ren->plan[j]));
      string_concat(buf, len, &off, "]");
    }

  string_concat(buf, len, &off, "]");
  return buf;
}

static char *sc_regex_plan_tojson(const sc_regex_t *re, char *buf, size_t len)
{
  sc_regexn_t *ren;
  size_t off = 0;
  int i, j;

  string_concat(buf, len, &off, "[");
  for(i=0; i<re->regexc; i++)
    {
      ren = re->regexes[i];
      string_concat(buf, len, &off, "%s[", (i > 0) ? ", " : "");
      for(j=0; j<ren->capc; j++)
	string_concat(buf, len, &off, "%s\"%s\"", (j > 0) ? ", " : "",
		      geotype_tostr(ren->plan[j]));
      string_concat(buf, len, &off, "]");
    }

  string_concat(buf, len, &off, "]");
  return buf;
}

static char *sc_regex_score_tostr(const sc_regex_t *re, char *buf, size_t len)
{
  static const char *class[] = {"poor", "good", "promising", "single"};
  uint32_t tp, fp;
  size_t off = 0;

  if(re->matchc == 0)
    {
      string_concat(buf, len, &off, "no matches");
      return buf;
    }

  tp = re->tp_c;
  fp = sc_regex_score_fp(re);

  string_concat(buf, len, &off, "ppv %.3f,", ((float)tp) / (tp+fp));
  if(do_learnalias != 0)
    string_concat(buf, len, &off, " rt %u", re->rt_c);
  else if(do_learnasn != 0 || do_learnasnames != 0)
    string_concat(buf, len, &off, " asn %u", re->rt_c);
  else if(do_learngeo != 0)
    string_concat(buf, len, &off, " geo %u", re->rt_c);
  string_concat(buf, len, &off, " tp %u fp %u", re->tp_c, re->fp_c);

  if(re->fne_c > 0)
    string_concat(buf, len, &off, " fne %u", re->fne_c);
  if(re->fnu_c > 0)
    string_concat(buf, len, &off, " fnu %u", re->fnu_c);
  if(re->unk_c > 0)
    string_concat(buf, len, &off, " unk %u", re->unk_c);
  if(re->sp_c > 0)
    string_concat(buf, len, &off, " sp %u", re->sp_c);
  if(re->sn_c > 0)
    string_concat(buf, len, &off, " sn %u", re->sn_c);
  if(re->ip_c > 0)
    string_concat(buf, len, &off, " ip %u", re->ip_c);

  string_concat(buf, len, &off, " tpr %.1f atp %d",
		sc_regex_score_tpr(re), sc_regex_score_atp(re));

  assert(re->class >= 0 && re->class <= 3);
  string_concat(buf, len, &off, " class %s", class[re->class]);

  string_concat(buf, len, &off, ", score %u matches %u", re->score, re->matchc);

  return buf;
}

static char *sc_regex_score_tojson(const sc_regex_t *re, char *buf, size_t len)
{
  static const char *class[] = {"poor", "good", "promising", "single"};
  size_t off = 0;
  uint32_t fp;

  fp = sc_regex_score_fp(re);
  if(fp == 0 && re->tp_c == 0)
    string_concat(buf, len, &off, "\"ppv\":\"none\", ");
  else
    string_concat(buf, len, &off, "\"ppv\":\"%.3f\",",
		  ((float)re->tp_c) / (re->tp_c + fp));

  if(do_learnalias != 0)
    string_concat(buf, len, &off, "\"rt\":%u, ", re->rt_c);
  else if(do_learnasn != 0 || do_learnasnames != 0)
    string_concat(buf, len, &off, "\"asn\": %u, ", re->rt_c);
  else if(do_learngeo != 0)
    string_concat(buf, len, &off, "\"geo\": %u, ", re->rt_c);

  string_concat(buf, len, &off, "\"tp\":%d, \"fp\":%d, \"ip\":%d, \"fnu\":%d",
		re->tp_c, re->fp_c, re->ip_c, re->fnu_c);

  if(do_learnalias != 0)
    string_concat(buf, len, &off, ", \"fne\":%d, \"sp\":%d, \"sn\":%d",
		  re->fne_c, re->sp_c, re->sn_c);

  if(do_learngeo != 0 || do_learnasnames != 0)
    string_concat(buf, len, &off, ", \"unk\":%d", re->unk_c);

  string_concat(buf, len, &off, ", \"tpr\":\"%.1f\", \"atp\":%d",
		sc_regex_score_tpr(re), sc_regex_score_atp(re));

  assert(re->class >= 0 && re->class <= 3);
  string_concat(buf, len, &off, ", \"class\":\"%s\"", class[re->class]);

  string_concat(buf, len, &off,
		", \"score\":%u, \"matches\":%u, \"routers\":%u",
		re->score, re->matchc, slist_count(re->dom->routers));

  return buf;
}

/*
 * sc_regex_str_cmp
 *
 * provide sorting to check if a regex already exists in the tree
 */
static int sc_regex_str_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int i, x;
  if(a->regexc < b->regexc) return -1;
  if(a->regexc > b->regexc) return  1;
  for(i=0; i<a->regexc; i++)
    if((x = strcmp(a->regexes[i]->str, b->regexes[i]->str)) != 0)
      return x;
  for(i=0; i<a->regexc; i++)
    {
      if(a->regexes[i]->plan != NULL && b->regexes[i]->plan == NULL)
	return -1;
      if(a->regexes[i]->plan == NULL && b->regexes[i]->plan != NULL)
	return 1;
      if(a->regexes[i]->plan == NULL && b->regexes[i]->plan == NULL)
	continue;
      if(a->regexes[i]->capc < b->regexes[i]->capc)
	return -1;
      if(a->regexes[i]->capc > b->regexes[i]->capc)
	return 1;
      for(x=0; x<a->regexes[i]->capc; x++)
	{
	  if(a->regexes[i]->plan[x] < b->regexes[i]->plan[x])
	    return -1;
	  if(a->regexes[i]->plan[x] > b->regexes[i]->plan[x])
	    return 1;
	}
    }
  return 0;
}

static int sc_regex_str_len(const sc_regex_t *re)
{
  size_t len = 0;
  int i;
  for(i=0; i<re->regexc; i++)
    len += strlen(re->regexes[i]->str);
  return len;
}

static int sc_regex_score_tie_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  size_t al, bl;
  int ac, bc, i, x;
  uint8_t agt, bgt;

  /* pick the regex that gets the same work done with less regexes */
  if(a->regexc < b->regexc) return -1;
  if(a->regexc > b->regexc) return  1;

  if(do_learngeo != 0)
    {
      /* for geo conventions, prefer IATA over LOCODE */
      for(i=0; i<a->regexc; i++)
	{
	  agt = sc_regexn_geotype(a->regexes[i]);
	  bgt = sc_regexn_geotype(b->regexes[i]);
	  if(agt < bgt) return -1;
	  if(agt > bgt) return  1;
	}
    }
  else if(do_learnalias != 0)
    {
      /*
       * for alias conventions, pick the convention that uses the
       * least capture elements
       */
      ac = 0;
      for(i=0; i<a->regexc; i++)
	ac += a->regexes[i]->capc;
      bc = 0;
      for(i=0; i<b->regexc; i++)
	bc += b->regexes[i]->capc;
      if(ac < bc) return -1;
      if(ac > bc) return  1;
    }

  /* pick the regex with the highest specificity score */
  if(a->score > b->score) return -1;
  if(a->score < b->score) return  1;

  /*
   * pick longer extraction names
   *
   * this breaks a tie between ([^-]+)\..+\.comcast\.net$ and
   * ([^-]+)\.comcast\.net$
   */
  if(a->namelen > b->namelen) return -1;
  if(a->namelen < b->namelen) return  1;

  /* pick longer regexes */
  al = sc_regex_str_len(a);
  bl = sc_regex_str_len(b);
  if(al > bl) return -1;
  if(al < bl) return  1;

  /* break ties with alphabetical sort */
  for(i=0; i<a->regexc; i++)
    if((x = strcmp(a->regexes[i]->str, b->regexes[i]->str)) != 0)
      return x;

  return 0;
}

/*
 * sc_regex_score_thin_cmp
 *
 * this function is used to cluster regexes that might be equivalent
 */
static int sc_regex_score_thin_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  if(a->tp_c  > b->tp_c)  return -1;
  if(a->tp_c  < b->tp_c)  return  1;
  if(a->fp_c  < b->fp_c)  return -1;
  if(a->fp_c  > b->fp_c)  return  1;
  if(a->ip_c  < b->ip_c)  return -1;
  if(a->ip_c  > b->ip_c)  return  1;
  if(a->fne_c < b->fne_c) return -1;
  if(a->fne_c > b->fne_c) return  1;
  if(a->fnu_c < b->fnu_c) return -1;
  if(a->fnu_c > b->fnu_c) return  1;
  if(a->sp_c  < b->sp_c)  return -1;
  if(a->sp_c  > b->sp_c)  return  1;
  if(a->sn_c  < b->sn_c)  return -1;
  if(a->sn_c  > b->sn_c)  return  1;
  return 0;
}

static int sc_regex_score_thin_sort_cmp(const sc_regex_t *a,const sc_regex_t *b)
{
  int x;
  if((x = sc_regex_score_thin_cmp(a, b)) != 0)
    return x;
  return sc_regex_score_tie_cmp(a, b);
}

static int sc_regex_score_atp_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int a_atp, b_atp;
  a_atp = sc_regex_score_atp(a);
  b_atp = sc_regex_score_atp(b);
  if(a_atp > b_atp)
    return -1;
  if(a_atp < b_atp)
    return 1;
  return 0;
}

static int sc_regex_score_rank_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int x;
  if((x = sc_regex_score_atp_cmp(a, b)) != 0)
    return x;
  if(a->fp_c < b->fp_c) return -1;
  if(a->fp_c > b->fp_c) return  1;
  if(a->tp_c > b->tp_c) return -1;
  if(a->tp_c < b->tp_c) return  1;
  return sc_regex_score_tie_cmp(a, b);
}

static int sc_regex_score_rank_asn_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int x;
  if((x = sc_regex_score_atp_cmp(a, b)) != 0)
    return x;
  if(a->tp_c > b->tp_c) return -1;
  if(a->tp_c < b->tp_c) return  1;
  if(a->fp_c < b->fp_c) return -1;
  if(a->fp_c > b->fp_c) return  1;
  return sc_regex_score_tie_cmp(a, b);
}

static int sc_regex_score_rank_asnames_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  if(a->rt_c > b->rt_c) return -1;
  if(a->rt_c < b->rt_c) return  1;
  return sc_regex_score_rank_asn_cmp(a, b);
}

/*
 * sc_regex_score_fp_cmp:
 *
 * this score function is used in the false positive refinement step.
 * sort the regexes by max(tp-fp), followed by single interfaces that
 * were matched.
 */
static int sc_regex_score_fp_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int ac = a->tp_c - a->fp_c;
  int bc = b->tp_c - b->fp_c;
  if(ac > bc) return -1;
  if(ac < bc) return 1;
  if(a->sp_c > b->sp_c) return -1;
  if(a->sp_c < b->sp_c) return  1;
  return sc_regex_score_tie_cmp(a, b);
}

/*
 * sc_reegx_score_ip_cmp:
 *
 * this score function is used to evaluate regexes that filter IP matches.
 * sort the regexes by max(tp-fp)
 */
static int sc_regex_score_ip_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int ac = a->tp_c - a->fp_c;
  int bc = b->tp_c - b->fp_c;
  if(a->fp_c < b->fp_c) return -1;
  if(a->fp_c > b->fp_c) return  1;
  if(ac > bc) return -1;
  if(ac < bc) return 1;
  return sc_regex_score_tie_cmp(a, b);
}

static int sc_regex_css_score_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  if(a->rt_c > b->rt_c) return -1;
  if(a->rt_c < b->rt_c) return  1;
  if(a->fp_c < b->fp_c) return -1;
  if(a->fp_c > b->fp_c) return  1;
  if(a->tp_c > b->tp_c) return -1;
  if(a->tp_c < b->tp_c) return  1;
  return sc_regex_score_tie_cmp(a, b);
}

static int sc_regex_css_regex_score_cmp(const sc_regex_css_t *a,
					const sc_regex_css_t *b)
{
  return sc_regex_css_score_cmp(a->regex, b->regex);
}

static int sc_regex_css_work_score_cmp(const sc_regex_css_t *a,
				       const sc_regex_css_t *b)
{
  return sc_regex_css_score_cmp(a->work, b->work);
}

static void sc_regex_free(sc_regex_t *re)
{
  size_t s;
  int i;
  if(re->regexes != NULL)
    {
      for(i=0; i<re->regexc; i++)
	if(re->regexes[i] != NULL)
	  sc_regexn_free(re->regexes[i]);
      free(re->regexes);
    }
  if(re->geohints != NULL)
    {
      for(s=0; s<re->geohintc; s++)
	if(re->geohints[s] != NULL)
	  sc_geohint_free(re->geohints[s]);
      free(re->geohints);
    }
  if(re->tp_mask != NULL) free(re->tp_mask);
  free(re);
  return;
}

static sc_regex_t *sc_regex_plus1(sc_regex_t *re, sc_regexn_t *ren, int i)
{
  sc_regex_t *out = NULL;
  int j, regexc = re->regexc + 1;

  assert(i >= 0);
  assert(i < regexc);

  if((out = malloc_zero(sizeof(sc_regex_t))) == NULL ||
     (out->regexes = malloc_zero(sizeof(sc_regexn_t *) * regexc)) == NULL)
    goto err;
  out->regexc = regexc;
  out->dom = re->dom;

  for(j=0; j<i; j++)
    if((out->regexes[j] = sc_regexn_dup(re->regexes[j])) == NULL)
      goto err;
  if((out->regexes[i] = sc_regexn_dup(ren)) == NULL)
    goto err;
  for(j=i; j<re->regexc; j++)
    if((out->regexes[j+1] = sc_regexn_dup(re->regexes[j])) == NULL)
      goto err;

  return out;

 err:
  if(out != NULL) sc_regex_free(out);
  return NULL;
}

static sc_regex_t *sc_regex_head_push(sc_regex_t *re, sc_regexn_t *ren)
{
  return sc_regex_plus1(re, ren, 0);
}

static sc_regex_t *sc_regex_tail_push(sc_regex_t *re, sc_regexn_t *ren)
{
  return sc_regex_plus1(re, ren, re->regexc);
}

static sc_regex_t *sc_regex_alloc_list(slist_t *list)
{
  sc_regex_t *re = NULL;
  slist_node_t *sn;
  char *ptr;
  int capc, k = 0;

  if((re = malloc_zero(sizeof(sc_regex_t))) == NULL)
    goto err;
  re->regexc = slist_count(list);
  if((re->regexes = malloc_zero(sizeof(sc_regexn_t *) * re->regexc)) == NULL)
    goto err;
  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      ptr = slist_node_item(sn);
      if((re->regexes[k] = sc_regexn_alloc(ptr)) == NULL)
	goto err;
      if((capc = capcount(ptr)) < 0)
	goto err;
      re->regexes[k]->capc = capc;
      k++;
    }
  return re;

 err:
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

static sc_regex_t *sc_regex_alloc_str(char *str)
{
  sc_regex_t *re = NULL;
  slist_t *list = NULL;
  char *ptr = str, *next;

  if((list = slist_alloc()) == NULL)
    goto err;

  do
    {
      string_nullterm_char(ptr, ' ', &next);
      if(slist_tail_push(list, ptr) == NULL)
	goto err;
      ptr = next;
    }
  while(ptr != NULL);

  if((re = sc_regex_alloc_list(list)) == NULL)
    goto err;
  slist_free(list); list = NULL;

  return re;

 err:
  if(list != NULL) slist_free(list);
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

static sc_regex_t *sc_regex_alloc_css(const sc_css_t *in)
{
  const char *ptr = in->css;
  const char *start;
  sc_regex_t *re = NULL;
  slist_t *list = NULL;
  int i = 0;
  char buf[256], *dup = NULL;
  size_t off;

  if((list = slist_alloc()) == NULL)
    goto err;

  while(i != in->cssc)
    {
      start = NULL;
      off = 0;
      buf[off++] = '^';

      while(*ptr != '\0')
	{
	  if(*ptr == '[')
	    {
	      if(start != NULL)
		{
		  sc_regex_capget_css_lit2(buf,sizeof(buf),&off,start,ptr-1);
		  start = NULL;
		}

	      /* skip over [X]+ */
	      while(*ptr != ']' && *ptr != '\0')
		{
		  buf[off++] = *ptr;
		  ptr++;
		}
	      if(*ptr == '\0')
		goto err;
	      buf[off++] = *ptr; ptr++;
	      buf[off++] = *ptr; ptr++;
	    }
	  else if(ptr[0] == '\\' && ptr[1] == 'd' && ptr[2] == '+')
	    {
	      if(start != NULL)
		{
		  sc_regex_capget_css_lit2(buf,sizeof(buf),&off,start,ptr-1);
		  start = NULL;
		}

	      /* skip over \d+ */
	      buf[off++] = *ptr; ptr++;
	      buf[off++] = *ptr; ptr++;
	      buf[off++] = *ptr; ptr++;
	    }
	  else if(*ptr == '.')
	    {
	      if(start != NULL)
		{
		  sc_regex_capget_css_lit2(buf,sizeof(buf),&off,start,ptr-1);
		  start = NULL;
		}

	      /* skip over .+ */
	      buf[off++] = *ptr; ptr++;
	      buf[off++] = *ptr; ptr++;
	    }
	  else if(*ptr == '\\')
	    {
	      if(start == NULL)
		{
		  buf[off++] = ptr[0];
		  buf[off++] = ptr[1];
		}
	      /* skip over escaped characters */
	      ptr++; ptr++;
	    }
	  else
	    {
	      if(start == NULL)
		start = ptr;
	      ptr++;
	    }
	}

      if(start != NULL)
	sc_regex_capget_css_lit2(buf, sizeof(buf), &off, start, ptr-1);

      buf[off++] = '$';
      buf[off++] = '\0';
      if((dup = memdup(buf,off)) == NULL || slist_tail_push(list,dup) == NULL)
	goto err;
      dup = NULL;

      ptr++;
      i++;
    }

  if((re = sc_regex_alloc_list(list)) == NULL)
    goto err;

  slist_free_cb(list, (slist_free_t)free);
  return re;

 err:
  if(list != NULL) slist_free_cb(list, (slist_free_t)free);
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

/*
 * sc_regex_capseg
 *
 * rewrite the input regex so that any character class segments are
 * captured separately so they can be further analyzed.
 */
static char *sc_regex_capseg(const char *in)
{
  const char *ptr = in;
  char *buf = NULL, *dup = NULL;
  size_t off, len;

  /* allocate a working buffer larger than we could possibly need */
  len = strlen(in) * 3;
  if((buf = malloc(len)) == NULL)
    goto done;

  off = 0;
  while(*ptr != '\0')
    {
      if(ptr[0] == '[' && ptr[1] == '^')
	{
	  buf[off++] = '(';
	  while(*ptr != ']' && *ptr != '\0')
	    {
	      buf[off++] = *ptr;
	      ptr++;
	    }
	  if(*ptr == '\0')
	    goto done;
	  buf[off++] = *ptr; ptr++; /* ] */
	  buf[off++] = *ptr; ptr++; /* + */
	  buf[off++] = ')';
	}
      else if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  while(*ptr != ')' && *ptr != '\0')
	    {
	      buf[off++] = *ptr;
	      ptr++;
	    }
	  if(*ptr == '\0')
	    goto done;
	  buf[off++] = *ptr; ptr++;
	}
      else if(ptr[0] == '.' && ptr[1] == '+')
	{
	  buf[off++] = '(';
	  buf[off++] = *ptr; ptr++;
	  buf[off++] = *ptr; ptr++;
	  buf[off++] = ')';
	}
      else if(ptr[0] == '\\')
	{
	  buf[off++] = *ptr; ptr++;
	  if(*ptr == '\0')
	    goto done;
	  buf[off++] = *ptr; ptr++;
	}
      else if(ptr[0] == '(' || ptr[0] == ')')
	{
	  ptr++;
	}
      else
	{
	  buf[off++] = *ptr; ptr++;
	}
    }
  buf[off++] = '\0';
  dup = strdup(buf);

 done:
  if(buf != NULL) free(buf);
  return dup;
}

#ifndef DMALLOC
static sc_regex_t *sc_regex_alloc(char *str)
#else
#define sc_regex_alloc(str) sc_regex_alloc_dm((str), __FILE__, __LINE__)
static sc_regex_t *sc_regex_alloc_dm(char *str,const char *file,const int line)
#endif
{
  sc_regex_t *re = NULL;
  int capc;

  if((capc = capcount(str)) < 0)
    goto err;

#ifndef DMALLOC
  re = malloc_zero(sizeof(sc_regex_t));
#else
  re = malloc_zero_dm(sizeof(sc_regex_t), file, line);
#endif

  if(re == NULL ||
     (re->regexes = malloc_zero(sizeof(sc_regexn_t *) * 1)) == NULL ||
     (re->regexes[0] = malloc_zero(sizeof(sc_regexn_t))) == NULL)
    goto err;
  re->regexc = 1;
  re->regexes[0]->str = str;
  re->regexes[0]->capc = capc;
  return re;

 err:
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

static sc_regex_t *sc_regex_dup(sc_regex_t *in)
{
  sc_regex_t *out = NULL;
  size_t len;
  int i;

  if((out = memdup(in, sizeof(sc_regex_t))) == NULL)
    goto err;
  out->regexes = NULL;
  out->tp_mask = NULL;
  len = sizeof(sc_regexn_t *) * in->regexc;
  if((out->regexes = malloc_zero(len)) == NULL)
    goto err;
  if(in->tp_mask != NULL)
    {
      len = sizeof(uint32_t) * in->dom->tpmlen;
      if((out->tp_mask = memdup(in->tp_mask, len)) == NULL)
	goto err;
    }

  for(i=0; i<in->regexc; i++)
    if((out->regexes[i] = sc_regexn_dup(in->regexes[i])) == NULL)
      goto err;

  return out;

 err:
  if(out != NULL) sc_regex_free(out);
  return NULL;
}

static sc_regex_t *sc_regex_find(splaytree_t *tree, char *str, int capc,
				 uint8_t *plan)
{
  sc_regex_t fm;
  sc_regexn_t *regexes[1];
  sc_regexn_t ren;

  ren.str = str;
  ren.capc = capc;
  ren.plan = plan;
  regexes[0] = &ren;
  fm.regexes = regexes;
  fm.regexc  = 1;

  return splaytree_find(tree, &fm);
}

#ifndef DMALLOC
static sc_regex_t *sc_regex_get(splaytree_t *tree, char *str, int capc,
				uint8_t *geotypes)
#else
#define sc_regex_get(tree, str, capc, geotypes) \
  sc_regex_get_dm((tree), (str), (capc), (geotypes), __FILE__, __LINE__)
static sc_regex_t *sc_regex_get_dm(splaytree_t *tree, char *str, int capc,
				   uint8_t *geotypes,
				   const char *file, const int line)
#endif
{
  sc_regex_t *re = NULL;
  char *dup = NULL;

  if((re = sc_regex_find(tree, str, capc, geotypes)) != NULL)
    return re;
  if((dup = strdup(str)) == NULL)
    goto err;
#ifndef DMALLOC
  re = sc_regex_alloc(dup);
#else
  re = sc_regex_alloc_dm(dup, file, line);
#endif
  if(re == NULL)
    goto err;
  dup = NULL;

  if(geotypes != NULL &&
     (re->regexes[0]->plan = memdup(geotypes,sizeof(uint8_t)*capc)) == NULL)
    goto err;
  re->regexes[0]->capc = capc;
  if(splaytree_insert(tree, re) == NULL)
    goto err;
  return re;

 err:
  if(dup != NULL) free(dup);
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

static int sc_regex_capset_css(dlist_t *list, splaytree_t *tree, sc_css_t *cap)
{
  sc_regex_t *re, *re_eval, *re_new = NULL;
  dlist_node_t *dn;
  char *ptr = NULL;

  for(dn=dlist_head_node(list); dn != NULL; dn=dlist_node_next(dn))
    {
      re_eval = dlist_node_item(dn);
      if((ptr = sc_regex_caprep_css(re_eval->regexes[0]->str, cap)) == NULL)
	continue;
      if((re_new = sc_regex_alloc(ptr)) == NULL)
	goto err;
      ptr = NULL;
      if((re = splaytree_find(tree, re_new)) != NULL)
	{
	  if(re->score < re_eval->score)
	    re->score = re_eval->score;
	  sc_regex_free(re_new); re_new = NULL;
	  continue;
	}
      re_new->dom = re_eval->dom;
      re_new->score = re_eval->score;
      if(splaytree_insert(tree, re_new) == NULL)
	goto err;
    }

  return 0;

 err:
  if(re_new != NULL) sc_regex_free(re_new);
  if(ptr != NULL) free(ptr);
  return -1;
}

static void sc_iface_free(sc_iface_t *iface)
{
  uint8_t i;
  if(iface->addr != NULL)
    scamper_addr_free(iface->addr);
  if(iface->name != NULL)
    free(iface->name);
  if(iface->asnames != NULL)
    free(iface->asnames);
  if(iface->geos != NULL)
    {
      for(i=0; i<iface->geoc; i++)
	free(iface->geos[i].tags);
      free(iface->geos);
    }
  free(iface);
  return;
}

static int sc_ifaceinf_css_null(sc_ifaceinf_t *ifi, void *param)
{
  ifi->css = NULL;
  return 0;
}

static void sc_ifaceinf_free(sc_ifaceinf_t *ifi)
{
  if(ifi->css != NULL) sc_css_free(ifi->css);
  free(ifi);
  return;
}

static int sc_ifaceinf_class_cmp(const sc_ifaceinf_t *a,const sc_ifaceinf_t *b)
{
  if(a->class == b->class)
    return sc_iface_cmp(a->ifd->iface, b->ifd->iface);
  if(a->class == '+') return -1;
  if(b->class == '+') return  1;
  if(a->class == '=') return -1;
  if(b->class == '=') return  1;
  if(a->class == '!') return -1;
  if(b->class == '!') return  1;
  if(a->class == '~') return -1;
  if(b->class == '~') return  1;
  if(a->class == '?') return -1;
  if(b->class == '?') return  1;
  if(a->class == '*') return -1;
  if(b->class == '*') return  1;
  return 0;
}

static int sc_ifaceinf_inf_cmp(const sc_ifaceinf_t *a, const sc_ifaceinf_t *b)
{
  if(a->css == NULL && b->css == NULL) return 0;
  if(a->css == NULL) return 1;
  if(b->css == NULL) return -1;
  return sc_css_css_cmp(a->css, b->css);
}

static int sc_ifaceinf_ifd_rd_cmp(const sc_ifaceinf_t *a,
				  const sc_ifaceinf_t *b)
{
  if(a->ifd->rd < b->ifd->rd) return -1;
  if(a->ifd->rd > b->ifd->rd) return  1;
  return 0;
}

static int sc_ifaceinf_rtrc_cmp(const sc_ifaceinf_t *a, const sc_ifaceinf_t *b)
{
  if(a->rtrc > b->rtrc) return -1;
  if(a->rtrc < b->rtrc) return  1;
  return ptrcmp(a->ifd->rd, b->ifd->rd);
}

#ifndef DMALLOC
static sc_ifaceinf_t *sc_ifaceinf_get(slist_t *list, sc_ifacedom_t *ifd,
				      sc_css_t *css, int ip, int regex)
#else
#define sc_ifaceinf_get(list,ifd,css,ip,regex) sc_ifaceinf_get_dm((list), \
    (ifd), (css),(ip),(regex),__FILE__,__LINE__)
static sc_ifaceinf_t *sc_ifaceinf_get_dm(slist_t *list, sc_ifacedom_t *ifd,
					 sc_css_t *css, int ip, int regex,
					 const char *file, const int line)
#endif
{
  sc_ifaceinf_t *ifi;

#ifndef DMALLOC
  ifi = malloc(sizeof(sc_ifaceinf_t));
#else
  ifi = dmalloc_malloc(file,line,sizeof(sc_ifaceinf_t),DMALLOC_FUNC_MALLOC,0,0);
#endif
  if(ifi == NULL)
    goto err;
  ifi->ifd = ifd;
  ifi->css = css;
  ifi->ri = NULL;
  ifi->geohint = NULL;
  ifi->rtrc = 0;
  ifi->regex = regex;
  ifi->class = '\0';
  ifi->ipm = ip;
  if(slist_tail_push(list, ifi) == NULL)
    goto err;
  return ifi;

 err:
  if(ifi != NULL) sc_ifaceinf_free(ifi);
  return NULL;
}

static void sc_regex_css_free(sc_regex_css_t *recss)
{
  if(recss == NULL)
    return;
  if(recss->work != NULL)
    sc_regex_free(recss->work);
  if(recss->regex != NULL)
    sc_regex_free(recss->regex);
  if(recss->css != NULL)
    sc_css_free(recss->css);
  free(recss);
  return;
}

static sc_iface_t *sc_iface_alloc(char *ip, char *name)
{
  sc_iface_t *iface;
  if((iface = malloc_zero(sizeof(sc_iface_t))) == NULL ||
     (iface->addr = scamper_addr_fromstr_unspec(ip)) == NULL ||
     (name[0] != '\0' && (iface->name = strdup(name)) == NULL))
    goto err;

  if(scamper_addr_isipv4(iface->addr))
    {
      if(ip_v != 4)
	{
	  printf("%s", ip);
	  if(name[0] != '\0')
	    printf(" for %s", name);
	  printf(" is an IPv4 address, but -6 was specified");
	  goto err;
	}
    }
  else if(scamper_addr_isipv6(iface->addr))
    {
      if(ip_v != 6)
	{
	  printf("%s", ip);
	  if(name[0] != '\0')
	    printf(" for %s", name);
	  printf(" is an IPv6 address, but -6 was not specified");
	  goto err;
	}
    }
  else
    {
      printf("unhandled address type\n");
      goto err;
    }

  iface->len = strlen(name);
  return iface;
 err:
  if(iface != NULL) sc_iface_free(iface);
  return NULL;
}

static int sc_iface_ip_find_4(sc_iface_t *iface, const char *suffix)
{
  const struct in_addr *in;
  uint32_t addr;
  const char *ptr;
  const char *so[200][2]; /* string offsets */
  long sb[200]; /* string address bytes */
  long ab[4]; /* IP address bytes */
  long set[4];
  int c, i, j, k, l, bo = 0, ip_s = -1, ip_e = -1;
  char *ep;
  char buf[128];

  ptr = iface->name;
  in = scamper_addr_addr_get(iface->addr);
  addr = ntohl(in->s_addr);

  while((size_t)bo < sizeof(sb) / sizeof(long))
    {
      while(isdigit((unsigned char)*ptr) == 0 && ptr != suffix)
	ptr++;
      if(ptr >= suffix)
	break;
      sb[bo] = strtol(ptr, &ep, 10);
      so[bo][0] = ptr;
      so[bo][1] = ep;
      bo++;
      ptr = ep;
    }

  if(bo == 0)
    return 0;

  ab[0] = (addr >> 24) & 0xFF;
  ab[1] = (addr >> 16) & 0xFF;
  ab[2] = (addr >> 8) & 0xFF;
  ab[3] = addr & 0xFF;

  /*
   * the approach is as follows: we first try to find examples where
   * all 4 bytes are present.  then, we try to find examples where at
   * least 3 bytes are present.  then two.  we do not try and find
   * examples where only a single byte of the address is present
   */
  for(l=4; l>=2; l--)
    {
      for(i=0; i<bo-l+1; i++)
	{
	  c = 0;
	  for(k=0; k<4; k++)
	    set[k] = 0;
	  ip_s = -1; ip_e = -1;

	  /* j is used to index the sb array, offset by i */
	  for(j=0; j<l; j++)
	    {
	      /*
	       * k is used to index the ab array.  we allow each byte
	       * of the ab array to be used once
	       */
	      for(k=0; k<4; k++)
		{
		  if(sb[i+j] == ab[k] && set[k] == 0)
		    {
		      if(ip_s == -1 || ip_s > so[i+j][0] - iface->name)
			ip_s = so[i+j][0] - iface->name;
		      if(ip_s == -1 || ip_e < so[i+j][1] - iface->name - 1)
			ip_e = so[i+j][1] - iface->name - 1;
		      set[k] = 1;
		      c++;
		      break;
		    }
		}
	    }

	  if(c == l)
	    {
	      iface->flags |= SC_IFACE_FLAG_IP;
	      iface->ip_s = ip_s;
	      iface->ip_e = ip_e;
	      if(do_debug != 0 && threadc <= 1)
		{
		  printf("found %s in %s bytes %d - %d\n",
			 scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
			 iface->name, iface->ip_s, iface->ip_e);
		}
	      return 1;
	    }
	}
    }

  return 0;
}

static int pos_diff(int x, int y)
{
  if(x < y)
    return y - x;
  return x - y;
}

#if 0
static int sc_charpos_isvalid(sc_iface_t *iface, sc_charpos_t *cp, int x)
{
  int i;

  for(i=0; i<32; i++)
    {
      if(cp->pos[i] == -1)
	continue;
      if(iface->name[cp->pos[i]] != cp->c[i])
	{
	  printf("%s %d: %c != %c at pos %d\n", iface->name, x,
		 iface->name[cp->pos[i]], cp->c[i], cp->pos[i]);
	}
    }

  return 0;
}
#endif

#if 0
static void sc_charpos_print(const sc_iface_t *iface, sc_charpos_t *cp, int max)
{
  char buf[256];
  int i;

  printf("%s %s %d %d %d\n", iface->name,
	 scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
	 cp->left, cp->right, cp->digits);
  for(i=0; i<max; i++)
    {
      if(cp->pos[i] == -1)
	continue;
      printf("%c %d %d\n", cp->c[i], i, cp->pos[i]);
    }

  return;
}
#endif

#if 0
static void sc_charposl_dump(sc_charposl_t *posl)
{
  static const char c[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			   'a', 'b', 'c', 'd', 'e', 'f'};
  int i, j;

  for(i=0; i<16; i++)
    {
      printf("%c:", posl[i].c);
      for(j=0; j<posl[i].posc; j++)
	printf(" %d", posl[i].pos[j]);
      printf("\n");
    }

  return;
}
#endif

static void sc_charpos_score(sc_charpos_t *cp, int max)
{
  int i;

  cp->left = -1;
  cp->right = -1;
  cp->digits = 0;

  for(i=0; i<max; i++)
    {
      if(cp->pos[i] == -1)
	continue;
      cp->digits++;
      if(cp->pos[i] < cp->left || cp->left == -1)
	cp->left = cp->pos[i];
      if(cp->pos[i] > cp->right || cp->right == -1)
	cp->right = cp->pos[i];
    }

  return;
}

static int sc_charpos_score_cmp(const sc_charpos_t *a, const sc_charpos_t *b)
{
  int ar, br;
  if(a->digits > b->digits) return -1;
  if(a->digits < b->digits) return  1;
  ar = a->right - a->left + 1;
  br = b->right - a->right + 1;
  if(ar < br) return -1;
  if(ar > br) return  1;
  return 0;
}

/**
 * INPUT iface
 * INPUT cp
 * OUTPUT int
 */
static int sc_iface_ip_isok(const sc_iface_t *iface, const sc_charpos_t *cp)
{
  int i, j, x, nonzero[8], set[8], left, right;
  int blocksize, blocks, max;

  if(scamper_addr_isipv4(iface->addr))
    {
      blocks = 4;
      blocksize = 2;
      max = 8;
    }
  else if(scamper_addr_isipv6(iface->addr))
    {
      blocks = 8;
      blocksize = 4;
      max = 32;
    }
  else return 0;

  /*
   * check each digit is set in each block when any digit in the block
   * is set.
   */
  for(i=0; i<blocks; i++)
    {
      nonzero[i] = 0;
      set[i] = 0;
      x = i * blocksize;

      /* check if any character in the block is not zero */
      for(j=0; j<blocksize; j++)
	if(cp->c[x+j] != '0')
	  break;
      if(j != blocksize)
	nonzero[i] = 1;

      /* check if any character after a set character is unset */
      for(j=0; j<blocksize; j++)
	if(cp->pos[x+j] != -1)
	  break;
      if(j == blocksize)
	continue;
      set[i] = 1;
      for(j=j+1; j<blocksize; j++)
	if(cp->pos[x+j] == -1)
	  return 0;
    }

  /* determine if there is a gap in block coverage, and reject if there is */
  x = 0; j = 0;
  for(i=0; i<blocks; i++)
    {
      if(set[i] == 1 && j == 0)
	j = 1;
      else if(j == 1 && set[i] == 0 && nonzero[i] != 0)
	x = 1;
      else if(set[i] == 1 && x == 1)
	return 0;
    }

  /* determine if there is any non-alnum character not covered */
  left = -1; right = -1;
  for(i=0; i<max; i++)
    {
      if(cp->pos[i] == -1)
	continue;
      if(cp->pos[i] < left || left == -1)
	left = cp->pos[i];
      if(cp->pos[i] > right || right == -1)
	right = cp->pos[i];
    }
  for(i=left+1; i<right; i++)
    {
      if(iface->name[i] == '0' || isalnum((unsigned char)iface->name[i]) == 0)
	continue;
      if(ishex(iface->name[i]) == 0)
	return 0;
      for(j=0; j<max; j++)
	if(cp->pos[j] == i)
	  break;
      if(j == max)
	return 0;
    }

  return 1;
}

static void sc_iface_ip_unfill_zero(sc_charpos_t *cp, int max)
{
  int i;
  for(i=0; i<max; i++)
    if(cp->c[i] == '0')
      cp->pos[i] = -1;
  return;
}

/**
 * Right-fills the pos array after the first set character.
 * INPUT iface
 * INPUT/OUTPUT cp: May change cp->pos array.
 */
static void sc_iface_ip_fill_zero6(sc_iface_t *iface, sc_charpos_t *cp)
{
  int i, j, x, pos, asc = 0, desc = 0;

  for(i=0; i<8; i++)
    {
      pos = -1;
      for(j=0; j<4; j++)
	{
	  if(cp->pos[(i*4)+j] == -1)
	    continue;
	  if(pos != -1)
	    {
	      if(pos < cp->pos[(i*4)+j])
		asc++;
	      else
		desc++;
	    }
	  pos = cp->pos[(i*4)+j];
	}
    }

  for(i=0; i<8; i++)
    {
      /* find the first set character in the block */
      x = i * 4;
      for(j=0; j<4; j++)
	if(cp->pos[x+j] != -1)
	  break;
      if(j == 4)
	continue;
      pos = j;

      if(asc > desc && asc > 0)
	{
	  /*
	   * make sure there are zeros for all unfilled positions to
	   * the right of the first set character in the block
	   */
	  for(j=pos+1; j<4; j++)
	    {
	      if(cp->pos[x+j] == -1 &&
		 iface->name[cp->pos[x+pos] + (j - pos)] != '0')
		break;
	    }
	  if(j != 4)
	    continue;

	  /* fill zeros to the left of the first set character */
	  for(j=pos-1; j>=0; j--)
	    {
	      if(iface->name[cp->pos[x+pos] - (pos - j)] != '0')
		break;
	      cp->pos[x+j] = cp->pos[x+pos] - (pos - j);
	    }

	  /* fill zeros to the right of the first set character */
	  for(j=pos+1; j<4; j++)
	    {
	      if(cp->pos[x+j] != -1)
		continue;
	      if(iface->name[cp->pos[x+pos] + (j - pos)] != '0')
		break;
	      cp->pos[x+j] = cp->pos[x+pos] + (j - pos);
	    }
	}
      else if(desc > asc && desc > 0)
	{
	  /*
	   * make sure there are zeros for all unfilled positions to
	   * the left of the first set character in the block
	   */
	  for(j=pos+1; j<4; j++)
	    {
	      if(cp->pos[x+j] == -1 &&
		 iface->name[cp->pos[x+pos] - (j - pos)] != '0')
		break;
	    }
	  if(j != 4)
	    continue;

	  /* fill zeros to the left of the first set character */
	  for(j=pos-1; j>=0; j--)
	    {
	      if(iface->name[cp->pos[x+pos] + (pos - j)] != '0')
		break;
	      cp->pos[x+j] = cp->pos[x+pos] + (pos - j);
	    }

	  /* fill zeros to the right of the first set character */
	  for(j=pos+1; j<4; j++)
	    {
	      if(cp->pos[x+j] != -1)
		continue;
	      if(iface->name[cp->pos[x+pos] - (j - pos)] != '0')
		break;
	      cp->pos[x+j] = cp->pos[x+pos] - (j - pos);
	    }
	}
    }

  return;
}

static void sc_iface_ip_fill_zero4(sc_iface_t *iface, sc_charpos_t *cp)
{
  int asc = 0, desc = 0, i, x, y;

  for(i=0; i<4; i++)
    {
      x = (i * 2); y = x + 1;
      if(cp->pos[x] != -1 && cp->pos[y] != -1)
	{
	  if(cp->pos[x] < cp->pos[y])
	    asc++;
	  else
	    desc++;
	}
    }

  for(i=0; i<4; i++)
    {
      x = (i * 2); y = x + 1;

      /* fill zero to the right of the set character */
      if(cp->pos[x] != -1 && cp->pos[y] == -1)
	{
	  if(asc > desc && asc > 0 && iface->name[cp->pos[x]+1] == '0')
	    cp->pos[y] = cp->pos[x]+1;
	}
      /* fill zero to the left of the set character */
      else if(cp->pos[x] == -1 && cp->pos[y] != -1)
	{
	  if(asc > desc && asc > 0 && cp->pos[y] > 0 &&
	     iface->name[cp->pos[y]-1] == '0')
	    cp->pos[x] = cp->pos[y]-1;
	}
    }

  return;
}

static void sc_iface_ip_fill_zero(sc_iface_t *iface, sc_charpos_t *cp)
{
  if(scamper_addr_isipv4(iface->addr))
    sc_iface_ip_fill_zero4(iface, cp);
  else if(scamper_addr_isipv6(iface->addr))
    sc_iface_ip_fill_zero6(iface, cp);
  return;
}

/**
 * INPUT iface:
 * INPUT suffix:
 * INPUT/OUTPUT posl:
 * INPUT/OUTPUT cp:
 * INPUT x: Starting position within the suffix string
 * OUTPUT best:
 */
static int sc_iface_ip_find_hex_rec(sc_iface_t *iface, const char *suffix,
				    sc_charposl_t *posl, sc_charpos_t *cp,
				    int x, int max, sc_charpos_t *best)
{
  int i, j, k, c, v;
  int a[4];

  /* for each 16 bit block, check for some basic properties or early reject */
  if(scamper_addr_isipv6(iface->addr) && (x % 4) == 0 && x != 0)
    {
      /* start offset */
      i = ((x / 4) - 1) * 4;

      /* ensure positions are sequential */
      c = 0;
      for(j=0; j<4; j++)
	if(cp->pos[i+j] != -1)
	  a[c++] = cp->pos[i+j];
      for(j=2; j<c; j++)
	if((a[j-2] < a[j-1] && a[j-1] > a[j]) ||
	   (a[j-2] > a[j-1] && a[j-1] < a[j]))
	  return 0;

      /* if any bit is set, make sure all non-zero chars are represented */
      if(c > 0 &&
	 ((cp->pos[i+0] == -1 && cp->c[i+0] != '0') ||
	  (cp->pos[i+1] == -1 && cp->c[i+1] != '0') ||
	  (cp->pos[i+2] == -1 && cp->c[i+2] != '0') ||
	  (cp->pos[i+3] == -1 && cp->c[i+3] != '0')))
	return 0;

      /* ensure the positions seem reasonable */
      for(j=0; j<4; j++)
	{
	  if(cp->pos[i+j] == -1)
	    continue;
	  for(k=j+1; k<4; k++)
	    {
	      if(cp->pos[i+k] == -1)
		continue;
	      if(pos_diff(cp->pos[i+j], cp->pos[i+k]) != k - j)
		return 0;
	    }
	}
    }

  if(x == max)
    {
      sc_iface_ip_fill_zero(iface, cp);
      if(sc_iface_ip_isok(iface, cp) != 0)
	{
	  sc_charpos_score(cp, max);
	  if(sc_charpos_score_cmp(cp, best) < 0)
	    memcpy(best, cp, sizeof(sc_charpos_t));
	}
      sc_iface_ip_unfill_zero(cp, max);
      return 0;
    }

  if(isdigit((unsigned char)cp->c[x]))
    c = cp->c[x] - '0';
  else
    c = cp->c[x] - 'a' + 10;

  if(cp->c[x] == '0')
    {
      sc_iface_ip_find_hex_rec(iface, suffix, posl, cp, x+1, max, best);
      return 0;
    }

  for(i=0; i<posl[c].posc; i++)
    {
      if(posl[c].pos[i] != -1)
	{
	  v = posl[c].pos[i]; posl[c].pos[i] = -1;
	  cp->pos[x] = v;
	  sc_iface_ip_find_hex_rec(iface, suffix, posl, cp, x+1, max, best);
	  posl[c].pos[i] = v;
	}
    }

  cp->pos[x] = -1;
  sc_iface_ip_find_hex_rec(iface, suffix, posl, cp, x+1, max, best);

  return 0;
}

static int sc_iface_ip_find_hex_enough(sc_iface_t *iface, sc_charpos_t *cp)
{
  int i;
  if(scamper_addr_isipv4(iface->addr))
    {
      if(cp->digits < 6)
	return 0;
      for(i=0; i<8; i++)
	if(cp->c[i] != '0' && cp->pos[i] == -1)
	  return 0;
      return 1;
    }
  else if(scamper_addr_isipv6(iface->addr))
    {
      if(cp->digits < 4)
	return 0;
      return 1;
    }
  return 0;
}

/*
 * sc_iface_ip_find_hex:
 *
 * INPUT/OUTPUT iface: May change iface->ip_s and iface->ip_e.
 * INPUT suffix: The domain name suffix of the interface.
 *
 * infer if a portion of the hostname happens to correspond to an IP
 * address literal in hex format.
 */
static int sc_iface_ip_find_hex(sc_iface_t *iface, const char *suffix)
{
  sc_charposl_t posl[16];
  sc_charpos_t cp, best;
  uint8_t u;
  char c, *ptr, buf[256];
  int i, j, max, rc = -1;

  memset(&cp, 0, sizeof(cp));
  memset(posl, 0, sizeof(posl));

  /* Convert scamper address to IPv6 address string */
  if(scamper_addr_isipv4(iface->addr))
    max = 8;
  else if(scamper_addr_isipv6(iface->addr))
    max = 32;
  else
    return -1;
  for(i=0; i<max; i++)
    {
      u =
	scamper_addr_bit(iface->addr, (i * 4) + 1) << 3 |
	scamper_addr_bit(iface->addr, (i * 4) + 2) << 2 |
	scamper_addr_bit(iface->addr, (i * 4) + 3) << 1 |
	scamper_addr_bit(iface->addr, (i * 4) + 4);
      if(u <= 9)
	cp.c[i] = '0' + u;
      else
	cp.c[i] = 'a' + (u - 10);
      cp.pos[i] = -1;
    }

  /* Count all possible hex digits that appear in the label */
  for(i=1; i<16; i++)
    {
      if(i < 10) c = '0' + i;
      else       c = 'a' + (i - 10);

      /* count how many instances of the character are in the string */
      j = 0;
      ptr = iface->name;
      while(ptr != suffix)
	{
	  if(*ptr == c)
	    j++;
	  ptr++;
	}

      /* allocate enough instances */
      if((posl[i].pos = malloc(sizeof(int) * j)) == NULL)
	goto done;
      posl[i].posc = j;
      j = 0;
      ptr = iface->name;
      while(ptr != suffix)
	{
	  if(*ptr == c)
	    {
	      posl[i].pos[j] = ptr - iface->name;
	      j++;
	    }
	  ptr++;
	}
    }

  memset(&best, 0, sizeof(best));

  sc_iface_ip_find_hex_rec(iface, suffix, posl, &cp, 0, max, &best);

  /* check that enough bits of the address are covered */
  if(sc_iface_ip_find_hex_enough(iface, &best) == 0)
    {
      rc = 0;
      goto done;
    }

  iface->ip_s = best.left;
  iface->ip_e = best.right;
  iface->flags |= (SC_IFACE_FLAG_IP|SC_IFACE_FLAG_IP_HEX);
  if(do_debug != 0 && threadc <= 1)
    {
      printf("found %s in %s bytes %d - %d\n",
	     scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
	     iface->name, iface->ip_s, iface->ip_e);
    }
  rc = 1;

 done:
  for(i=0; i<16; i++)
    if(posl[i].pos != NULL)
      free(posl[i].pos);
  return rc;
}

static void sc_iface_ip_find_thread(sc_iface_t *iface)
{
  const char *suffix = sc_suffix_find(iface->name);
  /* todo: integrate sc_iface_ip_find_unseparated_ipv4 */
  if(scamper_addr_isipv4(iface->addr))
    {
      sc_iface_ip_find_4(iface, suffix);
      if((iface->flags & SC_IFACE_FLAG_IP) == 0)
	sc_iface_ip_find_hex(iface, suffix);
    }
  else if(scamper_addr_isipv6(iface->addr))
    {
      sc_iface_ip_find_hex(iface, suffix);
    }
  return;
}

/*
 * sc_iface_ip_matched
 *
 * determine if the regex matched part of a string that appears to have
 * been derived from the corresponding IP address
 */
static int sc_iface_ip_matched(sc_iface_t *iface, sc_rework_t *rew)
{
  size_t i;

  if((iface->flags & SC_IFACE_FLAG_IP) == 0)
    return 0;

#if 0
  printf("%s %d %d:", iface->name, iface->ip_s, iface->ip_e);
  for(i=1; i<rew->m; i++)
    printf(" %d,%d", rew->ovector[2*i], rew->ovector[(2*i)+1]);
  printf("\n");
#endif

  for(i=1; i<rew->m; i++)
    {
      if(iface->ip_e < rew->ovector[2*i])
	continue;
      if(iface->ip_s > rew->ovector[(2*i)+1])
	continue;
      return 1;
    }

  return 0;
}

static void sc_iface_asn_find_thread(sc_ifacedom_t *ifd)
{
  sc_iface_t *iface = ifd->iface;
  char buf[128], *dup = NULL;
  int i, as_s = -1, as_e = -1, as_dist = -1, dist, start, stop;
  size_t len;

  snprintf(buf, sizeof(buf), "%u", iface->rtr->asn);
  len = strlen(buf);
  if((dup = strdup(ifd->label)) == NULL)
    return;

  i = 0; stop = 0;
  for(;;)
    {
      while(dup[i] != '\0' && isdigit((unsigned char)dup[i]) == 0)
	i++;
      if(dup[i] == '\0')
	break;

      start = i;
      while(dup[i] != '\0' && isdigit((unsigned char)dup[i]) != 0)
	i++;

      if(dup[i] == '\0')
	stop = 1;
      else
	dup[i] = '\0';

      if((iface->flags & SC_IFACE_FLAG_IP) == 0 ||
	 overlap(iface->ip_s, iface->ip_e, start, i-1) == 0)
	{
	  /*
	   * if the edit distance between the ASN extracted from
	   * the hostname and the ASN we believe operates the
	   * router is only one character, then classify the
	   * extraction as a true positive, marked with a '=',
	   * provided the ASNs are at least three characters in
	   * length and the first and last digits both agree.
	   */
	  dist = dled(dup+start, buf);
	  if((dist == 0 ||
	      (do_ed1 != 0 && dist == 1 && len >= 3 && i - start >= 3 &&
	       dup[start] == buf[0] && dup[i-1] == buf[len-1])) &&
	     (as_dist == -1 || as_dist > dist))
	    {
	      as_s = start;
	      as_e = i-1;
	      as_dist = dist;
	    }
	}

      if(stop != 0)
	break;
      i++;
    }

  if(as_s != -1)
    {
      iface->as_s = as_s;
      iface->as_e = as_e;
      iface->flags |= SC_IFACE_FLAG_AS;
      if(as_dist > 0)
	iface->flags |= SC_IFACE_FLAG_AS_ED1;
      if(do_debug != 0 && threadc <= 1)
	{
	  printf("found %u in %s %s bytes %d - %d\n", iface->rtr->asn,
		 iface->name, scamper_addr_tostr(iface->addr,buf,sizeof(buf)),
		 iface->as_s, iface->as_e);
	}
    }

  free(dup);
  return;
}

static int sc_iface_asname_find_check(slist_t *list, const sc_iface_t *iface,
				      char *str, int i, int j)
{
  sc_as2tag_t *a2t;
  int *pair = NULL;
  int rc = -1;
  char in;

  in = str[j];
  str[j] = '\0';

  if((a2t = sc_as2tag_find(str+i)) == NULL ||
     sc_as2org_siblings(a2t->asn, iface->rtr->asn) == 0)
    {
      rc = 0;
      goto done;
    }

  if(do_debug != 0 && threadc <= 1)
    printf("found %s in %s %u bytes %d %d\n",
	   a2t->tag, iface->name, a2t->asn, i, j-1);

  if((pair = malloc(sizeof(int) * 2)) == NULL ||
     slist_tail_push(list, pair) == NULL)
    goto done;

  pair[0] = i;
  pair[1] = j-1;
  pair = NULL;
  rc = 1;

 done:
  str[j] = in;
  if(pair != NULL) free(pair);
  return rc;
}

static void sc_iface_asname_find_thread(sc_ifacedom_t *ifd)
{
  sc_iface_t *iface = ifd->iface;
  slist_t *list = NULL;
  char *str = NULL;
  int i = 0, j = 0, k, x, stop = 0, *pair = NULL;

  if(iface->asnames != NULL)
    {
      free(iface->asnames);
      iface->asnames = NULL;
    }
  iface->asnamec = 0;

  if((list = slist_alloc()) == NULL || (str = strdup(ifd->label)) == NULL)
    goto done;

  /* skip over any non-alnum characters */
  while(str[i] != '\0' && isalnum((unsigned char)str[i]) == 0)
   i++;
  if(str[i] == '\0')
    goto done;

  j = i;
  for(;;)
    {
      while(isalnum((unsigned char)str[j]) != 0)
	j++;
      if(str[j] == '\0')
	stop = 1;

      /* see if we can find this exact tag */
      if((x = sc_iface_asname_find_check(list, iface, str, i, j)) < 0)
	goto done;

      /*
       * if we can't find this exact tag, and the string ends with digits,
       * try without the digits.
       */
      if(x == 0 && isdigit((unsigned char)str[j-1]) != 0)
	{
	  k = j;
	  while(k > i && isdigit((unsigned char)str[k-1]))
	    k--;
	  if(sc_iface_asname_find_check(list, iface, str, i, k) < 0)
	    goto done;
	}

      if(stop != 0)
	break;
      j++;
      while(str[j] != '\0')
	{
	  if(isalnum((unsigned char)str[j]) != 0)
	    break;
	  j++;
	}
      if(str[j] == 0)
	break;
      i = j;
    }

  if((iface->asnamec = slist_count(list)) == 0 ||
     (iface->asnames = malloc(iface->asnamec * sizeof(int16_t) * 2)) == NULL)
    goto done;
  i = 0;
  while((pair = slist_head_pop(list)) != NULL)
    {
      iface->asnames[i++] = pair[0];
      iface->asnames[i++] = pair[1];
      free(pair); pair = NULL;
    }

 done:
  if(list != NULL) slist_free_cb(list, (slist_free_t)free);
  if(str != NULL) free(str);
  if(pair != NULL) free(pair);
  return;
}

static int sc_rtt_cmp(const void *va, const void *vb)
{
  const sc_rtt_t *a = (const sc_rtt_t *)va;
  const sc_rtt_t *b = (const sc_rtt_t *)vb;
  if(a->rtt < b->rtt) return -1;
  if(a->rtt > b->rtt) return  1;
  return sc_geohint_cmp(a->vp, b->vp);
}

static void sc_router_rtt_sort(const sc_router_t *rtr)
{
  qsort(rtr->rtts, rtr->rttc, sizeof(sc_rtt_t), sc_rtt_cmp);
  return;
}

/*
 * sc_router_ooridx
 *
 * Get the index of the first vantage point in the sample list that is out
 * of range of the geohint
 */
static int sc_router_ooridx(const sc_router_t *rtr, sc_geohint_t *hint,
			    sc_rtt_t **sample_out)
{
  sc_rtt_t *sample;
  double distance;
  uint16_t rtt;
  size_t i;

  *sample_out = NULL;

  for(i=0; i<rtr->rttc; i++)
    {
      sample = &rtr->rtts[i];
      distance = sc_geohint_dist(hint, sample->vp);
      rtt = dist2rtt(distance);
      if(rtt > sample->rtt && rtt - sample->rtt > rtt_fudge)
	{
	  *sample_out = sample;
	  return 0;
	}
    }

  return -1;
}

/*
 * sc_router_checkgeo
 *
 * search for a geohint that is consistent with the string
 */
static sc_geohint_t *sc_router_checkgeo(const sc_regex_t *re,
					const sc_router_t *rtr,
					const sc_geomap_t *map)
{
  sc_geohint_t *hint;

  if(rtr->rttc == 0)
    return NULL;

  for(hint = sc_geohint_find(re, map); hint != NULL; hint = hint->next)
    {
      if(sc_geohint_checkmap(hint, map) == 0)
	continue;
      if(sc_geohint_checkrtt(hint, rtr) > 0)
	return hint;
    }

  return NULL;
}

static void sc_iface_geo_find_print(const sc_ifacedom_t *ifd, const char *code,
				    const sc_geotag_t *tag)
{
  char buf[256], tmp[256];
  int st[2], cc[2];
  size_t i, off = 0;

  st[0] = st[1] = cc[0] = cc[1] = -1;
  for(i=0; i<tag->tagc; i++)
    {
      if(tag->tags[i].type == GEOHINT_TYPE_ST)
	{
	  st[0] = tag->tags[i].start;
	  st[1] = tag->tags[i].end;
	}
      else if(tag->tags[i].type == GEOHINT_TYPE_CC)
	{
	  cc[0] = tag->tags[i].start;
	  cc[1] = tag->tags[i].end;
	}
    }

  string_concat(tmp, sizeof(tmp), &off, "%s", code);
  if(st[0] != -1)
    {
      memcpy(buf, ifd->label + st[0], st[1] - st[0] + 1);
      buf[st[1] - st[0] + 1] = '\0';
      string_concat(tmp, sizeof(tmp), &off, "|%s", buf);
    }
  if(cc[0] != -1)
    {
      memcpy(buf, ifd->label + cc[0], cc[1] - cc[0] + 1);
      buf[cc[1] - cc[0] + 1] = '\0';
      string_concat(tmp, sizeof(tmp), &off, "|%s", buf);
    }

  off = 0;
  string_concat(buf, sizeof(buf), &off,
		"found %s %s",
		geotype_tostr(tag->hint->type), tmp);
  string_concat(buf, sizeof(buf), &off, " \"%s\" in %s bytes",
		sc_geohint_place_tostr(tag->hint, tmp, sizeof(tmp)),
		ifd->iface->name);
  for(i=0; i<tag->tagc; i++)
    string_concat(buf, sizeof(buf), &off, " %d %d",
		  tag->tags[i].start, tag->tags[i].end);
  printf("%s\n", buf);

  return;
}

/*
 * sc_iface_geo_alloctag
 *
 * given a hint, first see if there might be a cc/st in the hostname.
 * then alloc a tag and return it.
 */
static sc_geotag_t *sc_iface_geo_alloctag(const slist_t *ptrc_list,
					  const sc_ifacedom_t *ifd,
					  const sc_geohint_t *hint,
					  const size_t *code, size_t codec)
{
  sc_geotag_t *tag = NULL;
  slist_node_t *sn;
  sc_ptrc_t *ptrc;
  size_t i, tagc = codec, x[2], ip[2];
  int cc[2], st[2];

  /* figure out if the hostname contains st/cc */
  cc[0] = -1; cc[1] = -1; st[0] = -1; st[1] = -1;

  if((ifd->iface->flags & SC_IFACE_FLAG_IP_HEX) != 0)
    {
      ip[0] = ifd->iface->ip_s;
      ip[1] = ifd->iface->ip_e;
    }

  for(sn=slist_head_node(ptrc_list); sn != NULL; sn=slist_node_next(sn))
    {
      ptrc = slist_node_item(sn);

      /*
       * skip over any string portion that overlaps with current capture
       * or an IP address literal
       */
      x[0] = (char *)ptrc->ptr - ifd->label;
      x[1] = x[0] + ptrc->c - 1;
      if(pt_overlap(code, codec * 2, x, 2) != 0 ||
	 ((ifd->iface->flags & SC_IFACE_FLAG_IP_HEX) != 0 &&
	  pt_overlap(ip, 2, x, 2) != 0))
	continue;

      /* if the hostname portion matches the hint's country code */
      if(ptrc->c == 2 && strncmp(ptrc->ptr, hint->cc, ptrc->c) == 0 &&
	 cc[0] == -1)
	{
	  cc[0] = x[0];
	  cc[1] = x[1];
	  tagc++;
	  continue;
	}

      /* if the hostname portion matches the hint's state code */
      if(strlen(hint->st) == ptrc->c && ptrc->c >= 2 &&
	 string_isalpha(hint->st) != 0 &&
	 strncmp(ptrc->ptr, hint->st, ptrc->c) == 0 && st[0] == -1)
	{
	  st[0] = x[0];
	  st[1] = x[1];
	  tagc++;
	  continue;
	}
    }

  if((tag = malloc_zero(sizeof(sc_geotag_t))) == NULL ||
     (tag->tags = malloc_zero(sizeof(sc_geotagn_t) * tagc)) == NULL)
    {
      if(tag != NULL) free(tag);
      return NULL;
    }

  for(i=0; i<codec; i++)
    {
      tag->tags[i].start = code[(i*2) + 0];
      tag->tags[i].end   = code[(i*2) + 1];
      tag->tags[i].type  = hint->type;
    }
  if(cc[0] != -1)
    {
      tag->tags[i].start = cc[0];
      tag->tags[i].end = cc[1];
      tag->tags[i].type = GEOHINT_TYPE_CC;
      i++;
    }
  if(st[0] != -1)
    {
      tag->tags[i].start = st[0];
      tag->tags[i].end = st[1];
      tag->tags[i].type = GEOHINT_TYPE_ST;
      i++;
    }
  assert(i == tagc);
  tag->tagc = tagc;
  tag->hint = (sc_geohint_t *)hint;
  qsort(tag->tags, tag->tagc, sizeof(sc_geotagn_t), sc_geotagn_cmp);

  return tag;
}

static int sc_iface_geo_find_fac(slist_t *list, const sc_ifacedom_t *ifd,
				 char *str, int start, int end,
				 slist_t *ptrc_list)
{
  sc_iface_t *iface = ifd->iface;
  sc_geotag_t *tag = NULL;
  sc_geohint_t *hint, *fac = NULL, *newhint = NULL;
  long in_no, hint_no;
  char buf[256], *ptr, *street;
  int rc = -1, locked = 0;
  size_t offs[256], ip[2], code[2], i;

  code[0] = start; code[1] = end;

  if(string_tolong(str, &in_no) != 0)
    return 0;
  ptr = str;
  while(isdigit((unsigned char)*ptr) != 0)
    ptr++;
  while(*ptr != '\0' && isalnum((unsigned char)*ptr) == 0)
    ptr++;
  if(*ptr == '\0')
    return 0;
  street = ptr;
  if(strlen(street) < 3)
    return 0;

  if((iface->flags & SC_IFACE_FLAG_IP_HEX) != 0)
    {
      ip[0] = iface->ip_s;
      ip[1] = iface->ip_e;
      if(pt_overlap(code, 2, ip, 2) != 0)
	return 0;
    }

  for(i=0; i<geohint_facc; i++)
    {
      hint = geohint_facs[i];
      if(hint->street == NULL ||
	 isdigit((unsigned char)hint->street[0]) == 0 ||
	 string_tolong(hint->street, &hint_no) != 0 || in_no != hint_no ||
	 sc_geohint_checkrtt(hint, iface->rtr) == 0)
	continue;

      /* skip over street number and then spaces after it */
      ptr = hint->street;
      while(isdigit((unsigned char)*ptr) != 0)
	ptr++;
      while(*ptr != '\0' && isalnum((unsigned char)*ptr) == 0)
	ptr++;
      if(*ptr == '\0')
	continue;

      /* if the street name is numeric (8th Ave) then convert to Eighth Ave */
      if(sc_geohint_street_tostr(ptr, buf, sizeof(buf)) != 0)
	continue;

      if(sc_geohint_abbrv(buf, street, offs, strlen(street),
			  sc_geohint_fudge_fac_ok) != 0)
	{
	  fac = hint;
	  break;
	}
    }

  if(fac == NULL)
    return 0;

  /* allocate a new geohint, and add it to the domain's list of geocodes */
  sc_domain_lock(ifd->dom);
  locked = 1;
  for(i=0; i<ifd->dom->geohintc; i++)
    {
      hint = ifd->dom->geohints[i];
      if(strcasecmp(hint->code, str) == 0)
	break;
    }
  if(i == ifd->dom->geohintc)
    {
      if((newhint = sc_geohint_alloc(GEOHINT_TYPE_FACILITY, str, fac->place,
				     fac->st, fac->cc, fac->lat,
				     fac->lng, fac->popn)) == NULL ||
	 (newhint->street = strdup(fac->street)) == NULL ||
	 realloc_wrap((void **)&ifd->dom->geohints,
		      sizeof(sc_geohint_t *) * (ifd->dom->geohintc+1)) != 0)
	{
	  fprintf(stderr, "%s: could not alloc facility %s\n", __func__, str);
	  goto done;
	}
      newhint->learned = 1;
      ifd->dom->geohints[ifd->dom->geohintc++] = newhint;
      hint = newhint; newhint = NULL;
      sc_geohint_sort(ifd->dom->geohints, ifd->dom->geohintc);
    }
  else
    {
      hint = ifd->dom->geohints[i];
    }
  sc_domain_unlock(ifd->dom); locked = 0;

  /* add a tag to the interface */
  if((tag = sc_iface_geo_alloctag(ptrc_list, ifd, hint, code, 1)) == NULL)
    goto done;
  if(slist_tail_push(list, tag) == NULL)
    goto done;

  if(do_debug != 0 && threadc <= 1)
    sc_iface_geo_find_print(ifd, str, tag);

  rc = 1;

 done:
  if(newhint != NULL) sc_geohint_free(newhint);
  if(locked != 0) sc_domain_unlock(ifd->dom);
  return rc;
}

static int sc_iface_geo_find_check(slist_t *list, const sc_ifacedom_t *ifd,
				   char *str, size_t *code, size_t codec,
				   uint8_t type, slist_t *ptrc_list)
{
  sc_iface_t *iface = ifd->iface;
  sc_geohint_t *hint, fm;
  sc_geotag_t *tag = NULL, *place = NULL;
  size_t ip[2];
  int rc = -1;

  if((iface->flags & SC_IFACE_FLAG_IP_HEX) != 0)
    {
      ip[0] = iface->ip_s;
      ip[1] = iface->ip_e;
      if(pt_overlap(code, codec * 2, ip, 2) != 0)
	return 0;
    }

  /* check the global geohint array */
  fm.code = str;
  if((hint = array_find((void **)geohints, geohintc, (void *)&fm,
			(array_cmp_t)sc_geohint_cmp)) == NULL)
    return 0;

  for(hint = hint->head; hint != NULL; hint = hint->next)
    {
      if(strcmp(str, hint->code) != 0)
	break;
      if((type != 0 && hint->type != type) ||
	 sc_geohint_checkrtt(hint, iface->rtr) == 0)
	continue;

      if((tag=sc_iface_geo_alloctag(ptrc_list, ifd, hint, code, codec)) == NULL)
	goto done;

      if(hint->type != GEOHINT_TYPE_PLACE)
	{
	  if(do_debug != 0 && threadc <= 1)
	    sc_iface_geo_find_print(ifd, str, tag);
	  if(slist_tail_push(list, tag) == NULL)
	    goto done;
	}
      else
	{
	  if(place != NULL)
	    {
	      if(sc_geotag_place_cmp(place, tag) > 0)
		{
		  sc_geotag_free(place);
		  place = tag;
		}
	      else sc_geotag_free(tag);
	    }
	  else place = tag;
	}

      tag = NULL;
    }

  if(place != NULL)
    {
      if(do_debug != 0 && threadc <= 1)
	sc_iface_geo_find_print(ifd, str, place);
      if(slist_tail_push(list, place) == NULL)
	goto done;
      place = NULL;
    }

  rc = 1;

 done:
  if(tag != NULL) sc_geotag_free(tag);
  if(place != NULL) sc_geotag_free(place);
  return rc;
}

/*
 * sc_iface_geo_find_thread
 *
 * Looks for geocodes within an interface label and puts the start and
 * end indexes into an array.
 */
static void sc_iface_geo_find_thread(sc_ifacedom_t *ifd)
{
  sc_iface_t *iface = ifd->iface;
  slist_t *list = NULL, *ptrc_list = NULL;
  slist_node_t *sn, *s2;
  sc_ptrc_t *ptrc = NULL, *a, *b, *x, *y;
  sc_geotag_t *tag = NULL;
  size_t i = 0, j = 0, start, gc[4];
  int stop = 0;
  uint8_t geotype;
  char buf[32];

  if((list = slist_alloc()) == NULL || (ptrc_list = slist_alloc()) == NULL)
    goto done;

  /* skip over any non-alnum characters */
  while(ifd->label[i] != '\0' && isalpha((unsigned char)ifd->label[i]) == 0)
   i++;
  if(ifd->label[i] == '\0')
    goto done;

  start = j = i;
  for(;;)
    {
      while(isalpha((unsigned char)ifd->label[j]) != 0)
	j++;
      if(ifd->label[j] == '\0')
	stop = 1;

      assert(j >= i);
      if((ptrc = malloc(sizeof(sc_ptrc_t))) == NULL)
	goto done;
      ptrc->ptr = ifd->label+i;
      ptrc->c = j - i;
      if(slist_tail_push(ptrc_list, ptrc) == NULL)
	goto done;
      ptrc = NULL;

      if(stop != 0)
	break;
      j++;
      while(ifd->label[j] != '\0')
	{
	  if(isalpha((unsigned char)ifd->label[j]) != 0)
	    break;
	  j++;
	}
      if(ifd->label[j] == '\0')
	break;
      i = j;
    }

  for(sn=slist_head_node(ptrc_list); sn != NULL; sn=slist_node_next(sn))
    {
      a = slist_node_item(sn);
      if(a->c + 1 >= sizeof(buf) || a->c < 3)
	continue;

      memcpy(buf, a->ptr, a->c);
      buf[a->c] = '\0';
      gc[0] = (char *)a->ptr - ifd->label;
      gc[1] = gc[0] + a->c - 1;
      if(sc_iface_geo_find_check(list, ifd, buf, gc, 1, 0, ptrc_list) < 0)
	goto done;

      /* check for a CLLI code split into 4+2 */
      if((s2 = slist_node_next(sn)) != NULL)
	b = slist_node_item(s2);
      else
	b = NULL;
      if(a->c == 4 && b != NULL && b->c == 2)
	{
	  memcpy(buf+4, b->ptr, b->c);
	  buf[6] = '\0';
	  gc[2] = (char *)b->ptr - ifd->label;
	  gc[3] = gc[2] + b->c - 1;
	  geotype = GEOHINT_TYPE_CLLI;
	  if(sc_iface_geo_find_check(list, ifd, buf, gc, 2, geotype,
				     ptrc_list) < 0)
	    goto done;
	}

      /* check for CLLI codes with more than six letters embedded */
      if(a->c > 6)
	{
	  memcpy(buf, a->ptr, 6);
	  buf[6] = '\0';
	  gc[0] = (char *)a->ptr - ifd->label;
	  gc[1] = gc[0] + 5;
	  geotype = GEOHINT_TYPE_CLLI;
	  if(sc_iface_geo_find_check(list, ifd, buf, gc, 1, geotype,
				     ptrc_list) < 0)
	    goto done;
	}

      /* check for a placename split with punctuation */
      if(a->c >= 2 && b != NULL && b->c >= 2 && (a->c + b->c) >= 6 &&
	 sizeof(buf) > (a->c + b->c + 1))
	{
	  memcpy(buf, a->ptr, a->c);
	  memcpy(buf+a->c, b->ptr, b->c);
	  buf[a->c+b->c] = '\0';
	  gc[0] = (char *)a->ptr - ifd->label;
	  gc[1] = (((char *)b->ptr) + b->c - 1) - ifd->label;
	  geotype = GEOHINT_TYPE_PLACE;
	  if(sc_iface_geo_find_check(list, ifd, buf, gc, 1, geotype,
				     ptrc_list) < 0)
	    goto done;
	}

      /* check for a LOCODE code split into 3+2 */
      if(do_splitlocode != 0 && a->c == 3)
	{
	  memcpy(buf+2, a->ptr, a->c); buf[5] = '\0';
	  for(s2=slist_head_node(ptrc_list); s2 != NULL; s2=slist_node_next(s2))
	    {
	      b = slist_node_item(s2);
	      if(b->c != 2)
		continue;
	      memcpy(buf, b->ptr, b->c);

	      if(a->ptr < b->ptr) {
		x = a; y = b;
	      } else {
		x = b; y = a;
	      }

	      gc[0] = (char *)x->ptr - ifd->label;
	      gc[1] = gc[0] + x->c - 1;
	      gc[2] = (char *)y->ptr - ifd->label;
	      gc[3] = gc[2] + y->c - 1;
	      geotype = GEOHINT_TYPE_LOCODE;
	      if(sc_iface_geo_find_check(list, ifd, buf, gc, 2, geotype,
					 ptrc_list) < 0)
		goto done;
	    }
	}
    }

  i = j = start;
  for(;;)
    {
      /* look for a sequence that starts with digits, and then alpha */
      if(isdigit((unsigned char)ifd->label[j]) == 0)
	goto next;
      j++;
      while(isdigit((unsigned char)ifd->label[j]) != 0)
	j++;
      if(isalpha((unsigned char)ifd->label[j]) == 0)
	goto next;
      j++;
      while(isalpha((unsigned char)ifd->label[j]) != 0)
	j++;

      assert(j <= ifd->len);
      assert(j >= i);
      if(j-i >= sizeof(buf))
	goto next;

      memcpy(buf, ifd->label+i, j-i);
      buf[j-i] = '\0';
      if(sc_iface_geo_find_fac(list, ifd, buf, i, j-1, ptrc_list) < 0)
	goto done;

      /* skip until the next punctuation-delimited sequence */
    next:
      while(isalnum((unsigned char)ifd->label[j]) != 0)
	j++;
      if(ifd->label[j] == '\0')
	break;
      while(ifd->label[j] != '\0' && isalnum((unsigned char)ifd->label[j]) == 0)
	j++;
      if(ifd->label[j] == '\0')
	break;
      i = j;
    }

  if((iface->geoc = slist_count(list)) == 0 ||
     (iface->geos = malloc_zero(iface->geoc * sizeof(sc_geotag_t))) == NULL)
    goto done;
  i = 0;
  while((tag = slist_head_pop(list)) != NULL)
    {
      iface->geos[i].hint = tag->hint; tag->hint = NULL;
      iface->geos[i].tags = tag->tags; tag->tags = NULL;
      iface->geos[i].tagc = tag->tagc; tag->tagc = 0;
      sc_geotag_free(tag); tag = NULL;
      i++;
    }

 done:
  if(ptrc_list != NULL) slist_free_cb(ptrc_list, (slist_free_t)free);
  if(list != NULL) slist_free_cb(list, (slist_free_t)sc_geotag_free);
  if(tag != NULL) sc_geotag_free(tag);
  return;
}

static void sc_ifdptr_free(sc_ifdptr_t *ifp)
{
  free(ifp);
  return;
}

static int sc_ifdptr_cmp(const sc_ifdptr_t *a, const sc_ifdptr_t *b)
{
  if(a->ifd < b->ifd) return -1;
  if(a->ifd > b->ifd) return  1;
  return 0;
}

static sc_ifdptr_t *sc_ifdptr_find(splaytree_t *tree, sc_ifacedom_t *ifd)
{
  sc_ifdptr_t fm; fm.ifd = ifd;
  return splaytree_find(tree, &fm);
}

static sc_ifdptr_t *sc_ifdptr_get(splaytree_t *tree, sc_ifacedom_t *ifd)
{
  sc_ifdptr_t *ifp;
  if((ifp = sc_ifdptr_find(tree, ifd)) != NULL)
    return ifp;
  if((ifp = malloc_zero(sizeof(sc_ifdptr_t))) == NULL)
    return NULL;
  ifp->ifd = ifd;
  ifp->ptr = NULL;
  if(splaytree_insert(tree, ifp) == NULL)
    {
      free(ifp);
      return NULL;
    }
  return ifp;
}

/*
 * sc_ifdptr_tree
 *
 * build a tree that can map each interface in a set of routers to
 * some other object.
 */
static splaytree_t *sc_ifdptr_tree(const slist_t *routers)
{
  splaytree_t *ifp_tree = NULL;
  slist_node_t *sn;
  sc_routerdom_t *rd;
  int i;

  if((ifp_tree = splaytree_alloc((splaytree_cmp_t)sc_ifdptr_cmp)) == NULL)
    goto err;

  for(sn=slist_head_node(routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	if(sc_ifdptr_get(ifp_tree, rd->ifaces[i]) == NULL)
	  goto err;
    }

  return ifp_tree;

 err:
  if(ifp_tree != NULL) splaytree_free(ifp_tree, (splaytree_free_t)sc_ifdptr_free);
  return NULL;
}

/*
 * sc_ifdptr_tree_ri
 *
 * given a tree filled with ifp constructed from a set of routers, attach
 * the inferred router interfaces to each ifp.
 */
static int sc_ifdptr_tree_ri(splaytree_t *ifp_tree, const slist_t *ri_list)
{
  slist_node_t *sn;
  sc_routerinf_t *ri;
  sc_ifdptr_t *ifp;
  size_t i;

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      for(i=0; i<ri->ifacec; i++)
	{
	  if((ifp=sc_ifdptr_find(ifp_tree, ri->ifaces[i]->ifd)) == NULL)
	    return -1;
	  ifp->ptr = ri->ifaces[i];
	}
    }

  return 0;
}

/*
 * sc_ifdptr_tree_ri
 *
 * given a tree filled with ifp constructed from a set of routers, attach
 * the inferred router interfaces to each ifp.
 */
static int sc_ifdptr_tree_ifi(splaytree_t *ifp_tree, const slist_t *ifi_list)
{
  slist_node_t *sn;
  sc_ifaceinf_t *ifi;
  sc_ifdptr_t *ifp;

  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if((ifp=sc_ifdptr_find(ifp_tree, ifi->ifd)) == NULL)
	return -1;
      ifp->ptr = ifi;
    }

  return 0;
}

static int sc_routercss_cmp(const sc_routercss_t *a, const sc_routercss_t *b)
{
  int rc;

  if(a->css != NULL && b->css != NULL)
    {
      if((rc = sc_css_css_cmp(a->css, b->css)) != 0)
	return rc;
      if(a->css->count > b->css->count) return -1;
      if(a->css->count < b->css->count) return  1;
    }
  else if(a->css != NULL && b->css == NULL)
    return -1;
  else if(a->css == NULL && b->css != NULL)
    return 1;

  if(a->rd->ifacec > b->rd->ifacec) return -1;
  if(a->rd->ifacec < b->rd->ifacec) return  1;
  return scamper_addr_human_cmp(a->rd->ifaces[0]->iface->addr,
				b->rd->ifaces[0]->iface->addr);
}

static int sc_routercss_rd_cmp(const sc_routercss_t *a, const sc_routercss_t *b)
{
  return ptrcmp(a->rd, b->rd);
}

static sc_routercss_t *sc_routercss_rd_find(splaytree_t *tr,sc_routerdom_t *rd)
{
  sc_routercss_t fm; fm.rd = rd;
  return splaytree_find(tr, &fm);
}

static void sc_routercss_free(sc_routercss_t *rcss)
{
  if(rcss->css != NULL) sc_css_free(rcss->css);
  free(rcss);
  return;
}

static int sc_routercss_geo_rd(splaytree_t *rcss_tree, sc_routerdom_t *rd,
			       splaytree_t *css_tree)
{
  sc_routercss_t *rcss = NULL;
  slist_t *list = NULL;
  sc_css_t *css;
  int rc = -1;

  if(splaytree_count(css_tree) == 0)
    return 0;

  if((list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(css_tree, tree_to_slist, list);
  slist_qsort(list, (slist_cmp_t)sc_css_count_cmp);
  css = slist_head_item(list);

  if((rcss = malloc_zero(sizeof(sc_routercss_t))) == NULL ||
     (rcss->css = sc_css_dup(css)) == NULL)
    goto done;
  rcss->matchc = css->count;
  rcss->rd = rd;

  if(splaytree_insert(rcss_tree, rcss) == NULL)
    goto done;
  rcss = NULL;
  rc = 0;

 done:
  if(rcss != NULL) sc_routercss_free(rcss);
  if(list != NULL) slist_free(list);
  return rc;
}

static splaytree_t *sc_routercss_geo(slist_t *ifi_list)
{
  sc_routerdom_t *rd = NULL;
  splaytree_t *rcss_tree = NULL, *css_tree = NULL;
  sc_ifaceinf_t *ifi;
  slist_node_t *sn;
  sc_css_t *fm;

  /* eval the regex on all interfaces to get name frequency */
  if((css_tree=splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL ||
     (rcss_tree=splaytree_alloc((splaytree_cmp_t)sc_routercss_rd_cmp)) == NULL)
    goto err;

  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if(ifi->class != '+')
	continue;

      if(ifi->ifd->rd != rd)
	{
	  if(sc_routercss_geo_rd(rcss_tree, rd, css_tree) != 0)
	    goto err;
	  splaytree_empty(css_tree, (splaytree_free_t)sc_css_free);
	  rd = ifi->ifd->rd;
	}

      if((fm = sc_css_get(css_tree, ifi->css)) == NULL)
	goto err;
      fm->count++;
    }

  if(sc_routercss_geo_rd(rcss_tree, rd, css_tree) != 0)
    goto err;

  splaytree_free(css_tree, (splaytree_free_t)sc_css_free); css_tree = NULL;
  return rcss_tree;

 err:
  if(css_tree != NULL)
    splaytree_free(css_tree, (splaytree_free_t)sc_css_free);
  if(rcss_tree != NULL)
    splaytree_free(rcss_tree, (splaytree_free_t)sc_routercss_free);
  return NULL;
}

/*
 * sc_routercss_alias
 *
 * figure out the likely router name given the regex
 */
static sc_routercss_t *sc_routercss_alias(sc_routerdom_t *rd, sc_rework_t *rew)
{
  sc_css_t *css = NULL, *fm, *css2[2];
  sc_routercss_t *rcss = NULL;
  splaytree_t *tree = NULL;
  slist_t *list = NULL;
  slist_node_t *sn;
  sc_iface_t *iface;
  int i, x, rc = -1, ip = 0;

  if((rcss = malloc_zero(sizeof(sc_routercss_t))) == NULL)
    goto done;
  rcss->rd = rd;

  /* eval the regex on all interfaces to get name frequency */
  if((tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
    goto done;

  for(i=0; i<rd->ifacec; i++)
    {
      iface = rd->ifaces[i]->iface;
      if((x = sc_rework_match(rew, iface, &css)) < 0)
	goto done;
      if(x == 0 || css == NULL)
	continue;
      if(sc_iface_ip_matched(iface, rew) != 0)
	{
	  ip++;
	}
      else
	{
	  if((fm = sc_css_get(tree, css)) == NULL)
	    goto done;
	  fm->count++;
	}
      sc_css_free(css); css = NULL;
    }

  if(splaytree_count(tree) > 0)
    {
      if((list = slist_alloc()) == NULL)
	goto done;
      splaytree_inorder(tree, tree_to_slist, list);
      slist_qsort(list, (slist_cmp_t)sc_css_count_cmp);

      sn = slist_head_node(list);
      for(i=0; i<2; i++)
	{
	  css2[i] = sn != NULL ? slist_node_item(sn) : NULL;
	  sn = sn != NULL ? slist_node_next(sn) : NULL;
	}
      slist_free(list); list = NULL;

      assert(css2[0] != NULL);
      rcss->matchc = css2[0]->count;
      if(css2[0] != NULL &&
	 (css2[1] == NULL || css2[0]->count > css2[1]->count) &&
	 (rcss->css = sc_css_dup(css2[0])) == NULL)
	goto done;
    }
  else rcss->matchc = ip;

  rc = 0;

 done:
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)sc_css_free);
  if(list != NULL) slist_free(list);
  if(rc != 0)
    {
      if(rcss != NULL) sc_routercss_free(rcss);
      return NULL;
    }
  return rcss;
}

static void sc_routercsss_free(sc_routercss_t **rcsss, int rcssc)
{
  int i;
  for(i=0; i<rcssc; i++)
    if(rcsss[i] != NULL)
      sc_routercss_free(rcsss[i]);
  free(rcsss);
  return;
}

static sc_routercss_t **sc_routercss_alias_alloc(slist_t *rs, sc_rework_t *rew)
{
  sc_routercss_t **rnames = NULL, *rn;
  sc_routerdom_t *rd;
  slist_node_t *sn;
  size_t rnamec;
  int i;

  if((i = slist_count(rs)) <= 0)
    return NULL;
  rnamec = (size_t)i;

  if((rnames = malloc_zero(sizeof(sc_routercss_t *) * rnamec)) == NULL)
    return NULL;
  i = 0;
  for(sn=slist_head_node(rs); sn != NULL; sn = slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      if((rn = sc_routercss_alias(rd, rew)) == NULL)
	goto err;
      rnames[i++] = rn;
    }
  array_qsort((void **)rnames, rnamec, (array_cmp_t)sc_routercss_cmp);
  return rnames;

 err:
  if(rnames != NULL) sc_routercsss_free(rnames, rnamec);
  return NULL;
}

static int sc_ifacedom_css(const sc_ifacedom_t *ifd, sc_css_t **out, int trim)
{
  sc_css_t *css = NULL;
  size_t len = strlen(ifd->label);
  size_t off = 0;
  size_t ip_s, ip_e;

  *out = NULL;

  /* if there is no IP address portion within, then copy whole string in */
  if((ifd->iface->flags & SC_IFACE_FLAG_IP) == 0)
    {
      if((css = sc_css_alloc(len+1)) == NULL)
	goto err;
      memcpy(css->css, ifd->label, len+1);
      css->len = len + 1;
      css->cssc = 1;
      *out = css;
      return 0;
    }

  if((css = sc_css_alloc0()) == NULL)
    goto err;

  /*
   * allocate a common substring structure to store the entire label
   * without the IP address portion
   */
  assert(ifd->iface->ip_s >= 0);
  assert(ifd->iface->ip_e >= ifd->iface->ip_s);
  ip_s = ifd->iface->ip_s;
  ip_e = ifd->iface->ip_e;
  if(trim != 0)
    {
      while(ip_s > 0 && isalnum((unsigned char)ifd->label[ip_s-1]) == 0)
	ip_s--;
      while(ifd->label[ip_e] != '\0' &&
	    isalnum((unsigned char)ifd->label[ip_e+1]) == 0)
	ip_e++;
    }
  if(ip_s > 0)
    {
      css->len = ip_s + 1;
      css->cssc++;
    }
  if(ip_e + 1 < len)
    {
      css->len += len - ip_e;
      css->cssc++;
    }

  if(css->cssc == 0)
    {
      sc_css_free(css);
      return 0;
    }
  assert(len > 0);

  if((css->css = malloc(css->len)) == NULL)
    goto err;

  /* copy in the substrings */
  if(ip_s > 0)
    {
      memcpy(css->css+off, ifd->label, ip_s);
      off += ip_s;
      css->css[off++] = '\0';
    }
  if(ip_e + 1 < len)
    {
      memcpy(css->css+off, ifd->label + ip_e + 1, len - ip_e - 1);
      off += len - ip_e - 1;
      css->css[off++] = '\0';
    }

  *out = css;
  return 0;

 err:
  if(css != NULL) sc_css_free(css);
  return -1;
}

static void sc_ifacedom_free(sc_ifacedom_t *ifd)
{
  if(ifd->label != NULL) free(ifd->label);
  free(ifd);
  return;
}

static sc_ifacedom_t *sc_ifacedom_alloc(const sc_iface_t *iface,
					const sc_domain_t *dom,
					const char *suffix)
{
  sc_ifacedom_t *ifd = NULL;
  size_t len = suffix - iface->name;
  if((ifd = malloc_zero(sizeof(sc_ifacedom_t))) == NULL ||
     (ifd->label = malloc(len)) == NULL)
    goto err;
  memcpy(ifd->label, iface->name, len-1);
  ifd->label[len-1] = '\0';
  ifd->len = len-1;
  ifd->iface = (sc_iface_t *)iface;
  ifd->dom = (sc_domain_t *)dom;
  return ifd;

 err:
  if(ifd != NULL) sc_ifacedom_free(ifd);
  return NULL;
}

static int sc_routerinf_ifaces_null(sc_routerinf_t *ri, void *param)
{
  if(ri == NULL)
    return 0;
  if(ri->ifaces != NULL)
    free(ri->ifaces);
  ri->ifaces = NULL;
  ri->ifacec = 0;
  return 0;
}

static int sc_routerinf_maxrtrc_cmp(const sc_routerinf_t *a,
				    const sc_routerinf_t *b)
{
  if(a->ip == 0 && b->ip == 1) return -1;
  if(a->ip == 1 && b->ip == 0) return  1;
  if(a->maxrtrc > b->maxrtrc) return -1;
  if(a->maxrtrc < b->maxrtrc) return  1;
  return 0;
}

static void sc_routerinf_free(sc_routerinf_t *ri)
{
  size_t i;
  if(ri->ifaces != NULL)
    {
      for(i=0; i<ri->ifacec; i++)
	if(ri->ifaces[i] != NULL)
	  sc_ifaceinf_free(ri->ifaces[i]);
      free(ri->ifaces);
    }
  free(ri);
  return;
}

/*
 * sc_routerinf_finish
 *
 * we built an inferred router using extractions from regular
 * expressions.  cluster interfaces from the same training router
 * together, and sort the interfaces in order of the number of
 * interfaces from the same training router.
 */
static int sc_routerinf_finish(sc_routerinf_t *ri)
{
  size_t i, x, c, ip, no_ip;
  sc_routerdom_t *rd;

  /*
   * count the number of interfaces from the same training routers are
   * represented in the inferred router.  tag each interface on the
   * inferred router with how many interfaces from the same training
   * router are included in the inferred router.
   */
  array_qsort((void **)ri->ifaces, ri->ifacec,
	      (array_cmp_t)sc_ifaceinf_ifd_rd_cmp);
  x = 0; rd = ri->ifaces[x]->ifd->rd;
  for(i=1; i<ri->ifacec; i++)
    {
      if(ri->ifaces[i]->ifd->rd != rd)
	{
	  assert(i >= x);
	  c = i - x;
	  while(x != i)
	    ri->ifaces[x++]->rtrc = c;
	  x = i; rd = ri->ifaces[x]->ifd->rd;
	}
    }
  assert(ri->ifacec >= x);
  c = ri->ifacec - x;
  while(x != ri->ifacec)
    ri->ifaces[x++]->rtrc = c;

  /*
   * sort the interfaces on the inferred router into clusters of
   * interfaces from the same training router, in order by the number
   * of interfaces from the same training router that are present
   */
  array_qsort((void **)ri->ifaces, ri->ifacec,
	      (array_cmp_t)sc_ifaceinf_rtrc_cmp);
  ri->maxrtrc = ri->ifaces[0]->rtrc;

  /*
   * for the interfaces from the first training router that match,
   * determine if all interfaces contain an IP address literal as part
   * of the extraction.  mark the router accordingly.
   */
  no_ip = 0; ip = 0;
  for(i=0; i<ri->ifaces[0]->rtrc; i++)
    {
      if(ri->ifaces[i]->ipm == 0)
	{
	  no_ip++;
	  break;
	}
      else ip++;
    }
  if(ip > 0 && no_ip == 0)
    ri->ip = 1;

  return 0;
}

/*
 * computing the Rand index according to
 *
 * "An Introduction to Information Retrieval"
 *
 * A true positive (TP) decision assigns two similar documents to the
 * same cluster, a true negative (TN) decision assigns two dissimilar
 * documents to different clusters. There are two types of errors we
 * can commit. A false positive (FP) decision assigns two dissimilar
 * documents to the same cluster. A false negative (FN) decision
 * assigns two similar documents to different clusters. The Rand index
 * (RI) measures the percentage of decisions that are correct.
 */
static double randindex(slist_t *ifp_list)
{
  slist_node_t *sn, *sn2;
  sc_ifdptr_t *ifp, *ifp2;
  sc_ifaceinf_t *ifi, *ifi2;
  uint32_t tp = 0, fp = 0, tn = 0, fn = 0;

  for(sn=slist_head_node(ifp_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifp = slist_node_item(sn);
      if(ifp->ptr == NULL)
	continue;
      ifi = ifp->ptr;

      assert(ifi->ri != NULL);
      for(sn2=slist_node_next(sn); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  ifp2 = slist_node_item(sn2);
	  if(ifp2->ptr == NULL)
	    continue;
	  ifi2 = ifp2->ptr;
	  assert(ifi2->ri != NULL);

	  if(ifp->ifd->iface->rtr == ifp2->ifd->iface->rtr)
	    {
	      if(ifi->ri == ifi2->ri)
		tp++;
	      else
		fn++;
	    }
	  else
	    {
	      if(ifi->ri == ifi2->ri)
		fp++;
	      else
		tn++;
	    }
	}
    }

  return ((double)((tp + tn) * 100)) / (tp + fp + fn + tn);
}

/*
 * sc_regex_alias_ri_build
 *
 * given a set of inferences on router interfaces, build routers
 */
static int sc_regex_alias_ri_build(slist_t *ifi_list_in, slist_t *ri_list_out)
{
  sc_ifaceinf_t *ifi = NULL;
  sc_routerinf_t *ri = NULL;
  slist_t *ifi_list = NULL, *ri_list = NULL;
  slist_node_t *sn;
  int rc = -1;
  size_t i;

  if((ifi_list = slist_dup(ifi_list_in, NULL, NULL)) == NULL)
    goto done;
  if((ri_list = slist_alloc()) == NULL)
    goto done;

  slist_qsort(ifi_list, (slist_cmp_t)sc_ifaceinf_inf_cmp);
  while((ifi = slist_head_pop(ifi_list)) != NULL)
    {
      i = 1;
      if(ifi->css != NULL)
	{
	  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
	    {
	      if(sc_ifaceinf_inf_cmp(ifi, slist_node_item(sn)) != 0)
		break;
	      i++;
	    }
	}

      if((ri = malloc_zero(sizeof(sc_routerinf_t))) == NULL ||
	 (ri->ifaces = malloc_zero(sizeof(sc_ifaceinf_t *) * i)) == NULL)
	goto done;
      ri->ifacec = i;
      ri->maxrtrc = 0;
      ri->ip = 0;
      ri->ifaces[0] = ifi; ifi->ri = ri;
      for(i=1; i<ri->ifacec; i++)
	{
	  ri->ifaces[i] = slist_head_pop(ifi_list);
	  ri->ifaces[i]->ri = ri;
	}
      if(sc_routerinf_finish(ri) != 0)
	goto done;

      /* add router to the list of inferred routers */
      if(slist_tail_push(ri_list, ri) == NULL)
	goto done;
      ri = NULL;
    }
  rc = 0;
  slist_concat(ri_list_out, ri_list);

 done:
  if(ri != NULL)
    {
      if(ri->ifaces != NULL) free(ri->ifaces);
      free(ri);
    }
  if(ri_list != NULL)
    {
      while((ri = slist_head_pop(ri_list)) != NULL)
	{
	  free(ri->ifaces);
	  free(ri);
	}
      slist_free(ri_list);
    }
  if(ifi_list != NULL) slist_free(ifi_list);
  return rc;
}

/*
 * sc_regex_ifi_build2
 *
 * given two sets of inferences on router interfaces, build a set of
 * inferences according the priority (p) of inferences in ifi1 and
 * ifi2.
 */
static int sc_regex_ifi_build2(slist_t *ifi1_list, slist_t *ifi2_list,
			       int p, slist_t *ifi_list_out)
{
  slist_t *ifi_list = NULL;
  slist_node_t *sn1, *sn2;
  sc_ifaceinf_t *ifi1, *ifi2;
  int x, rc = -1;

  sn1 = slist_head_node(ifi1_list);
  sn2 = slist_head_node(ifi2_list);
  if((ifi_list = slist_alloc()) == NULL)
    goto done;

  while(sn1 != NULL)
    {
      ifi1 = slist_node_item(sn1); sn1 = slist_node_next(sn1);
      ifi2 = slist_node_item(sn2); sn2 = slist_node_next(sn2);
      assert(ifi1->ifd == ifi2->ifd);

      if(ifi2->regex != -1 && (ifi1->regex >= p || ifi1->regex == -1))
	{
	  /* handle the case where ifi2 supersedes ifi1 */
	  if(sc_ifaceinf_get(ifi_list,ifi2->ifd,ifi2->css,ifi2->ipm,p) == NULL)
	    goto done;
	}
      else if(ifi1->regex != -1)
	{
	  /* adjust the regex id if necessary */
	  x = ifi1->regex >= p ? ifi1->regex + 1 : ifi1->regex;
	  if(sc_ifaceinf_get(ifi_list,ifi1->ifd,ifi1->css,ifi1->ipm,x) == NULL)
	    goto done;
	}
      else
	{
	  if(sc_ifaceinf_get(ifi_list, ifi1->ifd, NULL, 0, -1) == NULL)
	    goto done;
	}
    }
  assert(sn2 == NULL);
  rc = 0;
  slist_concat(ifi_list_out, ifi_list);

 done:
  if(ifi_list != NULL)
    {
      slist_foreach(ifi_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
    }
  return rc;
}

/*
 * sc_regex_ifi_build
 *
 * Return 0 iff assignments for each interface could be evaluated and
 * added to ifi_list_out.
 * ifi_list_out will be an slist_t of sc_ifaceinf_t (although the
 * length could be 0).
 */
static int sc_regex_ifi_build(sc_regex_t *re, slist_t *ifi_list_out)
{
  sc_routerdom_t *rd;
  slist_node_t *sn;
  int i, x, rc = -1, ip;
  sc_ifacedom_t *ifd;
  sc_css_t *css = NULL;
  slist_t *ifi_list = NULL;
  sc_rework_t *rew = NULL;

  if((ifi_list = slist_alloc()) == NULL ||
     (rew = sc_rework_alloc(re)) == NULL)
    goto done;

  for(i=0; i<re->regexc; i++)
    {
      if((x = sc_rework_capcount(rew, i)) < 0)
	goto done;
      re->regexes[i]->capc = (uint32_t)x;
    }

  /* go through all the interfaces and determine router assignments */
  for(sn=slist_head_node(re->dom->routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	{
	  ifd = rd->ifaces[i];
	  if((x = sc_rework_match(rew, ifd->iface, &css)) < 0)
	    goto done;

	  ip = 0;
	  if(x == 1)
	    {
	      if(css != NULL)
		ip = sc_iface_ip_matched(ifd->iface, rew);
	      if(sc_ifaceinf_get(ifi_list, ifd, css, ip, rew->k) == NULL)
		goto done;
	      css = NULL;
	    }
	  else
	    {
	      if(sc_ifaceinf_get(ifi_list, ifd, NULL, ip, -1) == NULL)
		goto done;
	    }
	}
    }

  slist_concat(ifi_list_out, ifi_list);
  rc = 0;

 done:
  if(rew != NULL) sc_rework_free(rew);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  return rc;
}

/*
 * sc_regex_ifi_thin
 *
 * go through candidate interface inferences and remove any that are
 * identical to what the current working regex has.
 *
 * return the count of extractions made by cand_l at the end of the
 * thin process
 */
static int sc_regex_ifi_thin(slist_t *ifi_work_l, slist_t *ifi_cand_l)
{
  slist_node_t *sn_work, *sn_cand;
  sc_ifaceinf_t *ifi_work, *ifi_cand;
  int c = 0;

  sn_cand = slist_head_node(ifi_cand_l);
  sn_work = slist_head_node(ifi_work_l);

  while(sn_cand != NULL)
    {
      ifi_work = slist_node_item(sn_work);
      ifi_cand = slist_node_item(sn_cand);

      assert(ifi_work->ifd == ifi_cand->ifd);

      /*
       * if the css is the same across regexes, clear out the
       * inference from cand_ifi so that it doesn't get counted as a
       * contribution from the candidate regex (the working regex
       * already had it covered)
       */
      if(ifi_cand->css != NULL && ifi_work->css != NULL &&
	 sc_css_css_cmp(ifi_cand->css, ifi_work->css) == 0)
	{
	  sc_css_free(ifi_cand->css); ifi_cand->css = NULL;
	  ifi_cand->ipm = 0;
	  ifi_cand->regex = -1;
	}

      if(ifi_cand->css != NULL)
	c++;

      sn_work = slist_node_next(sn_work);
      sn_cand = slist_node_next(sn_cand);
    }

  return c;
}

/*
 * sc_regex_alias_ri_sp
 *
 * the evaluation put a single interface of a router in its own
 * cluster.  is that a single positive or a false negative?  single
 * positive occurs on a multiple interface training router when other
 * interfaces from that training router are intentionally skipped, or
 * an IP address is matched.
 */
static int sc_regex_alias_ri_sp(sc_ifaceinf_t **ifimap, sc_routerdom_t *rd)
{
  int i, matchc = 0;
  sc_ifaceinf_t *ifi;

  if(rd->ifacec == 1)
    return 1;

  for(i=0; i<rd->ifacec; i++)
    {
      ifi = ifimap[rd->ifaces[i]->id-1];

      /*
       * there was another interface in the suffix on the router that
       * the regex did not match.  in the end, decide to count the
       * matched interface as a single positive.
       * if(ifi->regex == -1)
       *   return 0;
       */

      /*
       * if the interface was deliberately skipped, or we matched an
       * IP literal, then skip over -- do not count as something that
       * we ideally would have matched
       */
      if(ifi->css == NULL)
	continue;
      if(ifi->ipm != 0)
	continue;
      matchc++;
    }

  if(matchc == 1)
    return 1;
  return 0;
}

static void sc_regex_eval_tp_mask(sc_regex_t *re, sc_ifacedom_t *ifd)
{
  assert(re->dom != NULL);
  assert(re->tp_mask != NULL);
  mask_set(re->tp_mask, re->dom->tpmlen, ifd->id);
  return;
}

/*
 * sc_regex_alias_ri_score
 *
 * evaluate the infererences against the training data, storing results
 * in the regex scores.
 */
static int sc_regex_alias_ri_score(sc_regex_t *re, slist_t *ri_list)
{
  slist_node_t *sn;
  int ppv, tp, i, rc = -1, *remap = NULL;
  sc_routerdom_t *rd;
  sc_routerinf_t *ri = NULL;
  sc_ifaceinf_t **ifimap = NULL;
  uint32_t *rdmap = NULL;
  size_t len, s, x;

  if((remap = malloc(sizeof(int) * re->regexc)) == NULL ||
     (rdmap = malloc_zero(sizeof(uint32_t) * re->dom->rtmlen)) == NULL ||
     (ifimap = malloc(sizeof(sc_ifaceinf_t *) * re->dom->ifacec)) == NULL)
    goto done;

  /* figure out how many bits might be needed for the true positives mask */
  len = sizeof(uint32_t) * re->dom->tpmlen;
  if(re->tp_mask == NULL && (re->tp_mask = malloc_zero(len)) == NULL)
    goto done;

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);

      for(s=0; s<ri->ifacec; s++)
	{
	  /* record how many times each regex was used */
	  if(ri->ifaces[s]->regex >= 0)
	    {
	      assert(ri->ifaces[s]->regex < re->regexc);
	      re->matchc++;
	      re->regexes[ri->ifaces[s]->regex]->matchc++;
	    }

	  /* tag each sc_ifacedom_t with an sc_ifaceinf_t */
	  ifimap[ri->ifaces[s]->ifd->id-1] = ri->ifaces[s];
	}
    }

  slist_qsort(ri_list, (slist_cmp_t)sc_routerinf_maxrtrc_cmp);
  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);

      /* no inferred name for the router */
      if(ri->ifaces[0]->css == NULL)
	{
	  assert(ri->ifacec == 1);

	  if(ri->ifaces[0]->regex != -1)
	    {
	      ri->ifaces[0]->class = '*';
	      continue;
	    }

	  /*
	   * if the regex didn't match but there were no aliases in the
	   * training data, don't count it as a false negative, but don't
	   * count it as a true positive either.
	   */
	  if(ri->ifaces[0]->ifd->rd->ifacec > 1)
	    {
	      re->fnu_c++;
	      ri->ifaces[0]->class = '~';
	    }
	  else
	    {
	      re->sn_c++;
	      ri->ifaces[0]->class = 'o';
	    }
	  continue;
	}

      /* count how many training routers are in this inferred router */
      x = 1; rd=ri->ifaces[0]->ifd->rd;
      for(s=1; s<ri->ifacec; s++)
	{
	  if(ri->ifaces[s]->ifd->rd != rd)
	    {
	      rd = ri->ifaces[s]->ifd->rd;
	      x++;
	    }
	}

      /*
       * already counted this router.
       * if the inferred router only has interfaces from that router,
       * these are false negatives.
       * otherwise, count all as false positives.
       */
      rd = ri->ifaces[0]->ifd->rd;
      if(mask_isset(rdmap, re->dom->rtmlen, rd->id) != 0)
	{
	  for(s=0; s<ri->ifacec; s++)
	    {
	      if(ri->ifaces[s]->ipm != 0)
		{
		  re->ip_c++;
		  ri->ifaces[s]->class = 'x';
		}
	      else if(x == 1)
		{
		  re->fne_c++;
		  ri->ifaces[s]->class = '-';
		}
	      else
		{
		  re->fp_c++;
		  ri->ifaces[s]->class = '!';
		}
	    }
	  continue;
	}

      /* this inferred router is made up a single training router */
      if(x == 1)
	{
	  /* if the inferred router has a single interface */
	  if(ri->ifacec == 1)
	    {
	      /* if the match is on an IP address string */
	      if(ri->ifaces[0]->ipm != 0)
		{
		  re->ip_c++;
		  ri->ifaces[0]->class = 'x';
		}
	      /* if the training router also has a single interface */
	      else if(sc_regex_alias_ri_sp(ifimap,ri->ifaces[0]->ifd->rd)== 1)
		{
		  re->sp_c++;
		  ri->ifaces[0]->class = '+';
		}
	      else
		{
		  re->fne_c++;
		  ri->ifaces[0]->class = '-';
		}
	      continue;
	    }

	  /* mark the router as counted */
	  rd = ri->ifaces[0]->ifd->rd;
	  mask_set(rdmap, re->dom->rtmlen, rd->id);

	  /* true positives! */
	  tp = 0;
	  for(i=0; i<re->regexc; i++)
	    remap[i] = 0;
	  for(s=0; s<ri->ifacec; s++)
	    {
	      if(ri->ifaces[s]->ipm != 0 && ri->ip != 0)
		{
		  re->ip_c++;
		  ri->ifaces[s]->class = 'x';
		}
	      else
		{
		  tp++;
		  re->tp_c++;
		  ri->ifaces[s]->class = '+';
		  assert(ri->ifaces[s]->regex < re->regexc);
		  remap[ri->ifaces[s]->regex]++;
		  sc_regex_eval_tp_mask(re, ri->ifaces[s]->ifd);
		}
	    }
	  if(tp >= 2)
	    {
	      re->rt_c++;
	      re->namelen += sc_css_strlen(ri->ifaces[0]->css);
	      for(i=0; i<re->regexc; i++)
		if(remap[i] > 0)
		  re->regexes[i]->rt_c++;
	    }
	  continue;
	}
      assert(ri->maxrtrc < ri->ifacec);

      /*
       * if a majority of interfaces are from a single training router,
       * those are TP and the rest FP.
       */
      x = 1;
      rd = ri->ifaces[ri->maxrtrc]->ifd->rd;
      for(s=ri->maxrtrc+1; s<ri->ifacec; s++)
	{
	  if(ri->ifaces[s]->ifd->rd != rd)
	    break;
	  x++;
	}
      if(ri->maxrtrc > x)
	{
	  /* mark the router as counted */
	  rd = ri->ifaces[0]->ifd->rd;
	  mask_set(rdmap, re->dom->rtmlen, rd->id);

	  tp = 0;
	  for(i=0; i<re->regexc; i++)
	    remap[i] = 0;
	  for(s=0; s<ri->maxrtrc; s++)
	    {
	      if(ri->ifaces[s]->ipm != 0 && ri->ip != 0)
		{
		  ri->ifaces[s]->class = 'x';
		  re->ip_c++;
		}
	      else
		{
		  tp++;
		  re->tp_c++;
		  ri->ifaces[s]->class = '+';
		  assert(ri->ifaces[s]->regex < re->regexc);
		  remap[ri->ifaces[s]->regex]++;
		  sc_regex_eval_tp_mask(re, ri->ifaces[s]->ifd);
		}
	    }
	  if(tp >= 2)
	    {
	      re->rt_c++;
	      re->namelen += sc_css_strlen(ri->ifaces[0]->css);
	      for(i=0; i<re->regexc; i++)
		if(remap[i] > 0)
		  re->regexes[i]->rt_c++;
	    }

	  for(s=ri->maxrtrc; s<ri->ifacec; s++)
	    {
	      if(ri->ifaces[s]->ipm != 0)
		{
		  ri->ifaces[s]->class = 'x';
		  re->ip_c++;
		}
	      else
		{
		  ri->ifaces[s]->class = '!';
		  re->fp_c++;
		}
	    }
	}
      else
	{
	  for(s=0; s<ri->ifacec; s++)
	    {
	      if(ri->ifaces[s]->ipm != 0)
		{
		  ri->ifaces[s]->class = 'x';
		  re->ip_c++;
		}
	      else
		{
		  ri->ifaces[s]->class = '!';
		  re->fp_c++;
		}
	    }
	}
    }

  if(re->tp_c != 0)
    ppv = re->tp_c * 100 / (re->tp_c + re->fp_c);
  else
    ppv = 0;
  if(ppv < 80 || re->rt_c < 3)
    re->class = RE_CLASS_POOR;
  else if((re->rt_c >= 3 && re->rt_c <= 6 && re->fp_c > 0) || ppv < 90)
    re->class = RE_CLASS_PROM;
  else
    re->class = RE_CLASS_GOOD;

  rc = 0;

 done:
  if(rdmap != NULL) free(rdmap);
  if(remap != NULL) free(remap);
  if(ifimap != NULL) free(ifimap);
  return rc;
}

static int sc_regex_thin(sc_regex_t *re)
{
  sc_regexn_t **regexes = NULL;
  int i, j, mc = 0;

  /* nothing to do if every regex matched at least one thing */
  for(i=0; i<re->regexc; i++)
    if(re->regexes[i]->matchc > 0)
      mc++;
  if(mc == 0 || mc == re->regexc)
    return 0;

  if((regexes = malloc_zero(sizeof(sc_regexn_t *) * mc)) == NULL)
    return -1;
  j = 0;
  for(i=0; i<re->regexc; i++)
    {
      if(re->regexes[i]->matchc > 0)
	regexes[j++] = re->regexes[i];
      else
	sc_regexn_free(re->regexes[i]);
    }
  free(re->regexes);
  re->regexes = regexes;
  re->regexc = mc;
  return 0;
}

/*
 * sc_regex_issame
 *
 * determine if two different regexes with the same scores are because
 * the regexes are equivalent in all respects.
 */
static int sc_regex_issame(sc_regex_t *re1,slist_t *ifi1_list, sc_regex_t *re2)
{
  slist_t *ifi2_list = NULL;
  sc_ifaceinf_t *ifi1, *ifi2;
  slist_node_t *sn1, *sn2;
  size_t i;
  int rc = -1;

  /* the regexes must apply to the same domain */
  assert(re1->dom == re2->dom);

  /* two regexes are the same if their strings are the same */
  if(sc_regex_str_cmp(re1, re2) == 0)
    return 1;

  /* the regexes must at least infer the same set of true positives */
  for(i=0; i<re1->dom->tpmlen; i++)
    if(re1->tp_mask[i] != re2->tp_mask[i])
      return 0;

  /* we use ifi1_list across calls to sc_regex_issame to cache inferences */
  if(slist_count(ifi1_list) == 0 &&
     sc_regex_ifi_build(re1, ifi1_list) != 0)
    goto done;

  if((ifi2_list = slist_alloc()) == NULL ||
     sc_regex_ifi_build(re2, ifi2_list) != 0)
    goto done;

  sn1 = slist_head_node(ifi1_list);
  sn2 = slist_head_node(ifi2_list);
  while(sn1 != NULL && sn2 != NULL)
    {
      ifi1 = slist_node_item(sn1);
      ifi2 = slist_node_item(sn2);
      assert(scamper_addr_cmp(ifi1->ifd->iface->addr,
			      ifi2->ifd->iface->addr) == 0);

      if((ifi1->css != NULL && ifi2->css == NULL) ||
	 (ifi1->css == NULL && ifi2->css != NULL) ||
	 (ifi2->css != NULL && sc_css_css_cmp(ifi1->css, ifi2->css) != 0))
	break;

      sn1 = slist_node_next(sn1);
      sn2 = slist_node_next(sn2);
    }

  if(sn1 == NULL && sn2 == NULL)
    rc = 1;
  else
    rc = 0;

 done:
  if(ifi2_list != NULL) slist_free_cb(ifi2_list,(slist_free_t)sc_ifaceinf_free);
  return rc;
}

/*
 * sc_regex_alias_ifi_score
 *
 * Given a list of ifaceinfs, adjust the score of the regex and the
 * class of each inference.
 */
static int sc_regex_alias_ifi_score(sc_regex_t *re, slist_t *ifi_list)
{
  slist_t *ri_list = NULL;
  int rc = 0;

  sc_regex_score_reset(re);
  if((ri_list = slist_alloc()) == NULL ||
     sc_regex_alias_ri_build(ifi_list, ri_list) != 0 ||
     sc_regex_alias_ri_score(re, ri_list) != 0)
    rc = -1;

  if(ri_list != NULL)
    {
      slist_foreach(ri_list, (slist_foreach_t)sc_routerinf_ifaces_null, NULL);
      slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
    }

  return rc;
}

static int sc_regex_alias_eval(sc_regex_t *re, slist_t *out)
{
  slist_t *ifi_list = NULL, *ri_list = NULL;
  int rc = -1;

  assert(re->dom != NULL);
  sc_regex_score_reset(re);

  if((ifi_list = slist_alloc()) == NULL ||
     sc_regex_ifi_build(re, ifi_list) != 0)
    goto done;
  if(slist_count(ifi_list) == 0)
    {
      rc = 0;
      goto done;
    }

  /* build router structures using the assignments */
  if((ri_list = slist_alloc()) == NULL)
    goto done;
  if(sc_regex_alias_ri_build(ifi_list, ri_list) != 0)
    goto done;
  slist_free(ifi_list); ifi_list = NULL;

  /* score the router inferences */
  if(sc_regex_alias_ri_score(re, ri_list) != 0)
    goto done;

  if(out != NULL)
    slist_concat(out, ri_list);
  rc = 0;

 done:
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  return rc;
}

static int sc_regex_eval_cb(sc_regex_t *re, slist_t *out,
			    int (*score)(sc_regex_t *re, slist_t *ifi_list))
{
  slist_t *ifi_list = NULL;
  int rc = -1;

  assert(re->dom != NULL);

  if((ifi_list = slist_alloc()) == NULL ||
     sc_regex_ifi_build(re, ifi_list) != 0)
    goto done;
  if(slist_count(ifi_list) == 0)
    {
      rc = 0;
      goto done;
    }

  if(score(re, ifi_list) != 0)
    goto done;

  if(out != NULL)
    slist_concat(out, ifi_list);
  rc = 0;

 done:
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  return rc;
}

static void sc_reasn_free(sc_reasn_t *ts, int regexc)
{
  int i;

  if(ts->org != NULL) splaytree_free(ts->org, free);
  if(ts->ext != NULL) splaytree_free(ts->ext, free);
  if(ts->inf != NULL) splaytree_free(ts->inf, free);
  if(ts->exts != NULL)
    {
      for(i=0; i<regexc; i++)
	if(ts->exts[i] != NULL)
	  splaytree_free(ts->exts[i], free);
      free(ts->exts);
    }
  if(ts->infs != NULL)
    {
      for(i=0; i<regexc; i++)
	if(ts->infs[i] != NULL)
	  splaytree_free(ts->infs[i], free);
      free(ts->infs);
    }
  free(ts);

  return;
}

static sc_reasn_t *sc_reasn_alloc(int regexc)
{
  sc_reasn_t *ts = NULL;
  int i;

  if((ts = malloc_zero(sizeof(sc_reasn_t))) == NULL ||
     (ts->org = splaytree_alloc((splaytree_cmp_t)sc_as2org_cmp)) == NULL ||
     (ts->inf = splaytree_alloc((splaytree_cmp_t)sc_uint32c_num_cmp)) == NULL ||
     (ts->ext = splaytree_alloc((splaytree_cmp_t)sc_uint32c_num_cmp)) == NULL)
    goto err;

  if(regexc > 1)
    {
      if((ts->infs = malloc_zero(sizeof(splaytree_t *) * regexc)) == NULL ||
	 (ts->exts = malloc_zero(sizeof(splaytree_t *) * regexc)) == NULL)
	goto err;
      for(i=0; i<regexc; i++)
	{
	  ts->infs[i] = splaytree_alloc((splaytree_cmp_t)sc_uint32c_num_cmp);
	  if(ts->infs[i] == NULL)
	    goto err;
	  ts->exts[i] = splaytree_alloc((splaytree_cmp_t)sc_uint32c_num_cmp);
	  if(ts->exts[i] == NULL)
	    goto err;
	}
    }

  ts->sib = sibling_id;
  return ts;

 err:
  if(ts != NULL) sc_reasn_free(ts, regexc);
  return NULL;
}

static int sc_reasn_org(sc_reasn_t *ts, uint32_t a, uint32_t *o)
{
  sc_as2org_t *a2o, fm;

  /* if there is no sibling file, then no need to consider org_id mappings */
  if(sibling_file == NULL)
    {
      *o = a;
      return 0;
    }

  /* find an existing org_id mapping, if we have one */
  fm.asn = a;
  if((a2o = sc_as2org_find(a)) != NULL ||
     (a2o = splaytree_find(ts->org, &fm)) != NULL)
    {
      *o = a2o->org;
      return 0;
    }

  /* create a new org_id mapping */
  if((a2o = malloc(sizeof(sc_as2org_t))) == NULL)
    return -1;
  a2o->asn = a;
  a2o->org = ts->sib;
  if(splaytree_insert(ts->org, a2o) == NULL)
    return -1;

  *o = a2o->org;
  ts->sib++;
  return 0;
}

static int sc_reasn_tp(sc_reasn_t *ts, sc_regex_t *re, sc_ifaceinf_t *ifi,
		       uint32_t ext_asn)
{
  uint32_t inf_org, ext_org, inf_asn = ifi->ifd->iface->rtr->asn;
  sc_uint32c_t *c;

  if(sc_reasn_org(ts, inf_asn, &inf_org) != 0 ||
     sc_reasn_org(ts, ext_asn, &ext_org) != 0)
    return -1;

  if((c = sc_uint32c_get(ts->inf, inf_org)) == NULL)
    return -1;
  c->c++;
  if((c = sc_uint32c_get(ts->ext, ext_org)) == NULL)
    return -1;
  c->c++;

  if(re->regexc > 1)
    {
      if((c = sc_uint32c_get(ts->infs[ifi->regex], inf_org)) == NULL)
	return -1;
      c->c++;
      if((c = sc_uint32c_get(ts->exts[ifi->regex], ext_org)) == NULL)
	return -1;
      c->c++;
    }

  sc_regex_eval_tp_mask(re, ifi->ifd);
  re->tp_c++;
  re->regexes[ifi->regex]->tp_c++;
  return 0;
}

static int sc_regex_asn_ifi_score(sc_regex_t *re, slist_t *ifi_list)
{
  sc_reasn_t *ts = NULL;
  slist_t *list = NULL;
  sc_ifaceinf_t *ifi;
  sc_uint32c_t *c;
  slist_node_t *sn;
  sc_iface_t *iface;
  long long ll;
  size_t len, css_len, ed1 = 0;
  char asstr[16];
  int rc = -1;
  int i, x, ppv;

  sc_regex_score_reset(re);

  /* figure out how many bits might be needed for the true positives mask */
  len = sizeof(uint32_t) * re->dom->tpmlen;
  if(re->tp_mask == NULL && (re->tp_mask = malloc_zero(len)) == NULL)
    goto done;

  if((ts = sc_reasn_alloc(re->regexc)) == NULL)
    goto done;

  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      iface = ifi->ifd->iface;

      if(ifi->regex != -1)
	re->regexes[ifi->regex]->matchc++;

      if(ifi->css != NULL)
	{
	  if(string_isnumber(ifi->css->css) == 0 ||
	     string_tollong(ifi->css->css, &ll, NULL, 10) != 0 ||
	     ll < 0 || ll > 4294967295)
	    {
	      ifi->class = '!';
	      re->fp_c++;
	    }
	  else if((ll >= 64496 && ll <= 65551) || ll >= 4200000000 || ll == 0)
	    {
	      ifi->class = '*';
	      continue;
	    }
	  else if(iface->rtr->asn != ll)
	    {
	      /*
	       * if the edit distance between the ASN extracted from
	       * the hostname and the ASN we believe operates the
	       * router is only one character, then classify the
	       * extraction as a true positive, marked with a '=',
	       * provided the ASNs are at least three characters in
	       * length and the first and last digits both agree.
	       * note the final check is to ensure that we extract all
	       * of the apparent ASN embedded in the hostname.
	       */
	      snprintf(asstr, sizeof(asstr), "%u", iface->rtr->asn);
	      x = dled(ifi->css->css, asstr);
	      len = strlen(asstr);
	      css_len = strlen(ifi->css->css);
	      if(do_ed1 != 0 && x == 1 && len >= 3 && css_len >= 3 &&
		 ifi->css->css[0] == asstr[0] &&
		 ifi->css->css[css_len-1] == asstr[len-1] &&
		 css_len == (size_t)(iface->as_e - iface->as_s + 1))
		{
		  if(sc_reasn_tp(ts, re, ifi, ll) != 0)
		    goto done;
		  ifi->class = '=';
		  ed1++;
		}
	      else
		{
		  ifi->class = '!';
		  re->fp_c++;
		}
	    }
	  else
	    {
	      if(sc_reasn_tp(ts, re, ifi, ll) != 0)
		goto done;
	      ifi->class = '+';
	    }

	  re->matchc++;
	}
      else
	{
	  if((iface->flags & SC_IFACE_FLAG_AS) != 0 &&
	     (iface->flags & SC_IFACE_FLAG_AS_ED1) == 0)
	    {
	      ifi->class = '~';
	      re->fnu_c++;
	    }
	  else
	    {
	      ifi->class = ' ';
	    }
	}
    }

  /*
   * if all the true positives were edit distance 1 from the training
   * ASN, then these are bogus
   */
  if(ed1 > 0 && re->tp_c == ed1)
    {
      re->fp_c = re->tp_c;
      re->tp_c = 0;
      for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
	{
	  ifi = slist_node_item(sn);
	  if(ifi->class == '=')
	    ifi->class = '!';
	}
      if(re->regexc > 1)
	{
	  for(i=0; i<re->regexc; i++)
	    {
	      splaytree_empty(ts->infs[i], free);
	      splaytree_empty(ts->exts[i], free);
	    }
	}
      splaytree_empty(ts->inf, free);
      splaytree_empty(ts->ext, free);
    }

  if(re->regexc > 1)
    {
      for(i=0; i<re->regexc; i++)
	re->regexes[i]->rt_c = tree_mincount(ts->infs[i], ts->exts[i]);
    }
  else
    {
      re->regexes[0]->rt_c = tree_mincount(ts->inf, ts->ext);
    }
  re->rt_c = tree_mincount(ts->inf, ts->ext);

  if((list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(ts->inf, tree_to_slist, list);
  slist_qsort(list, (slist_cmp_t)sc_uint32c_c_cmp);
  if(re->tp_c != 0)
    ppv = re->tp_c * 100 / (re->tp_c + sc_regex_score_fp(re));
  else
    ppv = 0;
  if(((c = slist_head_item(list)) != NULL && re->tp_c > 3 && ppv < 80 &&
      c->c * 100 / re->tp_c > 50) || re->rt_c == 1)
    re->class = RE_CLASS_SINGLE;
  else if(re->rt_c >= 3 && ppv >= 80)
    re->class = RE_CLASS_GOOD;
  else if(re->rt_c >= 2 && ppv >= 50)
    re->class = RE_CLASS_PROM;
  else
    re->class = RE_CLASS_POOR;

  rc = 0;

 done:
  if(list != NULL) slist_free(list);
  if(ts != NULL) sc_reasn_free(ts, re->regexc);
  return rc;
}

static int sc_regex_asn_eval(sc_regex_t *re, slist_t *out)
{
  return sc_regex_eval_cb(re, out, sc_regex_asn_ifi_score);
}

static int sc_regex_asnames_ifi_score(sc_regex_t *re, slist_t *ifi_list)
{
  sc_reasn_t *ts = NULL;
  slist_t *list = NULL;
  sc_ifaceinf_t *ifi;
  sc_rework_t *rew = NULL;
  sc_as2tag_t *a2t;
  slist_node_t *sn;
  sc_iface_t *iface;
  sc_uint32c_t *c;
  size_t len;
  int i, ppv, rc = -1;

  sc_regex_score_reset(re);

  /* figure out how many bits might be needed for the true positives mask */
  len = sizeof(uint32_t) * re->dom->tpmlen;
  if((re->tp_mask == NULL && (re->tp_mask = malloc_zero(len)) == NULL) ||
     (ts = sc_reasn_alloc(re->regexc)) == NULL ||
     (rew = sc_rework_alloc(re)) == NULL)
    goto done;

  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      iface = ifi->ifd->iface;

      if(ifi->regex != -1)
	re->regexes[ifi->regex]->matchc++;

      if(ifi->css != NULL)
	{
	  if(sc_rework_match(rew, iface, NULL) < 0)
	    goto done;
	  if(sc_iface_ip_matched(iface, rew) != 0)
	    {
	      ifi->class = 'x';
	      ifi->ipm = 1;
	      re->ip_c++;
	      continue;
	    }

	  if((a2t = sc_as2tag_find(ifi->css->css)) == NULL)
	    {
	      if(iface->asnamec > 0)
		{
		  ifi->class = '~';
		  re->fnu_c++;
		}
	      else
		{
		  ifi->class = '?';
		  re->unk_c++;
		}
	      continue;
	    }
	  if(sc_as2org_siblings(a2t->asn, iface->rtr->asn) != 0)
	    {
	      if(sc_reasn_tp(ts, re, ifi, a2t->asn) != 0)
		goto done;
	      if(a2t->asn == iface->rtr->asn)
		ifi->class = '+';
	      else
		ifi->class = '=';
	    }
	  else
	    {
	      ifi->class = '!';
	      re->fp_c++;
	    }
	  re->matchc++;
	}
      else
	{
	  if(iface->asnamec > 0)
	    {
	      ifi->class = '~';
	      re->fnu_c++;
	    }
	  else
	    {
	      ifi->class = ' ';
	    }
	}
    }

  if(re->regexc > 1)
    {
      for(i=0; i<re->regexc; i++)
	re->regexes[i]->rt_c = tree_mincount(ts->infs[i], ts->exts[i]);
    }
  else
    {
      re->regexes[0]->rt_c = tree_mincount(ts->inf, ts->ext);
    }
  re->rt_c = tree_mincount(ts->inf, ts->ext);

  if((list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(ts->inf, tree_to_slist, list);
  slist_qsort(list, (slist_cmp_t)sc_uint32c_c_cmp);
  if(re->tp_c != 0)
    ppv = re->tp_c * 100 / (re->tp_c + sc_regex_score_fp(re));
  else
    ppv = 0;
  if(((c = slist_head_item(list)) != NULL && re->tp_c > 3 && ppv < 80 &&
      re->rt_c < 5 && c->c * 100 / re->tp_c > 50) || re->rt_c == 1)
    re->class = RE_CLASS_SINGLE;
  else if(re->rt_c >= 3 && ppv >= 80)
    re->class = RE_CLASS_GOOD;
  else if(re->rt_c >= 2 && ppv >= 50)
    re->class = RE_CLASS_PROM;
  else
    re->class = RE_CLASS_POOR;

  rc = 0;

 done:
  if(list != NULL) slist_free(list);
  if(rew != NULL) sc_rework_free(rew);
  if(ts != NULL) sc_reasn_free(ts, re->regexc);
  return rc;
}

static int sc_regex_asnames_eval(sc_regex_t *re, slist_t *out)
{
  return sc_regex_eval_cb(re, out, sc_regex_asnames_ifi_score);
}

static int sc_regex_geo_ifi_score_do(sc_regex_t *re, slist_t *ifi_list)
{
  splaytree_t *geo_tree = NULL, **geo_trees = NULL;
  sc_ifaceinf_t *ifi;
  sc_iface_t *iface;
  slist_t *list = NULL;
  slist_node_t *sn;
  sc_geohint_t *hint;
  sc_geotagn_t *tag;
  sc_geomap_t map;
  sc_rework_t *rew = NULL;
  int i, ppv, rc = -1, tp;
  char *ptr, *dup = NULL;
  char *code, three[3];
  size_t len, s;
  uint8_t u8;
  size_t min_code_len = 0, max_code_len = 0;

  sc_regex_score_reset(re);

  /* figure out how many bits might be needed for the true positives mask */
  len = sizeof(uint32_t) * re->dom->tpmlen;
  if(re->tp_mask == NULL && (re->tp_mask = malloc_zero(len)) == NULL)
    goto done;

  if((geo_tree = splaytree_alloc((splaytree_cmp_t)strcasecmp)) == NULL)
    goto done;
  if(re->regexc > 1)
    {
      if((geo_trees = malloc_zero(sizeof(splaytree_t *) * re->regexc)) == NULL)
	goto done;
      for(i=0; i<re->regexc; i++)
	if((geo_trees[i]=splaytree_alloc((splaytree_cmp_t)strcasecmp)) == NULL)
	  goto done;
    }

  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;

  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      iface = ifi->ifd->iface;

      if(ifi->regex != -1)
	re->regexes[ifi->regex]->matchc++;

      if(ifi->css == NULL)
	{
	  /* No match */
	  if(iface->geoc > 0)
	    {
	      ifi->class = '~';
	      ifi->geohint = iface->geos[0].hint;
	      re->fnu_c++;
	    }
	  else
	    {
	      ifi->class = ' ';
	    }
	  continue;
	}

      re->matchc++;

      if(iface->flags & SC_IFACE_FLAG_IP_HEX)
	{
	  if(sc_rework_match(rew, iface, NULL) < 0)
	    goto done;
	  if(sc_iface_ip_matched(iface, rew) != 0)
	    {
	      ifi->class = 'x';
	      ifi->ipm = 1;
	      re->ip_c++;
	      continue;
	    }
	}

      sc_css_geomap(ifi->css, re->regexes[ifi->regex]->plan, &map);
      if((hint = sc_router_checkgeo(re, iface->rtr, &map)) != NULL)
	{
	  /* find the hint */
	  tp = 1;
	  for(u8=0; u8<iface->geoc; u8++)
	    {
	      /*
	       * if we make an extraction of an apparent location,
	       * make sure the expected CC/ST comes as well.
	       */
	      if(iface->geos[u8].hint->type != hint->type ||
		 strcmp(iface->geos[u8].hint->code, hint->code) != 0)
		continue;
	      for(s=0; s<iface->geos[u8].tagc; s++)
		{
		  tag = &iface->geos[u8].tags[s];
		  if((tag->type == GEOHINT_TYPE_CC &&
		      strcasecmp(map.cc, hint->cc) != 0) ||
		     (tag->type == GEOHINT_TYPE_ST &&
		      strcasecmp(map.st, hint->st) != 0))
		    {
		      tp = 0;
		      break;
		    }
		}
	    }

	  if(tp == 1)
	    {
	      if(map.type == GEOHINT_TYPE_LOCODE)
		code = map.code+2;
	      else
		code = map.code;

	      if((ptr = splaytree_find(geo_tree, code)) == NULL)
		{
		  if((dup = strdup(code)) == NULL ||
		     splaytree_insert(geo_tree, dup) == NULL)
		    {
		      fprintf(stderr, "%s: could not insert %s into tree\n",
			      __func__, code);
		      goto done;
		    }
		  ptr = dup; dup = NULL;
		}

	      sc_regex_eval_tp_mask(re, ifi->ifd);
	      ifi->class = '+';
	      ifi->geohint = hint;

	      assert(map.codelen > 0);
	      if(min_code_len == 0 || min_code_len > map.codelen)
		min_code_len = map.codelen;
	      if(max_code_len == 0 || max_code_len < map.codelen)
		max_code_len = map.codelen;

	      re->tp_c++;
	      re->regexes[ifi->regex]->tp_c++;
	      if(re->regexc > 1 &&
		 splaytree_find(geo_trees[ifi->regex], ptr) == NULL &&
		 splaytree_insert(geo_trees[ifi->regex], ptr) == NULL)
		{
		  fprintf(stderr, "%s: could not insert %s into tree[%d]\n",
			  __func__, ptr, ifi->regex);
		  goto done;
		}
	    }
	  else
	    {
	      ifi->class = '~';
	      ifi->geohint = hint;
	      re->fnu_c++;
	    }
	}
      else if((hint = sc_geohint_find(re, &map)) != NULL &&
	      hint->type == map.type)
	{
	  /* Might be a geocode */
	  ifi->class = '!';
	  ifi->geohint = hint;
	  re->fp_c++;
	}
      else
	{
	  /* we don't have the extracted geocode in our dictionary */
	  ifi->class = '?';
	  re->unk_c++;
	}
    }

  if(re->regexc > 1)
    {
      for(i=0; i<re->regexc; i++)
	re->regexes[i]->rt_c = splaytree_count(geo_trees[i]);
    }
  else
    {
      re->regexes[0]->rt_c = splaytree_count(geo_tree);
    }
  re->rt_c = splaytree_count(geo_tree);

  if(re->tp_c != 0)
    ppv = re->tp_c * 100 / (re->tp_c + sc_regex_score_fp(re));
  else
    ppv = 0;

  if(re->regexc == 1)
    {
      u8 = sc_regexn_geotype(re->regexes[0]);

      /*
       * if all the apparent place names are the same length, then they
       * probably aren't place names.
       */
      if(u8 == GEOHINT_TYPE_PLACE && re->rt_c >= 3 &&
	 (min_code_len == max_code_len || max_code_len < 5))
	{
	  sc_regex_score_reset(re);
	  re->class = RE_CLASS_POOR;
	  rc = 0;
	  goto done;
	}

      /*
       * if one of the characters is the same for every IATA hint,
       * then they probably aren't IATA hints
       */
      if(u8 == GEOHINT_TYPE_IATA && re->rt_c >= 5)
	{
	  if((list = slist_alloc()) == NULL)
	    goto done;
	  splaytree_inorder(geo_tree, tree_to_slist, list);
	  ptr = slist_head_item(list);
	  three[0] = ptr[0]; three[1] = ptr[1]; three[2] = ptr[2];
	  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
	    {
	      ptr = slist_node_item(sn);
	      for(i=0; i<3; i++)
		if(three[i] != ptr[i])
		  three[i] = '\0';
	    }

	  /*
	   * do not consider first letter of IATA code, which could be
	   * related to the region of the airport, e.g. lots of airports
	   * in canada starting with Y
	   */
	  if(three[1] != '\0' || three[2] != '\0')
	    {
	      sc_regex_score_reset(re);
	      re->class = RE_CLASS_POOR;
	      rc = 0;
	      goto done;
	    }
	}
    }

  if(re->rt_c >= 3 && ppv >= 90)
    re->class = RE_CLASS_GOOD;
  else if(re->rt_c >= 3 && ppv >= 80)
    re->class = RE_CLASS_PROM;
  else
    re->class = RE_CLASS_POOR;

  rc = 0;

 done:
  if(dup != NULL) free(dup);
  if(rew != NULL) sc_rework_free(rew);
  if(list != NULL) slist_free(list);
  if(geo_tree != NULL) splaytree_free(geo_tree, free);
  if(geo_trees != NULL)
    {
      for(i=0; i<re->regexc; i++)
	if(geo_trees[i] != NULL)
	  splaytree_free(geo_trees[i], NULL);
      free(geo_trees);
    }
  return rc;
}

/*
 * sc_regex_geo_ifi_score
 *
 * this function works in two phases.  first, do a simple evaluation.
 * then, check for duplicate geocodes (e.g., milan -> "Milan, IT" and
 * "Milan, MI, US".  if there are duplicate geocodes, pick one, and
 * then re-evaluate.
 */
static int sc_regex_geo_ifi_score(sc_regex_t *re, slist_t *ifi_list)
{
  slist_t *m2h_list = NULL, *geoeval_list = NULL;
  sc_geomap2hint_t *m2h, *m2h_last;
  sc_geoeval_t *geoeval = NULL, *ge;
  slist_node_t *sn, *s2, *s3;
  sc_geohint_t *hint = NULL;
  sc_ifaceinf_t *ifi;
  sc_geomap_t map;
  int rc = 1;

  /* make a first pass at the evaluation */
  if(sc_regex_geo_ifi_score_do(re, ifi_list) != 0)
    goto done;

  /* no need to scan for duplicate codes */
  if(re->geohintc > 0)
    {
      rc = 0;
      goto done;
    }

  /*
   * check if there are duplicate codes for some entries.
   * this is an infinite for loop so that if the last geomap is a duplicate
   * of an earlier geomap, we'll catch it.
   */
  if((m2h_list = sc_geomap2hint_make(re, ifi_list)) == NULL)
    goto done;
  m2h_last = NULL;
  sn = slist_head_node(m2h_list);
  for(;;)
    {
      m2h = sn != NULL ? slist_node_item(sn) : NULL;

      if(m2h_last != NULL && m2h != NULL && m2h->hint != NULL &&
	 m2h->hint->type == GEOHINT_TYPE_PLACE &&
	 sc_geomap_cmp(&m2h_last->map, &m2h->map) == 0)
	{
	  if(geoeval_list == NULL && (geoeval_list = slist_alloc()) == NULL)
	    goto done;
	  if(slist_count(geoeval_list) == 0)
	    {
	      if((geoeval = malloc_zero(sizeof(sc_geoeval_t))) == NULL ||
		 slist_tail_push(geoeval_list, geoeval) == NULL)
		goto done;
	      assert(m2h_last->hint != NULL);
	      geoeval->hint = m2h_last->hint;
	      geoeval = NULL;
	    }
	  if((geoeval = malloc_zero(sizeof(sc_geoeval_t))) == NULL ||
	     slist_tail_push(geoeval_list, geoeval) == NULL)
	    goto done;
	  assert(m2h->hint != NULL);
	  geoeval->hint = m2h->hint;
	  geoeval = NULL;
	  goto next;
	}

      if(m2h != NULL && m2h->hint == NULL)
	goto next;

      /* if one geomap has multiple candidate hints, score them */
      if(geoeval_list != NULL && slist_count(geoeval_list) > 0)
	{
	  for(s2=slist_head_node(ifi_list); s2 != NULL; s2=slist_node_next(s2))
	    {
	      ifi = slist_node_item(s2);
	      if(ifi->css == NULL)
		continue;
	      sc_css_geomap(ifi->css, re->regexes[ifi->regex]->plan, &map);
	      if(sc_geomap_cmp(&m2h_last->map, &map) != 0)
		continue;

	      for(s3=slist_head_node(geoeval_list); s3 != NULL;
		  s3=slist_node_next(s3))
		{
		  ge = slist_node_item(s3);
		  if(sc_geohint_checkrtt(ge->hint, ifi->ifd->iface->rtr) != 0)
		    ge->tp_c++;
		}
	    }

	  slist_qsort(geoeval_list, (slist_cmp_t)sc_geoeval_cmp);
	  ge = slist_head_item(geoeval_list);
	  if((hint = sc_geohint_alloc(ge->hint->type, ge->hint->code,
				      ge->hint->place, ge->hint->st,
				      ge->hint->cc, ge->hint->lat,
				      ge->hint->lng, ge->hint->popn)) == NULL||
	     array_insert((void ***)&re->geohints, &re->geohintc,
			  hint, NULL) != 0)
	    goto done;
	  hint = NULL;
	  slist_empty_cb(geoeval_list, (slist_free_t)free);
	}

    next:
      if(sn == NULL)
	break;
      if(m2h != NULL && m2h->hint != NULL &&
	 m2h->hint->type == GEOHINT_TYPE_PLACE)
	m2h_last = m2h;
      sn = slist_node_next(sn);
    }

  /* if there were no duplicate entries, we're done */
  if(re->geohintc == 0)
    {
      rc = 0;
      goto done;
    }

  array_qsort((void **)re->geohints,re->geohintc,(array_cmp_t)sc_geohint_cmp);
  if(sc_regex_geo_ifi_score_do(re, ifi_list) != 0)
    goto done;
  rc = 0;

 done:
  if(hint != NULL) sc_geohint_free(hint);
  if(m2h_list != NULL) slist_free_cb(m2h_list, (slist_free_t)free);
  if(geoeval_list != NULL) slist_free_cb(geoeval_list, (slist_free_t)free);
  if(geoeval != NULL) free(geoeval);
  return rc;
}

static int sc_regex_geo_eval(sc_regex_t *re, slist_t *out)
{
  return sc_regex_eval_cb(re, out, sc_regex_geo_ifi_score);
}

static int sc_regex_eval(sc_regex_t *re, slist_t *out)
{
  if(do_learnalias != 0)
    return sc_regex_alias_eval(re, out);
  else if(do_learnasn != 0)
    return sc_regex_asn_eval(re, out);
  else if(do_learnasnames != 0)
    return sc_regex_asnames_eval(re, out);
  else if(do_learngeo != 0)
    return sc_regex_geo_eval(re, out);
  return -1;
}

/*
 * sc_regex_permute
 *
 * given a base regex (work) and inferences derived from that regex
 * (work_ifi), and a second regex (cand) which we are considering
 * permuting into a regex containing both work and cand, compute the
 * combinations.
 */
static int sc_regex_permute(sc_regex_t *work, slist_t *work_ifi,
			    sc_regex_t *cand, slist_t *set)
{
  slist_t *cand_ifi = NULL, *ifi = NULL, *ri_list = NULL;
  sc_regex_t *re = NULL;
  int i, rc = -1;

  /* don't add this regex if its already in the set */
  for(i=0; i<work->regexc; i++)
    if(strcmp(work->regexes[i]->str, cand->regexes[0]->str) == 0)
      return 0;

  if((ifi = slist_alloc()) == NULL || (ri_list = slist_alloc()) == NULL ||
     (cand_ifi = slist_alloc()) == NULL)
    goto done;

  if(sc_regex_ifi_build(cand, cand_ifi) != 0)
    goto done;

  /*
   * remove inferences from the candidate regex that are the same as those
   * made by the working regex so that they do not get counted against the
   * candidate.
   */
  if(sc_regex_ifi_thin(work_ifi, cand_ifi) == 0)
    {
      rc = 0;
      goto done;
    }

  for(i=0; i<=work->regexc; i++)
    {
      if((re = sc_regex_plus1(work, cand->regexes[0], i)) == NULL)
	goto done;
      re->score = work->score + cand->score;

      /* build a new set of inferences */
      if(sc_regex_ifi_build2(work_ifi, cand_ifi, i, ifi) != 0)
	goto done;

      if(do_learnalias != 0)
	{
	  if(sc_regex_alias_ri_build(ifi, ri_list) != 0)
	    goto done;
	  if(sc_regex_alias_ri_score(re, ri_list) != 0)
	    goto done;
	  slist_foreach(ifi, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
	  slist_empty(ifi);
	  slist_empty_cb(ri_list, (slist_free_t)sc_routerinf_free);
	}
      else if(do_learnasn != 0 || do_learnasnames != 0 || do_learngeo != 0)
	{
	  if(do_learnasn != 0)
	    {
	      if(sc_regex_asn_ifi_score(re, ifi) != 0)
		goto done;
	    }
	  else if(do_learnasnames != 0)
	    {
	      if(sc_regex_asnames_ifi_score(re, ifi) != 0)
		goto done;
	    }
	  else if(do_learngeo != 0)
	    {
	      if(sc_regex_geo_ifi_score(re, ifi) != 0)
		goto done;
	    }
	  slist_foreach(ifi, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
	  slist_empty_cb(ifi, (slist_free_t)sc_ifaceinf_free);
	}
      else goto done;

      /* keep regex around */
      if(slist_tail_push(set, re) == NULL)
	goto done;
      re = NULL;
    }

  rc = 0;

 done:
  if(ifi != NULL)
    {
      if(ri_list != NULL && slist_count(ri_list) > 0)
	{
	  slist_foreach(ifi, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
	  slist_free(ifi);
	}
      else slist_free_cb(ifi, (slist_free_t)sc_ifaceinf_free);
    }
  if(cand_ifi != NULL)
    slist_free_cb(cand_ifi, (slist_free_t)sc_ifaceinf_free);
  if(ri_list != NULL)
    slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(re != NULL)
    sc_regex_free(re);
  return rc;
}

static void sc_regex_sni_free(sc_regex_sni_t *sni)
{
  if(sni->out != NULL) sc_regex_free(sni->out);
  free(sni);
  return;
}

static int sc_regex_sn_lock(sc_regex_sn_t *sn)
{
#ifdef HAVE_PTHREAD
  if(pthread_mutex_lock(&sn->mutex) != 0)
    return -1;
#endif
  return 0;
}

static void sc_regex_sn_unlock(sc_regex_sn_t *sn)
{
#ifdef HAVE_PTHREAD
  pthread_mutex_unlock(&sn->mutex);
#endif
  return;
}

static void sc_regex_sn_free(sc_regex_sn_t *sn)
{
#ifdef HAVE_PTHREAD
  if(sn->mutex_o != 0)
    pthread_mutex_destroy(&sn->mutex);
#endif
  if(sn->snis != NULL) slist_free(sn->snis);
  free(sn);
  return;
}

static int sc_regex_sn_score_rank_cmp(sc_regex_sn_t *a, sc_regex_sn_t *b)
{
  return sc_regex_score_rank_cmp(a->re, b->re);
}

static int sc_regex_sn_base_rank_cmp(sc_regex_sn_t *a, sc_regex_sn_t *b)
{
  return sc_regex_score_rank_cmp(a->base, b->base);
}

static void sc_domain_fn_free(sc_domain_fn_t *domfn)
{
  if(domfn == NULL)
    return;
  if(domfn->work != NULL)
    slist_free_cb(domfn->work, (slist_free_t)sc_regex_sn_free);
  if(domfn->base != NULL)
    slist_free_cb(domfn->base, (slist_free_t)sc_regex_sn_free);
  free(domfn);
  return;
}

static splaytree_t *sc_routerdom_css_tree(const slist_t *routers)
{
  splaytree_t *rd_css_tree = NULL;
  sc_routerdom_t *rd;
  slist_node_t *sn;
  sc_css_t *css = NULL;

  /* build a tree of all inferred sc_routerdom_t names */
  if((rd_css_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
    goto err;
  for(sn=slist_head_node(routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      if(rd->css == NULL)
	continue;

      if((css = splaytree_find(rd_css_tree, rd->css)) != NULL)
	{
	  css->count++;
	  css = NULL;
	  continue;
	}

      if((css = sc_css_dup(rd->css)) == NULL)
	goto err;
      css->count = 1;
      if(splaytree_insert(rd_css_tree, css) == NULL)
	goto err;
    }

  return rd_css_tree;

 err:
  if(css != NULL) sc_css_free(css);
  if(rd_css_tree != NULL) splaytree_free(rd_css_tree, (splaytree_free_t)sc_css_free);
  return NULL;
}

static int sc_routerdom_lcs(sc_routerdom_t *rd)
{
  splaytree_t *tree = NULL;
  slist_t *list = NULL;
  slist_node_t *sn;
  sc_ifacedom_t *ifd;
  sc_css_t *css = NULL;
  int i, rc = -1;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL ||
     (list = slist_alloc()) == NULL)
    goto done;

  /* figure out the candidate longest common substrings */
  for(i=0; i<rd->ifacec; i++)
    {
      ifd = rd->ifaces[i];

      /* if the entire hostname is an IP address, skip over */
      if((ifd->iface->flags & SC_IFACE_FLAG_IP) != 0 &&
	 ifd->iface->ip_s == 0 && ifd->label[ifd->iface->ip_e+1] == '\0')
	continue;

      if(sc_ifacedom_css(ifd, &css, 1) != 0)
	goto done;
      if(css == NULL)
	continue;
      if(sc_css_get(tree, css) == NULL)
	goto done;
      sc_css_free(css); css = NULL;
    }

  if(sc_css_reduce(tree, 1, 2) != 0) /* trim on non-alnum, min length 2 */
    goto done;

  /* count how many interfaces match */
  splaytree_inorder(tree, tree_to_slist, list);
  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      css = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	if(sc_css_match(css, rd->ifaces[i]->label, NULL, 1) == 1)
	  css->count++;
    }

  if(slist_count(list) > 0)
    {
      slist_qsort(list, (slist_cmp_t)sc_css_count_cmp);
      css = slist_head_item(list);
      if(css->count > 1 && (rd->css = sc_css_dup(css)) == NULL)
	goto done;
    }

  rc = 0;

 done:
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)sc_css_free);
  if(list != NULL) slist_free(list);
  return rc;
}

static void sc_routerdom_lcs_thread(sc_routerdom_t *rd)
{
  sc_routerdom_lcs(rd);
  return;
}

static void sc_routerdom_free(sc_routerdom_t *rd)
{
  int i;
  if(rd->ifaces != NULL)
    {
      for(i=0; i<rd->ifacec; i++)
	if(rd->ifaces[i] != NULL)
	  sc_ifacedom_free(rd->ifaces[i]);
      free(rd->ifaces);
    }
  if(rd->css != NULL) sc_css_free(rd->css);
  free(rd);
  return;
}

static int sc_regex_del_ppv_ok(const sc_regex_t *cur, const sc_regex_t *can)
{
  int cur_ppv, del_ppv, del_tp, del_fp;

  if(cur->tp_c >= can->tp_c && cur->fp_c <= can->fp_c)
    return 0;
  if(cur->tp_c <= can->tp_c && cur->fp_c >= can->fp_c)
    return 1;

  assert(can->tp_c > cur->tp_c);
  assert(can->fp_c > cur->fp_c);
  del_tp = can->tp_c - cur->tp_c;
  del_fp = can->fp_c - cur->fp_c;
  del_ppv = (del_tp * 1000) / (del_tp + del_fp);
  cur_ppv = (cur->tp_c * 1000) / (cur->tp_c + cur->fp_c);
  if(del_ppv < cur_ppv && cur_ppv - del_ppv > 100 && del_fp != 1)
    return 0;

  return 1;
}

static sc_regex_t *sc_domain_bestre_asn(sc_domain_t *dom)
{
  sc_regex_t *re, *best;
  uint32_t re_fp, best_fp;
  slist_node_t *sn;

  if(do_learnasn != 0)
    slist_qsort(dom->regexes, (slist_cmp_t)sc_regex_score_rank_asn_cmp);
  else if(do_learnasnames != 0)
    slist_qsort(dom->regexes, (slist_cmp_t)sc_regex_score_rank_asnames_cmp);
  else
    return NULL;

  best = slist_head_item(dom->regexes);
  best_fp = sc_regex_score_fp(best);

  for(sn=slist_head_node(dom->regexes); sn != NULL; sn=slist_node_next(sn))
    {
      re = slist_node_item(sn);
      if(re == best)
	continue;

      re_fp = sc_regex_score_fp(re);

      /*
       * if the convention is made up of fewer regexes but matches
       * more hostnames, and the number of false positives is only one
       * more than the current best regex with at least the same
       * number of TPs, then take the shorter naming convention
       */
      if(re->regexc < best->regexc && re->matchc >= best->matchc &&
	 re->tp_c >= best->tp_c &&
	 re_fp > best_fp && re_fp - best_fp <= 1)
	goto new_best;

      /*
       * if the number of inferred ASNs is larger, take it if the current
       * regex only infers a single ASN, or if the number of TPs is larger
       * and the number of FPs smaller.
       */
      if(re->rt_c > best->rt_c && re->tp_c > 0 &&
	 ((best->rt_c == 1 &&
	   re->tp_c * 100 / (re->tp_c + re_fp) > 50) ||
	  (re->tp_c >= best->tp_c && re_fp <= best_fp)))
	goto new_best;

      continue;

    new_best:
      best = re;
      best_fp = re_fp;
    }

  return best;
}

static sc_regex_t *sc_domain_bestre_geo(sc_domain_t *dom)
{
  int best_ppv, del_ppv, del_tp, del_fp;
  uint32_t re_fp, best_fp;
  sc_regex_t *re, *best;
  slist_node_t *sn;

  slist_qsort(dom->regexes, (slist_cmp_t)sc_regex_score_rank_cmp);
  best = slist_head_item(dom->regexes);
  best_fp = sc_regex_score_fp(best);
  if(best->tp_c != 0 && best_fp != 0)
    best_ppv = (best->tp_c * 1000) / (best->tp_c + best_fp);
  else
    best_ppv = 0;

  for(sn=slist_head_node(dom->regexes); sn != NULL; sn=slist_node_next(sn))
    {
      re = slist_node_item(sn);
      if(re == best)
	continue;
      if(re->tp_c == 0)
	continue;
      re_fp = sc_regex_score_fp(re);

      /*
       * if the candidate replacement has more TPs and more FPs, skip
       * if the delta PPV is more than 10% worse than the best regex's
       * PPV.
       * this is the same logic we apply in sc_regex_del_ppv_ok
       */
      if(re->tp_c > best->tp_c && re_fp > best_fp)
        {
          del_tp = re->tp_c - best->tp_c;
          del_fp = re_fp - best_fp;
          del_ppv = (del_tp * 1000) / (del_tp + del_fp);
          if(del_ppv < best_ppv && best_ppv - del_ppv > 100 && del_fp != 1)
            continue;
        }

      /*
       * if the current best has at least as many regexes as a candidate,
       * is classified as poor, and the replacement is promising or good,
       * then replace
       */
      if(best->regexc >= re->regexc &&
	 best->class == RE_CLASS_POOR && class_cmp(re->class, best->class) < 0)
	goto new_best;

      /*
       * if the candidate convention is made up of fewer regexes, has
       * at most one more FP than the current best, and the best has
       * fewer than three more TPs, then take the shorter naming
       * convention.
       */
      if(best->regexc > re->regexc &&
	 (re->tp_c >= best->tp_c || best->tp_c - re->tp_c < 3) &&
	 (re_fp <= best_fp || re_fp - best_fp == 1))
	goto new_best;

      continue;

    new_best:
      best = re;
      best_fp = re_fp;
      best_ppv = (best->tp_c * 1000) / (best->tp_c + best_fp);
    }

  return best;
}

static sc_regex_t *sc_domain_bestre_alias(sc_domain_t *dom)
{
  int best_atp, best_ppv, best_len;
  int re_ppv, re_atp, re_len;
  int diff_atp, diff_atp_r;
  int del_ppv, del_tp, del_fp;
  sc_regex_t *re, *best;
  slist_node_t *sn;

  slist_qsort(dom->regexes, (slist_cmp_t)sc_regex_score_rank_cmp);
  best = slist_head_item(dom->regexes);
  best_atp = sc_regex_score_atp(best);
  best_len = sc_regex_str_len(best);

  if(best->tp_c != 0 && best->fp_c != 0)
    best_ppv = (best->tp_c * 1000) / (best->tp_c + best->fp_c);
  else
    best_ppv = 0;

  for(sn=slist_head_node(dom->regexes); sn != NULL; sn=slist_node_next(sn))
    {
      re = slist_node_item(sn);
      if(re == best)
	continue;
      if(re->tp_c == 0 && re->fp_c == 0)
	continue;
      if((re_atp = sc_regex_score_atp(re)) < 1)
	break;

      /*
       * this is the same logic we apply in sc_regex_del_ppv_ok
       * XXX: what happens when best has more TPs and more FPs?
       */
      if(re->tp_c > best->tp_c && re->fp_c > best->fp_c)
        {
          del_tp = re->tp_c - best->tp_c;
          del_fp = re->fp_c - best->fp_c;
          del_ppv = (del_tp * 1000) / (del_tp + del_fp);
          if(del_ppv < best_ppv && best_ppv - del_ppv > 100 && del_fp != 1)
            continue;
        }

      re_len = sc_regex_str_len(re);
      diff_atp = best_atp - re_atp;
      diff_atp_r = (diff_atp * 1000) / re_atp;

      /*
       * if the best regex has more TPs and more FPs than a candidate
       * regex down the list, the ATP difference is less than 4%, and
       * the delta ppv from the candidate regex to the current best
       * regex is poor, then replace the current best regex.
       */
      if(best->regexc == re->regexc && diff_atp_r <= 40 &&
	 best->tp_c > re->tp_c && best->fp_c > re->fp_c)
	{
	  del_tp = best->tp_c - re->tp_c;
	  del_fp = best->fp_c - re->fp_c;
	  del_ppv = (del_tp * 1000) / (del_tp + del_fp);
	  re_ppv = (re->tp_c * 1000) / (re->tp_c + re->fp_c);
	  if(del_ppv < re_ppv && re_ppv - del_ppv > 100 && del_fp != 1)
	    goto new_best;
	}

      if((best->regexc > re->regexc || best_len > re_len * 4) &&
	 (diff_atp_r <= 40 ||
	  (diff_atp == 2 && best->tp_c > re->tp_c && best->tp_c - re->tp_c == 1)))
	goto new_best;

      if(best->regexc >= re->regexc &&
	 best->class == RE_CLASS_POOR && class_cmp(re->class, best->class) < 0)
	goto new_best;

      continue;

    new_best:
      best = re;
      best_atp = sc_regex_score_atp(best);
      best_len = sc_regex_str_len(best);
      best_ppv = (best->tp_c * 1000) / (best->tp_c + best->fp_c);
    }

  return best;
}

static sc_regex_t *sc_domain_bestre(sc_domain_t *dom)
{
  if(slist_count(dom->regexes) < 1)
    return NULL;
  if(do_learnalias != 0)
    return sc_domain_bestre_alias(dom);
  else if(do_learnasn != 0 || do_learnasnames != 0)
    return sc_domain_bestre_asn(dom);
  else if(do_learngeo != 0)
    return sc_domain_bestre_geo(dom);
  return NULL;
}

static int sc_domain_cmp(const sc_domain_t *a, const sc_domain_t *b)
{
  return strcasecmp(a->domain, b->domain);
}

static void sc_domain_free(sc_domain_t *dom)
{
  size_t i;
  if(dom->geohints != NULL)
    {
      for(i=0; i<dom->geohintc; i++)
	if(dom->geohints[i] != NULL)
	  sc_geohint_free(dom->geohints[i]);
      free(dom->geohints);
    }
  if(dom->domain != NULL)
    free(dom->domain);
  if(dom->escape != NULL)
    free(dom->escape);
  if(dom->routers != NULL)
    slist_free_cb(dom->routers, (slist_free_t)sc_routerdom_free);
  if(dom->regexes != NULL)
    slist_free_cb(dom->regexes, (slist_free_t)sc_regex_free);
  if(dom->appl != NULL)
    slist_free_cb(dom->appl, (slist_free_t)sc_routerdom_free);
#ifdef HAVE_PTHREAD
  if(dom->mutex_o != 0)
    pthread_mutex_destroy(&dom->mutex);
#endif
  free(dom);
  return;
}

static sc_domain_t *sc_domain_alloc(const char *domain)
{
  sc_domain_t *dom = NULL;
  size_t x, off;

  if((dom = malloc_zero(sizeof(sc_domain_t))) == NULL ||
     (dom->domain = strdup(domain)) == NULL ||
     (dom->regexes = slist_alloc()) == NULL ||
     (dom->appl = slist_alloc()) == NULL ||
     (dom->routers = slist_alloc()) == NULL)
    goto err;

  /* escape the domain suffix */
  off = 0;
  for(x=0; domain[x] != '\0'; x++)
    {
      if(domain[x] == '.')
	off++;
      off++;
    }
  off++;
  if((dom->escape = malloc(off)) == NULL)
    goto err;
  off = 0;
  for(x=0; domain[x] != '\0'; x++)
    {
      if(domain[x] == '.')
	dom->escape[off++] = '\\';
      dom->escape[off++] = domain[x];
    }
  dom->escape[off] = '\0';
  dom->escapel = off;

#ifdef HAVE_PTHREAD
  if(pthread_mutex_init(&dom->mutex, NULL) != 0)
    goto err;
  dom->mutex_o = 1;
#endif

  return dom;

 err:
  if(dom != NULL) sc_domain_free(dom);
  return NULL;
}

static sc_domain_t *sc_domain_find(const char *domain)
{
  sc_domain_t fm; fm.domain = (char *)domain;
  return splaytree_find(domain_tree, &fm);
}

static sc_domain_t *sc_domain_get(const char *domain)
{
  sc_domain_t *dom;

  if((dom = sc_domain_find(domain)) != NULL)
    return dom;
  if((dom = sc_domain_alloc(domain)) == NULL)
    return NULL;
  if(splaytree_insert(domain_tree, dom) == NULL)
    {
      sc_domain_free(dom);
      return NULL;
    }

  return dom;
}

static int label_cmp(const char *ap, const char *bp)
{
  int j = 0;
  for(;;)
    {
      if((ap[j] == '.' || ap[j] == '\0') && (bp[j] == '.' || bp[j] == '\0'))
	break;
      if(ap[j] == '.' || ap[j] == '\0')
	return -1;
      if(bp[j] == '.' || bp[j] == '\0')
	return  1;
      if(ap[j] < bp[j])
	return -1;
      if(ap[j] > bp[j])
	return  1;
      j++;
    }
  return 0;
}

static int suffix_file_line_cmp(const char *a, const char *b)
{
  const char *ap, *bp;
  int ac = dotcount(a);
  int bc = dotcount(b);
  int i, rc;

  if(ac < bc) return -1;
  if(ac > bc) return  1;

  if(ac == 0) return strcmp(a, b);

  for(i=0; i<=bc; i++)
    {
      ap = label_get(a, i);
      bp = label_get(b, i);
      if((rc = label_cmp(ap, bp)) != 0)
	return rc;
    }

  assert(strcmp(a, b) == 0);
  return 0;
}

static int process_suffix(slist_t *list)
{
  slist_t *tmp;
  sc_suffix_t *se;
  slist_node_t *sn;
  char *suffix;
  int x;

  /*
   * sort the list from shortest to longest suffix, ordered by domain
   * name from TLD.
   */
  slist_qsort(list, (slist_cmp_t)suffix_file_line_cmp);

  /* to start with, get the root prefixes */
  if((tmp = slist_alloc()) == NULL)
    goto err;
  if((suffix_root = malloc_zero(sizeof(sc_suffix_t))) == NULL)
    goto err;
  for(;;)
    {
      if((sn = slist_head_node(list)) == NULL)
	break;
      suffix = slist_node_item(sn);
      if(dotcount(suffix) != 0)
	break;
      slist_head_pop(list);
      slist_tail_push(tmp, suffix);
    }
  if((x = slist_count(tmp)) > 0)
    {
      if((suffix_root->suffixes=malloc_zero(x*sizeof(sc_suffix_t *))) == NULL)
	goto err;
      x = 0;
      while((suffix = slist_head_pop(tmp)) != NULL)
	{
	  if((se = malloc_zero(sizeof(sc_suffix_t))) == NULL)
	    goto err;

	  se->label = suffix;
	  se->end = 1;

	  suffix_root->suffixes[x++] = se;
	}
      suffix_root->suffixc = (size_t)x;
    }
  slist_free(tmp);

  /* now work through strings with at least two labels */
  while((suffix = slist_head_pop(list)) != NULL)
    {
      if(sc_suffix_get(suffix) == NULL)
	goto err;
      free(suffix);
    }

  if((se = sc_suffix_get("arpa")) != NULL)
    se->end = -1;

  return 0;

 err:
  return -1;
}

static int isgeo(int x)
{
  assert(x >= BIT_TYPE_MIN && x <= BIT_TYPE_MAX);
  if(x == BIT_TYPE_GEO_IATA ||
     x == BIT_TYPE_GEO_ICAO ||
     x == BIT_TYPE_GEO_CLLI ||
     x == BIT_TYPE_GEO_PLACE ||
     x == BIT_TYPE_GEO_LOCODE ||
     x == BIT_TYPE_GEO_FACILITY ||
     x == BIT_TYPE_GEO_CC ||
     x == BIT_TYPE_GEO_ST)
    return 1;
  return 0;
}

static int iscapture(int x)
{
  assert(x >= BIT_TYPE_MIN && x <= BIT_TYPE_MAX);
  if(x == BIT_TYPE_CAPTURE ||
     x == BIT_TYPE_CAPTURE_LIT ||
     x == BIT_TYPE_CAPTURE_DIGIT ||
     isgeo(x) != 0)
    return 1;
  return 0;
}

static int sc_regex_build_skip(const char *name, int j, char *buf, size_t len,
			       size_t *to)
{
  char tmp[8];
  size_t r;

  while(name[j] != '\0' && isalnum((unsigned char)name[j]) == 0)
    {
      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
	return -1;

      /* string_concat(buf, len, to, "%s", tmp); */
      if(len - *to < r + 1)
	return -1;
      memcpy(buf + *to, tmp, r + 1);
      *to = *to + r;

      j++;
    }
  return j;
}

/*
 * sc_regex_build_0
 *
 * if the end of the unspecified content ends with a non alnum, and this
 * separator is not found within the boundaries, then output a match
 * that is anything without that separator.
 *
 * because this segment of the regex only says that a specific character
 * class is not allowed, the score only increases by 1.
 */
static size_t sc_regex_build_0(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0, r;
  char tmp[8];
  char sep;
  int j, x = rb->x;

  /* does not apply to literal, IP address, geo, or digit portions */
  assert(bits[x] >= BIT_TYPE_MIN); assert(bits[x] <= BIT_TYPE_MAX);
  if(bits[x] != BIT_TYPE_SKIP && bits[x] != BIT_TYPE_CAPTURE)
    return 0;

  /* does not apply if there is no dot or dash separator at the end */
  sep = name[bits[x+2]+1];
  if(sep == '\0')
    sep = '.';
  if(isalnum((unsigned char)sep) != 0)
    return 0;

  /* skip over any dashes and dots at the start of the string */
  if((j = sc_regex_build_skip(name, rb->o, buf, len, &to)) > bits[x+2])
    return 0;

  /* determine if separator at end of string is within */
  if(char_within(name, j, bits[x+2], sep) != 0)
    return 0;
  if((r = re_escape(tmp, sizeof(tmp), sep)) == 0)
    return 0;

  /* string_concat(buf, len, &to, "[^%s]+", tmp); */
  if(len < 4 + r + 1)
    return 0;
  buf[to++] = '['; buf[to++] = '^';
  memcpy(buf+to, tmp, r); to += r;
  buf[to++] = ']'; buf[to++] = '+';
  buf[to] = '\0';

  *o = bits[x+2] + 1;
  *score += 1;
  return to;
}

/*
 * sc_regex_build_1
 *
 * if the start of the unspecified content starts with a non alnum, and
 * this separator is not found within the boundaries, then output a match
 * that is anything without that separator.
 *
 * because this segment of the regex only says that a specific character
 * class is not allowed, the score only increases by 1 for each character
 * class exclusion
 */
static size_t sc_regex_build_1(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0, r;
  char tmp[8];
  char sep;
  int x = rb->x, j, last_sep = -1;

  /* does not apply to literal, IP address, geo, or digit portions */
  assert(bits[x] >= BIT_TYPE_MIN); assert(bits[x] <= BIT_TYPE_MAX);
  if(bits[x] != BIT_TYPE_SKIP && bits[x] != BIT_TYPE_CAPTURE)
    return 0;

  /* cannot be working at the very start of the string */
  if(rb->o == 0)
    return 0;

  /* needs to be a separator */
  sep = name[rb->o-1];
  if(isalnum((unsigned char)sep) != 0)
    return 0;

  /*
   * go through segment, emitting character class exclusions each time
   * we come across an instance of the separator
   */
  j = rb->o;
  while(j <= bits[x+2])
    {
      if(name[j] == sep)
	{
	  if((r = re_escape(tmp, sizeof(tmp), sep)) == 0)
	    return 0;

	  /* string_concat(buf, len, &to, "[^%s]+", tmp); */
	  if(len - to < 4 + r + 1)
	    return 0;
	  buf[to++] = '['; buf[to++] = '^';
	  memcpy(buf+to, tmp, r); to += r;
	  buf[to++] = ']'; buf[to++] = '+';

	  *score += 1;
	  while(name[j] == sep && j <= bits[x+2])
	    {
	      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
		return 0;

	      /* string_concat(buf, len, &to, "%s", tmp);*/
	      if(len - to < r + 1)
		return 0;
	      memcpy(buf+to, tmp, r); to += r;

	      j++;
	    }
	  last_sep = j;
	}
      else j++;
    }

  if(last_sep != bits[x+2]+1)
    {
      if((r = re_escape(tmp, sizeof(tmp), sep)) == 0)
	return 0;

      /* string_concat(buf, len, &to, "[^%s]+", tmp); */
      if(len - to < 4 + r + 1)
	return 0;
      buf[to++] = '['; buf[to++] = '^';
      memcpy(buf+to, tmp, r); to += r;
      buf[to++] = ']'; buf[to++] = '+';

      *score += 1;
    }
  *o = bits[x+2] + 1;

  buf[to] = '\0';
  return to;
}

/*
 * sc_regex_build_2
 *
 * use .+ if we haven't already.
 *
 * the score does not increase.
 */
static size_t sc_regex_build_2(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  int x = rb->x;

  /* can only use .+ once */
  if(rb->any != 0)
    return 0;

  /* does not apply at the beginning of a string without an anchor */
  if(rb->off == 0 && p->dom != NULL)
    return 0;

  /* does not apply to literal, IP address, geo, or digit portions */
  assert(bits[x] >= BIT_TYPE_MIN); assert(bits[x] <= BIT_TYPE_MAX);
  if(bits[x] != BIT_TYPE_SKIP && bits[x] != BIT_TYPE_CAPTURE)
    return 0;

  /* string_concat(buf, len, &to, ".+"); */
  if(len < 3)
    return 0;
  buf[to++] = '.'; buf[to++] = '+';
  buf[to] = '\0';

  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_3
 *
 * build a component that uses separators to specify format of string
 *
 * the score increases by 1 for each character class exclusion embedded.
 */
static size_t sc_regex_build_3(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0, r;
  char tmp[8];
  char sep;
  int x = rb->x, j, last_sep = -1;

  /*
   * RB_FIRST_PUNC_END will build what this routine would have, so no
   * need to duplicate its work here
   */
  if(rb->o != bits[x+1])
    return 0;

  /* does not apply to literal, IP address, geo, or digit portions */
  assert(bits[x] >= BIT_TYPE_MIN); assert(bits[x] <= BIT_TYPE_MAX);
  if(bits[x] != BIT_TYPE_SKIP && bits[x] != BIT_TYPE_CAPTURE)
    return 0;

  /* skip over any dashes and dots at the start of the string */
  if((j = sc_regex_build_skip(name, bits[x+1], buf, len, &to)) > bits[x+2])
    return 0;

  /* according to arrangement of separators observed */
  while(j <= bits[x+2]+1)
    {
      if(isalnum((unsigned char)name[j]) == 0)
	{
	  if(name[j] == '\0')
	    sep = '.';
	  else
	    sep = name[j];
	  if((r = re_escape(tmp, sizeof(tmp), sep)) == 0)
	    return 0;
	  /* string_concat(buf,len,&to, "[^%s]+", tmp); */
	  if(len - to < 4 + r + 1)
	    return 0;
	  buf[to++] = '['; buf[to++] = '^';
	  memcpy(buf+to, tmp, r); to += r;
	  buf[to++] = ']'; buf[to++] = '+';

	  while(j != bits[x+2]+1 && isalnum((unsigned char)name[j]) == 0)
	    {
	      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
		return 0;

	      /* string_concat(buf, len, &to, "%s", tmp);*/
	      if(len - to < r + 1)
		return 0;
	      memcpy(buf+to, tmp, r); to += r;

	      j++;
	    }

	  /* keep track of where the last [^X]+ was used */
	  last_sep = j;

	  *score += 1;
	}
      j++;
    }

  /* if there is a part of the input string not covered then skip */
  if(last_sep != bits[x+2]+1)
    return 0;

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_4
 *
 * embed a literal
 *
 * the score increases by 4 for each character
 */
static size_t sc_regex_build_4(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0, r;
  char tmp[8];
  int x = rb->x, j;

  /* do not allow partial starts for now */
  if(rb->o != bits[x+1])
    return 0;

  /* only applies to literals */
  assert(bits[x] >= BIT_TYPE_MIN && bits[x] <= BIT_TYPE_MAX);
  if(bits[x] != BIT_TYPE_SKIP_LIT && bits[x] != BIT_TYPE_CAPTURE_LIT)
    return 0;

  for(j=bits[x+1]; j <= bits[x+2]; j++)
    {
      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
	return 0;

      /* string_concat(buf, len, &to, "%s", tmp); */
      if(len - to < r + 1)
	return 0;
      memcpy(buf+to, tmp, r); to += r;
      *score += 4;
    }

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_5_dec
 *
 * embed an IPv4 address literal
 *
 * the score increases by 3 for each portion broken by a non alnum
 */
static size_t sc_regex_build_5_dec(const char *name, const sc_rebuild_p_t *p,
				   const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  const char *ptr;
  char tmp[8];
  size_t to = 0, r;
  int x = rb->x;

  ptr = name + bits[x+1];
  while(ptr < name + bits[x+2] + 1)
    {
      /* string_concat(buf, len, &to, "\\d+"); */
      if(len - to < 4)
	return 0;
      buf[to++] = '\\'; buf[to++] = 'd'; buf[to++] = '+';

      while(isdigit((unsigned char)*ptr) != 0)
	ptr++;
      while(ptr < name + bits[x+2] && isdigit((unsigned char)*ptr) == 0)
	{
	  if((r = re_escape(tmp, sizeof(tmp), *ptr)) == 0)
	    return 0;

	  /* string_concat(buf, len, &to, "%s", tmp); */
	  if(len - to < r + 1)
	    return 0;
	  memcpy(buf+to, tmp, r); to += r;

	  ptr++;
	}
      *score += 3;
    }

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_5_hex
 *
 * embed an address literal using hex
 *
 * the score increases by 3 for each portion broken by a non alnum
 */
static size_t sc_regex_build_5_hex(const char *name, const sc_rebuild_p_t *p,
				   const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  const char *ptr;
  char tmp[8];
  size_t to = 0, r;
  int x = rb->x;

  ptr = name + bits[x+1];
  while(ptr < name + bits[x+2] + 1)
    {
      /* string_concat(buf, len, &to, "[a-f\\d]+"); */
      if(len - to < 9)
	return 0;
      buf[to++] = '['; buf[to++] = 'a'; buf[to++] = '-'; buf[to++] = 'f';
      buf[to++] = '\\'; buf[to++] = 'd'; buf[to++] = ']'; buf[to++] = '+';

      while(ishex(*ptr) != 0)
	ptr++;
      while(ishex(*ptr) == 0 && ptr < name + bits[x+2])
	{
	  if((r = re_escape(tmp, sizeof(tmp), *ptr)) == 0)
	    return 0;

	  /* string_concat(buf, len, &to, "%s", tmp); */
	  if(len - to < r + 1)
	    return 0;
	  memcpy(buf+to, tmp, r); to += r;

	  ptr++;
	}
      *score += 3;
    }

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_5
 *
 * embed an IP address literal
 */
static size_t sc_regex_build_5(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  int x = rb->x;

  /* do not allow partial starts for now */
  if(rb->o != bits[x+1])
    return 0;

  /* only applies to IP literals */
  assert(bits[x] >= BIT_TYPE_MIN && bits[x] <= BIT_TYPE_MAX);
  if(bits[x] == BIT_TYPE_IP_DEC)
    return sc_regex_build_5_dec(name, p, rb, score, o);
  else if(bits[x] == BIT_TYPE_IP_HEX)
    return sc_regex_build_5_hex(name, p, rb, score, o);

  return 0;
}

/*
 * sc_regex_build_6
 *
 * if the part of the string we are concerned with contains only digits,
 * then output \d+.
 *
 * the score increases by 3 as this is a specific formation.
 */
static size_t sc_regex_build_6(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0, r;
  int digit = 0, j, x = rb->x;
  char tmp[8];

  /* do not allow partial starts for now */
  if(rb->o != bits[x+1])
    return 0;

  /* does not apply to literal, IP address, geo, or digit portions */
  assert(bits[x] >= BIT_TYPE_MIN); assert(bits[x] <= BIT_TYPE_MAX);
  if(bits[x] != BIT_TYPE_SKIP && bits[x] != BIT_TYPE_CAPTURE)
    return 0;

  /* skip over any dashes and dots at the start of the string */
  if((j = sc_regex_build_skip(name, bits[x+1], buf, len, &to)) > bits[x+2])
    return 0;

  /* does the string begin with a sequence of digits? */
  while(j <= bits[x+2])
    {
      if(isdigit((unsigned char)name[j]) == 0)
	break;
      digit++;
      j++;
    }

  /* if digits, concatenate and score */
  if(digit == 0)
    return 0;

  /* string_concat(buf, len, &to, "\\d+"); */
  *score += 3;
  if(len - to < 4)
    return 0;
  buf[to++] = '\\'; buf[to++] = 'd'; buf[to++] = '+';

  /* end with punctuation */
  while(j <= bits[x+2])
    {
      if(name[j] == '\0')
	break;
      if(isalnum((unsigned char)name[j]) != 0)
	return 0;
      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
	return 0;
      /* string_concat(buf, len, &to, "%s", tmp); */
      if(len - to < r + 1)
	return 0;
      memcpy(buf+to, tmp, r); to += r;

      j++;
    }

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_7
 *
 * output separator segment but only until the end of the next segment.
 *
 * the score increases by 1 because it embeds a single character class
 * exclusion.
 */
static size_t sc_regex_build_7(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0, r;
  char tmp[8];
  int j, x = rb->x;

  /* does not apply to literal, IP address, geo, or digit portions */
  assert(bits[x] >= BIT_TYPE_MIN); assert(bits[x] <= BIT_TYPE_MAX);
  if(bits[x] != BIT_TYPE_SKIP && bits[x] != BIT_TYPE_CAPTURE)
    return 0;

  /* skip over any dashes and dots at the start of the string */
  if((j = sc_regex_build_skip(name, rb->o, buf, len, &to)) > bits[x+2])
    return 0;

  /* find the next separator in this portion of the string */
  while(j <= bits[x+2]+1)
    {
      if(isalnum((unsigned char)name[j]) == 0)
	break;
      j++;
    }

  /* if the next separator isn't until after the end of the component, skip */
  if(j > bits[x+2]+1)
    return 0;

  /* embed the regex component */
  if((r = re_escape(tmp, sizeof(tmp), name[j] == '\0' ? '.' :  name[j])) == 0)
    return 0;

  /* string_concat(buf, len, &to, "[^%s]+", tmp); */
  if(len - to < 4 + r + 1)
    return 0;
  buf[to++] = '['; buf[to++] = '^';
  memcpy(buf+to, tmp, r); to += r;
  buf[to++] = ']'; buf[to++] = '+';
  buf[to] = '\0';

  *score += 1;
  *o = j;
  return to;
}

/*
 * sc_regex_build_8
 *
 * output \d+ to match an ASN embedded in the hostname.
 *
 * the score increases by 3 as this is a specific formation.
 */
static size_t sc_regex_build_8(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  int x = rb->x;

  /* do not allow partial starts for now */
  if(rb->o != bits[x+1])
    return 0;

  if(bits[x] != BIT_TYPE_CAPTURE_DIGIT && bits[x] != BIT_TYPE_SKIP_DIGIT)
    return 0;

  /*
   * skip over any dashes and dots at the start of the string
   * XXX: figure out if this is even necessary
   */
  if(sc_regex_build_skip(name, bits[x+1], buf, len, &to) > bits[x+2])
    return 0;

  /* string_concat(buf, len, &to, "\\d+"); */
  if(len - to < 4)
    return 0;
  buf[to++] = '\\'; buf[to++] = 'd'; buf[to++] = '+';
  buf[to] = '\0';

  *o = bits[x+2] + 1;
  *score += 3;

  return to;
}

/*
 * sc_regex_build_9
 *
 * match a geocode embedded in the hostname.
 *
 * the score increases by 3 as this is a specific formation.
 */
static size_t sc_regex_build_9(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  size_t num_chars = 0;
  int j, x = rb->x;
  char punc = '\0';

  /* do not allow partial starts for now */
  if(rb->o != bits[x+1] && p->dom != NULL)
    return 0;

  /* Cannot be the first addition to the regex. */
  if(rb->off == 0)
    return 0;

  /* only applies to geo components */
  if(isgeo(bits[x]) == 0)
    return 0;

  /*
   * skip over any dashes and dots at the start of the string
   * XXX: figure out if this is even necessary
   */
  if((j = sc_regex_build_skip(name, bits[x+1], buf, len, &to)) > bits[x+2])
    return 0;

  if(bits[x] == BIT_TYPE_GEO_PLACE)
    {
      while(j <= bits[x+2])
	{
	  if(isdigit((unsigned char)name[j]) != 0)
	    return 0;
	  if(name[j] != punc && isalpha((unsigned char)name[j]) == 0)
	    {
	      if(punc != '\0')
		return 0;
	      punc = name[j];
	    }
	  j++;
	}

      if(punc != '\0')
	{
	  if(len - to < 9)
	    return 0;
	}
      else
	{
	  if(len - to < 7)
	    return 0;
	}
      buf[to++] = '['; buf[to++] = 'a'; buf[to++] = '-'; buf[to++] = 'z';
      if(punc != '\0')
	{
	  if(re_escape_c(punc) != 0 || punc == '-')
	    buf[to++] = '\\';
	  buf[to++] = punc;
	}
      buf[to++] = ']'; buf[to++] = '+'; buf[to] = '\0';
    }
  else if(bits[x] == BIT_TYPE_GEO_FACILITY)
    {
      /* string_concat(buf, len, &to, "\d+[a-z]+"); */
      if(len - to < 10)
	return 0;
      buf[to++] = '\\'; buf[to++] = 'd'; buf[to++] = '+'; buf[to++] = '[';
      buf[to++] = 'a'; buf[to++] = '-'; buf[to++] = 'z'; buf[to++] = ']';
      buf[to++] = '+'; buf[to] = '\0';
    }
  else
    {
      num_chars = bits[x+2] - bits[x+1] + 1;
      assert(num_chars > 0 && num_chars < 10);

      /* string_concat(buf, len, &to, "[a-z]{3}"); or [a-z]{4} or [a-z]{6} */
      if(len - to < 9)
	return 0;
      buf[to++] = '['; buf[to++] = 'a'; buf[to++] = '-'; buf[to++] = 'z';
      buf[to++] = ']'; buf[to++] = '{';
      buf[to++] = '0' + num_chars;
      buf[to++] = '}'; buf[to] = '\0';
    }

  *o = bits[x+2] + 1;
  *score += 3;

  return to;
}

static sc_rebuild_t *sc_rebuild_push(slist_t *list, char *buf, size_t off,
				     int score, size_t f, int x, int o,
				     int any, int capc)
{
  sc_rebuild_t *rb;

  if((rb = malloc(sizeof(sc_rebuild_t))) == NULL ||
     slist_head_push(list, rb) == NULL)
    {
      if(rb != NULL) free(rb);
      return NULL;
    }
  if(off > 0)
    memcpy(rb->buf, buf, off);
  rb->off = off;
  rb->score = score;
  rb->f = f;
  rb->x = x;
  rb->o = o;
  rb->any = any;
  rb->capc = capc;
  return rb;
}

#define RB_BASE \
  (RB_SEG_PUNC_START | RB_SEG_PUNC_END | RB_SEG_ANY | RB_SEG_PUNC)

#define RB_SEG_PUNC_START 0x0001
#define RB_SEG_PUNC_END   0x0002
#define RB_SEG_ANY        0x0004
#define RB_SEG_PUNC       0x0008
#define RB_SEG_LITERAL    0x0010
#define RB_SEG_LITERAL_IP 0x0020
#define RB_SEG_DIGIT      0x0040
#define RB_FIRST_PUNC_END 0x0080
#define RB_SEG_DIGIT_SPEC 0x0100
#define RB_SEG_GEO        0x0200

/*
 * sc_regex_build
 *
 * given a string (in name) and instructions (in bits/bitc) construct
 * regular expressions that meet the instructions.  if a suffix is supplied
 * (in domain) append the suffix to the end of the regex.  place unique
 * regular expressions in the tree.
 */
static int sc_regex_build(splaytree_t *tree, const char *name, sc_domain_t *dom,
			  uint16_t build_mask, const int *bits, int bitc)
{
  static const sc_regex_build_t func[] = {
    sc_regex_build_0, /* 0x0001 : non alnum seperator at end */
    sc_regex_build_1, /* 0x0002 : non alnum separator at start */
    sc_regex_build_2, /* 0x0004 : use .+ */
    sc_regex_build_3, /* 0x0008 : match according to separators */
    sc_regex_build_4, /* 0x0010 : embed literal */
    sc_regex_build_5, /* 0x0020 : embed IP address literal */
    sc_regex_build_6, /* 0x0040 : use \d+ where appropriate */
    sc_regex_build_7, /* 0x0080 : non alnum seperator at first non-alnum */
    sc_regex_build_8, /* 0x0100 : use \d+ where specified */
    sc_regex_build_9, /* 0x0200 : use [a-z]{X} for a geocode */
  };

  sc_rebuild_p_t p;
  sc_rebuild_t *rb = NULL;
  slist_t *stack = NULL;
  int k, x, o, any, rc = -1;
  sc_regex_t *re;
  char buf[2048], tmp[2048];
  int score, capc;
  size_t off, to, r;
  uint8_t *geotypes = NULL;

  if((stack = slist_alloc()) == NULL)
    goto done;

  /*
   * if we are building regex components that are to be used in a
   * larger regex, do not prepend the anchor.
   */
  if(dom != NULL)
    {
      /* XXX: consider a score of 1 */
      if(sc_rebuild_push(stack, "^", 1, 0, 0, 0, 0, 0, 0) == NULL)
	goto done;
      if(bits[0] == BIT_TYPE_SKIP)
	{
	  assert(bitc > 3); assert(bits[3] != BIT_TYPE_SKIP);
	  if(sc_rebuild_push(stack, "", 0, 0, 0, 3, bits[3+1], 0, 0) == NULL)
	    goto done;
	}
    }
  else
    {
      if(sc_rebuild_push(stack, "", 0, 0, 0, 0, 0, 0, 0) == NULL)
	goto done;
    }

  p.bits = bits;
  p.bitc = bitc;
  p.dom = dom;
  p.buf = tmp;
  p.len = sizeof(tmp);

  for(;;)
    {
      rb = slist_head_item(stack);
      while(rb != NULL)
	{
	  if(rb->f < sizeof(func)/sizeof(sc_regex_build_t))
	    break;

	  slist_head_pop(stack);
	  free(rb);
	  rb = slist_head_item(stack);
	}
      if(rb == NULL)
	break;

      /* do we apply this build function? */
      if(((1 << rb->f) & build_mask) == 0 || func[rb->f] == NULL)
	{
	  rb->f++;
	  continue;
	}

      score = rb->score;
      o = rb->o;
      to = func[rb->f](name, &p, rb, &score, &o);
      rb->f++;
      if(to == 0)
	continue;

      memcpy(buf, rb->buf, sizeof(buf));
      off = rb->off;
      x = rb->x;
      capc = rb->capc;
      any = strcmp(tmp, ".+") == 0 ? 1 : rb->any;

      /* if we are at the start of a capture */
      if((rb->o == bits[x+1] && iscapture(bits[x]) == 1 &&
	  (x == 0 || iscapture(bits[x-3]) == 0)) ||
	 isgeo(bits[x]) != 0)
	{
	  /* string_concat(buf, sizeof(buf), &off, "("); */
	  if(sizeof(buf) - off < 1)
	    goto done;
	  buf[off++] = '(';
	}

      /* string_concat(buf, sizeof(buf), &off, "%s", tmp); */
      if(sizeof(buf) - off < to)
	goto done;
      memcpy(buf+off, tmp, to); off += to;

      /* if we are at the end of a capture */
      if((o == bits[x+2]+1 && iscapture(bits[x]) == 1 &&
	  (x+3 == bitc || iscapture(bits[x+3]) == 0)) ||
	 isgeo(bits[x]) != 0)
	{
	  /* string_concat(buf, sizeof(buf), &off, ")"); */
	  if(sizeof(buf) - off < 1)
	    goto done;
	  buf[off++] = ')';
	  capc++;
	}

      while(name[o] != '\0' && (x+3 == bitc || o < bits[x+3+1]) &&
	    isalnum((unsigned char)name[o]) == 0)
	{
	  if((r = re_escape(tmp, sizeof(tmp), name[o])) == 0)
	    goto done;
	  /* string_concat(buf, sizeof(buf), &off, "%s", tmp); */
	  if(sizeof(buf) - off < r)
	    goto done;
	  memcpy(buf+off, tmp, r); off += r;
	  o++;
	}

      if(x + 3 == bitc && name[o] == '\0')
	{
	  if(dom != NULL)
	    {
	      /* string_concat(buf,sizeof(buf),&off, "\\.%s$", dom->escape); */
	      if(sizeof(buf) - off < 4 + dom->escapel)
		goto done;
	      buf[off++] = '\\'; buf[off++] = '.';
	      memcpy(buf+off, dom->escape, dom->escapel); off += dom->escapel;
	      buf[off++] = '$'; buf[off++] = '\0';
	    }
	  else
	    {
	      if(sizeof(buf) - off < 1)
		goto done;
	      buf[off++] = '\0';
	    }

	  if(do_learngeo != 0)
	    {
	      if((geotypes = malloc_zero(sizeof(uint8_t) * capc)) == NULL)
		return -1;
	      r = 0;
	      for(k=0; k<bitc; k+=3)
		if(isgeo(bits[k]) != 0)
		  geotypes[r++] = bits_to_geohint_type(bits[k]);
	    }

	  if(sc_regex_find(tree, buf, capc, geotypes) != NULL)
	    {
	      if(geotypes != NULL) { free(geotypes); geotypes = NULL; }
	      continue;
	    }
	  if(do_debug != 0 && threadc <= 1)
	    {
	      printf("%s %s", buf, name);
	      for(k=0; k<bitc; k+=3)
		printf(" %d %d %d", bits[k], bits[k+1], bits[k+2]);
	      printf("\n");
	    }
	  if((re = sc_regex_get(tree, buf, capc, geotypes)) == NULL)
	    goto done;
	  re->score = score;
	  re->dom = dom;

	  if(geotypes != NULL)
	    {
	      free(geotypes);
	      geotypes = NULL;
	    }
	  continue;
	}

      if(o > bits[x+2])
	x += 3;
      assert(x < bitc);
      if(sc_rebuild_push(stack, buf, off, score, 0, x, o, any, capc) == NULL)
	goto done;
    }

  rc = 0;
 done:
  if(stack != NULL) slist_free_cb(stack, (slist_free_t)free);
  if(geotypes != NULL) free(geotypes);
  return rc;
}

/*
 * sc_regex_asn_lcs
 *
 * A modification of sc_regex_lcs which will treat the location of ASNs
 * differently -- the longest substring will be
 *
 * Generate regexes for the longest common substring.
 * param tree: Tree to put output on.
 * param dom: Domain that the interfaces belong to.
 * param S, T: A pair of interfaces from the same domain.
 * returns: 0 if successful.
 */
static int sc_regex_asn_lcs(splaytree_t *tree, sc_domain_t *dom,
			    sc_ifacedom_t *S, sc_ifacedom_t *T)
{
  static const uint16_t mask =
    RB_BASE | RB_FIRST_PUNC_END | RB_SEG_LITERAL | RB_SEG_DIGIT_SPEC;
  size_t cc[2], *L_array = NULL;
  slist_t *L = NULL;
  int i, j, Lc, rc = -1;
  const sc_ifacedom_t *R;
  int *bits = NULL, bitc;
  sc_lcs_pt_t *pt;
  slist_node_t *sn;

  /*
   * Expand literals outwards around the ASN to see how much of the
   * structure is shared between the two interfaces.
   */
  if((L = lcs_asn(S, T)) == NULL)
    goto done;

  Lc = slist_count(L) * 2;
  if(Lc > 0 && (L_array = malloc(sizeof(size_t) * Lc)) == NULL)
    goto done;

  for(i=0; i<2; i++)
    {
      /*
       * two identical loops, which only differ on which of the two
       * interface strings under consideration
       */
      j = 0;
      if(i == 0)
	{
	  R = S;
	  for(sn=slist_head_node(L); sn != NULL; sn=slist_node_next(sn))
	    {
	      pt = slist_node_item(sn);
	      L_array[j++] = pt->S_start;
	      L_array[j++] = pt->S_end;
	    }
	}
      else
	{
	  R = T;
	  for(sn=slist_head_node(L); sn != NULL; sn=slist_node_next(sn))
	    {
	      pt = slist_node_item(sn);
	      L_array[j++] = pt->T_start;
	      L_array[j++] = pt->T_end;
	    }
	}

      cc[0] = R->iface->as_s;
      cc[1] = R->iface->as_e;
      if(pt_to_bits(R->label,R->len, cc,2, L_array,Lc, cc,2, &bits,&bitc) == 0)
	{
	  if(sc_regex_build(tree, R->label, dom, mask, bits, bitc) != 0)
	    goto done;
	}
      free(bits); bits = NULL;
    }

  rc = 0;

 done:
  if(L != NULL) slist_free_cb(L, (slist_free_t)sc_lcs_pt_free);
  if(L_array != NULL) free(L_array);
  if(bits != NULL) free(bits);
  return rc;
}

static int sc_regex_lcs2(splaytree_t *tree, sc_domain_t *dom,
			 const sc_ifacedom_t *R, size_t *X_array, int Xc)
{
  static const uint16_t mask = RB_BASE | RB_FIRST_PUNC_END;
  int *bits = NULL, bitc, rc = -1; size_t ip[2];

  if(pt_to_bits(R->label,R->len, X_array,Xc, NULL,0, NULL,0, &bits,&bitc) == 0)
    {
      if(sc_regex_build(tree, R->label, dom, mask, bits, bitc) != 0)
	goto done;
    }
  if(bits != NULL)
    {
      free(bits);
      bits = NULL;
    }

  /* if there is no IP literal, or the literal was not captured */
  if((R->iface->flags & SC_IFACE_FLAG_IP) == 0)
    return 0;
  ip[0] = R->iface->ip_s; ip[1] = R->iface->ip_e;
  if(pt_overlap(X_array, Xc, ip, 2) == 0)
    return 0;

  /* remove the IP literal from the capture */
  if(pt_to_bits_noip(R, X_array, Xc, &bits, &bitc) == 0 && bitc > 0)
    {
      if(sc_regex_build(tree, R->label, dom, mask, bits, bitc) != 0)
	goto done;
    }
  if(bits != NULL)
    {
      free(bits);
      bits = NULL;
    }
  rc = 0;

 done:
  if(bits != NULL) free(bits);
  return rc;
}

/*
 * sc_regex_lcs
 *
 * Generate regexes for the longest common substring.
 * param tree: Tree to put output on.
 * param dom: Domain that the interfaces belong to.
 * param S, T: A pair of interfaces from the same domain.
 * returns: 0 if successful.
 */
static int sc_regex_lcs(splaytree_t *tree, sc_domain_t *dom,
			const sc_ifacedom_t *S, const sc_ifacedom_t *T)
{
  size_t *X_array = NULL;
  slist_t *X = NULL;
  int i, Xc, rc = -1;
  const sc_ifacedom_t *R;
  sc_css_t *X_css = NULL;
  sc_ptrc_t *ptrc = NULL;
  slist_t *X_list = NULL;

  /* determine the parts of strings in common */
  if((X = lcs(S->label, 0, T->label, 0, 2)) == NULL)
    goto done;

  /* trim substrings so that they start and end on a dot or dash boundary */
  lcs_trim(X, S->label, T->label);

  /* skip this pair of strings if no matches, or matches out of order */
  if(slist_count(X) == 0 || lcs_check(X) == 0)
    {
      rc = 0;
      goto done;
    }

  if((X_css = sc_css_alloc_lcs(X, S->label)) == NULL)
    goto done;
  Xc = X_css->cssc * 2;
  if((X_array = malloc(sizeof(size_t) * Xc)) == NULL)
    goto done;
  if((X_list = slist_alloc()) == NULL)
    goto done;

  for(i=0; i<2; i++)
    {
      /*
       * two identical loops, which only differ on which of the two
       * interface strings under consideration
       */
      if(i == 0)
	R = S;
      else
	R = T;

      if(sc_css_match(X_css, R->label, X_array, 1) == 0)
	continue;

      if(sc_regex_lcs2(tree, dom, R, X_array, Xc) != 0)
	goto done;

      if(Xc > 2)
	{
	  if(sc_regex_pt_decons(X_list, X_array, Xc) != 0)
	    goto done;
	  while((ptrc = slist_head_pop(X_list)) != NULL)
	    {
	      if(sc_regex_lcs2(tree, dom, R, (size_t *)ptrc->ptr, ptrc->c) != 0)
		goto done;
	      sc_ptrc_free2(ptrc); ptrc = NULL;
	    }
	}
    }

  rc = 0;

 done:
  if(X_list != NULL) slist_free_cb(X_list, (slist_free_t)sc_ptrc_free2);
  if(X != NULL) slist_free_cb(X, (slist_free_t)sc_lcs_pt_free);
  if(X_css != NULL) sc_css_free(X_css);
  if(X_array != NULL) free(X_array);
  return rc;
}

static void sc_routerload_reset(sc_routerload_t *rl)
{
  slist_empty_cb(rl->ifaces, (slist_free_t)sc_iface_free);
  rl->asn = 0;
  rl->id = 0;
  rl->flags = 0;
  return;
}

static int sc_router_id_cmp(const sc_router_t *a, const sc_router_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static int sc_router_istraining(sc_router_t *rtr)
{
  if(do_learnalias != 0)
    {
      if(rtr->ifacec > 1)
	return 1;
    }
  else if(do_learnasn != 0 || do_learnasnames != 0)
    {
      if(rtr->asn != 0)
	return 1;
    }
  else if(do_learngeo != 0)
    {
      if(rtr->rtts != NULL)
	return 1;
    }
  return 0;
}

static void sc_router_free(sc_router_t *rtr)
{
  size_t i;

  if(rtr->ifaces != NULL)
    {
      for(i=0; i<rtr->ifacec; i++)
	sc_iface_free(rtr->ifaces[i]);
      free(rtr->ifaces);
    }

  if(rtr->rtts != NULL)
    free(rtr->rtts);

  free(rtr);
  return;
}

/*
 * sc_router_finish
 *
 * a list of router interfaces has been assembled.  take the list of
 * interfaces and build the router, placing the router onto each
 * applicable domain
 */
static int sc_router_finish(sc_routerload_t *rl)
{
  splaytree_t *dctree = NULL; /* of sc_css_t */
  sc_router_t *rtr = NULL;
  sc_routerdom_t *rd = NULL;
  sc_iface_t *iface;
  sc_css_t *dc;
  sc_domain_t *dom;
  slist_node_t *sn; /* of sc_iface_t */
  size_t i, c;
  int free_rtr = 1, namec = 0;
  slist_t *tmp = NULL;
  const char *suffix;

  /* count how many interfaces have names.  if none, skip over */
  for(sn=slist_head_node(rl->ifaces); sn != NULL; sn=slist_node_next(sn))
    {
      iface = slist_node_item(sn);
      /* skip over domains that we're not interested in */
      if((suffix = sc_suffix_find(iface->name)) == NULL ||
	 (do_learnasnames == 0 && domain_eval != NULL &&
	  strcmp(domain_eval, suffix) != 0))
	continue;
      namec++;
    }
  if(namec == 0)
    {
      sc_routerload_reset(rl);
      return 0;
    }

  /* to start with, build the router and put it on the global list */
  c = slist_count(rl->ifaces);
  if((rtr = malloc_zero(sizeof(sc_router_t))) == NULL ||
     (rtr->ifaces = malloc_zero(sizeof(sc_iface_t *) * c)) == NULL)
    goto err;
  rtr->asn   = rl->asn;
  rtr->id    = rl->id;
  rtr->flags = rl->flags;
  while((iface = slist_head_pop(rl->ifaces)) != NULL)
    {
      rtr->ifaces[rtr->ifacec++] = iface;
      iface->rtr = rtr;
    }
  array_qsort((void **)rtr->ifaces, rtr->ifacec,
	      (array_cmp_t)sc_iface_suffix_cmp);
  if(slist_tail_push(router_list, rtr) == NULL)
    goto err;
  free_rtr = 0;

  /* figure out all the domains the router can be mapped to */
  if((dctree=splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp))==NULL)
    goto err;

  for(i=0; i<rtr->ifacec; i++)
    {
      /* use the public suffix list to figure out the domain */
      iface = rtr->ifaces[i];
      if((suffix = sc_suffix_find(iface->name)) == NULL)
	continue;

      /* skip over domains that we're not interested in */
      if(do_learnasnames == 0 && domain_eval != NULL &&
	 strcmp(domain_eval, suffix) != 0)
	continue;

      /* we only want to add the router once per domain */
      if((dc = sc_css_get_str(dctree, suffix)) == NULL)
	goto err;
      dc->count++;
    }

  /*
   * put the unique domains into a list, and push the router onto the list
   * of routers for the domain
   */
  if((tmp = slist_alloc()) == NULL)
    goto err;
  splaytree_inorder(dctree, tree_to_slist, tmp);
  splaytree_free(dctree, NULL);
  while((dc = slist_head_pop(tmp)) != NULL)
    {
      if((dom = sc_domain_get(dc->css)) == NULL)
	goto err;

      /* figure out how many interfaces within the domain the router has */
      c = 0;
      for(i=0; i<rtr->ifacec; i++)
	{
	  iface = rtr->ifaces[i];
	  if((suffix = sc_suffix_find(iface->name)) == NULL ||
	     strcmp(suffix, dc->css) != 0)
	    continue;
	  c++;
	}

      /*
       * allocate a sc_routerdom_t structure which only has the interfaces
       * relevant to the considered suffix
       */
      if((rd = malloc_zero(sizeof(sc_routerdom_t))) == NULL ||
	 (rd->ifaces = malloc_zero(sizeof(sc_ifacedom_t *) * c)) == NULL)
	goto err;
      rd->ifacec = c;
      rd->rtr = rtr;
      c = 0;
      for(i=0; i<rtr->ifacec; i++)
	{
	  iface = rtr->ifaces[i];
	  if((suffix = sc_suffix_find(iface->name)) == NULL ||
	     strcmp(suffix, dc->css) != 0)
	    continue;
	  if((rd->ifaces[c] = sc_ifacedom_alloc(iface, dom, suffix)) == NULL)
	    goto err;
	  rd->ifaces[c]->rd = rd;
	  c++;
	}

      if(slist_tail_push(dom->routers, rd) == NULL)
	goto err;
      rd = NULL;

      sc_css_free(dc);
    }
  slist_free(tmp);
  sc_routerload_reset(rl);
  return 0;

 err:
  if(rtr != NULL && free_rtr != 0) sc_router_free(rtr);
  if(rd != NULL) sc_routerdom_free(rd);
  sc_routerload_reset(rl);
  return -1;
}

static int router_file_line(char *line, void *param)
{
  sc_routerload_t *rl = param;
  sc_iface_t *iface = NULL;
  long long ll;
  char *ip, *ptr;
  char name[1024];

  if(line[0] == '#')
    {
      ptr = line + 1;
      while(*ptr == ' ')
	ptr++;
      if(strncasecmp(ptr, "node2as:", 8) == 0)
	{
	  ptr += 8;
	  while(*ptr == ' ')
	    ptr++;
	  if(string_tollong(ptr, &ll, NULL, 10) == 0)
	    {
	      rl->asn = ll;
	      rl->flags |= SC_ROUTER_FLAG_ASN;
	    }
	}
      else if(strncasecmp(ptr, "node2id:", 8) == 0)
	{
	  ptr += 8;
	  while(*ptr == ' ')
	    ptr++;
	  if(string_tollong(ptr, &ll, NULL, 10) == 0)
	    {
	      rl->id = ll;
	      rl->flags |= SC_ROUTER_FLAG_ID;
	    }
	}
      return 0;
    }

  if(line[0] == '\0')
    {
      if(sc_router_finish(rl) != 0)
	return -1;
      return 0;
    }

  ip = line;
  ptr = line;
  while(*ptr != '\0' && isspace((unsigned char)*ptr) == 0)
    ptr++;
  if(*ptr != '\0')
    {
      *ptr = '\0'; ptr++;
      while(isspace((unsigned char)*ptr) != 0)
	ptr++;
      hex_toascii(name, sizeof(name), ptr);
    }
  else name[0] = '\0';

  if((iface = sc_iface_alloc(ip, name)) == NULL ||
     slist_tail_push(rl->ifaces, iface) == NULL)
    goto err;

  return 0;

 err:
  return -1;
}

static int sibling_file_line(char *line, void *param)
{
  slist_t *list = param;
  sc_as2org_t *a2o = NULL;
  char *asn, *ptr;
  long long ll;
  int last = 0;

  if(line[0] == '#')
    return 0;

  asn = ptr = line;

  for(;;)
    {
      while(isdigit((unsigned char)*ptr) != 0)
	ptr++;
      if(*ptr == '\0')
	last = 1;
      else if(isspace((unsigned char)*ptr) == 0)
	goto err;
      *ptr = '\0'; ptr++;

      /* build an as2org node */
      if(string_tollong(asn, &ll, NULL, 10) != 0)
	goto err;
      if((a2o = malloc(sizeof(sc_as2org_t))) == NULL)
	goto err;
      a2o->asn = ll;
      a2o->org = sibling_id;
      if(slist_tail_push(list, a2o) == NULL)
	goto err;
      a2o = NULL;

      /* continue onto the next ASN in this org */
      if(last != 0)
	break;
      while(isspace((unsigned char)*ptr) != 0)
	ptr++;
      if(*ptr == '\0')
	break;

      asn = ptr;
    }

  sibling_id++;
  return 0;

 err:
  if(a2o != NULL) free(a2o);
  return -1;
}

static void dump_0_regex_geomap(slist_t *m2h_list)
{
  slist_node_t *sn;
  sc_geomap2hint_t *m2h;
  char buf[256];

  for(sn=slist_head_node(m2h_list); sn != NULL; sn=slist_node_next(sn))
    {
      m2h = slist_node_item(sn);
      if(m2h->tp_c == 0 && m2h->fp_c > 0)
	continue;
      printf(" %s -> ", sc_geomap_tostr(&m2h->map, buf, sizeof(buf)));
      if(m2h->hint == NULL)
	{
	  printf("???\n");
	  continue;
	}
      printf("%s%s\n", sc_geohint_place_tostr(m2h->hint, buf, sizeof(buf)),
	     m2h->hint->learned == 0 ? "" : " ***");
    }
  return;
}

static int dump_1(void)
{
  sc_domain_t *dom;
  sc_regex_t *re;
  slist_node_t *sn, *s2;
  char buf[512];
  int k, hdr;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if(slist_count(dom->regexes) < 1)
	continue;
      slist_qsort(dom->regexes, (slist_cmp_t)sc_regex_score_rank_cmp);
      hdr = 0;

      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  if(sc_regex_show(re) == 0)
	    continue;

	  if(hdr == 0)
	    {
	      printf("suffix %s\n", dom->domain);
	      hdr = 1;
	    }

	  for(k=0; k<re->regexc; k++)
	    {
	      if(k > 0) printf(" ");
	      printf("%s", re->regexes[k]->str);
	    }
	  printf(": %s", sc_regex_score_tostr(re, buf, sizeof(buf)));
	  if(do_learngeo != 0)
	    printf(", plan: %s", sc_regex_plan_tostr(re, buf, sizeof(buf)));
	  printf("\n");
	}
    }

  return 0;
}

static void dump_2_regex_iface(const sc_regex_t *re, sc_iface_t *iface,
			       char class, sc_rework_t *rew, sc_css_t *css,
			       sc_ifaceinf_t *ifi)
{
  char buf[256], *ptr;
  sc_as2tag_t *a2t;
  double distance;
  sc_rtt_t *sample;
  int x; size_t s;

  printf("{\"addr\":\"%s\"", scamper_addr_tostr(iface->addr,buf,sizeof(buf)));
  if(class != '\0')
    printf(", \"code\":\"%c\"", class);
  printf(", \"hostname\":\"");
  json_print(iface->name);
  printf("\"");
  if(rew != NULL)
    {
      printf(", \"span\":[");
      for(s=1; s<rew->m; s++)
	{
	  if(s > 1) printf(", ");
	  printf("%d, %d", (int)rew->ovector[2*s], (int)rew->ovector[(2*s)+1]);
	}
      printf("]");
    }
  else if(class == '~' && do_learnasn != 0 &&
	  (iface->flags & SC_IFACE_FLAG_AS) != 0)
    {
      printf(", \"span\":[%d, %d]", iface->as_s, iface->as_e+1);
    }
  else if(class == '~' && do_learnasnames != 0 && iface->asnamec > 0)
    {
      printf(", \"span\":[%d, %d]", iface->asnames[0], iface->asnames[1]+1);
      s = iface->asnames[1] - iface->asnames[0] + 1; assert(s < sizeof(buf));
      memcpy(buf, iface->name+iface->asnames[0], s); buf[s] = '\0';
      if((a2t = sc_as2tag_find(buf)) != NULL)
	printf(", \"name2asn\":%u", a2t->asn);
    }
  else if(class == '~' && do_learngeo != 0 && iface->geoc > 0)
    {
      printf(", \"span\":[");
      for(s=0; s<iface->geos[0].tagc; s++)
	{
	  if(s > 0) printf(", ");
	  printf("%d, %d", (int)iface->geos[0].tags[s].start,
		 iface->geos[0].tags[s].end + 1);
	}
      printf("]");
    }

  if(ifi != NULL && ifi->regex >= 0)
    printf(", \"regex\":%d", ifi->regex);

  if(class == '!' && do_learngeo != 0)
    {
      assert(ifi != NULL && re != NULL && ifi->geohint != NULL);
      x = sc_router_ooridx(iface->rtr, ifi->geohint, &sample); assert(x == 0);
      distance = sc_geohint_dist(sample->vp, ifi->geohint);
      printf(", \"fp\":[{\"loc\":\"%s\", \"rtt\":%u}]", sample->vp->code,
	     dist2rtt(distance));
    }

  if(css != NULL)
    {
      ptr = css->css;
      printf(", \"css\":[");
      for(x=0; x<css->cssc; x++)
	{
	  if(x > 0)
	    {
	      printf(", ");
	      ptr++;
	    }
	  printf("\"");
	  json_print(ptr);
	  printf("\"");
	  while(*ptr != '\0')
	    ptr++;
	}
      printf("]");

      if(do_learnasnames != 0 && (a2t = sc_as2tag_find(css->css)) != NULL)
	printf(", \"name2asn\":%u", a2t->asn);
    }

  printf("}");

  return;
}

static int dump_2_regex_alias(sc_domain_t *dom, sc_regex_t *re)
{
  sc_routercss_t **rnames = NULL, *rn;
  int rnamec = 0;
  slist_node_t *sn, *sn2;
  sc_rework_t *rew = NULL;
  sc_routerdom_t *rd;
  sc_iface_t *iface;
  sc_ifdptr_t *ifp;
  sc_ifacedom_t *ifd;
  sc_ifaceinf_t *ifi, *ifi2;
  sc_routerinf_t *ri;
  slist_t *ri_list = NULL;
  slist_t *ifp_list = NULL;
  splaytree_t *ifp_tree = NULL;
  splaytree_t *ri_tree = NULL;
  slist_t *appl_list = NULL;
  int i, r, x, ip;
  sc_css_t *last_css, *css = NULL;
  const char *suffix;
  char code;
  char buf[2048];
  int rc = -1;
  double randi;
  size_t s;

  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;

  /* take a pass through all routers, and decide on a name for each */
  rnamec = slist_count(dom->routers);
  if((rnames = sc_routercss_alias_alloc(dom->routers, rew)) == NULL)
    goto done;

  /* take another pass, getting all the interfaces within the suffix */
  if((ifp_tree = sc_ifdptr_tree(dom->routers)) == NULL)
    goto done;

  /* take a pass through the inferred routers, pairing inference with iface */
  if((ri_list = slist_alloc()) == NULL)
    goto done;
  if(sc_regex_alias_eval(re, ri_list) != 0)
    goto done;
  if(sc_ifdptr_tree_ri(ifp_tree, ri_list) != 0)
    goto done;

  if(do_ri != 0)
    {
      /* compute the Rand index if requested */
      if((ifp_list = slist_alloc()) == NULL)
	goto done;
      splaytree_inorder(ifp_tree, tree_to_slist, ifp_list);
      randi = randindex(ifp_list);
      slist_free(ifp_list); ifp_list = NULL;
    }
  else randi = 0;

  if(do_json == 0)
    {
      printf("%s: %d routers:", dom->domain, slist_count(dom->routers));
      for(i=0; i<re->regexc; i++)
	printf(" %s", re->regexes[i]->str);
      printf(" %s", sc_regex_score_tostr(re, buf, sizeof(buf)));
      if(do_ri != 0)
	printf(", ri %.2f", randi);
      printf("\n");
    }
  else
    {
      printf("{\"domain\":\"%s\", \"routerc\":%d",
	     dom->domain, slist_count(dom->routers));
      printf(", \"re\":[");
      for(i=0; i<re->regexc; i++)
	{
	  if(i > 0) printf(", ");
	  printf("\"");
	  json_print(re->regexes[i]->str);
	  printf("\"");
	}
      printf("]");
      printf(", \"score\":{%s}", sc_regex_score_tojson(re, buf, sizeof(buf)));
    }

  if(do_json != 0)
    printf(", \"routers\":[");
  last_css = NULL;
  for(r=0; r<rnamec; r++)
    {
      rn = rnames[r];
      rd = rn->rd;

      if(do_json == 0)
	{
	  if(rn->css != NULL)
	    {
	      printf("%s %d", sc_css_tostr(rn->css, '|', buf, sizeof(buf)),
		     rn->css->count);
	      if(last_css != NULL && sc_css_css_cmp(last_css, rn->css) == 0)
		printf(" ***");
	    }
	  else printf("unnamed %d", rn->matchc);
	  if(rd->css != NULL)
	    printf(" %s %d",
		   sc_css_tostr(rd->css,'|',buf,sizeof(buf)), rd->css->count);
	  printf("\n");
	}
      else
	{
	  if(r > 0) printf(", ");
	  if(rn->css != NULL)
	    printf("{\"name\":\"%s\"",
		   sc_css_tostr(rn->css, '|', buf, sizeof(buf)));
	  else
	    printf("{\"name\":\"\"");
	}

      last_css = rn->css;

      if(do_json != 0)
	printf(", \"ifaces\":[");

      for(i=0; i<rd->ifacec; i++)
	{
	  ifd = rd->ifaces[i]; iface = ifd->iface;
	  ifp = sc_ifdptr_find(ifp_tree, ifd); assert(ifp != NULL);
	  ifi = ifp->ptr; assert(ifi != NULL);
	  code = ifi->class;

	  if(do_json == 0)
	    {
	      if(rd->css != NULL && ifi->css != NULL && code == '-' &&
		 (rn->css == NULL || sc_css_css_cmp(rn->css, ifi->css) != 0) &&
		 sc_css_morespecific(rd->css, ifi->css) != 0)
		code = 'M';
	      else if(rn->css != NULL && (code == '~' || code == '-') &&
		      (ifi->css == NULL ||
		       sc_css_css_cmp(rn->css,ifi->css) != 0) &&
		      sc_css_match(rn->css, ifd->label, NULL, 1) == 1)
		code = 'm';
	      printf("%16s %c %s\n",
		     scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
		     code, iface->name);
	    }
	  else
	    {
	      if(i > 0) printf(", ");
	      if(ifi->css != NULL)
		{
		  if(sc_rework_match(rew, iface, NULL) < 0)
		    goto done;
		  dump_2_regex_iface(re, iface, code, rew, ifi->css, ifi);
		}
	      else dump_2_regex_iface(re, iface, code, NULL, NULL, NULL);
	    }
	}

      for(s=0; s<rd->rtr->ifacec; s++)
	{
	  iface = rd->rtr->ifaces[s];
	  if((suffix = sc_suffix_find(iface->name)) == NULL ||
	     strcmp(suffix, dom->domain) != 0)
	    {
	      scamper_addr_tostr(iface->addr, buf, sizeof(buf));
	      if(do_json == 0)
		{
		  if(iface->name != NULL)
		    printf("%16s   %s\n", buf, iface->name);
		  else
		    printf("%16s\n", buf);
		}
	      else
		{
		  printf(", ");
		  dump_2_regex_iface(NULL, iface, '\0', NULL, NULL, NULL);
		}
	    }
	}

      if(do_json == 0)
	printf("\n");
      else
	printf("]}");
    }
  if(do_json != 0)
    printf("]");

  if(do_appl != 0 && slist_count(dom->appl) > 0)
    {
      /*
       * put the existing inferences into a tree, as the set in
       * "appl" should not match if the training data is perfect
       */
      if((ri_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
	goto done;
      for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
	{
	  ri = slist_node_item(sn);
	  if(ri->ifaces[0]->css == NULL)
	    continue;
	  if(splaytree_insert(ri_tree, ri->ifaces[0]->css) == NULL)
	    goto done;
	}

      if((appl_list = slist_alloc()) == NULL)
	goto done;

      for(sn=slist_head_node(dom->appl); sn != NULL; sn=slist_node_next(sn))
	{
	  rd = slist_node_item(sn); assert(rd->ifacec == 1);
	  ifd = rd->ifaces[0];
	  iface = ifd->iface;
	  code = ' ';

	  if((x = sc_rework_match(rew, iface, &css)) < 0)
	    goto done;

	  ip = 0;
	  if(x == 1)
	    {
	      if(css == NULL)
		code = '*';
	      else if(sc_iface_ip_matched(iface, rew) != 0)
		{
		  ip = 1;
		  code = 'x';
		}
	      else if(splaytree_find(ri_tree, css) != NULL)
		code = '!';
	      else
		code = '+';
	      ifi = sc_ifaceinf_get(appl_list, ifd, css, ip, rew->k);
	    }
	  else
	    {
	      ifi = sc_ifaceinf_get(appl_list, ifd, NULL, ip, -1);
	    }
	  ifi->class = code;
	  css = NULL;
	}

      if(do_json == 0)
	printf("application:\n\n");
      else
	printf(", \"application\":[");

      r = 0;
      slist_qsort(appl_list, (slist_cmp_t)sc_ifaceinf_inf_cmp);
      sn = slist_head_node(appl_list);
      while(sn != NULL)
	{
	  ifi = slist_node_item(sn);
	  if(ifi->css == NULL)
	    break;

	  x = 1;
	  if((sn2 = slist_node_next(sn)) != NULL)
	    {
	      ifi2 = slist_node_item(sn2);
	      while(ifi2->css != NULL && sc_css_css_cmp(ifi->css,ifi2->css)==0)
		{
		  x++;
		  if((sn2 = slist_node_next(sn2)) == NULL)
		    break;
		  ifi2 = slist_node_item(sn2);
		}
	    }

	  sc_css_tostr(ifi->css, '|', buf, sizeof(buf));
	  if(do_json == 0)
	    printf("%s %d\n", buf, x);
	  else
	    {
	      if(r > 0) printf(", ");
	      printf("{\"name\":\"");
	      json_print(buf);
	      printf("\", \"ifaces\":[");
	    }

	  i = 0;
	  while(sn != sn2)
	    {
	      ifi = slist_node_item(sn); iface = ifi->ifd->iface;
	      if(do_json == 0)
		{
		  printf("%16s %c %s\n",
			 scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
			 ifi->class, iface->name);
		}
	      else
		{
		  if(i > 0) printf(", ");
		  if(sc_rework_match(rew, iface, NULL) < 0)
		    goto done;
		  dump_2_regex_iface(re, iface, ifi->class, rew, ifi->css,NULL);
		}
	      sn = slist_node_next(sn);
	      i++;
	    }

	  if(do_json == 0)
	    printf("\n");
	  else
	    printf("]}");
	  r++;
	}

      if(do_json != 0)
	printf("]");

      if(sn != NULL)
	{
	  if(do_json == 0)
	    printf("application-unnamed:\n");
	  else
	    printf(", \"application_unnamed\":[");
	  i = 0;
	  while(sn != NULL)
	    {
	      ifi = slist_node_item(sn); iface = ifi->ifd->iface;
	      if(do_json == 0)
		{
		  printf("%16s %c %s\n",
			 scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
			 ifi->class, iface->name);
		}
	      else
		{
		  if(i > 0) printf(", ");
		  dump_2_regex_iface(re, iface, ifi->class, NULL, NULL, NULL);
		  i++;
		}
	      sn = slist_node_next(sn);
	    }

	  if(do_json != 0)
	    printf("]");
	}

      if(do_json == 0)
	printf("\n");
    }

  if(do_json != 0)
    printf("}\n");

  rc = 0;

 done:
  if(appl_list != NULL)
    slist_free_cb(appl_list, (slist_free_t)sc_ifaceinf_free);
  if(rew != NULL) sc_rework_free(rew);
  if(rnames != NULL) sc_routercsss_free(rnames, rnamec);
  if(css != NULL) sc_css_free(css);
  if(ri_tree != NULL) splaytree_free(ri_tree, NULL);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifp_list != NULL) slist_free(ifp_list);
  if(ifp_tree != NULL)
    splaytree_free(ifp_tree, (splaytree_free_t)sc_ifdptr_free);
  return rc;
}

static void dump_2_regex_router_asn(const sc_routerdom_t *rd, sc_css_t *css)
{
  if(do_json != 0)
    {
      printf("{\"asn\":%u", rd->rtr->asn);
      if((rd->rtr->flags & SC_ROUTER_FLAG_ID) != 0)
	printf(", \"id\":%u", rd->rtr->id);
      printf(", \"ifaces\":[");
    }
  else
    {
      printf("%u\n", rd->rtr->asn);
    }
  return;
}

static void dump_2_regex_router_geo(const sc_routerdom_t *rd, sc_css_t *css)
{
  sc_rtt_t *rtt;
  char buf[64];

  if(do_json != 0)
    {
      printf("{");
      if(rd->rtr->id != 0)
	printf("\"id\":%u, ", rd->rtr->id);
      if(rd->rtr->rttc > 0)
	{
	  rtt = &rd->rtr->rtts[0];
	  printf("\"minrtt\":{\"loc\":\"%s\", \"rtt\":%u}, ",
		 rtt->vp->code, rtt->rtt);
	}
      if(css != NULL)
	printf("\"loc\":\"%s\", ", sc_css_tostr(css, '|', buf, sizeof(buf)));
      printf("\"ifaces\":[");
    }
  else
    {
      if(css != NULL)
	printf("%s\n", sc_css_tostr(css, '|', buf, sizeof(buf)));
    }

  return;
}

static int dump_2_regex_router(sc_domain_t *dom, sc_regex_t *re,
			       splaytree_t *(*rcss_tree_cb)(slist_t *),
			       void (*router_cb)(const sc_routerdom_t *,
						 sc_css_t *))
{
  splaytree_t *rd_tree = NULL, *ifp_tree = NULL, *rcss_tree = NULL;
  slist_t *ifi_list = NULL, *rd_list = NULL, *z_list = NULL, *rd0_list = NULL;
  slist_t *m2h_list = NULL;
  sc_routercss_t *rcss;
  sc_rework_t *rew = NULL;
  const char *suffix;
  sc_ifaceinf_t *ifi;
  sc_ifacedom_t *ifd;
  sc_geomap2hint_t *m2h;
  sc_routerdom_t *rd;
  sc_iface_t *iface;
  sc_ifdptr_t *ifp;
  sc_css_t *css = NULL;
  slist_node_t *sn;
  int matched, x, z, i, j, r, rc = -1;
  char buf[2048];
  void *ptr;
  size_t s;

  if((rd_tree = splaytree_alloc((splaytree_cmp_t)ptrcmp)) == NULL ||
     (rd_list = slist_alloc()) == NULL ||
     (ifi_list = slist_alloc()) == NULL ||
     (ifp_tree = sc_ifdptr_tree(dom->routers)) == NULL ||
     sc_regex_eval(re, ifi_list) != 0 ||
     (rcss_tree_cb != NULL && (rcss_tree = rcss_tree_cb(ifi_list)) == NULL) ||
     sc_ifdptr_tree_ifi(ifp_tree, ifi_list) != 0 ||
     (rew = sc_rework_alloc(re)) == NULL)
    goto done;

  if(do_learngeo != 0 &&
     (m2h_list = sc_geomap2hint_make(re, ifi_list)) == NULL)
    goto done;

  if(do_json == 0)
    {
      printf("%s:", dom->domain);
      for(i=0; i<re->regexc; i++)
	printf(" %s", re->regexes[i]->str);
      printf(" %s", sc_regex_score_tostr(re, buf, sizeof(buf)));
      printf("\n");

      if(do_learngeo != 0)
	dump_0_regex_geomap(m2h_list);
    }
  else
    {
      printf("{\"domain\":\"%s\"", dom->domain);
      printf(", \"re\":[");
      for(i=0; i<re->regexc; i++)
	{
	  if(i > 0) printf(", ");
	  printf("\"");
	  json_print(re->regexes[i]->str);
	  printf("\"");
	}
      printf("]");
      printf(", \"score\":{%s}", sc_regex_score_tojson(re, buf, sizeof(buf)));

      if(do_learngeo != 0)
	{
	  /* emit all the geohints */
	  printf(", \"geohints\":[");
	  i = 0;
	  for(sn=slist_head_node(m2h_list); sn != NULL; sn=slist_node_next(sn))
	    {
	      m2h = slist_node_item(sn);
	      if(sc_geomap2hint_tojson(m2h, buf, sizeof(buf)) != 0)
		goto done;
	      if(i > 0) printf(",");
	      printf("%s", buf);
	      i++;
	    }
	  printf("]");
	  printf(", \"plan\":%s", sc_regex_plan_tojson(re, buf, sizeof(buf)));
	}

      printf(", \"routers\":[");
    }

  slist_qsort(ifi_list, (slist_cmp_t)sc_ifaceinf_class_cmp);
  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if(ifi->class == ' ')
	continue;
      if(splaytree_find(rd_tree, ifi->ifd->rd) != NULL)
	continue;
      if(splaytree_insert(rd_tree, ifi->ifd->rd) == NULL ||
	 slist_tail_push(rd_list, ifi->ifd->rd) == NULL)
	goto done;
    }

  r = 0;
  for(z=0; z<2; z++)
    {
      if(z == 0)
	z_list = rd_list;
      else
	z_list = dom->routers;

      for(sn=slist_head_node(z_list); sn != NULL; sn=slist_node_next(sn))
	{
	  rd = slist_node_item(sn);
	  ptr = splaytree_find(rd_tree, rd);
	  if((ptr == NULL && z == 0) || (ptr != NULL && z == 1))
	    continue;

	  if(do_json != 0)
	    {
	      if(r > 0) printf(",");
	      r++;
	    }

	  if(rcss_tree != NULL)
	    rcss = sc_routercss_rd_find(rcss_tree, rd);
	  else
	    rcss = NULL;
	  router_cb(rd, rcss != NULL ? rcss->css : NULL);

	  for(i=0; i<rd->ifacec; i++)
	    {
	      ifd = rd->ifaces[i]; iface = ifd->iface;
	      ifp = sc_ifdptr_find(ifp_tree, ifd); assert(ifp != NULL);
	      ifi = ifp->ptr;
	      if(do_json != 0)
		{
		  if(i > 0) printf(", ");
		  if(ifi->css != NULL)
		    {
		      if(sc_rework_match(rew, iface, NULL) < 0)
			goto done;
		      dump_2_regex_iface(re,iface,ifi->class,rew,ifi->css,ifi);
		    }
		  else dump_2_regex_iface(re,iface,ifi->class,NULL,NULL,NULL);
		}
	      else
		{
		  printf("%16s %c %s\n",
			 scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
			 ifi->class, iface->name);
		}
	    }

	  for(s=0; s<rd->rtr->ifacec; s++)
	    {
	      iface = rd->rtr->ifaces[s];
	      if((suffix = sc_suffix_find(iface->name)) == NULL ||
		 strcmp(suffix, dom->domain) != 0)
		{
		  if(do_json == 0)
		    {
		      scamper_addr_tostr(iface->addr, buf, sizeof(buf));
		      if(iface->name != NULL)
			printf("%16s   %s\n", buf, iface->name);
		      else
			printf("%16s\n", buf);
		    }
		  else
		    {
		      printf(", ");
		      dump_2_regex_iface(NULL, iface, '\0', NULL, NULL, NULL);
		    }
		}
	    }

	  if(do_json == 0)
	    printf("\n");
	  else
	    printf("]}");
	}
    }
  if(do_json != 0)
    printf("]");

  if(do_appl != 0 && slist_count(dom->appl) > 0)
    {
      /* empty out the list, put unmatched routers in it */
      slist_empty(rd_list);
      if((rd0_list = slist_alloc()) == NULL)
	goto done;

      for(sn=slist_head_node(dom->appl); sn != NULL; sn=slist_node_next(sn))
	{
	  rd = slist_node_item(sn);
	  matched = 0;
	  for(i=0; i<rd->ifacec; i++)
	    {
	      if((x = sc_rework_match(rew, rd->ifaces[i]->iface, NULL)) < 0)
		goto done;
	      if(x == 1)
		{
		  matched = 1;
		  break;
		}
	    }
	  if(slist_tail_push(matched != 0 ? rd_list : rd0_list, rd) == NULL)
	    goto done;
	}

      if(slist_count(rd_list) > 0)
	{
	  if(do_json == 0)
	    printf("application-matched:\n\n");
	  else
	    printf(", \"application_matched\":[");
	  r = 0;

	  for(sn=slist_head_node(rd_list); sn != NULL; sn=slist_node_next(sn))
	    {
	      rd = slist_node_item(sn);
	      if(do_json != 0)
		{
		  if(r > 0) printf(",");
		  printf("{\"ifaces\":[");
		  r++;
		}

	      /* print matched interfaces first, then unmatched */
	      j = 0;
	      for(z=0; z<2; z++)
		{
		  for(i=0; i<rd->ifacec; i++)
		    {
		      iface = rd->ifaces[i]->iface;
		      if((x = sc_rework_match(rew, iface, &css)) < 0)
			goto done;
		      if((x == 0 && z == 0) || (x == 1 && z == 1))
			continue;
		      if(do_json == 0)
			{
			  scamper_addr_tostr(iface->addr, buf, sizeof(buf));
			  printf("%16s %c %s\n", buf,
				 (x == 1 && z == 0) ? '?' : ' ', iface->name);
			}
		      else
			{
			  if(j > 0) printf(", ");
			  if(x == 1 && z == 0)
			    dump_2_regex_iface(re, iface, '?', rew, css, NULL);
			  else
			    dump_2_regex_iface(re, iface, '\0', NULL,NULL,NULL);
			}
		      if(css != NULL)
			{
			  sc_css_free(css);
			  css = NULL;
			}
		      j++;
		    }
		}

	      for(s=0; s<rd->rtr->ifacec; s++)
		{
		  iface = rd->rtr->ifaces[s];
		  if((suffix = sc_suffix_find(iface->name)) == NULL ||
		     strcmp(suffix, dom->domain) != 0)
		    {
		      if(do_json == 0)
			{
			  scamper_addr_tostr(iface->addr, buf, sizeof(buf));
			  if(iface->name != NULL)
			    printf("%16s   %s\n", buf, iface->name);
			  else
			    printf("%16s\n", buf);
			}
		      else
			{
			  printf(", ");
			  dump_2_regex_iface(NULL, iface, '\0', NULL,NULL,NULL);
			}
		    }
		}

	      if(do_json == 0)
		printf("\n");
	      else
		printf("]}");
	    }
	  if(do_json != 0)
	    printf("]");
	}

      /* print other routers in the domain with no matched interfaces */
      if(slist_count(rd0_list) > 0)
	{
	  if(do_json == 0)
	    printf("application-unmatched:\n\n");
	  else
	    printf(", \"application_unmatched\":[");
	  r = 0;

	  for(sn=slist_head_node(rd0_list); sn != NULL; sn=slist_node_next(sn))
	    {
	      rd = slist_node_item(sn);
	      if(do_json != 0)
		{
		  if(r > 0) printf(",");
		  printf("{\"ifaces\":[");
		  r++;
		}

	      /* print interfaces in the domain first */
	      j = 0;
	      for(i=0; i<rd->ifacec; i++)
		{
		  iface = rd->ifaces[i]->iface;
		  if(do_json == 0)
		    {
		      printf("%16s   %s\n",
			     scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
			     iface->name);
		    }
		  else
		    {
		      if(j > 0) printf(", ");
		      dump_2_regex_iface(re, iface, '\0', NULL, NULL,NULL);
		    }
		  j++;
		}

	      /* print other interfaces on the router */
	      for(s=0; s<rd->rtr->ifacec; s++)
		{
		  iface = rd->rtr->ifaces[s];
		  if((suffix = sc_suffix_find(iface->name)) == NULL ||
		     strcmp(suffix, dom->domain) != 0)
		    {
		      if(do_json == 0)
			{
			  scamper_addr_tostr(iface->addr, buf, sizeof(buf));
			  if(iface->name != NULL)
			    printf("%16s   %s\n", buf, iface->name);
			  else
			    printf("%16s\n", buf);
			}
		      else
			{
			  printf(", ");
			  dump_2_regex_iface(NULL, iface, '\0', NULL,NULL,NULL);
			}
		    }
		}

	      if(do_json == 0)
		printf("\n");
	      else
		printf("]}");
	    }
	  if(do_json != 0)
	    printf("]");
	}
    }

  if(do_json != 0)
    printf("}\n");

  rc = 0;

 done:
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(ifp_tree != NULL)
    splaytree_free(ifp_tree, (splaytree_free_t)sc_ifdptr_free);
  if(rcss_tree != NULL)
    splaytree_free(rcss_tree, (splaytree_free_t)sc_routercss_free);
  if(rd_tree != NULL) splaytree_free(rd_tree, NULL);
  if(rd_list != NULL) slist_free(rd_list);
  if(rd0_list != NULL) slist_free(rd0_list);
  if(m2h_list != NULL) slist_free_cb(m2h_list, (slist_free_t)free);
  if(rew != NULL) sc_rework_free(rew);
  if(css != NULL) sc_css_free(css);
  return rc;
}

static int dump_2(void)
{
  slist_node_t *sn;
  sc_domain_t *dom;
  sc_regex_t *re;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if((re = sc_domain_bestre(dom)) == NULL || sc_regex_show(re) == 0)
	continue;

      if(do_learnalias != 0)
	{
	  if(dump_2_regex_alias(dom, re) != 0)
	    return -1;
	}
      else if(do_learnasn != 0 || do_learnasnames != 0)
	{
	  if(dump_2_regex_router(dom, re, NULL, dump_2_regex_router_asn) != 0)
	    return -1;
	}
      else if(do_learngeo != 0)
	{
	  if(dump_2_regex_router(dom, re, sc_routercss_geo,
				 dump_2_regex_router_geo) != 0)
	    return -1;
	}
      else return -1;
    }

  return 0;
}

static int dump_3_json(void)
{
  slist_t *m2h_list = NULL, *ifi_list = NULL;
  sc_geomap2hint_t *m2h;
  slist_node_t *sn, *s2;
  sc_domain_t *dom;
  sc_regex_t *re;
  char buf[2048];
  int i, rc = -1;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if((re = sc_domain_bestre(dom)) == NULL || sc_regex_show(re) == 0)
	continue;

      printf("{\"domain\":\"%s\"", dom->domain);
      printf(", \"re\":[");
      for(i=0; i<re->regexc; i++)
	{
	  if(i > 0) printf(", ");
	  printf("\"");
	  json_print(re->regexes[i]->str);
	  printf("\"");
	}
      printf("]");
      printf(", \"score\":{%s}", sc_regex_score_tojson(re, buf, sizeof(buf)));

      if(do_learngeo != 0)
	{
	  if((ifi_list = slist_alloc()) == NULL ||
	     sc_regex_eval(re, ifi_list) != 0 ||
	     (m2h_list = sc_geomap2hint_make(re, ifi_list)) == NULL)
	    goto done;

	  /* emit all the geohints */
	  printf(", \"geohints\":[");
	  i = 0;
	  for(s2=slist_head_node(m2h_list); s2 != NULL; s2=slist_node_next(s2))
	    {
	      m2h = slist_node_item(s2);

	      /* skip over hints with no true positives */
	      if(m2h->tp_c == 0)
		continue;

	      if(sc_geomap2hint_tojson(m2h, buf, sizeof(buf)) != 0)
		goto done;
	      if(i > 0) printf(",");
	      printf("%s", buf);
	      i++;
	    }
	  printf("]");
	  printf(", \"plan\":%s", sc_regex_plan_tojson(re, buf, sizeof(buf)));

	  slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
	  slist_free_cb(m2h_list, (slist_free_t)free);
	  ifi_list = NULL; m2h_list = NULL;
	}
      printf("}\n");
    }
  rc = 0;

 done:
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(m2h_list != NULL) slist_free_cb(m2h_list, (slist_free_t)free);
  return rc;
}

static int dump_3_text(void)
{
  slist_node_t *sn;
  sc_domain_t *dom;
  sc_regex_t *re;
  char buf[512];
  size_t s;
  int k;

  if(do_learnasnames != 0)
    {
      for(s=0; s<tag2asc; s++)
	printf("%u %s\n", tag2ass[s]->asn, tag2ass[s]->tag);
      printf("###\n");
    }

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if((re = sc_domain_bestre(dom)) == NULL || sc_regex_show(re) == 0)
	continue;
      printf("%s:", dom->domain);
      for(k=0; k<re->regexc; k++)
	printf(" %s", re->regexes[k]->str);
      printf(", score: %s", sc_regex_score_tostr(re, buf, sizeof(buf)));
      if(do_learngeo != 0)
	printf(", plan: %s", sc_regex_plan_tostr(re, buf, sizeof(buf)));
      printf(", routers: %d\n", slist_count(dom->routers));
    }

  return 0;
}


static int dump_3(void)
{
  if(do_json != 0)
    return dump_3_json();
  return dump_3_text();
}

static int dump_4_regex_asn(sc_domain_t *dom, sc_regex_t *re)
{
  slist_t *ifi_list = NULL;
  sc_rework_t *rew = NULL;
  sc_css_t *css = NULL;
  sc_routerdom_t *rd;
  sc_ifaceinf_t *ifi;
  sc_iface_t *iface;
  slist_node_t *sn;
  int i, x, rc = -1;
  char buf[2048], tmp[128], restr[16];

  if((ifi_list = slist_alloc()) == NULL ||
     sc_regex_asn_eval(re, ifi_list) != 0)
    goto done;

  printf("%s:", dom->domain);
  for(i=0; i<re->regexc; i++)
    printf(" %s", re->regexes[i]->str);
  printf(" %s", sc_regex_score_tostr(re, buf, sizeof(buf)));
  printf("\n");

  slist_qsort(ifi_list, (slist_cmp_t)sc_ifaceinf_class_cmp);
  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if(ifi->class == ' ' && do_showclass != 0)
	continue;
      iface = ifi->ifd->iface;
      scamper_addr_tostr(iface->addr, buf, sizeof(buf));
      tmp[0] = '\0'; restr[0] = '\0';
      if(ifi->css != NULL)
	{
	  sc_css_tostr(ifi->css, '|', tmp, sizeof(tmp));
	  snprintf(restr, sizeof(restr), "[%d]", ifi->regex+1);
	}
      printf("%16s %c %6d %6s %3s %s\n",
	     buf, ifi->class, iface->rtr->asn, tmp, restr, iface->name);
    }

  if(do_appl != 0 && slist_count(dom->appl) > 0)
    {
      if((rew = sc_rework_alloc(re)) == NULL)
	goto done;
      for(sn=slist_head_node(dom->appl); sn != NULL; sn=slist_node_next(sn))
	{
	  rd = slist_node_item(sn);
	  for(i=0; i<rd->ifacec; i++)
	    {
	      iface = rd->ifaces[i]->iface;
	      if((x = sc_rework_match(rew, iface, &css)) < 0)
		goto done;
	      if(x == 1)
		{
		  scamper_addr_tostr(iface->addr, buf, sizeof(buf));
		  tmp[0] = '\0'; restr[0] = '\0';
		  if(css != NULL)
		    {
		      sc_css_tostr(css, '|', tmp, sizeof(tmp));
		      snprintf(restr, sizeof(restr), "[%d]", (int)rew->k+1);
		    }
		  printf("%16s a %6s %6s %3s %s\n",
			 buf, "", tmp, restr, iface->name);
		}
	      if(css != NULL)
		{
		  sc_css_free(css);
		  css = NULL;
		}
	    }
	}
    }

  rc = 0;

 done:
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(rew != NULL) sc_rework_free(rew);
  if(css != NULL) sc_css_free(css);
  return rc;
}

static int dump_4_regex_asnames(sc_domain_t *dom, sc_regex_t *re)
{
  slist_t *ifi_list = NULL;
  sc_rework_t *rew = NULL;
  sc_css_t *css = NULL;
  sc_ifaceinf_t *ifi;
  sc_iface_t *iface;
  slist_node_t *sn;
  sc_as2tag_t *a2t;
  int i, rc = -1;
  char buf[2048], tmp[128];

  if((ifi_list = slist_alloc()) == NULL ||
     sc_regex_asnames_eval(re, ifi_list) != 0)
    goto done;

  printf("%s:", dom->domain);
  for(i=0; i<re->regexc; i++)
    printf(" %s", re->regexes[i]->str);
  printf(" %s", sc_regex_score_tostr(re, buf, sizeof(buf)));
  printf("\n");

  slist_qsort(ifi_list, (slist_cmp_t)sc_ifaceinf_class_cmp);
  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if(ifi->class == ' ' && do_showclass != 0)
	continue;
      iface = ifi->ifd->iface;
      scamper_addr_tostr(iface->addr, buf, sizeof(buf));
      tmp[0] = '\0';
      if(ifi->css != NULL && (a2t = sc_as2tag_find(ifi->css->css)) != NULL)
	snprintf(tmp,sizeof(tmp),"%u", a2t->asn);
      else if(ifi->class == '~')
	snprintf(tmp,sizeof(tmp),"%d:%d", iface->asnames[0],iface->asnames[1]);
      printf("%16s %c %6d %12s %6s [%d] %s\n", buf, ifi->class,
	     iface->rtr->asn, ifi->css != NULL ? ifi->css->css : "",
	     tmp, ifi->regex+1, iface->name);
    }

  rc = 0;

 done:
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(rew != NULL) sc_rework_free(rew);
  if(css != NULL) sc_css_free(css);
  return rc;
}

static int dump_4_regex_geo(sc_domain_t *dom, sc_regex_t *re)
{
  slist_t *ifi_list = NULL, *out_list = NULL, *m2h_list = NULL;
  char buf[2048], rtt[16], render[136], fstr[64], restr[16];
  size_t addr_len = 0, render_len = 0, rtt_len = 0, len;
  sc_rework_t *rew = NULL;
  sc_ifaceinf_t *ifi;
  sc_iface_t *iface;
  sc_router_t *rtr;
  sc_routerdom_t *rd;
  sc_geohint_t *vp;
  sc_geomap_t map;
  sc_rtt_t *sample;
  sc_css_t *css = NULL;
  slist_node_t *sn;
  sc_dump4_t *d4 = NULL;
  int i, z, rc = -1;
  double distance;

  if((ifi_list = slist_alloc()) == NULL ||
     (out_list = slist_alloc()) == NULL ||
     sc_regex_geo_eval(re, ifi_list) != 0 ||
     (m2h_list = sc_geomap2hint_make(re, ifi_list)) == NULL)
    goto done;

  printf("%s:", dom->domain);
  for(i=0; i<re->regexc; i++)
    printf(" %s", re->regexes[i]->str);
  printf(" %s", sc_regex_score_tostr(re, buf, sizeof(buf)));
  printf(", plan: %s", sc_regex_plan_tostr(re, buf, sizeof(buf)));
  printf("\n");

  dump_0_regex_geomap(m2h_list);

  slist_qsort(ifi_list, (slist_cmp_t)sc_ifaceinf_class_cmp);
  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if(ifi->class == ' ' && do_showclass != 0)
	continue;
      iface = ifi->ifd->iface; rtr = iface->rtr;
      scamper_addr_tostr(iface->addr, buf, sizeof(buf));

      memset(&map, 0, sizeof(map));
      rtt[0] = '\0';
      vp = NULL;

      if(ifi->class == '+' || ifi->class == '!' || ifi->class == '?')
	sc_css_geomap(ifi->css, re->regexes[ifi->regex]->plan, &map);
      else if(ifi->class == '~')
	sc_iface_geomap(iface, &map);
      sc_geomap_tostr(&map, render, sizeof(render));

      if(ifi->class == '+')
	{
	  assert(ifi->geohint != NULL);
	  vp = rtr->rtts[0].vp;
	  distance = sc_geohint_dist(vp, ifi->geohint);
	  snprintf(rtt, sizeof(rtt), "%u<%u", dist2rtt(distance),
		   rtr->rtts[0].rtt + rtt_fudge);
	}
      else if(ifi->class == '!')
	{
	  assert(ifi->geohint != NULL);
	  i = sc_router_ooridx(rtr, ifi->geohint, &sample); assert(i == 0);
	  vp = sample->vp;
	  distance = sc_geohint_dist(vp, ifi->geohint);
	  snprintf(rtt, sizeof(rtt), "%u>%u", dist2rtt(distance),
		   sample->rtt + rtt_fudge);
	}
      else if(ifi->class == '~')
	{
	  assert(ifi->geohint != NULL);
	  vp = rtr->rtts[0].vp;
	  distance = sc_geohint_dist(vp, ifi->geohint);
	  snprintf(rtt, sizeof(rtt), "%u<%u", dist2rtt(distance),
		   rtr->rtts[0].rtt + rtt_fudge);
	}
      else if(ifi->class == '?' || ifi->class == ' ')
	{
	  vp = rtr->rtts[0].vp;
	  snprintf(rtt, sizeof(rtt), "%u", rtr->rtts[0].rtt);
	}

      if((d4 = malloc_zero(sizeof(sc_dump4_t))) == NULL ||
	 (d4->render = strdup(render)) == NULL ||
	 (d4->rtt = strdup(rtt)) == NULL ||
	 slist_tail_push(out_list, d4) == NULL)
	goto done;
      d4->iface = iface;
      d4->class = ifi->class;
      d4->vp = vp;
      d4->regex = ifi->regex;
      d4 = NULL;

      if((len = strlen(buf)) > addr_len) addr_len = len;
      if((len = strlen(render)) > render_len) render_len = len;
      if((len = strlen(rtt)) > rtt_len) rtt_len = len;
    }

  if(do_appl != 0 && slist_count(dom->appl) > 0)
    {
      if((rew = sc_rework_alloc(re)) == NULL)
	goto done;
      for(z=0; z<2; z++)
	{
	  for(sn=slist_head_node(dom->appl); sn != NULL; sn=slist_node_next(sn))
	    {
	      rd = slist_node_item(sn);
	      for(i=0; i<rd->ifacec; i++)
		{
		  iface = rd->ifaces[i]->iface;
		  if(sc_rework_match(rew, iface, &css) < 0)
		    goto done;

		  render[0] = '\0';
		  if(css != NULL)
		    {
		      memset(&map, 0, sizeof(map));
		      sc_css_geomap(css, re->regexes[rew->k]->plan, &map);
		      sc_geomap_tostr(&map, render, sizeof(render));
		    }

		  if((render[0] != '\0' && z == 0) ||
		     (render[0] == '\0' && z == 1))
		    {
		      if((d4 = malloc_zero(sizeof(sc_dump4_t))) == NULL ||
			 (d4->render = strdup(render)) == NULL ||
			 slist_tail_push(out_list, d4) == NULL)
			goto done;
		      d4->class = 'a';
		      d4->iface = iface;
		      d4->regex = rew->k;
		      d4 = NULL;

		      scamper_addr_tostr(iface->addr, buf, sizeof(buf));
		      if((len = strlen(buf)) > addr_len) addr_len = len;
		      if((len = strlen(render)) > render_len) render_len = len;
		    }

		  if(css != NULL)
		    {
		      sc_css_free(css);
		      css = NULL;
		    }
		}
	    }
	}
    }

  snprintf(fstr, sizeof(fstr), "%%%ds %%c %%%ds %%3s %%%ds %%3s %%s\n",
	   (int)addr_len, (int)render_len, (int)rtt_len);
  while((d4 = slist_head_pop(out_list)) != NULL)
    {
      scamper_addr_tostr(d4->iface->addr, buf, sizeof(buf));
      if(d4->regex == -1)
	restr[0] = '\0';
      else
	snprintf(restr, sizeof(restr), "[%d]", d4->regex+1);
      printf(fstr, buf, d4->class, d4->render,
	     d4->vp != NULL ? d4->vp->code : "",
	     d4->rtt != NULL ? d4->rtt : "",
	     restr, d4->iface->name);
      sc_dump4_free(d4);
    }
  rc = 0;

 done:
  if(m2h_list != NULL) slist_free_cb(m2h_list, (slist_free_t)free);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(out_list != NULL) slist_free_cb(out_list, (slist_free_t)sc_dump4_free);
  if(d4 != NULL) sc_dump4_free(d4);
  if(rew != NULL) sc_rework_free(rew);
  if(css != NULL) sc_css_free(css);
  return rc;
}

static int dump_4(void)
{
  slist_node_t *sn;
  sc_domain_t *dom;
  sc_regex_t *re;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if((re = sc_domain_bestre(dom)) == NULL || sc_regex_show(re) == 0)
	continue;

      if(do_learnasn != 0)
	{
	  if(dump_4_regex_asn(dom, re) != 0)
	    return -1;
	}
      else if(do_learnasnames != 0)
	{
	  if(dump_4_regex_asnames(dom, re) != 0)
	    return -1;
	}
      else if(do_learngeo != 0)
	{
	  if(dump_4_regex_geo(dom, re) != 0)
	    return -1;
	}
    }

  return 0;
}

static char *duration_tostr(char *buf, size_t len, const struct timeval *start,
			    const struct timeval *finish)
{
  struct timeval tv;

  timeval_diff_tv(&tv, start, finish);
  if(tv.tv_sec < 60)
    snprintf(buf, len, "%d.%d seconds",
	     (int)tv.tv_sec, (int)(tv.tv_usec / 100000));
  else if(tv.tv_sec < 3600)
    snprintf(buf, len, "%d.%d minutes",
	     (int)tv.tv_sec / 60, (((int)tv.tv_sec % 60) * 10) / 60);
  else
    snprintf(buf, len, "%d.%d hours",
	     (int)tv.tv_sec / 3600, (((int)tv.tv_sec % 3600) * 10) / 3600);
  return buf;
}

static int thin_regexes_domain_same_set(dlist_t *set, slist_t *kept,
					slist_t *same)
{
  sc_regex_t *re, *re2;
  dlist_node_t *dn, *dn_this;
  slist_t *ifi_list = NULL;
  int rc = -1;

  if((ifi_list = slist_alloc()) == NULL)
    goto done;

  while((re = dlist_head_pop(set)) != NULL)
    {
      if(slist_tail_push(kept, re) == NULL)
	goto done;

      dn = dlist_head_node(set);
      while(dn != NULL)
	{
	  re2 = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);
	  if(sc_regex_issame(re, ifi_list, re2) == 1)
	    {
	      dlist_node_pop(set, dn_this);
	      if(slist_tail_push(same, re2) == NULL)
		goto done;
	    }
	}

      slist_empty_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
    }
  rc = 0;

 done:
  if(ifi_list != NULL) slist_free_cb(ifi_list,(slist_free_t)sc_ifaceinf_free);
  return rc;
}

static int thin_regexes_domain_same(slist_t *regexes)
{
  slist_t *kept = NULL, *same = NULL;
  dlist_t *set = NULL;
  sc_regex_t *re = NULL, *re2;
  slist_node_t *sn;
  int rc = -1;

  if(slist_head_node(regexes) == NULL)
    {
      rc = 0;
      goto done;
    }

  if((kept = slist_alloc()) == NULL ||
     (same = slist_alloc()) == NULL || (set = dlist_alloc()) == NULL)
    goto done;

  for(sn=slist_head_node(regexes); sn != NULL; sn=slist_node_next(sn))
    {
      if(re == NULL)
	{
	  re = slist_node_item(sn);
	  if(dlist_tail_push(set, re) == NULL)
	    goto done;
	  continue;
	}

      re2 = slist_node_item(sn);

      /* when we get to a different regex score, thin the set */
      if(sc_regex_score_thin_cmp(re, re2) != 0)
	{
	  if(thin_regexes_domain_same_set(set, kept, same) != 0)
	    goto done;
	  dlist_empty(set);
	  re = re2;
	}

      if(dlist_tail_push(set, re2) == NULL)
	goto done;
    }

  if(thin_regexes_domain_same_set(set, kept, same) != 0)
    goto done;

  rc = 0;
  slist_empty(regexes);
  slist_concat(regexes, kept);
  slist_empty_cb(same, (slist_free_t)sc_regex_free);

 done:
  if(set != NULL) dlist_free(set);
  if(same != NULL) slist_free(same);
  if(kept != NULL) slist_free(kept);
  return rc;
}

static int thin_regexes_domain_matchc(slist_t *regexes)
{
  slist_t *keep = NULL, *del = NULL, *list;
  slist_node_t *sn;
  sc_regex_t *re;
  int rc = -1;

  assert(do_learnalias != 0 || do_learnasn != 0 || do_learnasnames != 0 ||
	 do_learngeo != 0);

  if((keep = slist_alloc()) == NULL || (del = slist_alloc()) == NULL)
    goto done;

  for(sn = slist_head_node(regexes); sn != NULL; sn = slist_node_next(sn))
    {
      re = slist_node_item(sn);
      if(do_learnalias != 0 && re->matchc >= 3 && re->rt_c > 0)
	list = keep;
      else if((do_learnasn != 0 || do_learnasnames != 0) && re->rt_c > 0)
	list = keep;
      else if(do_learngeo != 0 && re->matchc >= 3 && re->rt_c > 1)
	list = keep;
      else
	list = del;
      if(slist_tail_push(list, re) == NULL)
	goto done;
    }

  rc = 0;
  slist_empty(regexes);
  slist_concat(regexes, keep);
  slist_empty_cb(del, (slist_free_t)sc_regex_free);

 done:
  if(keep != NULL) slist_free(keep);
  if(del != NULL) slist_free(del);
  return rc;
}

static int thin_regexes_domain_mask(slist_t *regexes)
{
  dlist_t *kept = NULL;
  slist_t *cont = NULL, *skept = NULL;
  dlist_node_t *dn1, *dn2, *dn3;
  sc_regex_t *re1, *re2;
  int i, c2, masklen, rc = -1;
  uint32_t u;

  if((kept = dlist_alloc()) == NULL || (cont = slist_alloc()) == NULL)
    goto done;
  slist_qsort(regexes, (slist_cmp_t)sc_regex_score_rank_cmp);
  if(slist_foreach(regexes, slist_to_dlist, kept) != 0)
    goto done;

  for(dn1=dlist_head_node(kept); dn1 != NULL; dn1=dlist_node_next(dn1))
    {
      re1 = dlist_node_item(dn1);
      dn2 = dlist_node_next(dn1);
      masklen = re1->dom->tpmlen;

      while(dn2 != NULL)
	{
	  re2 = dlist_node_item(dn2);
	  dn3 = dlist_node_next(dn2);
	  c2 = -1;
	  if(re1->fp_c <= re2->fp_c && re1->tp_c >= re2->tp_c)
	    {
	      c2 = 0;
	      for(i=0; i<masklen; i++)
		{
		  u = re1->tp_mask[i] & re2->tp_mask[i];
		  if((re2->tp_mask[i] & ~u) != 0)
		    {
		      c2++;
		      break;
		    }
		}
	    }

	  if(c2 == 0)
	    {
	      if(slist_tail_push(cont, re2) == NULL)
		goto done;
	      dlist_node_pop(kept, dn2);
	    }
	  dn2 = dn3;
	}
    }

  if((skept = slist_alloc()) == NULL ||
     dlist_foreach(kept, dlist_to_slist, skept) != 0)
    goto done;
  slist_empty(regexes);
  slist_concat(regexes, skept);
  slist_empty_cb(cont, (slist_free_t)sc_regex_free);
  rc = 0;

 done:
  if(kept != NULL) dlist_free(kept);
  if(cont != NULL) slist_free(cont);
  if(skept != NULL) slist_free(skept);
  return rc;
}

static int thin_regexes_domain(slist_t *regexes, uint8_t mask)
{
  /* make sure the regexes are sorted by score */
  slist_qsort(regexes, (slist_cmp_t)sc_regex_score_thin_sort_cmp);
  if((thin_matchc != 0 && (mask & 0x1) != 0 &&
      thin_regexes_domain_matchc(regexes) != 0) ||
     (thin_same != 0 && (mask & 0x2) != 0 &&
      thin_regexes_domain_same(regexes) != 0) ||
     (thin_mask != 0 && (mask & 0x4) != 0 &&
      thin_regexes_domain_mask(regexes) != 0))
    return -1;
  return 0;
}

/*
 * thin_regexes_thread_0:
 *
 * remove regexes that perform the same as other regexes in the set, and
 * those without sufficient matches.
 */
static void thin_regexes_thread_0(sc_domain_t *dom)
{
  thin_regexes_domain(dom->regexes, 0x3);
  return;
}

/*
 * thin_regexes_thread_1:
 *
 * remove regexes that perform the same as other regexes in the set,
 * those without sufficient matches, and those that are contained in
 * another regex in the set.
 */
static void thin_regexes_thread_1(sc_domain_t *dom)
{
  thin_regexes_domain(dom->regexes, 0x7);
  return;
}

/*
 * thin_regexes_thread_2:
 *
 * only remove regexes that perform identically
 */
static void thin_regexes_thread_2(sc_domain_t *dom)
{
  thin_regexes_domain(dom->regexes, 0x2);
  return;
}

static int thin_regexes(int mode)
{
  struct timeval start, finish;
  slist_node_t *sn;
  sc_domain_t *dom;
  int from = 0, to = 0;
  char buf[32];

  if(thin_same == 0 && thin_matchc == 0 && thin_mask == 0)
    return 0;

  gettimeofday_wrap(&start);
  threadp = threadpool_alloc(threadc);

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      from += slist_count(dom->regexes);
      if(mode == 0)
	threadpool_tail_push(threadp,
			     (threadpool_func_t)thin_regexes_thread_0, dom);
      else if(mode == 1)
	threadpool_tail_push(threadp,
			     (threadpool_func_t)thin_regexes_thread_1, dom);
      else if(mode == 2)
	threadpool_tail_push(threadp,
			     (threadpool_func_t)thin_regexes_thread_2,dom);
    }

  threadpool_join(threadp); threadp = NULL;
  gettimeofday_wrap(&finish);

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      to += slist_count(dom->regexes);
    }

  fprintf(stderr, "thinned from %d to %d regexes in %s\n",
	  from, to, duration_tostr(buf, sizeof(buf), &start, &finish));

  return 0;
}

static int sc_regex_tp_isbetter(sc_regex_t *re, sc_regex_t *can)
{
  uint32_t re_ppv, can_ppv;

  /*
   * if we have at least three routers, or the same number of routers
   * as in the original regex, and we have at least as many true
   * positives and no more false positives, then the candidate regex
   * is better and we're done.
   */
  if((can->rt_c >= 3 || re->rt_c == can->rt_c) &&
     can->tp_c >= re->tp_c && can->fp_c <= re->fp_c)
    return 1;

  /*
   * the following code handles the case when we get less true
   * positives in the candidate regex.  we therefore need to determine
   * if the PPV of the candidate regex is at least as good as what we
   * started with.
   */
  if(can->rt_c < 3)
    return 0;

  re_ppv = (re->tp_c * 1000) / (re->tp_c + re->fp_c + re->ip_c);
  can_ppv = (can->tp_c * 1000) / (can->tp_c + can->fp_c + can->ip_c);
  if(re_ppv > can_ppv)
    return 0;

  return 1;
}

/*
 * sc_regex_refine_tp
 *
 * given a regex with true positives, infer what the matching
 * components of the regex might have in common.  for alias
 * regexes, this is part of the capture, by definition.
 */
static int sc_regex_refine_tp(sc_regex_t *re)
{
  static const uint16_t mask = RB_BASE | RB_FIRST_PUNC_END | RB_SEG_LITERAL | RB_SEG_DIGIT;
  slist_t *ri_list = NULL, *css_list = NULL, *re_list = NULL, *re2_list = NULL;
  splaytree_t *re_tree = NULL, **css_trees = NULL;
  sc_regex_t *re_eval = NULL, *re_new = NULL;
  int Lc, bitc, *bits = NULL; size_t *La = NULL;
  sc_rework_t *rew = NULL;
  char *str = NULL, *ptr;
  slist_node_t *sn, *s2;
  int i, x, capc, rc = -1;
  sc_routerinf_t *ri;
  sc_css_t *css, css_fm;
  char buf[256];
  size_t len;

  /* figure out how many capture elements there are */
  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;
  if((capc = sc_rework_capcount(rew, 0)) < 0)
    goto done;
  if(capc == 0)
    {
      rc = 0;
      goto done;
    }
  sc_rework_free(rew); rew = NULL;

  /* create trees to put captured elements in */
  if((css_trees = malloc_zero(sizeof(splaytree_t *) * capc)) == NULL)
    goto done;
  for(i=0; i<capc; i++)
    {
      css_trees[i] = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp);
      if(css_trees[i] == NULL)
	goto done;
    }

  /*
   * evaluate the current regex, taking note of each captured element
   * in separate trees
   */
  if((ri_list = slist_alloc()) == NULL ||
     sc_regex_alias_eval(re, ri_list) != 0)
    goto done;
  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      if(ri->ifacec == 1 || ri->ip != 0)
	continue;
      css = ri->ifaces[0]->css;
      css_fm.css = css->css;
      css_fm.cssc = 1;

      /* go through each captured element and put in the tree */
      for(i=0; i<capc; i++)
	{
	  css_fm.len = strlen(css_fm.css) + 1;
	  if(sc_css_get(css_trees[i], &css_fm) == NULL)
	    goto done;
	  if(i+1 != capc)
	    {
	      while(css_fm.css[0] != '\0')
		css_fm.css++;
	      css_fm.css++;
	    }
	}
    }

  if((css_list = slist_alloc()) == NULL ||
     (re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL ||
     (re_list = slist_alloc()) == NULL ||
     (re2_list = slist_alloc()) == NULL)
    goto done;

  for(i=0; i<capc; i++)
    {
      /* trim on non-alnum, min length 1 */
      if(sc_css_reduce(css_trees[i], 1, 1) != 0)
	goto done;
      /* trim on char class, min length 1 */
      if(sc_css_reduce(css_trees[i], 2, 1) != 0)
	goto done;

      /* get all the substrings out for this capture element */
      splaytree_inorder(css_trees[i], tree_to_slist, css_list);
      splaytree_free(css_trees[i], NULL); css_trees[i] = NULL;

      /* figure out regular expressions that match the given strings */
      for(sn=slist_head_node(css_list); sn != NULL; sn=slist_node_next(sn))
	{
	  css = slist_node_item(sn);
	  Lc = css->cssc * 2;
	  La = malloc(sizeof(size_t) * Lc);
	  for(s2=slist_head_node(ri_list); s2 != NULL; s2=slist_node_next(s2))
	    {
	      ri = slist_node_item(s2);
	      if(ri->ifacec == 1 || ri->ip != 0)
		continue;

	      ptr = ri->ifaces[0]->css->css;
	      for(x=0; x<i; x++)
		{
		  while(ptr[0] != '\0')
		    ptr++;
		  ptr++;
		}

	      if(sc_css_match(css, ptr, La, 0) == 0)
		continue;
	      /*
	       * don't allow a regex to form where the entire capture
	       * portion is specified with a literal
	       */
	      if(capc == 1 && css->cssc == 1 &&
		 La[0] == 0 && ptr[La[1]+1] == '\0')
		continue;
	      if(threadc <= 1 && do_debug != 0)
		printf("%s %s\n", ptr, sc_css_tostr(css,'|',buf,sizeof(buf)));
	      len = strlen(ptr);
	      if(pt_to_bits(ptr,len, NULL,0, La,Lc, NULL,0, &bits,&bitc) == 0)
		{
		  if(sc_regex_build(re_tree, ptr, NULL, mask, bits, bitc) != 0)
		    goto done;
		}
	      if(bits != NULL)
		{
		  free(bits);
		  bits = NULL;
		}
	    }
	  free(La); La = NULL;
	}
      slist_empty_cb(css_list, (slist_free_t)sc_css_free);
      splaytree_inorder(re_tree, tree_to_slist, re_list);
      splaytree_empty(re_tree, NULL);

      for(sn=slist_head_node(re_list); sn != NULL; sn=slist_node_next(sn))
	{
	  re_eval = slist_node_item(sn);
	  str = sc_regex_caprep(re->regexes[0]->str, i+1, 1,
				re_eval->regexes[0]->str);
	  if(str == NULL || (re_new = sc_regex_alloc(str)) == NULL)
	    goto done;
	  str = NULL;
	  re_new->dom = re->dom;

	  if(sc_regex_alias_eval(re_new, NULL) != 0)
	    goto done;
	  if(re_new->matchc == 0 && threadc <= 1 && do_debug != 0)
	    printf("no matches %s\n", re_new->regexes[0]->str);
	  if(sc_regex_tp_isbetter(re, re_new) == 0)
	    {
	      sc_regex_free(re_new); re_new = NULL;
	      continue;
	    }
	  re_new->score = re->score + re_eval->score;
	  if(slist_tail_push(re2_list, re_new) == NULL)
	    goto done;
	  re_new = NULL;
	}
      slist_empty_cb(re_list, (slist_free_t)sc_regex_free);

      if(slist_count(re2_list) > 0)
	{
	  thin_regexes_domain(re2_list, 0x3);
	  if(sc_domain_lock(re->dom) != 0)
	    goto done;
	  slist_concat(re->dom->regexes, re2_list);
	  sc_domain_unlock(re->dom);
	}
    }

  rc = 0;

 done:
  if(str != NULL) free(str);
  if(bits != NULL) free(bits);
  if(La != NULL) free(La);
  if(rew != NULL) sc_rework_free(rew);
  if(re_new != NULL) sc_regex_free(re_new);
  if(re_list != NULL) slist_free_cb(re_list, (slist_free_t)sc_regex_free);
  if(re2_list != NULL) slist_free_cb(re2_list, (slist_free_t)sc_regex_free);
  if(re_tree != NULL) splaytree_free(re_tree, (splaytree_free_t)sc_regex_free);
  if(css_list != NULL) slist_free_cb(css_list, (slist_free_t)sc_css_free);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(css_trees != NULL)
    {
      for(i=0; i<capc; i++)
	if(css_trees[i] != NULL)
	  splaytree_free(css_trees[i], (splaytree_free_t)sc_css_free);
      free(css_trees);
    }
  return rc;
}

/*
 * sc_regex_ip_ri_eval
 *
 * if regex matches an interface we wish to filter, tp++, otherwise fp++
 * this function is used with alias regexes.
 */
static int sc_regex_ip_ri_eval(sc_regex_t *re, slist_t *ri_list)
{
  splaytree_t *tree = NULL;
  sc_rework_t *rew = NULL;
  int rc = -1, x;
  slist_node_t *sn;
  sc_routerinf_t *ri;
  sc_routerdom_t *rd;
  sc_iface_t *iface;
  size_t i;

  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;
  if((tree = splaytree_alloc((splaytree_cmp_t)ptrcmp)) == NULL)
    goto done;
  sc_regex_score_reset(re);

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      for(i=0; i<ri->ifacec; i++)
	{
	  iface = ri->ifaces[i]->ifd->iface;
	  if((x = sc_rework_match(rew, iface, NULL)) < 0)
	    goto done;

	  /* matched */
	  if(x == 1)
	    {
	      re->matchc++;
	      rd = ri->ifaces[i]->ifd->rd;
	      if(ri->ifaces[i]->class == 'x')
		{
		  re->tp_c++;
		  if(splaytree_find(tree, rd) == NULL &&
		     splaytree_insert(tree, rd) == NULL)
		    goto done;
		}
	      else if(ri->ifaces[i]->class == '+')
		re->fp_c++;
	      else
		re->fne_c++;
	    }
	  else
	    {
	      if(ri->ifaces[i]->class == 'x')
		re->fnu_c++;
	    }
	}
    }
  re->rt_c = splaytree_count(tree);
  rc = 0;

 done:
  if(rew != NULL) sc_rework_free(rew);
  if(tree != NULL) splaytree_free(tree, NULL);
  return rc;
}

/*
 * sc_regex_ip_ifi_eval
 *
 * if regex matches an interface we wish to filter, tp++, otherwise fp++
 * this function is used with asname, geo, asn regexes.
 */
static int sc_regex_ip_ifi_eval(sc_regex_t *re, slist_t *ifi_list)
{
  sc_rework_t *rew = NULL;
  int rc = -1, x;
  slist_node_t *sn;
  sc_ifaceinf_t *ifi;
  sc_iface_t *iface;

  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;
  sc_regex_score_reset(re);

  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      iface = ifi->ifd->iface;
      if((x = sc_rework_match(rew, iface, NULL)) < 0)
	goto done;

      /* matched */
      if(x == 1)
	{
	  re->matchc++;
	  if(ifi->class == 'x')
	    {
	      re->tp_c++;
	      re->rt_c++;
	    }
	  else if(ifi->class == '+')
	    re->fp_c++;
	  else
	    re->fne_c++;
	}
      else
	{
	  if(ifi->class == 'x')
	    re->fnu_c++;
	}
    }

  rc = 0;

 done:
  if(rew != NULL) sc_rework_free(rew);
  return rc;
}

/*
 * sc_regex_fne_isbetter
 *
 * three regexes: the current over-specific regex, a previous candidate
 * regex that might be better, a refined candidate regex that might be
 * better again.  determine if can2 > can1.
 */
static int sc_regex_fne_isbetter(sc_regex_t *cur,
				 sc_regex_t *can1, sc_regex_t *can2)
{
  uint32_t cur_tp, cur_fp, cur_ppv;
  uint32_t can1_tp, can1_fp, can1_ppv;
  uint32_t can2_tp, can2_fp, can2_ppv;
  uint32_t del_tp, del_fp, del_ppv;

  /* if we don't gain any true positives, then no better */
  if(can2->tp_c <= can1->tp_c)
    {
#if 0
      printf("no tp_c %s %u %u\n",
	     can2->regexes[can2->regexc-1]->str, can1->tp_c, can2->tp_c);
#endif
      return 0;
    }

  /* if we don't gain three routers, then no better */
  if(can2->rt_c < can1->rt_c + 3 && can2->regexes[can2->regexc-1]->rt_c < 3)
    {
#if 0
      printf("no gain %s %u %u %u\n", can2->regexes[can2->regexc-1]->str,
	     can1->rt_c, can2->rt_c, can2->regexes[can2->regexc-1]->rt_c);
#endif
      return 0;
    }

  /*
   * if we gain false positives, the fraction of correct assignments
   * made in the delta must be better than the current regex does
   */
  can1_fp = can1->fp_c + can1->ip_c;
  can2_fp = can2->fp_c + can2->ip_c;
  if(can2_fp > can1_fp)
    {
      can1_tp = can1->tp_c;
      can2_tp = can2->tp_c;
      del_tp = can2_tp - can1_tp;
      del_fp = can2_fp - can1_fp;

      /* make sure there are more TP than FP */
      if(del_tp <= del_fp)
	return 0;

      cur_tp = cur->tp_c;
      cur_fp = cur->fp_c + cur->ip_c;
      del_ppv = (del_tp * 1000) / (del_tp + del_fp);
      cur_ppv = (cur_tp * 1000) /  (cur_tp + cur_fp);
      can2_ppv = (can2_tp * 1000) / (can2_tp + can2_fp);
      can1_ppv = (can1_tp * 1000) / (can1_tp + can1_fp);

#if 0
      printf("%s %d %d | %d %d %d %d\n",
	     can2->regexes[can2->regexc-1]->str, del_tp, del_fp,
	     del_ppv, cur_ppv, can1_ppv, can2_ppv);
#endif

      if((del_ppv < cur_ppv && del_ppv < can1_ppv &&
	  can1_ppv - del_ppv > 20 && del_fp > 1) ||
	 (can2_ppv < can1_ppv && can1_ppv - can2_ppv > 20))
	{
#if 0
	  printf("poor ppv %s %u %u %u %u\n",
		 can2->regexes[can2->regexc-1]->str,
		 del_tp, del_tp + del_fp, cur_tp, cur_tp+cur_fp);
#endif
	  return 0;
	}
    }

  return 1;
}

static int sc_regex_fne_isbetter2(sc_regex_t *cur, sc_regex_t *can)
{
  uint32_t cur_tp, cur_fp, can_tp, can_fp, cur_ppv, can_ppv;

  can_tp = can->tp_c; can_fp = can->fp_c + can->ip_c;
  cur_tp = cur->tp_c; cur_fp = cur->fp_c + cur->ip_c;

  if(cur->rt_c > 3 && can->rt_c < 3)
    return 0;

  /*
   * the candidate regex has to at least have a true positive to avoid
   * dividing by zero later.
   */
  if(can_tp == 0)
    return 0;

  /* if we get more TPs and less FPs, then better */
  if(can_tp >= cur_tp && can_fp <= cur_fp)
    return 1;

  /* if we get less TPs and more FPs, then worse */
  if(can_tp < cur_tp && can_fp > cur_fp)
    return 0;

  /* if we get more TPs and one more FP, then tag the regex as better */
  if(can_tp > cur_tp && can_fp == cur_fp + 1)
    return 1;

  /* if the candidate has less FP + FNE than the current, then better */
  if(can->fp_c + can->fne_c < cur->fp_c + cur->fne_c)
    return 1;

  /*
   * if the PPV of the candidate regex is less than the current
   * regex, and worse by more than 0.5%, then it is not better
   */
  cur_ppv = (cur_tp * 1000) / (cur_tp + cur_fp);
  can_ppv = (can_tp * 1000) / (can_tp + can_fp);
  if(cur_ppv > can_ppv && cur_ppv - can_ppv > 5)
    return 0;

  return 1;
}

static int sc_regex_css_thin(const sc_regex_t *re, int cap, dlist_t *css_list)
{
  char *str = NULL, *restr = re->regexes[0]->str;
  dlist_t *out = NULL;
  sc_regex_t *re_work = NULL;
  sc_css_t *css;
  size_t len;

  if(dlist_count(css_list) < 2)
    return 0;

  if((out = dlist_alloc()) == NULL)
    goto err;

  len = sizeof(sc_regexn_t *) * dlist_count(css_list);
  if((re_work = malloc_zero(sizeof(sc_regex_t))) == NULL ||
     (re_work->regexes = malloc_zero(len)) == NULL)
    goto err;
  re_work->dom = re->dom;
  re_work->regexc = 1;

  css = dlist_tail_pop(css_list);
  if(dlist_head_push(out, css) == NULL)
    goto err;
  if((str = sc_regex_caprep(restr, cap, 0, css->css)) == NULL ||
     (re_work->regexes[0] = sc_regexn_alloc(str)) == NULL)
    goto err;
  free(str); str = NULL;

  while((css = dlist_tail_pop(css_list)) != NULL)
    {
      if((str = sc_regex_caprep(restr, cap, 0, css->css)) == NULL ||
	 (re_work->regexes[re_work->regexc++] = sc_regexn_alloc(str)) == NULL)
	goto err;
      free(str); str = NULL;
      if(sc_regex_eval(re_work, NULL) != 0)
	goto err;

      if(re_work->regexes[re_work->regexc-1]->matchc != 0)
	{
	  if(dlist_tail_push(out, css) == NULL)
	    goto err;
	}
      else
	{
	  sc_css_free(css);
	  css = NULL;
	  sc_regexn_free(re_work->regexes[re_work->regexc-1]);
	  re_work->regexc--;
	}
    }

  sc_regex_free(re_work);
  dlist_concat(css_list, out);
  dlist_free(out);

  return 0;

 err:
  if(str != NULL) free(str);
  if(re_work != NULL) sc_regex_free(re_work);
  return -1;
}

/*
 * sc_regex_refine_fne
 *
 * given a regex that appears to split interfaces of a router apart,
 * determine if there are literal components in a match component that
 * we should not extract, but we should match on.
 */
static int sc_regex_refine_fne(sc_regex_t *re)
{
  splaytree_t *rd_ri_tree = NULL, *rd_tree = NULL, *css_tree = NULL;
  splaytree_t *re_tree = NULL;
  slist_t *rd_ri_list = NULL, *ri_list = NULL;
  sc_rework_t *rew = NULL, *rew_eval = NULL;
  sc_css_t *ri_css, *rd_css, *css;
  sc_regex_t *re_eval = NULL, *re_work = NULL;
  sc_regexn_t *ren;
  sc_regex_css_t *recss;
  slist_t *list = NULL, *ifi_list = NULL, *ifi2_list = NULL, *ifi3_list = NULL;
  dlist_t *recss_list = NULL, *css_list = NULL;
  slist_node_t *sn; dlist_node_t *dn, *dn_this;
  sc_routerdom_t *rd;
  sc_routerinf_t *ri;
  sc_ptrc_t *ptrc;
  int i, x, cap, capc, rc = -1;
  int *caps = NULL;
  char *str = NULL;
  char buf[128];
  size_t s;

  if((rew = sc_rework_alloc(re)) == NULL ||
     (ri_list = slist_alloc()) == NULL ||
     (rd_tree = splaytree_alloc((splaytree_cmp_t)sc_ptrc_ptr_cmp)) == NULL ||
     (rd_ri_list = slist_alloc()) == NULL ||
     (rd_ri_tree = splaytree_alloc((splaytree_cmp_t)sc_ptrc_ptr_cmp)) == NULL)
    goto done;
  if(sc_regex_alias_eval(re, ri_list) != 0)
    goto done;

  if((css_tree = sc_routerdom_css_tree(re->dom->routers)) == NULL)
    goto done;

  /* array to count which element seems to be too specific */
  if((capc = sc_rework_capcount(rew, 0)) < 0)
    goto done;
  if(capc < 2)
    {
      rc = 0;
      goto done;
    }
  if((caps = malloc_zero(sizeof(int) * (capc + 1))) == NULL)
    goto done;

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      /* skip over interfaces where the regex did not match */
      ri = slist_node_item(sn);
      ri_css = ri->ifaces[0]->css;
      if(ri->ifacec == 1 && ri_css == NULL)
	continue;

      for(s=0; s<ri->ifacec; s++)
	{
	  /*
	   * skip over interfaces which did not have a more specific
	   * name
	   */
	  if(ri->ifaces[s]->class != '-' ||
	     (rd_css = ri->ifaces[s]->ifd->rd->css) == NULL ||
	     sc_css_morespecific(rd_css, ri_css) == 0)
	    continue;

	  /*
	   * if the less specific name is not unique among routers,
	   * skip
	   */
	  if((css = splaytree_find(css_tree, rd_css)) == NULL)
	    goto done;
	  if(css->count > 1)
	    continue;

	  /* count this router as maybe not matching */
	  if((ptrc = sc_ptrc_get(rd_ri_tree, ri->ifaces[s]->ifd->rd)) == NULL)
	    goto done;
	  ptrc->c++;

	  if(sc_css_morespecific_ex(rd_css, ri_css, &css) != 0 ||
	     css == NULL || css->cssc != 1)
	    {
	      if(css != NULL)
		{
		  sc_css_free(css);
		  css = NULL;
		}
	      continue;
	    }
	  sc_css_morespecific_ov(rew, css, ri->ifaces[s]->ifd->iface, &cap);
	  sc_css_free(css); css = NULL;
	  caps[cap]++;
	}

      splaytree_inorder(rd_ri_tree, tree_to_slist, rd_ri_list);
      while((ptrc = slist_head_pop(rd_ri_list)) != NULL)
	{
	  if((ptrc = sc_ptrc_get(rd_tree, ptrc->ptr)) == NULL)
	    goto done;
	  ptrc->c++;
	}
      splaytree_empty(rd_ri_tree, (splaytree_free_t)sc_ptrc_free);
    }
  sc_rework_free(rew); rew = NULL;

  /*
   * if there are at least four routers that appear to be too specific,
   * then look further.  otherwise move on.
   */
  rc = splaytree_count(rd_tree);
  if(rc < 4)
    {
      rc = 0;
      goto done;
    }

  /* figure out the capture element that is likely the too specific one */
  cap = 0;
  for(i=1; i<=capc; i++)
    if(caps[cap] < caps[i])
      cap = i;
  if(cap == 0)
    goto done;
  free(caps); caps = NULL;

  /* build a regex that only matches this element */
  if((str = sc_regex_caponly(re->regexes[0]->str, cap)) == NULL)
    goto done;
  if((re_eval = sc_regex_alloc(str)) == NULL)
    goto done;
  str = NULL;
  re_eval->dom = re->dom;
  if((rew_eval = sc_rework_alloc(re_eval)) == NULL)
    goto done;

  /* loop through the interfaces, extracting the literals seen */
  splaytree_empty(css_tree, (splaytree_free_t)sc_css_free);
  for(sn=slist_head_node(re->dom->routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	{
	  if((x = sc_rework_match(rew_eval, rd->ifaces[i]->iface, &css)) < 0)
	    goto done;
	  if(x != 1 || css == NULL)
	    continue;
	  if(sc_css_get(css_tree, css) == NULL)
	    goto done;
	  sc_css_free(css);
	}
    }
  sc_rework_free(rew_eval); rew_eval = NULL;
  sc_regex_free(re_eval); re_eval = NULL;

  if((css_list = sc_css_reduce_ls(css_tree)) == NULL)
    goto done;
  splaytree_free(css_tree, (splaytree_free_t)sc_css_free); css_tree = NULL;

  /*
   * build a set of regexes that substitute a more specific extraction
   * with a supplied literal match
   */
  if((recss_list = dlist_alloc()) == NULL ||
     (re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto done;
  while((css = dlist_head_pop(css_list)) != NULL)
    {
      if((str = sc_regex_caprep(re->regexes[0]->str,cap,0,css->css)) == NULL)
	goto done;
      if(sc_regex_find(re_tree, str, 0, NULL) == NULL)
	{
	  /* create and evaluate a regex that matches with the literal */
	  if((re_eval = sc_regex_get(re_tree, str, 0, NULL)) == NULL)
	    goto done;
	  re_eval->score = re->score + css->count;
	  re_eval->dom = re->dom;
	  if(sc_regex_alias_eval(re_eval, NULL) != 0)
	    goto done;

	  /* tag the regex with the css */
	  if((recss = malloc_zero(sizeof(sc_regex_css_t))) == NULL)
	    goto done;
	  recss->regex = re_eval; re_eval = NULL;
	  recss->css = css; css = NULL;
	  if(dlist_tail_push(recss_list, recss) == NULL)
	    {
	      sc_regex_css_free(recss);
	      goto done;
	    }
	  re_eval = NULL;
	}
      if(css != NULL)
	{
	  sc_css_free(css);
	  css = NULL;
	}
      free(str); str = NULL;
    }
  splaytree_free(re_tree, NULL); re_tree = NULL;
  dlist_qsort(recss_list, (dlist_cmp_t)sc_regex_css_regex_score_cmp);

  if(do_debug != 0 && threadc <= 1)
    {
      for(dn=dlist_head_node(recss_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  recss = dlist_node_item(dn);
	  printf("%s %s\n", recss->regex->regexes[0]->str,
		 sc_regex_score_tostr(recss->regex, buf, sizeof(buf)));
	}
    }

  /* take the top element off the list and assume its a good place to start */
  recss = dlist_head_pop(recss_list);
  if(dlist_tail_push(css_list, recss->css) == NULL)
    goto done;
  recss->css = NULL;
  re_work = recss->regex; recss->regex = NULL;
  sc_regex_css_free(recss); recss = NULL;

  /* build a set of inferences which we re-use */
  if((ifi_list = slist_alloc()) == NULL ||
     (ifi2_list = slist_alloc()) == NULL ||
     (ifi3_list = slist_alloc()) == NULL)
    goto done;

  for(;;)
    {
      slist_empty_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
      if(sc_regex_ifi_build(re_work, ifi_list) != 0)
	goto done;

      /* build a new set of regexes that include the current working regex */
      dn = dlist_head_node(recss_list);
      while(dn != NULL)
	{
	  recss = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);

	  ren = recss->regex->regexes[0];
	  if((re_eval = sc_regex_tail_push(re_work, ren)) == NULL)
	    goto done;
	  re_eval->score = re_work->score + recss->regex->score;
	  if(recss->work != NULL) sc_regex_free(recss->work);
	  recss->work = re_eval; re_eval = NULL;

	  if(sc_regex_ifi_build(recss->regex, ifi2_list) != 0 ||
	     sc_regex_ifi_build2(ifi_list, ifi2_list,
				      recss->work->regexc-1, ifi3_list) != 0 ||
	     sc_regex_alias_ifi_score(recss->work, ifi3_list) != 0)
	    goto done;

	  slist_empty_cb(ifi2_list, (slist_free_t)sc_ifaceinf_free);
	  slist_foreach(ifi3_list, (slist_foreach_t)sc_ifaceinf_css_null,NULL);
	  slist_empty_cb(ifi3_list, (slist_free_t)sc_ifaceinf_free);

	  /* if the regex is no longer relevant, don't try it again */
	  if(recss->work->regexes[recss->work->regexc-1]->matchc <= 0)
	    {
	      sc_regex_css_free(recss);
	      dlist_node_pop(recss_list, dn_this);
	    }
	}
      dlist_qsort(recss_list, (dlist_cmp_t)sc_regex_css_work_score_cmp);

      if(do_debug != 0 && threadc <= 1)
	{
	  for(dn=dlist_head_node(recss_list);dn != NULL;dn=dlist_node_next(dn))
	    {
	      recss = dlist_node_item(dn);
	      printf("%s %s\n", recss->regex->regexes[0]->str,
		     sc_regex_score_tostr(recss->regex, buf, sizeof(buf)));
	    }
	}

      /* take the first regex refinement that is better */
      for(dn=dlist_head_node(recss_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  recss = dlist_node_item(dn);
	  if(sc_regex_fne_isbetter(re, re_work, recss->work) > 0)
	    {
#if 0
	      printf("%s\n%s\n",
		     recss->work->regexes[recss->work->regexc-1]->str,
		     sc_regex_score_tostr(recss->work, buf, sizeof(buf)));
#endif
	      dlist_node_pop(recss_list, dn);
	      sc_regex_free(re_work);
	      re_work = recss->work; recss->work = NULL;
	      dlist_tail_push(css_list, recss->css); recss->css = NULL;
	      sc_regex_css_free(recss); recss = NULL;
	      break;
	    }
	}
      if(dn == NULL)
	break;
    }

  /* make sure there is no redundancy in the set of literals */
  if(sc_regex_css_thin(re, cap, css_list) != 0)
    goto done;
  sc_regex_free(re_work); re_work = NULL;
  str = sc_regex_caprep_list(re->regexes[0]->str, cap, css_list);
  if(str == NULL)
    goto done;
  if((re_work = sc_regex_alloc(str)) == NULL)
    goto done;
  str = NULL;
  re_work->dom = re->dom;
  re_work->score = re->score;
  for(dn=dlist_head_node(css_list); dn != NULL; dn=dlist_node_next(dn))
    {
      css = dlist_node_item(dn);
      re_work->score += css->count;
    }
  if(sc_regex_alias_eval(re_work, NULL) != 0)
    goto done;

  if(sc_regex_fne_isbetter2(re, re_work) > 0)
    {
      if(sc_domain_lock(re->dom) != 0)
	goto done;
      if(slist_tail_push(re->dom->regexes, re_work) == NULL)
	goto done;
      sc_domain_unlock(re->dom);
      re_work = NULL;
    }
  else if(do_debug != 0 && threadc <= 1)
    {
      printf("%s %s\n",
	     re_work->regexes[0]->str,
	     sc_regex_score_tostr(re_work, buf, sizeof(buf)));
      printf("is not better than\n");
      printf("%s %s\n",
	     re->regexes[0]->str, sc_regex_score_tostr(re, buf, sizeof(buf)));
      printf("\n");
    }

  rc = 0;

 done:
  if(ifi3_list != NULL)
    {
      slist_foreach(ifi3_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi3_list, (slist_free_t)sc_ifaceinf_free);
    }
  if(ifi2_list != NULL)
    {
      slist_foreach(ifi2_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi2_list, (slist_free_t)sc_ifaceinf_free);
    }
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(recss_list != NULL)
    dlist_free_cb(recss_list, (dlist_free_t)sc_regex_css_free);
  if(list != NULL) slist_free(list);
  if(rd_tree != NULL) splaytree_free(rd_tree, (splaytree_free_t)sc_ptrc_free);
  if(re_tree != NULL) splaytree_free(re_tree, NULL);
  if(rd_ri_tree != NULL)
    splaytree_free(rd_ri_tree, (splaytree_free_t)sc_ptrc_free);
  if(rd_ri_list != NULL) slist_free(rd_ri_list);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(css_tree != NULL) splaytree_free(css_tree, (splaytree_free_t)sc_css_free);
  if(css_list != NULL) dlist_free_cb(css_list, (dlist_free_t)sc_css_free);
  if(caps != NULL) free(caps);
  if(str != NULL) free(str);
  if(re_eval != NULL) sc_regex_free(re_eval);
  if(re_work != NULL) sc_regex_free(re_work);
  if(rew_eval != NULL) sc_rework_free(rew_eval);
  if(rew != NULL) sc_rework_free(rew);
  return rc;
}

static int sc_regex_refine_init(const sc_regex_t *re, const sc_rework_t *rew,
				int *Xc, size_t **Xa, int *LXc, size_t **LXa,
				sc_css_t **capcss, sc_regex_t **capre,
				sc_rework_t **caprew)
{
  int i, rc = -1;

  *Xa = NULL; *LXa = NULL;
  *capcss = NULL; *capre = NULL; *caprew = NULL;

  *Xc = sc_rework_capcount(rew, 0);
  if((*Xa = malloc(sizeof(size_t) * *Xc * 2)) == NULL)
    goto done;

  /* extract the capture portion of the regex */
  if(sc_regex_capget_css(re->regexes[0]->str, capcss) != 0)
    goto done;
  if((*capcss)->cssc != *Xc)
    goto done;

  /*
   * build a regex that allows us to pick out the literal components in
   * the extraction component of a regex.  check that there are actually
   * literal components at least somewhere...
   */
  if((*capre = sc_regex_alloc_css(*capcss)) == NULL)
    goto done;
  *LXc = 0;
  for(i=0; i<(*capre)->regexc; i++)
    *LXc += (*capre)->regexes[i]->capc;
  if(*LXc == 0)
    {
      sc_regex_free(*capre);
      *capre = NULL;
    }
  else
    {
      if((*LXa = malloc(sizeof(size_t) * *LXc * 2)) == NULL ||
	 (*caprew = sc_rework_alloc(*capre)) == NULL)
	goto done;
#if 0
      printf("%s\n", sc_css_tostr(*capcss, '|', buf, sizeof(buf)));
      for(i=0; i<(*capre)->regexc; i++)
	printf(" %s\n", (*capre)->regexes[i]->str);
#endif
    }

  rc = 0;

 done:
  return rc;
}

/*
 * sc_regex_refine_class_seg
 *
 * this function builds replacement regexes with character classes
 * embedded at the appropriate places.
 */
static int sc_regex_refine_class_seg(slist_t *list, sc_regex_t *re, int ro_in,
				     char *buf, size_t len, size_t off_in,
				     slist_t **segs, int c, int cc, int adj)
{
  sc_segscore_t *ss;
  slist_node_t *sn;
  size_t off = off_in, off_x, segl;
  int ro = ro_in;
  char *dup, *res = re->regexes[0]->str;
  sc_regex_t *re_new;

  if(c == cc)
    {
      while(res[ro] != '\0')
	buf[off++] = res[ro++];
      buf[off++] = '\0';
      if((dup = strdup(buf)) == NULL)
	return -1;
      if((re_new = sc_regex_alloc(dup)) == NULL)
	{
	  free(dup);
	  return -1;
	}
      re_new->dom = re->dom;
      re_new->score = re->score + adj;
      if(slist_tail_push(list, re_new) == NULL)
	{
	  sc_regex_free(re_new);
	  return -1;
	}
      return 0;
    }

  while(res[ro] != '\0')
    {
      /*
       * look for the less specific regex components to replace, i.e.:
       * .+ or [^\.]+ or [^-]+ or .+?
       */
      if((res[ro] == '.' && res[ro+1] == '+') ||
	 (res[ro] == '[' && res[ro+1] == '^'))
	{
	  if(res[ro] == '[')
	    {
	      while(res[ro] != '\0' && res[ro] != ']')
		ro++;
	      if(res[ro] != ']' || res[ro+1] != '+')
		return -1;
	      adj -= 1;
	    }
	  else if(res[ro] == '.' && res[ro+2] == '?')
	    ro++;
	  ro += 2;

	  off_x = off;
	  for(sn=slist_head_node(segs[c]); sn != NULL; sn=slist_node_next(sn))
	    {
	      ss = slist_node_item(sn);
	      off = off_x;

	      /* string_concat(buf, len, &off, "%s", ss->seg); */
	      segl = strlen(ss->seg);
	      if(len - off < segl + 1)
		return -1;
	      memcpy(buf+off, ss->seg, segl + 1); off += segl;

	      if(sc_regex_refine_class_seg(list, re, ro, buf, len, off,
					   segs, c+1, cc,
					   adj + ss->score) != 0)
		return -1;
	    }
	  return 0;
	}
      else if(res[ro] == '\\')
	{
	  buf[off++] = res[ro++];
	  buf[off++] = res[ro++];
	}
      else
	{
	  buf[off++] = res[ro++];
	}
    }

  return -1;
}

/*
 * slist_str_len
 *
 * determine if all the strings in the list are the same length.
 * returns zero if they are not all the same length, the length
 * otherwise.
 */
static size_t slist_str_len(const slist_t *list, int (*filter)(const char *))
{
  size_t seglen = 0, len;
  slist_node_t *sn;
  char *ptr;

  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      ptr = slist_node_item(sn);
      if(filter != NULL && filter(ptr) == 0)
	continue;
      len = strlen(ptr);
      if(seglen != len)
	{
	  if(seglen == 0)
	    {
	      seglen = len;
	      continue;
	    }
	  return 0;
	}
    }

  return seglen;
}

static char *class_seglen(char *buf, size_t len, int seglen)
{
  if(seglen == 0)
    {
      buf[0] = '+';
      buf[1] = '\0';
    }
  else if(seglen >= 2)
    snprintf(buf, len, "{%d}", seglen);
  else
    buf[0] = '\0';
  return buf;
}

/*
 * sc_regex_refine_class_do
 *
 * given an input regex, figure out what more specific components
 * might go between punctuation delimeters.
 */
static int sc_regex_refine_class_do(sc_regex_t *re, slist_t *ifd_list,
				    slist_t *out)
{
  splaytree_t **trees = NULL, *seg_tree = NULL;
  slist_t *list = NULL, *re_list = NULL, **segs = NULL;
  sc_regex_t *capre = NULL, *re2;
  sc_rework_t *caprew = NULL;
  sc_ifacedom_t *ifd;
  sc_segscore_t *ss;
  slist_node_t *sn;
  sc_css_t *css = NULL;
  char *str = NULL, *ptr, buf[256], tmp[16], *alpha_ptr, *digit_ptr;
  int switchc, alpha, digit, score;
  int i, j, x, cc = 0, rc = -1;
  size_t off, len, seglen;

  if((str = sc_regex_capseg(re->regexes[0]->str)) == NULL)
    goto done;
  if((capre = sc_regex_alloc(str)) == NULL)
    goto done;
  str = NULL;
  if((caprew = sc_rework_alloc(capre)) == NULL)
    goto done;
  if((cc = sc_rework_capcount(caprew, 0)) == 0)
    {
      rc = 0;
      goto done;
    }

  if((trees = malloc_zero(sizeof(splaytree_t *) * cc)) == NULL ||
     (list = slist_alloc()) == NULL)
    goto done;

  for(i=0; i<cc; i++)
    if((trees[i] = splaytree_alloc((splaytree_cmp_t)strcmp)) == NULL)
      goto done;

  /*
   * get all the unique strings and put them in a tree per delimited
   * component.
   */
  for(sn=slist_head_node(ifd_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifd = slist_node_item(sn);
      if((x = sc_rework_match(caprew, ifd->iface, &css)) < 0)
	goto done;
      if(x == 0)
	continue;
      ptr = css->css;
      for(j=0; j<css->cssc; j++)
	{
	  if(splaytree_find(trees[j], ptr) == NULL)
	    {
	      if((str = strdup(ptr)) == NULL ||
		 splaytree_insert(trees[j], str) == NULL)
		goto done;
	      str = NULL;
	    }
	  while(*ptr != '\0')
	    ptr++;
	  ptr++;
	}
      sc_css_free(css); css = NULL;
    }

  if((seg_tree = splaytree_alloc((splaytree_cmp_t)sc_segscore_cmp)) == NULL)
    goto done;
  if((segs = malloc_zero(sizeof(slist_t *) * cc)) == NULL)
    goto done;

  for(i=0; i<cc; i++)
    {
      splaytree_inorder(trees[i], tree_to_slist, list);
      assert(slist_count(list) > 0);

      /*
       * this list contains different regex components that we might
       * use in place of the existing component
       */
      if((segs[i] = slist_alloc()) == NULL)
	goto done;

      /*
       * if there is only one string, then we'll emit that in the
       * final regex
       */
      if(slist_count(list) == 1 &&
	 ((do_learnalias != 0 && re->rt_c >= 2) ||
	  do_learnasn != 0 || do_learnasnames != 0 || do_learngeo != 0))
	{
	  ptr = slist_head_pop(list);
	  if(string_isdigit(ptr) != 0)
	    ss = sc_segscore_alloc("\\d+", 3);
	  else
	    ss = sc_segscore_alloc(ptr, 4);
	  if(ss == NULL || slist_tail_push(segs[i], ss) == NULL)
	    goto done;
	  continue;
	}

      /*
       * figure out if strings in this component always have the same
       * length
       */
      seglen = slist_str_len(list, string_isalnum);

      for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
	{
	  ptr = slist_node_item(sn);
	  off = 0; alpha = 0; digit = 0; switchc = 0; score = 0;
	  alpha_ptr = digit_ptr = NULL;

	  /*
	   * figure out the make-up of the component, in terms of
	   * whether the component contains, digits, alphas, or a
	   * combination of both
	   */
	  while(*ptr != '\0')
	    {
	      if(isdigit((unsigned char)*ptr) != 0)
		{
		  if(digit == 0)
		    {
		      if(digit == 0) switchc++;
		      if(digit_ptr == NULL) digit_ptr = ptr;
		      digit = 1; alpha = 0;
		      /* string_concat(buf, sizeof(buf), &off, "\\d+"); */
		      if(sizeof(buf) - off < 4)
			goto done;
		      buf[off++] = '\\'; buf[off++] = 'd'; buf[off++] = '+';
		      buf[off] = '\0';
		      score += 3;
		    }
		}
	      else if(isalpha((unsigned char)*ptr) != 0)
		{
		  if(alpha == 0)
		    {
		      if(alpha == 0) switchc++;
		      if(alpha_ptr == NULL) alpha_ptr = ptr;
		      alpha = 1; digit = 0;
		      /* string_concat(buf, sizeof(buf), &off, "[a-z]+"); */
		      if(sizeof(buf) - off < 7)
			goto done;
		      buf[off++] = '['; buf[off++] = 'a'; buf[off++] = '-';
		      buf[off++] = 'z'; buf[off++] = ']'; buf[off++] = '+';
		      buf[off] = '\0';
		      score += 3;
		    }
		}
	      else break;
	      ptr++;
	    }

	  /*
	   * if the component contains non-alnum, we will keep the existing
	   * component.
	   */
	  if(*ptr != '\0' || switchc == 0)
	    {
	      if(sc_regex_capget(capre->regexes[0]->str, i+1,
				 buf, sizeof(buf)) != 0)
		goto done;
	      if(strcmp(buf, ".+") == 0 || strcmp(buf, ".+?") == 0)
		score = 0;
	      else
		score = 1;
	      if(sc_segscore_get(seg_tree, buf, score) == NULL)
		goto done;
	      continue;
	    }

	  /* if we switch no more than twice, emit the component */
	  if(switchc <= 2)
	    {
	      if(strcmp(buf, "[a-z]+") == 0)
		snprintf(buf, sizeof(buf), "[a-z]%s",
			 class_seglen(tmp, sizeof(tmp), seglen));

	      if((ss = sc_segscore_get(seg_tree, buf, score)) == NULL)
		goto done;

	      /* keep track of the alpha literals -- foo in foo1, foo2 */
	      if(switchc == 2 && sc_segscore_switch2(ss, alpha_ptr) != 0)
		goto done;
	    }

	  if(switchc > 0)
	    {
	      snprintf(buf, sizeof(buf), "[a-z\\d]%s",
		       class_seglen(tmp, sizeof(tmp), seglen));
	      if(sc_segscore_get(seg_tree, buf, 2) == NULL)
		goto done;
	    }
	}

      splaytree_inorder(seg_tree, tree_to_slist, segs[i]);
      splaytree_empty(seg_tree, NULL);
      slist_empty(list);

      for(sn=slist_head_node(segs[i]); sn != NULL; sn=slist_node_next(sn))
	{
	  ss = slist_node_item(sn);
	  if(ss->tree == NULL)
	    continue;

	  if(splaytree_count(ss->tree) == 1)
	    {
	      /* replace the [a-z]+ with the literal */
	      ptr = splaytree_gethead(ss->tree);
	      if(strcmp(ss->seg, "[a-z]+\\d+") == 0)
		snprintf(buf, sizeof(buf), "%s\\d+", ptr);
	      else if(strcmp(ss->seg, "\\d+[a-z]+") == 0)
		snprintf(buf, sizeof(buf), "\\d+%s", ptr);
	      else continue;
	    }
	  else
	    {
	      splaytree_inorder(ss->tree, tree_to_slist, list);
	      seglen = slist_str_len(list, NULL);
	      slist_empty(list);
	      if(seglen == 0)
		continue;
	      if(strcmp(ss->seg, "[a-z]+\\d+") == 0)
		snprintf(buf, sizeof(buf), "[a-z]%s\\d+",
			 class_seglen(tmp, sizeof(tmp), seglen));
	      else if(strcmp(ss->seg, "\\d+[a-z]+") == 0)
		snprintf(buf, sizeof(buf), "\\d+[a-z]%s",
			 class_seglen(tmp, sizeof(tmp), seglen));
	      else continue;
	    }

	  /* XXX: set score */
	  if((str = strdup(buf)) == NULL)
	    goto done;
	  free(ss->seg); ss->seg = str; str = NULL;
	}
    }

  if(do_debug != 0 && threadc <= 1)
    {
      for(i=0; i<cc; i++)
	{
	  for(sn=slist_head_node(segs[i]); sn != NULL; sn=slist_node_next(sn))
	    {
	      ss = slist_node_item(sn);
	      printf("%d %s %d\n", i, ss->seg, ss->score);
	    }
	}
    }

  if((re_list = slist_alloc()) == NULL)
    goto done;
  len = strlen(re->regexes[0]->str) * 3;
  if((str = malloc(len)) == NULL)
    goto done;
  /* XXX: eventually handle return codes */
  sc_regex_refine_class_seg(re_list, re, 0, str, len, 0, segs, 0, cc, 0);
  free(str); str = NULL;

  for(sn=slist_head_node(re_list); sn != NULL; sn=slist_node_next(sn))
    {
      re2 = slist_node_item(sn);
      sc_regexn_clean_digits(re2->regexes[0]);
      if(re->regexes[0]->plan != NULL)
	{
	  len = sizeof(uint8_t) * re->regexes[0]->capc;
	  re2->regexes[0]->plan = memdup(re->regexes[0]->plan, len);
	  if(re2->regexes[0]->plan == NULL)
	    goto done;
	}
    }

  slist_concat(out, re_list);
  rc = 0;

 done:
  if(trees != NULL)
    {
      for(i=0; i<cc; i++)
	splaytree_free(trees[i], free);
      free(trees);
    }
  if(seg_tree != NULL)
    splaytree_free(seg_tree, (splaytree_free_t)sc_segscore_free);
  if(segs != NULL)
    {
      for(i=0; i<cc; i++)
	if(segs[i] != NULL)
	  slist_free_cb(segs[i], (slist_free_t)sc_segscore_free);
      free(segs);
    }
  if(list != NULL) slist_free(list);
  if(re_list != NULL) slist_free_cb(re_list, (slist_free_t)sc_regex_free);
  if(capre != NULL) sc_regex_free(capre);
  if(caprew != NULL) sc_rework_free(caprew);
  if(str != NULL) free(str);
  return rc;
}

/*
 * sc_regex_refine_class_tree
 *
 * work through the list of classless regexes, adding additional
 * unique regexes that embed classes
 */
static int sc_regex_refine_class_tree(splaytree_t *re_tree, slist_t *ifd_list)
{
  slist_t *re_tree_list = NULL, *re_list = NULL;
  sc_regex_t *re, *re_new = NULL;
  slist_node_t *sn, *sn_tail;
  int rc = -1;

  if((re_tree_list = slist_alloc()) == NULL ||
     (re_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(re_tree, tree_to_slist, re_tree_list);
  sn_tail = slist_tail_node(re_tree_list);
  for(sn=slist_head_node(re_tree_list); sn != NULL; sn=slist_node_next(sn))
    {
      re = slist_node_item(sn);
      if(sc_regex_refine_class_do(re, ifd_list, re_list) != 0)
	goto done;
      while((re_new = slist_head_pop(re_list)) != NULL)
	{
	  if(splaytree_find(re_tree, re_new) != NULL)
	    {
	      sc_regex_free(re_new); re_new = NULL;
	      continue;
	    }
	  if(splaytree_insert(re_tree, re_new) == NULL)
	    goto done;
	}
      if(sn == sn_tail)
	break;
    }

  rc = 0;

 done:
  if(re_new != NULL) sc_regex_free(re_new);
  if(re_list != NULL) slist_free_cb(re_list, (slist_free_t)sc_regex_free);
  if(re_tree_list != NULL) slist_free(re_tree_list);
  return rc;
}

/*
 * sc_regex_refine_class
 *
 * given an input regex, add character classes
 */
static int sc_regex_refine_class(sc_regex_t *re)
{
  splaytree_t *seg_tree = NULL;
  slist_t *ifd_list = NULL, *re_list = NULL;
  slist_t *ri_list = NULL, *ifi_list = NULL;
  sc_regex_t *capre = NULL, *re_eval;
  sc_rework_t *caprew = NULL;
  sc_routerinf_t *ri;
  sc_ifaceinf_t *ifi;
  slist_node_t *sn;
  char *str = NULL, buf[256];
  int rc = -1;
  size_t i;

  if((ifd_list = slist_alloc()) == NULL || (re_list = slist_alloc()) == NULL)
    goto done;

  /* assemble the set of interfaces we want to train with */
  if(do_learnalias != 0)
    {
      if((ri_list = slist_alloc()) == NULL ||
	 sc_regex_alias_eval(re, ri_list) != 0)
	goto done;
      for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
	{
	  ri = slist_node_item(sn);
	  if(ri->ifacec == 1 || ri->ip != 0)
	    continue;
	  for(i=0; i<ri->ifacec; i++)
	    {
	      ifi = ri->ifaces[i];
	      if(ifi->class != '+')
		continue;
	      if(slist_tail_push(ifd_list, ifi->ifd) == NULL)
		goto done;
	    }
	}
      slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free); ri_list = NULL;
    }
  else if(do_learnasn != 0 || do_learnasnames != 0 || do_learngeo != 0)
    {
      if((ifi_list = slist_alloc()) == NULL ||
	 ((do_learnasn != 0 && sc_regex_asn_eval(re, ifi_list) != 0) ||
	  (do_learnasnames != 0 && sc_regex_asnames_eval(re, ifi_list) != 0) ||
	  (do_learngeo != 0 && sc_regex_geo_eval(re, ifi_list) != 0)))
	goto done;
      for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
	{
	  ifi = slist_node_item(sn);
	  if(ifi->class != '+')
	    continue;
	  if(slist_tail_push(ifd_list, ifi->ifd) == NULL)
	    goto done;
	}
      slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free); ifi_list = NULL;
    }

  if(slist_count(ifd_list) == 0)
    goto done;

  /* get the set of regexes and evaluate them */
  if(sc_regex_refine_class_do(re, ifd_list, re_list) != 0)
    goto done;
  slist_free(ifd_list); ifd_list = NULL;
  for(sn=slist_head_node(re_list); sn != NULL; sn=slist_node_next(sn))
    {
      re_eval = slist_node_item(sn);
      if(sc_regex_eval(re_eval, NULL) != 0)
	goto done;
    }
  slist_qsort(re_list, (slist_cmp_t)sc_regex_score_rank_cmp);

  if(do_debug != 0 && threadc <= 1)
    {
      for(sn=slist_head_node(re_list); sn != NULL; sn=slist_node_next(sn))
	{
	  re_eval = slist_node_item(sn);
	  printf("%s %s\n", re_eval->regexes[0]->str,
		 sc_regex_score_tostr(re_eval, buf, sizeof(buf)));
	}
    }

  thin_regexes_domain(re_list, 0x7);
  if(sc_domain_lock(re->dom) != 0)
    goto done;
  slist_concat(re->dom->regexes, re_list);
  sc_domain_unlock(re->dom);

  rc = 0;

 done:
  if(seg_tree != NULL)
    splaytree_free(seg_tree, (splaytree_free_t)sc_segscore_free);
  if(re_list != NULL) slist_free_cb(re_list, (slist_free_t)sc_regex_free);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifd_list != NULL) slist_free(ifd_list);
  if(capre != NULL) sc_regex_free(capre);
  if(caprew != NULL) sc_rework_free(caprew);
  if(str != NULL) free(str);
  return rc;
}

static int sc_regex_fnu_isbetter(sc_regex_t *cur, sc_regex_t *can, int i)
{
  uint32_t cur_tp, cur_fp, cur_ppv;
  uint32_t del_tp, del_fp, del_ppv;
  uint32_t can_tp, can_fp;

  /*
   * if the current regex has more true positives than the candidate,
   * then this refinement cannot be better.
   */
  if(cur->tp_c >= can->tp_c)
    return 0;

  /*
   * the candidate refinement must find at least three more routers
   * and affect 4% of routers to be better.
   */
  if(can->regexes[i]->rt_c < 3 ||
     (can->regexes[i]->rt_c * 100) / cur->rt_c < 4)
    return 0;

  /*
   * if there are any new false positives, determine if rate of false
   * positives seems reasonable
   */
  can_fp = can->fp_c + can->ip_c;
  cur_fp = cur->fp_c + cur->ip_c;
  if(can_fp > cur_fp)
    {
      can_tp = can->tp_c;
      cur_tp = cur->tp_c;
      del_tp = can_tp - cur_tp;
      del_fp = can_fp - cur_fp;
      cur_ppv = (cur_tp * 1000) / (can_tp + can_fp);
      del_ppv = (del_tp * 1000) / (del_tp + del_fp);

      /*
       * if the PPV of the candidate regex is less than the current
       * regex, and worse by more than 0.5%, then it is not better
       */
      if(cur_ppv > del_ppv && cur_ppv - del_ppv > 5)
	return 0;
    }

  return 1;
}

/*
 * sc_regex_refine_fnu
 *
 * figure out regexes that should be paired with another candidate regex,
 * where the candidate regex infers a name, but the regex does not match.
 */
static int sc_regex_refine_fnu(sc_regex_t *re)
{
  static const uint16_t mask = RB_BASE | RB_SEG_LITERAL | RB_SEG_DIGIT;
  sc_routercss_t **rnames = NULL, *rn;
  sc_regex_t *re_eval = NULL, *re_new = NULL, *re_cur = NULL, *re_fnu = NULL;
  slist_t *ri_list = NULL, *ifp_list = NULL, *css_list = NULL;
  splaytree_t *css_tree = NULL, *ifp_tree = NULL, *re_tree = NULL;
  dlist_t *re_list = NULL; slist_t *re2_list = NULL;
  slist_t *ifi_list = NULL, *ifi2_list = NULL, *ifi3_list = NULL;
  slist_t *fnu_list = NULL, *re_set = NULL;
  int Xc, Lc, *bits = NULL, bitc; size_t *Xa = NULL, *La = NULL;
  int r, i, c, x, rc = -1, rnamec = 0; size_t d;
  sc_rework_t *rew = NULL;
  sc_routerdom_t *rd;
  sc_ifacedom_t *ifd;
  sc_ifdptr_t *ifp;
  sc_ifaceinf_t *ifi;
  slist_node_t *sn;
  dlist_node_t *dn, *dn_this;
  sc_css_t *css;
  sc_css_t *capcss = NULL;
  sc_regex_t *capre = NULL;
  sc_rework_t *caprew = NULL;
  int LXc, LXi, LAc; size_t *LAa = NULL, *LXa = NULL;
  uint32_t tp, fp;
  char buf[256], rebuf[256], *ptr = NULL;

  tp = re->tp_c;
  fp = re->fp_c + re->ip_c;
  if(tp + fp == 0 || tp * 100 / (tp + fp) < 90)
    return 0;

  rnamec = slist_count(re->dom->routers);
  if((rew = sc_rework_alloc(re)) == NULL ||
     (rnames = sc_routercss_alias_alloc(re->dom->routers, rew)) == NULL ||
     (ifp_tree = sc_ifdptr_tree(re->dom->routers)) == NULL ||
     (css_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL ||
     (re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL ||
     (re_list = dlist_alloc()) == NULL ||
     (re2_list = slist_alloc()) == NULL ||
     (css_list = slist_alloc()) == NULL ||
     (ri_list = slist_alloc()) == NULL ||
     sc_regex_alias_eval(re, ri_list) != 0 ||
     sc_ifdptr_tree_ri(ifp_tree, ri_list) != 0)
    goto done;

  if(sc_regex_refine_init(re, rew, &Xc, &Xa, &LXc, &LXa,
			  &capcss, &capre, &caprew) != 0)
    goto done;

  for(r=0; r<rnamec; r++)
    {
      rn = rnames[r];
      rd = rn->rd;
      if(rn->css == NULL)
	continue;

      for(i=0; i<rd->ifacec; i++)
	{
	  ifd = rd->ifaces[i];
	  ifp = sc_ifdptr_find(ifp_tree, ifd); assert(ifp != NULL);
	  ifi = ifp->ptr; assert(ifi != NULL);

	  /* if regex matched then skip this interface */
	  if(ifi->css != NULL && sc_css_css_cmp(ifi->css, rn->css) == 0)
	    continue;

	  /* get the parts of the hostname that were not extracted */
	  if((css = sc_css_matchxor(rn->css, ifd)) != NULL)
	    {
	      if(css->cssc > 0)
		{
		  if(sc_css_get(css_tree, css) == NULL)
		    goto done;
		}
	      else if(Xc == 1 && splaytree_count(re_tree) == 0)
		{
		  /*
		   * if there was no extraction, infer that the entire
		   * hostname is to be extracted, and build a regex
		   * that uses the same capture component
		   */
		  if(sc_regex_capget(re->regexes[0]->str,1,buf,sizeof(buf))!=0)
		    continue;
		  x = snprintf(rebuf, sizeof(rebuf), "^(%s)\\.%s$",
			       buf, re->dom->escape);
		  if(x < 0 || (size_t)x >= sizeof(rebuf))
		    goto done;
		  if((re_new = sc_regex_get(re_tree, rebuf, 0, NULL)) == NULL)
		    goto done;
		  re_new->dom = re->dom;
		  re_new->score = re->score; /* XXX: increase score? */
		  re_new = NULL;
		}
	      sc_css_free(css);
	    }
	}
    }

  if(sc_css_reduce(css_tree, 1, 1) != 0) /* trim on non-alnum, min length 1 */
    goto done;
  if(sc_css_reduce(css_tree, 2, 1) != 0) /* trim on char class, min length 1 */
    goto done;
  splaytree_inorder(css_tree, tree_to_slist, css_list);
  splaytree_free(css_tree, NULL); css_tree = NULL;

  for(sn=slist_head_node(css_list); sn != NULL; sn=slist_node_next(sn))
    {
      css = slist_node_item(sn);

      /* skip over css where we don't have any alpha characters */
      if(sc_css_hasalpha(css) == 0)
	continue;

      /*
       * allocate an array large enough to store where the literal can
       * be found
       */
      Lc = css->cssc;
      if((La = malloc(sizeof(size_t) * Lc * 2)) == NULL ||
	 (LAa = malloc(sizeof(size_t) * (Lc+LXc) * 2)) == NULL)
	goto done;
      LAc = Lc + LXc;

      /*
       * go through the routers and build regexes for false negatives
       * that the current regex did not match
       */
      for(r=0; r<rnamec; r++)
	{
	  rn = rnames[r];
	  rd = rn->rd;
	  if(rn->css == NULL)
	    continue;

	  for(i=0; i<rd->ifacec; i++)
	    {
	      ifd = rd->ifaces[i];
	      ifp = sc_ifdptr_find(ifp_tree, ifd); assert(ifp != NULL);
	      ifi = ifp->ptr; assert(ifi != NULL);

	      /* if regex matched then skip this interface */
	      if(ifi->css != NULL && sc_css_css_cmp(ifi->css, rn->css) == 0)
		continue;

	      /* if router name is not found in this interface, skip */
	      if(sc_css_match(rn->css, ifd->label, Xa, 1) != 1)
		continue;

	      /*
	       * if the literal is not found in this interface, skip
	       * XXX: need to xor the name out.
	       */
	      if(sc_css_match(css, ifd->label, La, 0) == 0)
		continue;

	      /*
	       * make sure La and Xa do not overlap, i.e. the literal
	       * is not allowed to be within the extraction
	       */
	      if(threadc <= 1 && do_debug != 0)
		printf("%s %s\n", ifd->label,
		       sc_css_tostr(css, '|', buf, sizeof(buf)));
	      if(pt_overlap(Xa, Xc * 2, La, Lc * 2) != 0)
		continue;

	      /* if the capture portion contains literals, get those */
	      if(capre != NULL)
		{
		  LXi = 0;
		  ptr = rn->css->css;
		  for(c=0; c<capre->regexc; c++)
		    {
		      if(capre->regexes[c]->capc > 0 &&
			 sc_rework_matchk(caprew, c, ptr) == 1)
			{
			  for(d=1; d<caprew->m; d++)
			    {
			      LXa[LXi++] = Xa[2*c]+caprew->ovector[2*d];
			      LXa[LXi++] = Xa[2*c]+caprew->ovector[(2*d)+1]-1;
			    }
			}
		      while(*ptr != '\0')
			ptr++;
		      ptr++;
		    }
		  ptr = NULL;
		  if(LXi != LXc * 2)
		    continue;
		  pt_merge(LAa, La, Lc, LXa, LXc);
		}
	      else
		{
		  memcpy(LAa, La, Lc * 2 * sizeof(size_t));
		}

	      if(pt_to_bits(ifd->label, ifd->len, Xa, Xc*2, LAa, LAc*2,
			    NULL, 0, &bits, &bitc) == 0)
		{
		  /* 0xff, no char classes */
		  if(sc_regex_build(re_tree, ifd->label, re->dom, mask,
				    bits, bitc) != 0)
		    goto done;
		}
	      if(bits != NULL)
		{
		  free(bits);
		  bits = NULL;
		}
	    }
	}

      free(LAa); LAa = NULL;
      free(La); La = NULL;
    }

  /*
   * make sure the capture format matches the base regex by
   * substituting in the capture from the base.
   */
  splaytree_inorder(re_tree, tree_to_dlist, re_list);
  splaytree_empty(re_tree, NULL);
  if(sc_regex_capset_css(re_list, re_tree, capcss) != 0)
    goto done;
  dlist_empty_cb(re_list, (dlist_free_t)sc_regex_free);
  splaytree_inorder(re_tree, tree_to_dlist, re_list);
  splaytree_free(re_tree, NULL); re_tree = NULL;

  if(threadc <= 1 && do_debug != 0)
    {
      for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  re_eval = dlist_node_item(dn);
	  printf("%s\n", re_eval->regexes[0]->str);
	  re_eval = NULL;
	}
    }

  /* build a set of inferences which we re-use */
  if((ifi_list = slist_alloc()) == NULL ||
     (ifi2_list = slist_alloc()) == NULL ||
     (ifi3_list = slist_alloc()) == NULL)
    goto done;

  /* put the regexes into a new list to concat at the end */
  if((re_set = slist_alloc()) == NULL ||
     (fnu_list = slist_alloc()) == NULL)
    goto done;

  re_cur = sc_regex_dup(re);
  for(;;)
    {
      /* in this block, if r == 0 then we should not loop around */
      r = 0;

      slist_empty_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
      if(sc_regex_ifi_build(re_cur, ifi_list) != 0)
	goto done;

      /* try every candidate regex paired with the current regex */
      dn = dlist_head_node(re_list);
      while(dn != NULL)
	{
	  re_eval = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);

	  if(sc_regex_permute(re_cur, ifi_list, re_eval, re_set) != 0)
	    goto done;
	  if(slist_count(re_set) == 0)
	    {
	      if(threadc <= 1 && do_debug != 0)
		printf("no matches %s\n", re_eval->regexes[0]->str);
	      sc_regex_free(re_eval); re_eval = NULL;
	      dlist_node_pop(re_list, dn_this);
	      continue;
	    }

	  /* select the best permutation */
	  re_new = slist_head_pop(re_set);
	  if(slist_tail_push(re2_list, re_new) == NULL)
	    goto done;
	  re_new = NULL;
	  slist_empty_cb(re_set, (slist_free_t)sc_regex_free);
	}
      slist_qsort(re2_list, (slist_cmp_t)sc_regex_score_rank_cmp);

      /* check if any of the paired regexes are better than the current */
      while((re_new = slist_head_pop(re2_list)) != NULL)
	{
	  i = sc_regex_findnew(re_cur, re_new);

	  /* if this regex is no better, then discard it */
	  if(sc_regex_fnu_isbetter(re_cur, re_new, i) != 1)
	    {
	      sc_regex_free(re_new);
	      re_new = NULL;
	      continue;
	    }

	  /*
	   * if the new regex is better than the current regex, put it
	   * in a list for further processing when we finish
	   */
	  if((ptr = strdup(re_new->regexes[i]->str)) == NULL ||
	     (re_fnu = sc_regex_alloc(ptr)) == NULL)
	    goto done;
	  ptr = NULL;
	  if(slist_tail_push(fnu_list, re_fnu) == NULL)
	    goto done;
	  re_fnu->score = re_new->score - re_cur->score;
	  re_fnu->dom = re->dom;
	  re_fnu = NULL;

	  /*
	   * update the current regex so that we can efficiently find
	   * other productive regexes, and loop again (r = 1)
	   */
	  sc_regex_free(re_cur);
	  re_cur = re_new; re_new = NULL;
	  r = 1;
	  break;
	}
      slist_empty_cb(re2_list, (slist_free_t)sc_regex_free);

      /* do not loop anymore */
      if(r == 0)
	break;
    }

  for(sn=slist_head_node(fnu_list); sn != NULL; sn=slist_node_next(sn))
    {
      re_fnu = slist_node_item(sn);
      sc_regex_alias_eval(re_fnu, NULL);
      re_fnu = NULL;
    }

  if(sc_domain_lock(re->dom) != 0)
    goto done;
  slist_concat(re->dom->regexes, fnu_list);
  sc_domain_unlock(re->dom);

  rc = 0;

 done:
  if(ifi3_list != NULL)
    {
      slist_foreach(ifi3_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi3_list, (slist_free_t)sc_ifaceinf_free);
    }
  if(ifi2_list != NULL)
    {
      slist_foreach(ifi2_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi2_list, (slist_free_t)sc_ifaceinf_free);
    }
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(La != NULL) free(La);
  if(LAa != NULL) free(LAa);
  if(LXa != NULL) free(LXa);
  if(Xa != NULL) free(Xa);
  if(ptr != NULL) free(ptr);
  if(capcss != NULL) sc_css_free(capcss);
  if(capre != NULL) sc_regex_free(capre);
  if(caprew != NULL) sc_rework_free(caprew);
  if(rew != NULL) sc_rework_free(rew);
  if(rnames != NULL) sc_routercsss_free(rnames, rnamec);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifp_list != NULL) slist_free(ifp_list);
  if(ifp_tree != NULL)
    splaytree_free(ifp_tree, (splaytree_free_t)sc_ifdptr_free);
  if(css_tree != NULL) splaytree_free(css_tree, (splaytree_free_t)sc_css_free);
  if(re_tree != NULL) splaytree_free(re_tree, (splaytree_free_t)sc_regex_free);
  if(re_list != NULL) dlist_free_cb(re_list, (dlist_free_t)sc_regex_free);
  if(re2_list != NULL) slist_free_cb(re2_list, (slist_free_t)sc_regex_free);
  if(fnu_list != NULL) slist_free_cb(fnu_list, (slist_free_t)sc_regex_free);
  if(re_set != NULL) slist_free_cb(re_set, (slist_free_t)sc_regex_free);
  if(css_list != NULL) slist_free_cb(css_list, (slist_free_t)sc_css_free);
  if(re_new != NULL) sc_regex_free(re_new);
  if(re_cur != NULL) sc_regex_free(re_cur);
  if(re_fnu != NULL) sc_regex_free(re_fnu);
  return rc;
}

/*
 * sc_regex_refine_ip
 *
 * figure out regexes to filter out extractions that contain at least portion
 * of an IP literal
 */
static int sc_regex_refine_ip(sc_regex_t *re)
{
  static const uint16_t mask =
    RB_BASE | RB_SEG_LITERAL_IP | RB_SEG_DIGIT | RB_SEG_LITERAL;
  static const uint16_t mask_nolit =
    RB_BASE | RB_SEG_LITERAL_IP | RB_SEG_DIGIT;
  slist_t *ifd_list = NULL, *css_list = NULL;
  slist_t *ri_list = NULL, *ifi_list = NULL;
  dlist_t *re_list = NULL;
  sc_domain_t *dom = re->dom;
  splaytree_t *css_tree = NULL, *re_tree = NULL;
  sc_routerinf_t *ri;
  sc_ifaceinf_t *ifi;
  sc_ifacedom_t *ifd;
  slist_node_t *sn, *sn2;
  dlist_node_t *dn, *dn_this;
  sc_css_t *css;
  sc_regex_t *re_ip = NULL, *re_new = NULL;
  int *bits = NULL, bitc, rc = -1;
  size_t *I_array = NULL, i;
  char buf[256];

  if((re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto done;

  if((ifd_list = slist_alloc()) == NULL ||
     (css_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
    goto done;

  /* assemble the set of interfaces we want to train with */
  if(do_learnalias != 0)
    {
      if((ri_list = slist_alloc()) == NULL ||
	 sc_regex_alias_eval(re, ri_list) != 0)
	goto done;
      for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
	{
	  ri = slist_node_item(sn);
	  for(i=0; i<ri->ifacec; i++)
	    if(ri->ifaces[i]->class == 'x' &&
	       slist_tail_push(ifd_list, ri->ifaces[i]->ifd) == NULL)
	      goto done;
	}
    }
  else if(do_learnasn != 0 || do_learnasnames != 0 || do_learngeo != 0)
    {
      if((ifi_list = slist_alloc()) == NULL ||
	 ((do_learnasn != 0 && sc_regex_asn_eval(re, ifi_list) != 0) ||
	  (do_learnasnames != 0 && sc_regex_asnames_eval(re, ifi_list) != 0) ||
	  (do_learngeo != 0 && sc_regex_geo_eval(re, ifi_list) != 0)))
	goto done;
      for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
	{
	  ifi = slist_node_item(sn);
	  if(ifi->class == 'x' &&
	     slist_tail_push(ifd_list, ifi->ifd) == NULL)
	    goto done;
	}
    }

  for(sn=slist_head_node(ifd_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifd = slist_node_item(sn);

      /* generate a regex covering only the IP address, no literals */
      if(pt_to_bits_ip(ifd, NULL, 0, &bits, &bitc) == 0)
	{
	  if(sc_regex_build(re_tree,ifd->label,dom,mask_nolit,bits,bitc) != 0)
	    goto done;
	}
      if(bits != NULL)
	{
	  free(bits);
	  bits = NULL;
	}

      /* if the entire hostname is an IP address, skip over */
      if((ifd->iface->flags & SC_IFACE_FLAG_IP) != 0 &&
	 ifd->iface->ip_s == 0 && ifd->label[ifd->iface->ip_e+1] == '\0')
	continue;

      if(sc_ifacedom_css(ifd, &css, 0) != 0)
	goto done;
      if(css == NULL)
	continue;

      /* insert the css if not already present */
      if(sc_css_get(css_tree, css) == NULL)
	goto done;
      sc_css_free(css);
    }
  if(sc_css_reduce(css_tree, 1, 1) != 0) /* trim on non-alnum, min length 1 */
    goto done;
  if(sc_css_reduce(css_tree, 2, 1) != 0) /* trim on char class, min length 1 */
    goto done;

  /* use literals to build regexes */
  if((css_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(css_tree, tree_to_slist, css_list);

  for(sn=slist_head_node(css_list); sn != NULL; sn=slist_node_next(sn))
    {
      css = slist_node_item(sn);
      I_array = malloc(sizeof(size_t) * 2 * css->cssc);
      for(sn2=slist_head_node(ifd_list); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  ifd = slist_node_item(sn2);
	  if(sc_css_match(css, ifd->label, I_array, 0) == 1)
	    {
	      if(pt_to_bits_ip(ifd, I_array, css->cssc * 2, &bits, &bitc) == 0)
		{
		  if(sc_regex_build(re_tree,ifd->label,dom,mask,bits,bitc) != 0)
		    goto done;
		}
	      if(bits != NULL)
		{
		  free(bits);
		  bits = NULL;
		}
	    }
	}
      free(I_array); I_array = NULL;
    }

  /* add classes to the regexes */
  if(sc_regex_refine_class_tree(re_tree, ifd_list) != 0)
    goto done;

  if((re_list = dlist_alloc()) == NULL)
    goto done;
  splaytree_inorder(re_tree, tree_to_dlist, re_list);
  splaytree_free(re_tree, NULL); re_tree = NULL;

  for(;;)
    {
      /*
       * evaluate all of the candidate IP filters.  when we're done,
       * free the old ri_list / ifi_list -- the next block of code
       * replaces it with inferences from the refined naming convention.
       */
      if(do_learnasn != 0)
	{
	  for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	    {
	      re_ip = dlist_node_item(dn);
	      if(sc_regex_ip_ri_eval(re_ip, ri_list) != 0)
		goto done;
	    }
	  slist_empty_cb(ri_list, (slist_free_t)sc_routerinf_free);
	}
      else if(do_learnasn != 0 || do_learnasnames != 0 || do_learngeo != 0)
	{
	  for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	    {
	      re_ip = dlist_node_item(dn);
	      if(sc_regex_ip_ifi_eval(re_ip, ifi_list) != 0)
		goto done;
	    }
	  slist_empty_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
	}

      dlist_qsort(re_list, (dlist_cmp_t)sc_regex_score_ip_cmp);
      if(do_debug != 0 && threadc <= 1)
	{
	  for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	    {
	      re_ip = dlist_node_item(dn);
	      printf("%s %s\n", re_ip->regexes[0]->str,
		     sc_regex_score_tostr(re_ip, buf, sizeof(buf)));
	    }
	}

      /* clean out any regexes that did not match at least three routers */
      dn = dlist_head_node(re_list);
      while(dn != NULL)
	{
	  re_ip = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);
	  if(re_ip->rt_c < 3)
	    {
	      sc_regex_free(re_ip);
	      dlist_node_pop(re_list, dn_this);
	    }
	}

      re_ip = dlist_head_item(re_list);
      if(re_ip != NULL && re_ip->fp_c == 0 && re_ip->rt_c >= 3)
	{
	  if((re_new = sc_regex_head_push(re, re_ip->regexes[0])) == NULL)
	    goto done;
	  re_new->score = re->score + re_ip->score;

	  /*
	   * evaluate the new regex, replace the set of inferences we
	   * are working with for the next loop
	   */
	  if((do_learnalias != 0 &&
	      sc_regex_alias_eval(re_new, ri_list) != 0) ||
	     (do_learnasn != 0 &&
	      sc_regex_asn_eval(re_new, ifi_list) != 0) ||
	     (do_learnasnames != 0 &&
	      sc_regex_asnames_eval(re_new, ifi_list) !=0 ) ||
	     (do_learngeo != 0 &&
	      sc_regex_geo_eval(re_new, ifi_list) != 0))
	    goto done;

	  /* put a copy on the regex list */
	  if(sc_domain_lock(dom) != 0)
	    goto done;
	  sn = slist_head_push(dom->regexes, re_new);
	  sc_domain_unlock(dom);

	  if(sn == NULL)
	    goto done;
	  re = re_new;
	  re_new = NULL;

	  /* if there's no more IP addresses to filter, then we're done */
	  if(re->ip_c == 0)
	    break;
	}
      else break;
    }

  rc = 0;

 done:
  if(re_new != NULL) sc_regex_free(re_new);
  if(bits != NULL) free(bits);
  if(I_array != NULL) free(I_array);
  if(ifd_list != NULL) slist_free(ifd_list);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(re_list != NULL) dlist_free_cb(re_list, (dlist_free_t)sc_regex_free);
  if(re_tree != NULL) splaytree_free(re_tree, (splaytree_free_t)sc_regex_free);
  if(css_tree != NULL) splaytree_free(css_tree, (splaytree_free_t)sc_css_free);
  if(css_list != NULL) slist_free(css_list);
  return rc;
}

/*
 * sc_regex_alias_fp_eval
 *
 * if regex matches an interface we wish to filter, tp++
 * if regex matches an interface counted as a TP, fp++
 * if regex matches a single interface router, sp++
 * if regex does not match but should have, fnu++
 */
static int sc_regex_alias_fp_eval(slist_t *ri_list, sc_regex_t *re)
{
  splaytree_t *tree = NULL;
  sc_rework_t *rew = NULL;
  int rc = -1, x;
  slist_node_t *sn;
  sc_routerinf_t *ri;
  sc_routerdom_t *rd;
  sc_iface_t *iface;
  size_t i;

  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;
  if((tree = splaytree_alloc((splaytree_cmp_t)ptrcmp)) == NULL)
    goto done;
  sc_regex_score_reset(re);

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      for(i=0; i<ri->ifacec; i++)
	{
	  iface = ri->ifaces[i]->ifd->iface;
	  if((x = sc_rework_match(rew, iface, NULL)) < 0)
	    goto done;

	  /* matched */
	  if(x == 1)
	    {
	      re->matchc++;
	      rd = ri->ifaces[i]->ifd->rd;
	      if(ri->ifaces[i]->class == '!')
		{
		  re->tp_c++;
		  if(splaytree_find(tree, rd) == NULL &&
		     splaytree_insert(tree, rd) == NULL)
		    goto done;
		}
	      else if(ri->ifaces[i]->class == 'x')
		re->ip_c++;
	      else if(ri->ifaces[i]->class == '+' && rd->ifacec > 1)
		re->fp_c++;
	      else if(rd->ifacec == 1)
		re->sp_c++;
	      else /* interfaces tagged '-' */
		re->fne_c++;
	    }
	  else
	    {
	      if(ri->ifaces[i]->class == '!')
		re->fnu_c++;
	    }
	}
    }
  re->rt_c = splaytree_count(tree);
  rc = 0;

 done:
  if(rew != NULL) sc_rework_free(rew);
  if(tree != NULL) splaytree_free(tree, NULL);
  return rc;
}

/*
 * sc_regex_fp_isbetter
 *
 * determine if the candidate false positive filter makes the current
 * best regex materially better
 */
static int sc_regex_fp_isbetter(sc_regex_t *cur, sc_regex_t *can, int x)
{
  sc_regex_t *merged = NULL;
  uint32_t m_fp, c_fp;
  uint32_t cur_ppv, can_ppv;
  int rc = 0;

  /*
   * there must be more true positives (matches correctly removed from
   * a router) than false positives (matches incorrectly removed from
   * a router
   */
  if(can->tp_c <= can->fp_c)
    goto done;

  /*
   * there must be at least three different routers with matches
   * correctly filtered
   */
  if(can->rt_c < 3)
    goto done;

  /*
   * the PPV of the candidate filtering regex must be better than the
   * clustering without it
   */
  cur_ppv = (cur->tp_c * 1000) / (cur->tp_c + cur->fp_c);
  can_ppv = (can->tp_c * 1000) / (can->tp_c + can->fp_c);
  if(cur_ppv >= can_ppv)
    goto done;

  if((merged = sc_regex_plus1(cur, can->regexes[0], x)) == NULL ||
     sc_regex_alias_eval(merged, NULL) != 0)
    {
      rc = -1;
      goto done;
    }

  /* if we're left with fewer than 3 inferred routers */
  if(merged->rt_c < 3)
    goto done;

  c_fp = cur->fp_c + cur->ip_c;
  m_fp = merged->fp_c + merged->ip_c;

  /* sanity check: we must at least reduce the number of FPs */
  if(c_fp <= m_fp)
    goto done;

  /*
   * if the reduction in FPs is not at least 10% of the FPs that we
   * started with, then stop
   */
  if(((c_fp - m_fp) * 100 / c_fp) < 10)
    {
      rc = 0;
      goto done;
    }

  rc = 1;

 done:
  if(merged != NULL) sc_regex_free(merged);
  return rc;
}

static int sc_regex_refine_fp_best(sc_regex_t *re, int x, dlist_t *re_list,
				   slist_t *ifd_list, slist_t *ri_list,
				   sc_regex_t **re_out)
{
  sc_regex_t *re_fp, *re_fp2, *re_tmp = NULL;
  dlist_node_t *dn; slist_node_t *sn;
  slist_t *class_list = NULL;
  int rc = -1, i;

  *re_out = NULL;

  for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
    {
      re_fp = dlist_node_item(dn);
      if((i = sc_regex_fp_isbetter(re, re_fp, x)) == -1)
	goto done;
      if(i == 1)
	break;
    }
  if(dn == NULL)
    {
      rc = 0;
      goto done;
    }

  if((class_list = slist_alloc()) == NULL)
    goto done;
  if(sc_regex_refine_class_do(re_fp, ifd_list, class_list) != 0)
    goto done;
  if(slist_count(class_list) > 0)
    {
      for(sn=slist_head_node(class_list); sn != NULL; sn=slist_node_next(sn))
	{
	  re_fp = slist_node_item(sn);
	  if(sc_regex_alias_fp_eval(ri_list, re_fp) != 0)
	    goto done;
	}
      slist_qsort(class_list, (slist_cmp_t)sc_regex_score_fp_cmp);

      re_fp = dlist_node_item(dn);
      re_fp2 = slist_head_item(class_list);
      if(sc_regex_score_fp_cmp(re_fp, re_fp2) > 0)
	re_fp = re_fp2;
    }

  if((re_tmp = sc_regex_plus1(re, re_fp->regexes[0], x)) == NULL)
    goto done;
  re_tmp->score = re->score + re_fp->score;
  *re_out = re_tmp;
  rc = 0;

 done:
  if(class_list != NULL) slist_free_cb(class_list, (slist_free_t)sc_regex_free);
  return rc;
}

/*
 * sc_regex_refine_fp
 *
 * given an input regex with false positives, build regexes that might
 * filter those false positives out.
 */
static int sc_regex_refine_fp(sc_regex_t *re)
{
  static const uint16_t mask = RB_BASE | RB_SEG_LITERAL | RB_SEG_DIGIT;
  slist_t *ifd_list = NULL, *ifi_list = NULL, *ri_list = NULL, *css_list = NULL;
  dlist_t *re_list = NULL;
  splaytree_t *css_tree = NULL, *re_tree = NULL;
  sc_routerinf_t *ri;
  sc_ifacedom_t *ifd;
  sc_ifaceinf_t *ifi;
  slist_node_t *sn, *sn2;
  dlist_node_t *dn, *dn_this;
  sc_css_t *css = NULL;
  sc_regex_t *re_fp = NULL, *re_tmp = NULL;
  int *bits = NULL, bitc, x, rc = -1;
  size_t *La = NULL, i, len;
  char buf[256], *str;

  if((re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto done;

  if((ifd_list = slist_alloc()) == NULL ||
     (css_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
    goto done;

  if(do_learnalias != 0)
    {
      if((ri_list = slist_alloc()) == NULL ||
	 sc_regex_alias_eval(re, ri_list) != 0)
	goto done;

      /* figure out the interfaces where the associations are bad */
      for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
	{
	  ri = slist_node_item(sn);
	  for(i=0; i<ri->ifacec; i++)
	    if(ri->ifaces[i]->class == '!' &&
	       slist_tail_push(ifd_list, ri->ifaces[i]->ifd) == NULL)
	      goto done;
	}
    }
  else if(do_learngeo != 0)
    {
      if((ifi_list = slist_alloc()) == NULL ||
	 sc_regex_geo_eval(re, ifi_list) != 0)
	goto done;
      for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
	{
	  ifi = slist_node_item(sn);
	  if(ifi->class != '!' &&
	     slist_tail_push(ifd_list, ifi->ifd) == NULL)
	    goto done;
	}
    }

  for(sn=slist_head_node(ifd_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifd = slist_node_item(sn);
      if(sc_ifacedom_css(ifd, &css, 0) != 0)
	goto done;
      if(css == NULL)
	continue;
      if(sc_css_get(css_tree, css) == NULL)
	goto done;
      sc_css_free(css); css = NULL;
    }
  if(sc_css_reduce(css_tree, 1, 1) != 0) /* trim on non-alnum, min length 1 */
    goto done;
  if(sc_css_reduce(css_tree, 2, 1) != 0) /* trim on char class, min length 1 */
    goto done;

  /* use literals to build regexes */
  if((css_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(css_tree, tree_to_slist, css_list);
  splaytree_free(css_tree, NULL); css_tree = NULL;

  for(sn=slist_head_node(css_list); sn != NULL; sn=slist_node_next(sn))
    {
      css = slist_node_item(sn);
      if(do_debug != 0 && threadc <= 1)
	printf("%s\n", sc_css_tostr(css, '|', buf, sizeof(buf)));
      La = malloc(sizeof(size_t) * 2 * css->cssc);
      for(sn2=slist_head_node(ifd_list); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  ifd = slist_node_item(sn2);
	  str = ifd->label;
	  if(sc_css_match(css, str, La, 0) == 1)
	    {
	      len = strlen(str);
	      if(pt_to_bits(str, len, NULL, 0, La, css->cssc * 2,
			    NULL, 0, &bits, &bitc) == 0)
		{
		  if(sc_regex_build(re_tree,str,re->dom,mask,bits,bitc) != 0)
		    goto done;
		}
	      if(bits != NULL)
		{
		  free(bits);
		  bits = NULL;
		}
	    }
	}
      free(La); La = NULL;
    }

  if((re_list = dlist_alloc()) == NULL)
    goto done;
  splaytree_inorder(re_tree, tree_to_dlist, re_list);
  splaytree_free(re_tree, NULL); re_tree = NULL;

  x = 0;
  for(;;)
    {
      for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  re_fp = dlist_node_item(dn);
	  if(sc_regex_alias_fp_eval(ri_list, re_fp) != 0)
	    goto done;
	}
      dlist_qsort(re_list, (dlist_cmp_t)sc_regex_score_fp_cmp);

      if(do_debug != 0 && threadc <= 1)
	{
	  printf("fp round %d\n", x);
	  for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	    {
	      re_fp = dlist_node_item(dn);
	      printf("%s %s\n", re_fp->regexes[0]->str,
		     sc_regex_score_tostr(re_fp, buf, sizeof(buf)));
	    }
	}

      /*
       * clear out any with less then three false positives correctly
       * filtered from different routers, because these cannot meet
       * basic criteria to be considered
       */
      dn = dlist_head_node(re_list);
      while(dn != NULL)
	{
	  re_fp = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);
	  if(re_fp->rt_c < 3)
	    {
	      sc_regex_free(re_fp);
	      dlist_node_pop(re_list, dn_this);
	    }
	}

      if(sc_regex_refine_fp_best(re,x, re_list, ifd_list,ri_list, &re_tmp) != 0)
	goto done;

      if(re_tmp == NULL)
	break;

      x++;
      if(sc_domain_lock(re->dom) != 0)
	goto done;
      sn = slist_tail_push(re->dom->regexes, re_tmp);
      sc_domain_unlock(re->dom);
      if(sn == NULL)
	goto done;
      re = re_tmp; re_tmp = NULL;

      slist_empty_cb(ri_list, (slist_free_t)sc_routerinf_free);
      if(sc_regex_alias_eval(re, ri_list) != 0 || sc_regex_thin(re) != 0)
	goto done;

      if(re->fp_c < 2)
	break;
    }

  rc = 0;

 done:
  if(bits != NULL) free(bits);
  if(re_tmp != NULL) sc_regex_free(re_tmp);
  if(ifd_list != NULL) slist_free(ifd_list);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(re_list != NULL) dlist_free_cb(re_list, (dlist_free_t)sc_regex_free);
  if(re_tree != NULL) splaytree_free(re_tree, (splaytree_free_t)sc_regex_free);
  if(css_tree != NULL) splaytree_free(css_tree, (splaytree_free_t)sc_css_free);
  if(css_list != NULL) slist_free_cb(css_list, (slist_free_t)sc_css_free);
  return rc;
}

/*
 * sc_regex_sets_stop
 *
 * should we stop refining this regex, given the gains made this
 * round?
 */
static int sc_regex_sets_stop(sc_regex_t *cur, sc_regex_t *can)
{
  int i;

  /* if the score can't realistically be improved */
  if(can->fne_c + can->fnu_c + can->unk_c + can->fp_c < 2)
    return 1;

  if(do_learnalias != 0)
    {
      /* find the new regex in the candidate */
      i = sc_regex_findnew(cur, can);

      /*
       * if the gain affects less than 4% routers over what we started
       * with, then no better
       */
      if(can->regexes[i]->rt_c * 100 / cur->rt_c < 4)
	return 1;
    }

  return 0;
}

/*
 * sc_regex_sets_isbetter
 *
 * is the candidate regex better than the current best?
 */
static int sc_regex_sets_isbetter(sc_regex_t *cur, sc_regex_t *can)
{
  uint32_t tp_max = 0;
  int i;

  assert(do_learnalias != 0 || do_learnasn != 0 || do_learnasnames != 0 ||
	 do_learngeo != 0);

  /* if we don't gain any true positives, then no better */
  if(can->tp_c <= cur->tp_c)
    return 0;

  /* if the atp score does not increase, then no better */
  if(sc_regex_score_atp(cur) >= sc_regex_score_atp(can))
    return 0;

  if(do_learnalias != 0)
    {
      /*
       * if the new regex is unable to cluster at least three routers,
       * then no better
       */
      i = sc_regex_findnew(cur, can);
      if(can->regexes[i]->rt_c < 3)
	return 0;

      /* make sure the PPV rate is acceptable, otherwise no better */
      if(sc_regex_del_ppv_ok(cur, can) == 0)
	return 0;
    }
  else if(do_learngeo != 0)
    {
      /* figure out the maximum number of TPs contributed */
      for(i=0; i<can->regexc; i++)
	if(can->regexes[i]->tp_c > tp_max)
	  tp_max = can->regexes[i]->tp_c;

      /* XXX: prevent possible division by zero */
      if(tp_max == 0)
	return 0;

      /*
       * make sure each regex identifies at least three unique
       * geocodes, and has at least 1% of the TPs of the regex with
       * the most TPs in the set.
       */
      for(i=0; i<can->regexc; i++)
	{
	  if(can->regexes[i]->rt_c < 3)
	    return 0;
	  if(can->regexes[i]->tp_c * 1000 / tp_max < 10)
	    return 0;
	}

      /* make sure the PPV rate is acceptable, otherwise no better */
      if(sc_regex_del_ppv_ok(cur, can) == 0)
	return 0;
    }
  else if(do_learnasn != 0 || do_learnasnames != 0)
    {
      /*
       * if any component regex is unable to find two unique ASNs,
       * then no better
       */
      for(i=0; i<can->regexc; i++)
	if(can->regexes[i]->rt_c < 2)
	  return 0;
    }

  return 1;
}

/*
 * sc_regex_refine_sets_permute
 *
 * given a base regex (work) and inferences derived from that regex
 * (work_ifi), and a second regex (cand) which we are considering
 * permuting into a regex containing both work and cand, determine the
 * best combination of the two regexes and return that.
 */
static int sc_regex_refine_sets_permute(sc_regex_t *work, slist_t *work_ifi,
					sc_regex_t *cand, sc_regex_t **best)
{
  slist_t *set = NULL;
  int rc = -1;
  sc_regex_t *re;

  assert(cand->regexc == 1);

  if((set = slist_alloc()) == NULL)
    goto done;
  if(sc_regex_permute(work, work_ifi, cand, set) != 0)
    goto done;
  if(slist_count(set) == 0)
    {
      rc = 0;
      goto done;
    }

  slist_qsort(set, (slist_cmp_t)sc_regex_score_rank_cmp);
  re = slist_head_item(set);
  if(sc_regex_sets_isbetter(work, re) != 1 ||
     (*best != NULL && sc_regex_score_rank_cmp(*best, re) <= 0))
    {
      rc = 0;
      goto done;
    }

  if(*best != NULL) sc_regex_free(*best);
  *best = slist_head_pop(set);
  rc = 0;

 done:
  if(set != NULL)
    slist_free_cb(set, (slist_free_t)sc_regex_free);
  return rc;
}

/*
 * sc_regex_refine_sets
 *
 *
 */
static int sc_regex_refine_sets(sc_regex_sni_t *sin)
{
  sc_regex_sn_t *work = sin->work;
  sc_domain_t *dom = work->re->dom;
  slist_t *ifi_list = NULL;
  sc_regex_t *best = NULL;
  sc_regex_sni_t *sni;
  slist_node_t *sn;
  int snic, rc = -1;

  if((ifi_list = slist_alloc()) == NULL ||
     sc_regex_ifi_build(work->re, ifi_list) != 0 ||
     sc_regex_refine_sets_permute(work->re, ifi_list, sin->re, &sin->out) != 0)
    {
      work->done = 1;
      goto done;
    }

  if(sc_regex_sn_lock(work) != 0)
    goto done;
  work->snic--;
  snic = work->snic;
  sc_regex_sn_unlock(work);

  assert(snic >= 0);
  if(snic > 0)
    {
      rc = 0;
      goto done;
    }

  while((sni = slist_head_pop(work->snis)) != NULL)
    {
      if(sni->out != NULL &&
	 (best == NULL || sc_regex_score_rank_cmp(best, sni->out) > 0))
	{
	  if(best != NULL)
	    sc_regex_free(best);
	  best = sni->out;
	  sni->out = NULL;
	}
      sc_regex_sni_free(sni);
    }

  if(best == NULL)
    {
      work->done = 1; rc = 0;
      goto done;
    }

  /*
   * make a copy of the current working regex and put it in
   * the set
   */
  if(sc_domain_lock(dom) != 0)
    goto done;
  sn = slist_tail_push(dom->regexes, best);
  sc_domain_unlock(dom);

  if(sn == NULL)
    goto done;
  if(sc_regex_sets_stop(work->re, best) != 0)
    work->done = 1;
  work->re = best;
  rc = 0;

 done:
  if(ifi_list != NULL)
    slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  return rc;
}

static sc_regex_t *sc_regex_refine_merge_do(sc_remerge_t *rem)
{
  sc_regex_t *re = NULL;
  char *ptr, *ptr_a, *ptr_b, *str = NULL;
  slist_node_t *sn;
  size_t off, len;
  char tmp[4];
  int i;

  /*
   * if the difference between two regexes is a single character, emit
   * a regex that uses an ? operator on that character to make it
   * optional.
   * or if the difference between the two regexes is \d+, then embed
   * \d*
   */
  if(slist_count(rem->list) == 1 &&
     (ptr = slist_head_item(rem->list)) != NULL &&
     (strlen(ptr) == 1 || strcmp(ptr, "\\d+") == 0))
    {
      assert(rem->opt == 1);

      /* figure out the first part of the regex */
      ptr_a = rem->css->css;
      if(strcmp(ptr, "\\d+") == 0)
	{
	  if(strcmp(ptr_a, "^(.+)") == 0)
	    ptr_a = "^(.+?)";
	  snprintf(tmp, sizeof(tmp), "\\d*");
	}
      else snprintf(tmp, sizeof(tmp), "%c?", *ptr);

      /* figure out the second part of the regex */
      if(rem->css->cssc == 2)
	{
	  ptr_b = rem->css->css;
	  while(*ptr_b != '\0')
	    ptr_b++;
	  ptr_b++;
	}
      else ptr_b = NULL;

      /* allocate enough space for the regex, and then build it */
      len = strlen(ptr_a) + strlen(tmp) + 1;
      if(ptr_b != NULL) len += strlen(ptr_b);
      if((str = malloc(len)) == NULL)
	goto done;
      if(ptr_b != NULL)
	snprintf(str, len, "%s%s%s", ptr_a, tmp, ptr_b);
      else
	snprintf(str, len, "%s%s", tmp, ptr_a);

      if((re = sc_regex_alloc(str)) != NULL)
	return re;
      goto done;
    }

  /*
   * sort the strings so that we produce regexes consistently given
   * the inputs available
   */
  slist_qsort(rem->list, (slist_cmp_t)strcmp);

  /*
   * allocate a string buffer that should be large enough to assemble
   * the regex
   */
  len = rem->css->len + 4; /* (?:) */
  if(rem->opt != 0) len++; /* ? */
  for(sn=slist_head_node(rem->list); sn != NULL; sn=slist_node_next(sn))
    {
      ptr = slist_node_item(sn);
      len += strlen(ptr) + 1; /* | */
    }
  if((str = malloc(len)) == NULL)
    goto done;

  /* assemble the regex from its component parts */
  off = 0;
  if(rem->css->cssc == 2)
    string_concat(str, len, &off, "%s", rem->css->css);
  string_concat(str, len, &off, "(?:");
  i = 0;
  for(sn=slist_head_node(rem->list); sn != NULL; sn=slist_node_next(sn))
    {
      ptr = slist_node_item(sn);
      if(i > 0) string_concat(str, len, &off, "|%s", ptr);
      else string_concat(str, len, &off, "%s", ptr);
      i++;
    }
  if(rem->css->cssc == 2)
    {
      ptr = rem->css->css;
      while(*ptr != '\0')
	ptr++;
      ptr++;
    }
  else ptr = rem->css->css;
  if(rem->opt != 0)
    string_concat(str, len, &off, ")?%s", ptr);
  else
    string_concat(str, len, &off, ")%s", ptr);

  /* build a new regex */
  if((re = sc_regex_alloc(str)) != NULL)
    return re;

 done:
  if(str != NULL) free(str);
  return NULL;
}

/*
 * sc_regex_refine_merge_strok
 *
 * is the difference between two strings mergeable?  OK, as long as
 * long as the string contains alphanumeric characters, "\d+", "\d*", "-",
 * and "\."
 */
static int sc_regex_refine_merge_strok(const char *str)
{
  int ok = 0;

  while(*str != '\0')
    {
      if(isalnum((unsigned char)*str) != 0)
	{
	  ok = 1;
	  str++;
	}
      else if(*str == '\\' && *(str+1) == 'd' &&
	      (*(str+2) == '+' || *(str+2) == '*'))
	{
	  ok = 1;
	  str += 3;
	}
      else if(*str == '-')
	{
	  str++;
	}
      else if(*str == '\\' && *(str+1) == '.')
	{
	  str += 2;
	}
      else return 0;
    }

  return ok;
}

/*
 * sc_regex_refine_merge_skip
 *
 * determine if we should build a merged regex given the differences
 * between the regexes.
 */
static int sc_regex_refine_merge_skip(const sc_remerge_t *rem)
{
  slist_node_t *sn;
  char *ptr;
  int x;

  if(slist_count(rem->list) < 1)
    {
      return 1;
    }
  else if(slist_count(rem->list) == 1)
    {
      /* if the only difference is \d*, then don't build (?:\d*)? */
      ptr = slist_head_item(rem->list); assert(ptr != NULL);
      if(strcmp(ptr, "\\d*") == 0)
	return 1;
    }
  else
    {
      /* if all are digits or \d+ or \d* then skip */
      x = 0;
      for(sn=slist_head_node(rem->list); sn != NULL; sn=slist_node_next(sn))
	{
	  ptr = slist_node_item(sn);
	  if(ptr[0]=='\\' && ptr[1]=='d' && (ptr[2] == '*' || ptr[2] == '+'))
	    continue;
	  if(string_isdigit(ptr) == 0)
	    {
	      x = 1;
	      break;
	    }
	}
      if(x == 0)
	return 1;
    }

  return 0;
}

static int sc_regex_refine_merge_setup(char *S, char *T, sc_css_t **css_o,
				       sc_css_t **S_css_o, sc_css_t **T_css_o)
{
  sc_css_t *css = NULL, *S_css = NULL, *T_css = NULL;
  sc_lcs_pt_t *pt1, *pt2;
  slist_t *X = NULL;
  size_t S_len, T_len;
  size_t flat[4], flat_len;
  int rc = -1;

  *css_o = NULL; *S_css_o = NULL; *T_css_o = NULL;
  S_len = strlen(S);
  T_len = strlen(T);

  /* figure out what is in common */
  if((X = lcs(S, S_len, T, T_len, 1)) == NULL)
    goto done;

  /* if there are more than two substrings, can't merge */
  if(slist_count(X) > 2)
    {
      rc = 0;
      goto done;
    }

  /* figure out what is in common, and what is unique to S and T */
  if((css = sc_css_alloc_lcs(X, S)) == NULL)
    goto done;
  pt_s_flatten(X, flat, &flat_len);
  if((S_css = sc_css_alloc_xor(S, S_len, flat, flat_len)) == NULL)
    goto done;
  pt_t_flatten(X, flat, &flat_len);
  if((T_css = sc_css_alloc_xor(T, T_len, flat, flat_len)) == NULL)
    goto done;

  if(S_css->css == NULL && T_css->css == NULL)
    {
      rc = 0;
      goto done;
    }

  if(slist_count(X) == 2)
    {
      /*
       * there are two substrings.  if the difference looks like d+\, then
       * rearrange so we'll end up with \d+
       */
      pt1 = slist_head_item(X);
      pt2 = slist_node_item(slist_node_next(slist_head_node(X)));
      if(S[pt1->S_end] == '\\' &&
	 (S_css->css == NULL || S[pt2->S_start-1] == '\\') &&
	 (T_css->css == NULL || T[pt2->T_start-1] == '\\'))
	{
	  pt1->S_end--; pt2->S_start--;
	  pt1->T_end--; pt2->T_start--;

	  sc_css_free(css); css = NULL;
	  sc_css_free(S_css); S_css = NULL;
	  sc_css_free(T_css); T_css = NULL;

	  if((css = sc_css_alloc_lcs(X, S)) == NULL)
	    goto done;
	  pt_s_flatten(X, flat, &flat_len);
	  if((S_css = sc_css_alloc_xor(S, S_len, flat, flat_len)) == NULL)
	    goto done;
	  pt_t_flatten(X, flat, &flat_len);
	  if((T_css = sc_css_alloc_xor(T, T_len, flat, flat_len)) == NULL)
	    goto done;
	}
    }

  rc = 0;
  if((S_css->css != NULL && sc_regex_refine_merge_strok(S_css->css) == 0)||
     (T_css->css != NULL && sc_regex_refine_merge_strok(T_css->css) == 0))
    goto done;

  *css_o = css; css = NULL;
  *S_css_o = S_css; S_css = NULL;
  *T_css_o = T_css; T_css = NULL;

 done:
  if(css != NULL) sc_css_free(css);
  if(S_css != NULL) sc_css_free(S_css);
  if(T_css != NULL) sc_css_free(T_css);
  if(X != NULL) slist_free_cb(X, (slist_free_t)sc_lcs_pt_free);
  return rc;
}

static int sc_regex_refine_merge(sc_regex_t *re, slist_node_t *sn)
{
  sc_css_t *css = NULL, *S_css = NULL, *T_css = NULL;
  slist_t *list = NULL, *re_list = NULL, *ifi_list = NULL;
  char *S, *T, *dup = NULL;
  splaytree_t *tree = NULL;
  sc_regex_t *re2, *re_new = NULL;
  size_t len;
  sc_remerge_t *rem;
  int rc = -1;

  if(re->rt_c < 2)
    return 0;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_remerge_cmp)) == NULL ||
     (ifi_list = slist_alloc()) == NULL)
    goto done;

  S = re->regexes[0]->str;

  while(sn != NULL)
    {
      re2 = slist_node_item(sn); sn = slist_node_next(sn);
      if(re2->rt_c < 1 ||
	 sc_regexn_plan_cmp(re->regexes[0], re2->regexes[0]) != 0)
	continue;

      T = re2->regexes[0]->str;

      if(sc_regex_refine_merge_setup(S, T, &css, &S_css, &T_css) != 0)
	goto done;
      if(css == NULL)
	continue;

      /*
       * record the common part, and the different parts, in a
       * sc_remerge_t structure
       */
      if((rem = sc_remerge_get(tree, css)) == NULL)
	goto done;
      if(slist_count(rem->list) == 0)
	{
	  if(S_css->css != NULL)
	    {
	      if((dup = strdup(S_css->css)) == NULL ||
		 slist_tail_push(rem->list, dup) == NULL)
		goto done;
	      dup = NULL;
	    }
	  else rem->opt = 1;
	}
      if(T_css->css != NULL)
	{
	  if((dup = strdup(T_css->css)) == NULL ||
	     slist_tail_push(rem->list, dup) == NULL)
	    goto done;
	  dup = NULL;
	}
      else rem->opt = 1;

      if(css != NULL)   { sc_css_free(css);   css = NULL; }
      if(S_css != NULL) { sc_css_free(S_css); S_css = NULL; }
      if(T_css != NULL) { sc_css_free(T_css); T_css = NULL; }
    }

  if(splaytree_count(tree) == 0)
    {
      rc = 0;
      goto done;
    }

  if((list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(tree, (splaytree_inorder_t)tree_to_slist, list);
  splaytree_free(tree, NULL); tree = NULL;

  if((re_list = slist_alloc()) == NULL)
    goto done;
  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      rem = slist_node_item(sn);
      if(sc_regex_refine_merge_skip(rem) != 0)
	continue;
      if((re_new = sc_regex_refine_merge_do(rem)) == NULL)
	goto done;
      re_new->score = re->score;
      re_new->dom = re->dom;

      if(re->regexes[0]->plan != NULL)
	{
	  len = sizeof(uint8_t) * re->regexes[0]->capc;
	  re_new->regexes[0]->plan = memdup(re->regexes[0]->plan, len);
	  if(re_new->regexes[0]->plan == NULL)
	    goto done;
	}

      if(sc_regex_eval(re_new, NULL) != 0)
	goto done;

      if(re_new->rt_c == 0 || sc_regex_issame(re, ifi_list, re_new) != 0)
	{
	  sc_regex_free(re_new); re_new = NULL;
	  continue;
	}

      if(slist_tail_push(re_list, re_new) == NULL)
	goto done;
      re_new = NULL;
    }

  if(sc_domain_lock(re->dom) != 0)
    goto done;
  slist_concat(re->dom->regexes, re_list);
  sc_domain_unlock(re->dom);

  rc = 0;

 done:
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)sc_remerge_free);
  if(list != NULL) slist_free_cb(list, (slist_free_t)sc_remerge_free);
  if(re_list != NULL) slist_free_cb(re_list, (slist_free_t)sc_regex_free);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(css != NULL) sc_css_free(css);
  if(S_css != NULL) sc_css_free(S_css);
  if(T_css != NULL) sc_css_free(T_css);
  if(dup != NULL) free(dup);
  if(re_new != NULL) sc_regex_free(re_new);
  return rc;
}

static int generate_regexes_domain_alias(sc_domain_t *dom)
{
  splaytree_t *re_tree = NULL; /* of sc_regex_t */
  sc_routerdom_t *rd;
  slist_node_t *sn; /* of sc_routerdom_t */
  int i, j;

  if((re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto err;

  for(sn=slist_head_node(dom->routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	{
	  for(j=i+1; j<rd->ifacec; j++)
	    {
	      if(sc_regex_lcs(re_tree, dom, rd->ifaces[i], rd->ifaces[j]) != 0)
		goto err;
	    }
	}
    }

  /*
   * take the regex strings out of the tree and put them in a list
   * ready to be evaluated
   */
  splaytree_inorder(re_tree, tree_to_slist, dom->regexes);
  splaytree_free(re_tree, NULL); re_tree = NULL;
  return 0;

 err:
  if(re_tree != NULL) splaytree_free(re_tree, NULL);
  return -1;
}

static int generate_regexes_domain_asn(sc_domain_t *dom)
{
  splaytree_t *re_tree = NULL;
  sc_routerdom_t *rd = NULL;
  sc_ifacedom_t *ifd1, *ifd2;
  slist_node_t *sn1, *sn2; /* of sc_ifacedom_t */
  slist_t *ifaces = NULL; /* of sc_ifacedom_t */
  int i;

  if((re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL ||
     (ifaces = slist_alloc()) == NULL)
    goto err;

  /*
   * get the hostnames with an apparent ASN embedded and put them
   * in their own list for easier processing
   */
  for(sn1=slist_head_node(dom->routers); sn1 != NULL; sn1=slist_node_next(sn1))
    {
      rd = slist_node_item(sn1);
      for(i=0; i<rd->ifacec; i++)
	if((rd->ifaces[i]->iface->flags & SC_IFACE_FLAG_AS) != 0 &&
	   slist_tail_push(ifaces, rd->ifaces[i]) == NULL)
	  goto err;
    }

  /* all ifaces in the list have an apparent ASN embedded */
  for(sn1=slist_head_node(ifaces); sn1 != NULL; sn1=slist_node_next(sn1))
    {
      ifd1 = slist_node_item(sn1);
      for(sn2=slist_node_next(sn1); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  ifd2 = slist_node_item(sn2);

	  /*
	   * Does the particular label containing the ASN have more structure?
	   * This might include the prefix "as" before the number.
	   */
	  if(sc_regex_asn_lcs(re_tree, dom, ifd1, ifd2) != 0)
	    goto err;
	}
    }
  slist_free(ifaces); ifaces = NULL;

  /*
   * take the regex strings out of the tree and put them in a list
   * ready to be evaluated
   */
  splaytree_inorder(re_tree, tree_to_slist, dom->regexes);
  splaytree_free(re_tree, NULL); re_tree = NULL;
  return 0;

 err:
  if(ifaces != NULL) slist_free(ifaces);
  if(re_tree != NULL) splaytree_free(re_tree, NULL);
  return -1;
}

static int generate_regexes_domain_asnames(sc_domain_t *dom)
{
  static const uint16_t mask = RB_BASE | RB_SEG_DIGIT_SPEC | RB_FIRST_PUNC_END;
  splaytree_t *tree = NULL;
  sc_routerdom_t *rd = NULL;
  sc_ifacedom_t *ifd;
  slist_node_t *sn;
  int i, j, *bits = NULL, bitc, ctype = BIT_TYPE_CAPTURE;
  int16_t c[2];

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto err;

  for(sn=slist_head_node(dom->routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	{
	  ifd = rd->ifaces[i];
	  for(j=0; j<ifd->iface->asnamec; j+=2)
	    {
	      c[0] = ifd->iface->asnames[j];
	      c[1] = ifd->iface->asnames[j+1];
	      if(pt_to_bits_ctype(ifd, &ctype, c, 2, &bits, &bitc) == 0)
		{
		  if(sc_regex_build(tree,ifd->label,dom,mask,bits,bitc) != 0)
		    goto err;
		}
	      if(bits != NULL)
		{
		  free(bits);
		  bits = NULL;
		}
	    }
	}
    }

  /*
   * take the regex strings out of the tree and put them in a list
   * ready to be evaluated
   */
  splaytree_inorder(tree, tree_to_slist, dom->regexes);
  splaytree_free(tree, NULL); tree = NULL;
  return 0;

 err:
  if(tree != NULL) splaytree_free(tree, NULL);
  return -1;
}

static int generate_regexes_domain_geo(sc_domain_t *dom)
{
  static const uint16_t mask =
    RB_BASE | RB_SEG_DIGIT_SPEC | RB_FIRST_PUNC_END | RB_SEG_GEO;
  splaytree_t *tree = NULL;
  sc_routerdom_t *rd = NULL;
  sc_ifacedom_t *ifd;
  slist_node_t *sn;
  int *ctypes = NULL, cc, i, j, *bits = NULL, bitc;
  int16_t *c = NULL;
  sc_geotag_t *tag;
  size_t k;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto err;

  for(sn=slist_head_node(dom->routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	{
	  ifd = rd->ifaces[i];
	  for(j=0; j<ifd->iface->geoc; j++)
	    {
	      tag = &ifd->iface->geos[j];
	      cc = tag->tagc * 2;

	      if((c = malloc(sizeof(int16_t) * cc)) == NULL ||
		 (ctypes = malloc(sizeof(int) * tag->tagc)) == NULL)
		goto err;

	      for(k=0; k<tag->tagc; k++)
		{
		  ctypes[k] = geohint_to_bits_type(tag->tags[k].type);
		  c[(k*2)+0] = tag->tags[k].start;
		  c[(k*2)+1] = tag->tags[k].end;
		}

	      if(pt_to_bits_ctype(ifd, ctypes, c, cc, &bits, &bitc) == 0)
		{
		  if(sc_regex_build(tree,ifd->label,dom,mask,bits,bitc) != 0)
		    goto err;
		}
	      if(bits != NULL) { free(bits); bits = NULL; }
	      if(ctypes != NULL) { free(ctypes); ctypes = NULL; }
	      if(c != NULL) { free(c); c = NULL; }
	    }
	}
    }

  /*
   * take the regex strings out of the tree and put them in a list
   * ready to be evaluated
   */
  splaytree_inorder(tree, tree_to_slist, dom->regexes);
  splaytree_free(tree, NULL); tree = NULL;

  return 0;

 err:
  if(bits != NULL) free(bits);
  if(ctypes != NULL) free(ctypes);
  if(c != NULL) free(c);
  if(tree != NULL) splaytree_free(tree, NULL);
  return -1;
}

static void generate_regexes_thread(sc_domain_t *dom)
{
  if(do_learnalias != 0)
    generate_regexes_domain_alias(dom);
  else if(do_learnasn != 0)
    generate_regexes_domain_asn(dom);
  else if(do_learnasnames != 0)
    generate_regexes_domain_asnames(dom);
  else if(do_learngeo != 0)
    generate_regexes_domain_geo(dom);
  return;
}

static uint32_t regex_file_line_score(char *score_str)
{
  uint32_t score = 0;
  char *ptr = score_str + 6;
  long lo;

  score_str = ptr;
  while(*ptr != '\0' && *ptr != ' ')
    ptr++;
  if(*ptr == ' ')
    *ptr = '\0';
  if(string_isnumber(score_str) != 0 && string_tolong(score_str, &lo) == 0)
    score = (uint32_t)lo;

  return score;
}

static int regex_file_line_plan(sc_regex_t *re, char *plan_str)
{
  sc_regexn_t *ren;
  slist_t *list = NULL;
  char *type, *ptr = plan_str + 7;
  int i = 0, x, eop, rc = -1;

  while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
    ptr++;

  /* look for the opening [ */
  if(*ptr != '[')
    {
      fprintf(stderr, "%s: expected [ got %s\n", __func__, ptr);
      goto done;
    }
  ptr++;

  if((list = slist_alloc()) == NULL)
    {
      fprintf(stderr, "%s: could not alloc list\n", __func__);
      goto done;
    }

  while(*ptr != '\0')
    {
      /* look for the opening [ */
      if(*ptr != '[')
	{
	  fprintf(stderr, "%s: expected [ got %s\n", __func__, ptr);
	  goto done;
	}
      ptr++;

      eop = 0;
      while(eop == 0)
	{
	  /* skip over any whitespace */
	  while(isspace((unsigned char)*ptr) != 0)
	    ptr++;

	  type = ptr;

	  /* continue until we get to a comma ',' or end of plan ']' */
	  while(*ptr != ',' && *ptr != ']' && *ptr != '\0')
	    ptr++;
	  if(*ptr == '\0')
	    {
	      fprintf(stderr, "%s: unexpected null\n", __func__);
	      goto done;
	    }
	  if(*ptr == ']')
	    eop = 1;
	  *ptr = '\0';
	  ptr++;
	  if(slist_tail_push(list, type) == NULL)
	    {
	      fprintf(stderr, "%s: could not push %s\n", __func__, type);
	      goto done;
	    }
	}

      /* any captures? */
      if((x = slist_count(list)) <= 0)
	{
	  fprintf(stderr, "%s: no entries in list\n", __func__);
	  goto done;
	}

      type = slist_head_item(list);
      if(x == 1 && type[0] == '\0')
	{
	  slist_empty(list);
	  goto next;
	}

      /* set the types for each capture */
      ren = re->regexes[i];
      if((ren->plan = malloc_zero(sizeof(uint8_t) * x)) == NULL)
	{
	  fprintf(stderr, "%s: could not malloc %d geotypes\n", __func__, x);
	  goto done;
	}
      ren->capc = x;
      x = 0;
      while((type = slist_head_pop(list)) != NULL)
	{
	  if((ren->plan[x++] = geotype_uint8(type)) == 0)
	    {
	      fprintf(stderr, "%s: unknown type |%s|\n", __func__, type);
	      goto done;
	    }
	}

    next:
      /* end of the plan */
      if(*ptr == ']')
	break;
      if(*ptr != ',')
	{
	  fprintf(stderr, "%s: expected , got %s\n", __func__, ptr);
	  goto done;
	}
      ptr++;
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;
      i++;
    }

  rc = 0;

 done:
  if(list != NULL) slist_free(list);
  return rc;
}

static int regex_file_line_d3(char *line)
{
  sc_domain_t *dom;
  sc_regex_t *re = NULL;
  uint32_t score;
  char *dup = NULL, *plan_ptr = NULL;
  char *ptr, *eval_ptr, *score_ptr;
  int rc = -1;

  /* dup the string in case we find the string isn't one we wanted */
  if((dup = strdup(line)) == NULL)
    return -1;

  /* look for magic ", score: " and "score " strings */
  if((eval_ptr = (char *)string_findlc(dup, ", score: ")) == NULL ||
     (score_ptr = (char *)string_findlc(eval_ptr, "score ")) == NULL)
    {
      rc = 0;
      goto done;
    }

  /* need a regex plan for geo regexes */
  if(do_learngeo != 0 &&
     (plan_ptr = (char *)string_findlc(dup, ", plan: ")) == NULL)
    {
      printf("%s: no plan\n", __func__);
      goto done;
    }

  *eval_ptr = '\0';
  score = regex_file_line_score(score_ptr);

  ptr = dup;
  while(*ptr != '\0')
    {
      if(*ptr == ':')
	break;
      ptr++;
    }

  if(*ptr == '\0' || *(ptr+1) == '\0' || *(ptr+2) == '\0')
    {
      rc = 0;
      goto done;
    }
  *ptr = '\0';
  ptr += 2;

  if((dom = sc_domain_find(dup)) == NULL)
    {
      rc = 0;
      goto done;
    }

  /* build the regex and tag the score */
  if((re = sc_regex_alloc_str(ptr)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc regex\n", __func__);
      goto done;
    }
  re->score = score;
  re->dom = dom;
  if(slist_tail_push(dom->regexes, re) == NULL)
    {
      fprintf(stderr, "%s: could not push regex\n", __func__);
      goto done;
    }

  if(do_learngeo != 0 && regex_file_line_plan(re, plan_ptr) != 0)
    {
      fprintf(stderr, "%s: could not parse plan\n", __func__);
      goto done;
    }

  re = NULL;
  rc = 1;

 done:
  if(re != NULL) sc_regex_free(re);
  if(dup != NULL) free(dup);
  return rc;
}

static int regex_file_line(char *line, void *param)
{
  static sc_domain_t *dom = NULL;
  char *ptr, *plan = NULL;
  sc_regex_t *re;
  int rc;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  /* if a suffix line, get the equivalent domain */
  if(strncmp(line, "suffix ", 7) == 0)
    {
      dom = sc_domain_find(line + 7);
      return 0;
    }

  /* try process the line as if it was from -d 3 */
  if((rc = regex_file_line_d3(line)) == -1)
    return -1;
  if(rc == 1)
    return 0;

  /* don't care about this domain */
  if(dom == NULL)
    return 0;

  /* truncate the string at the end of the regex */
  ptr = line;
  while(*ptr != '\0')
    {
      if(*ptr == ':' && *(ptr+1) == ' ')
	break;
      ptr++;
    }
  if(*ptr == '\0')
    return -1;
  *ptr = '\0';
  ptr++;

  /* need a plan for geo regexes */
  if(do_learngeo != 0 && (plan = (char *)string_findlc(ptr, ", plan:")) == NULL)
    return -1;

  /* build the regex and tag the score */
  if((re = sc_regex_alloc_str(line)) != NULL)
    {
      re->dom = dom;

      /* if the regex is tagged with a score, copy it */
      if((ptr = (char *)string_findlc(ptr, "score ")) != NULL)
	re->score = regex_file_line_score(ptr);

      if((plan != NULL && regex_file_line_plan(re, plan) != 0) ||
	 slist_tail_push(dom->regexes, re) == NULL)
	{
	  sc_regex_free(re);
	  return -1;
	}
    }

  return 0;
}

static int generate_regexes_supplied(void)
{
  sc_domain_t *dom;
  sc_regex_t *re = NULL;
  char *dup = NULL;
  struct stat sb;
  int rc = -1;

  if(stat(regex_eval, &sb) != 0)
    {
      if((dom = sc_domain_find(domain_eval)) == NULL ||
	 (dup = strdup(regex_eval)) == NULL ||
	 (re = sc_regex_alloc_str(dup)) == NULL ||
	 slist_tail_push(dom->regexes, re) == NULL)
	goto done;
      re->dom = dom;
      re = NULL;
    }
  else
    {
      if(file_lines(regex_eval, regex_file_line, NULL) != 0)
	{
	  fprintf(stderr, "could not read %s\n", regex_eval);
	  goto done;
	}
    }

  rc = 0;

 done:
  if(re != NULL) sc_regex_free(re);
  if(dup != NULL) free(dup);
  return rc;
}

static int generate_regexes(void)
{
  struct timeval start, finish;
  sc_domain_t *dom;
  slist_node_t *sn;
  int regexc = 0;
  char buf[32];

  if(regex_eval != NULL)
    return generate_regexes_supplied();

  gettimeofday_wrap(&start);
  if((threadp = threadpool_alloc(threadc)) == NULL)
    return -1;
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      threadpool_tail_push(threadp,
			   (threadpool_func_t)generate_regexes_thread, dom);
    }
  threadpool_join(threadp); threadp = NULL;
  gettimeofday_wrap(&finish);

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      regexc += slist_count(dom->regexes);
    }

  fprintf(stderr, "generated %d regexes in %s\n", regexc,
	  duration_tostr(buf, sizeof(buf), &start, &finish));

  return 0;
}

static void eval_regexes_thread(sc_regex_t *re)
{
  sc_regex_eval(re, NULL);
  return;
}

static int eval_regexes(void)
{
  struct timeval start, finish;
  slist_node_t *sn, *s2;
  sc_domain_t *dom;
  sc_regex_t *re;
  int regexc = 0;
  char buf[32];

  gettimeofday_wrap(&start);
  threadp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  threadpool_tail_push(threadp,
			       (threadpool_func_t)eval_regexes_thread, re);
	  regexc++;
	}
    }
  threadpool_join(threadp); threadp = NULL;
  gettimeofday_wrap(&finish);

  fprintf(stderr, "evaluated %d regexes in %s\n", regexc,
	  duration_tostr(buf, sizeof(buf), &start, &finish));

  return 0;
}

static void refine_regexes_ip_thread(sc_regex_t *re)
{
  sc_regex_refine_ip(re);
  return;
}

static void refine_regexes_fp_thread(sc_regex_t *re)
{
  sc_regex_refine_fp(re);
  return;
}

static void refine_regexes_class_thread(sc_regex_t *re)
{
  sc_regex_refine_class(re);
  return;
}

static void refine_regexes_fne_thread(sc_regex_t *re)
{
  sc_regex_refine_fne(re);
  return;
}

static void refine_regexes_fnu_thread(sc_regex_t *re)
{
  sc_regex_refine_fnu(re);
  return;
}

static void refine_regexes_tp_thread(sc_regex_t *re)
{
  if(do_learnalias != 0)
    sc_regex_refine_tp(re);
  return;
}

static void refine_regexes_sets_work_thread(sc_regex_sni_t *sni)
{
  sc_regex_refine_sets(sni);
  return;
}

static void refine_regexes_sets_onion_thread(sc_regex_sn_t *work)
{
  sc_regex_sn_t *base = work->refn, *refn;
  sc_regex_sni_t *sni;
  slist_node_t *sn, *sn_next;

  assert(work->snic == 0);

  /* nothing to do if there aren't any regexes after this one in the set */
  if(base->refn == NULL)
    {
      work->done = 1;
      return;
    }

  if(work->snis == NULL && (work->snis = slist_alloc()) == NULL)
    return;

#ifdef HAVE_PTHREAD
  if(work->mutex_o == 0)
    {
      if(pthread_mutex_init(&work->mutex, NULL) != 0)
	return;
      work->mutex_o = 1;
    }
#endif

  for(refn = base->refn; refn != NULL; refn = refn->refn)
    {
      if((sni = malloc_zero(sizeof(sc_regex_sni_t))) == NULL ||
	 slist_tail_push(work->snis, sni) == NULL)
	return;
      work->snic++;
      sni->work = work;
      sni->re = refn->re;
    }

  sn = slist_head_node(work->snis);
  while(sn != NULL)
    {
      sni = slist_node_item(sn);
      sn_next = slist_node_next(sn);
      threadpool_head_push_nolock(threadp,
			    (threadpool_func_t)refine_regexes_sets_work_thread,
			    sni);
      sn = sn_next;
    }

  return;
}

static void refine_regexes_merge_thread(sc_regex_mn_t *rmn)
{
  sc_regex_refine_merge(rmn->re, rmn->sn);
  free(rmn);
  return;
}

static void refine_regexes_sets_domain_check(sc_domain_fn_t *domfn)
{
  sc_regex_sn_t *work = NULL, *work2;
  slist_node_t *sn, *s2;
  sc_regex_t *head;
  int all_done = 0, work_atp, head_atp;

  /* check if we've inferred a near-perfect regex */
  slist_qsort(domfn->work, (slist_cmp_t)sc_regex_sn_score_rank_cmp);
  work = slist_head_item(domfn->work);  assert(work != NULL);
  head = work->re;
  if(head->fne_c + head->fnu_c + head->unk_c + head->fp_c < 2)
    {
      domfn->done = 1;
      return;
    }
  head_atp = sc_regex_score_atp(head);

  /* put the list back in to the order it started with */
  slist_qsort(domfn->work, (slist_cmp_t)sc_regex_sn_base_rank_cmp);

  /* check if there are any regexes not marked done */
  all_done = 1;
  for(sn=slist_head_node(domfn->work); sn != NULL; sn=slist_node_next(sn))
    {
      work = slist_node_item(sn);
      if(work->done != 0)
	continue;

      /*
       * do not consider further refinement of a naming convention
       * made up of more regexes but a lower ATP score.
       */
      work_atp = sc_regex_score_atp(work->re);
      if(head->regexc < work->re->regexc && head_atp >= work_atp)
	{
	  work->done = 2;
	  continue;
	}
      for(s2=slist_head_node(domfn->work); s2 != sn; s2=slist_node_next(s2))
	{
	  work2 = slist_node_item(s2);
	  if(work2->re->regexc < work->re->regexc &&
	     sc_regex_score_atp(work2->re) >= work_atp)
	    break;
	}
      if(s2 != sn)
	{
	  work->done = 2;
	  continue;
	}

      all_done = 0;
    }
  if(all_done != 0)
    domfn->done = 1;

  return;
}

/*
 * refine_regexes_sets_domain_init
 *
 * this function creates a set of sc_domain_fn_t nodes, each of which
 * point to a list of sc_regex_sn_t nodes.
 *
 * the sc_regex_sn_t nodes represent the starting point of a regex -- hoiho
 * considers all the other regexes below it in an ordered list and chooses
 * the regex that gets the most gain.
 */
static int refine_regexes_sets_domain_init(dlist_t *out, sc_domain_t *dom)
{
  sc_regex_sn_t *base = NULL, *work = NULL, *last = NULL;
  sc_domain_fn_t *domfn = NULL;
  slist_node_t *sn, *s2;
  sc_regex_t *head, *re;
  int rc = -1;

  /*
   * nothing to be done if there aren't at least two regexes that
   * could be merged.
   */
  if(slist_count(dom->regexes) < 2)
    return 0;

  /* sc_regex_sn_base_rank_cmp calls sc_regex_score_rank_cmp */
  slist_qsort(dom->regexes, (slist_cmp_t)sc_regex_score_rank_cmp);
  head = slist_head_item(dom->regexes);

  /*
   * nothing to be done if the number of false inferences is less than
   * two
   */
  if(head->fne_c + head->fnu_c + head->unk_c + head->fp_c < 2)
    return 0;

  if((domfn = malloc_zero(sizeof(sc_domain_fn_t))) == NULL ||
     (domfn->work = slist_alloc()) == NULL ||
     (domfn->base = slist_alloc()) == NULL)
    goto done;

  for(sn=slist_head_node(dom->regexes); sn != NULL; sn=slist_node_next(sn))
    {
      re = slist_node_item(sn);

      if((base = malloc_zero(sizeof(sc_regex_sn_t))) == NULL ||
	 slist_tail_push(domfn->base, base) == NULL)
	goto done;
      base->re = re;

      /*
       * set the 'next' pointer in the last sc_regex_sn_t structure to
       * point to this one
       */
      if(last != NULL)
	last->refn = base;
      last = base;

      /*
       * do not consider a regex that is worse than the head regex, or
       * one already in the work set
       */
      if(head != re && re->tp_c <= head->tp_c &&
	 ((do_learnalias != 0 && re->fp_c >= head->fp_c) ||
	  (do_learnasn != 0 && re->fp_c > head->fp_c) ||
	  (do_learnasnames != 0 && re->fp_c > head->fp_c) ||
	  (do_learngeo != 0 && re->fp_c > head->fp_c)))
	continue;
      for(s2=slist_head_node(domfn->work); s2 != NULL; s2=slist_node_next(s2))
	{
	  work = slist_node_item(s2);
	  if(re->tp_c <= work->re->tp_c &&
	     ((do_learnalias != 0 && re->fp_c >= work->re->fp_c) ||
	      (do_learnasn != 0 && re->fp_c > work->re->fp_c) ||
	      (do_learnasnames != 0 && re->fp_c > work->re->fp_c) ||
	      (do_learngeo != 0 && re->fp_c > work->re->fp_c)))
	    break;
	}
      if(s2 != NULL)
	continue;

      if((work = malloc_zero(sizeof(sc_regex_sn_t))) == NULL ||
	 slist_tail_push(domfn->work, work) == NULL)
	goto done;
      work->refn = base;
      work->base = re;
      work->re = re;
    }

  if(dlist_tail_push(out, domfn) == NULL)
    goto done;
  domfn = NULL;
  rc = 0;

 done:
  if(domfn != NULL) sc_domain_fn_free(domfn);
  return rc;
}

static int refine_regexes_sets(void)
{
  dlist_t *domfn_list = NULL;
  struct timeval start, finish;
  char buf[1024], score[128];
  sc_domain_fn_t *domfn;
  sc_regex_sn_t *work;
  dlist_node_t *dn, *dn_this;
  slist_node_t *sn;
  sc_domain_t *dom;
  int rc = -1;

  if((refine_mask & REFINE_SETS) == 0)
    return 0;

  /*
   * go through the regexes and figure out if there are missed routers
   * with apparent names that we might be able to match with more work
   */
  fprintf(stderr, "refining regexes: build sets\n");
  gettimeofday_wrap(&start);

  /* figure out which domains still have work to be done */
  if((domfn_list = dlist_alloc()) == NULL)
    goto done;
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if(refine_regexes_sets_domain_init(domfn_list, dom) != 0)
	goto done;
    }

  while(dlist_count(domfn_list) > 0)
    {
      if(do_debug != 0 && threadc <= 1)
	printf("\n###\n");

      /*
       * do the main bit of work which figures out which regex in the set
       * below makes the most sense to merge in
       */
      if((threadp = threadpool_alloc(threadc)) == NULL)
	goto done;
      for(dn=dlist_head_node(domfn_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  domfn = dlist_node_item(dn);
	  for(sn=slist_head_node(domfn->work); sn!=NULL; sn=slist_node_next(sn))
	    {
	      work = slist_node_item(sn);
	      if(do_debug != 0 && threadc <= 1)
		printf("%d %s %s\n", work->done,
		       sc_regex_tostr(work->re, buf, sizeof(buf)),
		       sc_regex_score_tostr(work->re, score, sizeof(score)));
	      if(work->done != 0)
		continue;
	      threadpool_tail_push_onion(threadp,
			(threadpool_func_t)refine_regexes_sets_onion_thread,
			work);
	    }
	}
      threadpool_join(threadp); threadp = NULL;

      /*
       * go through the list of domains, and figure out which ones do
       * not need further work
       */
      if((threadp = threadpool_alloc(threadc)) == NULL)
	goto done;
      for(dn=dlist_head_node(domfn_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  domfn = dlist_node_item(dn);
	  threadpool_tail_push(threadp,
			(threadpool_func_t)refine_regexes_sets_domain_check,
			domfn);
	}
      threadpool_join(threadp); threadp = NULL;

      /* remove the ones that do not require further work */
      dn=dlist_head_node(domfn_list);
      while(dn != NULL)
	{
	  domfn = dlist_node_item(dn); dn_this=dn;
	  dn = dlist_node_next(dn);
	  if(domfn->done != 0)
	    {
	      sc_domain_fn_free(domfn);
	      dlist_node_pop(domfn_list, dn_this);
	    }
	}
    }

  gettimeofday_wrap(&finish);
  fprintf(stderr, "refining regexes: build sets finished in %s\n",
	  duration_tostr(buf, sizeof(buf), &start, &finish));
  rc = 0;

 done:
  if(domfn_list != NULL)
    dlist_free_cb(domfn_list, (slist_free_t)sc_domain_fn_free);
  return rc;
}

static int refine_regexes(const char *type, threadpool_func_t func,
			  int (*skip)(sc_regex_t *, void *), void *param,
			  void *(*prep)(sc_regex_t *, slist_node_t *))
{
  struct timeval start, finish;
  slist_node_t *sn, *s2, *sn_tail;
  int from = 0, to = 0, rc = -1;
  sc_domain_t *dom;
  sc_regex_t *re;
  void *ptr;
  char buf[32];

  fprintf(stderr, "refining regexes: %s\n", type);
  gettimeofday_wrap(&start);

  if((threadp = threadpool_alloc(threadc)) == NULL)
    goto done;
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      sn_tail = slist_tail_node(dom->regexes);
      from += slist_count(dom->regexes);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  if(skip != NULL && skip(re, param) != 0)
	    continue;
	  if(prep == NULL)
	    {
	      threadpool_tail_push(threadp, func, re);
	      if(s2 == sn_tail)
		break;
	    }
	  else
	    {
	      if(s2 == sn_tail)
		break;
	      if((ptr = prep(re, slist_node_next(s2))) == NULL)
		goto done;
	      threadpool_tail_push(threadp, func, ptr);
	    }
	}
    }
  threadpool_join(threadp); threadp = NULL;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      to += slist_count(dom->regexes);
    }
  gettimeofday_wrap(&finish);

  fprintf(stderr, "refining regexes: %s finished %d to %d regexes in %s\n",
	  type, from, to, duration_tostr(buf, sizeof(buf), &start, &finish));
  rc = 0;

 done:
  return rc;
}

static int refine_regexes_ip_skip(sc_regex_t *re, void *param)
{
  if(re->ip_c == 0 || re->rt_c == 0 || re->tp_c == 0)
    return 1;
  return 0;
}

/*
 * refine_regexes_ip:
 *
 * go through the regexes and figure out if there are matches including
 * IP address literals
 */
static int refine_regexes_ip(void)
{
  if((refine_mask & REFINE_IP) == 0)
    return 0;
  return refine_regexes("ip matches",
			(threadpool_func_t)refine_regexes_ip_thread,
			refine_regexes_ip_skip, NULL, NULL);
}

static int refine_regexes_fp(void)
{
  struct timeval start, finish;
  slist_node_t *sn, *s2;
  sc_regex_t *best, *re;
  sc_domain_t *dom;
  char buf[32];
  int rc = -1;

  if((refine_mask & REFINE_FP) == 0)
    return 0;

  fprintf(stderr, "refining regexes: false positives\n");
  gettimeofday_wrap(&start);

  if((threadp = threadpool_alloc(threadc)) == NULL)
    goto done;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if((best = sc_domain_bestre(dom)) == NULL)
	continue;
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  if(re->tp_c < best->tp_c || re->rt_c < 3 || re->fp_c < 2)
	    continue;
	  threadpool_tail_push(threadp,
			       (threadpool_func_t)refine_regexes_fp_thread,re);
	}
    }
  threadpool_join(threadp); threadp = NULL;

  gettimeofday_wrap(&finish);
  fprintf(stderr, "refining regexes: false positives finished in %s\n",
          duration_tostr(buf, sizeof(buf), &start, &finish));
  rc = 0;

 done:
  return rc;
}

static int refine_regexes_fnu_skip(sc_regex_t *re, void *param)
{
  if(re->fnu_c == 0)
    return 1;
  return 0;
}

static int refine_regexes_fnu(void)
{
  if((refine_mask & REFINE_FNU) == 0)
    return 0;
  if(refine_regexes("false negative unmatched",
		    (threadpool_func_t)refine_regexes_fnu_thread,
		    refine_regexes_fnu_skip, NULL, NULL) != 0)
    return -1;

  thin_regexes(2);
  return 0;
}

static void *refine_regexes_merge_prep(sc_regex_t *re, slist_node_t *sn)
{
  sc_regex_mn_t *rmn;
  if((rmn = malloc(sizeof(sc_regex_mn_t))) == NULL)
    return NULL;
  rmn->re = re;
  rmn->sn = sn;
  return rmn;
}

static int refine_regexes_merge(void)
{
  if((refine_mask & REFINE_MERGE) == 0)
    return 0;

  if(refine_regexes("merge",
		    (threadpool_func_t)refine_regexes_merge_thread,
		    NULL, NULL, refine_regexes_merge_prep) != 0)
    return -1;

  thin_regexes(1);
  return 0;
}

static int refine_regexes_class(void)
{
  if((refine_mask & REFINE_CLASS) == 0)
    return 0;

  if(refine_regexes("class",
		    (threadpool_func_t)refine_regexes_class_thread,
		    NULL, NULL, NULL) != 0)
    return -1;

  thin_regexes(1);
  return 0;
}

static int refine_regexes_fne_skip(sc_regex_t *re, void *param)
{
  if(re->fne_c == 0)
    return 1;
  return 0;
}

static int refine_regexes_fne(void)
{
  if((refine_mask & REFINE_FNE) == 0)
    return 0;

  if(refine_regexes("false negative extractions",
		    (threadpool_func_t)refine_regexes_fne_thread,
		    refine_regexes_fne_skip, NULL, NULL) != 0)
    return -1;

  thin_regexes(1);
  return 0;
}

static int refine_regexes_tp_skip(sc_regex_t *re, void *param)
{
  if(re->tp_c == 0)
    return 1;
  return 0;
}

static int refine_regexes_tp(void)
{
  if((refine_mask & REFINE_TP) == 0)
    return 0;

  if(refine_regexes("true positives",
		    (threadpool_func_t)refine_regexes_tp_thread,
		    refine_regexes_tp_skip, NULL, NULL) != 0)
    return -1;

  thin_regexes(0);
  return 0;
}

/*
 * refine_dict_asnames_name_dig
 *
 * do not keep names in the form of foo\d+ if foo is in the dict
 */
static int refine_dict_asnames_name_dig(slist_t *thin, const sc_as2tag_t *a2t)
{
  const char *S, *T;
  size_t S_len, T_len;
  sc_as2tag_t *a2tb;
  slist_node_t *sn;

  T = a2t->tag; T_len = strlen(T);
  for(sn=slist_head_node(thin); sn != NULL; sn=slist_node_next(sn))
    {
      a2tb = slist_node_item(sn);
      if(a2t->asn != a2tb->asn)
	continue;
      S = a2tb->tag; S_len = strlen(S);
      if((S_len < T_len &&
	  strncmp(S, T, S_len) == 0 && string_isdigit(T + S_len) != 0) ||
	 (S_len > T_len &&
	  strncmp(S, T, T_len) == 0 && string_isdigit(S + T_len) != 0))
	return 1;
    }

  return 0;
}

static int refine_dict_asnames_unk_want(slist_t *thin,
					const sc_as2tag_t *a2t,
					const sc_as2tag_t *a2tb)
{
  static const char *digit2string[] = {
    "zero", "one", "two", "three", "four", "five",
    "six", "seven", "eight", "nine", "ten"};
  static size_t digit2stringl[] = {4, 3, 3, 5, 4, 4, 3, 5, 5, 4, 3};
  const char *S, *T;
  size_t S_len, T_len, S_i, T_i;
  slist_node_t *sn;
  sc_as2tag_t *a2tn;
  int digit;

  /* if the name is in as\d+ form, we do not want it */
  if(strncmp(a2t->tag, "as", 2) == 0 && string_isdigit(a2t->tag+2) != 0)
    return 0;

  /* do not want foo\d+ if foo is in the dict */
  if(refine_dict_asnames_name_dig(thin, a2t) != 0)
    return 0;

  /*
   * if there are no other apparent AS assignments for that name, and
   * at least two suffixes agree on the name, add the name/asn to the
   * dictionary
   */
  if((a2tb == NULL || strcmp(a2t->tag, a2tb->tag) != 0) &&
     splaytree_count(a2t->sxes) >= 2)
    return 1;

  /*
   * there are other possible mappings, but the evidence points to
   * one particular mapping.
   */
  if(a2tb != NULL && strcmp(a2t->tag, a2tb->tag) == 0 &&
     splaytree_count(a2t->sxes) >= 3 &&
     splaytree_count(a2tb->sxes) <= 1)
    return 1;

  T = a2t->tag; T_len = strlen(T);

  /*
   * look for cases where the alternate name expands a digit -- e.g.
   * 1and1 -> oneandone, m247 -> m24seven, level3 -> levelthree.
   */
  for(sn=slist_head_node(thin); sn != NULL; sn=slist_node_next(sn))
    {
      a2tn = slist_node_item(sn);
      if(sc_as2org_siblings(a2tn->asn, a2t->asn) == 0)
	continue;
      S = a2tn->tag; S_len = strlen(S);
      S_i = T_i = 0;
      while(S_i < S_len && T_i < T_len)
	{
	  if(S[S_i] == T[T_i])
	    {
	      S_i++;
	      T_i++;
	    }
	  else if(isdigit((unsigned char)S[S_i]) != 0)
	    {
	      digit = S[S_i] - '0';
	      if(strncmp(T+T_i,digit2string[digit],digit2stringl[digit]) != 0)
		break;
	      S_i++;
	      T_i += digit2stringl[digit];
	    }
	  else break;
	}

      if(S_i == S_len && T_i == T_len)
	return 1;
    }

  /*
   * figure out if two extracted names for the same ASN are similar.
   * the candidate under consideration must be longer than the name
   * stored in the list to count.
   */
  if(T_len >= 2)
    {
      for(sn=slist_head_node(thin); sn != NULL; sn=slist_node_next(sn))
	{
	  a2tn = slist_node_item(sn);
	  if(sc_as2org_siblings(a2tn->asn, a2t->asn) == 0)
	    continue;
	  S = a2tn->tag; S_len = strlen(S);
	  if(S_len < 2)
	    continue;

	  if(S_len < T_len && strncmp(S, T, S_len) == 0 &&
	     string_isalpha(T+S_len) != 0)
	    return 1;

#if 0
	  /* shorter names caused false inferences */
	  if(S_len > T_len && strncmp(S, T, T_len) == 0 &&
	     string_isalpha(S+T_len) != 0)
	    return 1;
#endif
	}
    }

  return 0;
}

static int refine_dict_asnames_thin(slist_t *list, slist_t *unk_list)
{
  slist_t *thin = NULL;
  sc_as2tag_t *a2t, *a2tb;
  slist_node_t *sn;
  int want, rc = -1;

  if((thin = slist_alloc()) == NULL)
    goto done;

  slist_qsort(list, (slist_cmp_t)sc_as2tag_sxes_cmp);
  while((a2t = slist_head_pop(list)) != NULL)
    {
      /*
       * there needs to be at least three suffixes with TPs before we
       * keep it
       */
      if(splaytree_count(a2t->sxes) < 3)
	{
	  sc_as2tag_free(a2t);
	  continue;
	}

      /* do not keep names in the form of foo\d+ if foo is in the dict */
      if(refine_dict_asnames_name_dig(thin, a2t) == 0)
	{
	  if(slist_tail_push(thin, a2t) == NULL)
	    {
	      sc_as2tag_free(a2t);
	      goto done;
	    }
	}
      else
	{
	  sc_as2tag_free(a2t);
	}
    }

  /*
   * go through the unknown set and see if we can match them up with
   * an existing entry
   */
  slist_qsort(unk_list, (slist_cmp_t)sc_as2tag_tagrank_cmp);
  for(;;)
    {
      if((a2t = slist_head_pop(unk_list)) == NULL)
	break;

      /*
       * determine if there are possible other AS/org assignments for
       * this apparent AS name
       */
      a2tb = NULL;
      for(sn=slist_head_node(unk_list); sn != NULL; sn=slist_node_next(sn))
	{
	  a2tb = slist_node_item(sn);
	  if(strcmp(a2t->tag, a2tb->tag) != 0 ||
	     sc_as2org_siblings(a2t->asn, a2tb->asn) == 0)
	    break;
	}

      want = refine_dict_asnames_unk_want(thin, a2t, a2tb);

      /* free the other tags with the same name, if any */
      while((a2tb = slist_head_item(unk_list)) != NULL)
	{
	  if(strcmp(a2t->tag, a2tb->tag) != 0)
	    break;
	  slist_head_pop(unk_list);
	  sc_as2tag_free(a2tb);
	}

      if(want != 0)
	{
	  /* add the mapping to the dictionary */
	  if(slist_tail_push(thin, a2t) == NULL)
	    {
	      sc_as2tag_free(a2t);
	      goto done;
	    }
	}
      else
	{
	  /* free because we do not want the tag */
	  sc_as2tag_free(a2t);
	}
    }

  slist_concat(list, thin);
  slist_qsort(list, (slist_cmp_t)sc_as2tag_cmp);

  rc = 0;

 done:
  slist_free_cb(thin, (slist_free_t)sc_as2tag_free);
  return rc;
}

static int refine_dict_asnames(void)
{
  slist_t *ifi_list = NULL, *list = NULL, *thin = NULL, *unk_list = NULL;
  splaytree_t *tree = NULL, *unk_tree = NULL;
  slist_node_t *sn, *s2;
  sc_routerdom_t *rd;
  sc_ifaceinf_t *ifi;
  sc_ifacedom_t *ifd;
  sc_domain_t *dom;
  sc_as2tag_t *a2t;
  sc_regex_t *re;
  int i, rc = -1;
  size_t s;

  if((refine_mask & REFINE_DICT) == 0 || domain_eval != NULL)
    return 0;

  if((ifi_list = slist_alloc()) == NULL ||
     (tree = splaytree_alloc((splaytree_cmp_t)sc_as2tag_cmp)) == NULL ||
     (unk_tree = splaytree_alloc((splaytree_cmp_t)sc_as2tag_cmp)) == NULL)
    goto done;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if((re = sc_domain_bestre(dom)) == NULL || re->rt_c < 3)
	continue;
      if(sc_regex_asnames_eval(re, ifi_list) != 0)
	goto done;
      for(s2=slist_head_node(ifi_list); s2 != NULL; s2=slist_node_next(s2))
	{
	  ifi = slist_node_item(s2);
	  if(ifi->class == '+' || ifi->class == '=')
	    {
	      a2t = sc_as2tag_find(ifi->css->css);
	      if((a2t = sc_as2tag_get(tree, a2t->asn, ifi->css->css)) == NULL ||
		 (splaytree_find(a2t->sxes, dom->domain) == NULL &&
		  splaytree_insert(a2t->sxes, dom->domain) == NULL))
		goto done;
	    }
	  else if(ifi->class == '?')
	    {
	      if((a2t = sc_as2tag_get(unk_tree, ifi->ifd->iface->rtr->asn,
				      ifi->css->css)) == NULL ||
		 (splaytree_find(a2t->sxes, dom->domain) == NULL &&
		  splaytree_insert(a2t->sxes, dom->domain) == NULL))
		goto done;
	    }
	}
      slist_empty_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
    }

  /* thin out the dictionary */
  if((list = slist_alloc()) == NULL || (unk_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(tree, tree_to_slist, list);
  splaytree_free(tree, NULL); tree = NULL;
  splaytree_inorder(unk_tree, tree_to_slist, unk_list);
  splaytree_free(unk_tree, NULL); unk_tree = NULL;
  if(refine_dict_asnames_thin(list, unk_list) != 0)
    goto done;

  /* clean out the old asnames dictionary */
  if(tag2ass != NULL)
    {
      for(s=0; s<tag2asc; s++)
	if(tag2ass[s] != NULL)
	  sc_as2tag_free(tag2ass[s]);
      free(tag2ass); tag2ass = NULL;
    }

  /* install the new asnames dictionary */
  if((i = slist_count(list)) <= 0)
    {
      rc = 0;
      goto done;
    }
  tag2asc = (size_t)i;
  if((tag2ass = malloc_zero(sizeof(sc_as2tag_t *) * tag2asc)) == NULL)
    goto done;
  i = 0;
  while((a2t = slist_head_pop(list)) != NULL)
    tag2ass[i++] = a2t;
  slist_free(list); list = NULL;

  /* infer which hostnames could embed an AS name */
  threadp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  for(i=0; i<rd->ifacec; i++)
	    {
	      ifd = rd->ifaces[i];
	      threadpool_tail_push(threadp,
		   (threadpool_func_t)sc_iface_asname_find_thread, ifd);
	    }
	}
    }
  threadpool_join(threadp); threadp = NULL;

  fprintf(stderr, "refining dictionary: %d entries\n", (int)tag2asc);

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if(dom->regexes != NULL)
	slist_empty_cb(dom->regexes, (slist_free_t)sc_regex_free);
    }

  if(generate_regexes() != 0)
    goto done;
  if(eval_regexes() != 0)
    goto done;
  if(refine_regexes_merge() != 0)
    goto done;

  rc = 0;

 done:
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)sc_as2tag_free);
  if(list != NULL) slist_free_cb(list, (slist_free_t)sc_as2tag_free);
  if(unk_tree != NULL)
    splaytree_free(unk_tree, (splaytree_free_t)sc_as2tag_free);
  if(unk_list != NULL) slist_free_cb(unk_list, (slist_free_t)sc_as2tag_free);
  if(thin != NULL) slist_free_cb(thin, (slist_free_t)sc_as2tag_free);
  return rc;
}

static void refine_dict_geo_thread(sc_regex_t *re)
{
  slist_t *ifi_list = NULL, *rd_list = NULL, *geoeval_list = NULL;
  slist_t *gr_list = NULL, *m2h_list = NULL;
  splaytree_t *gr_tree = NULL, *gh_tree = NULL;
  sc_ifaceinf_t *ifi;
  slist_node_t *sn, *s2;
  sc_geohint_t *gh = NULL;
  sc_georef_t *gr = NULL;
  sc_geoeval_t *ge = NULL;
  sc_geomap_t map;
  sc_geomap2hint_t *m2h;
  uint32_t rt_tp_c, rt_c, ifi_c;
  uint8_t geotype;
  char buf[128];
  int x;

  if(re->rt_c < 3 ||
     re->tp_c * 100 / (re->tp_c + re->fp_c) < 40 ||
     (ifi_list = slist_alloc()) == NULL ||
     sc_regex_geo_eval(re, ifi_list) != 0 ||
     (gr_tree = splaytree_alloc((splaytree_cmp_t)sc_georef_cmp)) == NULL)
    goto done;

  /* collect the geo codes that are questionable */
  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if(ifi->class != '!' && ifi->class != '?')
	continue;
      geotype = sc_regexn_geotype(re->regexes[ifi->regex]);
      if(geotype != GEOHINT_TYPE_IATA && geotype != GEOHINT_TYPE_LOCODE &&
	 geotype != GEOHINT_TYPE_PLACE &&
	 (geotype != GEOHINT_TYPE_CLLI || ifi->class == '!') &&
	 (geotype != GEOHINT_TYPE_FACILITY || ifi->class == '!'))
	continue;
      sc_css_geomap(ifi->css, re->regexes[ifi->regex]->plan, &map);
      if(map.codelen == 0)
	continue;
      if((gr = sc_georef_get(gr_tree, &map)) == NULL ||
	 slist_tail_push(gr->ifi_list, ifi) == NULL ||
	 (gr->f_mask == NULL &&
	  (gr->f_mask=malloc_zero(sizeof(uint32_t)*re->dom->rtmlen)) == NULL))
	goto done;
      assert(gr->class == '\0' || gr->class == ifi->class);
      if(gr->class == '\0')
	gr->class = ifi->class;
      if(mask_isset(gr->f_mask, re->dom->rtmlen, ifi->ifd->rd->id) != 0)
	continue;
      if(slist_tail_push(gr->rd_list, ifi->ifd->rd) == NULL)
	goto done;
      mask_set(gr->f_mask, re->dom->rtmlen, ifi->ifd->rd->id);
    }

  /* collect the other routers that share that geocode */
  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifi = slist_node_item(sn);
      if(ifi->class != '+')
	continue;
      geotype = sc_regexn_geotype(re->regexes[ifi->regex]);

      /* note CLLI + PLACE + FACILITY checks redundant with ! check above */
      if(geotype != GEOHINT_TYPE_IATA && geotype != GEOHINT_TYPE_LOCODE &&
	 geotype != GEOHINT_TYPE_CLLI && geotype != GEOHINT_TYPE_PLACE &&
	 geotype != GEOHINT_TYPE_FACILITY)
	continue;
      sc_css_geomap(ifi->css, re->regexes[ifi->regex]->plan, &map);
      if((gr = sc_georef_find(gr_tree, &map)) == NULL ||
	 slist_tail_push(gr->ifi_list, ifi) == NULL)
	continue;
      gr->ifi_tp_c++;
      if(gr->t_mask == NULL &&
	 (gr->t_mask = malloc_zero(sizeof(uint32_t) * re->dom->rtmlen)) == NULL)
	goto done;
      if(mask_isset(gr->t_mask, re->dom->rtmlen, ifi->ifd->rd->id) != 0)
	continue;
      mask_set(gr->t_mask, re->dom->rtmlen, ifi->ifd->rd->id);
      if(mask_isset(gr->f_mask, re->dom->rtmlen, ifi->ifd->rd->id) == 0 &&
	 slist_tail_push(gr->rd_list, ifi->ifd->rd) == NULL)
	goto done;
    }

  /* convert the tree to a flat list for further work */
  if((gr_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(gr_tree, tree_to_slist, gr_list);
  splaytree_free(gr_tree, NULL); gr_tree = NULL;

  /* get the unique set of hints from the dictionary */
  if((m2h_list = sc_geomap2hint_make(re, ifi_list)) == NULL ||
     (gh_tree = splaytree_alloc(ptrcmp)) == NULL)
    goto done;
  for(sn=slist_head_node(m2h_list); sn != NULL; sn=slist_node_next(sn))
    {
      m2h = slist_node_item(sn);
      if(m2h->tp_c == 0 || splaytree_find(gh_tree, m2h->hint) != NULL)
	continue;
      if(splaytree_insert(gh_tree, m2h->hint) == NULL)
	goto done;
    }

  if((geoeval_list = slist_alloc()) == NULL)
    goto done;
  for(sn=slist_head_node(gr_list); sn != NULL; sn=slist_node_next(sn))
    {
      gr = slist_node_item(sn);
      rt_c = slist_count(gr->rd_list);
      ifi_c = slist_count(gr->ifi_list);
      rt_tp_c = gr->t_mask != NULL ? mask_cnt(gr->t_mask, re->dom->rtmlen) : 0;

      if(do_debug != 0 && threadc <= 1)
	printf("%s rt %d/%d ifi %d/%d\n",
	       sc_geomap_tostr(&gr->map, buf, sizeof(buf)),
	       rt_tp_c, rt_c, gr->ifi_tp_c, ifi_c);

      /*
       * skip over hints with a PPV >= 80%, and those with at most one
       * FP provided there are no TPs
       */
      if(gr->ifi_tp_c * 100 / ifi_c >= 80 ||
	 (ifi_c - gr->ifi_tp_c == 1 && ifi_c > 1))
	continue;

      /* allocate a scratch buffer for checking acronyms */
      if((gr->offs = malloc(sizeof(size_t) * gr->map.codelen)) == NULL)
	goto done;

      if(gr->map.type == GEOHINT_TYPE_IATA)
	x = sc_geohint_fudge_iata(gr, re, gh_tree, geoeval_list);
      else if(gr->map.type == GEOHINT_TYPE_CLLI)
	x = sc_geohint_fudge_clli(gr, re, gh_tree, geoeval_list);
      else if(gr->map.type == GEOHINT_TYPE_LOCODE)
	x = sc_geohint_fudge_locode(gr, re, gh_tree, geoeval_list);
      else if(gr->map.type == GEOHINT_TYPE_PLACE)
	x = sc_geohint_fudge_place(gr, re, gh_tree, geoeval_list);
      else if(gr->map.type == GEOHINT_TYPE_FACILITY)
	x = sc_geohint_fudge_facility(gr, re, gh_tree, geoeval_list);

      if(x != 0)
	goto done;

      /* no longer need the scratch buffer */
      free(gr->offs); gr->offs = NULL;

      if(slist_count(geoeval_list) < 1)
	continue;

      slist_qsort(geoeval_list, (slist_cmp_t)sc_geoeval_cmp);

      if(do_debug != 0 && threadc <= 1)
	{
	  for(s2=slist_head_node(geoeval_list); s2 != NULL;
	      s2=slist_node_next(s2))
	    {
	      ge = slist_node_item(s2);
	      printf("  %s %d %d %d\n",
		     sc_geohint_place_tostr(ge->hint, buf, sizeof(buf)),
		     ge->hint->popn, ge->hint->flags, ge->tp_c);
	    }
	  ge = NULL;
	}

      /* get the highest ranked geohint, free the rest */
      ge = slist_head_pop(geoeval_list);
      slist_empty_cb(geoeval_list, free);

      if(ge->alloc == 0)
	{
	  if((gh = sc_geohint_alloc(gr->map.type, gr->map.code, ge->hint->place,
				    ge->hint->st, ge->hint->cc,
				    ge->hint->lat, ge->hint->lng, 0)) == NULL)
	    goto done;
	  if(gr->map.type == GEOHINT_TYPE_PLACE &&
	     ge->hint->type == GEOHINT_TYPE_FACILITY)
	    {
	      if(ge->round == 0)
		{
		  if((gh->facname = strdup(ge->hint->facname)) == NULL)
		    goto done;
		}
	      else if(ge->round == 1)
		{
		  if((gh->street = strdup(ge->hint->street)) == NULL)
		    goto done;
		}
	    }
	  else if(gr->map.type == GEOHINT_TYPE_FACILITY)
	    {
	      if((gh->street = strdup(ge->hint->street)) == NULL)
		goto done;
	    }
	}
      else
	{
	  gh = ge->hint;
	  ge->hint = NULL;
	}

      gh->learned = 1;
      sc_geoeval_free(ge); ge = NULL;
      if(array_insert((void ***)&re->geohints, &re->geohintc, gh, NULL) != 0)
	goto done;
      gh = NULL;
    }

  if(re->geohintc > 0)
    {
      sc_geohint_sort(re->geohints, re->geohintc);
      sc_regex_eval(re, NULL);
    }

 done:
  if(gr_tree != NULL)
    splaytree_free(gr_tree, (splaytree_free_t)sc_georef_free);
  if(gr_list != NULL) slist_free_cb(gr_list, (slist_free_t)sc_georef_free);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(geoeval_list != NULL) slist_free_cb(geoeval_list, free);
  if(rd_list != NULL) slist_free(rd_list);
  if(m2h_list != NULL) slist_free_cb(m2h_list, (slist_free_t)free);
  if(gh_tree != NULL) splaytree_free(gh_tree, NULL);
  if(gh != NULL) sc_geohint_free(gh);
  if(ge != NULL) sc_geoeval_free(ge);
  return;
}

static int refine_dict_geo(void)
{
  struct timeval start, finish;
  slist_node_t *sn, *s2;
  sc_domain_t *dom;
  char buf[32];
  int rc = -1;

  if((refine_mask & REFINE_DICT) == 0)
    return 0;

  fprintf(stderr, "refining regexes: dictionary\n");
  gettimeofday_wrap(&start);

  if((threadp = threadpool_alloc(threadc)) == NULL)
    goto done;
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  threadpool_tail_push(threadp,
	       (threadpool_func_t)refine_dict_geo_thread, slist_node_item(s2));
	}
    }
  threadpool_join(threadp); threadp = NULL;

  gettimeofday_wrap(&finish);
  fprintf(stderr, "refining regexes: dictionary finished in %s\n",
	  duration_tostr(buf, sizeof(buf), &start, &finish));
  rc = 0;

 done:
  return rc;
}

static int assert_domains(void)
{
  slist_node_t *sn, *s2;
  sc_domain_t *dom;
  sc_routerdom_t *rd;
  uint32_t id;
  int i;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      id = 0;
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  for(i=0; i<rd->ifacec; i++)
	    {
	      if(id + 1 != rd->ifaces[i]->id)
		return -1;
	      id++;
	    }
	}
      if(id != dom->ifacec)
	return -1;
    }

  return 0;
}

static void load_routers_alias(void)
{
  slist_node_t *sn, *s2;
  sc_domain_t *dom;

  /* compute likely names for the routers */
  threadp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  threadpool_tail_push(threadp,
			       (threadpool_func_t)sc_routerdom_lcs_thread,
			       slist_node_item(s2));
	}
    }
  threadpool_join(threadp); threadp = NULL;

  return;
}

static void load_routers_asn(void)
{
  sc_routerdom_t *rd;
  slist_node_t *sn, *s2;
  sc_domain_t *dom;
  int i;

  /* infer if the hostname embeds an ASN */
  threadp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  for(i=0; i<rd->ifacec; i++)
	    threadpool_tail_push(threadp,
				 (threadpool_func_t)sc_iface_asn_find_thread,
				 rd->ifaces[i]);
	}
    }
  threadpool_join(threadp); threadp = NULL;
  return;
}

static int load_routers_asnames_dict(void)
{
  splaytree_t *tree = NULL;
  slist_t *list = NULL, *thin = NULL;
  slist_node_t *sn, *s2;
  sc_routerdom_t *rd;
  sc_domain_t *dom;
  sc_css_t *css = NULL;
  sc_as2tag_t *a2t, *a2t_head;
  char *ptr;
  int i, j, rc = -1;

  /* go through all routers, extracting tags per router */
  if((tree = splaytree_alloc((splaytree_cmp_t)sc_as2tag_cmp)) == NULL)
    goto done;
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  for(i=0; i<rd->ifacec; i++)
	    {
	      if((css = sc_css_alloc_tags(rd->ifaces[i]->label)) == NULL)
		goto done;
	      if(css->cssc == 0)
		{
		  sc_css_free(css);
		  css = NULL;
		  continue;
		}

	      ptr = css->css;
	      for(j=0; j<css->cssc; j++)
		{
		  if(string_isdigit(ptr) != 0 ||
		     (strncmp(ptr,"as",2) == 0 && string_isdigit(ptr+2) != 0))
		    goto next;

		  /* associate the tag/asn with the suffix */
		  if((a2t = sc_as2tag_get(tree, rd->rtr->asn, ptr)) == NULL ||
		     (splaytree_find(a2t->sxes, dom->domain) == NULL &&
		      splaytree_insert(a2t->sxes, dom->domain) == NULL))
		    goto done;

		next:
		  /* skip to the next tag */
		  while(*ptr != '\0')
		    ptr++;
		  ptr++;
		}

	      sc_css_free(css); css = NULL;
	    }
	}
    }

  /* thin out any ASN tags that are in less than 3 suffixes */
  if((list = slist_alloc()) == NULL || (thin = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(tree, tree_to_slist, list);
  splaytree_free(tree, NULL); tree = NULL;
  while((a2t = slist_head_pop(list)) != NULL)
    {
      if(splaytree_count(a2t->sxes) < 3)
	{
	  sc_as2tag_free(a2t);
	  continue;
	}
      if(slist_tail_push(thin, a2t) == NULL)
	{
	  sc_as2tag_free(a2t);
	  goto done;
	}
    }
  slist_concat(list, thin);

  /*
   * remove any ASN tags where there are conflicting ASes who might
   * have that tag
   */
  slist_qsort(list, (slist_cmp_t)sc_as2tag_tagrank_cmp);
  for(;;)
    {
      if((a2t_head = slist_head_pop(list)) == NULL)
	break;
      a2t = NULL;
      for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
	{
	  a2t = slist_node_item(sn);
	  if(strcmp(a2t_head->tag, a2t->tag) != 0 ||
	     sc_as2org_siblings(a2t_head->asn, a2t->asn) == 0)
	    break;
	}
      j = 0;
      if(a2t == NULL || strcmp(a2t_head->tag, a2t->tag) != 0 ||
	 splaytree_count(a2t_head->sxes) >= splaytree_count(a2t->sxes) * 2)
	{
	  if(slist_tail_push(thin, a2t_head) == NULL)
	    {
	      sc_as2tag_free(a2t_head);
	      goto done;
	    }
	}
      else j = 1;
      while((a2t = slist_head_item(list)) != NULL)
	{
	  if(strcmp(a2t_head->tag, a2t->tag) != 0)
	    break;
	  slist_head_pop(list);
	  sc_as2tag_free(a2t);
	}
      if(j != 0) sc_as2tag_free(a2t_head);
    }
  slist_concat(list, thin);

  if((i = slist_count(list)) <= 0)
    {
      rc = 0;
      goto done;
    }
  tag2asc = (size_t)i;
  if((tag2ass = malloc_zero(sizeof(sc_as2tag_t *) * tag2asc)) == NULL)
    goto done;

  i = 0;
  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      a2t = slist_node_item(sn);
      tag2ass[i++] = a2t;
      if(do_debug != 0 && threadc <= 1)
	printf("%s %u %d\n", a2t->tag, a2t->asn, splaytree_count(a2t->sxes));
    }
  slist_free(list); list = NULL;

  fprintf(stderr, "inferred %d entries in asnames dictionary\n", (int)tag2asc);
  rc = 0;

 done:
  if(css != NULL) sc_css_free(css);
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)sc_as2tag_free);
  if(list != NULL) slist_free_cb(list, (slist_free_t)sc_as2tag_free);
  if(thin != NULL) slist_free_cb(thin, (slist_free_t)sc_as2tag_free);
  return rc;
}

static int load_routers_asnames(void)
{
  slist_node_t *sn, *s2;
  sc_routerdom_t *rd;
  sc_domain_t *dom;
  int i;

  /* infer the initial dictionary if one is not provided */
  if(dicts == NULL && load_routers_asnames_dict() != 0)
    return -1;

  /* infer which hostnames could embed an AS name */
  threadp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  for(i=0; i<rd->ifacec; i++)
	    threadpool_tail_push(threadp,
				 (threadpool_func_t)sc_iface_asname_find_thread,
				 rd->ifaces[i]);
	}
    }
  threadpool_join(threadp); threadp = NULL;

  return 0;
}

static void load_routers_geo(void)
{
  sc_routerdom_t *rd;
  slist_node_t *sn, *s2;
  sc_domain_t *dom;
  int i;

  /* check each label for geocodes */
  threadp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  for(i=0; i<rd->ifacec; i++)
	    threadpool_tail_push(threadp,
				 (threadpool_func_t)sc_iface_geo_find_thread,
				 rd->ifaces[i]);
	}
    }
  threadpool_join(threadp); threadp = NULL;
  return;
}

static int load_routers_1(void)
{
  sc_routerload_t rl;
  struct timeval start, finish;
  slist_node_t *sn, *s2;
  sc_routerdom_t *rd;
  sc_domain_t *dom;
  sc_iface_t *iface;
  int i, rc = -1;
  char buf[32];

  /* load the routers */
  memset(&rl, 0, sizeof(rl));
  gettimeofday_wrap(&start);
  if((domain_tree = splaytree_alloc((splaytree_cmp_t)sc_domain_cmp)) == NULL ||
     (router_list = slist_alloc()) == NULL ||
     (rl.ifaces = slist_alloc()) == NULL)
    goto done;
  if(file_lines(router_file, router_file_line, &rl) != 0)
    {
      fprintf(stderr, "could not read %s\n", router_file);
      goto done;
    }
  if(slist_count(rl.ifaces) > 0 && sc_router_finish(&rl) != 0)
    goto done;
  if((domain_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(domain_tree, tree_to_slist, domain_list);

  /* infer if the hostnames contain IP address literals */
  threadp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      if(do_ip == 0)
	continue;
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  for(i=0; i<rd->ifacec; i++)
	    {
	      iface = rd->ifaces[i]->iface;
	      threadpool_tail_push(threadp,
				   (threadpool_func_t)sc_iface_ip_find_thread,
				   iface);
	    }
	}
    }
  threadpool_join(threadp); threadp = NULL;

  gettimeofday_wrap(&finish);
  fprintf(stderr, "loaded %d routers in %d domains in %s\n",
	  slist_count(router_list), slist_count(domain_list),
	  duration_tostr(buf, sizeof(buf), &start, &finish));

  rc = 0;

 done:
  if(rl.ifaces != NULL) slist_free_cb(rl.ifaces, (slist_free_t)sc_iface_free);
  return rc;
}

static int load_routers_2(void)
{
  struct timeval start, finish;
  slist_node_t *sn, *s2;
  sc_routerdom_t *rd;
  sc_domain_t *dom;
  slist_t *tmp = NULL;
  int i, rc = -1;
  int rtr_id, ifd_id;
  uint32_t rtc;
  char buf[32];

  gettimeofday_wrap(&start);

  /* figure out which routers are training routers */
  if((tmp = slist_alloc()) == NULL)
    goto done;
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      slist_concat(tmp, dom->routers);
      while((rd = slist_head_pop(tmp)) != NULL)
	{
	  if(sc_router_istraining(rd->rtr) != 0)
	    {
	      if(slist_tail_push(dom->routers, rd) == NULL)
		goto done;
	    }
	  else
	    {
	      if(slist_tail_push(dom->appl, rd) == NULL)
		goto done;
	    }
	}
    }

  if(do_learnalias != 0)
    load_routers_alias();
  else if(do_learnasn != 0)
    load_routers_asn();
  else if(do_learnasnames != 0)
    {
      if(load_routers_asnames() != 0)
	goto done;
      if(domain_eval != 0)
	{
	  slist_empty(domain_list);
	  if((dom = sc_domain_find(domain_eval)) == NULL ||
	     slist_tail_push(domain_list, dom) == NULL)
	    goto done;
	}
    }
  else if(do_learngeo != 0)
    load_routers_geo();

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);

#if 0
      printf("%s %d %d\n", dom->domain, slist_count(dom->routers),
	     slist_count(dom->appl));
#endif

      /* assign router and interface ids to each training router and iface */
      rtr_id = 1; ifd_id = 1;
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  rd->id = rtr_id++;
	  for(i=0; i<rd->ifacec; i++)
	    rd->ifaces[i]->id = ifd_id++;
	  dom->ifacec += rd->ifacec;
	}

      rtc = slist_count(dom->routers);
      dom->tpmlen = dom->ifacec / 32 + ((dom->ifacec % 32 == 0) ? 0 : 1);
      dom->rtmlen = rtc / 32 + ((rtc % 32 == 0) ? 0 : 1);
    }

  /* run some assertions on the domains */
  if(assert_domains() != 0)
    {
      fprintf(stderr, "checks failed\n");
      goto done;
    }

  gettimeofday_wrap(&finish);
  fprintf(stderr, "tagged %d routers in %d domains in %s\n",
	  slist_count(router_list), slist_count(domain_list),
	  duration_tostr(buf, sizeof(buf), &start, &finish));

  rc = 0;

 done:
  if(tmp != NULL) slist_free_cb(tmp, (slist_free_t)sc_routerdom_free);
  return rc;
}

static int load_suffix(void)
{
  slist_t *list = NULL;
  int rc = -1;

  assert(suffix_file != NULL);

  if((list = slist_alloc()) == NULL)
    goto done;
  if(file_lines(suffix_file, suffix_file_line, list) != 0)
    {
      fprintf(stderr, "could not read %s\n", suffix_file);
      goto done;
    }
  fprintf(stderr, "loaded %d suffixes\n", slist_count(list));
  process_suffix(list);
  rc = 0;

 done:
  if(list != NULL) slist_free(list);
  return rc;
}

static int load_siblings(void)
{
  slist_t *list = NULL;
  sc_as2org_t *a2o;
  int rc = -1, x;

  if(sibling_file == NULL)
    return 0;
  if((list = slist_alloc()) == NULL)
    {
      fprintf(stderr,"%s: could not malloc list\n", __func__);
      goto done;
    }
  if(file_lines(sibling_file, sibling_file_line, list) != 0)
    {
      fprintf(stderr,"%s: could not read %s\n", __func__, sibling_file);
      goto done;
    }
  if((x = slist_count(list)) <= 0)
    {
      rc = 0;
      goto done;
    }
  siblingc = (size_t)x;

  x = 0;
  if((siblings = malloc_zero(sizeof(sc_as2org_t *) * siblingc)) == NULL)
    {
      fprintf(stderr, "%s: could not malloc %d siblings\n", __func__,
	      (int)siblingc);
      goto done;
    }
  while((a2o = slist_head_pop(list)) != NULL)
    siblings[x++] = a2o;
  assert((size_t)x == siblingc);
  array_qsort((void **)siblings, siblingc, (array_cmp_t)sc_as2org_cmp);
  fprintf(stderr, "loaded %d sibling ases in %d orgs\n",
	  (int)siblingc, sibling_id-1);
  rc = 0;

 done:
  if(list != NULL) slist_free_cb(list, (slist_free_t)free);
  return rc;
}

static int geohints_file_line_place(const char *line, char **ptr_in,
				    char *place, size_t place_len)
{
  char *ptr = *ptr_in;
  int p;

  if(*ptr == '\0')
    {
      place[0] = '\0';
      return 0;
    }

  if(*ptr != '"')
    {
      fprintf(stderr, "%s: expected \": %s\n", __func__, line);
      return -1;
    }
  ptr++; p = 0;
  while(*ptr != '"' && *ptr != '\0')
    {
      place[p++] = *ptr;
      ptr++;
    }
  if(*ptr != '"')
    {
      fprintf(stderr, "%s: expected \": %s\n", __func__, line);
      return -1;
    }
  place[p] = '\0';
  ptr++;

  *ptr_in = ptr;
  return 0;
}

static int geohints_file_line_iso3166(const char *line, char **ptr_in,
				      char *cc, char *st)
{
  char *ptr = *ptr_in;
  char iso3166[8];
  size_t i = 0;

  while(i < sizeof(iso3166) && (*ptr == '-' || isalnum((unsigned char)*ptr)))
    {
      iso3166[i++] = tolower((unsigned char)*ptr);
      ptr++;
    }
  if(i == sizeof(iso3166))
    {
      fprintf(stderr, "%s: code too long, %s\n", __func__, line);
      return -1;
    }
  if(*ptr != '\0' && isspace((unsigned char)*ptr) == 0)
    {
      fprintf(stderr, "%s: unexpected character, %s\n", __func__, line);
      return -1;
    }

  if(i == 0)
    goto done;

  iso3166[i] = '\0';

  if(isalpha((unsigned char)iso3166[0]) == 0 ||
     isalpha((unsigned char)iso3166[1]) == 0)
    {
      fprintf(stderr, "%s: expected country code, %s\n", __func__, line);
      return -1;
    }
  cc[0] = iso3166[0];
  cc[1] = iso3166[1];
  cc[2] = '\0';

  if(iso3166[2] == '\0')
    goto done;

  if(iso3166[2] != '-')
    {
      fprintf(stderr, "%s: expected hyphen, %s\n", __func__, line);
      return -1;
    }

  for(i=0; i<3; i++)
    {
      if(iso3166[3+i] == '\0')
	break;
      if(isalnum((unsigned char)iso3166[3+i]) == 0)
	{
	  fprintf(stderr, "%s: expected state code, %s\n", __func__, line);
	  return -1;
	}
      st[i] = iso3166[3+i];
    }
  st[i] = '\0';
  if(iso3166[3+i] != '\0' && isspace((unsigned char)iso3166[3+i]) == 0)
    {
      fprintf(stderr, "%s: invalid state code, %s\n", __func__, line);
      return -1;
    }

 done:
  *ptr_in = ptr;
  return 0;
}

static sc_geohint_t *geohints_file_line_make(slist_t *list, uint8_t type,
					     char *code, char *place,
					     char *cc, char *st,
					     double lat, double lng, long popn)
{
  sc_geohint_t *hint;
  hint = sc_geohint_alloc(type, code, place, st, cc, lat, lng, popn);
  if(hint == NULL || slist_tail_push(list, hint) == NULL)
    {
      if(hint != NULL)
	sc_geohint_free(hint);
      return NULL;
    }
  return hint;
}

/*
 * geohints_file_line:
 *
 * If the current line is a geo code, load it into the geohints
 * array.
 * line:
 * param: An slist_t to add the geocode to.
 */
static int geohints_file_line(char *line, void *param)
{
  slist_t *list = (slist_t *)param;
  char code[256], place[256], street[256], facname[256], cc[3], st[4];
  double lat = 0.0, lng = 0.0;
  int got_lat = 0, got_lng = 0;
  sc_geohint_t *hint;
  long popn = 0;
  char *ptr, *end;
  size_t expected_len = 0;
  uint8_t type = 0;
  size_t i, j;

  if ('#' == *line) return 0;

  place[0] = street[0] = cc[0] = st[0] = '\0';

  if(strncmp(line, "iata ", 5) == 0)
    {
      type = GEOHINT_TYPE_IATA;
      expected_len = 3; j = 4;
    }
  else if(strncmp(line, "icao ", 5) == 0)
    {
      type = GEOHINT_TYPE_ICAO;
      expected_len = 4; j = 4;
    }
  else if(strncmp(line, "clli ", 5) == 0)
    {
      type = GEOHINT_TYPE_CLLI;
      expected_len = 6; j = 4;
    }
  else if(strncmp(line, "locode ", 7) == 0)
    {
      type = GEOHINT_TYPE_LOCODE;
      expected_len = 5; j = 6;
    }
  else if(strncmp(line, "place ", 6) == 0)
    {
      type = GEOHINT_TYPE_PLACE;
      j = 5;
    }
  else if(strncmp(line, "facility ", 9) == 0)
    {
      type = GEOHINT_TYPE_FACILITY;
      j = 8;
    }
  else if(strncmp(line, "country ", 8) == 0)
    {
      type = GEOHINT_TYPE_COUNTRY;
      j = 7;
    }
  else if(strncmp(line, "state ", 6) == 0)
    {
      type = GEOHINT_TYPE_STATE;
      j = 5;
    }
  else if(strncmp(line, "vp ", 3) == 0)
    {
      type = GEOHINT_TYPE_VP;
      j = 2;
    }
  else
    {
      fprintf(stderr, "Invalid line: %s\n", line);
      return -1;
    }

  ptr = line + j;
  while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
    ptr++;
  if(*ptr == '\0')
    goto err;

  if(type == GEOHINT_TYPE_IATA || type == GEOHINT_TYPE_ICAO ||
     type == GEOHINT_TYPE_CLLI || type == GEOHINT_TYPE_LOCODE)
    {
      for(i=0; i<expected_len; i++)
	{
	  if(ptr[i] != '-' && isalnum((unsigned char)ptr[i]) == 0)
	    {
	      fprintf(stderr, "Invalid geocode: %s\n", line);
	      goto err;
	    }
	  code[i] = tolower((unsigned char)ptr[i]);
	}
      code[i] = '\0';
      ptr += expected_len;
      if(*ptr != '\0' && isspace((unsigned char)*ptr) == 0)
	{
	  fprintf(stderr, "Invalid geocode: %s\n", line);
	  goto err;
	}
    }
  else if(type == GEOHINT_TYPE_VP)
    {
      for(i=0; i<sizeof(code); i++)
	{
	  if(ptr[i] != '-' && isalnum((unsigned char)ptr[i]) == 0)
	    break;
	  code[i] = tolower((unsigned char)ptr[i]);
	}
      if(i == sizeof(code) || isspace((unsigned char)ptr[i]) == 0)
	{
	  fprintf(stderr, "Invalid geocode: %s\n", line);
	  goto err;
	}
      code[i] = '\0';
      ptr += (i+1);
    }
  else if(type == GEOHINT_TYPE_PLACE || type == GEOHINT_TYPE_FACILITY)
    {
      /* read the place */
      if(geohints_file_line_place(line, &ptr, place, sizeof(place)) != 0)
	goto err;

      /* form the code from the lower-case alphabetic characters */
      i = j = 0;
      while(place[i] != '\0')
	{
	  if(isalpha((unsigned char)place[i]) != 0)
	    code[j++] = tolower((unsigned char)place[i]);
	  i++;
	}
      code[j] = '\0';

      /* skip over spaces */
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;

      /* iso3166 code */
      if(geohints_file_line_iso3166(line, &ptr, cc, st) != 0)
	goto err;
    }
  else if(type == GEOHINT_TYPE_COUNTRY)
    {
      /* iso3166 2-letter CC */
      if(isalpha((unsigned char)ptr[0]) != 0 &&
	 isalpha((unsigned char)ptr[1]) != 0 && ptr[2] == ' ')
	{
	  cc[0] = tolower((unsigned char)ptr[0]);
	  cc[1] = tolower((unsigned char)ptr[1]); cc[2] = '\0';
	}
      else goto err;
      ptr += 3;

      /* skip over whitespace */
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;

      /* iso3166 3-letter CC */
      if(isalpha((unsigned char)ptr[0]) != 0 &&
	 isalpha((unsigned char)ptr[1]) != 0 &&
	 isalpha((unsigned char)ptr[2]) != 0 && ptr[3] == ' ')
	{
	  st[0] = tolower((unsigned char)ptr[0]);
	  st[1] = tolower((unsigned char)ptr[1]);
	  st[2] = tolower((unsigned char)ptr[2]); st[3] = '\0';
	}
      else goto err;
      ptr += 4;

      /* skip over whitespace */
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;

      /* country name */
      line = ptr;
      if(geohints_file_line_place(line, &ptr, place, sizeof(place)) != 0)
	goto err;

      /* form the code from the lower-case alphabetic characters */
      i = j = 0;
      while(place[i] != '\0')
	{
	  if(isalpha((unsigned char)place[i]) != 0)
	    code[j++] = tolower((unsigned char)place[i]);
	  i++;
	}
      code[j] = '\0';

      /* make the hint and we're done */
      if(geohints_file_line_make(list, type, code, place,
				 cc, st, lat, lng, popn) == NULL)
	goto err;

      return 0;
    }
  else if(type == GEOHINT_TYPE_STATE)
    {
      /* iso3166 code */
      if(geohints_file_line_iso3166(line, &ptr, cc, st) != 0)
	goto err;

      /* only keep alphabetic state codes of 3 letters in length*/
      if(string_isalpha(st) == 0 || strlen(st) != 3)
	return 0;

      /* skip over whitespace */
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;

      /* state name */
      line = ptr;
      if(geohints_file_line_place(line, &ptr, place, sizeof(place)) != 0)
	goto err;

      /* form the code from the state code */
      memcpy(code, st, sizeof(st));

      /* make the hint and we're done */
      if(geohints_file_line_make(list, type, code, place,
				 cc, st, lat, lng, popn) == NULL)
	goto err;

      return 0;
    }
  else goto err;

  /* lat */
  while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
    ptr++;
  if(*ptr != '\0')
    {
      lat = strtod(ptr, &end);
      if(ptr == end || (*end != '\0' && isspace((unsigned char)*end) == 0))
	{
	  fprintf(stderr, "invalid latitude: %s\n", line);
	  goto err;
	}
      ptr = end;
      got_lat = 1;
    }

  /* long */
  while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
    ptr++;
  if(*ptr != '\0')
    {
      lng = strtod(ptr, &end);
      if(ptr == end || (*end != '\0' && isspace((unsigned char)*end) == 0))
	{
	  fprintf(stderr, "invalid longitude: %s\n", line);
	  goto err;
	}
      got_lng = 1;
      ptr = end;
    }

  if(got_lat == 0 || got_lng == 0)
    return 0;

  if(type == GEOHINT_TYPE_IATA || type == GEOHINT_TYPE_ICAO ||
     type == GEOHINT_TYPE_CLLI || type == GEOHINT_TYPE_LOCODE)
    {
      /* advance over any space, and then parse an iso3166 code if present */
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;
      if(geohints_file_line_iso3166(line, &ptr, cc, st) != 0)
	goto err;

      /* advance over any space, and then parse the location if present */
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;
      if(geohints_file_line_place(line, &ptr, place, sizeof(place)) != 0)
	goto err;
    }
  else if(type == GEOHINT_TYPE_PLACE)
    {
      /* advance over any space, and then parse population if present */
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;
      if(*ptr != '\0')
	{
	  popn = strtol(ptr, &end, 10);
	  if(ptr == end || (*end != '\0' && isspace((unsigned char)*end) == 0))
	    {
	      fprintf(stderr, "invalid population: %s\n", line);
	      goto err;
	    }
	}
    }
  else if(type == GEOHINT_TYPE_FACILITY)
    {
      /* advance over any space, and then parse the street address */
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;
      if(geohints_file_line_place(line, &ptr, street, sizeof(street)) != 0)
	goto err;

      /* advance over any space and then parse the facility name */
      while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
	ptr++;
      if(geohints_file_line_place(line, &ptr, facname, sizeof(facname)) != 0)
	goto err;
    }

  if((hint = geohints_file_line_make(list, type, code, place,
				     cc, st, lat, lng, popn)) == NULL)
    goto err;

  if(type == GEOHINT_TYPE_FACILITY)
    {
      if((street[0] != '\0' && (hint->street = strdup(street)) == NULL) ||
	 (facname[0] != '\0' && (hint->facname = strdup(facname)) == NULL))
	goto err;
      hint->flags |= GEOHINT_FLAG_FACILITY;
    }
  else if(type == GEOHINT_TYPE_LOCODE)
    {
      if((code[0] == 'g' && code[1] == 'b') ||
	 (code[0] == 'h' && code[1] == 'k'))
	{
	  if(code[0] == 'g' && code[1] == 'b')
	    {
	      code[0] = 'u';
	      code[1] = 'k';
	    }
	  else
	    {
	      code[0] = 'c';
	      code[1] = 'n';
	    }
	  if(geohints_file_line_make(list, type, code, place, cc, st,
				     lat, lng, popn) == NULL)
	    goto err;
	}
    }

  return 0;

 err:
  return -1;
}

/*
 * load_dict_geohints:
 *
 * load geohints into an slist and then compress into an array.
 */
static int load_dict_geohints(void)
{
  splaytree_t *clligp_tree = NULL, *strlist_tree = NULL;
  slist_t *geo_list = NULL, *clligp_list = NULL, *fac_list = NULL;
  slist_t *place_list = NULL, *other_list = NULL, *country_list = NULL;
  slist_t *state_list = NULL, *vp_list = NULL, *list;
  size_t *cou_hintc = NULL, *sta_hintc = NULL;
  size_t first[26];
  slist_node_t *sn;
  sc_strlist_t *sl;
  sc_geohint_t *hint, *fac;
  struct timeval start, finish;
  sc_clligp_t *clligp;
  char *geohint_file;
  int i, rc = -1;
  char buf[64];
  uint32_t x;
  size_t s;

  if(dicts == NULL)
    return 0;

  gettimeofday_wrap(&start);

  if((geo_list = slist_alloc()) == NULL ||
     (fac_list = slist_alloc()) == NULL ||
     (place_list = slist_alloc()) == NULL ||
     (other_list = slist_alloc()) == NULL ||
     (country_list = slist_alloc()) == NULL ||
     (state_list = slist_alloc()) == NULL ||
     (vp_list = slist_alloc()) == NULL ||
     (clligp_tree = splaytree_alloc((splaytree_cmp_t)sc_clligp_3cmp)) == NULL||
     (strlist_tree = splaytree_alloc((splaytree_cmp_t)sc_strlist_cmp))== NULL||
     (clligp_list = slist_alloc()) == NULL)
    goto done;

  while((geohint_file = slist_head_pop(dicts)) != NULL)
    {
      if(file_lines(geohint_file, geohints_file_line, geo_list))
	{
	  fprintf(stderr, "failed to read geohint file: %s\n", geohint_file);
	  goto done;
	}
    }

  while((hint = slist_head_item(geo_list)) != NULL)
    {
      /* map the geopolitical portion of the clli code to ISO3166 cc/st */
      if(hint->type == GEOHINT_TYPE_CLLI &&
	 sc_clligp_get(clligp_tree, hint->code+4, hint->cc, hint->st) == NULL)
	goto done;

      /* put the hint into one of five lists for further processing */
      if(hint->type == GEOHINT_TYPE_FACILITY)
	list = fac_list;
      else if(hint->type == GEOHINT_TYPE_PLACE)
	list = place_list;
      else if(hint->type == GEOHINT_TYPE_COUNTRY)
	list = country_list;
      else if(hint->type == GEOHINT_TYPE_STATE)
	list = state_list;
      else if(hint->type == GEOHINT_TYPE_VP)
	list = vp_list;
      else
	list = other_list;
      if(slist_tail_push(list, hint) == NULL)
	goto done;
      slist_head_pop(geo_list);
    }

  /* map the geopolitical portion of the clli code to ISO3166 cc/st */
  splaytree_inorder(clligp_tree, tree_to_slist, clligp_list);
  splaytree_free(clligp_tree, NULL); clligp_tree = NULL;
  if((i = slist_count(clligp_list)) > 0)
    {
      clligpc = (size_t)i;
      if((clligps = malloc_zero(sizeof(sc_clligp_t *) * clligpc)) == NULL)
	goto done;
      i = 0;
      while((clligp = slist_head_pop(clligp_list)) != NULL)
	clligps[i++] = clligp;
    }

  /* put the facilities in their own global array separate from other hints */
  geohint_facc = slist_count(fac_list);
  if((geohint_facs = malloc_zero(sizeof(sc_geohint_t *)*geohint_facc)) == NULL)
    goto done;
  i = 0;
  while((hint = slist_head_pop(fac_list)) != NULL)
    geohint_facs[i++] = hint;

  /* put vp geohints in their own array */
  if((i = slist_count(vp_list)) > 0)
    {
      geohint_vpc = (size_t)i;
      if((geohint_vps = malloc_zero(sizeof(sc_geohint_t *)*geohint_vpc))==NULL)
	goto done;
      s = 0;
      while((hint = slist_head_pop(vp_list)) != NULL)
	{
	  geohint_vps[s] = hint;
	  hint->index = s;
	  s++;
	}
      array_qsort((void **)geohint_vps, geohint_vpc,
		  (array_cmp_t)sc_geohint_cmp);
    }

  /* put the states in their own array */
  if((i = slist_count(state_list)) > 0)
    {
      geohint_stac = (size_t)i;
      if((geohint_stas=malloc_zero(sizeof(sc_state_t *)*geohint_stac)) == NULL)
	goto done;
      i = 0;
      while((hint = slist_head_pop(state_list)) != NULL)
	{
	  if((geohint_stas[i] = malloc_zero(sizeof(sc_state_t))) == NULL)
	    goto done;
	  memcpy(geohint_stas[i]->cc, hint->cc, sizeof(geohint_stas[i]->cc));
	  memcpy(geohint_stas[i]->st, hint->st, sizeof(geohint_stas[i]->st));
	  geohint_stas[i]->name = hint->place; hint->place = NULL;
	  sc_geohint_free(hint);
	  i++;
	}
      sc_state_sort();
    }

  /* put the countries in their own array */
  if((i = slist_count(country_list)) > 0)
    {
      geohint_couc = (size_t)i;
      if((geohint_cous=malloc_zero(sizeof(sc_country_t *)*geohint_couc))==NULL)
	goto done;
      i = 0;
      while((hint = slist_head_pop(country_list)) != NULL)
	{
	  if((geohint_cous[i] = malloc_zero(sizeof(sc_country_t))) == NULL)
	    goto done;
	  memcpy(geohint_cous[i]->cc, hint->cc, sizeof(geohint_cous[i]->cc));
	  memcpy(geohint_cous[i]->iso3,hint->st,sizeof(geohint_cous[i]->iso3));
	  geohint_cous[i]->name = hint->place; hint->place = NULL;
	  sc_geohint_free(hint);
	  i++;
	}
      array_qsort((void **)geohint_cous, geohint_couc,
		  (array_cmp_t)sc_country_cmp2);
    }

  /* count how many location hints we have per country and state */
  if((cou_hintc = malloc_zero(sizeof(size_t) * geohint_couc)) == NULL ||
     (sta_hintc = malloc_zero(sizeof(size_t) * geohint_stac)) == NULL)
    goto done;
  for(sn=slist_head_node(place_list); sn != NULL; sn=slist_node_next(sn))
    {
      hint = slist_node_item(sn);
      if(sc_country_findpos(hint->cc, &s) == 0)
	cou_hintc[s]++;
      if(sc_state_sort_findpos(hint->st, hint->cc, &s) == 0)
	sta_hintc[s]++;
    }

  /* put some landmarks in for each country and state */
  for(s=0; s<geohint_couc; s++)
    {
      if(cou_hintc[s] > 0 &&
	 (geohint_cous[s]->hints = malloc_zero(sizeof(sc_geohint_t *) *
					       cou_hintc[s])) == NULL)
	goto done;
    }
  for(s=0; s<geohint_stac; s++)
    {
      if(sta_hintc[s] > 0 &&
	 (geohint_stas[s]->hints = malloc_zero(sizeof(sc_geohint_t *) *
					       sta_hintc[s])) == NULL)
	goto done;
    }
  for(sn=slist_head_node(place_list); sn != NULL; sn=slist_node_next(sn))
    {
      hint = slist_node_item(sn);
      if(sc_country_findpos(hint->cc, &s) == 0)
	{
	  assert(geohint_cous[s]->hintc < cou_hintc[s]);
	  geohint_cous[s]->hints[geohint_cous[s]->hintc++] = hint;
	}
      if(sc_state_sort_findpos(hint->st, hint->cc, &s) == 0)
	{
	  assert(geohint_stas[s]->hintc < sta_hintc[s]);
	  geohint_stas[s]->hints[geohint_stas[s]->hintc++] = hint;
	}
    }
  for(s=0; s<geohint_couc; s++)
    {
      array_qsort((void **)geohint_cous[s]->hints, geohint_cous[s]->hintc,
		  (array_cmp_t)sc_geohint_popn_cmp);
    }
  for(s=0; s<geohint_stac; s++)
    {
      array_qsort((void **)geohint_stas[s]->hints, geohint_stas[s]->hintc,
		  (array_cmp_t)sc_geohint_popn_cmp);
    }

  /* sort countries by iso3166 3-letter code */
  array_qsort((void **)geohint_cous, geohint_couc,
	      (array_cmp_t)sc_country_cmp3);

  /*
   * go through the places, tagging those that have a known facility.
   * if we have a facility in a place that we don't have in our dictionary,
   * add an entry for it.
   */
  for(sn=slist_head_node(place_list); sn != NULL; sn=slist_node_next(sn))
    {
      hint = slist_node_item(sn);
      if((sl = sc_strlist_get(strlist_tree, hint->code)) == NULL ||
	 slist_tail_push(sl->list, hint) == NULL)
	goto done;

      /*
       * while we are here, count how many place names start with a specific
       * letter.
       */
      i = hint->code[0] - 'a'; assert(i >= 0 && i < 26);
      geohint_plc[i]++;

    }
  for(s=0; s<geohint_facc; s++)
    {
      fac = geohint_facs[s];

      sl = sc_strlist_get(strlist_tree, fac->code); x = 0;
      for(sn=slist_head_node(sl->list); sn != NULL; sn=slist_node_next(sn))
	{
	  hint = slist_node_item(sn);
	  if(strcmp(fac->cc,hint->cc) == 0 && sc_geohint_dist(fac,hint) <= 40)
	    {
	      hint->flags |= GEOHINT_FLAG_FACILITY;
	      x++;
	    }
	}

      /* there is no existing place by this name in the dictionary, add it */
      if(x != 0)
	continue;
      if((hint = sc_geohint_alloc(GEOHINT_TYPE_PLACE, fac->code, fac->place,
				  fac->st, fac->cc,
				  fac->lat, fac->lng, 0)) == NULL ||
	 slist_tail_push(sl->list, hint) == NULL ||
	 slist_tail_push(place_list, hint) == NULL)
	{
	  goto done;
	}

      x = hint->code[0] - 'a'; assert(x < 26);
      geohint_plc[x]++;
      hint->flags |= GEOHINT_FLAG_FACILITY;
    }

  /*
   * add places to an array indexed by the first letter to make subsequent
   * lookups by first name fast.
   */
  memset(first, 0, sizeof(first));
  for(i=0; i<26; i++)
    {
      if((geohint_pls[i] =
	  malloc_zero(sizeof(sc_geohint_t *) * geohint_plc[i])) == NULL)
	goto done;
    }
  for(sn=slist_head_node(place_list); sn != NULL; sn=slist_node_next(sn))
    {
      hint = slist_node_item(sn);
      i = hint->code[0] - 'a';
      assert(i >= 0 && i < 26); assert(first[i] < geohint_plc[i]);
      geohint_pls[i][first[i]] = hint;
      first[i]++;
    }
  for(i=0; i<26; i++)
    assert(first[i] == geohint_plc[i]);

  slist_concat(geo_list, other_list);
  slist_concat(geo_list, place_list);
  if((i = slist_count(geo_list)) <= 0)
    {
      rc = 0;
      goto done;
    }
  geohintc = (size_t)i;
  if((geohints = malloc_zero(sizeof(sc_geohint_t *) * geohintc)) == NULL)
    {
      fprintf(stderr,"%s: could not malloc %d geohints\n", __func__,
	      (int)geohintc);
      goto done;
    }
  s = 0;
  while((hint = slist_head_pop(geo_list)) != NULL)
    geohints[s++] = hint;
  sc_geohint_sort(geohints, geohintc);
  for(s=0; s<geohintc; s++)
    geohints[s]->index = s;

  gettimeofday_wrap(&finish);
  fprintf(stderr, "loaded %d geohints in %s\n", (int)geohintc,
	  duration_tostr(buf, sizeof(buf), &start, &finish));
  rc = 0;

 done:
  if(geo_list != NULL) slist_free_cb(geo_list, (slist_free_t)sc_geohint_free);
  if(vp_list != NULL) slist_free_cb(vp_list, (slist_free_t)sc_geohint_free);
  if(place_list != NULL)
    slist_free_cb(place_list, (slist_free_t)sc_geohint_free);
  if(other_list != NULL)
    slist_free_cb(other_list, (slist_free_t)sc_geohint_free);
  if(clligp_list != NULL) slist_free_cb(clligp_list, free);
  if(clligp_tree != NULL) splaytree_free(clligp_tree, free);
  if(fac_list != NULL) slist_free_cb(fac_list, (slist_free_t)sc_geohint_free);
  if(strlist_tree != NULL)
    splaytree_free(strlist_tree, (splaytree_free_t)sc_strlist_free);
  if(country_list != NULL)
    slist_free_cb(country_list, (slist_free_t)sc_geohint_free);
  if(state_list != NULL)
    slist_free_cb(state_list, (slist_free_t)sc_geohint_free);
  if(cou_hintc != NULL) free(cou_hintc);
  if(sta_hintc != NULL) free(sta_hintc);
  return rc;
}

/*
 * asnames_file_line:
 *
 */
static int asnames_file_line(char *line, void *param)
{
  splaytree_t *tree = param;
  char *name = NULL, *asn = NULL, *ptr;
  sc_as2tag_t fm;
  long long ll;

  if(*line == '#')
    return 0;

  asn = line;
  ptr = line;
  while(isdigit((unsigned char)*ptr) != 0)
    ptr++;
  if(*ptr == '\0')
    {
      fprintf(stderr, "%s: unexpected null: %s\n", __func__, line);
      return -1;
    }

  *ptr = '\0';
  ptr++;
  if(isspace((unsigned char)*ptr) != 0)
    {
      while(*ptr != '\0' && isspace((unsigned char)*ptr) == 0)
	ptr++;
      if(*ptr == '\0')
	{
	  fprintf(stderr, "%s: unexpected null\n", __func__);
	  return -1;
	}
    }
  name = ptr;

  if(string_isdigit(asn) == 0 || string_tollong(asn, &ll, NULL, 10) != 0 ||
     ll < 0 || ll > 4294967295)
    {
      fprintf(stderr, "%s: invalid asn %s\n", __func__, asn);
      return -1;
    }

  fm.tag = name;
  if(splaytree_find(tree, &fm) != NULL)
    {
      fprintf(stderr, "%s: %s already exists\n", __func__, name);
      return -1;
    }

  if(sc_as2tag_get(tree, ll, name) == NULL)
    {
      fprintf(stderr, "%s: could not add %s\n", __func__, name);
      return -1;
    }

  return 0;
}

/*
 * load_dict_asnames:
 *
 * load asnames into an slist and then compress into an array.
 */
static int load_dict_asnames(void)
{
  splaytree_t *tree = NULL;
  slist_t *list = NULL;
  sc_as2tag_t *a2t;
  int x, rc = -1;
  char *file;

  if(dicts == NULL)
    return 0;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_as2tag_tag_cmp)) == NULL ||
     (list = slist_alloc()) == NULL)
    goto done;

  while((file = slist_head_pop(dicts)) != NULL)
    {
      if(file_lines(file, asnames_file_line, tree))
	{
	  fprintf(stderr, "failed to read %s\n", file);
	  goto done;
	}
    }
  splaytree_inorder(tree, tree_to_slist, list);
  splaytree_free(tree, NULL); tree = NULL;
  if((x = slist_count(list)) <= 0)
    {
      rc = 0;
      goto done;
    }
  tag2asc = (size_t)x;

  if((tag2ass = malloc_zero(sizeof(sc_as2tag_t *) * tag2asc)) == NULL)
    {
      fprintf(stderr,"%s: could not alloc %d entries\n",__func__,(int)tag2asc);
      goto done;
    }

  x = 0;
  while((a2t = slist_head_pop(list)) != NULL)
    tag2ass[x++] = a2t;

  fprintf(stderr, "loaded %d asnames\n", x);
  rc = 0;

 done:
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)sc_as2tag_free);
  if(list != NULL) slist_free_cb(list, (slist_free_t)sc_as2tag_free);
  return rc;
}

static int load_dict(void)
{
  if(dicts == NULL)
    return 0;

  if(do_learngeo != 0)
    {
      if(load_dict_geohints() != 0)
	return -1;
    }
  else if(do_learnasnames != 0)
    {
      if(load_dict_asnames() != 0)
	return -1;
    }
  else
    {
      fprintf(stderr, "unnecessary dictionary supplied\n");
      return -1;
    }

  return 0;
}

/*
 * rttload_router_finish
 *
 * load RTT samples into the router node
 */
static int rttload_router_finish(sc_rttload_t *rtl)
{
  assert(rtl->rtr->rtts == NULL);
  if(rtl->rttc == 0)
    return 0;
  if((rtl->rtr->rtts = memdup(rtl->rtts, sizeof(sc_rtt_t) * rtl->rttc)) == NULL)
    {
      fprintf(stderr, "%s: could not memdup %d entries\n", __func__,
	      (int)rtl->rttc);
      return -1;
    }
  rtl->rtr->rttc = rtl->rttc;
  rtl->rttc = 0;
  return 0;
}

static int rtt_file_line(char *line, void *param)
{
  static int lineno = 0;
  sc_rttload_t *rtl = param;
  sc_geohint_t *vp;
  sc_router_t rt;
  char *id_ptr, *vp_ptr, *rtt_ptr, *dup = NULL;
  long long id;
  long rtt;
  int rc = -1;

  lineno++;

  /* skip over comments */
  if(line[0] == '#')
    return 0;

  /* ensure nodeid starts with N */
  if(line[0] != 'N')
    {
      fprintf(stderr, "%s: line %d expected N\n", __func__, lineno);
      goto done;
    }

  /*
   * get the node ID.  check to see if we should 'finish' the last
   * router, and then continue parsing the line
   */
  id_ptr = line+1;
  if((vp_ptr = string_nextword(id_ptr)) == NULL)
    {
      fprintf(stderr, "%s: no VP on line %d\n", __func__, lineno);
      goto done;
    }
  if(string_isdigit(id_ptr) == 0 || string_tollong(id_ptr, &id, NULL, 10) != 0)
    {
      fprintf(stderr, "%s: id %s invalid on line %d\n", __func__,
	      id_ptr, lineno);
      goto done;
    }
  /* finish the router */
  assert(id >= 0);
  if(rtl->rtr != NULL && rtl->id != id && rttload_router_finish(rtl) != 0)
    goto done;

  /* get the appropriate router */
  if(rtl->rtr == NULL || rtl->id != id)
    {
      rt.id = (uint32_t)id;
      rtl->rtr = array_find((void **)rtl->routers, rtl->routerc, &rt,
			    (array_cmp_t)sc_router_id_cmp);
      rtl->id = id;
    }
  if(rtl->rtr == NULL)
    {
      rc = 0;
      goto done;
    }

  /* sanity check the VP and RTT */
  if((rtt_ptr = string_nextword(vp_ptr)) == NULL)
    {
      fprintf(stderr, "%s: no RTT on line %d\n", __func__, lineno);
      goto done;
    }

  if((vp = sc_geohint_vpfind(vp_ptr)) == NULL)
    {
      if(array_find((void **)rtl->unknown, rtl->unknownc, vp_ptr,
		    (array_cmp_t)strcasecmp) == NULL)
	{
	  fprintf(stderr, "warning: unknown geocode %s in %s line %d\n",
		  vp_ptr, rtt_file, lineno);
	  if((dup = strdup(vp_ptr)) == NULL ||
	     array_insert((void ***)&rtl->unknown, &rtl->unknownc, dup,
			  (array_cmp_t)strcasecmp) != 0)
	    {
	      fprintf(stderr, "%s: could not remember unknown geocode %s\n",
		      __func__, vp_ptr);
	      goto done;
	    }
	}
    }
  if(string_isdigit(rtt_ptr) == 0 || string_tolong(rtt_ptr, &rtt) != 0)
    {
      fprintf(stderr, "%s: rtt %s invalid on line %d\n", __func__,
	      rtt_ptr, lineno);
      goto done;
    }
  assert(rtt >= 0);

  if(vp != NULL)
    {
      if(rtl->rttc == rtl->rttm)
	{
	  if(realloc_wrap((void **)&rtl->rtts,
			  sizeof(sc_rtt_t) * (rtl->rttm + 50)) != 0)
	    {
	      fprintf(stderr, "%s: could not realloc rtts\n", __func__);
	      goto done;
	    }
	  rtl->rttm += 50;
	}

      rtl->rtts[rtl->rttc].rtt = rtt;
      rtl->rtts[rtl->rttc].vp = vp;
      rtl->rttc++;
    }

  rc = 0;

 done:
  return rc;
}

static int load_rtt(void)
{
  struct timeval start, finish;
  sc_router_t *rtr;
  sc_rttload_t rtl;
  slist_node_t *sn;
  int rc = -1, rttc = 0, rtc = 0;
  char buf[32];
  size_t i;

  if(rtt_file == NULL)
    return 0;

  gettimeofday_wrap(&start);

  memset(&rtl, 0, sizeof(rtl));
  for(sn=slist_head_node(router_list); sn != NULL; sn=slist_node_next(sn))
    {
      rtr = slist_node_item(sn);
      if((rtr->flags & SC_ROUTER_FLAG_ID) != 0)
	rtl.routerc++;
    }
  if(rtl.routerc == 0)
    {
      fprintf(stderr, "%s: no routers tagged with an ID\n", __func__);
      goto done;
    }

  if((rtl.routers = malloc_zero(sizeof(sc_router_t *) * rtl.routerc)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc %d routers\n", __func__,
	      (int)rtl.routerc);
      goto done;
    }

  if((rtl.rtts = malloc(sizeof(sc_rtt_t) * 50)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc samples\n", __func__);
      goto done;
    }
  rtl.rttc = 0;
  rtl.rttm = 50;

  i = 0;
  for(sn=slist_head_node(router_list); sn != NULL; sn=slist_node_next(sn))
    {
      rtr = slist_node_item(sn);
      if((rtr->flags & SC_ROUTER_FLAG_ID) != 0)
	rtl.routers[i++] = rtr;
    }
  assert(i == rtl.routerc);
  array_qsort((void **)rtl.routers,rtl.routerc,(array_cmp_t)sc_router_id_cmp);

  if(file_lines(rtt_file, rtt_file_line, &rtl) != 0)
    {
      fprintf(stderr, "could not read %s\n", rtt_file);
      goto done;
    }
  if(rtl.rtr != NULL)
    rttload_router_finish(&rtl);

  threadp = threadpool_alloc(threadc);
  for(i=0; i<rtl.routerc; i++)
    {
      if(rtl.routers[i]->rttc == 0)
	continue;
      rtc++;
      rttc += rtl.routers[i]->rttc;
      threadpool_tail_push(threadp, (threadpool_func_t)sc_router_rtt_sort,
			   rtl.routers[i]);
    }
  threadpool_join(threadp); threadp = NULL;

  gettimeofday_wrap(&finish);
  fprintf(stderr, "loaded %d rtts in %d routers in %s\n", rttc, rtc,
	  duration_tostr(buf, sizeof(buf), &start, &finish));

  rc = 0;

 done:
  if(rtl.routers != NULL) free(rtl.routers);
  if(rtl.rtts != NULL) free(rtl.rtts);
  if(rtl.unknown != NULL)
    {
      for(i=0; i<rtl.unknownc; i++)
	free(rtl.unknown[i]);
      free(rtl.unknown);
    }
  return rc;
}

static void cleanup(void)
{
  size_t i;

  if(suffix_root != NULL)
    {
      sc_suffix_free(suffix_root);
      suffix_root = NULL;
    }

  if(domain_tree != NULL)
    {
      splaytree_free(domain_tree, (splaytree_free_t)sc_domain_free);
      domain_tree = NULL;
    }

  if(domain_list != NULL)
    {
      slist_free(domain_list);
      domain_list = NULL;
    }

  if(siblings != NULL)
    {
      for(i=0; i<siblingc; i++)
	if(siblings[i] != NULL)
	  free(siblings[i]);
      free(siblings); siblings = NULL;
    }

  if(tag2ass != NULL)
    {
      for(i=0; i<tag2asc; i++)
	if(tag2ass[i] != NULL)
	  sc_as2tag_free(tag2ass[i]);
      free(tag2ass); tag2ass = NULL;
    }

  if(geohints != NULL)
    {
      for(i=0; i<geohintc; i++)
	if(geohints[i] != NULL)
	  sc_geohint_free(geohints[i]);
      free(geohints); geohints = NULL;
    }

  if(geohint_facs != NULL)
    {
      for(i=0; i<geohint_facc; i++)
	if(geohint_facs[i] != NULL)
	  sc_geohint_free(geohint_facs[i]);
      free(geohint_facs); geohint_facs = NULL;
    }

  if(geohint_vps != NULL)
    {
      for(i=0; i<geohint_vpc; i++)
	if(geohint_vps[i] != NULL)
	  sc_geohint_free(geohint_vps[i]);
      free(geohint_vps); geohint_vps = NULL;
    }

  if(geohint_cous != NULL)
    {
      for(i=0; i<geohint_couc; i++)
	if(geohint_cous[i] != NULL)
	  sc_country_free(geohint_cous[i]);
      free(geohint_cous); geohint_cous = NULL;
    }

  if(geohint_stas != NULL)
    {
      for(i=0; i<geohint_stac; i++)
	if(geohint_stas[i] != NULL)
	  sc_state_free(geohint_stas[i]);
      free(geohint_stas); geohint_stas = NULL;
    }

  for(i=0; i<26; i++)
    if(geohint_pls[i] != NULL)
      free(geohint_pls[i]);

  if(clligps != NULL)
    {
      for(i=0; i<clligpc; i++)
	if(clligps[i] != NULL)
	  free(clligps[i]);
      free(clligps); clligps = NULL;
    }

  if(dicts != NULL)
    {
      slist_free(dicts);
      dicts = NULL;
    }

  if(router_list != NULL)
    {
      slist_free_cb(router_list, (slist_free_t)sc_router_free);
      router_list = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
  int j, rc = -1;

#ifdef HAVE_PTHREAD
  long i;
#endif

#ifdef DMALLOC
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    {
      return -1;
    }

#ifdef HAVE_PTHREAD
  if(threadc == -1)
    {
      threadc = 1;
#ifdef _SC_NPROCESSORS_ONLN
      if((i = sysconf(_SC_NPROCESSORS_ONLN)) > 1)
	threadc = i;
#endif
    }
  fprintf(stderr, "using %ld threads\n", threadc);
#else
  threadc = 0;
#endif

  /* load the public suffix list */
  if(load_suffix() != 0)
    return -1;

  /* load the siblings */
  if(load_siblings() != 0)
    return -1;

  /* load the routers, part 1 */
  if(load_routers_1() != 0)
    return -1;

  /* load any dictionaries */
  if(load_dict() != 0)
    return -1;

  /* load the RTT samples */
  if(load_rtt() != 0)
    return -1;

  /* load the routers, part 2 */
  if(load_routers_2() != 0)
    return -1;

  /* stop if we were told to stop after loading the data */
  if(do_loadonly != 0)
    return 0;

  /* generate regular expressions */
  if(generate_regexes() != 0)
    return -1;

  /* evaluate regular expressions */
  if(eval_regexes() != 0)
    return -1;

  if(do_learnasn != 0)
    {
      for(j=1; j<=stop_id; j++)
	{
	  if(j == 1)      { if(refine_regexes_merge() != 0) return -1; }
	  else if(j == 2) { if(refine_regexes_class() != 0) return -1; }
	  else if(j == 3) { if(refine_regexes_merge() != 0) return -1; }
	  else if(j == 4) { if(refine_regexes_sets() != 0) return -1; }
	}
    }
  else if(do_learnasnames != 0)
    {
      for(j=1; j<=stop_id; j++)
	{
	  if(j == 1)      { if(refine_regexes_merge() != 0) return -1; }
	  else if(j == 2) { if(refine_dict_asnames() != 0) return -1; }
	  else if(j == 3) { if(refine_regexes_class() != 0) return -1; }
	  else if(j == 4) { if(refine_regexes_merge() != 0) return -1; }
	  else if(j == 5) { if(refine_regexes_sets() != 0) return -1; }
	  else if(j == 6) { if(refine_regexes_ip() != 0) return -1; }
	}
    }
  else if(do_learngeo != 0)
    {
      for(j=1; j<=stop_id; j++)
	{
	  if(j == 1)      { if(refine_regexes_merge() != 0) return -1; }
	  else if(j == 2) { if(refine_regexes_class() != 0) return -1; }
	  else if(j == 3) { if(refine_regexes_merge() != 0) return -1; }
	  else if(j == 4) { if(refine_regexes_sets() != 0) return -1; }
	  else if(j == 5) { if(refine_dict_geo() != 0) return -1; }
	  else if(j == 6) { if(refine_regexes_fp() != 0) return -1; }
	}
    }
  else if(do_learnalias != 0)
    {
      for(j=1; j<=stop_id; j++)
	{
	  if(j == 1)
	    {
	      if(regex_eval == NULL && thin_regexes(0) != 0)
		return -1;
	    }
	  else if(j == 2) { if(refine_regexes_tp() != 0) return -1; }
	  else if(j == 3) { if(refine_regexes_fne() != 0) return -1; }
	  else if(j == 4) { if(refine_regexes_class() != 0) return -1; }
	  else if(j == 5) { if(refine_regexes_fnu() != 0) return -1; }
	  else if(j == 6) { if(refine_regexes_sets() != 0) return -1; }
	  else if(j == 7) { if(refine_regexes_ip() != 0) return -1; }
	  else if(j == 8) { if(refine_regexes_fp() != 0) return -1; }
	}
    }

  rc = dump_funcs[dump_id].func();
  return rc;
}

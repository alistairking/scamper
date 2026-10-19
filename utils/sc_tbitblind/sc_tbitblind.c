/*
 * sc_tbitblind : scamper driver to collect data on receiver response to
 *              : packets that might have been sent by a blind in-window
 *              : attacker.
 *
 * Authors      : Matthew Luckie, Robert Beverly.
 *
 * Copyright (C) 2015,2023 The Regents of the University of California
 * Copyright (C) 2022-2026 Matthew Luckie
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

#include "scamper_addr.h"
#include "scamper_list.h"
#include "tbit/scamper_tbit.h"
#include "lib/libscamperctrl/libscamperctrl.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "utils.h"

static uint32_t               options       = 0;
static splaytree_t           *tree          = NULL;
static slist_t               *list          = NULL;
static heap_t                *heap          = NULL;
static int                    port          = 31337;
static char                  *addressfile   = NULL;
static scamper_ctrl_t        *scamper_ctrl  = NULL;
static scamper_inst_t        *scamper_inst  = NULL;
static char                  *outfile_type  = "warts";
static char                  *outfile_name  = NULL;
static scamper_file_t        *outfile       = NULL;
static int                    outfile_obj   = 0;
static int                    outfile_i     = 0;
static int                    ttl           = 0;
static int                    wait_between  = 0;
static int                    limit         = 10000;
static int                    tbit_app      = SCAMPER_TBIT_APP_HTTP;
static int                    noshuffle     = 0;
static scamper_file_filter_t *ffilter       = NULL;
static scamper_file_t        *decode_sf     = NULL;
static scamper_file_readbuf_t *decode_rb    = NULL;
static char                   cmd[512];
static int                    more          = 0;
static int                    error         = 0;
static int                    probing       = 0;
static FILE                  *text          = NULL;
static FILE                  *comp          = NULL;
static struct timeval         now;

static char *methods[] = {
  "-t blind-rst",
  "-t blind-rst -o -70000",
  "-t blind-syn",
  "-t blind-syn -o -70000",
  "-t blind-data",
  "-t blind-data -o 70000",
};
static const int methodc = sizeof(methods) / sizeof(char *);

#define MODE_ICW   0
#define MODE_BLIND 1
#define MODE_FP    2
#define MODE_LAST  2

typedef struct target
{
  scamper_addr_t   *addr;
  struct timeval    next;
  int               mode;
  union
  {
    char           *url;
    uint16_t        asn;
  } un;
  slist_t          *methods;
  uint16_t          sport;
  heap_node_t      *hn;
  splaytree_node_t *tn;
} target_t;

#define OPT_HELP        0x0001
#define OPT_ADDRESSFILE 0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_TEXT        0x0010
#define OPT_LIMIT       0x0020
#define OPT_COMPLETED   0x0080
#define OPT_RANDOM      0x0100
#define OPT_WAIT        0x0200
#define OPT_OPTIONS     0x0400
#define OPT_APPTYPE     0x0800
#define OPT_TTL         0x1000

/* XXX: need to handle -? */
static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
  "usage: sc_tbitblind [-?r] [-a addressfile] [-o outfile] [-p port]\n"
  "                    [-A app] [-c comp] [-l limit] [-t logfile] [-T ttl]\n"
  "                    [-O options] [-w wait]\n");
  return;
}

static int check_options(int argc, char *argv[])
{
  int ch;
  long lo;
  char *opts = "A:a:c:l:o:O:p:rt:T:w:";
  char *opt_port = NULL, *opt_text = NULL, *opt_limit = NULL;
  char *opt_wait = NULL, *opt_comp = NULL;
  char *opt_apptype = NULL, *opt_ttl = NULL;
  uint32_t mandatory = OPT_ADDRESSFILE | OPT_OUTFILE | OPT_PORT;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_ADDRESSFILE;
	  addressfile = optarg;
	  break;

	case 'A':
	  options |= OPT_APPTYPE;
	  opt_apptype = optarg;
	  break;

	case 'c':
	  options |= OPT_COMPLETED;
	  opt_comp = optarg;
	  break;

	case 'l':
	  options |= OPT_LIMIT;
	  opt_limit = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "noshuffle") == 0)
	    noshuffle = 1;
	  else if(strcasecmp(optarg, "gz") == 0 ||
		  strcasecmp(optarg, "warts.gz") == 0)
	    {
#ifdef HAVE_ZLIB
	      outfile_type = "warts.gz";
#else
	      fprintf(stderr, "cannot write %s: did not link against zlib\n",
		      optarg);
	      return -1;
#endif
	    }
	  else if(strcasecmp(optarg, "bz2") == 0 ||
		  strcasecmp(optarg, "warts.bz2") == 0)
	    {
#ifdef HAVE_LIBBZ2
	      outfile_type = "warts.bz2";
#else
	      fprintf(stderr, "cannot write %s: did not link against libbz2\n",
		      optarg);
	      return -1;
#endif
	    }
	  else if(strcasecmp(optarg, "xz") == 0 ||
		  strcasecmp(optarg, "warts.xz") == 0)
	    {
#ifdef HAVE_LIBLZMA
	      outfile_type = "warts.xz";
#else
	      fprintf(stderr, "cannot write %s: did not link against liblzma\n",
		      optarg);
	      return -1;
#endif
	    }
	  else
	    {
	      usage(OPT_OPTIONS);
	      return -1;
	    }
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'r':
	  options |= OPT_RANDOM;
	  break;

	case 't':
	  options |= OPT_TEXT;
	  opt_text = optarg;
	  break;

	case 'T':
	  options |= OPT_TTL;
	  opt_ttl = optarg;
	  break;

	case 'w':
	  options |= OPT_WAIT;
	  opt_wait = optarg;
	  break;

	case '?':
	default:
	  usage(0xffffffff);
	  return -1;
	}
    }

  /* these options are mandatory */
  if((options & mandatory) != mandatory)
    {
      if(options == 0) usage(0);
      else             usage(mandatory);
      return -1;
    }

  /* find out which port scamper can be found listening on */
  if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
    {
      usage(OPT_PORT);
      return -1;
    }
  port = lo;

  if(opt_limit != NULL)
    {
      if(string_tolong(opt_limit, &lo) != 0 || lo < 1 || lo > 10000)
	{
	  usage(OPT_LIMIT);
	  return -1;
	}
      limit = lo;
    }
  outfile_obj = limit;

  if(opt_wait != NULL)
    {
      if(string_tolong(opt_wait, &lo) != 0 || lo < 1 || lo > 180)
	{
	  usage(OPT_WAIT);
	  return -1;
	}
      wait_between = lo;
    }

  if(opt_text != NULL)
    {
      if((text = fopen(opt_text, "w")) == NULL)
	{
	  usage(OPT_TEXT);
	  fprintf(stderr, "could not open %s\n", opt_text);
	  return -1;
	}
    }

  if(opt_apptype != NULL)
    {
      if(strcasecmp(opt_apptype, "http") == 0)
	tbit_app = SCAMPER_TBIT_APP_HTTP;
      else if(strcasecmp(opt_apptype, "bgp") == 0)
	tbit_app = SCAMPER_TBIT_APP_BGP;
      else
	{
	  usage(OPT_APPTYPE);
	  return -1;
	}
    }

  if(wait_between == 0)
    {
      if(tbit_app == SCAMPER_TBIT_APP_HTTP)
	wait_between = 60;
      else if(tbit_app == SCAMPER_TBIT_APP_BGP)
	wait_between = 180;
    }

  if(opt_ttl != NULL)
    {
      if(string_tolong(opt_ttl, &lo) != 0 || lo < 1 || lo > 255)
	{
	  usage(OPT_TTL);
	  return -1;
	}
      ttl = lo;
    }

  if(opt_comp != NULL)
    {
      if((comp = fopen(opt_comp, "a")) == NULL)
	{
	  usage(OPT_COMPLETED);
	  fprintf(stderr, "could not open %s\n", opt_comp);
	  return -1;
	}
    }

  return 0;
}

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static void print(char *format, ...) __attribute__((format(printf, 1, 2)));
#endif

static void print(char *format, ...)
{
  va_list ap;
  char time[32], msg[512];
  struct tm *tm;
  time_t t;

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  t = now.tv_sec;
  if((tm = localtime(&t)) != NULL)
    {
      snprintf(time, sizeof(time), "[%02d:%02d:%02d:%03ld]", tm->tm_hour,
	       tm->tm_min, tm->tm_sec, (long int)now.tv_usec / 1000);
    }
  else
    {
      snprintf(time, sizeof(time), "[%12ld]", (long int)now.tv_sec);
    }

  printf("%s %s", time, msg);

  if(text != NULL)
    {
      fprintf(text, "%s %s", time, msg);
      fflush(text);
    }

  return;
}

static int target_next_cmp(const void *va, const void *vb)
{
  const target_t *a = va;
  const target_t *b = vb;
  return timeval_cmp(&b->next, &a->next);
}

static int target_addr_cmp(const void *va, const void *vb)
{
  const target_t *a = va;
  const target_t *b = vb;
  return scamper_addr_cmp(a->addr, b->addr);
}

static void target_free(target_t *target)
{
  if(target == NULL)
    return;

  if(tbit_app == SCAMPER_TBIT_APP_HTTP && target->un.url != NULL)
    free(target->un.url);

  if(target->hn != NULL)
    heap_delete(heap, target->hn);

  if(target->tn != NULL)
    splaytree_remove_node(tree, target->tn);

  if(target->addr != NULL)
    scamper_addr_free(target->addr);

  if(target->methods != NULL)
    slist_free(target->methods);

  free(target);
  return;
}

static int do_method(void)
{
  target_t *target;
  char addr[128];
  size_t off = 0;
  char *m = NULL;
  int i;

  if(more < 1)
    return 0;

  if((target = heap_head_item(heap)) != NULL &&
     timeval_cmp(&target->next, &now) <= 0)
    {
      target = heap_remove(heap);
      target->hn = NULL;
    }
  else if((target = slist_head_pop(list)) != NULL)
    {
      if((target->methods = slist_alloc()) == NULL)
	return -1;
      for(i=0; i<methodc; i++)
	if(slist_tail_push(target->methods, methods[i]) == NULL)
	  return -1;
      if(noshuffle == 0)
	slist_shuffle(target->methods);
    }
  else
    {
      return 0;
    }

  if(target->tn == NULL && (target->tn=splaytree_insert(tree,target)) == NULL)
    {
      return -1;
    }

  if(target->mode == MODE_ICW)
    m = "-t icw";
  else if(target->mode == MODE_BLIND)
    m = slist_head_pop(target->methods);
  else if(target->mode == MODE_FP)
    m = "-t null -w 2 -O tcpts -O sack";
  if(m == NULL)
    return -1;

  if(tbit_app == SCAMPER_TBIT_APP_HTTP)
    {
      if(string_firstof_char(target->un.url, '\'') == NULL)
	string_concat3(cmd, sizeof(cmd), &off, "tbit -u '",
		       target->un.url, "'");
      else
	string_concat3(cmd, sizeof(cmd), &off, "tbit -u \"",
		       target->un.url, "\"");
      if(ttl != 0)
	string_concaf(cmd,sizeof(cmd),&off, " -T %d", ttl);
    }
  else if(tbit_app == SCAMPER_TBIT_APP_BGP)
    {
      string_concaf(cmd, sizeof(cmd), &off, "tbit -p bgp -T %d -b %d",
		    ttl == 0 ? 69 : ttl, target->un.asn);
    }
  else return -1;

  string_concaf(cmd, sizeof(cmd), &off, " %s -s %d %s", m, target->sport,
		scamper_addr_tostr(target->addr, addr, sizeof(addr)));
  if(scamper_inst_do(scamper_inst, cmd, target) == NULL)
    {
      fprintf(stderr, "could not send %s\n", cmd);
      return -1;
    }
  probing++;
  more--;

  print("p %d/%d, v %d : %s\n", probing, splaytree_count(tree),
	slist_count(list), cmd);

  return 0;
}

static int parse_list(char *str, void *param)
{
  char *ip, *url, *asn, *ptr = str;
  target_t *target;
  long lo;

  if(str[0] == '#' || str[0] == '\0')
    return 0;

  if(tbit_app == SCAMPER_TBIT_APP_HTTP)
    {
      /* position in the list */
      while(*ptr != ',' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	return -1;
      *ptr = '\0';
      ptr++;

      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	return -1;
      ptr++;

      /* size of the object */
      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	return -1;
      *ptr = '\0';
      ptr++;

      ip = ptr;
      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	return -1;
      *ptr = '\0';
      ptr++;

      url = ptr;

      /* skip over urls with ' in them */
      if(string_firstof_char(url, '\'') != NULL &&
	 string_firstof_char(url, '\"') != NULL)
	return 0;

      if((target = malloc_zero(sizeof(target_t))) == NULL ||
	 (target->un.url = strdup(url)) == NULL)
	return -1;
      target->addr  = scamper_addr_fromstr_unspec(ip);
      target->sport = 1050;
    }
  else if(tbit_app == SCAMPER_TBIT_APP_BGP)
    {
      /* ipaddress asn */
      ip = ptr;
      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      *ptr = '\0';
      ptr++;

      asn = ptr;
      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      *ptr = '\0';

      if(string_tolong(asn, &lo) != 0 || lo < 1 || lo > 65535)
	return -1;
      if((target = malloc_zero(sizeof(target_t))) == NULL)
	return -1;
      target->addr = scamper_addr_fromstr_unspec(ip);
      target->sport = 1050;
      target->un.asn = lo;
      target->mode = MODE_BLIND;
    }
  else return -1;

  if(splaytree_insert(tree, target) == NULL ||
     slist_tail_push(list, target) == NULL)
    return -1;

  return 0;
}

static int process_tbit(target_t *target, scamper_tbit_t *tbit)
{
  char buf[128];
  int rc = -1;

  target->sport++;

  if(target->mode == MODE_BLIND)
    {
      if(slist_count(target->methods) == 0)
	target->mode++;
    }
  else
    {
      target->mode++;
    }

  if(target->mode > MODE_LAST)
    goto completed;

  /* wait before we try again, by default a minute */
  timeval_add_s(&target->next, &now, wait_between);
  if((target->hn = heap_insert(heap, target)) == NULL)
    {
      fprintf(stderr, "process_tbit: could not insert into heap");
      goto done;
    }
  rc = 0;

 done:
  scamper_tbit_free(tbit);
  return rc;

 completed:
  if(comp != NULL)
    {
      fprintf(comp, "%s\n", scamper_addr_tostr(target->addr,buf,sizeof(buf)));
      fflush(comp);
    }
  target_free(target);
  scamper_tbit_free(tbit);
  return 0;
}

static void ctrlcb(scamper_inst_t *inst, uint8_t type, scamper_task_t *task,
		   const void *data, size_t len)
{
  target_t *target;
  uint16_t obj_type;
  void *obj_data;
  char buf[1024];

  gettimeofday_wrap(&now);

  if(type == SCAMPER_CTRL_TYPE_MORE)
    {
      more++;
      do_method();
    }
  else if(type == SCAMPER_CTRL_TYPE_DATA)
    {
      if(scamper_file_readbuf_add(decode_rb, data, len) != 0 ||
	 scamper_file_read(decode_sf, ffilter, &obj_type, &obj_data) != 0)
	{
	  fprintf(stderr, "%s: could not read\n", __func__);
	  goto err;
	}

      if(obj_data == NULL)
	return;

      /* rotate the file if necessary */
      if(outfile_obj >= limit)
	{
	  if(outfile != NULL)
	    {
	      scamper_file_close(outfile);
	      outfile = NULL;
	    }
	  outfile_obj = 0;
	  snprintf(buf, sizeof(buf), "%s_%02d.%s",
		   outfile_name, outfile_i++, outfile_type);
	  if((outfile = scamper_file_open(buf, 'w', outfile_type)) == NULL)
	    {
	      fprintf(stderr, "could not open outfile\n");
	      goto err;
	    }
	}

      if(scamper_file_write_obj(outfile, obj_type, obj_data) != 0)
	{
	  fprintf(stderr, "%s: could not write obj %d\n", __func__, obj_type);
	  goto err;
	}

      if(obj_type == SCAMPER_FILE_OBJ_CYCLE_START ||
	 obj_type == SCAMPER_FILE_OBJ_CYCLE_STOP)
	{
	  scamper_cycle_free(obj_data);
	  return;
	}

      probing--;
      target = scamper_task_param_get(task);

      if(obj_type == SCAMPER_FILE_OBJ_TBIT)
	{
	  outfile_obj++;
	  if(process_tbit(target, obj_data) != 0)
	    goto err;
	}
      else
	{
	  fprintf(stderr, "unexpected type %d\n", obj_type);
	  goto err;
	}
    }
  else if(type == SCAMPER_CTRL_TYPE_ERR)
    {
      goto err;
    }
  else if(type == SCAMPER_CTRL_TYPE_EOF)
    {
      scamper_inst_free(scamper_inst);
      scamper_inst = NULL;
    }
  else if(type == SCAMPER_CTRL_TYPE_FATAL)
    {
      print("fatal: %s", scamper_ctrl_strerror(scamper_ctrl));
      goto err;
    }
  return;

 err:
  error = 1;
  return;
}

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
  if((scamper_ctrl = scamper_ctrl_alloc(ctrlcb)) == NULL)
    {
      fprintf(stderr, "could not alloc scamper_ctrl\n");
      return -1;
    }

  if((scamper_inst = scamper_inst_inet(scamper_ctrl, NULL, NULL, port)) == NULL)
    {
      fprintf(stderr, "could not alloc port inst\n");
      return -1;
    }

  return 0;
}

static int do_files(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_TBIT,
		      SCAMPER_FILE_OBJ_CYCLE_START,
		      SCAMPER_FILE_OBJ_CYCLE_STOP
  };

  if((ffilter = scamper_file_filter_alloc(types, 3)) == NULL)
    {
      return -1;
    }

  if((decode_sf = scamper_file_opennull('r', "warts")) == NULL)
    {
      fprintf(stderr, "could not alloc decode_sf\n");
      return -1;
    }
  if((decode_rb = scamper_file_readbuf_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc decode_rb\n");
      return -1;
    }
  scamper_file_setreadfunc(decode_sf, decode_rb, scamper_file_readbuf_read);
  return 0;
}

static void cleanup(void)
{
  if(tree != NULL)
    {
      splaytree_free(tree, NULL);
      tree = NULL;
    }

  if(list != NULL)
    {
      slist_free(list);
      list = NULL;
    }

  if(heap != NULL)
    {
      heap_free(heap, NULL);
      heap = NULL;
    }

  if(ffilter != NULL)
    {
      scamper_file_filter_free(ffilter);
      ffilter = NULL;
    }

  if(decode_rb != NULL)
    {
      scamper_file_readbuf_free(decode_rb);
      decode_rb = NULL;
    }

  if(decode_sf != NULL)
    {
      scamper_file_close(decode_sf);
      decode_sf = NULL;
    }

  if(scamper_inst != NULL)
    {
      scamper_inst_free(scamper_inst);
      scamper_inst = NULL;
    }

  if(scamper_ctrl != NULL)
    {
      scamper_ctrl_free(scamper_ctrl);
      scamper_ctrl = NULL;
    }

  if(text != NULL)
    {
      fclose(text);
      text = NULL;
    }

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
  struct timeval tv, *tv_ptr;
  target_t *target;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  if((tree = splaytree_alloc(target_addr_cmp)) == NULL)
    return -1;
  if((heap = heap_alloc(target_next_cmp)) == NULL)
    return -1;
  if((list = slist_alloc()) == NULL)
    return -1;
  assert(addressfile != NULL);
  if(file_lines(addressfile, parse_list, NULL) != 0)
    return -1;
  splaytree_empty(tree, NULL);

  if((options & OPT_RANDOM) != 0)
    {
      random_seed();
      if(noshuffle == 0)
	slist_shuffle(list);
    }

  if(do_scamperconnect() != 0)
    return -1;
  if(do_files() != 0)
    return -1;

  while(scamper_ctrl_isdone(scamper_ctrl) == 0)
    {
      /*
       * need to set a timeout on select if scamper's processing window is
       * not full and there is a trace in the waiting queue.
       */
      tv_ptr = NULL;
      if(more > 0)
	{
	  gettimeofday_wrap(&now);

	  /*
	   * if there is something ready to probe now, then try and
	   * do it.
	   */
	  if(slist_count(list) > 0 ||
	     ((target = heap_head_item(heap)) != NULL &&
	      timeval_cmp(&target->next, &now) <= 0))
	    {
	      if(do_method() != 0)
		{
		  print("do_method did not return 0");
		  return -1;
		}
	    }

	  /*
	   * if there is something ready to probe now, then try and
	   * do it.
	   */
	  if(more > 0 && (target = heap_head_item(heap)) != NULL)
	    {
	      if(timeval_cmp(&now, &target->next) <= 0)
		timeval_diff_tv(&tv, &now, &target->next);
	      else
		memset(&tv, 0, sizeof(tv));
	      tv_ptr = &tv;
	    }
	}

      if(splaytree_count(tree) == 0 && slist_count(list) == 0 &&
	 scamper_inst != NULL && scamper_inst_isdone(scamper_inst) == 0)
	scamper_inst_done(scamper_inst);

      scamper_ctrl_wait(scamper_ctrl, tv_ptr);

      if(error != 0)
	return -1;
    }

  return 0;
}

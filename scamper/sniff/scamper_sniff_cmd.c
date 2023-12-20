#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_sniff.h"
#include "scamper_sniff_int.h"
#include "scamper_sniff_cmd.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "utils.h"

/* Address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define SNIFF_OPT_LIMIT_PKTC   1
#define SNIFF_OPT_LIMIT_TIME   2
#define SNIFF_OPT_SRCADDR      3
#define SNIFF_OPT_USERID       4

static const scamper_option_in_t opts[] = {
  {'c', NULL, SNIFF_OPT_LIMIT_PKTC, SCAMPER_OPTION_TYPE_NUM},
  {'G', NULL, SNIFF_OPT_LIMIT_TIME, SCAMPER_OPTION_TYPE_STR},
  {'S', NULL, SNIFF_OPT_SRCADDR,    SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, SNIFF_OPT_USERID,     SCAMPER_OPTION_TYPE_NUM},
};

static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_sniff_usage(void)
{
  return "sniff [-c limit-pktc] [-G limit-time] [-S ipaddr] [-U userid] <expression>\n";
}

static int sniff_arg_param_validate(int optid, char *param, long long *out)
{
  struct timeval tv;
  long tmp = 0;

  switch(optid)
    {
    case SNIFF_OPT_SRCADDR:
      break;

    case SNIFF_OPT_LIMIT_PKTC:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 5000)
	goto err;
      break;

    case SNIFF_OPT_LIMIT_TIME:
      if(timeval_fromstr(&tv, param, 1000000) != 0 || tv.tv_usec != 0 ||
	 timeval_cmp_lt(&tv, 1, 0) || timeval_cmp_gt(&tv, 1200, 0))
	goto err;
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case SNIFF_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	goto err;
      break;

    default:
      return -1;
    }

  if(out != NULL)
    *out = (long long)tmp;
  return 0;

 err:
  return -1;
}

int scamper_do_sniff_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  sniff_arg_param_validate);
}

void *scamper_do_sniff_alloc(char *str, uint32_t *id)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_sniff_t *sniff = NULL;
  struct timeval limit_time;
  uint32_t userid = 0;
  uint32_t limit_pktc = 100;
  long icmpid = -1;
  char *expr = NULL;
  char *src = NULL;
  long long tmp = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &expr) != 0)
    goto err;

  if(expr == NULL)
    goto err;

  if(strncasecmp(expr, "icmp[icmpid] == ", 16) != 0 ||
     string_isnumber(expr+16) == 0 ||
     string_tolong(expr+16, &icmpid) != 0 ||
     icmpid < 0 || icmpid > 65535)
    {
      scamper_debug(__func__, "icmp[icmpid] not supplied");
      goto err;
    }

  /* default time limit of 60 seconds */
  limit_time.tv_sec = 60; limit_time.tv_usec = 0;

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 sniff_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case SNIFF_OPT_SRCADDR:
	  src = opt->str;
	  break;

	case SNIFF_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case SNIFF_OPT_LIMIT_TIME:
	  limit_time.tv_sec = tmp / 1000000;
	  limit_time.tv_usec = tmp % 1000000;
	  break;

	case SNIFF_OPT_LIMIT_PKTC:
	  limit_pktc = (uint32_t)tmp;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if(src == NULL)
    {
      printerror(__func__, "missing -S parameter");
      goto err;
    }

  if((sniff = scamper_sniff_alloc()) == NULL)
    goto err;

  if((sniff->src = scamper_addrcache_resolve(addrcache,AF_UNSPEC,src)) == NULL)
    {
      printerror(__func__, "could not resolve %s", src);
      goto err;
    }

  sniff->limit_pktc = limit_pktc;
  sniff->userid     = *id = userid;
  sniff->icmpid     = (uint16_t)icmpid;
  timeval_cpy(&sniff->limit_time, &limit_time);

  return sniff;

 err:
  if(sniff != NULL) scamper_sniff_free(sniff);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

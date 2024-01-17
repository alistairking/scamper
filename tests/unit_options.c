/*
 * unit_options : unit tests for options module
 *
 * $Id: unit_options.c,v 1.2 2023/12/02 09:21:16 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023 Matthew Luckie
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

#include "scamper_options.h"
#include "utils.h"

typedef struct sc_test
{
  char                 *str;
  scamper_option_in_t   opts[5];
  int                   optc;
  int                 (*func)(int rc, scamper_option_out_t *opt, char *endptr);
} sc_test_t;

#define OPT_c 1
#define OPT_d 2

static int isbad(int c, scamper_option_out_t *opts, char *endptr)
{
  if(c == 0)
    return -1;
  return 0;
}

static int c_1_foo(int c, scamper_option_out_t *opts, char *endptr)
{
  uint32_t bits = 0;
  scamper_option_out_t *opt;
  if(c != 0)
    return -1;
  for(opt = opts; opt != NULL; opt = opt->next)
    {
      bits |= (1 << opt->id);
      switch(opt->id)
	{
	case OPT_c:
	  if(strcmp(opt->str, "1") != 0)
	    return -1;
	  break;
	}
    }
  if(endptr == NULL || strcmp(endptr, "foo") != 0)
    return -1;
  if(bits != (1 << OPT_c))
    return -1;
  return 0;
}

static int d_bar_baz(int c, scamper_option_out_t *opts, char *endptr)
{
  uint32_t bits = 0;
  scamper_option_out_t *opt;
  if(c != 0)
    return -1;
  for(opt = opts; opt != NULL; opt = opt->next)
    {
      bits |= (1 << opt->id);
      switch(opt->id)
	{
	case OPT_d:
	  if(strcmp(opt->str, "bar") != 0)
	    return -1;
	  break;
	}
    }
  if(endptr == NULL || strcmp(endptr, "baz") != 0)
    return -1;
  if(bits != (1 << OPT_d))
    return -1;
  return 0;
}

static int d_zz_zz_bar(int c, scamper_option_out_t *opts, char *endptr)
{
  uint32_t bits = 0;
  scamper_option_out_t *opt;
  if(c != 0)
    return -1;
  for(opt = opts; opt != NULL; opt = opt->next)
    {
      bits |= (1 << opt->id);
      switch(opt->id)
	{
	case OPT_d:
	  if(strcmp(opt->str, "zz'zz") != 0)
	    {
	      fprintf(stderr, "%s: OPT_d %s expected zz'zz\n",
		      __func__, opt->str);
	      return -1;
	    }
	  break;
	}
    }
  if(endptr == NULL || strcmp(endptr, "bar") != 0)
    return -1;
  if(bits != (1 << OPT_d))
    return -1;
  return 0;
}

static int d_zz___zz_foo(int c, scamper_option_out_t *opts, char *endptr)
{
  uint32_t bits = 0;
  scamper_option_out_t *opt;
  if(c != 0)
    return -1;
  for(opt = opts; opt != NULL; opt = opt->next)
    {
      bits |= (1 << opt->id);
      switch(opt->id)
	{
	case OPT_d:
	  if(strcmp(opt->str, "zz'\\'zz") != 0)
	    {
	      fprintf(stderr, "%s: OPT_d %s expected zz'\\'zz\n",
		      __func__, opt->str);
	      return -1;
	    }
	  break;
	}
    }
  if(endptr == NULL || strcmp(endptr, "foo") != 0)
    return -1;
  if(bits != (1 << OPT_d))
    return -1;
  return 0;
}

static int c_15(int c, scamper_option_out_t *opts, char *endptr)
{
  uint32_t bits = 0;
  scamper_option_out_t *opt;
  if(c != 0)
    return -1;
  for(opt = opts; opt != NULL; opt = opt->next)
    {
      bits |= (1 << opt->id);
      switch(opt->id)
	{
	case OPT_c:
	  if(strcmp(opt->str, "15") != 0)
	    return -1;
	  break;
	}
    }
  if(endptr != NULL)
    return -1;
  if(bits != (1 << OPT_c))
    return -1;
  return 0;
}

static int check(char *str,
		 scamper_option_in_t *ins, int inc,
		 int (*func)(int c, scamper_option_out_t *opt, char *endptr))
{
  scamper_option_out_t *opts_out = NULL;
  char *endptr, *dup = NULL;
  int rc = -1;
  int x;

  if((dup = strdup(str)) == NULL)
    goto done;
  x = scamper_options_parse(dup, ins, inc, &opts_out, &endptr);
  if(func(x, opts_out, endptr) != 0)
    goto done;
  rc = 0;

 done:
  if(dup != NULL) free(dup);
  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"-c 1 foo",
     {{'c', NULL, OPT_c, SCAMPER_OPTION_TYPE_NUM},
      {'d', NULL, OPT_d, SCAMPER_OPTION_TYPE_NULL},
     },
     2,
     c_1_foo},
    {"-d 'bar' baz",
     {{'c', NULL, OPT_c, SCAMPER_OPTION_TYPE_NUM},
      {'d', NULL, OPT_d, SCAMPER_OPTION_TYPE_STR},
     },
     2,
     d_bar_baz},
    {"-d 'zz\\'zz' bar", /* zz'zz */
     {{'c', NULL, OPT_c, SCAMPER_OPTION_TYPE_NUM},
      {'d', NULL, OPT_d, SCAMPER_OPTION_TYPE_STR},
     },
     2,
     d_zz_zz_bar},
    {"-d zz'zz bar", /* zz'zz */
     {{'c', NULL, OPT_c, SCAMPER_OPTION_TYPE_NUM},
      {'d', NULL, OPT_d, SCAMPER_OPTION_TYPE_STR},
     },
     2,
     d_zz_zz_bar},
    {"-d 'zz\\'\\\\\\'zz' foo", /* zz'\'zz */
     {{'c', NULL, OPT_c, SCAMPER_OPTION_TYPE_NUM},
      {'d', NULL, OPT_d, SCAMPER_OPTION_TYPE_STR},
     },
     2,
     d_zz___zz_foo},
    {"-c 15",
     {{'c', NULL, OPT_c, SCAMPER_OPTION_TYPE_NUM},
      {'d', NULL, OPT_d, SCAMPER_OPTION_TYPE_STR},
     },
     2,
     c_15},
    {"-c 15a",
     {{'c', NULL, OPT_c, SCAMPER_OPTION_TYPE_NUM},
      {'d', NULL, OPT_d, SCAMPER_OPTION_TYPE_STR},
     },
     2,
     isbad},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);

  for(i=0; i<testc; i++)
    if(check(tests[i].str, tests[i].opts, tests[i].optc, tests[i].func) != 0)
      break;
  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}

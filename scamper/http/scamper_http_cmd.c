/*
 * scamper_http_cmd.c
 *
 * $Id: scamper_http_cmd.c,v 1.8 2024/05/02 02:33:38 mjl Exp $
 *
 * Copyright (C) 2023-2024 The Regents of the University of California
 *
 * Author: Matthew Luckie
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

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_http.h"
#include "scamper_http_int.h"
#include "scamper_http_cmd.h"
#include "scamper_options.h"
#include "mjl_list.h"
#include "utils.h"

/* options that http supports */
#define HTTP_OPT_URL     1
#define HTTP_OPT_USERID  2
#define HTTP_OPT_HEADER  3
#define HTTP_OPT_OPTION  4
#define HTTP_OPT_MAXTIME 5

static const scamper_option_in_t opts[] = {
  {'H', NULL, HTTP_OPT_HEADER,  SCAMPER_OPTION_TYPE_STR},
  {'m', NULL, HTTP_OPT_MAXTIME, SCAMPER_OPTION_TYPE_STR},
  {'O', NULL, HTTP_OPT_OPTION,  SCAMPER_OPTION_TYPE_STR},
  {'u', NULL, HTTP_OPT_URL,     SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, HTTP_OPT_USERID,  SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

/* Address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

const char *scamper_do_http_usage(void)
{
  return "http [-H header] [-m max-time] [-O option] [-u url] [-U userid]";
}

static int http_header_validate(const char *header)
{
  const char *ptr = header;

  /* field-name has ascii characters between 33-126 */
  while(*ptr != ':')
    {
      if(*ptr < 33 || *ptr > 126)
	return -1;
      ptr++;
    }

  /* skip over colon, and any OWS until the field-body */
  ptr++;
  while(*ptr == ' ')
    ptr++;
  if(*ptr == '\0')
    return -1;

  /* check that the field-body is well formed */
  while(*ptr != '\0')
    {
      if(isprint((unsigned char)*ptr) == 0)
	return -1;
      ptr++;
    }

  /* do not allow Host: to be over-ridden */
  if(strncasecmp(header, "host:", 5) == 0)
    return -1;

  return 0;
}

static int http_arg_param_validate(int optid, char *param, long long *out,
				   char *errbuf, size_t errlen)
{
  struct timeval tv;
  long long tmp = 0;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case HTTP_OPT_HEADER:
      if(http_header_validate(param) != 0)
	{
	  snprintf(errbuf, errlen, "invalid HTTP header");
	  goto err;
	}
      break;

    case HTTP_OPT_MAXTIME:
      if(timeval_fromstr(&tv, param, 1000000) != 0)
	{
	  snprintf(errbuf, errlen, "malformed maximum runtime");
	  goto err;
	}
      if(timeval_cmp_lt(&tv, 1, 0) || timeval_cmp_gt(&tv, 60, 0))
	{
	  snprintf(errbuf, errlen, "maximum runtime must be within 1s - 60s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case HTTP_OPT_OPTION:
      if(strcasecmp(param, "insecure") == 0)
	tmp = SCAMPER_HTTP_FLAG_INSECURE;
      else
	{
	  snprintf(errbuf, errlen, "unknown option");
	  goto err;
	}
      break;

    case HTTP_OPT_URL:
      break;

    case HTTP_OPT_USERID:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < 0 || tmp > UINT32_MAX)
	{
	  snprintf(errbuf, errlen, "userid must be within %u - %u", 0,
		   UINT32_MAX);
	  goto err;
	}
      break;

    default:
      goto err;
    }

  /* valid parameter */
  if(out != NULL)
    *out = tmp;
  return 0;

 err:
  assert(errbuf[0] != '\0');
  return -1;
}

int scamper_do_http_arg_validate(int argc, char *argv[], int *stop,
				 char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, http_arg_param_validate);
}

void *scamper_do_http_alloc(char *str, char *errbuf, size_t errlen)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_http_t *http = NULL;
  slist_t *headers = NULL;
  char *url = NULL;
  uint32_t userid = 0;
  char *addr = NULL, *header;
  long long tmp = 0;
  uint16_t dport;
  uint8_t h;
  char *scheme = NULL, *host = NULL, *file = NULL;
  uint32_t flags = 0;
  struct timeval maxtime;
  char buf[256];

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  /* Parse the options */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      snprintf(errbuf, errlen, "could not parse http command");
      goto err;
    }

  /* If there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      snprintf(errbuf, errlen, "expected address to connect to");
      goto err;
    }

  maxtime.tv_sec = 60;
  maxtime.tv_usec = 0;

  /* Parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 http_arg_param_validate(opt->id, opt->str, &tmp,
				 buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id), buf);
	  goto err;
	}

      switch(opt->id)
	{
	case HTTP_OPT_HEADER:
	  if((headers == NULL && (headers = slist_alloc()) == NULL) ||
	     slist_tail_push(headers, opt->str) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not store header");
	      goto err;
	    }
	  break;

	case HTTP_OPT_MAXTIME:
	  maxtime.tv_sec = tmp / 1000000;
	  maxtime.tv_usec = tmp % 1000000;
	  break;

	case HTTP_OPT_OPTION:
	  flags |= (uint32_t)tmp;
	  break;

	case HTTP_OPT_URL:
	  url = opt->str;
	  break;

	case HTTP_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if(url == NULL)
    {
      snprintf(errbuf, errlen, "missing URL parameter");
      goto err;
    }
  if(url_parse(url, &dport, &scheme, &host, &file) != 0)
    {
      snprintf(errbuf, errlen, "could not parse URL");
      goto err;
    }

  if((http = scamper_http_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc http");
      goto err;
    }

  if((http->dst = scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid destination address");
      goto err;
    }

  if(strcasecmp(scheme, "http") == 0)
    {
      http->type = SCAMPER_HTTP_TYPE_HTTP;
      http->dport = (dport == 0 ? 80 : dport);
    }
  else if(strcasecmp(scheme, "https") == 0)
    {
#ifdef BUILDING_SCAMPER
#ifndef HAVE_OPENSSL
      snprintf(errbuf, errlen, "scamper not built with openssl");
      goto err;
#else
      if(scamper_option_notls() != 0)
	{
	  snprintf(errbuf, errlen, "scamper run with -O notls");
	  goto err;
	}
#endif /* HAVE_OPENSSL */
#endif /* BUILDING_SCAMPER */
      http->type = SCAMPER_HTTP_TYPE_HTTPS;
      http->dport = (dport == 0 ? 443 : dport);
    }
  else
    {
      snprintf(errbuf, errlen, "unhandled HTTP scheme");
      goto err;
    }
  free(scheme); scheme = NULL;

  if(headers != NULL)
    {
      assert(slist_count(headers) > 0);
      if(slist_count(headers) > 255)
	{
	  snprintf(errbuf, errlen, "cannot provide more than 255 headers");
	  goto err;
	}
      http->headerc = slist_count(headers);
      if((http->headers = malloc_zero(http->headerc * sizeof(char *)))==NULL)
	{
	  snprintf(errbuf, errlen, "could not alloc headers");
	  goto err;
	}
      h = 0;
      while((header = slist_head_pop(headers)) != NULL)
	{
	  if((http->headers[h] = strdup(header)) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not duplicate header %d", h);
	      goto err;
	    }
	  h++;
	}
      slist_free(headers); headers = NULL;
    }

  http->flags = flags;
  http->userid = userid;
  timeval_cpy(&http->maxtime, &maxtime);
  http->host = host; host = NULL;
  if(file != NULL)
    {
      http->file = file;
      file = NULL;
    }
  else if((http->file = strdup("/")) == NULL)
    {
      snprintf(errbuf, errlen, "could not set default file to fetch");
      goto err;
    }

  return http;

 err:
  assert(errbuf[0] != '\0');
  if(headers != NULL) slist_free(headers);
  if(http != NULL) scamper_http_free(http);
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(scheme != NULL) free(scheme);
  if(host != NULL) free(host);
  if(file != NULL) free(file);
  return NULL;
}

/*
 * scamper_config.c
 *
 * $Id: scamper_config.c,v 1.5 2025/05/03 01:44:03 mjl Exp $
 *
 * Copyright (C) 2025 Matthew Luckie
 *
 * Authors: Matthew Luckie
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
#include "scamper_config.h"
#include "scamper_debug.h"

#include "utils.h"

scamper_config_t *config = NULL;

typedef struct conf_cb
{
  const char *key;
  size_t      len;
  int        (*cb)(const char *key, char *val, scamper_config_t *cf);
} conf_cb_t;

static int check_enable(const char *key_in, const char *key, const char *val,
			uint8_t *cf_val)
{
  long lo;

  if(strcasecmp(key, "enable") == 0)
    {
      if(string_tolong(val, &lo) != 0 || lo < 0 || lo > 1)
	{
	  printerror_msg(__func__, "%s: expected 0 or 1", key_in);
	  return -1;
	}
      *cf_val = (uint8_t)lo;
      return 1;
    }

  return 0;
}

static int trace_cb(const char *key_in, char *val, scamper_config_t *cf)
{
  const char *key = key_in + 6;
  int rc;
  rc = check_enable(key_in, key, val, &cf->trace_enable);
  return rc < 0 ? rc : 0;
}

static int ping_cb(const char *key_in, char *val, scamper_config_t *cf)
{
  const char *key = key_in + 5;
  int rc;
  rc = check_enable(key_in, key, val, &cf->ping_enable);
  return rc < 0 ? rc : 0;
}

static int dealias_cb(const char *key_in, char *val, scamper_config_t *cf)
{
  const char *key = key_in + 8;
  int rc;
  rc = check_enable(key_in, key, val, &cf->dealias_enable);
  return rc < 0 ? rc : 0;
}

static int tracelb_cb(const char *key_in, char *val, scamper_config_t *cf)
{
  const char *key = key_in + 8;
  int rc;
  rc = check_enable(key_in, key, val, &cf->tracelb_enable);
  return rc < 0 ? rc : 0;
}

static int sting_cb(const char *key_in, char *val, scamper_config_t *cf)
{
  const char *key = key_in + 6;
  int rc;
  rc = check_enable(key_in, key, val, &cf->sting_enable);
  return rc < 0 ? rc : 0;
}

static int tbit_cb(const char *key_in, char *val, scamper_config_t *cf)
{
  const char *key = key_in + 5;
  int rc;
  rc = check_enable(key_in, key, val, &cf->tbit_enable);
  return rc < 0 ? rc : 0;
}

static int udpprobe_cb(const char *key_in, char *val, scamper_config_t *cf)
{
  const char *key = key_in + 9;
  int rc;
  rc = check_enable(key_in, key, val, &cf->udpprobe_enable);
  return rc < 0 ? rc : 0;
}

static int http_cb(const char *key_in, char *val, scamper_config_t *cf)
{
  const char *key = key_in + 5;
  int rc;
  rc = check_enable(key_in, key, val, &cf->http_enable);
  return rc < 0 ? rc : 0;
}

static int host_cb(const char *key_in, char *val, scamper_config_t *cf)
{
  const char *key = key_in + 5;
  int rc;
  rc = check_enable(key_in, key, val, &cf->host_enable);
  return rc < 0 ? rc : 0;
}

static int config_line(char *line, void *param)
{
  conf_cb_t cbs[] = {
    {"dealias.",  8, dealias_cb},
    {"host.",     5, host_cb},
    {"http.",     5, http_cb},
    {"ping.",     5, ping_cb},
    {"sting.",    6, sting_cb},
    {"tbit.",     5, tbit_cb},
    {"trace.",    6, trace_cb},
    {"tracelb.",  8, tracelb_cb},
    {"udpprobe.", 9, udpprobe_cb},
  };
  size_t i, cbc = sizeof(cbs) / sizeof(conf_cb_t);
  scamper_config_t *cf = param;
  char *key = NULL, *val = NULL, *ptr;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  key = line;

  /* find the '=' */
  ptr = line;
  while(*ptr != '\0')
    {
      if(*ptr == '=')
	break;
      ptr++;
    }
  if(*ptr == '\0')
    return -1;

  /*
   * break the string where the '=' is, the value starts after the '='
   * and any spaces
   */
  *ptr = '\0';
  val = ptr + 1;
  while(*val != '\0')
    {
      if(isspace((unsigned char)*val) == 0)
	break;
      val++;
    }
  if(*val == '\0')
    return -1;

  /*
   * go backwards over any whitespace after the key, and then null
   * terminate the key at the last whitespace
   */
  ptr--;
  while(ptr > key)
    {
      if(isspace((unsigned char)*ptr) == 0)
	break;
      *ptr = '\0';
      ptr--;
    }
  if(*key == '\0')
    return -1;

  for(i=0; i<cbc; i++)
    {
      if(strncasecmp(key, cbs[i].key, cbs[i].len) == 0)
	{
	  if(cbs[i].cb(key, val, cf) != 0)
	    return -1;
	  break;
	}
    }

  return 0;
}

static void config_free(scamper_config_t *cf)
{
  free(cf);
  return;
}

static scamper_config_t *config_dup(const scamper_config_t *cf)
{
  return memdup(cf, sizeof(scamper_config_t));
}

int scamper_config_read(const char *filename)
{
  scamper_config_t *newconfig = NULL;

  if((newconfig = config_dup(config)) == NULL ||
     file_lines(filename, config_line, newconfig) != 0)
    goto err;

  config_free(config);
  config = newconfig;

  return 0;

 err:
  if(newconfig != NULL) config_free(newconfig);
  return -1;
}

void scamper_config_cleanup(void)
{
  if(config != NULL)
    config_free(config);
  return;
}

int scamper_config_init(const char *filename)
{
  scamper_config_t *cf = NULL;

  if((cf = malloc_zero(sizeof(scamper_config_t))) == NULL)
    goto err;

  cf->trace_enable = 1;
  cf->ping_enable = 1;
  cf->dealias_enable = 1;
  cf->tracelb_enable = 1;
  cf->sting_enable = 1;
  cf->tbit_enable = 1;
  cf->udpprobe_enable = 1;
  cf->http_enable = 1;
  cf->host_enable = 1;

  if(filename != NULL && file_lines(filename, config_line, cf) != 0)
    goto err;

  config = cf;
  return 0;

 err:
  if(cf != NULL) config_free(config);
  return -1;
}

/*
 * scamper_dealias_json.c
 *
 * Copyright (c) 2013      Matthew Luckie
 * Copyright (c) 2013-2014 The Regents of the University of California
 * Copyright (c) 2022-2025 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_dealias_json.c,v 1.30 2025/05/03 21:22:34 mjl Exp $
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
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_dealias.h"
#include "scamper_dealias_int.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_dealias_json.h"

#include "utils.h"

static char *dealias_flags_encode(char *buf, size_t len, uint8_t flags,
				  const char **f2s, size_t f2sc)
{
  size_t i, off = 0;
  int f = 0;
  uint8_t u8;

  string_concat(buf, len, &off, ", \"flags\":[");
  for(i=0; i<8; i++)
    {
      if((u8 = flags & (0x1 << i)) == 0) continue;
      if(f > 0) string_concatc(buf, len, &off, ',');
      if(i < f2sc)
	string_concat3(buf, len, &off, "\"", f2s[i], "\"");
      else
	string_concat_u8(buf, len, &off, NULL, u8);
      f++;
    }
  string_concatc(buf, len, &off, ']');

  return buf;
}

static char *dealias_header_tostr(const scamper_dealias_t *dealias)
{
  static const char *pf_flags[] = {"nobs", "csa"};
  static const char *rg_flags[] = {"nobs"};
  static const char *ally_flags[] = {"nobs"};
  scamper_dealias_mercator_t *mc;
  scamper_dealias_ally_t *ally;
  scamper_dealias_radargun_t *rg;
  scamper_dealias_prefixscan_t *pf;
  scamper_dealias_bump_t *bump;
  char buf[512], tmp[64];
  size_t off = 0;
  uint16_t u16;
  int x;

  string_concat3(buf, sizeof(buf), &off,
		 "{\"type\":\"dealias\",\"version\":\"0.2\",\"method\":\"",
		 scamper_dealias_method_tostr(dealias->method,tmp,sizeof(tmp)),
		 "\"");
  string_concat_u32(buf, sizeof(buf), &off, ", \"userid\":", dealias->userid);
  scamper_dealias_result_tostr(dealias->result, tmp, sizeof(tmp));
  string_concat2(buf, sizeof(buf), &off, ", \"result\":\"", tmp);
  string_concat_u32(buf, sizeof(buf), &off, "\", \"start\":{\"sec\":",
		    (uint32_t)dealias->start.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)dealias->start.tv_usec);
  string_concatc(buf, sizeof(buf), &off, '}');

  if(SCAMPER_DEALIAS_METHOD_IS_MERCATOR(dealias) &&
     (mc = dealias->data) != NULL)
    {
      string_concat_u8(buf, sizeof(buf), &off, ", \"attempts\":",
		       mc->attempts);
      string_concat_u32(buf, sizeof(buf), &off, ", \"wait_timeout\":",
			(uint32_t)mc->wait_timeout.tv_sec);
    }
  else if(SCAMPER_DEALIAS_METHOD_IS_ALLY(dealias) &&
	  (ally = dealias->data) != NULL)
    {
      u16 = (ally->wait_probe.tv_sec * 1000)+(ally->wait_probe.tv_usec / 1000);
      string_concat_u16(buf, sizeof(buf), &off, ", \"wait_probe\":", u16);
      string_concat_u32(buf, sizeof(buf), &off, ", \"wait_timeout\":",
			(uint32_t)ally->wait_timeout.tv_sec);
      string_concat_u8(buf, sizeof(buf), &off, ", \"attempts\":",
		       ally->attempts);
      string_concat_u16(buf, sizeof(buf), &off, ", \"fudge\":", ally->fudge);
      if(ally->flags != 0)
	{
	  dealias_flags_encode(tmp, sizeof(tmp), ally->flags, ally_flags,
			       sizeof(ally_flags)/sizeof(char *));
	  string_concat(buf, sizeof(buf), &off, tmp);
	}
    }
  else if(SCAMPER_DEALIAS_METHOD_IS_RADARGUN(dealias) &&
	  (rg = dealias->data) != NULL)
    {
      string_concat_u16(buf, sizeof(buf), &off, ", \"attempts\":", rg->rounds);
      u16 = (rg->wait_probe.tv_sec * 1000) + (rg->wait_probe.tv_usec / 1000);
      string_concat_u16(buf, sizeof(buf), &off, ", \"wait_probe\":", u16);
      u16 = (rg->wait_round.tv_sec * 1000) + (rg->wait_round.tv_usec / 1000);
      string_concat_u16(buf, sizeof(buf), &off, ", \"wait_round\":", u16);
      string_concat_u32(buf, sizeof(buf), &off, ", \"wait_timeout\":",
			(uint32_t)rg->wait_timeout.tv_sec);
      if(rg->flags != 0)
	string_concat(buf, sizeof(buf), &off,
		      dealias_flags_encode(tmp,sizeof(tmp),rg->flags,rg_flags,
					   sizeof(rg_flags)/sizeof(char *)));
    }
  else if(SCAMPER_DEALIAS_METHOD_IS_PREFIXSCAN(dealias) &&
	  (pf = dealias->data) != NULL)
    {
      if(pf->a != NULL)
	string_concat3(buf, sizeof(buf), &off, ", \"a\":\"",
		       scamper_addr_tostr(pf->a, tmp, sizeof(tmp)), "\"");
      if(pf->b != NULL)
	{
	  scamper_addr_tostr(pf->b, tmp, sizeof(tmp));
	  string_concat2(buf, sizeof(buf), &off, ", \"b\":\"", tmp);
	  string_concat_u8(buf, sizeof(buf), &off, "/", pf->prefix);
	  string_concatc(buf, sizeof(buf), &off, '"');
	}
      if(pf->b != NULL && pf->ab != NULL &&
	 (x = scamper_addr_prefixhosts(pf->b, pf->ab)) >= 0)
	{
	  string_concat2(buf, sizeof(buf), &off, ", \"ab\":\"",
			 scamper_addr_tostr(pf->ab, tmp, sizeof(tmp)));
	  string_concat_u8(buf, sizeof(buf), &off, "/", (uint8_t)x);
	  string_concatc(buf, sizeof(buf), &off, '"');
	}
      if(pf->xc > 0 && pf->xs != NULL)
	{
	  x = 0;
	  string_concat(buf, sizeof(buf), &off, ", \"xs\":[");
	  for(u16=0; u16 < pf->xc; u16++)
	    {
	      if(pf->xs[u16] == NULL)
		continue;
	      scamper_addr_tostr(pf->xs[u16], tmp, sizeof(tmp));
	      if(x > 0) string_concatc(buf, sizeof(buf), &off, ',');
	      string_concat3(buf, sizeof(buf), &off, "\"", tmp, "\"");
	      x++;
	    }
	  string_concatc(buf, sizeof(buf), &off, ']');
	}
      string_concat_u8(buf,sizeof(buf),&off, ", \"attempts\":", pf->attempts);
      string_concat_u8(buf, sizeof(buf), &off, ", \"replyc\":", pf->replyc);
      string_concat_u16(buf, sizeof(buf), &off, ", \"fudge\":", pf->fudge);
      u16 = (pf->wait_probe.tv_sec * 1000) + (pf->wait_probe.tv_usec / 1000);
      string_concat_u16(buf, sizeof(buf), &off, ", \"wait_probe\":", u16);
      string_concat_u32(buf, sizeof(buf), &off, ", \"wait_timeout\":",
			(uint32_t)pf->wait_timeout.tv_sec);
      if(pf->flags != 0)
	string_concat(buf, sizeof(buf), &off,
		      dealias_flags_encode(tmp,sizeof(tmp),pf->flags,pf_flags,
					   sizeof(pf_flags)/sizeof(char *)));
    }
  else if(SCAMPER_DEALIAS_METHOD_IS_BUMP(dealias) &&
	  (bump = dealias->data) != NULL)
    {
      u16 = (bump->wait_probe.tv_sec * 1000)+(bump->wait_probe.tv_usec / 1000);
      string_concat_u16(buf, sizeof(buf), &off, ", \"wait_probe\":", u16);
      string_concat_u16(buf, sizeof(buf), &off, ", \"bump_limit\":",
			bump->bump_limit);
      string_concat_u8(buf, sizeof(buf), &off, ", \"attempts\":",
		       bump->attempts);
    }

  return strdup(buf);
}

static char *dealias_probedef_tostr(const scamper_dealias_probedef_t *def)
{
  char buf[256], tmp[64];
  size_t off = 0;
  string_concat_u32(buf, sizeof(buf), &off, "{\"id\":", def->id);
  if(def->src != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"src\":\"",
		   scamper_addr_tostr(def->src, tmp, sizeof(tmp)), "\"");
  if(def->dst != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"dst\":\"",
		   scamper_addr_tostr(def->dst, tmp, sizeof(tmp)), "\"");
  string_concat_u8(buf, sizeof(buf), &off, ", \"ttl\":", def->ttl);
  string_concat_u16(buf, sizeof(buf), &off, ", \"size\":", def->size);
  string_concat3(buf, sizeof(buf), &off, ", \"method\":\"",
		 scamper_dealias_probedef_method_tostr(def, tmp, sizeof(tmp)),
		 "\"");
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      string_concat_u16(buf, sizeof(buf), &off, ", \"icmp_id\":",
			def->un.icmp.id);
      string_concat_u16(buf, sizeof(buf), &off, ", \"icmp_csum\":",
			def->un.icmp.csum);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      string_concat_u16(buf, sizeof(buf), &off, ", \"udp_sport\":",
			def->un.udp.sport);
      string_concat_u16(buf, sizeof(buf), &off, ", \"udp_dport\":",
			def->un.udp.dport);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      string_concat_u16(buf, sizeof(buf), &off, ", \"tcp_sport\":",
			def->un.tcp.sport);
      string_concat_u16(buf, sizeof(buf), &off, ", \"tcp_dport\":",
			def->un.tcp.dport);
      string_concat_u8(buf, sizeof(buf), &off, ", \"tcp_flags\":",
		       def->un.tcp.flags);
    }
  if(def->mtu > 0)
    string_concat_u16(buf, sizeof(buf), &off, ", \"mtu\":", def->mtu);
  string_concatc(buf, sizeof(buf), &off, '}');
  return strdup(buf);
}

static int dealias_probedefs_get(const scamper_dealias_t *dealias,
				 scamper_dealias_probedef_t ***defs, int *defc)
{
  scamper_dealias_mercator_t *mc;
  scamper_dealias_ally_t *ally;
  scamper_dealias_radargun_t *rg;
  scamper_dealias_prefixscan_t *pf;
  scamper_dealias_bump_t *bump;

  switch(dealias->method)
    {
    case SCAMPER_DEALIAS_METHOD_MERCATOR:
      mc = dealias->data;
      *defs = &mc->probedef; *defc = 1;
      break;

    case SCAMPER_DEALIAS_METHOD_ALLY:
      ally = dealias->data;
      *defs = ally->probedefs; *defc = 2;
      break;

    case SCAMPER_DEALIAS_METHOD_RADARGUN:
      rg = dealias->data;
      *defs = rg->probedefs; *defc = rg->probedefc;
      break;

    case SCAMPER_DEALIAS_METHOD_PREFIXSCAN:
      pf = dealias->data;
      *defs = pf->probedefs; *defc = pf->probedefc;
      break;

    case SCAMPER_DEALIAS_METHOD_BUMP:
      bump = dealias->data;
      *defs = bump->probedefs; *defc = 2;
      break;

    default:
      return -1;
    }

  return 0;
}

static char *dealias_reply_tostr(const scamper_dealias_reply_t *reply)
{
  char buf[256], tmp[64];
  size_t off = 0;

  string_concatc(buf, sizeof(buf), &off, '{');
  if(reply->src != NULL)
    string_concat3(buf, sizeof(buf), &off, "\"src\":\"",
		   scamper_addr_tostr(reply->src, tmp, sizeof(tmp)), "\"");
  string_concat_u32(buf, sizeof(buf), &off, ",\"rx\":{\"sec\":",
		    (uint32_t)reply->rx.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ",\"usec\":",
		    (uint32_t)reply->rx.tv_usec);
  string_concat_u8(buf, sizeof(buf), &off, "},\"ttl\":", reply->ttl);
  if(reply->size != 0)
    string_concat_u16(buf, sizeof(buf), &off, ", \"size\":", reply->size);
  if(reply->src != NULL && SCAMPER_ADDR_TYPE_IS_IPV4(reply->src))
    string_concat_u16(buf, sizeof(buf), &off, ", \"ipid\":", reply->ipid);
  else if(reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32)
    string_concat_u32(buf, sizeof(buf), &off, ", \"ipid\":", reply->ipid32);
  string_concat_u8(buf, sizeof(buf), &off, ", \"proto\":", reply->proto);

  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply))
    {
      string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_type\":",
		       reply->icmp_type);
      string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_code\":",
		       reply->icmp_code);
      if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH(reply) ||
	 SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply))
	string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_q_ttl\":",
			 reply->icmp_q_ttl);
    }
  else if(SCAMPER_DEALIAS_REPLY_IS_TCP(reply))
    {
      string_concat_u8(buf, sizeof(buf), &off, ", \"tcp_flags\":",
		       reply->tcp_flags);
    }

  string_concatc(buf, sizeof(buf), &off, '}');
  return strdup(buf);
}

static char *dealias_probe_tostr(const scamper_dealias_probe_t *probe)
{
  char hdr[256], **replies = NULL, *rc = NULL, *str = NULL;
  size_t len, wc = 0, hdr_len = 0, *reply_lens = NULL;
  int i, x;

  string_concatc(hdr, sizeof(hdr), &hdr_len, '{');
  if(probe->def != NULL)
    {
      string_concat_u32(hdr, sizeof(hdr), &hdr_len,
			"\"probedef_id\":", probe->def->id);
      string_concatc(hdr, sizeof(hdr), &hdr_len, ',');
    }
  string_concat_u32(hdr, sizeof(hdr), &hdr_len, "\"seq\":", probe->seq);
  string_concat_u32(hdr, sizeof(hdr), &hdr_len, ",\"tx\":{\"sec\":",
		    (uint32_t)probe->tx.tv_sec);
  string_concat_u32(hdr, sizeof(hdr), &hdr_len, ",\"usec\":",
		    (uint32_t)probe->tx.tv_usec);
  string_concatc(hdr, sizeof(hdr), &hdr_len, '}');
  if(probe->def != NULL && probe->def->dst != NULL &&
     SCAMPER_ADDR_TYPE_IS_IPV4(probe->def->dst))
    string_concat_u16(hdr, sizeof(hdr), &hdr_len, ", \"ipid\":", probe->ipid);
  string_concat(hdr, sizeof(hdr), &hdr_len, ", \"replies\":[");
  len = hdr_len;
  if(probe->replyc > 0 && probe->replies != NULL)
    {
      if((replies = malloc_zero(sizeof(char *) * probe->replyc)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * probe->replyc)) == NULL)
	goto done;
      x = 0;
      for(i=0; i<probe->replyc; i++)
	{
	  if(probe->replies[i] == NULL)
	    continue;
	  if((replies[x] = dealias_reply_tostr(probe->replies[i])) == NULL)
	    goto done;
	  if(x > 0) len += 2; /* , */
	  reply_lens[x] = strlen(replies[x]);
	  len += reply_lens[x];
	  x++;
	}
    }
  len += 3; /* ]}\0 */

  if((str = malloc_zero(len)) == NULL)
    goto done;
  memcpy(str, hdr, hdr_len); wc += hdr_len;
  if(probe->replyc > 0)
    {
      for(i=0; i<probe->replyc; i++)
	{
	  if(replies[i] == NULL)
	    continue;
	  if(i > 0)
	    {
	      memcpy(str+wc, ", ", 2);
	      wc += 2;
	    }
	  memcpy(str+wc, replies[i], reply_lens[i]);
	  wc += reply_lens[i];
	}
    }
  memcpy(str+wc, "]}", 3); wc += 3;
  assert(wc == len);

  rc = str;

 done:
  if(rc == NULL && str != NULL)
    free(str);
  if(replies != NULL) {
    for(i=0; i<probe->replyc; i++)
      if(replies[i] != NULL)
	free(replies[i]);
    free(replies);
  }
  if(reply_lens != NULL)
    free(reply_lens);
  return rc;
}

char *scamper_dealias_tojson(const scamper_dealias_t *dealias, size_t *len_out)
{
  char     *str         = NULL;
  size_t    len         = 0;
  size_t    wc          = 0;
  char     *header      = NULL;
  size_t    header_len  = 0;
  char    **pds         = NULL;
  size_t   *pd_lens     = NULL;
  char    **prs         = NULL;
  size_t   *pr_lens     = NULL;
  int       i, rc       = -1;
  uint32_t  j;
  scamper_dealias_probedef_t **defs = NULL;
  int defc = 0;

  /* get the header string */
  if((header = dealias_header_tostr(dealias)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));
  len += 2; /* }\0" */

  /* get the probedef strings */
  if(dealias_probedefs_get(dealias, &defs, &defc) != 0 ||
     (pds = malloc_zero(sizeof(char *) * defc)) == NULL ||
     (pd_lens = malloc_zero(sizeof(size_t) * defc)) == NULL)
    goto cleanup;
  len += 16; /* , "probedefs":[] */
  for(i=0; i<defc; i++)
    {
      if(i > 0) len += 2; /* , */
      pds[i] = dealias_probedef_tostr(defs[i]);
      pd_lens[i] = strlen(pds[i]);
      len += pd_lens[i];
    }

  /* get the probe strings */
  len += 13; /* , "probes":[] */
  if(dealias->probec > 0)
    {
      if((prs = malloc_zero(sizeof(char *) * dealias->probec)) == NULL ||
	 (pr_lens = malloc_zero(sizeof(size_t) * dealias->probec)) == NULL)
	goto cleanup;

      for(j=0; j<dealias->probec; j++)
	{
	  if(j > 0) len += 2; /* , */
	  if((prs[j] = dealias_probe_tostr(dealias->probes[j])) == NULL)
	    goto cleanup;
	  pr_lens[j] = strlen(prs[j]);
	  len += pr_lens[j];
	}
    }

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"probedefs\":[", 15); wc += 15;
  for(i=0; i<defc; i++)
    {
      if(i > 0)
	{
	  memcpy(str+wc, ", ", 2);
	  wc += 2;
	}
      memcpy(str+wc, pds[i], pd_lens[i]);
      wc += pd_lens[i];
    }
  memcpy(str+wc, "]", 1); wc++;
  memcpy(str+wc, ", \"probes\":[", 12); wc += 12;
  if(dealias->probec > 0)
    {
      for(j=0; j<dealias->probec; j++)
	{
	  if(j > 0 )
	    {
	      memcpy(str+wc, ", ", 2);
	      wc += 2;
	    }
	  memcpy(str+wc, prs[j], pr_lens[j]);
	  wc += pr_lens[j];
	}
    }
  memcpy(str+wc, "]}\0", 3); wc += 3;

  assert(wc == len);
  rc = 0;

 cleanup:
  if(header != NULL) free(header);
  if(pd_lens != NULL) free(pd_lens);
  if(pr_lens != NULL) free(pr_lens);
  if(pds != NULL)
    {
      for(i=0; i<defc; i++)
	if(pds[i] != NULL)
	  free(pds[i]);
      free(pds);
    }
  if(prs != NULL)
    {
      for(j=0; j<dealias->probec; j++)
	if(prs[j] != NULL)
	  free(prs[j]);
      free(prs);
    }

  if(rc != 0)
    {
      if(str != NULL)
	free(str);
      return NULL;
    }

  if(len_out != NULL)
    *len_out = len;
  return str;
}

int scamper_file_json_dealias_write(const scamper_file_t *sf,
				    const scamper_dealias_t *dealias, void *p)
{
  char *str;
  size_t len;
  int rc;

  if((str = scamper_dealias_tojson(dealias, &len)) == NULL)
    return -1;
  str[len-1] = '\n';
  rc = json_write(sf, str, len, p);
  free(str);

  return rc;
}

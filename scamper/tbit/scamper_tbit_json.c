/*
 * scamper_tbit_json.c
 *
 * Copyright (c) 2014      Matthew Luckie
 * Copyright (C) 2015      The Regents of the University of California
 * Copyright (C) 2022-2024 Matthew Luckie
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_tbit_json.c,v 1.40 2025/10/15 23:58:44 mjl Exp $
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
#include "scamper_tbit.h"
#include "scamper_tbit_int.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_tbit_json.h"

#include "utils.h"

typedef struct tbit_state
{
  uint8_t  flags;
  uint32_t client_isn;
  uint32_t server_isn;
} tbit_state_t;

#define TBIT_STATE_FLAG_CISN 0x01
#define TBIT_STATE_FLAG_SISN 0x02

static void tbit_bits_encode(char *buf, size_t len, uint32_t flags, int bits,
			     const char **f2s, int f2sc)
{
  size_t off =  0;
  int i, f = 0;
  uint32_t u32;

  if(flags == 0)
    {
      buf[0] = '\0';
      return;
    }
  for(i=0; i<bits; i++)
    {
      if((u32 = flags & (0x1 << i)) == 0) continue;
      if(f > 0) string_concatc(buf, len, &off, ',');
      if(i < f2sc)
	string_concat3(buf, len, &off, "\"", f2s[i], "\"");
      else
	string_concat_u32(buf, len, &off, NULL, u32);
      f++;
    }

  return;
}

static uint32_t tbit_isnoff(uint32_t isn, uint32_t seq)
{
  if(seq >= isn)
    return seq - isn;
  return TCP_MAX_SEQNUM - isn + seq + 1;
}

static char *tbit_header_tostr(const scamper_tbit_t *tbit,
			       const tbit_state_t *state)
{
  static const char *tbit_options[] = {"tcpts", "sack"};
  static const char *pmtud_options[] = {"blackhole"};
  static const char *null_options[] = {"tcpts", "ipts-syn", "iprr-syn",
				       "ipqs-syn", "sack", "fo", "fo-exp"};
  static const char *null_results[] = {"tcpts-ok", "sack-ok", "fo-ok"};
  char buf[2048], tmp[512];
  size_t off = 0;
  scamper_tbit_pmtud_t *pmtud;
  scamper_tbit_null_t *null;
  scamper_tbit_blind_t *blind;
  scamper_tbit_app_http_t *http;
  scamper_tbit_app_bgp_t *bgp;
  uint32_t u32;

  string_concat2(buf, sizeof(buf), &off, "{\"type\":\"tbit\", \"tbit_type\":\"",
		 scamper_tbit_type_tostr(tbit, tmp, sizeof(tmp)));
  string_concat_u32(buf, sizeof(buf), &off, "\", \"userid\":", tbit->userid);
  string_concat3(buf, sizeof(buf), &off, ", \"src\":\"",
		 scamper_addr_tostr(tbit->src, tmp, sizeof(tmp)), "\"");
  string_concat3(buf, sizeof(buf), &off, ", \"dst\":\"",
		 scamper_addr_tostr(tbit->dst, tmp, sizeof(tmp)), "\"");
  string_concat_u16(buf, sizeof(buf), &off, ", \"sport\":", tbit->sport);
  string_concat_u16(buf, sizeof(buf), &off, ", \"dport\":", tbit->dport);
  string_concat_u32(buf, sizeof(buf), &off, ", \"start\":{\"sec\":",
		    (uint32_t)tbit->start.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ",\"usec\":",
		    (uint32_t)tbit->start.tv_usec);
  string_concat_u16(buf, sizeof(buf), &off, "}, \"client_mss\":",
		    tbit->client_mss);
  string_concat_u16(buf, sizeof(buf), &off, ", \"server_mss\":",
		    tbit->server_mss);
  string_concat_u8(buf, sizeof(buf), &off, ", \"ttl\":", tbit->client_ipttl);
  string_concat3(buf, sizeof(buf), &off, ", \"result\":\"",
		 scamper_tbit_result_tostr(tbit, tmp, sizeof(tmp)), "\"");
  if(tbit->options != 0)
    {
      tbit_bits_encode(tmp, sizeof(tmp), tbit->options, 16,
		       tbit_options, sizeof(tbit_options) / sizeof(char *));
      string_concat3(buf, sizeof(buf), &off, ", \"options\":[", tmp, "]");
    }

  if(tbit->errmsg != NULL)
    string_concat3(buf, sizeof(buf), &off, ",\"errmsg\":\"",
		   json_esc(tbit->errmsg, tmp, sizeof(tmp)), "\"");

  if(tbit->client_wscale > 0)
    string_concat_u8(buf, sizeof(buf), &off, ", \"wscale\":",
		     tbit->client_wscale);

  if(tbit->client_fo_cookielen > 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"fo_cookie\":\"");
      string_byte2hex(buf, sizeof(buf), &off,
		      tbit->client_fo_cookie, tbit->client_fo_cookielen);
      string_concatc(buf, sizeof(buf), &off, '"');
    }

  if(state->flags & TBIT_STATE_FLAG_CISN)
    string_concat_u32(buf, sizeof(buf), &off, ", \"client_isn\":",
		      state->client_isn);
  if(state->flags & TBIT_STATE_FLAG_SISN)
    string_concat_u32(buf, sizeof(buf), &off, ", \"server_isn\":",
		      state->server_isn);

  if(tbit->type == SCAMPER_TBIT_TYPE_PMTUD && (pmtud = tbit->data) != NULL)
    {
      string_concat_u16(buf, sizeof(buf), &off, ", \"mtu\":", pmtud->mtu);
      string_concat_u8(buf, sizeof(buf), &off, ", \"ptb_retx\":",
		       pmtud->ptb_retx);
      if(pmtud->ptbsrc != NULL)
	string_concat3(buf, sizeof(buf), &off, ", \"ptbsrc\":\"",
		       scamper_addr_tostr(pmtud->ptbsrc, tmp, sizeof(tmp)),
		       "\"");
      tbit_bits_encode(tmp, sizeof(tmp), pmtud->options, 8,
		       pmtud_options, sizeof(pmtud_options) / sizeof(char *));
      string_concat3(buf, sizeof(buf), &off, ", \"pmtud_options\":[", tmp, "]");
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_NULL && (null = tbit->data) != NULL)
    {
      tbit_bits_encode(tmp, sizeof(tmp), null->options, 16,
		       null_options, sizeof(null_options) / sizeof(char *));
      string_concat3(buf, sizeof(buf), &off, ", \"null_options\":[", tmp, "]");
      tbit_bits_encode(tmp, sizeof(tmp), null->results, 16,
		       null_results, sizeof(null_results) / sizeof(char *));
      string_concat3(buf, sizeof(buf), &off, ", \"null_results\":[", tmp, "]");
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_ICW)
    {
      if(scamper_tbit_server_icw_size_get(tbit, &u32) == 0)
	string_concat_u32(buf, sizeof(buf), &off, ", \"icw_bytes\":", u32);
    }
  else if(SCAMPER_TBIT_TYPE_IS_BLIND(tbit) && (blind = tbit->data) != NULL)
    {
      string_concaf(buf, sizeof(buf), &off, ", \"blind_off\":%d", blind->off);
      string_concat_u8(buf, sizeof(buf), &off, ", \"blind_retx\":",
		       blind->retx);
    }

  if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP && tbit->app_data != NULL)
    {
      http = tbit->app_data;
      string_concat(buf, sizeof(buf), &off, ", \"app\":\"http\"");
      if(http->host != NULL)
	{
	  if(http->type == SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS)
	    string_concat2(buf, sizeof(buf), &off,
			   ", \"http_url\":\"https://", http->host);
	  else
	    string_concat2(buf, sizeof(buf), &off,
			   ", \"http_url\":\"http://", http->host);
	  if(http->file != NULL)
	    string_concat(buf, sizeof(buf), &off, http->file);
	  string_concatc(buf, sizeof(buf), &off, '"');
	}
    }
  else if(tbit->app_proto == SCAMPER_TBIT_APP_BGP && tbit->app_data != NULL)
    {
      bgp = tbit->app_data;
      string_concat_u32(buf, sizeof(buf), &off,
			", \"app\":\"bgp\", \"bgp_asn\":", bgp->asn);
    }

  return strdup(buf);
}

static char *tbit_pkt_tostr(const scamper_tbit_t *tbit,
			    const scamper_tbit_pkt_t *pkt, tbit_state_t *state)
{
  static const char *tcpflags_str[] = {"fin", "syn", "rst", "psh", "ack",
				       "urg", "ece", "cwr"};
  struct timeval tv;
  char buf[1024], tmp[128];
  size_t off = 0;
  int frag = 0;
  uint32_t frag_id = 0;
  uint8_t frag_mf = 0;
  uint8_t u8, proto, tcpoptc, tcpflags, iphlen, tcphlen, v, ecn, ttl, *pp;
  uint16_t u16, len, win, frag_off = 0;
  uint32_t u32, seq, ack;

  if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
    string_concat(buf, sizeof(buf), &off, "{\"dir\":\"tx\"");
  else if(pkt->dir == SCAMPER_TBIT_PKT_DIR_RX)
    string_concat(buf, sizeof(buf), &off, "{\"dir\":\"rx\"");
  else
    string_concat_u8(buf, sizeof(buf), &off, "{\"dir\":", pkt->dir);

  timeval_diff_tv(&tv, &tbit->start, &pkt->tv);
  string_concat_u32(buf, sizeof(buf), &off, ", \"tv_sec\":",
		    (uint32_t)tv.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"tv_usec\":",
		    (uint32_t)tv.tv_usec);
  string_concat_u16(buf, sizeof(buf), &off, ", \"len\":", pkt->len);

  v = (pkt->data[0] >> 4);
  if(v == 4)
    {
      iphlen = (pkt->data[0] & 0xf) * 4;
      len = bytes_ntohs(pkt->data+2);
      proto = pkt->data[9];
      ecn = pkt->data[1] & 0x3;
      ttl = pkt->data[8];
      if(pkt->data[6] & 0x20)
	frag_mf = 1;
      frag_id  = bytes_ntohs(pkt->data+4);
      frag_off = (bytes_ntohs(pkt->data+6) & 0x1fff) * 8;
      if(frag_mf != 0 || frag_off != 0)
	frag = 1;
    }
  else if(v == 6)
    {
      iphlen = 40;
      len = bytes_ntohs(pkt->data+4) + iphlen;
      proto = pkt->data[6];
      ecn = (pkt->data[1] & 0x30) >> 4;
      ttl = pkt->data[7];

      for(;;)
	{
	  switch(proto)
	    {
	    case IPPROTO_HOPOPTS:
	    case IPPROTO_DSTOPTS:
	    case IPPROTO_ROUTING:
	      proto = pkt->data[iphlen+0];
	      iphlen += (pkt->data[iphlen+1] * 8) + 8;
	      continue;

	    case IPPROTO_FRAGMENT:
	      if(pkt->data[iphlen+3] & 0x1)
		frag_mf = 1;
	      frag_off = (bytes_ntohs(pkt->data+iphlen+2) & 0xfff8);
	      frag_id = bytes_ntohl(pkt->data+iphlen+4);
	      proto = pkt->data[iphlen+0];
	      iphlen += 8;
	      frag = 1;
	      continue;
	    }
	  break;
	}
    }
  else goto done; /* not v4 or v6 */

  string_concat_u8(buf, sizeof(buf), &off, ", \"ip_hlen\":", iphlen);
  string_concat_u8(buf, sizeof(buf), &off, ", \"ip_ecn\":", ecn);
  string_concat_u8(buf, sizeof(buf), &off, ", \"ip_ttl\":", ttl);

  if(v == 4 || (v == 6 && frag != 0))
    {
      string_concat_u32(buf, sizeof(buf), &off, ", \"frag_id\":", frag_id);
      string_concat_u16(buf, sizeof(buf), &off, ", \"frag_off\":", frag_off);
      string_concat_u8(buf, sizeof(buf), &off, ", \"frag_mf\":", frag_mf);
    }
  if(v == 4)
    string_concat_u8(buf, sizeof(buf), &off, ", \"frag_df\":",
		     (pkt->data[6] & 0x40) >> 7);

  if(frag_off != 0)
    goto done;

  if(proto == IPPROTO_TCP)
    {
      seq      = bytes_ntohl(pkt->data+iphlen+4);
      ack      = bytes_ntohl(pkt->data+iphlen+8);
      win      = bytes_ntohs(pkt->data+iphlen+14);
      tcpflags = pkt->data[iphlen+13];
      tcphlen  = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;

      if((tcpflags & (TH_SYN|TH_ACK)) == TH_SYN &&
	 (state->flags & TBIT_STATE_FLAG_CISN) == 0)
	{
	  state->client_isn = seq;
	  state->flags |= TBIT_STATE_FLAG_CISN;
	}
      else if((tcpflags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK) &&
	      (state->flags & TBIT_STATE_FLAG_SISN) == 0)
	{
	  state->server_isn = seq;
	  state->flags |= TBIT_STATE_FLAG_SISN;
	}

      string_concat_u8(buf, sizeof(buf), &off, ", \"tcp_hlen\":", tcphlen);
      tbit_bits_encode(tmp, sizeof(tmp), tcpflags, 8, tcpflags_str,
		       sizeof(tcpflags_str) / sizeof(char *));
      string_concat3(buf, sizeof(buf), &off, ", \"tcp_flags\":[", tmp, "]");

      /* parse TCP header for options */
      string_concat(buf, sizeof(buf), &off, ", \"tcp_options\":[");
      u8 = 20; tcpoptc = 0;
      while(u8 < tcphlen)
	{
	  pp = pkt->data + iphlen + u8;
	  if(pp[0] == 0)
	    {
	      string_concat2(buf, sizeof(buf), &off,
			     tcpoptc > 0 ? ", " : "", "{\"kind\":\"eol\"}");
	      break;
	    }
	  if(pp[0] == 1)
	    {
	      string_concat2(buf, sizeof(buf), &off,
			     tcpoptc > 0 ? ", " : "", "{\"kind\":\"nop\"}");
	      tcpoptc++; u8++;
	      continue;
	    }
	  if(pp[1] == 0 || u8 + pp[1] > tcphlen)
	    break;
	  if(pp[0] == 3 && pp[1] == 3)
	    {
	      if(tcpoptc > 0)
		string_concatc(buf, sizeof(buf), &off, ',');
	      string_concat_u8(buf, sizeof(buf), &off,
			       "{\"kind\":\"wscale\", \"shift\":", pp[2]);
	      string_concatc(buf, sizeof(buf), &off, '}');
	      tcpoptc++;
	    }
	  else if(pp[0] == 4 && pp[1] == 2)
	    {
	      if(tcpoptc > 0)
		string_concatc(buf, sizeof(buf), &off, ',');
	      string_concat(buf, sizeof(buf), &off, "{\"kind\":\"sack-ok\"}");
	      tcpoptc++;
	    }
	  else if(pp[0] == 5 && (pp[1]==10||pp[1]==18||pp[1]==26||pp[1]==34))
	    {
	      if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
		u32 = state->server_isn;
	      else
		u32 = state->client_isn;
	      if(tcpoptc > 0)
		string_concatc(buf, sizeof(buf), &off, ',');
	      string_concat(buf, sizeof(buf), &off,
			    "{\"kind\":\"sack\", \"blocks\":[");
	      for(u16=0; u16<(pp[1]-2)/8; u16++)
		{
		  if(u16 != 0)
		    string_concatc(buf, sizeof(buf), &off, ',');
		  string_concat_u32(buf, sizeof(buf), &off, "{\"left\":",
				    bytes_ntohl(pp+2+(u16*8)) - u32);
		  string_concat_u32(buf, sizeof(buf), &off, ", \"right\":",
				    bytes_ntohl(pp+2+(u16*8)+4) - u32);
		  string_concatc(buf, sizeof(buf), &off, '}');
		}			      
	      string_concat(buf, sizeof(buf), &off, "]}");
	      tcpoptc++;
	    }
	  else if(pp[0] == 8 && pp[1] == 10)
	    {
	      if(tcpoptc > 0)
		string_concatc(buf, sizeof(buf), &off, ',');
	      string_concat_u32(buf, sizeof(buf), &off,
				"{\"kind\":\"ts\", \"val\":",
				bytes_ntohl(pp+2));
	      string_concat_u32(buf, sizeof(buf), &off, ", \"ecr\":",
				bytes_ntohl(pp+6));
	      string_concatc(buf, sizeof(buf), &off, '}');
	      tcpoptc++;
	    }
	  else if(pp[0] == 34 && pp[1] >= 2)
	    {
	      string_concat2(buf, sizeof(buf), &off, tcpoptc > 0 ? ", " : "",
			     "{\"kind\":\"fo\"");
	      if(pp[1] > 2)
		{
		  string_concat(buf, sizeof(buf), &off, ", \"cookie\":\"");
		  string_byte2hex(buf, sizeof(buf), &off, pp+2, pp[1]-2);
		  string_concat(buf, sizeof(buf), &off, "\"}");
		}
	      tcpoptc++;
	    }
	  else if(pp[0] == 254 && pp[1] >= 4 && pp[2] == 0xF9 && pp[3] == 0x89)
	    {
	      string_concat2(buf, sizeof(buf), &off, tcpoptc > 0 ? ", " : "",
			     "{\"kind\":\"fo-exp\"");
	      if(pp[1] > 4)
		{
		  string_concat(buf, sizeof(buf), &off, ", \"cookie\":\"");
		  string_byte2hex(buf, sizeof(buf), &off, pp+4, pp[1]-4);
		  string_concat(buf, sizeof(buf), &off, "\"}");
		}
	      tcpoptc++;
	    }

	  u8 += pp[1];
	}
      string_concatc(buf, sizeof(buf), &off, ']');

      if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
	{
	  seq = tbit_isnoff(state->client_isn, seq);
	  ack = tbit_isnoff(state->server_isn, ack);
	}
      else
	{
	  if(!(seq == 0 && (tcpflags & TH_RST) != 0))
	    seq = tbit_isnoff(state->server_isn, seq);
	  ack = tbit_isnoff(state->client_isn, ack);
	}

      string_concat_u32(buf, sizeof(buf), &off, ", \"tcp_seq\":", seq);
      if(tcpflags & TH_ACK)
	string_concat_u32(buf, sizeof(buf), &off, ", \"tcp_ack\":", ack);
      string_concat_u16(buf, sizeof(buf), &off, ", \"tcp_datalen\":",
			len - iphlen - tcphlen);
      string_concat_u16(buf, sizeof(buf), &off, ", \"tcp_win\":", win);
    }

 done:
  string_concatc(buf, sizeof(buf), &off, '}');
  return strdup(buf);
}

char *scamper_tbit_tojson(const scamper_tbit_t *tbit, size_t *len_out)
{
  tbit_state_t state;
  char *str = NULL, *header = NULL, **pkts = NULL;
  size_t header_len = 0, len = 0, wc = 0, *pkt_lens = NULL;
  int rc = -1;
  uint32_t i;

  memset(&state, 0, sizeof(state));

  /* put together packet strings, done first to get state for header string */
  len += 11; /* , "pkts":[] */
  if(tbit->pktc > 0 &&
     ((pkts = malloc_zero(sizeof(char *) * tbit->pktc)) == NULL ||
      ((pkt_lens = malloc_zero(sizeof(size_t) * tbit->pktc)) == NULL)))
    goto cleanup;
  for(i=0; i<tbit->pktc; i++)
    {
      if(i > 0) len += 2; /* , */
      if((pkts[i] = tbit_pkt_tostr(tbit, tbit->pkts[i], &state)) == NULL)
	goto cleanup;
      pkt_lens[i] = strlen(pkts[i]);
      len += pkt_lens[i];
    }

  /* get the header string */
  if((header = tbit_header_tostr(tbit, &state)) == NULL)
    goto cleanup;
  len += (header_len = strlen(header));
  len += 2; /* }\0" */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"pkts\":[", 10); wc += 10;
  for(i=0; i<tbit->pktc; i++)
    {
      if(i > 0)
	{
	  memcpy(str+wc, ", ", 2);
	  wc += 2;
	}
      memcpy(str+wc, pkts[i], pkt_lens[i]);
      wc += pkt_lens[i];
    }
  memcpy(str+wc, "]}\0", 3); wc += 3;

  assert(wc == len);
  rc = 0;

 cleanup:
  if(header != NULL) free(header);
  if(pkt_lens != NULL) free(pkt_lens);
  if(pkts != NULL)
    {
      for(i=0; i<tbit->pktc; i++)
	if(pkts[i] != NULL)
	  free(pkts[i]);
      free(pkts);
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

int scamper_file_json_tbit_write(const scamper_file_t *sf,
				 const scamper_tbit_t *tbit, void *p)
{
  char *str;
  size_t len;
  int rc;

  if((str = scamper_tbit_tojson(tbit, &len)) == NULL)
    return -1;
  str[len-1] = '\n';
  rc = json_write(sf, str, len, p);
  free(str);

  return rc;
}

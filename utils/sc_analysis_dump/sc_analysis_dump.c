/*
 * sc_analysis_dump
 *
 * $Id: sc_analysis_dump.c,v 1.83 2025/05/01 02:58:04 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2013 The Regents of the University of California
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2023-2025 Matthew Luckie
 * Copyright (C) 2025      The Regents of the University of California
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "scamper_icmpext.h"
#include "trace/scamper_trace.h"
#include "mjl_splaytree.h"
#include "utils.h"

#define OPT_SKIP          0x00001
#define OPT_DEBUG         0x00002
#define OPT_DSTEND        0x00004
#define OPT_OLDFORMAT     0x00008
#define OPT_HIDECOMMENTS  0x00010
#define OPT_HIDESRC       0x00020
#define OPT_HIDEDST       0x00040
#define OPT_HIDELIST      0x00080
#define OPT_HIDECYCLE     0x00100
#define OPT_HIDETIME      0x00200
#define OPT_HIDEREPLY     0x00400
#define OPT_HIDEHALT      0x00800
#define OPT_HIDEPATH      0x01000
#define OPT_HIDEIRTT      0x02000
#define OPT_HELP          0x04000
#define OPT_SHOWUSERID    0x08000
#define OPT_SHOWQTTL      0x10000
#define OPT_SHOWMPLS      0x20000
#define OPT_SHOWIPTTL     0x40000

static uint32_t options = 0;

static int skip_numlines = 0;
static int debug_numlines = 0;

/* the input warts files */
static char **filelist = NULL;
static int    filelist_len = 0;

/* where the output goes.  stdout by default */
static FILE *out = NULL;

static void usage(void)
{
  fprintf(stderr,
	  "usage: sc_analysis_dump [-oeCsdlctrHpihUQMT]\n"
	  "                        [-S skip count] [-D debug count]\n"
	  "                        [file1 file2 ... fileN]\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int i, ch;
  char opts[48];
  snprintf(opts, sizeof(opts), "oeCsdlctrHpiS:D:?UQMT");

  while((i = getopt(argc, argv, opts)) != -1)
    {
      ch = (char)i;
      switch(ch)
	{
	case 'S':
	  options |= OPT_SKIP;
	  skip_numlines = atoi(optarg);
	  break;

	case 'D':
	  options |= OPT_DEBUG;
	  debug_numlines = atoi(optarg);
	  break;

	case 'e':
	  options |= OPT_DSTEND;
	  break;

	case 'o':
	  options |= OPT_OLDFORMAT;
	  break;

	case 'C':
	  options |= OPT_HIDECOMMENTS;
	  break;

	case 's':
	  options |= OPT_HIDESRC;
	  break;

	case 'd':
	  options |= OPT_HIDEDST;
	  break;

	case 'l':
	  options |= OPT_HIDELIST;
	  break;

	case 'c':
	  options |= OPT_HIDECYCLE;
	  break;

	case 't':
	  options |= OPT_HIDETIME;
	  break;

	case 'r':
	  options |= OPT_HIDEREPLY;
	  break;

	case 'H':
	  options |= OPT_HIDEHALT;
	  break;

	case 'p':
	  options |= OPT_HIDEPATH;
	  break;

	case 'i':
	  options |= OPT_HIDEIRTT;
	  break;

	case 'U':
	  options |= OPT_SHOWUSERID;
	  break;

	case 'Q':
	  options |= OPT_SHOWQTTL;
	  break;

	case 'M':
	  options |= OPT_SHOWMPLS;
	  break;

	case 'T':
	  options |= OPT_SHOWIPTTL;
	  break;

	case '?':
	  options |= OPT_HELP;
	  break;

	default:
	  usage();
	  return -1;
	}
    }

  filelist = argv + optind;
  filelist_len = argc - optind;

  return 0;
}

static char *rtt_tostr(char *str, const size_t len, const struct timeval *rtt)
{
  if(rtt != NULL)
    {
      snprintf(str, len, "%ld.%03d",
	       (long)((rtt->tv_sec * 1000) + (rtt->tv_usec / 1000)),
	       (int)(rtt->tv_usec % 1000));
    }
  else
    {
      str[0] = '\0';
    }

  return str;
}

static scamper_trace_reply_t *trace_reply_get(const scamper_trace_t *trace,
					  uint8_t i)
{
  scamper_trace_probettl_t *pttl;
  if(i == 255 || (pttl = scamper_trace_probettl_get(trace, i+1)) == NULL)
    return NULL;
  return scamper_trace_probettl_reply_get(pttl);
}

/*
 * trace_hop_firstaddr
 *
 * return 1 if this hop record is the first instance of the address at
 * the TTL.
 */
static int trace_hop_firstaddr(const scamper_trace_t *trace, uint8_t probe_ttl,
			       const scamper_trace_reply_t *hop)
{
  const scamper_trace_reply_t *tmp;
  scamper_trace_hopiter_t *hi = NULL;
  int rc = -1;

  if((hi = scamper_trace_hopiter_alloc()) == NULL ||
     scamper_trace_hopiter_ttl_set(hi, probe_ttl, probe_ttl) != 0)
    goto done;

  while((tmp = scamper_trace_hopiter_next(trace, hi)) != NULL)
    {
      if(tmp == hop)
	{
	  rc = 1;
	  break;
	}
      if(scamper_trace_reply_addr_cmp(tmp, hop) == 0)
	{
	  rc = 0;
	  break;
	}
    }

 done:
  if(hi != NULL) scamper_trace_hopiter_free(hi);
  return rc;
}

/*
 * trace_loop:
 *
 * find the nth instance of a loop in the trace.
 */
static int trace_loop(const scamper_trace_t *trace, int n)
{
  scamper_trace_hopiter_t *hi = NULL, *hi2 = NULL;
  const scamper_trace_probe_t *probe;
  const scamper_trace_reply_t *hop, *tmp;
  int loopc = 0, rc = -1;
  uint8_t probe_ttl, ttl;

  if((hi = scamper_trace_hopiter_alloc()) == NULL ||
     (hi2 = scamper_trace_hopiter_alloc()) == NULL)
    goto done;

  while((hop = scamper_trace_hopiter_next(trace, hi)) != NULL)
    {
      /*
       * if this address was already checked for loops earlier, then
       * continue with the next hop record
       */
      probe = scamper_trace_hopiter_probe_get(hi);
      if((probe_ttl = scamper_trace_probe_ttl_get(probe)) == 0)
	break;
      if(trace_hop_firstaddr(trace, probe_ttl, hop) == 0)
	continue;

      ttl = probe_ttl - 1;
      while(ttl > 0)
	{
	  scamper_trace_hopiter_ttl_set(hi2, ttl, ttl);
	  while((tmp = scamper_trace_hopiter_next(trace, hi2)) != NULL)
	    {
	      /*
	       * if there's a loop (and this is the first instance of
	       * this address in at this distance into the traceroute)
	       * then we found a new loop.
	       */
	      if(scamper_trace_reply_addr_cmp(tmp, hop) == 0 &&
		 trace_hop_firstaddr(trace, ttl, tmp) != 0 && ++loopc == n)
		{
		  rc = probe_ttl - ttl;
		  goto done;
		}
	    }

	  ttl--;
	}
    }

  rc = 0;

 done:
  if(hi != NULL) scamper_trace_hopiter_free(hi);
  if(hi2 != NULL) scamper_trace_hopiter_free(hi2);
  return rc;
}

static void print_help()
{
  usage();
  fprintf(stderr,
  "  This program prints out scamper warts and skitter arts traces.\n"
  "  C - hide comments\n"
  "  o - old format version 1.0\n"
  "  s - hide Source \n"
  "  d - hide Destination \n"
  "  l - hide list number\n"
  "  c - hide cycle number\n"
  "  U - show userid number\n"
  "  t - hide Timestamp \n"
  "  r - hide Reply Fields\n"
  "     DestReplied, DestRTT, RequestTTL, ReplyTTL \n"
  "  H - hide Halt Fields \n"
  "      HaltReason, HaltReasonData\n"
  "  p - hide Path Fields \n"
  "      PathComplete, PerHopData\n"
  "  i - hides hop non IP data\n"
  "      HopRTT, HopNumTries\n"
  "  M - show MPLS headers recorded in ICMP extension headers\n"
  "  Q - show quoted IP-TTL in response\n"
  "  T - show IP-TTL in response\n"
  "\n"
  "  e - add Destination to Ending\n"
  "\n"
  "  D numline - debug mode that only reads the first numline objects\n"
  "  S numline - skips first numline objects in the file\n"
  "\n"
  "  ? - prints this message\n"
  " \n"
 );

  return;
}


static void print_header_comments(void)
{
  uint32_t u32;
  int i = 1;
  char buf[64], buf2[64], buf3[256];
  size_t off;

  printf(
 "# =======================================================================\n"
 "# This file contains an ASCII representation of the IP paths stored in\n"
 "# the binary skitter arts++ and scamper warts file formats.\n"
 "#\n"
 "# =======================================================================\n"
 "# There is one trace per line, with the following tab-separated fields:\n"
 "#\n"
 "#\n");

  if((options & OPT_OLDFORMAT) == 0)
    {
      printf(
 "# %2d. Key -- Indicates the type of line and determines the meaning of the\n"
 "#            remaining fields.  This will always be 'T' for an IP trace.\n"
 "#\n", i++);

      u32 = (OPT_HIDESRC|OPT_HIDEDST|OPT_HIDELIST|OPT_HIDECYCLE|OPT_HIDETIME);
      if((options & u32) != u32 || (options & OPT_SHOWUSERID) != 0)
	printf(
 "# -------------------- Header Fields ------------------\n"
 "#\n");

      if((options & OPT_HIDESRC) == 0)
	printf(
 "# %2d. Source -- Source IP of skitter/scamper monitor performing the trace.\n"
 "#\n", i++);

      if((options & OPT_HIDEDST) == 0)
	printf(
 "# %2d. Destination -- Destination IP being traced.\n"
 "#\n", i++);

      if((options & OPT_HIDELIST) == 0)
	printf(
 "# %2d. ListId -- ID of the list containing this destination address.\n"
 "#\n"
 "#        This value will be zero if no list ID was provided.  (uint32_t)\n"
 "#\n", i++);

      if((options & OPT_HIDECYCLE) == 0)
	printf(
 "# %2d. CycleId -- ID of current probing cycle (a cycle is a single run\n"
 "#                through a given list).  For skitter traces, cycle IDs\n"
 "#                will be equal to or slightly earlier than the timestamp\n"
 "#                of the first trace in each cycle. There is no standard\n"
 "#                interpretation for scamper cycle IDs.\n"
 "#\n"
 "#        This value will be zero if no cycle ID was provided.  (uint32_t)\n"
 "#\n", i++);

      if((options & OPT_SHOWUSERID) != 0)
	printf(
 "# %2d. UserId -- ID provided by the user for this trace.\n"
 "#\n"
 "#        This value will be zero if no user ID was provided.  (uint32_t)\n"
 "#\n", i++);

      if((options & OPT_HIDETIME) == 0)
	printf(
 "# %2d. Timestamp -- Timestamp when trace began to this destination.\n"
 "#\n", i++);

      if((options & OPT_HIDEREPLY) == 0)
	{
	  printf(
 "# -------------------- Reply Fields ------------------\n"
 "#\n"
 "# %2d. DestReplied -- Whether a response from the destination was received.\n"
 "#\n"
 "#        R - Replied, reply was received\n"
 "#        N - Not-replied, no reply was received;\n"
 "#            Since skitter sends a packet with a TTL of 255 when it halts\n"
 "#            probing, it is still possible for the final destination to\n"
 "#            send a reply and for the HaltReasonData (see below) to not\n"
 "#            equal no_halt.  Note: scamper does not perform last-ditch\n"
 "#            probing at TTL 255 by default.\n"
 "#\n", i++);

	  printf(
 "# %2d. DestRTT -- RTT (ms) of first response packet from destination.\n"
 "#        0 if DestReplied is N.\n"
 "#\n", i++);

	  printf(
 "# %2d. RequestTTL -- TTL set in request packet which elicited a response\n"
 "#      (echo reply) from the destination.\n"
 "#        0 if DestReplied is N.\n"
 "#\n", i++);

	  printf(
 "# %2d. ReplyTTL -- TTL found in reply packet from destination;\n"
 "#        0 if DestReplied is N.\n"
 "#\n", i++);
	}

      if((options & OPT_HIDEHALT) == 0)
	{
	  printf(
 "# -------------------- Halt Fields ------------------\n"
 "#\n"
 "# %2d. HaltReason -- The reason, if any, why incremental probing stopped.\n"
 "#\n", i++);

	  printf(
 "# %2d. HaltReasonData -- Extra data about why probing halted.\n"
 "#\n"
 "#        HaltReason            HaltReasonData\n"
 "#        ------------------------------------\n"
 "#        S (success/no_halt)    0\n"
 "#        U (icmp_unreachable)   icmp_code\n"
 "#        L (loop_detected)      loop_length\n"
 "#        G (gap_detected)       gap_limit\n"
 "#\n", i++);
	}
    }

  if((options & OPT_HIDEPATH) == 0)
    {
      printf(
 "# -------------------- Path Fields ------------------\n"
 "#\n"
 "# %2d. PathComplete -- Whether all hops to destination were found.\n"
 "#\n"
 "#        C - Complete, all hops found\n"
 "#        I - Incomplete, at least one hop is missing (i.e., did not\n"
 "#            respond)\n"
 "#\n", i++);

      printf(
 "# %2d. PerHopData -- Response data for the first hop.\n"
 "#\n"
 "#       If multiple IP addresses respond at the same hop, response data\n"
 "#       for each IP address are separated by semicolons:\n"
 "#\n", i++);

      off = 0;
      string_concat(buf, sizeof(buf), &off, "IP");
      if((options & OPT_HIDEIRTT) == 0)
	string_concat(buf, sizeof(buf), &off, ",RTT,nTries");
      if((options & OPT_SHOWQTTL) != 0)
	string_concat(buf, sizeof(buf), &off, ",Q|quoted-TTL");
      if((options & OPT_SHOWMPLS) != 0)
	string_concat(buf, sizeof(buf), &off, ",M|ttl|label|exp|s");
      if((options & OPT_SHOWIPTTL) != 0)
	string_concat(buf, sizeof(buf), &off, ",T|IP-TTL");

      snprintf(buf2, sizeof(buf2),
	       "#       %%-%ds %%s\n", (int)((off*2) + 5));
      printf(buf2, buf, "(for only one responding IP)");

      snprintf(buf3, sizeof(buf3), "%s;%s;...", buf, buf);
      printf(buf2, buf3, "(for multiple responding IPs)");

      printf(
 "#\n"
 "#         where\n"
 "#\n"
 "#       IP -- IP address which sent a TTL expired packet\n");
      if((options & OPT_HIDEIRTT) == 0)
	{
	  printf(
 "#       RTT -- RTT of the TTL expired packet\n"
 "#       nTries -- number of tries before response received from hop\n");
	}
      if((options & OPT_SHOWQTTL) != 0)
	{
	  printf(
 "#       qTTL -- the IP-TTL in the quoted packet ('-' if not present)\n");
	}
      if((options & OPT_SHOWMPLS) != 0)
	{
	  printf(
 "#       ttl   -- the TTL in the MPLS header\n"
 "#       label -- the label in the MPLS header\n"
 "#       exp   -- the value of the 3 Exp bits in the MPLS header\n"
 "#       s     -- the value of the 'S' bit in the MPLS header\n");
	}

      printf(
 "#\n"
 "#       This field will have the value 'q' if there was no response at\n"
 "#       this hop.\n"
 "#\n");

      printf(
 "# %2d. PerHopData -- Response data for the second hop in the same format\n"
 "#       as field %d.\n", i, i-1);

      printf(
 "#\n"
 "# ...\n"
 "#\n");

      if(options & OPT_DSTEND)
	{
	  printf(
 "#  N. PerHopData -- Response data for the destination\n"
 "#       (if destination replied).\n"
 "#\n"
		 );
	}
    }

  return;
}

static void print_header_fields(const scamper_trace_t *trace)
{
  scamper_list_t *list;
  scamper_cycle_t *cycle;
  const struct timeval *tv;
  char buf[256];

  if((options & OPT_HIDESRC) == 0)
    fprintf(out, "\t%s", scamper_addr_tostr(scamper_trace_src_get(trace),
					    buf, sizeof(buf)));

  if((options & OPT_HIDEDST) == 0)
    fprintf(out, "\t%s", scamper_addr_tostr(scamper_trace_dst_get(trace),
					    buf, sizeof(buf)));

  if((options & OPT_HIDELIST) == 0)
    {
      list = scamper_trace_list_get(trace);
      fprintf(out, "\t%d", (list != NULL) ? scamper_list_id_get(list) : 0);
    }

  if((options & OPT_HIDECYCLE) == 0)
    {
      cycle = scamper_trace_cycle_get(trace);
      fprintf(out, "\t%d", (cycle != NULL) ? scamper_cycle_id_get(cycle) : 0);
    }

  if((options & OPT_SHOWUSERID) != 0)
    fprintf(out, "\t%d", scamper_trace_userid_get(trace));

  if((options & OPT_HIDETIME) == 0)
    {
      tv = scamper_trace_start_get(trace);
      fprintf(out, "\t%ld", (long)tv->tv_sec);
    }

  return;
}

static void print_reply_fields(const scamper_trace_probe_t *probe,
			       const scamper_trace_reply_t *reply)
{
  char rtt[64];

  if(reply != NULL)
    {
      rtt_tostr(rtt, sizeof(rtt), scamper_trace_reply_rtt_get(reply));
      fprintf(out, "\tR\t%s\t%d\t%d", rtt,
	      scamper_trace_probe_ttl_get(probe),
	      scamper_trace_reply_ttl_get(reply));
    }
  else
    {
      fprintf(out, "\tN\t0\t0\t0");
    }

  return;
}

static void print_halt_fields(const scamper_trace_t *trace)
{
  int l;

  switch(scamper_trace_stop_reason_get(trace))
    {
    case SCAMPER_TRACE_STOP_COMPLETED:
    case SCAMPER_TRACE_STOP_NONE:
      fprintf(out, "\tS\t0");
      break;

    case SCAMPER_TRACE_STOP_UNREACH:
      fprintf(out, "\tU\t%d", scamper_trace_stop_data_get(trace));
      break;

    case SCAMPER_TRACE_STOP_LOOP:
      if((l = scamper_trace_stop_data_get(trace)) == 0)
	l = trace_loop(trace, 1);
      fprintf(out, "\tL\t%d", l);
      break;

    case SCAMPER_TRACE_STOP_GAPLIMIT:
      fprintf(out, "\tG\t%d", scamper_trace_stop_data_get(trace));
      break;

    default:
      fprintf(out, "\t?\t0");
      break;
    }
  return;
}

static void print_old_fields(const scamper_trace_t *trace,
			     const scamper_trace_reply_t *hop)
{
  const struct timeval *start = scamper_trace_start_get(trace);
  char src[256], dst[256], rtt[256];

  fprintf(out, " %s %s %ld %s %d",
	  scamper_addr_tostr(scamper_trace_src_get(trace), src, sizeof(src)),
	  scamper_addr_tostr(scamper_trace_dst_get(trace), dst, sizeof(dst)),
	  (long)start->tv_sec,
	  rtt_tostr(rtt, sizeof(rtt),
		    (hop != NULL) ? scamper_trace_reply_rtt_get(hop) : NULL),
	  scamper_trace_hop_count_get(trace));

  return;
}

static char *hop_tostr(const scamper_trace_probe_t *probe,
		       const scamper_trace_reply_t *hop, char *buf, size_t len)
{
  const scamper_icmpexts_t *exts;
  const scamper_icmpext_t *ie;
  const scamper_addr_t *ha;
  char rtt[128], addr[128];
  size_t off = 0;
  uint16_t u16;
  int i;

  if((ha = scamper_trace_reply_addr_get(hop)) != NULL)
    string_concat(buf, len, &off, scamper_addr_tostr(ha, addr, sizeof(addr)));

  if((options & OPT_HIDEIRTT) == 0)
    string_concaf(buf, len, &off, ",%s,%d",
		  rtt_tostr(rtt, sizeof(rtt), scamper_trace_reply_rtt_get(hop)),
		  scamper_trace_probe_id_get(probe));

  if((options & OPT_SHOWQTTL) != 0 && scamper_trace_reply_is_icmp_q(hop))
    string_concaf(buf, len, &off, ",Q|%d",
		  scamper_trace_reply_icmp_q_ttl_get(hop));

  if((options & OPT_SHOWIPTTL) != 0)
    string_concaf(buf, len, &off, ",T|%d", scamper_trace_reply_ttl_get(hop));

  if((options & OPT_SHOWMPLS) != 0 &&
     (exts = scamper_trace_reply_icmp_exts_get(hop)) != NULL)
    {
      for(u16=0; u16 < scamper_icmpexts_count_get(exts); u16++)
	{
	  if((ie = scamper_icmpexts_ext_get(exts, u16)) != NULL &&
	     scamper_icmpext_is_mpls(ie))
	    {
	      for(i=0; i<scamper_icmpext_mpls_count_get(ie); i++)
		{
		  string_concaf(buf, len, &off, ",M|%d|%d|%d|%d",
				scamper_icmpext_mpls_ttl_get(ie, i),
				scamper_icmpext_mpls_label_get(ie, i),
				scamper_icmpext_mpls_exp_get(ie, i),
				scamper_icmpext_mpls_s_get(ie, i));
		}
	    }
	}
    }

  return buf;
}

static void print_path_fields(const scamper_trace_t *trace,
			      const scamper_trace_probe_t *dst_probe,
			      const scamper_trace_reply_t *dst)
{
  const scamper_trace_probe_t *probe;
  const scamper_trace_reply_t *hop;
  scamper_trace_hopiter_t *hi = NULL;
  char buf[256], path_complete;
  int i, j, unresponsive = 0;

  /*
   * decide what the path_complete flag should be set to.  if we reached
   * the destination then the path_complete flag == 'C' (for complete).
   * otherwise the path_complete flag == 'I' (incomplete) or 'N' if
   * using the old sk_analysis_dump output format.
   */
  path_complete = 'I';
  if(dst != NULL)
    {
      j = scamper_trace_probe_ttl_get(dst_probe);
      for(i=0; i<j; i++)
	if(trace_reply_get(trace, i) == NULL)
	  break;

      if(i == j && (options & OPT_OLDFORMAT) == 0)
	path_complete = 'C';
    }
  else if(options & OPT_OLDFORMAT)
    {
      path_complete = 'N';
    }

  /*
   * actually output the path complete flag, and some extra old fields
   * if requested
   */
  if((options & OPT_OLDFORMAT) == 0)
    {
      fprintf(out, "\t%c", path_complete);
    }
  else
    {
      fprintf(out, "%c", path_complete);
      print_old_fields(trace, dst);
    }

  if((j = scamper_trace_hop_count_get(trace)) > 255 ||
     (hi = scamper_trace_hopiter_alloc()) == NULL)
    goto done;

  for(i=0; i<j; i++)
    {
      /* look at hop records just for this TTL value */
      scamper_trace_hopiter_ttl_set(hi, i+1, i+1);

      /* no hop at this index, count up unresponsive hops */
      if((hop = scamper_trace_hopiter_next(trace, hi)) == NULL)
	{
	  unresponsive++;
	  continue;
	}

      /* don't print out the hop corresponding to the destination */
      if(hop == dst && (hop = scamper_trace_hopiter_next(trace, hi)) == NULL)
	break;

      /* print out unresponsive hops leading up to this hop records */
      while(unresponsive > 0)
	{
	  fprintf(out, "%c", options & OPT_OLDFORMAT ? ' ' : '\t');
	  fprintf(out, "q");
	  unresponsive--;
	}

      fprintf(out, "%c", options & OPT_OLDFORMAT ? ' ' : '\t');

      for(;;)
	{
	  probe = scamper_trace_hopiter_probe_get(hi);
	  if((options & OPT_OLDFORMAT) == 0)
	    fprintf(out, "%s", hop_tostr(probe, hop, buf, sizeof(buf)));

	  if((hop = scamper_trace_hopiter_next(trace, hi)) == NULL ||
	     hop == dst)
	    break;

	  if((options & OPT_OLDFORMAT) == 0)
	    fprintf(out, ";");
	  else
	    fprintf(out, ",");
	}
    }

  if(dst != NULL && options & OPT_DSTEND)
    {
      while(i < scamper_trace_probe_ttl_get(dst_probe) - 1)
        {
	  i++;
	  fprintf(out, "\tq");
	}

      fprintf(out, "\t%s", hop_tostr(dst_probe, dst, buf, sizeof(buf)));
    }

 done:
  if(hi != NULL) scamper_trace_hopiter_free(hi);
  return;
}

static void print_trace(const scamper_trace_t *trace)
{
  const scamper_trace_reply_t *dst = NULL, *hop;
  scamper_trace_probe_t *dst_probe = NULL;
  scamper_trace_hopiter_t *hi;
  uint16_t hop_count = scamper_trace_hop_count_get(trace);
  uint8_t stop_reason = scamper_trace_stop_reason_get(trace);
  int i;

  if((hop_count == 0 && stop_reason == SCAMPER_TRACE_STOP_ERROR) ||
     hop_count > 255)
    return;

  /* try to determine the hop that corresponds to the destination */
  if(hop_count > 0 && stop_reason != SCAMPER_TRACE_STOP_ERROR)
    {
      if((hi = scamper_trace_hopiter_alloc()) == NULL)
	return;

      for(i=hop_count; i>0 && dst == NULL; i--)
	{
	  scamper_trace_hopiter_ttl_set(hi, i, i);
	  while((hop = scamper_trace_hopiter_next(trace, hi)) != NULL)
	    {
	      if((scamper_trace_reply_is_icmp_unreach_port(hop) &&
		  (scamper_trace_type_is_udp(trace) ||
		   scamper_trace_type_is_tcp(trace))) ||
		 (scamper_trace_reply_is_icmp_echo_reply(hop) &&
		  scamper_trace_type_is_icmp(trace)) ||
		 (scamper_trace_reply_is_tcp(hop) &&
		  scamper_trace_type_is_tcp(trace)))
		{
		  dst_probe = scamper_trace_hopiter_probe_get(hi);
		  dst = hop;
		  break;
		}
	    }
	}
      scamper_trace_hopiter_free(hi);
    }

  if((options & OPT_OLDFORMAT) == 0)
    {
      fprintf(out, "T");
      print_header_fields(trace);

      if((options & OPT_HIDEREPLY) == 0)
	{
	  print_reply_fields(dst_probe, dst);
	}

      if((options & OPT_HIDEHALT) == 0)
	{
	  print_halt_fields(trace);
	}
    }

  if((options & OPT_HIDEPATH) == 0 || (options & OPT_OLDFORMAT))
    {
      print_path_fields(trace, dst_probe, dst);
    }

  fprintf(out, "\n");
  fflush(out);

  return;
}

static void process(scamper_file_t *file, scamper_file_filter_t *filter)
{
  scamper_trace_t *trace;
  uint16_t type;
  int n = 0;

  while(scamper_file_read(file, filter, &type, (void *)&trace) == 0)
    {
      if(trace == NULL) break; /* EOF */

      if((options & OPT_DEBUG) && n == debug_numlines)
	{
	  scamper_trace_free(trace);
	  break;
	}

      n++;

      if(n > skip_numlines)
	{
	  print_trace(trace);
	}

      scamper_trace_free(trace);
    }

  scamper_file_close(file);

  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t *file;
  scamper_file_filter_t *filter;
  uint16_t type = SCAMPER_FILE_OBJ_TRACE;
  int i;

#ifdef HAVE_WSASTARTUP
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

  out = stdout;

  if(check_options(argc, argv) == -1)
    {
      return -1;
    }
  if(options & OPT_HELP)
    {
      print_help();
      return 0;
    }

  if((filter = scamper_file_filter_alloc(&type, 1)) == NULL)
    {
      return -1;
    }

  if((options & OPT_HIDECOMMENTS) == 0)
    {
      print_header_comments();
    }

  if(filelist_len != 0)
    {
      for(i=0; i<filelist_len; i++)
	{
	  if((file = scamper_file_open(filelist[i], 'r', NULL)) == NULL)
	    {
	      fprintf(stderr, "unable to open %s\n", filelist[i]);
	      if((options & OPT_HIDECOMMENTS) == 0)
		{
		  fprintf(out, "# unable to open %s\n", filelist[i]);
		}

	      continue;
	    }

	  process(file, filter);
	}
    }
  else
    {
      if((file = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts")) == NULL)
	{
	  fprintf(stderr, "unable to open stdin\n");
	  if((options & OPT_HIDECOMMENTS) == 0)
	    {
	      fprintf(out, "# unable to open stdin\n");
	    }
	}
      else process(file, filter);
    }

  scamper_file_filter_free(filter);

  return 0;
}

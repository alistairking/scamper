/*
 * scamper_dlhdr.c
 *
 * $Id: scamper_dlhdr.c,v 1.26 2025/10/20 00:46:53 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2023      Matthew Luckie
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

#include "scamper_debug.h"
#include "scamper_fds.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_addr2mac.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_if.h"
#include "scamper_list.h"
#include "neighbourdisc/scamper_neighbourdisc_do.h"
#include "utils.h"

/*
 * dlhdr_eth_common:
 *
 * called both via scamper_dlhdr_get, and via neighbourdisc callback.
 */
static int dlhdr_eth_common(scamper_dlhdr_t *dlhdr, scamper_err_t *error)
{
  /* allocate space for ethernet header */
  if((dlhdr->buf = malloc_zero(14)) == NULL)
    {
      scamper_err_make(error, errno, "dlhdr_eth_common: could not malloc");
      return -1;
    }
  dlhdr->len = 14;

  /* the ethertype */
  if(SCAMPER_ADDR_TYPE_IS_IPV4(dlhdr->dst))
    {
      dlhdr->buf[12] = 0x08;
      dlhdr->buf[13] = 0x00;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dlhdr->dst))
    {
      dlhdr->buf[12] = 0x86;
      dlhdr->buf[13] = 0xDD;
    }
  else
    {
      scamper_err_make(error, 0, "dlhdr_eth_common: dst not IP address");
      return -1;
    }

  return 0;
}

static int dlhdr_ethmake(scamper_dlhdr_t *dlhdr, scamper_addr_t *mac,
			 scamper_err_t *error)
{
  /* allocate space for the header */
  if(dlhdr_eth_common(dlhdr, error) != 0)
    return -1;

  /* the source mac address to use */
  if(scamper_if_getmac(dlhdr->ifindex, dlhdr->buf+6, error) != 0)
    return -1;

  /* copy the destination mac address to use */
  memcpy(dlhdr->buf, mac->addr, 6);
  return 0;
}

/*
 * dlhdr_ethcb
 *
 * this callback is used by the neighbour discovery code.
 */
static void dlhdr_ethcb(void *param, scamper_addr_t *ip, scamper_addr_t *mac)
{
  scamper_dlhdr_t *dlhdr = param;
  scamper_err_t error;
  char buf[128];

  SCAMPER_ERR_INIT(&error);

  dlhdr->internal = NULL;

  /* we did not get a MAC address */
  if(mac == NULL)
    {
      scamper_err_make(&error, 0,
		       "dlhdr_ethcb: did not get mac address for %s",
		       scamper_addr_tostr(ip, buf, sizeof(buf)));
      dlhdr->cb(dlhdr, &error);
      return;
    }

  /* make the ethernet header */
  if(dlhdr_ethmake(dlhdr, mac, &error) != 0)
    dlhdr->cb(dlhdr, &error);
  else
    dlhdr->cb(dlhdr, NULL);

  /* cache the response */
  scamper_addr2mac_add(dlhdr->ifindex, ip, mac);
  return;
}

/*
 * dlhdr_ethernet
 *
 * form an ethernet header.  as this requires mac addresses, and scamper
 * may not know the mac address of the relevant IP, this function deals with
 * doing a neighbour discovery.
 */
static int dlhdr_ethernet(scamper_dlhdr_t *dlhdr, scamper_err_t *error)
{
  scamper_neighbourdisc_do_t *nd = NULL;
  scamper_addr_t *ip = NULL;
  scamper_addr_t *mac = NULL;
  int ifindex = dlhdr->ifindex;

  /* determine what we should be looking up */
  if(dlhdr->gw == NULL)
    ip = dlhdr->dst;
  else if(dlhdr->gw->type == SCAMPER_ADDR_TYPE_ETHERNET)
    mac = dlhdr->gw;
  else
    ip = dlhdr->gw;

  /* if we need to get a mac address, then look it up */
  if(mac == NULL && (mac = scamper_addr2mac_whohas(ifindex, ip)) == NULL)
    {
      nd = scamper_do_neighbourdisc_do(ifindex, ip, dlhdr, dlhdr_ethcb, error);
      if(nd == NULL)
	return -1;
      dlhdr->internal = nd;
      return 0;
    }

  /* return a cached mac address */
  if(dlhdr_ethmake(dlhdr, mac, error) != 0)
    return -1;
  dlhdr->cb(dlhdr, NULL);

  return 0;
}

static int dlhdr_ethloop(scamper_dlhdr_t *dlhdr, scamper_err_t *error)
{
  if(dlhdr_eth_common(dlhdr, error) != 0)
    return -1;
  dlhdr->cb(dlhdr, NULL);
  return 0;
}

static int dlhdr_null(scamper_dlhdr_t *dlhdr, scamper_err_t *error)
{
  int af;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(dlhdr->dst))
    af = AF_INET;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dlhdr->dst))
    af = AF_INET6;
  else
    {
      scamper_err_make(error, 0, "dlhdr_null: dst not IP address");
      return -1;
    }

  if((dlhdr->buf = memdup(&af, sizeof(af))) == NULL)
    {
      scamper_err_make(error, errno, "dlhdr_null: could not dup af");
      return -1;
    }

  dlhdr->len = sizeof(af);
  dlhdr->cb(dlhdr, NULL);
  return 0;
}

static int dlhdr_raw(scamper_dlhdr_t *dlhdr, scamper_err_t *error)
{
  dlhdr->cb(dlhdr, NULL);
  return 0;
}

static int dlhdr_unsupp(scamper_dlhdr_t *dlhdr, scamper_err_t *error)
{
  scamper_err_make(error, 0, "dlhdr_get: unsupported on ifindex %d",
		   dlhdr->ifindex);
  return -1;
}

/*
 * scamper_dlhdr_get
 *
 * determine the datalink header to use when framing a packet.
 */
int scamper_dlhdr_get(scamper_dlhdr_t *dlhdr, scamper_err_t *error)
{
  static int (*const func[])(scamper_dlhdr_t *, scamper_err_t *) = {
    dlhdr_unsupp,
    dlhdr_ethernet,
    dlhdr_null,
    dlhdr_raw,
    dlhdr_ethloop,
  };

  if(dlhdr->txtype < 0 || dlhdr->txtype > 4)
    {
      scamper_err_make(error, 0, "dlhdr_get: invalid txtype %d", dlhdr->txtype);
      return -1;
    }

  return func[dlhdr->txtype](dlhdr, error);
}

scamper_dlhdr_t *scamper_dlhdr_alloc(void)
{
  return (scamper_dlhdr_t *)malloc_zero(sizeof(scamper_dlhdr_t));
}

void scamper_dlhdr_free(scamper_dlhdr_t *dlhdr)
{
  if(dlhdr == NULL)
    return;
  if(dlhdr->gw != NULL) scamper_addr_free(dlhdr->gw);
  if(dlhdr->dst != NULL) scamper_addr_free(dlhdr->dst);
  if(dlhdr->buf != NULL) free(dlhdr->buf);
  if(dlhdr->internal != NULL) scamper_neighbourdisc_do_free(dlhdr->internal);
  free(dlhdr);
  return;
}

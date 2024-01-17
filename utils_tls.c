/*
 * utils_tls : functions for TLS
 *
 * $Id: utils_tls.c,v 1.2 2024/01/03 01:00:33 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2014-2023 Matthew Luckie
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

#include "utils_tls.h"

/*
 * tls_is_valid_cert
 *
 * this code ensures that the peer presented a valid certificate --
 * first that the peer verified and passed a signed certificate, and
 * then that the name provided in the cert corresponds to the name of
 * our peer.
 *
 * it is based on post_connection_check in "Network Security with
 * OpenSSL" by John Viega, Matt Messier, and Pravir Chandra, and
 * notes from https://wiki.openssl.org/index.php/Hostname_validation
 */
int tls_is_valid_cert(SSL *ssl, const char *hostname)
{
  X509 *cert = NULL;
  X509_NAME *name;
  STACK_OF(GENERAL_NAME) *names = NULL;
  const GENERAL_NAME *gname;
  const char *dname;
  char buf[256];
  int rc = 0;
  int i, count, x;

  if(SSL_get_verify_result(ssl) != X509_V_OK)
    return 0;

  if((cert = SSL_get_peer_certificate(ssl)) == NULL)
    return 0;

  if((names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL)) != NULL)
    {
      count = sk_GENERAL_NAME_num(names);
      for(i=0; i<count; i++)
	{
	  gname = sk_GENERAL_NAME_value(names, i);
	  if(gname == NULL || gname->type != GEN_DNS ||
	     gname->d.dNSName == NULL ||
	     (x = ASN1_STRING_length(gname->d.dNSName)) < 1)
	    continue;
#ifdef HAVE_ASN1_STRING_GET0_DATA
	  dname = (const char *)ASN1_STRING_get0_data(gname->d.dNSName);
#else
	  dname = (const char *)ASN1_STRING_data(gname->d.dNSName);
#endif
	  if(dname == NULL || (size_t)x != strlen(dname))
	    continue;
	  if(strcasecmp(dname, hostname) == 0)
	    {
	      rc = 1;
	      goto done;
	    }
	}
    }

  if((name = X509_get_subject_name(cert)) != NULL &&
     X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf)) > 0)
    {
      buf[sizeof(buf)-1] = 0;
      if(strcasecmp(buf, hostname) == 0)
	rc = 1;
    }

 done:
  if(names != NULL) sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
  if(cert != NULL) X509_free(cert);
  return rc;
}

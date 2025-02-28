/*
 * utils_tls : functions for TLS
 *
 * $Id: utils_tls.c,v 1.8 2025/02/07 16:37:20 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2014-2024 Matthew Luckie
 * Copyright (C) 2024-2025 The Regents of the University of California
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

int tls_want_read(BIO *wbio, void *param, char *errbuf, size_t errlen,
		  int (*cb)(void *param, uint8_t *buf, int len))
{
  uint8_t buf[1024];
  int pending, rc, size, off = 0;

  if((pending = BIO_pending(wbio)) < 0)
    {
      snprintf(errbuf, errlen, "BIO_pending returned %d", pending);
      return -1;
    }

  while(off < pending)
    {
      if((size_t)(pending - off) > sizeof(buf))
	size = sizeof(buf);
      else
	size = pending - off;

      if((rc = BIO_read(wbio, buf, size)) <= 0)
	{
	  if(BIO_should_retry(wbio) == 0)
	    snprintf(errbuf, errlen, "BIO_read should not retry");
	  else
	    snprintf(errbuf, errlen, "BIO_read returned %d", rc);
	  return -1;
	}
      off += rc;

      if(cb(param, buf, rc) != 0)
	{
	  snprintf(errbuf, errlen, "cb did not return zero");
	  return -1;
	}
    }

  return pending;
}

int tls_bio_alloc(SSL_CTX *ctx, SSL **ssl, BIO **rbio, BIO **wbio)
{
  /*
   * the order is important because once the BIOs are associated with
   * the ssl structure, SSL_free will clean them up.
   */
  if((*wbio = BIO_new(BIO_s_mem())) == NULL ||
     (*rbio = BIO_new(BIO_s_mem())) == NULL ||
     (*ssl  = SSL_new(ctx)) == NULL)
    return -1;
  SSL_set_bio(*ssl, *rbio, *wbio);
  return 0;
}

void tls_bio_free(SSL *ssl, BIO *rbio, BIO *wbio)
{
  /*
   * SSL_free() also calls the free()ing procedures for indirectly
   * affected items, if applicable: the buffering BIO, the read and
   * write BIOs, cipher lists specially created for this ssl, the
   * SSL_SESSION. Do not explicitly free these indirectly freed up
   * items before or after calling SSL_free(), as trying to free
   * things twice may lead to program failure.
   */
  if(ssl != NULL)
    {
      SSL_free(ssl);
    }
  else
    {
      if(wbio != NULL)
	BIO_free(wbio);
      if(rbio != NULL)
	BIO_free(rbio);
    }
  return;
}

static int tls_certname_matches(const char *certname, const char *hostname)
{
  size_t suffix_len, hostname_len, i;

  if(certname[0] == '*')
    {
      /* do not support partial wildcard */
      if(certname[1] != '.' || certname[2] == '\0')
	return 0;

      /* do not let hostname start with dot */
      if(hostname[0] == '.')
	return 0;

      suffix_len = strlen(certname+2);
      hostname_len = strlen(hostname);

      /*
       * hostname cannot match a wildcard cert where the suffix of the
       * wildcard is not shorter than the input hostname.  choice of
       * >= deliberate.
       */
      if(suffix_len >= hostname_len)
	return 0;

      /* suffix does not match */
      if(strcasecmp(hostname + hostname_len - suffix_len, certname+2) != 0)
	return 0;

      /* ensure the text after the next dot is the suffix of the cert */
      i = 0;
      while(hostname[i] != '\0' && hostname[i] != '.')
	i++;
      if(hostname[i] != '.' || i + 1 != hostname_len - suffix_len)
	return 0;

      return 1;
    }
  if(strcasecmp(certname, hostname) == 0)
    return 1;
  return 0;
}

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
  int i, count;

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
	     ASN1_STRING_length(gname->d.dNSName) < 1)
	    continue;
#ifdef HAVE_ASN1_STRING_GET0_DATA
	  dname = (const char *)ASN1_STRING_get0_data(gname->d.dNSName);
#else
	  dname = (const char *)ASN1_STRING_data(gname->d.dNSName);
#endif
	  if(dname == NULL)
	    continue;
	  if(tls_certname_matches(dname, hostname) != 0)
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
      if(tls_certname_matches(buf, hostname) != 0)
	rc = 1;
    }

 done:
  if(names != NULL) sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
  if(cert != NULL) X509_free(cert);
  return rc;
}

int tls_load_key(SSL_CTX *ctx, int fd)
{
  BIO *bio = NULL;
  EVP_PKEY *key = NULL;
  uint8_t buf[1024];
  ssize_t rrc;
  int rc = -1;

  if((bio = BIO_new(BIO_s_mem())) == NULL)
    goto done;

  while((rrc = read(fd, buf, sizeof(buf))) > 0)
    if(BIO_write(bio, buf, (int)rrc) < (int)rrc)
      goto done;
  if(rrc < 0)
    goto done;

  if((key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL)
    goto done;

  if(SSL_CTX_use_PrivateKey(ctx, key) != 1)
    goto done;

  rc = 0;

 done:
  if(key != NULL) EVP_PKEY_free(key);
  if(bio != NULL) BIO_free(bio);
  return rc;
}

int tls_load_certchain(SSL_CTX *ctx, int fd)
{
  unsigned long err;
  X509 *cert = NULL;
  BIO *bio = NULL;
  uint8_t buf[1024];
  ssize_t rrc;
  int rc = -1;

  if((bio = BIO_new(BIO_s_mem())) == NULL)
    goto done;

  while((rrc = read(fd, buf, sizeof(buf))) > 0)
    if(BIO_write(bio, buf, (int)rrc) < (int)rrc)
      goto done;
  if(rrc < 0)
    goto done;

  if((cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)) == NULL)
    goto done;
  if(SSL_CTX_use_certificate(ctx, cert) != 1)
    goto done;
  X509_free(cert); cert = NULL;

  if(SSL_CTX_clear_chain_certs(ctx) != 1)
    goto done;

  while((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL)
    {
      if(SSL_CTX_add0_chain_cert(ctx, cert) != 1)
	goto done;
    }

  /* make sure we stopped because the file was intact */
  err = ERR_peek_last_error();
  if(ERR_GET_LIB(err) == ERR_LIB_PEM &&
     ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
    ERR_clear_error();
  else
    goto done;

  rc = 0;

 done:
  if(cert != NULL) X509_free(cert);
  if(bio != NULL) BIO_free(bio);
  return rc;
}

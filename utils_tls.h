/*
 * utils_tls : functions for TLS
 *
 * $Id: utils_tls.h,v 1.5 2024/08/19 02:59:36 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2014-2024 Matthew Luckie
 * Copyright (C) 2024      The Regents of the University of California
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

#ifndef __UTILS_TLS_H
#define __UTILS_TLS_H

int tls_bio_alloc(SSL_CTX *ctx, SSL **ssl, BIO **rbio, BIO **wbio);
void tls_bio_free(SSL *ssl, BIO *rbio, BIO *wbio);

int tls_is_valid_cert(SSL *ssl, const char *hostname);

int tls_want_read(BIO *wbio, void *param, char *errbuf, size_t errlen,
		  int (*cb)(void *param, uint8_t *buf, int len));

int tls_load_certchain(SSL_CTX *ctx, int fd);
int tls_load_key(SSL_CTX *ctx, int fd);

#endif /* __UTILS_TLS_H */

/*
 * huffman coding
 *
 * Copyright (C) 2026 Matthew Luckie. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Matthew Luckie ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Matthew Luckie BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include "mjl_huffman.h"

typedef struct huffman_byte
{
  uint32_t        code;
  uint8_t         val;
} huffman_byte_t;

typedef struct huffman_bytes
{
  huffman_byte_t *bytes;
  size_t          count;
} huffman_bytes_t;

struct huffman
{
  huffman_bytes_t bits[32];
  uint8_t         max;
};

static int huffman_match(const huffman_t *hf,
			 uint8_t b, uint32_t code, uint8_t *out)
{
  size_t i;
  for(i=0; i<hf->bits[b].count; i++)
    {
      if(hf->bits[b].bytes[i].code == code)
	{
	  *out = hf->bits[b].bytes[i].val;
	  return 1;
	}
    }
  return 0;
}

int huffman_decode(const huffman_t *hf,
		   const uint8_t *in, size_t inlen,
		   uint8_t *out, size_t *outoff, size_t outlen)
{
  uint32_t state = 0, expected;
  size_t i, off = *outoff;
  uint8_t bits = 0, val;
  int b;

  if(off >= outlen)
    return -1;

  for(i = 0; i < inlen; i++)
    {
      for(b = 7; b >= 0; b--)
	{
	  state = (state << 1) | (uint32_t)((in[i] >> b) & 1);
	  if(++bits > hf->max)
	    return -1;
	  if(huffman_match(hf, bits, state, &val))
	    {
	      if(off >= outlen)
		return -1;
	      out[off++] = val;
	      state = 0; bits = 0;
	    }
	}
    }

  if(bits > 7)
    return -1;
  if(bits > 0)
    {
      expected = (1 << bits) - 1;
      if((state & expected) != expected)
	return -1;
    }
  *outoff = off;
  return 0;
}

void huffman_free(huffman_t *hf)
{
  int i;
  for(i=0; i<32; i++)
    if(hf->bits[i].bytes != NULL)
      free(hf->bits[i].bytes);
  free(hf);
  return;
}

huffman_t *huffman_alloc(huffman_entry_t *entries)
{
  huffman_t *hf = NULL;
  size_t counts[32], len, x, b;
  int i;

  memset(counts, 0, sizeof(counts));
  for(i=0; i<256; i++)
    {
      if(entries[i].bits >= 32)
	goto err;
      counts[entries[i].bits]++;
    }

  if((hf = malloc(sizeof(huffman_t))) == NULL)
    goto err;
  memset(hf, 0, sizeof(huffman_t));

  for(i=0; i<32; i++)
    {
      if(counts[i] == 0)
	continue;
      hf->max = i;
      len = counts[i] * sizeof(huffman_byte_t);
      if((hf->bits[i].bytes = malloc(len)) == NULL)
	goto err;
      memset(hf->bits[i].bytes, 0, len);
      hf->bits[i].count = counts[i];
    }

  memset(counts, 0, sizeof(counts));
  for(i=0; i<256; i++)
    {
      b = entries[i].bits;
      x = counts[b];
      hf->bits[b].bytes[x].code = entries[i].code;
      hf->bits[b].bytes[x].val = i;
      counts[b]++;
    }

  return hf;

 err:
  if(hf != NULL) huffman_free(hf);
  return NULL;
}

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_probe.h"
#include "scamper_udp4.h"

typedef struct sc_test
{
  int       (*define)(scamper_probe_t *);
  int       (*build)(scamper_probe_t *, uint8_t *, size_t *);
  const char *out;
} sc_test_t;

static int udp4_define(scamper_probe_t *pr)
{
  static uint8_t data[] = {0xaa, 0xbb, 0xcc, 0xdd};
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    return -1;
  pr->pr_ip_tos   = 0;
  pr->pr_ip_ttl   = 255;
  pr->pr_ip_proto = IPPROTO_UDP;
  pr->pr_ip_id    = 0x1234;
  pr->pr_ip_off   = 0;
  pr->pr_udp_sport = 49713;
  pr->pr_udp_dport = 33435;
  pr->pr_data      = data;
  pr->pr_len       = sizeof(data);

  return 0;
}

int compare(const uint8_t *pktbuf, size_t pktlen, const char *bufstr)
{
  size_t i;
  if(strlen(bufstr) / 2 != pktlen)
    {
      printf("expected %d got %d\n", (int)strlen(bufstr) / 2, (int)pktlen);
      for(i=0; i<pktlen; i++)
	printf("%02x", pktbuf[i]);
      printf("\n");
      return -1;
    }

  return 0;
}

void probe_clean(scamper_probe_t *pr)
{
  if(pr->pr_ip_src != NULL) scamper_addr_free(pr->pr_ip_src);
  if(pr->pr_ip_dst != NULL) scamper_addr_free(pr->pr_ip_dst);
  memset(pr, 0, sizeof(scamper_probe_t));
  return;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {udp4_define, scamper_udp4_build,
     "45000020" "12340000" "ff112595" "c0000201" "c0000202"
     "c231829b" "000cbf6b"
     "aabbccdd"
    }
  };
  size_t i, pktlen, testc = sizeof(tests) / sizeof(sc_test_t);
  scamper_probe_t pr;
  uint8_t pktbuf[1500];

  memset(&pr, 0, sizeof(pr));

  for(i=0; i<testc; i++)
    {
      pktlen = sizeof(pktbuf);
      if(tests[i].define(&pr) != 0 ||
	 tests[i].build(&pr, pktbuf, &pktlen) != 0 ||
	 compare(pktbuf, pktlen, tests[i].out) != 0)
	{
	  printf("test %d failed\n", (int)i);
	  goto err;
	}
      probe_clean(&pr);
    }

  printf("OK\n");
  return 0;

 err:
  return -1;
}

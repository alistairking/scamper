/*
 * scamper_tbit.h
 *
 * $Id: scamper_tbit.h,v 1.65 2023/08/08 06:19:31 mjl Exp $
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2010-2011 University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2012,2015 The Regents of the University of California
 * Copyright (C) 2023      Matthew Luckie
 *
 * This file implements algorithms described in the tbit-1.0 source code,
 * as well as the papers:
 *
 *  "On Inferring TCP Behaviour"
 *      by Jitendra Padhye and Sally Floyd
 *  "Measuring the Evolution of Transport Protocols in the Internet" by
 *      by Alberto Medina, Mark Allman, and Sally Floyd.
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

#ifndef __SCAMPER_TBIT_H
#define __SCAMPER_TBIT_H

/* types of tbit tests */
#define SCAMPER_TBIT_TYPE_PMTUD              1
#define SCAMPER_TBIT_TYPE_ECN                2
#define SCAMPER_TBIT_TYPE_NULL               3
#define SCAMPER_TBIT_TYPE_SACK_RCVR          4
#define SCAMPER_TBIT_TYPE_ICW                5
#define SCAMPER_TBIT_TYPE_ABC                6
#define SCAMPER_TBIT_TYPE_BLIND_DATA         7
#define SCAMPER_TBIT_TYPE_BLIND_RST          8
#define SCAMPER_TBIT_TYPE_BLIND_SYN          9
#define SCAMPER_TBIT_TYPE_BLIND_FIN          10

/* tbit options */
#define SCAMPER_TBIT_OPTION_TCPTS            0x01 /* tcp timestamps */
#define SCAMPER_TBIT_OPTION_SACK             0x02 /* offer use of TCP SACK */

/* application layer protocols supported by the tbit test */
#define SCAMPER_TBIT_APP_HTTP                1
#define SCAMPER_TBIT_APP_SMTP                2
#define SCAMPER_TBIT_APP_DNS                 3
#define SCAMPER_TBIT_APP_FTP                 4
#define SCAMPER_TBIT_APP_BGP                 5

/* for http, either http or https */
#define SCAMPER_TBIT_APP_HTTP_TYPE_HTTP      0
#define SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS     1

/* generic tbit results */
#define SCAMPER_TBIT_RESULT_NONE             0 /* no result */
#define SCAMPER_TBIT_RESULT_TCP_NOCONN       1 /* no connection */
#define SCAMPER_TBIT_RESULT_TCP_RST          2 /* Early reset */
#define SCAMPER_TBIT_RESULT_TCP_ERROR        3 /* TCP Error */
#define SCAMPER_TBIT_RESULT_ERROR            4 /* System error */
#define SCAMPER_TBIT_RESULT_ABORTED          5 /* Test aborted */
#define SCAMPER_TBIT_RESULT_TCP_NOCONN_RST   6 /* no connection: rst rx */
#define SCAMPER_TBIT_RESULT_HALTED           7 /* halted */
#define SCAMPER_TBIT_RESULT_TCP_BADOPT       8 /* bad TCP option */
#define SCAMPER_TBIT_RESULT_TCP_FIN          9 /* early fin */
#define SCAMPER_TBIT_RESULT_TCP_ZEROWIN      10 /* zero window */

/* possible PMTUD test results */
#define SCAMPER_TBIT_RESULT_PMTUD_NOACK      20 /* no ACK of request */
#define SCAMPER_TBIT_RESULT_PMTUD_NODATA     21 /* no data received */
#define SCAMPER_TBIT_RESULT_PMTUD_TOOSMALL   22 /* packets too small */
#define SCAMPER_TBIT_RESULT_PMTUD_NODF       23 /* DF not set (IPv4 only) */
#define SCAMPER_TBIT_RESULT_PMTUD_FAIL       24 /* did not reduce pkt size */
#define SCAMPER_TBIT_RESULT_PMTUD_SUCCESS    25 /* responded correctly */
#define SCAMPER_TBIT_RESULT_PMTUD_CLEARDF    26 /* cleared DF in response */

/* possible ECN test results */
#define SCAMPER_TBIT_RESULT_ECN_SUCCESS      30 /* responded correctly */
#define SCAMPER_TBIT_RESULT_ECN_INCAPABLE    31 /* no ece on syn/ack */
#define SCAMPER_TBIT_RESULT_ECN_BADSYNACK    32 /* bad syn/ack */
#define SCAMPER_TBIT_RESULT_ECN_NOECE        33 /* no ECN echo */
#define SCAMPER_TBIT_RESULT_ECN_NOACK        34 /* no ack of request */
#define SCAMPER_TBIT_RESULT_ECN_NODATA       35 /* no data received */

/* possible NULL test results */
#define SCAMPER_TBIT_RESULT_NULL_SUCCESS     40 /* responded correctly */
#define SCAMPER_TBIT_RESULT_NULL_NODATA      41 /* no data received */

/* possible SACK-RCVR test results */
#define SCAMPER_TBIT_RESULT_SACK_INCAPABLE      50 /* not capable of SACK */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_SUCCESS   51 /* responded correctly */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_SHIFTED   52 /* shifted sack blocks */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_TIMEOUT   53 /* missing ack */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_NOSACK    54 /* missing sack blocks */

/* possible ICW test results */
#define SCAMPER_TBIT_RESULT_ICW_SUCCESS      60 /* estimate of ICW */
#define SCAMPER_TBIT_RESULT_ICW_TOOSHORT     61 /* not enough data to infer */

/* possible ABC test results */
#define SCAMPER_TBIT_RESULT_ABC_SUCCESS      70 /* ABC test successful */
#define SCAMPER_TBIT_RESULT_ABC_TOOSHORT     71 /* not enough data to infer */
#define SCAMPER_TBIT_RESULT_ABC_BADICW       72 /* apparent bad ICW */

/* possible blind test results */
#define SCAMPER_TBIT_RESULT_BLIND_ACCEPTED   80 /* blind packet accepted */
#define SCAMPER_TBIT_RESULT_BLIND_CHALLENGE  81 /* challenge ack */
#define SCAMPER_TBIT_RESULT_BLIND_IGNORED    82 /* no effect */
#define SCAMPER_TBIT_RESULT_BLIND_RST        83 /* reset for blinded packet */
#define SCAMPER_TBIT_RESULT_BLIND_SYNNEW     84 /* new S/A for blinded syn */

/* direction of recorded packet */
#define SCAMPER_TBIT_PKT_DIR_TX              1
#define SCAMPER_TBIT_PKT_DIR_RX              2

/* pmtud options */
#define SCAMPER_TBIT_PMTUD_OPTION_BLACKHOLE  0x1 /* test blackhole behaviour */

/* null options */
#define SCAMPER_TBIT_NULL_OPTION_TCPTS       0x01 /* tcp timestamps */
#define SCAMPER_TBIT_NULL_OPTION_IPTS_SYN    0x02 /* IP TS option on SYN */
#define SCAMPER_TBIT_NULL_OPTION_IPRR_SYN    0x04 /* IP RR option on SYN */
#define SCAMPER_TBIT_NULL_OPTION_IPQS_SYN    0x08 /* IP QS option on SYN */
#define SCAMPER_TBIT_NULL_OPTION_SACK        0x10 /* offer use of TCP SACK */
#define SCAMPER_TBIT_NULL_OPTION_FO          0x20 /* offer use of TCP FO */
#define SCAMPER_TBIT_NULL_OPTION_FO_EXP      0x40 /* offer use of TCP FO-exp */

/* null results */
#define SCAMPER_TBIT_NULL_RESULT_TCPTS       0x01 /* TCP timestamps OK */
#define SCAMPER_TBIT_NULL_RESULT_SACK        0x02 /* use of TCP SACK OK */
#define SCAMPER_TBIT_NULL_RESULT_FO          0x04 /* use of TCP FO OK */

typedef struct scamper_tbit scamper_tbit_t;
typedef struct scamper_tbit_pkt scamper_tbit_pkt_t;
typedef struct scamper_tbit_app_http scamper_tbit_app_http_t;
typedef struct scamper_tbit_app_bgp scamper_tbit_app_bgp_t;
typedef struct scamper_tbit_pmtud scamper_tbit_pmtud_t;
typedef struct scamper_tbit_null scamper_tbit_null_t;
typedef struct scamper_tbit_icw scamper_tbit_icw_t;
typedef struct scamper_tbit_blind scamper_tbit_blind_t;

/* scamper_tbit_t functions */
void scamper_tbit_free(scamper_tbit_t *tbit);
scamper_list_t *scamper_tbit_list_get(const scamper_tbit_t *tbit);
scamper_cycle_t *scamper_tbit_cycle_get(const scamper_tbit_t *tbit);
uint32_t scamper_tbit_userid_get(const scamper_tbit_t *tbit);
scamper_addr_t *scamper_tbit_src_get(const scamper_tbit_t *tbit);
scamper_addr_t *scamper_tbit_dst_get(const scamper_tbit_t *tbit);
uint16_t scamper_tbit_sport_get(const scamper_tbit_t *tbit);
uint16_t scamper_tbit_dport_get(const scamper_tbit_t *tbit);
const struct timeval *scamper_tbit_start_get(const scamper_tbit_t *tbit);
uint16_t scamper_tbit_result_get(const scamper_tbit_t *tbit);
char *scamper_tbit_result_tostr(const scamper_tbit_t *tbit,char *buf,size_t len);
scamper_tbit_pkt_t *scamper_tbit_pkt_get(const scamper_tbit_t *tbit,uint32_t i);
uint32_t scamper_tbit_pktc_get(const scamper_tbit_t *tbit);
uint8_t scamper_tbit_type_get(const scamper_tbit_t *tbit);
char *scamper_tbit_type_tostr(const scamper_tbit_t *tbit,char *buf, size_t len);
uint8_t scamper_tbit_app_proto_get(const scamper_tbit_t *tbit);
uint32_t scamper_tbit_options_get(const scamper_tbit_t *tbit);
uint16_t scamper_tbit_client_mss_get(const scamper_tbit_t *tbit);
const uint8_t *scamper_tbit_client_fo_cookie_get(const scamper_tbit_t *tbit);
uint8_t scamper_tbit_client_fo_cookielen_get(const scamper_tbit_t *tbit);
uint8_t scamper_tbit_client_wscale_get(const scamper_tbit_t *tbit);
uint8_t scamper_tbit_client_ipttl_get(const scamper_tbit_t *tbit);
uint8_t scamper_tbit_client_syn_retx_get(const scamper_tbit_t *tbit);
uint8_t scamper_tbit_client_dat_retx_get(const scamper_tbit_t *tbit);
uint16_t scamper_tbit_server_mss_get(const scamper_tbit_t *tbit);
int scamper_tbit_server_fo_cookie_get(scamper_tbit_t *tbit,
				      uint8_t *cookie, uint8_t *len);
int scamper_tbit_type_isblind(const scamper_tbit_t *tbit);

/* scamper_tbit_pkt_t functions */
void scamper_tbit_pkt_free(scamper_tbit_pkt_t *pkt);
const struct timeval *scamper_tbit_pkt_tv_get(const scamper_tbit_pkt_t *pkt);
uint8_t scamper_tbit_pkt_dir_get(const scamper_tbit_pkt_t *pkt);
uint16_t scamper_tbit_pkt_len_get(const scamper_tbit_pkt_t *pkt);
const uint8_t *scamper_tbit_pkt_data_get(const scamper_tbit_pkt_t *pkt);
int scamper_tbit_pkt_tcpdatabytes_get(const scamper_tbit_pkt_t *pkt,
				      uint16_t *bc);
int scamper_tbit_pkt_tcpack_get(const scamper_tbit_pkt_t *pkt, uint32_t *ack);

/* scamper_tbit_app_http_t functions */
scamper_tbit_app_http_t *scamper_tbit_app_http_get(const scamper_tbit_t *tbit);
uint8_t scamper_tbit_app_http_type_get(const scamper_tbit_app_http_t *http);
const char *scamper_tbit_app_http_host_get(const scamper_tbit_app_http_t *http);
const char *scamper_tbit_app_http_file_get(const scamper_tbit_app_http_t *http);

/* scamper_tbit_app_bgp_t functions */
scamper_tbit_app_bgp_t *scamper_tbit_app_bgp_get(const scamper_tbit_t *tbit);
uint32_t scamper_tbit_app_bgp_asn_get(const scamper_tbit_app_bgp_t *bgp);

/* scamper_tbit_pmtud_t functions */
scamper_tbit_pmtud_t *scamper_tbit_pmtud_get(const scamper_tbit_t *tbit);
uint16_t scamper_tbit_pmtud_mtu_get(const scamper_tbit_pmtud_t *pmtu);
uint8_t scamper_tbit_pmtud_ptb_retx_get(const scamper_tbit_pmtud_t *pmtu);
uint8_t scamper_tbit_pmtud_options_get(const scamper_tbit_pmtud_t *pmtu);
scamper_addr_t *scamper_tbit_pmtud_ptbsrc_get(const scamper_tbit_pmtud_t *pmtu);

/* scamper_tbit_null_t functions */
scamper_tbit_null_t *scamper_tbit_null_get(const scamper_tbit_t *tbit);
uint32_t scamper_tbit_null_options_get(const scamper_tbit_null_t *n);
uint32_t scamper_tbit_null_results_get(const scamper_tbit_null_t *n);

/* scamper_tbit_icw_t functions */
scamper_tbit_icw_t *scamper_tbit_icw_get(const scamper_tbit_t *tbit);
uint32_t scamper_tbit_icw_start_seq_get(const scamper_tbit_icw_t *icw);
int scamper_tbit_server_icw_size_get(const scamper_tbit_t *tbit,uint32_t *size);

/* scamper_tbit_blind_t functions */
scamper_tbit_blind_t *scamper_tbit_blind_get(const scamper_tbit_t *tbit);
int32_t scamper_tbit_blind_off_get(const scamper_tbit_blind_t *blind);
uint8_t scamper_tbit_blind_retx_get(const scamper_tbit_blind_t *blind);

/*
 * scamper_tbit_stats
 *
 * give some idea about what took place during the tbit measurement.
 */
typedef struct scamper_tbit_stats scamper_tbit_stats_t;
const struct timeval *scamper_tbit_stats_synack_rtt_get(const scamper_tbit_stats_t *stats);
uint32_t scamper_tbit_stats_rx_xfersize_get(const scamper_tbit_stats_t *stats);
uint32_t scamper_tbit_stats_rx_totalsize_get(const scamper_tbit_stats_t *stats);
const struct timeval *scamper_tbit_stats_xfertime_get(const scamper_tbit_stats_t *stats);

scamper_tbit_stats_t *scamper_tbit_stats_alloc(const scamper_tbit_t *tbit);
void scamper_tbit_stats_free(scamper_tbit_stats_t *stats);

#endif /* __SCAMPER_TBIT_H */

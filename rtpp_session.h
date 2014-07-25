/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2007 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: rtpp_session.h,v 1.17 2008/12/24 10:46:03 sobomax Exp $
 *
 */

#ifndef _RTPP_SESSION_H_
#define _RTPP_SESSION_H_

#include <sys/types.h>
#include <sys/socket.h>
#include "rtpp_defines.h"
#include "rtp_server.h"
#include "rtp_resizer.h"

#include "rtp_transcoder.h"
#include "rtpp_srtp.h"
#include "rtpp_mem.h"
#include "rtpp_dtls.h"
#include "openssl/bio.h"
#include "rtpp_stun.h"

/* DROP RTP PACKETS until the bridge is setup by CMD/STUN/DTLS */
#define RTPP_CMD_DROP_RTP  1
#define RTPP_STUN_DROP_RTP 2
#define RTPP_DTLS_DROP_RTP 3


struct rtpp_timeout_data {
    char *notify_tag;
    struct rtpp_timeout_handler *handler;
};

struct remote_ice_candidate {
    struct sockaddr_in *addr;
    int port;
    double priority;
    struct remote_ice_candidate *prev;
    struct remote_ice_candidate *next;
};

struct ice_user {
    char* local_user_name;
    char* local_password;
	char* remote_user_name;
	char* remote_password;
};


struct rtpp_session {
    /* ttl for caller [0] and callee [1] */
    int ttl[2];
    rtpp_ttl_mode ttl_mode;
    unsigned long pcount[4];
    char *call_id;
    char *tag;
    rtpp_log_t log;
    struct rtpp_session* rtcp;
    struct rtpp_session* rtp;
    /* Remote source addresses, one for caller and one for callee */
    struct sockaddr *addr[2];
    /* Save previous address when doing update */
    struct sockaddr *prev_addr[2];
    /* Flag which tells if we are allowed to update address with RTP src IP */
    int canupdate[2];
    /* Local listen addresses/ports */
    struct sockaddr *laddr[2];
    int ports[2];
    int has_video;
    /* Descriptors */
    int fds[2];
    /* DTLS streams */
    rtpp_stream *stream[2];
    bool dtls_pending;
    /* Session is complete, that is we received both request and reply */
    int complete;
    int asymmetric[2];
    /* Flags: strong create/delete; weak ones */
    int strong;
    int weak[2];
    /* Pointers to rtpp_record's opaque data type */
    void *rrcs[2];
    struct rtp_server *rtps[2];
    /* References to fd-to-session table */
    int sidx[2];
    /* Reference to active RTP generators table */
    int sridx;
    /* Flag that indicates whether or not address supplied by client can't be trusted */
    int untrusted_addr[2];
    struct rtp_resizer resizers[2];
    /* value that indicates whether session is on hold */
    int isCallOnHold;
    struct rtpp_session *prev;
    struct rtpp_session *next;
    struct rtpp_timeout_data timeout_data;
    struct rtp_transcoder trans[2];
    int transcode;
    struct rtpp_srtp_context srtp[2];
    int secure;
    /* Timestamp of the last session update */
    double last_update[2];
    /* Supported codecs */
    char *codecs[2];
    //Drop Packets till bridge is created fully for RTP<->SRTP or SRTP(SDES)<->SRTP(MIKEY) interworking.
    int drop_rtp_packets;
    // VLAN Support (FRN4811)
    struct sockaddr *bridgeBindAddr[2];

    // list of from and to codecs, one for each pidx
    rtp_transcoder_codecLists rtp_trans_codeclists[2];

    struct      rtp_data_list rsz_pckt_list[2];
    uint32_t    incr_pkt_ts[2];
    int         marker_status[2];
    // ICE candidate support
    struct remote_ice_candidate *ice_candidate_list[2];
    struct ice_user *ice_u[2];

    // Stun support
    rtpp_stun_agent *agent;
};


// ICE candidates support
struct remote_ice_candidate *find_ice_candidate(struct rtpp_session *, int ridx, struct sockaddr *, int addr_len);
void append_ice_candidate(struct cfg *, struct remote_ice_candidate **, struct remote_ice_candidate **);
void delete_ice_candidate(struct rtpp_session *, int ridx);

void init_hash_table(struct cfg *);
struct rtpp_session *session_findfirst(struct cfg *, char *);
struct rtpp_session *session_findnext(struct rtpp_session *);
void hash_table_append(struct cfg *, struct rtpp_session *);
void append_session(struct cfg *, struct rtpp_session *, int);
void remove_session(struct cfg *, struct rtpp_session *);
int compare_session_tags(char *, char *, unsigned *);
int find_stream(struct cfg *, char *, char *, char *, struct rtpp_session **);
void do_timeout_notification(struct rtpp_session *, int);
int get_ttl(struct rtpp_session *);
void clean_session_rsz_pkt_list(struct rtpp_session *, int);
void remove_session_frm_active_rsz_lst(struct rtpp_session *sp);

#endif

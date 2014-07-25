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
 * $Id: rtpp_command.c,v 1.24.2.2 2009/10/06 09:51:28 sobomax Exp $
 *
 */

#include "config.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_ALLOCA_H
    #include <alloca.h>
#endif
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_command.h"
#include "rtpp_log.h"
#include "rtpp_record.h"
#include "rtpp_session.h"
#include "rtpp_util.h"
#include "rtpp_dtls.h"
#include "ssl_identity.h"
#include "openssl/bio.h"
#include "rtpp_mem.h"
#include "rtpp_parse.h"

extern struct rtp_data_list* active_resized_sp_list;
extern int g_use_timed_resizer;

#ifdef DEBUG
    #include <arpa/inet.h>
#endif

#ifdef DEBUG
extern FILE *tfp;

static void trace_session(struct rtpp_session *sp)
{
#if 0
    struct rtpp_session
    {
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
        /* Descriptors */
        int fds[2];
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
        int drop_rtp_packets, fix_srtp_seq, maintain_bridge_params;
    };
#endif
    if (tfp)
    {
        fprintf(tfp, "Tracing Session: %p\n", sp);
        if (!sp)return;
        fprintf(tfp, "ttl[0]: %d, ttl[1]: %d, ttl_mode: %d\n", sp->ttl[0], sp->ttl[1], (int)sp->ttl_mode);
        fprintf(tfp, "packet counts: %lu, %lu, %lu, %lu\n", sp->pcount[0], sp->pcount[1], sp->pcount[2], sp->pcount[3]);
        fprintf(tfp, "Call ID: %s, tag: %s\n", (sp->call_id?sp->call_id:"NULL"), (sp->tag?sp->tag:"NULL"));
        fprintf(tfp, "RTCP Session Pointer: %p, RP Session Pointer: %p\n", sp->rtcp, sp->rtp);
        fprintf(tfp, "Address[0]: %s:%d,  Address[1]: %s:%d\n",
                sp->addr[0]?addr2char(sp->addr[0]):NULL, sp->addr[0]?addr2port(sp->addr[0]):0,
                sp->addr[1]?addr2char(sp->addr[1]):NULL, sp->addr[1]?addr2port(sp->addr[1]):0);
        fprintf(tfp, "Prev Address[0]: %s:%d,  Prev Address[1]: %s:%d\n",
                sp->prev_addr[0]?addr2char(sp->prev_addr[0]):NULL, sp->prev_addr[0]?addr2port(sp->prev_addr[0]):0,
                sp->prev_addr[1]?addr2char(sp->prev_addr[1]):NULL, sp->prev_addr[1]?addr2port(sp->prev_addr[1]):0);
        fprintf(tfp, "Local Address[0]: %s:%d,  Local Address[1]: %s:%d\n",
                sp->laddr[0]?addr2char(sp->laddr[0]):NULL, sp->laddr[0]?addr2port(sp->laddr[0]):0,
                sp->laddr[1]?addr2char(sp->laddr[1]):NULL, sp->laddr[1]?addr2port(sp->laddr[1]):0);
        fprintf(tfp, "FD:port 0: %d:%d, FD:port 1: %d:%d\n", sp->fds[0], sp->ports[0], sp->fds[1], sp->ports[1]);
        fprintf(tfp, "Session %s complete, %s strong\n", sp->complete?"is":"is NOT", sp->strong?"is":"is NOT");
        fprintf(tfp, "asymmetric 0: %d, asymmetric 1: %d\n", sp->asymmetric[0], sp->asymmetric[1]);
        fprintf(tfp, "weak 0: %d, weak 1: %d\n", sp->weak[0], sp->weak[1]);
        fprintf(tfp, "sidx 0: %d, sidx 1: %d\n", sp->sidx[0], sp->sidx[1]);
        fprintf(tfp, "untrusted_addr 0: %d, untrusted_addr 1: %d\n", sp->untrusted_addr[0], sp->untrusted_addr[1]);
        fprintf(tfp, "Is secure: %d drop_rtp_packets :%d\n", sp->secure,sp->drop_rtp_packets);
        fprintf(tfp, "SRTP[0]: rcv_hdl Policy:srtp %p:%p\n", sp->srtp[0].rcv_hdl.policy, sp->srtp[0].rcv_hdl.srtp);
        fprintf(tfp, "SRTP[0]: snd_hdl Policy:srtp %p:%p\n", sp->srtp[0].snd_hdl.policy, sp->srtp[0].snd_hdl.srtp);
        fprintf(tfp, "SRTP[1]: rcv_hdl Policy:srtp %p:%p\n", sp->srtp[1].rcv_hdl.policy, sp->srtp[1].rcv_hdl.srtp);
        fprintf(tfp, "SRTP[1]: snd_hdl Policy:srtp %p:%p\n", sp->srtp[1].snd_hdl.policy, sp->srtp[1].snd_hdl.srtp);
    }
}
#endif

#ifdef DEBUG
static unsigned char *bin_to_hex(unsigned char *dest, size_t dest_len, unsigned char *src, size_t src_len)
{
    if (dest_len < 3)
    {
        if (dest_len > 0)
            dest[0] = '\0';
        return dest;
    }

    size_t max = (dest_len - 1)/2;
    if (max > src_len)max = src_len;

    size_t didx = 0;
    for (size_t idx = 0; idx < max; ++idx)
    {
        unsigned char c = src[idx] >> 4;
        if (c < 10)
            dest[didx++] = ('0' + c);
        else
            dest[didx++] = ('A' + (c - 10));

        c = src[idx] & 0x0f;
        if (c < 10)
            dest[didx++] = ('0' + c);
        else
            dest[didx++] = ('A' + (c - 10));
    }
    dest[didx] = '\0';

    return dest;
}

#endif

struct proto_cap proto_caps[] = {
    /*
     * The first entry must be basic protocol version and isn't shown
     * as extension on -v.
     */
    { "20040107", "Basic RTP proxy functionality"},
    { "20050322", "Support for multiple RTP streams and MOH"},
    { "20060704", "Support for extra parameter in the V command"},
    { "20071116", "Support for RTP re-packetization"},
    { "20071218", "Support for forking (copying) RTP stream"},
    { "20080403", "Support for RTP statistics querying"},
    { "20081102", "Support for setting codecs in the update/lookup command"},
    { "20081224", "Support for session timeout notifications"},
    { NULL, NULL}
};


static int create_twinlistener(struct cfg *, struct sockaddr *, int, int *, int);
static int create_listener(struct cfg *, struct sockaddr *, int *, int *, int);
static int create_video_listener(struct cfg *, struct sockaddr *, int *, int *, int);
static int handle_delete(struct cfg *, char *, char *, char *, int);
static void handle_noplay(struct cfg *, struct rtpp_session *, int);
static int handle_play(struct cfg *, struct rtpp_session *, int, char *, char *, int);
static void handle_copy(struct cfg *, struct rtpp_session *, int, char *);
static int handle_record(struct cfg *, char *, char *, char *);
static void handle_query(struct cfg *, int, struct sockaddr_storage *,
                         socklen_t, char *, struct rtpp_session *, int);

static int bind_to_device(struct cfg *cf, int fd, char *networkId);

extern int g_rtp_ctrace_enabled;

static int
create_twinlistener(struct cfg *cf, struct sockaddr *ia, int port, int *fds, int tos)
{
    struct sockaddr_storage iac;
    int rval, i, flags;

    fds[0] = fds[1] = -1;

    rval = -1;
    for (i = 0; i < 2; i++)
    {
        fds[i] = socket(ia->sa_family, SOCK_DGRAM, 0);
        if (fds[i] == -1)
        {
            rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog, "can't create %s socket",
                            (ia->sa_family == AF_INET) ? "IPv4" : "IPv6");
            goto failure;
        }
        memcpy(&iac, ia, SA_LEN(ia));
        satosin(&iac)->sin_port = htons(port);

        if (bind(fds[i], sstosa(&iac), SA_LEN(ia)) != 0)
        {
#if 0
            rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog, "1 can't bind to the %s port %d errno:%d",
                            (ia->sa_family == AF_INET) ? "IPv4" : "IPv6", port, errno);

            fprintf(tfp," 1 can't bind to the %s port %d errno:%d",
                    (ia->sa_family == AF_INET) ? "IPv4" : "IPv6", port, errno);
#endif
            if (errno != EADDRINUSE && errno != EACCES)
            {
                rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog, "can't bind to the %s port %d",
                                (ia->sa_family == AF_INET) ? "IPv4" : "IPv6", port);
            }
            else
            {
                rval = -2;
            }
            goto failure;
        }
        port++;
        if ((ia->sa_family == AF_INET) && (tos >= 0) &&
            (setsockopt(fds[i], IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1))
            rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog, "unable to set TOS to %d", tos);

        flags = fcntl(fds[i], F_GETFL);
        if(flags != -1)
          fcntl(fds[i], F_SETFL, flags | O_NONBLOCK);

    }
    return 0;

failure:
    for (i = 0; i < 2; i++)
        if (fds[i] != -1)
        {
            close(fds[i]);
            fds[i] = -1;
        }
    return rval;
}

static int
create_listener_ext(struct cfg *cf, struct sockaddr *ia, int *port, int *fds, int qos, bool video)
{
    int i, idx, rval;

    int32_t   port_min;
    int32_t   port_max;
    int16_t   port_table_len;
    int16_t  *port_table_idx;
    uint16_t *port_table;
    int32_t   cf_tos;

    for (i = 0; i < 2; i++)
        fds[i] = -1;

    rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                   "create_listener: ia: %s", addr2char(ia));
    if(!video || !cf->video_port_table_len )
    {
        port_min       =  cf->port_min;
        port_max       =  cf->port_max;
        port_table_len =  cf->port_table_len;
        port_table_idx = &cf->port_table_idx;
        port_table     =  cf->port_table;
    }
    else
    { 
        port_min       =  cf->video_port_min;
        port_max       =  cf->video_port_max;
        port_table_len =  cf->video_port_table_len;
        port_table_idx = &cf->video_port_table_idx;
        port_table     =  cf->video_port_table;
    }
    cf_tos = video?cf->video_tos:cf->tos;

    if( *port )
    { /*Use the Assigned Port*/
        if (*port < port_min || *port > port_max)
        {
            rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog, "Assigned Port(%d) is out of Range", *port);
            return -1;
        }
        rval = create_twinlistener(cf, ia, *port, fds, qos?qos:cf_tos);
        if (rval == 0)
            return 0;

        return -1;
    }
   /* Assign the Port*/
    for (i = 1; i < port_table_len; i++)
    {
        idx = (*port_table_idx + i) % port_table_len;
        *port = *(port_table + idx);
        rval = create_twinlistener(cf, ia, *port, fds, qos?qos:cf_tos);
        if (rval == 0)
        {
            *port_table_idx = idx;
            return 0;
        }
        if (rval == -1)
            break;
    }
    return -1;
}

#define create_listener(cf,ia,port,fds,qos)       create_listener_ext(cf,ia,port,fds,qos,0)
#define create_video_listener(cf,ia,port,fds,qos) create_listener_ext(cf,ia,port,fds,qos,1)

static void doreply(struct cfg *cf, int fd, char *buf, int len,
        struct sockaddr_storage *raddr, socklen_t rlen)
{
    if (buf==NULL || len == 0 || cf==NULL)
    {
        rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                       "input null buflen = %d", len);
        return;
    }

    buf[len] = '\0';
    rtpp_log_write(RTPP_LOG_INFO, cf->glog, "sending reply \"%s\"", buf);
    if (cf->umode == 0)
    {
        ssize_t unused;
        unused = write(fd, buf, len);
    }
    else
    {
        while (sendto(fd, buf, len, 0, sstosa(raddr),
                      rlen) == -1 && errno == ENOBUFS);
    }
}

static void reply_number(struct cfg *cf, int fd, struct sockaddr_storage *raddr,
             socklen_t rlen, char *cookie, int number)
{
    int len;
    char buf[1024 * 8];

    if (cookie != NULL)
        len = sprintf(buf, "%s %d\n", cookie, number);
    else
    {
        len = sprintf(buf, "%d\n", number);
    }
    doreply(cf, fd, buf, len, raddr, rlen);
}

static void
reply_ok(struct cfg *cf, int fd, struct sockaddr_storage *raddr,
         socklen_t rlen, char *cookie)
{

    reply_number(cf, fd, raddr, rlen, cookie, 0);
}

static void reply_port(struct cfg *cf, int fd, struct sockaddr_storage *raddr,
                       socklen_t rlen, char *cookie, int lport, struct sockaddr **lia, unsigned char *fp)
{
    int tlen, len;
    char buf[1024 * 8], *cp;

    cp = buf;
    len = 0;
    tlen = 0;
    if (cookie != NULL)
    {
        len = sprintf(cp, "%s ", cookie);
        cp += len;
        tlen += len;
    }
    if (lia[0] == NULL || ishostnull(lia[0]))
    {
        len = sprintf(cp, "%d\n", lport);
        cp += len;
        tlen += len;
    }
    else
    {
        len = sprintf(cp, "%d %s%s", lport, addr2char(lia[0]),
                       (lia[0]->sa_family == AF_INET) ? "" : " 6");
        cp += len;
        tlen += len;
    }
    if (fp != NULL)
    {
        len = sprintf(cp, " %s\n", (char *)fp);
        tlen += len;
    }
    doreply(cf, fd, buf, tlen, raddr, rlen);
}

static void reply_error(struct cfg *cf, int fd, struct sockaddr_storage *raddr,
            socklen_t rlen, char *cookie, int ecode)
{
    int len;
    char buf[1024 * 8];

    if (cookie != NULL)
        len = sprintf(buf, "%s E%d\n", cookie, ecode);
    else
        len = sprintf(buf, "E%d\n", ecode);
    doreply(cf, fd, buf, len, raddr, rlen);
}

static void handle_nomem(struct cfg *cf, int fd, struct sockaddr_storage *raddr,
             socklen_t rlen, char *cookie, int ecode, struct sockaddr **ia, int *fds,
             struct rtpp_session *spa, struct rtpp_session *spb)
{
    int i;

    rtpp_log_write(RTPP_LOG_ERR, cf->glog, "can't allocate memory");
    if (spa && spa->secure)
    {
        rtpp_srtp_free_context(&spa->srtp[0]);
        rtpp_srtp_free_context(&spa->srtp[1]);
    }
    if (spb && spb->secure)
    {
        rtpp_srtp_free_context(&spb->srtp[0]);
        rtpp_srtp_free_context(&spb->srtp[1]);
    }
    for (i = 0; i < 2; i++)
    {
        if (ia[i] != NULL)
        {
            free(ia[i]);
        }
    }
    if (spa != NULL)
    {
        if (spa->call_id != NULL)
        {
            free(spa->call_id);
        }
        free(spa);
    }
    if (spb != NULL)
    {
        free(spb);
    }
    for (i = 0; i < 2; i++)
    {
        if (fds[i] != -1)
        {
            close(fds[i]);
        }
    }
    reply_error(cf, fd, raddr, rlen, cookie, ecode);
}

void free_ice_user_pass(struct ice_user **ice_user_pass)
{
    if (*ice_user_pass != NULL)
    {
        free((*ice_user_pass)->local_user_name);
        free((*ice_user_pass)->local_password);
        free((*ice_user_pass)->remote_user_name);
        free((*ice_user_pass)->remote_password);
        free(*ice_user_pass);
        *ice_user_pass = NULL;
    }
}
int handle_command(struct cfg *cf, int controlfd, double dtime)
{
    int len, argc, i, j, pidx, asymmetric, dtls;
    int wcandidate_side;
    int external, pf, lidx, playcount, weak;
    int fds[2], lport, n;
    socklen_t rlen;
    char buf[1024 * 8];
    char *cp, *call_id, *from_tag, *to_tag, *addr, *port, *cookie;
    char *pname, *codecs, *recording_name, *t;
    struct rtpp_session *spa, *spb;
    char **ap, *argv[60];
    const char *rname;
    struct sockaddr *ia[2], *lia[2];
    struct sockaddr_storage raddr;
    int requested_nsamples, requested_nsamples_from, requested_nsamples_to;
    int callHoldIndicator = 0;
    enum
    {
        DELETE, RECORD, PLAY, NOPLAY, COPY, UPDATE, LOOKUP, QUERY, REFRESH, WCANDIDATE
    } op;
    int max_argc, refresh_ttl;
    char *socket_name_u, *notify_tag, *s_mapped_port, temp_cookie[128];
    char  s_trans_codec[256],  s_trans_payload[64], s_trans_ptime[64];
    char* s_cn, *s_qos;
    char* pargv;
    int transcode,codec_from, payload_from, codec_to, payload_to, secure, cn_payload, processTrans, is_video_session;
    int ptime_from, ptime_to;

    int codec_from_nidx, payload_from_nidx, codec_to_nidx, payload_to_nidx;
    int retval=0;

    short int argindx, arg_min;
    char dummy_addr[64]="127.0.1.1";

    int drop_rtp_packets,fix_srtp_seq,maintain_bridge_params, qos;
    uint32_t rcv_ssrc, snd_ssrc, prcv_ssrc, psnd_ssrc;
    unsigned char *rcv_key, *snd_key, *prcv_key, *psnd_key;
    unsigned char *drcv_fp, *dsnd_fp, *dprcv_fp, *dpsnd_fp;
    dtls_fingerprint dsnd_fp_int, dpsnd_fp_int;
    short int rcv_suite, snd_suite, prcv_suite, psnd_suite,comfort_noise_disable;
    short int rcv_attr, snd_attr, prcv_attr, psnd_attr;
    dtls = 0;

    pname = codecs = recording_name =t = NULL;
    int bckVerCodecCmd=0;
    requested_nsamples = requested_nsamples_from = requested_nsamples_to = -1;
    is_video_session = 0;
    ia[0] = ia[1] = NULL;
    spa = spb = NULL;
    lia[0] = lia[1] = cf->bindaddr[0];
    lidx = 1;
    fds[0] = fds[1] = -1;
    recording_name = NULL;
    socket_name_u = notify_tag = NULL ;
    s_cn = s_qos = NULL;
    comfort_noise_disable = 1;
    cn_payload= PT_CODEC_COMFORT_NOISE;
    wcandidate_side = -1;

    // VLAN Support (FRN4811)
    int isBridgeModifierPresent = 0;
    char bridgeBindNetworkId[MAX_NETWORK_ID_LEN];
    char bridgeBindIpAddr[MAX_IP_ADDR_LEN];
    int isBridgeBindIpV6 = 0;
    struct sockaddr_storage bridgeBindAddr;
    struct sockaddr *pBridgeBindAddr = (struct sockaddr *)&bridgeBindAddr;

    // ICE support
    struct remote_ice_candidate *rtp_ice_candidate = NULL;
    struct remote_ice_candidate *rtcp_ice_candidate = NULL;
    struct ice_user *ice_user_pass = NULL;


    if (cf->umode == 0)
    {
        for (;;)
        {
            len = read(controlfd, buf, sizeof(buf) - 1);
            if (len != -1 || (errno != EAGAIN && errno != EINTR))
                break;
            sched_yield();
        }
    }
    else
    {
        rlen = sizeof(raddr);
        len = recvfrom(controlfd, buf, sizeof(buf) - 1, 0,
                       sstosa(&raddr), &rlen);
        rtpp_log_write(RTPP_LOG_DBUG, cf->glog, "Finished recvfrom controlfd, len=%d", len);
    }
    if (len == -1)
    {
        rtpp_log_ewrite(RTPP_LOG_DBUG, cf->glog, "Error number: %d %s", errno, strerror(errno));
        if (errno != EAGAIN && errno != EINTR)
            rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog, "can't read from control socket");
        return -1;
    }
    buf[len] = '\0';
#ifdef DEBUG
    if (tfp)
    {
        fprintf(tfp, "Received command: \"%s\"\n", buf);
    }
#endif

    rtpp_log_write(RTPP_LOG_INFO, cf->glog, "received command \"%s\"", buf);
    cp = buf;
    argc = 0;
    s_mapped_port=NULL;
    rcv_attr = snd_attr = prcv_attr = psnd_attr = 0;
    rcv_suite = snd_suite = prcv_suite = psnd_suite = 1;
    rcv_ssrc = snd_ssrc = prcv_ssrc = psnd_ssrc = 0;
    rcv_key = snd_key = prcv_key = psnd_key = NULL;
    drcv_fp = dsnd_fp = dprcv_fp = dpsnd_fp = NULL;
    codec_from = payload_from = codec_to = payload_to = -1;
    codec_from_nidx=payload_from_nidx= codec_to_nidx= payload_to_nidx=-1;
    transcode = secure = 0;

    memset(argv, 0, sizeof(argv));
    memset(temp_cookie, 0, 128);
    for (ap = argv; (*ap = rtpp_strsep(&cp, "\r\n\t ")) != NULL;)
    {
        if (**ap != '\0')
        {
            argc++;
            if (++ap >= &argv[48])
                break;
        }
    }
    cookie = NULL;
    if (argc < 1 || (cf->umode != 0 && argc < 2))
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
        reply_error(cf, controlfd, &raddr, rlen, cookie, 0);
        return 0;
    }
    /* Stream communication mode doesn't use cookie */
    if (cf->umode != 0)
    {
        strncpy(temp_cookie, argv[0],MIN(128,strlen(argv[0])));
        cookie = temp_cookie;
        for (i = 1; i < argc; i++)
            argv[i - 1] = argv[i];
        argc--;
        argv[argc] = NULL;
    }
    else
    {
        cookie = NULL;
    }
    addr = port = NULL;
    refresh_ttl =0;
    argindx =0;
    switch (argv[0][0])
    {
    case 'u':
    case 'U':
        /* U[opts] callid remote_ip remote_port from_tag [to_tag] */
        op = UPDATE;
        rname = "update/create";
        break;
    case 'l':
    case 'L':
        op = LOOKUP;
        rname = "lookup";
        break;
    case 'd':
    case 'D':
        op = DELETE;
        rname = "delete";
        break;
    case 'p':
    case 'P':
        /*
         * P callid pname codecs from_tag to_tag
         *
         *   <codecs> could be either comma-separated list of supported
         *   payload types or word "session" (without quotes), in which
         *   case list saved on last session update will be used instead.
         */
        op = PLAY;
        rname = "play";
        playcount = 1;
        pname = argv[2];
        codecs = argv[3];
        break;
    case 'r':
    case 'R':
        op = RECORD;
        rname = "record";
        break;
    case 'c':
    case 'C':
        op = COPY;
        rname = "copy";
        break;
    case 's':
    case 'S':
        op = NOPLAY;
        rname = "noplay";
        break;
    case 'v':
    case 'V':
        if (argv[0][1] == 'F' || argv[0][1] == 'f')
        {
            int i, known;
            /*
             * Wait for protocol version datestamp and check whether we
             * know it.
             */
            if (argc != 2 && argc != 3)
            {
                rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
                reply_error(cf, controlfd, &raddr, rlen, cookie, 2);
                return 0;
            }
            /*
             * Only list 20081224 protocol mod as supported if
             * user actually enabled notification with -n
             */
            if (strcmp(argv[1], "20081224") == 0 &&
                cf->timeout_handler.socket_name == NULL)
            {
                reply_number(cf, controlfd, &raddr, rlen, cookie, 0);
                return 0;
            }
            for (known = i = 0; proto_caps[i].pc_id != NULL; ++i)
            {
                if (!strcmp(argv[1], proto_caps[i].pc_id))
                {
                    known = 1;
                    break;
                }
            }
            reply_number(cf, controlfd, &raddr, rlen, cookie, known);
            return 0;
        }
        if (argc != 1 && argc != 2)
        {
            rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
            reply_error(cf, controlfd, &raddr, rlen, cookie, 2);
            return 0;
        }
        /* This returns base version. */
        reply_number(cf, controlfd, &raddr, rlen, cookie, CPROTOVER);
        return 0;
        /* Refresh TTL */
    case 't':
    case 'T':
        refresh_ttl =1;

    case 'i':
    case 'I':
        if (cookie == NULL)
            len = sprintf(buf, "sessions created: %llu\nactive sessions: %d\n"
                          "active streams: %d\n", cf->sessions_created,
                          cf->sessions_active, cf->nsessions / 2);
        else
            len = sprintf(buf, "%s sessions created: %llu\nactive sessions: %d\n"
                          "active streams: %d\n", cookie, cf->sessions_created,
                          cf->sessions_active, cf->nsessions / 2);
        if (refresh_ttl)
            refresh_ttl = len;
        for (i = 1; i < cf->nsessions; i++)
        {
            char addrs[4][256];

            spa = cf->sessions[i];
            if (spa == NULL || spa->sidx[0] != i)
                continue;
            /* RTCP twin session */
            if (spa->rtcp == NULL)
            {
                spb = spa->rtp;
                buf[len++] = '\t';
            }
            else
            {
                spb = spa->rtcp;
                buf[len++] = '\t';
                buf[len++] = 'C';
                buf[len++] = ' ';
            }
            if (spa->srtp[0].rcv_hdl.srtp)rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Id:0 rcv-hdl\n");
            rtpp_srtp_session_print_policy(spa->srtp[0].rcv_hdl.srtp);
            if (spa->srtp[0].snd_hdl.srtp)rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Id:0 snd_hdl\n");
            rtpp_srtp_session_print_policy(spa->srtp[0].snd_hdl.srtp);
            if (spa->srtp[1].rcv_hdl.srtp)rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Id:1 rcv-hdl\n");
            rtpp_srtp_session_print_policy(spa->srtp[1].rcv_hdl.srtp);
            if (spa->srtp[1].snd_hdl.srtp)rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Id:1 snd_hdl\n");
            rtpp_srtp_session_print_policy(spa->srtp[1].snd_hdl.srtp);
            if (refresh_ttl)
            {
                if (spa->ttl[0] >= 0 || spa->ttl[1] >= 0)
                    spa->ttl[0] = spa->ttl[1]= cf->max_ttl;
                if (spb!=NULL && (spb->ttl[0] >=0 || spb->ttl[1] >=0))
                    spb->ttl[0] = spb->ttl[1] = cf->max_ttl;
                continue;
            }
            addr2char_r(spb->laddr[1], addrs[0], sizeof(addrs[0]));
            if (spb->addr[1] == NULL)
            {
                strcpy(addrs[1], "NONE");
            }
            else
            {
                sprintf(addrs[1], "%s:%d", addr2char(spb->addr[1]),
                        addr2port(spb->addr[1]));
            }
            addr2char_r(spb->laddr[0], addrs[2], sizeof(addrs[2]));
            if (spb->addr[0] == NULL)
            {
                strcpy(addrs[3], "NONE");
            }
            else
            {
                sprintf(addrs[3], "%s:%d", addr2char(spb->addr[0]),
                        addr2port(spb->addr[0]));
            }
            len += sprintf(buf + len,
                           "%s/%s: caller = %s:%d/%s, callee = %s:%d/%s, "
                           "stats = %lu/%lu/%lu/%lu, ttl = %d/%d\n",
                           spb->call_id, spb->tag, addrs[0], spb->ports[1], addrs[1],
                           addrs[2], spb->ports[0], addrs[3], spa->pcount[0], spa->pcount[1],
                           spa->pcount[2], spa->pcount[3], spb->ttl[0], spb->ttl[1]);
            if (len + 512 > (int)sizeof(buf))
            {
                doreply(cf, controlfd, buf, len, &raddr, rlen);
                len = 0;
            }
        }
        if (refresh_ttl)
            len =refresh_ttl;

        if (len > 0)
            doreply(cf, controlfd, buf, len, &raddr, rlen);;
        return 0;
        break;

    case 'q':
    case 'Q':
        op = QUERY;
        rname = "query";
        break;

    case 'x':
    case 'X':
        /* Delete all active sessions */
        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "deleting all active sessions");
        for (i = 1; i < cf->nsessions; i++)
        {
            spa = cf->sessions[i];
            if (spa == NULL || spa->sidx[0] != i)
                continue;
            /* Skip RTCP twin session */
            if (spa->rtcp != NULL)
            {
                remove_session(cf, spa);
            }
        }
        reply_ok(cf, controlfd, &raddr, rlen, cookie);
        return 0;
        break;

    case 'w':
    case 'W':
        /* Change candidates in the middle of a call - for trickle ICE support */
        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "trickle ICE - add candidates");
        op = WCANDIDATE;
        rname = "candidate";
        break;

    default:
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "unknown command");
        reply_error(cf, controlfd, &raddr, rlen, cookie, 3);
        return 0;
    }
    call_id = argv[1];
    if (op == UPDATE || op == LOOKUP || op == PLAY || op == WCANDIDATE)
    {
        if (argc == 1)
        {
            // check if modifier is for ctrace start/stop
            char* u_modif =  argv[0]+1;
            if ( u_modif && strncasecmp((const char *)u_modif,"L",1)==0)
            {
                  // l modifier is to indicate we need RTP packets to be logged to the current ctrace connection
                  // set g_rtp_ctrace_enabled and break
                  rtpp_log_write(RTPP_LOG_INFO, cf->glog, " u_modif = %s Enabling ctrace ",u_modif);
                  g_rtp_ctrace_enabled=1;
            }
            if ( u_modif && strncasecmp((const char *)u_modif,"X",1)==0)
            {
                  // x modifier is to indicate we need to stop the current ctrace connection
                  // reset g_rtp_ctrace_enabled and break
                  rtpp_log_write(RTPP_LOG_INFO, cf->glog, " u_modif = %s Disabling ctrace ",u_modif);
                  g_rtp_ctrace_enabled=0;
            }
            reply_ok(cf, controlfd, &raddr, rlen, cookie);
            return 0;
        }
        switch (op)
        {
        case UPDATE:
            max_argc = MAX_ARGS_IN_UPDATE_CMD;
            break;
        case LOOKUP:
            max_argc = MAX_ARGS_IN_LOOKUP_CMD;
            break;
        case PLAY:
            max_argc = MAX_ARGS_IN_PLAY_CMD;
            break;
        case WCANDIDATE:
            max_argc = MAX_ARGS_IN_WCANDIDATE_CMD;
            break;
        default:
            max_argc = MAX_ARGS_IN_UPDATE_CMD;
        }

        if ((op != WCANDIDATE && argc < 5) || (op == WCANDIDATE && argc < 3) || argc > max_argc)
        {
            rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
            reply_error(cf, controlfd, &raddr, rlen, cookie, 4);
            return 0;
        }

        if (op == WCANDIDATE)
        {
            from_tag = argv[2];
            to_tag = argv[3];
        }
        else
        {
        from_tag = argv[4];
        to_tag = argv[5];
        }

        if ((op == UPDATE || op == LOOKUP) && argc > 5)
        {
            if (argc > 8)
                s_mapped_port = argv[8];
            else if (argc > 5)
                s_mapped_port= argv[5];
            if (strncmp(PORT_ARG_PREFIX, s_mapped_port, PORT_ARG_PREFIX_LEN) == 0)
                s_mapped_port+= PORT_ARG_PREFIX_LEN;
            else
                s_mapped_port= NULL;
            if (argc > 5)
            {
                s_mapped_port = argv[5];

                if (strncmp(PORT_ARG_PREFIX, s_mapped_port, PORT_ARG_PREFIX_LEN) == 0)
                    s_mapped_port += PORT_ARG_PREFIX_LEN;
                else
                    s_mapped_port= NULL;
            }
        }
        if (op == PLAY && argv[0][1] != '\0')
        {
            playcount = atoi(argv[0] + 1);\
        }
        if ((s_mapped_port== NULL) && (op == UPDATE || op == LOOKUP) && argc > 6)
        {
            s_mapped_port = argv[6];
            if (strncmp(PORT_ARG_PREFIX, s_mapped_port, PORT_ARG_PREFIX_LEN) == 0)
            {
                s_mapped_port+= PORT_ARG_PREFIX_LEN;
            }
            else
            {
                s_mapped_port= NULL;
            }
        }
        if (s_mapped_port != NULL)
        {
            argindx++;
        }
        /* TO TAG not Set in this case.*/
        if ((op == UPDATE || op == LOOKUP) && argc > 5 && ((s_mapped_port != NULL) ||
            is_optional_arg_present(argv[5])) )
        {
            to_tag = NULL;
        }
        else if (op == WCANDIDATE && is_optional_arg_present(argv[3]))
        {
            to_tag = NULL;
        }
        else
        {
            argindx++; /* To Tag shall be present*/
        }
        if (op == UPDATE && argc > 6 && ( s_mapped_port == NULL || argc > 8) &&
            is_optional_arg_not_present(argv[6]) )
        {
            argindx++;
            socket_name_u = argv[6];
            if (strncmp("unix:", socket_name_u, 5) == 0)
            {
                socket_name_u += 5;
            }
            if ((argc > 7) && is_optional_arg_not_present(argv[7]) )
            {
                argindx++;
                notify_tag = argv[7];
                len = url_unquote((uint8_t *)notify_tag, strlen(notify_tag));
                if (len == -1)
                {
                    rtpp_log_write(RTPP_LOG_ERR, cf->glog,
                                   "command syntax error - invalid URL encoding");
                    reply_error(cf, controlfd, &raddr, rlen, cookie, 4);
                    return 0;
                }
                notify_tag[len] = '\0';
            }
        }
    }
    if (op == COPY)
    {
        if (argc < 4 || argc > 5)
        {
            rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
            reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
            return 0;
        }
        recording_name = argv[2];
        from_tag = argv[3];
        to_tag = argv[4];
    }
    if (op == DELETE || op == RECORD || op == NOPLAY || op == QUERY)
    {
        if (argc < 3 || argc > 4)
        {
            rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
            reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
            return 0;
        }
        from_tag = argv[2];
        to_tag = argv[3];
    }
    if (op == DELETE || op == RECORD || op == COPY || op == NOPLAY)
    {
        /* D, R and S commands don't take any modifiers */
        if (argv[0][1] != '\0')
        {
            rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
            reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
            return 0;
        }
    }
    if (op == UPDATE || op == LOOKUP || op == DELETE || op == WCANDIDATE)
    {

        if (op != WCANDIDATE)
    {
        if (!strcmp(argv[2],"0.0.0.0"))
            addr = dummy_addr;
        else
            addr = argv[2];
        port = argv[3];
        /* Process additional command modifiers */
        external = 1;
        /* In bridge mode all clients are assumed to be asymmetric */
        asymmetric = (cf->bmode != 0) ? 1 : 0;
        pf = AF_INET;
        weak = 0;
        drop_rtp_packets = fix_srtp_seq = maintain_bridge_params = qos = 0;
        }

        for (cp = argv[0] + 1; *cp != '\0'; cp++)
        {
            switch (*cp)
            {
            case 'a':
            case 'A':
                asymmetric = 1;
                break;

            case 'b':
            case 'B':

                // Bridge modifier (FRN4811)
                arg_min = 5+argindx;

                rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                               " B arg_min:%d argindx:%d argc:%d", arg_min, argindx, argc);

                if (rtpp_parse_bridge_modifier(cf, argv[arg_min], &isBridgeBindIpV6, bridgeBindNetworkId, bridgeBindIpAddr) != 0)
                {
                    rtpp_log_write(RTPP_LOG_ERR, cf->glog, "Bridge modifier argument syntax error");
                    reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
                    return 0;
                }

                isBridgeModifierPresent = 1;

                // Build sockaddr for the bridge address
                setbindhost(pBridgeBindAddr, isBridgeBindIpV6?AF_INET6:AF_INET, bridgeBindIpAddr, SERVICE);

                break;


            case 'e':
            case 'E':
                if (lidx < 0)
                {
                    rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
                    reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
                    return 0;
                }
                lia[lidx] = cf->bindaddr[1];
                lidx--;
                break;

            case 'h':
            case 'H':
                callHoldIndicator = 1;
                rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                               "Received command option 'H'");
                break;

            case 'i':
            case 'I':
                if (lidx < 0)
                {
                    rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
                    reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
                    return 0;
                }
                lia[lidx] = cf->bindaddr[0];
                lidx--;
                break;

            case '6':
                pf = AF_INET6;
                break;

            case 's':
            case 'S':
                asymmetric = 0;
                break;

            case 'w':
            case 'W':
                weak = 1;
                break;

            case 'z':
            case 'Z':
                requested_nsamples = (strtol(cp + 1, &cp, 10) / 10) * 80;
                if (requested_nsamples <= 0)
                {
                    rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
                    reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
                    return 0;
                }
                cp--;
                break;

            case 'c':
            case 'C':
                cp += 1;
                for (t = cp; *cp != '\0'; cp++)
                {
                    if (!isdigit(*cp) && *cp != ',')
                        break;
                }
                if (t == cp)
                {
                    rtpp_log_write(RTPP_LOG_ERR, cf->glog, "command syntax error");
                    reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
                    return 0;
                }
                codecs = (char *)alloca(cp - t + 1);
                memcpy(codecs, t, cp - t);
                codecs[cp - t] = '\0';
                cp--;
                break;

            case 'm':
            case 'M':
                maintain_bridge_params = 1;
                break;

            case 'n':
            case 'N':
                rtpp_log_write(RTPP_LOG_ERR, cf->glog,
                               " N arg_min:%d argindx:%d argc:%d",arg_min,argindx, argc);
                arg_min =5+argindx;
                s_cn= NULL;
                cn_payload = PT_CODEC_COMFORT_NOISE;
                comfort_noise_disable=1;
                while (arg_min < argc)
                {
                    if (strncmp(CN_ARG_PREFIX, argv[arg_min], CN_ARG_PREFIX_LEN) == 0)
                    {
                        s_cn = argv[arg_min];
                        s_cn+= CN_ARG_PREFIX_LEN;
                        cn_payload= atoi(s_cn);
                        rtpp_log_write(RTPP_LOG_ERR, cf->glog,
                                       " N cn:%d",cn_payload);
                        break;
                    }
                    arg_min++;
                }
                break;
            case 'd':
            case 'D':
                drop_rtp_packets = RTPP_CMD_DROP_RTP;
                break;

            case 'o':
            case 'O':

                arg_min = 5 + argindx;
                qos = 0;
                rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                        "QOS arg_min:%d argindx:%d argc:%d",arg_min,argindx, argc);
                while (arg_min < argc)
                {
                    if (strncmp(QOS_ARG_PREFIX, argv[arg_min], QOS_ARG_PREFIX_LEN) == 0)
                    {
                        s_qos = argv[arg_min];
                        s_qos+= QOS_ARG_PREFIX_LEN;
                        qos   = atoi(s_qos);
                        rtpp_log_write(RTPP_LOG_INFO, cf->glog," QOS int:%d hex: 0x%x",qos, qos);
                        break;
                    }
                    arg_min++;
                }
                break;

            case 'r':
            case 'R':
                fix_srtp_seq = 1;
                break;

            case 't':
            case 'T':
                arg_min =5+argindx;
                rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                               " T arg_min:%d argindx:%d argc:%d",arg_min,argindx, argc);
                memset(s_trans_codec,'\0',sizeof(s_trans_codec));
                memset(s_trans_payload,'\0',sizeof(s_trans_payload));
                memset(s_trans_ptime,'\0',sizeof(s_trans_ptime));
                while (arg_min < argc)
                {
                    if (strncmp(TRANS_ARG_PREFIX, argv[arg_min], TRANS_ARG_PREFIX_LEN) == 0)
                    {
                        pargv=argv[arg_min];
                        pargv+=TRANS_ARG_PREFIX_LEN;
                        strncpy(s_trans_codec,pargv,min(sizeof(s_trans_codec),strlen(pargv)));
                    }
                    else if (strncmp(PAYLOAD_ARG_PREFIX, argv[arg_min], PAYLOAD_ARG_PREFIX_LEN) == 0)
                    {
                        pargv= argv[arg_min];
                        pargv+=PAYLOAD_ARG_PREFIX_LEN;
                        strncpy(s_trans_payload,pargv,min(sizeof(s_trans_payload),strlen(pargv)));
                    }
                    else if (strncmp(PTIME_ARG_PREFIX, argv[arg_min], PTIME_ARG_PREFIX_LEN) == 0)
                    {
                        pargv=argv[arg_min];
                        pargv+=PTIME_ARG_PREFIX_LEN;
                        strncpy(s_trans_ptime,pargv,min(sizeof(s_trans_ptime),strlen(pargv)));
                    }
                    arg_min++;
                }

                transcode=1;
                if (strlen(s_trans_codec)==0)
                {
                    processTrans=0;
                    if (strlen(s_trans_ptime)==0 )
                    {
                      rtpp_log_write(RTPP_LOG_ERR, cf->glog, "Error trans_codec and trans_ptime are empty ");
                      return(0);
                    }
                    else
                    {
                       char *payld=NULL;
                       char* pstr = s_trans_ptime;
                       ptime_from=ptime_to=-1;
                       rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                                   "Ptime command s_trans_ptime:%s ",s_trans_ptime);

                       if ((payld = rtpp_strsep(&pstr, ",")) != NULL)
                         ptime_from =  atoi(payld);
                       if ((payld = rtpp_strsep(&pstr, ",")) != NULL)
                         ptime_to = atoi(payld);

                       rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                          "Ptime From :%d To : %d",
                          ptime_from, ptime_to);

                      // ptime change without transcoding. Set resizing..
                      requested_nsamples = (ptime_to/10) * 80;

                      requested_nsamples_from = (ptime_from/10) * 80;
                      requested_nsamples_to = (ptime_to/10) * 80;
                    }
                }
                else
                {
                  rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                                 "codec command s_trans_codec:%s ",s_trans_codec);

                    if (strstr(s_trans_codec,"_") == NULL) // old format of command
                    bckVerCodecCmd=1;
                  processTrans=1;
                }
                break;




            case 'f':
            case 'F':
            case 'k':
            case 'K':
                char *s_rcv_key, *s_snd_key, *s_prcv_key, *s_psnd_key, *temp ;
                char *s_drcv_fp, *s_dsnd_fp, *s_dprcv_fp, *s_dpsnd_fp;
                arg_min = 5+argindx;
                s_rcv_key = s_snd_key = s_prcv_key = s_psnd_key = NULL;
                s_drcv_fp = s_dsnd_fp = s_dprcv_fp = s_dpsnd_fp = NULL;
                rcv_key = snd_key = prcv_key = psnd_key = NULL;
                rtpp_log_write(RTPP_LOG_INFO, cf->glog, " K arg_min:%d argindx:%d argc:%d",arg_min, argindx, argc);

                while (arg_min < argc)
                {
                    if (strncmp(RCV_ARG_PREFIX, argv[arg_min], RCV_ARG_PREFIX_LEN) == 0)
                    {
                        s_rcv_key = argv[arg_min];
                        s_rcv_key+= RCV_ARG_PREFIX_LEN;
#ifdef DEBUG
                        if (tfp)fprintf(tfp, "s_rcv_key = '%s'\n",s_rcv_key);
                        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "s_rcv_key = '%s'\n",s_rcv_key);

#endif
                    }
                    else if (strncmp(SEND_ARG_PREFIX, argv[arg_min], SEND_ARG_PREFIX_LEN) == 0)
                    {
                        s_snd_key = argv[arg_min];
                        s_snd_key+= SEND_ARG_PREFIX_LEN;
#ifdef DEBUG
                        if (tfp)fprintf(tfp, "s_snd_key = '%s'\n",s_snd_key);
                        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "s_snd_key = '%s'\n",s_snd_key);
#endif
                    }
                    else if (strncmp(PRCV_ARG_PREFIX, argv[arg_min], PRCV_ARG_PREFIX_LEN) == 0)
                    {
                        s_prcv_key = argv[arg_min];
                        s_prcv_key+= PRCV_ARG_PREFIX_LEN;
#ifdef DEBUG
                        if (tfp)fprintf(tfp, "s_prcv_key = '%s'\n",s_prcv_key);
                        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "s_prcv_key = '%s'\n",s_prcv_key);
#endif
                    }
                    else if (strncmp(PSEND_ARG_PREFIX, argv[arg_min], PSEND_ARG_PREFIX_LEN) == 0)
                    {
                        s_psnd_key = argv[arg_min];
                        s_psnd_key+= PSEND_ARG_PREFIX_LEN;
#ifdef DEBUG
                        if (tfp)fprintf(tfp, "s_psnd_key = '%s'\n",s_psnd_key);
                        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "s_psnd_key = '%s'\n",s_psnd_key);
#endif
                    }
                    else if (strncmp(RCV_FP_ARG_PREFIX, argv[arg_min], RCV_FP_ARG_PREFIX_LEN) == 0)
                    {
                        s_drcv_fp = argv[arg_min];
                        s_drcv_fp += RCV_FP_ARG_PREFIX_LEN;
#ifdef DEBUG
                        if (tfp)fprintf(tfp, "s_drcv_fp = '%s'\n", s_drcv_fp);
#endif
                    }
                    else if (strncmp(SEND_FP_ARG_PREFIX, argv[arg_min], SEND_FP_ARG_PREFIX_LEN) == 0)
                    {
                        s_dsnd_fp = argv[arg_min];
                        s_dsnd_fp += SEND_FP_ARG_PREFIX_LEN;
#ifdef DEBUG
                        if (tfp)fprintf(tfp, "s_dsnd_fp = '%s'\n", s_dsnd_fp);
#endif
                    }
                    else if (strncmp(PRCV_FP_ARG_PREFIX, argv[arg_min], PRCV_FP_ARG_PREFIX_LEN) == 0)
                    {
                        s_dprcv_fp = argv[arg_min];
                        s_dprcv_fp += PRCV_FP_ARG_PREFIX_LEN;
#ifdef DEBUG
                        if (tfp)fprintf(tfp, "s_dprcv_fp = '%s'\n", s_dprcv_fp);
#endif
                    }
                    else if (strncmp(PSEND_FP_ARG_PREFIX, argv[arg_min], PSEND_FP_ARG_PREFIX_LEN) == 0)
                    {
                        s_dpsnd_fp = argv[arg_min];
                        s_dpsnd_fp += PSEND_FP_ARG_PREFIX_LEN;
#ifdef DEBUG
                        if (tfp)fprintf(tfp, "s_dpsend_fp = '%s'\n", s_dpsnd_fp);
#endif
                    }
                    arg_min++;
                }
                rtpp_log_write(RTPP_LOG_INFO, cf->glog, "s_rcv_key:%s s_snd_key:%s s_prcv_key:%s s_psnd_key:%s"
                               "s_drcv_fp:%s s_dsnd_fp:%s s_dprcv_fp:%s s_dpsnd_fp:%s",
                               s_rcv_key?s_rcv_key:"NONE", s_snd_key?s_snd_key:"NONE",
                               s_prcv_key?s_prcv_key:"NONE", s_psnd_key?s_psnd_key:"NONE",
                               s_drcv_fp?s_drcv_fp:"NONE", s_dsnd_fp?s_dsnd_fp:"NONE",
                               s_dprcv_fp?s_dprcv_fp:"NONE", s_dpsnd_fp?s_dpsnd_fp:"NONE");
#ifdef DEBUG
                if (tfp)fprintf(tfp, "s_rcv_key:%s s_snd_key:%s s_prcv_key:%s s_psnd_key:%s"
                                "s_drcv_fp:%s s_dsnd_fp:%s s_dprcv_fp:%s s_dpsnd_fp:%s\n",
                                s_rcv_key?s_rcv_key:"NONE", s_snd_key?s_snd_key:"NONE",
                                s_prcv_key?s_prcv_key:"NONE", s_psnd_key?s_psnd_key:"NONE",
                                s_drcv_fp?s_drcv_fp:"NONE", s_dsnd_fp?s_dsnd_fp:"NONE",
                                s_dprcv_fp?s_dprcv_fp:"NONE", s_dpsnd_fp?s_dpsnd_fp:"NONE");
#endif
                if (s_rcv_key != NULL)
                {
                    rtpp_parse_srtp_cmd(cf, s_rcv_key, rcv_key, drcv_fp, rcv_ssrc, rcv_suite,rcv_attr);
#ifdef DEBUG
                    if (tfp)
                    {
                        unsigned char buffer[256];
                        fprintf(tfp, "rcv_key:%s, rcv_ssrc:(0x%08x)%u - %s, rcv_suite:%d,rcv_attr\n",
                                rcv_key, rcv_ssrc, rcv_ssrc, bin_to_hex(buffer, sizeof(buffer), (unsigned char *)temp, 4), rcv_suite,rcv_attr);
                    }
#endif
                }
                if (s_snd_key != NULL)
                {
                    rtpp_parse_srtp_cmd(cf, s_snd_key, snd_key, dsnd_fp, snd_ssrc, snd_suite, snd_attr);
#ifdef DEBUG
                    if (tfp)
                    {
                        unsigned char buffer[256];
                        fprintf(tfp, "snd_key:%s, snd_ssrc:(0x%08x)%u - %s, snd_suite:%d snd_attr:%d\n",
                                snd_key, snd_ssrc, snd_ssrc, bin_to_hex(buffer, sizeof(buffer), (unsigned char *)temp, 4), snd_suite,snd_attr);
                    }
#endif
                }
                if (s_prcv_key != NULL)
                {
                    rtpp_parse_srtp_cmd(cf, s_prcv_key, prcv_key, dprcv_fp, prcv_ssrc, prcv_suite, prcv_attr);
#ifdef DEBUG
                    if (tfp)
                    {
                        unsigned char buffer[256];
                        fprintf(tfp, "prcv_key:%s, prcv_ssrc:(0x%08x)%u - %s, prcv_suite:%d prcv_attr:%d\n",
                                prcv_key, prcv_ssrc, prcv_ssrc, bin_to_hex(buffer, sizeof(buffer), (unsigned char *)temp, 4), prcv_suite,prcv_attr);
                    }
#endif
                }
                if (s_psnd_key != NULL)
                {
                    rtpp_parse_srtp_cmd(cf, s_psnd_key, psnd_key,dpsnd_fp, psnd_ssrc, psnd_suite, psnd_attr);
#ifdef DEBUG
                    if (tfp)
                    {
                        unsigned char buffer[256];
                        fprintf(tfp, "psnd_key:%s, psnd_ssrc:(0x%08x)%u - %s, psnd_suite:%d psnd_attr:%d\n",
                                psnd_key, psnd_ssrc, psnd_ssrc, bin_to_hex(buffer, sizeof(buffer), (unsigned char *)temp, 4), psnd_suite,psnd_attr);
                    }
#endif
                }

                rtpp_log_write(RTPP_LOG_INFO, cf->glog, "rcv_key:%s,ssrc:%u,suite:%d snd_key:%s,ssrc:%u,suite:%d "
                       "prcv_key:%s,ssrc:%u,suite:%d psnd_key:%s,ssrc:%u,suite:%d ",
                       rcv_key?(const char*)rcv_key:"NONE",rcv_ssrc, rcv_suite,
                       snd_key?(const char*)snd_key:"NONE", snd_ssrc, snd_suite,
                       prcv_key?(const char*)prcv_key:"NONE",prcv_ssrc, prcv_suite,
                       psnd_key?(const char*)psnd_key:"NONE", psnd_ssrc, psnd_suite);

                if (rtpp_srtp_validate_key(rcv_key) || rtpp_srtp_validate_key(snd_key) ||
                    rtpp_srtp_validate_key(prcv_key) || rtpp_srtp_validate_key(psnd_key))
                {
                    rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                                   "rtpp_srtp_validate_key Error on rcv_key:%s,ssrc:%u,suite:%d snd_key:%s,ssrc:%u,suite:%d "
                                   "prcv_key:%s,ssrc:%u,suite:%d psnd_key:%s,ssrc:%u,suite:%d ",
                                   rcv_key?(const char*)rcv_key:"NONE",rcv_ssrc, rcv_suite,
                                   snd_key?(const char*)snd_key:"NONE", snd_ssrc, snd_suite,
                                   prcv_key?(const char*)prcv_key:"NONE",prcv_ssrc, prcv_suite,
                                   psnd_key?(const char*)psnd_key:"NONE", psnd_ssrc, psnd_suite);
#ifdef DEBUG
                    if (tfp)fprintf(tfp,
                                    "rtpp_srtp_validate_key Error on rcv_key:%s,ssrc:%u,suite:%d snd_key:%s,ssrc:%u,suite:%d\n"
                                    "prcv_key:%s,ssrc:%u,suite:%d psnd_key:%s,ssrc:%u,suite:%d\n",
                                    rcv_key?(const char*)rcv_key:"NONE",rcv_ssrc, rcv_suite,
                                    snd_key?(const char*)snd_key:"NONE", snd_ssrc, snd_suite,
                                    prcv_key?(const char*)prcv_key:"NONE",prcv_ssrc, prcv_suite,
                                    psnd_key?(const char*)psnd_key:"NONE", psnd_ssrc, psnd_suite);
#endif
                    reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
                    return(0);

                }
#ifdef DEBUG
                if (tfp)fprintf(tfp,
                                "rcv_key:%s,ssrc:%u,suite:%d snd_key:%s,ssrc:%u,suite:%d prcv_key:%s,ssrc:%u,suite:%d psnd_key:%s,ssrc:%u,suite:%d"
                                "drcv_fp:%s,ssrc:%u,algo:%d dsnd_fp:%s,ssrc:%u,algo:%d dprcv_fp:%s,ssrc:%u,algo:%d dpsnd_fp:%s,ssrc:%u,algo:%d\n",
                                rcv_key?(const char*)rcv_key:"NONE",rcv_ssrc, rcv_suite,
                                snd_key?(const char*)snd_key:"NONE", snd_ssrc, snd_suite,
                                prcv_key?(const char*)prcv_key:"NONE",prcv_ssrc, prcv_suite,
                                psnd_key?(const char*)psnd_key:"NONE", psnd_ssrc, psnd_suite,
                                drcv_fp?(const char*)drcv_fp:"NONE",rcv_ssrc, rcv_suite,
                                dsnd_fp?(const char*)dsnd_fp:"NONE",snd_ssrc, snd_suite,
                                dprcv_fp?(const char*)dprcv_fp:"NONE",prcv_ssrc, prcv_suite,
                                dpsnd_fp?(const char*)dpsnd_fp:"NONE",psnd_ssrc, psnd_suite);
#endif
                rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                               "rcv_key:%s,drcv_fp:%s,ssrc:%u,suite:%d,attr:%d "
                               "snd_key:%s,dsnd_fp:%s, ssrc:%u,suite:%d,attr:%d "
                               "prcv_key:%s,dprcv_fp:%s,ssrc:%u,suite:%d,attr:%d "
                               "psnd_key:%s,dpsnd_fp:%s,ssrc:%u,suite:%d,attr:%d",
                               rcv_key?(const char*)rcv_key:"NONE",drcv_fp?(const char*)drcv_fp:"NONE",rcv_ssrc, rcv_suite,rcv_attr,
                               snd_key?(const char*)snd_key:"NONE",dsnd_fp?(const char*)dsnd_fp:"NONE",snd_ssrc, snd_suite,snd_attr,
                               prcv_key?(const char*)prcv_key:"NONE",dprcv_fp?(const char*)dprcv_fp:"NONE",prcv_ssrc, prcv_suite,prcv_attr,
                               psnd_key?(const char*)psnd_key:"NONE",dpsnd_fp?(const char*)dpsnd_fp:"NONE",psnd_ssrc, psnd_suite,psnd_attr);

                if (rcv_key!=NULL || snd_key!=NULL || prcv_key!=NULL || psnd_key!=NULL)
                    secure = 1;
                if (drcv_fp!=NULL || dsnd_fp!=NULL || dprcv_fp!=NULL || dpsnd_fp!=NULL)
                    dtls = 1;
                break;

            case 'U':
            case 'u':
            case 'L':
            case 'l':

                rtpp_log_write(RTPP_LOG_INFO, cf->glog, " U/L modifier argc = %d", argc);

                // handle ICE candidates
                int param_idx;
                if (op == WCANDIDATE)
                {
                    param_idx = 3; // WCANDIDATE has no addr and port params
                    if (*cp == 'U' || *cp == 'u')
                    {
                        wcandidate_side = 0; // This is the trickle-ice following UPDATE
                    }
                    else if (*cp == 'L' || *cp == 'l')
                    {
                        wcandidate_side = 1; // This is the trickle-ice following LOOKUP
                    }
                }
                else
                {
                    param_idx = 5;
                    drop_rtp_packets = RTPP_STUN_DROP_RTP;
                }

                for (;param_idx < argc; param_idx++)
                {
                    if (strlen(argv[param_idx]) > 3 && (strncmp(argv[param_idx], "ice", 3) == 0))
                    {
                        // parse the ice candidate arguments
                        if (strncmp(argv[param_idx], ICE_LOCAL_USER_PREFIX, 5) == 0)
                        {
                            rtpp_parse_ice_user(cf, argv[param_idx], &ice_user_pass, 0);
                        }
                        else if (strncmp(argv[param_idx], ICE_REMOTE_USER_PREFIX, 5) == 0)
                        {
                            rtpp_parse_ice_user(cf, argv[param_idx], &ice_user_pass, 1);
                        }
                        else if (strncmp(argv[param_idx], ICE_RTP_CANDIDATE_PREFIX, 8) == 0)
                        {
                            rtpp_parse_ice_remote_candidate(cf, argv[param_idx], &rtp_ice_candidate);
                        }
                        else if (strncmp(argv[param_idx], ICE_RTCP_CANDIDATE_PREFIX, 9) == 0)
                        {
                            rtpp_parse_ice_remote_candidate(cf, argv[param_idx], &rtcp_ice_candidate);
                        }
                        else
                        {
                            rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Unrecognized ice candidate arg %s", argv[param_idx]);
                        }
                    }
                }

                break;
            case 'y':
            case 'Y':
              rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Video port indicator found in command");
              is_video_session = 1;
              break;
            default:
                rtpp_log_write(RTPP_LOG_ERR, cf->glog, "unknown command modifier `%c'", *cp);
                break;
            }
        }

        // FRN4811 (Check if the remote address is IPv6)
        if (op!= WCANDIDATE && strstr(addr, ":") != NULL)
        {
            pf = AF_INET6;
            rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Remote address is IPv6");
        }

        if (op != DELETE && op != WCANDIDATE && addr != NULL && port != NULL && strlen(addr) >= 7)
        {
            struct sockaddr_storage tia;

            if ((n = resolve(sstosa(&tia), pf, addr, port, AI_NUMERICHOST)) == 0)
            {
                if (!ishostnull(sstosa(&tia)))
                {
                    for (i = 0; i < 2; i++)
                    {
                        //ia[i] = (struct sockaddr *)malloc(SS_LEN(&tia));  // VLAN Support Change (FNR4811)
                        ia[i] = (struct sockaddr *)malloc(sizeof(struct sockaddr_storage));
                        if (ia[i] == NULL)
                        {
                            handle_nomem(cf, controlfd, &raddr, rlen, cookie, 5, ia, fds, spa, spb);
                            return 0;
                        }
                        //memcpy(ia[i], &tia, SS_LEN(&tia));   // VLAN Support Change (FRN4811)
                        memcpy(ia[i], &tia, sizeof(struct sockaddr_storage));
                    }
                    /* Set port for RTCP, will work both for IPv4 and IPv6 */
                    n = ntohs(satosin(ia[1])->sin_port);
                    satosin(ia[1])->sin_port = htons(n + 1);
                }
            }
            else
            {
                rtpp_log_write(RTPP_LOG_ERR, cf->glog, "getaddrinfo: %s", gai_strerror(n));
            }
        }
    }

    if (isBridgeModifierPresent)
    {
        // If bridge modifier present, set lia[0] to bridge bind address
        lia[0] = pBridgeBindAddr;
    }

    /*
     * Record and delete need special handling since they apply to all
     * streams in the session.
     */
    switch (op)
    {
    case DELETE:
        i = handle_delete(cf, call_id, from_tag, to_tag, weak);
        break;

    case RECORD:
        i = handle_record(cf, call_id, from_tag, to_tag);
        break;

    default:
        i = find_stream(cf, call_id, from_tag, to_tag, &spa);
        if (i != -1)
        {
            if (op == WCANDIDATE)
            {
                if (wcandidate_side == 1) // trickle-ice following LOOKUP
                    i = NOT(i);
            }
            else if (op != UPDATE)
                i = NOT(i);
        }
    }

    // operations apply to specific stream
    if (i == -1 && op != UPDATE)
    {
        rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                       "%s request failed: session %s, tags %s/%s not found", rname,
                       call_id, from_tag, to_tag != NULL ? to_tag : "NONE");
        if (op == LOOKUP)
        {
            for (i = 0; i < 2; i++)
            {
                if (ia[i] != NULL)
                {
                    free(ia[i]);
                }
            }

            //ICE - delete the parsed candidates here ?
            free_ice_user_pass(&ice_user_pass);

            if (rtp_ice_candidate != NULL)
            {
                struct remote_ice_candidate *pi = rtp_ice_candidate;
                while (pi->next != NULL)
                {
                    pi = pi->next;
                }
                while (pi->prev != NULL)
                {
                    pi = pi->prev;
                    free(pi->next->addr);

                    free(pi->next);
                    pi->next = NULL;
                }
                free(pi->addr);
                free(pi);
            }

            if (rtcp_ice_candidate != NULL)
            {
                struct remote_ice_candidate *pi = rtcp_ice_candidate;
                while (pi->next != NULL)
                {
                    pi = pi->next;
                }
                while (pi->prev != NULL)
                {
                    pi = pi->prev;
                    free(pi->next->addr);

                    free(pi->next);
                    pi->next = NULL;
                }
                free(pi->addr);
                free(pi);

            }
            // end ICE

            reply_port(cf, controlfd, &raddr, rlen, cookie, 0, lia, NULL);

            return 0;

        }
        reply_error(cf, controlfd, &raddr, rlen, cookie, 8);
        return 0;
    }

    switch (op)
    {
    case DELETE:
    case RECORD:
        reply_ok(cf, controlfd, &raddr, rlen, cookie);
        return 0;

    case NOPLAY:
        handle_noplay(cf, spa, i);
        reply_ok(cf, controlfd, &raddr, rlen, cookie);
        return 0;

    case PLAY:
        handle_noplay(cf, spa, i);
        if (strcmp(codecs, "session") == 0)
        {
            if (spa->codecs[i] == NULL)
            {
                reply_error(cf, controlfd, &raddr, rlen, cookie, 6);
                return 0;
            }
            codecs = spa->codecs[i];
        }
        if (playcount != 0 && handle_play(cf, spa, i, codecs, pname, playcount) != 0)
        {
            reply_error(cf, controlfd, &raddr, rlen, cookie, 6);
            return 0;
        }
        reply_ok(cf, controlfd, &raddr, rlen, cookie);
        return 0;

    case COPY:
        handle_copy(cf, spa, i, recording_name);
        reply_ok(cf, controlfd, &raddr, rlen, cookie);
        return 0;

    case QUERY:
        handle_query(cf, controlfd, &raddr, rlen, cookie, spa, i);
        return 0;

    case LOOKUP:
    case UPDATE:
    case WCANDIDATE:
        /* those are handled below */
        break;

    default:
        /* Programmatic error, should not happen */
        abort();
    }

    pidx = 1;
    lport = 0;

    if (s_mapped_port!=NULL)
        lport = atoi(s_mapped_port);

    if (i != -1)
    {
        // existing stream
        assert(op == UPDATE || op == LOOKUP || op == WCANDIDATE);
        if (spa->fds[i] == -1)
        {
            if (isBridgeModifierPresent)
            {
                    // VLAN Support (FRN4811)
                rtpp_log_write(RTPP_LOG_INFO, cf->glog, "BridgeModifier: Lookup Cmd; Create listener to bridge addr: %s",
                                   addr2char(pBridgeBindAddr));

                    // Copy address to spa laddr
                    memcpy(spa->bridgeBindAddr[i], pBridgeBindAddr, sizeof(struct sockaddr_storage));
            }
            else
            {
                    j = ishostseq(cf->bindaddr[0], spa->laddr[i]) ? 0 : 1;    // j is unused

                    pBridgeBindAddr = spa->laddr[i];
            }

            if(!is_video_session)
            {
                retval = create_listener(cf, pBridgeBindAddr, &lport, fds, qos);
            }
            else
            {
                retval = create_video_listener(cf, pBridgeBindAddr, &lport, fds, qos);
            }

            if (retval == -1)
            {
                rtpp_log_write(RTPP_LOG_ERR, spa->log, "can't create listener");
                reply_error(cf, controlfd, &raddr, rlen, cookie, 7);
                return 0;
            }
            rtpp_log_write(RTPP_LOG_INFO, spa->log, "%s: bind laddr:%s lport:%d",
                           rname,addr2char(pBridgeBindAddr), lport );

            // VLAN Support (FRN4811)
            if (isBridgeModifierPresent)
            {
                bind_to_device(cf, fds[0], bridgeBindNetworkId);
                bind_to_device(cf, fds[1], bridgeBindNetworkId);
#ifdef DEBUG
                if (tfp)
                {
                    fprintf(tfp, " fds[0]=%d fds[1]=%d \n", fds[0], fds[1]);
                }
#endif
            }

            assert(spa->fds[i] == -1);
            spa->fds[i] = fds[0];
            assert(spa->rtcp->fds[i] == -1);
            spa->rtcp->fds[i] = fds[1];
            spa->ports[i] = lport;
            spa->rtcp->ports[i] = lport + 1;
            satosin(spa->laddr[i])->sin_port = htons(lport);
            spa->complete = spa->rtcp->complete = 1;
            append_session(cf, spa, i);
            append_session(cf, spa->rtcp, i);
            spb = spa->rtcp;
#ifdef DEBUG1
            if (tfp)
            {
                const char *opsp = "UPDATE";
                if (op == LOOKUP)opsp = "LOOKUP";
                fprintf(tfp, "\n%s RTP Session: %p\n", opsp, spa);
                fprintf(tfp, "FD:port[0] = %d:%d\n", spa->fds[0], spa->ports[0]);
                fprintf(tfp, "FD:port[1] = %d:%d\n", spa->fds[1], spa->ports[1]);
                fprintf(tfp, "srtp[0] Send policy:srtp %p:%p\n", spa->srtp[0].snd_hdl.policy, spa->srtp[0].snd_hdl.srtp);
                fprintf(tfp, "srtp[0] Recv policy:srtp %p:%p\n", spa->srtp[0].rcv_hdl.policy, spa->srtp[0].rcv_hdl.srtp);
                fprintf(tfp, "srtp[1] Send policy:srtp %p:%p\n", spa->srtp[1].snd_hdl.policy, spa->srtp[1].snd_hdl.srtp);
                fprintf(tfp, "srtp[1] Recv policy:srtp %p:%p\n", spa->srtp[1].rcv_hdl.policy, spa->srtp[1].rcv_hdl.srtp);
                fprintf(tfp, "\n%s RTCP Session: %p\n", opsp, spb);
                fprintf(tfp, "FD:port[0] = %d:%d\n", spb->fds[0], spb->ports[0]);
                fprintf(tfp, "FD:port[1] = %d:%d\n", spb->fds[1], spb->ports[1]);
                fprintf(tfp, "srtp[0] Send policy:srtp %p:%p\n", spb->srtp[0].snd_hdl.policy, spb->srtp[0].snd_hdl.srtp);
                fprintf(tfp, "srtp[0] Recv policy:srtp %p:%p\n", spb->srtp[0].rcv_hdl.policy, spb->srtp[0].rcv_hdl.srtp);
                fprintf(tfp, "srtp[1] Send policy:srtp %p:%p\n", spb->srtp[1].snd_hdl.policy, spb->srtp[1].snd_hdl.srtp);
                fprintf(tfp, "srtp[1] Recv policy:srtp %p:%p\n", spb->srtp[1].rcv_hdl.policy, spb->srtp[1].rcv_hdl.srtp);
            }
#endif

            rtpp_log_write(RTPP_LOG_INFO, spa->log,
                           "%s: spa->ports[0]:%d  spb->ports[0]:%d spa->ports[1]:%d  spb->ports[1]:%d",
                           rname,spa->ports[0], spb->ports[0], spa->ports[1],  spb->ports[1] );
            rtpp_log_write(RTPP_LOG_INFO, spa->log,
                           "%s: spa->fds[0]:%d  spb->fds[0]:%d spa->fds[1]:%d  spb->fds[1]:%d",
                           rname,spa->fds[0], spb->fds[0], spa->fds[1],  spb->fds[1] );
        }

        if (op == UPDATE || op == LOOKUP)
        {
            // ICE support - update local and remote users
            if (ice_user_pass != NULL)
            {
                free_ice_user_pass(&spa->ice_u[1-i]);
                spa->ice_u[1-i] = ice_user_pass;
                spa->rtcp->ice_u[1-i] = ice_user_pass;
                retval = rtpp_stun_agent_init(spa); 
                rtpp_log_write(RTPP_LOG_INFO, spa->log,"Stun Agent Init returned(%d)", retval);

            }
            if (rtp_ice_candidate != NULL)
            {
                delete_ice_candidate(spa, 1-i);
                spa->ice_candidate_list[1-i] = NULL;
                append_ice_candidate(cf, &(spa->ice_candidate_list[1-i]), &rtp_ice_candidate);
            }
            if (rtcp_ice_candidate != NULL)
            {
                delete_ice_candidate(spa->rtcp, 1-i);
                spa->rtcp->ice_candidate_list[1-i] = NULL;
                append_ice_candidate(cf, &(spa->rtcp->ice_candidate_list[1-i]), &rtcp_ice_candidate);
            }

        }
        else if (op == WCANDIDATE)
        {
            // In case of trickle-ICE only add candidates, don't delete the old ones
            if (rtp_ice_candidate != NULL)
                append_ice_candidate(cf, &(spa->ice_candidate_list[1-i]), &rtp_ice_candidate);
            if (rtcp_ice_candidate != NULL)
                append_ice_candidate(cf, &(spa->rtcp->ice_candidate_list[1-i]), &rtcp_ice_candidate);
        }
        if (callHoldIndicator)
            spa->isCallOnHold = 1;
        else
            spa->isCallOnHold = 0;

        if (weak)
            spa->weak[i] = 1;
        else if (op == UPDATE)
            spa->strong = 1;
        lport = spa->ports[i];
        lia[0] = spa->laddr[i];
        pidx = (i == 0) ? 1 : 0;
        spa->ttl_mode = cf->ttl_mode;
        spa->ttl[0] = cf->max_ttl;
        spa->ttl[1] = cf->max_ttl;
        if (op == UPDATE)
        {
            rtpp_log_write(RTPP_LOG_INFO, spa->log,
                           "adding %s flag to existing session, new=%d/%d/%d",
                           weak ? ( i ? "weak[1]" : "weak[0]" ) : "strong",
                           spa->strong, spa->weak[0], spa->weak[1]);
        }
        rtpp_log_write(RTPP_LOG_INFO, spa->log,
                       "pidx [%d] lookup on ports %d/%d, session timer restarted ", pidx, spa->ports[0],
                       spa->ports[1]);
    }
    else
    {
        // new stream
        assert(op == UPDATE);
        rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                       "new session %s, tag %s requested, type %s pidx:%d",
                       call_id, from_tag, weak ? "weak" : "strong", pidx);

        if (isBridgeModifierPresent)
        {
            // VLAN Support (FRN4811)
            rtpp_log_write(RTPP_LOG_INFO, cf->glog, "BridgeModifier: Update Cmd; Create listener to bridge addr: %s",
                           addr2char(pBridgeBindAddr));
        }
        else
        {
            j = ishostseq(cf->bindaddr[0], lia[0]) ? 0 : 1;
            pBridgeBindAddr = cf->bindaddr[j];
        }

        if(!is_video_session)
        {
            retval = create_listener(cf, pBridgeBindAddr, &lport, fds, qos);
        }
        else
        {
            retval = create_video_listener(cf, pBridgeBindAddr, &lport, fds, qos);
        }

        if (retval == -1)
        {
            rtpp_log_write(RTPP_LOG_ERR, cf->glog, "can't create listener");
            free_ice_user_pass(&ice_user_pass);
            reply_error(cf, controlfd, &raddr, rlen, cookie, 10);
            return 0;
        }
        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "2 %s: bind laddr:%s lport:%d",
                       rname,addr2char(pBridgeBindAddr),lport );

        // VLAN Support (FRN4811)
        if (isBridgeModifierPresent)
        {
            bind_to_device(cf, fds[0], bridgeBindNetworkId);
            bind_to_device(cf, fds[1], bridgeBindNetworkId);
#ifdef DEBUG
            if (tfp)
            {
                fprintf(tfp, " fds[0]=%d fds[1]=%d \n", fds[0], fds[1]);
            }
#endif
        }

        /*
         * Session creation. If creation is requested with weak flag,
         * set weak[0].
         */
        spa = (struct rtpp_session *)malloc(sizeof(*spa));
        if (spa == NULL)
        {
            handle_nomem(cf, controlfd, &raddr, rlen, cookie, 11, ia,
                         fds, spa, spb);
            return 0;
        }
        /* spb is RTCP twin session for this one. */
        spb = (struct rtpp_session *)malloc(sizeof(*spb));
        if (spb == NULL)
        {
            handle_nomem(cf, controlfd, &raddr, rlen, cookie, 12, ia,
                         fds, spa, spb);
            return 0;
        }
        memset(spa, 0, sizeof(*spa));
        memset(spb, 0, sizeof(*spb));
        for (i = 0; i < 2; i++)
        {
            spa->fds[i] = spb->fds[i] = -1;
            spa->last_update[i] = 0;
            spb->last_update[i] = 0;
        }
        spa->call_id = strdup(call_id);
        if (spa->call_id == NULL)
        {
            handle_nomem(cf, controlfd, &raddr, rlen, cookie, 13, ia,
                         fds, spa, spb);
            return 0;
        }
        spb->call_id = spa->call_id;
        spa->tag = strdup(from_tag);
        if (spa->tag == NULL)
        {
            handle_nomem(cf, controlfd, &raddr, rlen, cookie, 14, ia,
                         fds, spa, spb);
            return 0;
        }
        spb->tag = spa->tag;
        for (i = 0; i < 2; i++)
        {
            spa->rrcs[i] = NULL;
            spb->rrcs[i] = NULL;

            if (isBridgeModifierPresent)
            {
                // VLAN Support (FRN4811)
                rtpp_log_write(RTPP_LOG_INFO, cf->glog, "BridgeModifier: Allocate new mem for spa laddr[%d]: %s", i,
                               addr2char(pBridgeBindAddr));

                // Allocate new structure for the local address in session data
                // laddr[0] will be set with valid address; laddr[1] is set to same as laddr[0] here but will be updated
                // with correct address in lookup process
                spa->bridgeBindAddr[i] = (struct sockaddr *)malloc(sizeof(struct sockaddr_storage));
                if (spa->bridgeBindAddr[i] == NULL)
                {
                    rtpp_log_write(RTPP_LOG_ERR, cf->glog, "BridgeModifier: Malloc failed for spa laddr");

                    handle_nomem(cf, controlfd, &raddr, rlen, cookie, 12, ia, fds, spa, spb);
                    return 0;
                }
                memcpy(spa->bridgeBindAddr[i], pBridgeBindAddr, sizeof(struct sockaddr_storage));
                spa->laddr[i] = spa->bridgeBindAddr[i];
                spb->laddr[i] = spa->bridgeBindAddr[i];   // RTP and RTCP local addr point to same bridge bind addr
            }
            else
            {
                spa->laddr[i] = lia[i];
                spb->laddr[i] = lia[i];
            }
        }
        spa->strong = spa->weak[0] = spa->weak[1] = 0;
        if (weak)
            spa->weak[0] = 1;
        else
            spa->strong = 1;
        assert(spa->fds[0] == -1);
        spa->fds[0] = fds[0];
        assert(spb->fds[0] == -1);
        spb->fds[0] = fds[1];
        spa->ports[0] = lport;
        spb->ports[0] = lport + 1;
        satosin(spa->laddr[0])->sin_port = htons(lport);
        spa->has_video = spb->has_video = is_video_session;
        spa->ttl[0] = cf->max_ttl;
        spa->ttl[1] = cf->max_ttl;
        spb->ttl[0] = -1;
        spb->ttl[1] = -1;
        spa->log = rtpp_log_open(cf, "rtpproxy", spa->call_id, 0);
        spb->log = spa->log;
        spa->rtcp = spb;
        spb->rtcp = NULL;
        spa->rtp = NULL;
        spb->rtp = spa;
        spa->sridx = spb->sridx = -1;
        spa->agent = NULL;
        // ICE support
        if (ice_user_pass != NULL)
        {
            spa->ice_u[1] = ice_user_pass;
            spb->ice_u[1] = ice_user_pass;
            if((retval = rtpp_stun_agent_init(spa)) < 0)
               rtpp_log_write(RTPP_LOG_INFO, spa->log,"Stun Agent Init Failed(%d)", retval);
        }
        if (rtp_ice_candidate != NULL)
        {
            spa->ice_candidate_list[1] = NULL;
            append_ice_candidate(cf, &(spa->ice_candidate_list[1]), &rtp_ice_candidate);
        }
        if (rtcp_ice_candidate != NULL)
        {
            spb->ice_candidate_list[1] = NULL;
            append_ice_candidate(cf, &(spb->ice_candidate_list[1]), &rtcp_ice_candidate);
        }

        rtpp_log_write(RTPP_LOG_INFO, spa->log,
                       "2 %s: spa->ports[0]:%d  spb->ports[0]:%d spa->ports[1]:%d  spb->ports[1]%d",
                       rname, spa->ports[0], spb->ports[0], spa->ports[1],  spb->ports[1] );
        rtpp_log_write(RTPP_LOG_INFO, spa->log,
                       "2 %s: spa->fds[0]:%d  spb->fds[0]:%d spa->fds[1]:%d  spb->fds[1]%d",
                       rname, spa->fds[0], spb->fds[0], spa->fds[1],  spb->fds[1] );

        append_session(cf, spa, 0);
        append_session(cf, spa, 1);
        append_session(cf, spb, 0);
        append_session(cf, spb, 1);

        hash_table_append(cf, spa);

        cf->sessions_created++;
        cf->sessions_active++;
        /* Init SRTP Context */
        rtpp_srtp_init_context(&spa->srtp[0]);
        rtpp_srtp_init_context(&spb->srtp[0]);
        rtpp_srtp_init_context(&spa->srtp[1]);
        rtpp_srtp_init_context(&spb->srtp[1]);
        /*
         * Each session can consume up to 5 open file descriptors (2 RTP,
         * 2 RTCP and 1 logging) so that warn user when he is likely to
         * exceed 80% mark on hard limit.
         */
        if (cf->sessions_active > (int)(cf->nofile_limit.rlim_max * 80 / (100 * 5)) &&
            cf->nofile_limit_warned == 0)
        {
            cf->nofile_limit_warned = 1;
            rtpp_log_write(RTPP_LOG_WARN, cf->glog, "passed 80%% "
                           "threshold on the open file descriptors limit (%d), "
                           "consider increasing the limit using -L command line "
                           "option", (int)cf->nofile_limit.rlim_max);
        }

        rtpp_log_write(RTPP_LOG_INFO, spa->log, "[%d] new session on a port %d created, "
                       "tag %s", 0, lport, from_tag);
        if (cf->record_all != 0)
        {
            handle_copy(cf, spa, 0, NULL);
            handle_copy(cf, spa, 1, NULL);
        }
    }
    /* TODO: we have to do binary operation instead modifying the value
    */
    if (drop_rtp_packets)
        spa->drop_rtp_packets = drop_rtp_packets;
    else if(spa->drop_rtp_packets != RTPP_STUN_DROP_RTP)
        spa->drop_rtp_packets = 0;
    rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                   "%s Setting isCallOnHold:%d drop_rtp_packets:%d fix_seq:%d",rname, spa->isCallOnHold, spa->drop_rtp_packets,fix_srtp_seq);

    if (op == UPDATE)
    {
        if (cf->timeout_handler.socket_name == NULL && socket_name_u != NULL)
            rtpp_log_write(RTPP_LOG_ERR, spa->log, "must permit notification socket with -n");
        if (spa->timeout_data.notify_tag != NULL)
        {
            free(spa->timeout_data.notify_tag);
            spa->timeout_data.notify_tag = NULL;
        }
        if (cf->timeout_handler.socket_name != NULL && socket_name_u != NULL)
        {
            if (strcmp(cf->timeout_handler.socket_name, socket_name_u) != 0)
            {
                rtpp_log_write(RTPP_LOG_ERR, spa->log, "invalid socket name %s", socket_name_u);
                socket_name_u = NULL;
            }
            else
            {
                rtpp_log_write(RTPP_LOG_INFO, spa->log, "setting timeout handler");
                spa->timeout_data.handler = &cf->timeout_handler;
                spa->timeout_data.notify_tag = strdup(notify_tag);
            }
        }
        else if (socket_name_u == NULL && spa->timeout_data.handler != NULL)
        {
            spa->timeout_data.handler = NULL;
            rtpp_log_write(RTPP_LOG_INFO, spa->log, "disabling timeout handler");
        }
    }

    if (ia[0] != NULL && ia[1] != NULL)
    {
        if (spa->addr[pidx] != NULL)
            spa->last_update[pidx] = dtime;
        if (spa->rtcp->addr[pidx] != NULL)
            spa->rtcp->last_update[pidx] = dtime;
        /*
         * Unless the address provided by client historically
         * cannot be trusted and address is different from one
         * that we recorded update it.
         */
        rtpp_log_write(RTPP_LOG_INFO, spa->log, "Pre-Update %s with %s:%s untrusted:%d "
                       "spa->addr[pidx]:%s", (pidx == 0) ? "callee" : "caller",addr, port,
                       spa->untrusted_addr[pidx],
                       (spa->addr[pidx] != NULL)?addr2char(spa->addr[pidx]):"NULL");

        if (spa->untrusted_addr[pidx] == 0 && !(spa->addr[pidx] != NULL &&
                                                SA_LEN(ia[0]) == SA_LEN(spa->addr[pidx]) &&
                                                memcmp(ia[0], spa->addr[pidx], SA_LEN(ia[0])) == 0))
        {
            rtpp_log_write(RTPP_LOG_INFO, spa->log, "1pre-filling %s's address "
                           "with %s:%s", (pidx == 0) ? "callee" : "caller", addr, port);
            if (spa->addr[pidx] != NULL)
            {
                if (spa->canupdate[pidx] == 0)
                {
                    rtpp_log_write(RTPP_LOG_INFO, spa->log, "11pre-filling %s's address "
                                   "with %s:%s", (pidx == 0) ? "callee" : "caller", addr, port);
                    if (spa->prev_addr[pidx] != NULL)
                        free(spa->prev_addr[pidx]);
                    spa->prev_addr[pidx] = spa->addr[pidx];
                }
                else
                {
                    free(spa->addr[pidx]);
                }
            }

            spa->addr[pidx] = ia[0];
            ia[0] = NULL;
        }

        if (spa->rtcp->untrusted_addr[pidx] == 0 && !(spa->rtcp->addr[pidx] != NULL &&
                                                      SA_LEN(ia[1]) == SA_LEN(spa->rtcp->addr[pidx]) &&
                                                      memcmp(ia[1], spa->rtcp->addr[pidx], SA_LEN(ia[1])) == 0))
        {
            if (spa->rtcp->addr[pidx] != NULL)
            {
                if (spa->rtcp->canupdate[pidx] == 0)
                {
                    if (spa->rtcp->prev_addr[pidx] != NULL)
                        free(spa->rtcp->prev_addr[pidx]);
                    spa->rtcp->prev_addr[pidx] = spa->rtcp->addr[pidx];
                }
                else
                {
                    free(spa->rtcp->addr[pidx]);
                }
                rtpp_log_write(RTPP_LOG_INFO, spa->log, "2pre-filling %s's address "
                               "with %s:%s", (pidx == 0) ? "callee" : "caller", addr, port);
            }
            spa->rtcp->addr[pidx] = ia[1];
            ia[1] = NULL;
        }
    }

    spa->asymmetric[pidx] = spa->rtcp->asymmetric[pidx] = asymmetric;
    spa->canupdate[pidx] = spa->rtcp->canupdate[pidx] = NOT(asymmetric);
    if (spa->codecs[pidx] != NULL)
    {
        free(spa->codecs[pidx]);
        spa->codecs[pidx] = NULL;
    }
    if (codecs != NULL)
        spa->codecs[pidx] = strdup(codecs);

    if (transcode)
    {
        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "callid:%s pidx:%d setting up Transcode context",call_id?call_id:"NULL",pidx);
        memset(&spa->resizers[0], 0, sizeof(rtp_resizer));
        memset(&spa->resizers[1], 0, sizeof(rtp_resizer));
        rtp_resizer_free(&spa->resizers[0]);
        rtp_resizer_free(&spa->resizers[1]);

        if (requested_nsamples_to > 0 && requested_nsamples_from > 0)
        {
          // this is if we got ptime: along with trans command.
          spa->resizers[pidx].output_nsamples = requested_nsamples_to;
          rtpp_log_write(RTPP_LOG_INFO, spa->log, "RTP packets from %s "
                         "will be resized to requested_nsamples_to=%d bytes",
                         (pidx == 0) ? "callee" : "caller", requested_nsamples_to );

          spa->resizers[!pidx].output_nsamples = requested_nsamples_from;
          rtpp_log_write(RTPP_LOG_INFO, spa->log, "RTP packets from %s "
                       "will be resized to requested_nsamples_from=%d bytes",
                       (!pidx == 0) ? "callee" : "caller", requested_nsamples_from );
        }

        if (processTrans) // if we have valid transcodeString
        {
               int needsTranscoding=0;
               // decide if transcoding necessary

               // read codec lists - covers both old and new command
               // covers both pidx and !pidx
               // !pidx will have from/to -> changed to to/from
               // codec_from, payload_from, codec_to, payload_to
               // will be populated with the top priority ones from pidx/!pidx
               rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                               "Process transcode. Calling rtp_get_codec_lists with Codec string %s", s_trans_codec);

               static char transcodeString[256];
               static char payloadString[256];

               memset(transcodeString,'\0',256);
               memset(payloadString,'\0',256);

               strncpy(transcodeString,s_trans_codec,sizeof(transcodeString));

            if (strlen(s_trans_payload) != 0 )
                 strncpy(payloadString,s_trans_payload,sizeof(payloadString));

               retval = rtp_get_codec_lists(transcodeString, payloadString, spa, pidx,
                                      &codec_from, &payload_from,
                                      &codec_to, &payload_to,
                                      &codec_from_nidx,&payload_from_nidx,
                                      &codec_to_nidx,&payload_to_nidx);

            if (retval<0)
               {
                 //something wrong in parsing.
                 rtpp_log_write(RTPP_LOG_ERR, cf->glog,
                              "Error parsing command:%s ret:%d",
                              s_trans_codec,retval);

                 return(0);
               }

                rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                               "cod_f=%d pay_f=%d ==> cod_t=%d pay_t=%d  ",
                               codec_from,payload_from,codec_to,payload_to );
                if (codec_from <0 || payload_from <0 || codec_to <0 || payload_to <0)
                {
                    rtpp_log_write(RTPP_LOG_ERR, cf->glog,
                                   "Codec/Payload validation Error codec:%s payload:%s ",
                                   transcodeString,payloadString);
                    reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
                    return(0);
                }

                rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                                   "Is old verion of command ? :%d ",bckVerCodecCmd);

            if (bckVerCodecCmd==0) // if new version of command, validate !idx values also
                {
                    if (codec_from_nidx <0 || payload_from_nidx <0 || codec_to_nidx <0 || payload_to_nidx <0)
                    {
                        rtpp_log_write(RTPP_LOG_ERR, cf->glog,
                                       "Codec/Payload validation Error codec:%s payload:%s ",
                                       transcodeString,payloadString);
                        reply_error(cf, controlfd, &raddr, rlen, cookie, 1);
                        return(0);
                    }
                }

        itrans_codec_create_info idxFrmInfo, idxToInfo;
        itrans_codec_create_info nidxFrmInfo, nidxToInfo;

        rtp_trans_fillCodecInfo(&idxFrmInfo, &idxToInfo,
                                &nidxFrmInfo, &nidxToInfo,
                                spa, pidx);

        // In case transcoding data has been previosuly allocated, free it.
        rtp_transcoder_free(&spa->trans[pidx],cf);
        rtp_transcoder_free(&spa->trans[!pidx],cf);

        rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                       " Transcode Session idx=%d cod_f=%d pay_f=%d ==> cod_t=%d pay_t=%d ",
                       pidx, codec_from,payload_from,codec_to,payload_to );


        int fromMode = spa->rtp_trans_codeclists[pidx].rtp_transcoder_FromCodecDetails[0].mode;
        int toMode =   spa->rtp_trans_codeclists[!pidx].rtp_transcoder_FromCodecDetails[0].mode;
        /*int fromBR = spa->rtp_trans_codeclists[pidx].rtp_transcoder_FromCodecDetails[0].bitRate;
        int toBR = spa->rtp_trans_codeclists[!pidx].rtp_transcoder_FromCodecDetails[0].bitRate;
        int fromCR = spa->rtp_trans_codeclists[pidx].rtp_transcoder_FromCodecDetails[0].clockRate;
        int toCR = spa->rtp_trans_codeclists[!pidx].rtp_transcoder_FromCodecDetails[0].clockRate;*/

            if (codec_from!=codec_to)
        {
           needsTranscoding=1;
                if (fromMode != toMode) // needs resizing with linear in between, samples * 2
           {
               rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                               "Process transcode. codec_from!=codec_to and fromMode != toMode. Calculate Linear Resize time.");

               requested_nsamples_from = (fromMode/10) * 80;
               requested_nsamples_to = (toMode/10) * 80;
                    if (requested_nsamples_to > 0)
                {
                  spa->resizers[pidx].output_nsamples = requested_nsamples_to*2;
                  rtpp_log_write(RTPP_LOG_INFO, spa->log, "RTP packets from %s "
                                   "will be resized to %d bytes",
                                   (pidx == 0) ? "callee" : "caller", spa->resizers[pidx].output_nsamples );

                }
                    if (requested_nsamples_from > 0)
                {
                  spa->resizers[!pidx].output_nsamples = requested_nsamples_from*2;
                  rtpp_log_write(RTPP_LOG_INFO, spa->log, "RTP packets from %s "
                                   "will be resized to %d bytes",
                                   (!pidx == 0) ? "callee" : "caller", spa->resizers[!pidx].output_nsamples );
                }
            }
            else // no resizing
            {
               memset(&spa->resizers[0], 0, sizeof(rtp_resizer));
               memset(&spa->resizers[1], 0, sizeof(rtp_resizer));
            }
        }
        else // here, codec_from==codec_to
        {
             needsTranscoding=0;
             spa->transcode = 0;

                if (fromMode != toMode)
             {
               rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                               "Process transcode. Codecs are same, but ptimes are different. Calculate Resize time.");

               // no transcoding to linear. So, no multiplying by 2
               requested_nsamples_from = (fromMode/10) * 80;
               requested_nsamples_to = (toMode/10) * 80;
                    if (requested_nsamples_to > 0)
               {
                  spa->resizers[pidx].output_nsamples = requested_nsamples_to;
                  rtpp_log_write(RTPP_LOG_INFO, spa->log, "RTP packets from %s "
                                   "will be resized to %d bytes",
                                   (pidx == 0) ? "callee" : "caller", spa->resizers[pidx].output_nsamples );

               }
                    if (requested_nsamples_from > 0)
               {
                  spa->resizers[!pidx].output_nsamples = requested_nsamples_from;
                  rtpp_log_write(RTPP_LOG_INFO, spa->log, "RTP packets from %s "
                                   "will be resized to %d bytes",
                                   (!pidx == 0) ? "callee" : "caller", spa->resizers[!pidx].output_nsamples );
               }
             }
             else
             {
               // if mode is same, we do not need resizing.
               memset(&spa->resizers[0], 0, sizeof(rtp_resizer));
               memset(&spa->resizers[1], 0, sizeof(rtp_resizer));
             }
        }

            if (needsTranscoding)
        {
            // even for multiple codecs, create only one transcoder, top priority only
             rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                       " Calling Transcode Update for idx=%d cod_f=%d pay_f=%d ==> cod_t=%d pay_t=%d ",
                       pidx, codec_from,payload_from,codec_to,payload_to );

            if (rtp_transcoder_update(&spa->trans[pidx],
                                      spa,
                                      payload_from,
                                      codec_from,
                                      &idxFrmInfo,
                                      payload_to,
                                      codec_to,
                                      &idxToInfo,
                                      pidx) != RTPP_TRANSCODER_OK)
            {
                rtpp_log_write(RTPP_LOG_ERR, cf->glog, "rtp_transcoder_update failed");

                //handle_nomem(cf, controlfd, &raddr, rlen, cookie, 12, ia,  fds, spa, spb);
                return 0;
            }
            // drop comfort noise packets by default.
            rtp_set_comfort_noise(&spa->trans[pidx],(char)PT_CODEC_COMFORT_NOISE,1);
            if (comfort_noise_disable)
                rtp_set_comfort_noise(&spa->trans[pidx],(char)cn_payload,comfort_noise_disable);

            //  create !pidx transcoder
                if (bckVerCodecCmd==0)
            {
                 rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                       " Calling Transcode Update for idx=%d cod_f=%d pay_f=%d ==> cod_t=%d pay_t=%d ",
                       !pidx, codec_from_nidx,payload_from_nidx,codec_to_nidx,payload_to_nidx );

                if (rtp_transcoder_update(&spa->trans[!pidx],
                    spa,
                    payload_from_nidx,
                    codec_from_nidx,
                    &nidxFrmInfo,
                    payload_to_nidx,
                    codec_to_nidx,
                    &nidxToInfo,
                    !pidx))
                {
                    rtpp_log_write(RTPP_LOG_ERR, cf->glog, "rtp_transcoder_update failed");
                    //handle_nomem(cf, controlfd, &raddr, rlen, cookie, 12, ia,  fds, spa, spb);
                    return 0;
                }
               rtp_set_comfort_noise(&spa->trans[!pidx],(char)PT_CODEC_COMFORT_NOISE,1);
               if (comfort_noise_disable)
                 rtp_set_comfort_noise(&spa->trans[!pidx],(char)cn_payload,comfort_noise_disable);

            }
            spa->transcode = 1;
        }
      }
      if(g_use_timed_resizer
         && (spa->resizers[0].output_nsamples || spa->resizers[1].output_nsamples))
      {
            // clean any prev resize list data
            remove_session_frm_active_rsz_lst(spa);
            active_rsz_sp spnode;
            spnode.rsz_sp = spa;
            rtp_data_list_append(&spnode, sizeof(active_rsz_sp), active_resized_sp_list );
            rtpp_log_write(RTPP_LOG_INFO,cf->glog,
                       "added session to active resized-packet session list ");
      }
    }
    else if(!maintain_bridge_params)
    {

        if (spa->resizers[0].output_nsamples)
        {
               memset(&spa->resizers[0], 0, sizeof(rtp_resizer));
               rtp_resizer_free(&spa->resizers[0]);
        }

        if (spa->resizers[1].output_nsamples)
        {
               memset(&spa->resizers[1], 0, sizeof(rtp_resizer));
               rtp_resizer_free(&spa->resizers[1]);
        }

        if(g_use_timed_resizer
         && (spa->resizers[0].output_nsamples || spa->resizers[1].output_nsamples))
        {
           remove_session_frm_active_rsz_lst(spa);
        }

        rtpp_log_write(RTPP_LOG_INFO, spa->log, "Cleaned up resizer data");

        if (spa->transcode)
        {
#ifdef DEBUG
            if (tfp)fprintf(tfp, "%s_%d: Freeing transcoding data\n", __FILE__, __LINE__);
#endif
            rtpp_log_write(RTPP_LOG_INFO, cf->glog, "No Trans required. Freeing transcoding data");
            rtp_transcoder_free(&spa->trans[0],cf);
            rtp_transcoder_free(&spa->trans[1],cf);
        }
        spa->transcode = 0;
    }

        if (secure)
        {
#ifdef DEBUG
                if (tfp)fprintf(tfp, "The call is secure - snd_key:%p, rcv_key:%p\n",
                                snd_key, rcv_key);
#endif
                rtpp_log_write(RTPP_LOG_INFO, cf->glog, "callid:%s pidx:%d setting up Secure context",call_id?call_id:"NULL",pidx);
                if (snd_key!= NULL)
                {
                        int kidx = pidx;
                        int ret = rtpp_srtp_create_context(spa, kidx, snd_key, snd_suite, snd_ssrc, fix_srtp_seq, 1);
                        ret &= rtpp_srtp_create_context(spa->rtcp, kidx, snd_key, snd_suite, snd_ssrc, fix_srtp_seq, 1);
            if (!ret)return 0;
                }

                if (psnd_key != NULL)
                {
                        int kidx = (pidx == 0) ? 1:0;
                        int ret = rtpp_srtp_create_context(spa, kidx, psnd_key, psnd_suite, psnd_ssrc, fix_srtp_seq, 1);
                        ret &= rtpp_srtp_create_context(spa->rtcp, kidx, psnd_key, psnd_suite, psnd_ssrc, fix_srtp_seq, 1);
            if (!ret)return 0;

                }

        if (rcv_key != NULL)
                {
                        int kidx = (pidx == 0) ? 1:0;
                        int ret = rtpp_srtp_create_context(spa, kidx, rcv_key, rcv_suite, rcv_ssrc, fix_srtp_seq, 0);
                        ret &= rtpp_srtp_create_context(spa->rtcp, kidx, rcv_key, rcv_suite, rcv_ssrc, fix_srtp_seq, 0);
            if (!ret)return 0;
                }

        if (prcv_key != NULL)
                {
                        int kidx = pidx;
                        int ret = rtpp_srtp_create_context(spa, kidx, prcv_key, prcv_suite, prcv_ssrc, fix_srtp_seq, 0);
                        ret &= rtpp_srtp_create_context(spa->rtcp, kidx, prcv_key, prcv_suite, prcv_ssrc, fix_srtp_seq, 0);
            if (!ret)return 0;
                }
    }
    else if (op != WCANDIDATE && !maintain_bridge_params)
    {
        // Make sure that if any SRTP data has been previously allocated, it is freed.
        if (spa->secure)
        {
#ifdef DEBUG
            if (tfp)fprintf(tfp, "%s_%d: Freeing SRTP data\n", __FILE__, __LINE__);
#endif
            rtpp_log_write(RTPP_LOG_INFO, cf->glog, "callid:%s pidx:%d freeing up Secure context",call_id?call_id:"NULL",pidx);
            rtpp_srtp_free_context(&spa->srtp[0]);
            rtpp_srtp_free_context(&spa->srtp[1]);
            rtpp_srtp_free_context(&spa->rtcp->srtp[0]);
            rtpp_srtp_free_context(&spa->rtcp->srtp[1]);
        }

        spa->secure = 0;
    }
    if (dtls)
    {
        int kidx = -1;
        int ret;
        size_t fp_len;
        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "callid:%s pidx:%d setting up Secure context",call_id?call_id:"NULL",pidx);
        bzero(&dsnd_fp_int, sizeof(dtls_fingerprint));
        bzero(&dpsnd_fp_int,sizeof(dtls_fingerprint));
        if (dsnd_fp || dprcv_fp)
        {

            kidx = pidx;
            if (spa->stream[kidx] == NULL)
            {
                ret  = rtpp_dtls_create_stream(cf, spa, kidx);
                ret &= rtpp_dtls_create_stream(cf, spa->rtcp, kidx);
                if (!ret)return 0;
            }
        }
        if (drcv_fp || dpsnd_fp)
        {
            kidx = (pidx == 0) ? 1:0;
            if (spa->stream[kidx] == NULL)
            {
                ret  = rtpp_dtls_create_stream(cf, spa, kidx);
                ret &= rtpp_dtls_create_stream(cf, spa->rtcp, kidx);
                if (!ret)return 0;
            }
        }
        if (dsnd_fp && strlen((char*)dsnd_fp) == 0 && snd_suite)
        {
            ret = compute_digest(spa->stream[pidx]->local_identity->certificate, snd_suite, dsnd_fp_int.fp, EVP_MAX_MD_SIZE, &dsnd_fp_int.len);
            if (!ret)return 0;
        }
        if (dpsnd_fp && strlen((char*)dpsnd_fp) == 0 && psnd_suite)
        {
            ret = compute_digest(spa->stream[NOT(pidx)]->local_identity->certificate, psnd_suite, dpsnd_fp_int.fp, EVP_MAX_MD_SIZE, &dpsnd_fp_int.len);
            if (!ret)return 0;
        }
        if (dsnd_fp || dprcv_fp)
        {

            ret  = rtpp_dtls_setup_stream(spa, kidx, dsnd_fp, snd_suite, snd_ssrc, snd_attr, dprcv_fp, prcv_suite, prcv_ssrc, prcv_attr, fix_srtp_seq);
            ret &= rtpp_dtls_setup_stream(spa->rtcp, kidx, dsnd_fp, snd_suite, snd_ssrc, snd_attr, dprcv_fp, prcv_suite, prcv_ssrc, prcv_attr, fix_srtp_seq);
            if (!ret) return 0;
        }
        if (drcv_fp || dpsnd_fp)
        {
            ret  = rtpp_dtls_setup_stream(spa, kidx, dpsnd_fp, psnd_suite, psnd_ssrc, psnd_attr, drcv_fp, rcv_suite, rcv_ssrc, rcv_attr, fix_srtp_seq);
            ret &= rtpp_dtls_setup_stream(spa->rtcp, kidx, dpsnd_fp, psnd_suite, psnd_ssrc, psnd_attr, drcv_fp, rcv_suite, rcv_ssrc, rcv_attr, fix_srtp_seq);
            if (!ret) return 0;
        }
    }
#ifdef DEBUG
    if (tfp)
    {
        const char *opsp = "UPDATE";
        if (op == LOOKUP)opsp = "LOOKUP";
        fprintf(tfp, "\n%s RTP Session: %p\n", opsp, spa);
        trace_session(spa);
        fprintf(tfp, "\n%s RTCP Session: %p\n", opsp, spb);
        trace_session(spb);
    }
#endif


    for (i = 0; i < 2; i++)
        if (ia[i] != NULL)
            free(ia[i]);
    if (spa->addr[0] != NULL)
        rtpp_log_write(RTPP_LOG_INFO, spa->log, "spa->raddr[0]:%s:%d",addr2char(spa->addr[0]), addr2port(spa->addr[0]));
    if (spa->addr[1] != NULL)
        rtpp_log_write(RTPP_LOG_INFO, spa->log, "spa->raddr[1]:%s:%d",addr2char(spa->addr[1]), addr2port(spa->addr[1]));
    if (spa->laddr[0] != NULL)
        rtpp_log_write(RTPP_LOG_INFO, spa->log, "spa->laddr[0]:%s:%d",addr2char(spa->laddr[0]), spa->ports[0]);
    if (spa->laddr[1] != NULL)
        rtpp_log_write(RTPP_LOG_INFO, spa->log, "spa->laddr[1]:%s:%d",addr2char(spa->laddr[1]), spa->ports[1]);

#ifdef DEBUG
    if(tfp)
    {
        if (spa->addr[0] != NULL)
            fprintf(tfp, " spa->raddr[0]:%s:%d \n",addr2char(spa->addr[0]), addr2port(spa->addr[0]));
        if (spa->addr[1] != NULL)
            fprintf(tfp, " spa->raddr[1]:%s:%d \n",addr2char(spa->addr[1]), addr2port(spa->addr[1]));
        if (spa->laddr[0] != NULL)
            fprintf(tfp, ": spa->laddr[0]:%s:%d",addr2char(spa->laddr[0]), addr2port(spa->laddr[0]));
        if (spa->laddr[1] != NULL)
            fprintf(tfp, ": spa->laddr[1]:%s:%d",addr2char(spa->laddr[1]), addr2port(spa->laddr[1]));
    }
#endif

    for (i = 0; i < 2; i++)
    {
        if (spa->ice_u[1-i] != NULL)
        {
            rtpp_log_write(RTPP_LOG_INFO, spa->log, "spa->ice_u[%u]: local username: %s, local password: %s, remote username: %s, remote password: %s", 1-i, spa->ice_u[1-i]->local_user_name, spa->ice_u[1-i]->local_password, spa->ice_u[1-i]->remote_user_name, spa->ice_u[1-i]->remote_password);
        }

        if (spa->ice_candidate_list[1-i] != NULL)
        {
            j = 0;
            struct remote_ice_candidate *rtp_candidate = spa->ice_candidate_list[1-i];
            do
            {
                j ++;
                rtpp_log_write(RTPP_LOG_INFO, spa->log, "spa->ice_candidate_list[%u] candidate %u: addr:%s port:%u prio:%f ",
                               1-i,
                               j,
                               inet_ntoa(rtp_candidate->addr->sin_addr),
                               rtp_candidate->port,
                               rtp_candidate->priority);
                rtp_candidate = rtp_candidate->next;
            } while (rtp_candidate != NULL);
        }

        if (spa->rtcp->ice_candidate_list[1-i] != NULL)
        {
            struct remote_ice_candidate *rtcp_candidate = spa->rtcp->ice_candidate_list[1-i];
            j = 0;
            do
            {
                j ++;
                rtpp_log_write(RTPP_LOG_INFO, spa->rtcp->log, "spa->rtcp->ice_candidate_list[%u] candidate %u: addr:%s port:%u prio:%f ",
                               1-i,
                               j,
                               inet_ntoa(rtcp_candidate->addr->sin_addr),
                               rtcp_candidate->port,
                               rtcp_candidate->priority);
                rtcp_candidate = rtcp_candidate->next;
            } while (rtcp_candidate != NULL);
        }
    }

    assert(lport != 0);
    if (dtls)
    {
        unsigned char *fp = NULL;
        char *send_fingerprint = NULL;
        char buf_fp[2048];
        char *pbuf_fp = buf_fp;
        int len=0;
        bool space=0;
        bzero(buf_fp,2048);
        if (dsnd_fp && strlen((char*)dsnd_fp) == 0)
        {
            fp = dsnd_fp_int.fp;
            len = fp_to_hex(fp, dsnd_fp_int.len, &send_fingerprint);
            if(len)
            {
                strcpy(pbuf_fp, SEND_ARG_PREFIX);
                pbuf_fp += SEND_ARG_PREFIX_LEN;
                len = sprintf(pbuf_fp,"%s",send_fingerprint);
                rtpp_log_write(RTPP_LOG_INFO, cf->glog, "pidx:%d sndfp: %s[END]\n",pidx, send_fingerprint);
                pbuf_fp += len;
                free(send_fingerprint);
                send_fingerprint = NULL;
                space = 1;
            }
        }
        if (dpsnd_fp && strlen((char*)dpsnd_fp) == 0)
        {
            fp = dpsnd_fp_int.fp;
            len = fp_to_hex(fp,dpsnd_fp_int.len, &send_fingerprint);
            if(len)
            {
                if(space)
                   *pbuf_fp++ =' ';
                strcpy(pbuf_fp,PSEND_ARG_PREFIX);
                pbuf_fp += PSEND_ARG_PREFIX_LEN;
                rtpp_log_write(RTPP_LOG_INFO, cf->glog, "pidx:%d psndfp: %s[END]\n",pidx,send_fingerprint);
                len = sprintf(pbuf_fp,"%s",send_fingerprint);
                free(send_fingerprint);
            }
        }
        if (fp != NULL && len > 0)
        {
         rtpp_log_write(RTPP_LOG_INFO, cf->glog, "pidx:%d pbuf_fp:%s\n",pidx,buf_fp);
           reply_port(cf, controlfd, &raddr, rlen, cookie, lport, lia, (unsigned char*)buf_fp);
        }
        else
        {
            reply_port(cf, controlfd, &raddr, rlen, cookie, lport, lia, NULL);
        }
    }
    else
    {
        reply_port(cf, controlfd, &raddr, rlen, cookie, lport, lia, NULL);
    }
    return 0;
}


static int handle_delete(struct cfg *cf, char *call_id, char *from_tag, char *to_tag, int weak)
{
    int ndeleted;
    unsigned int medianum;
    struct rtpp_session *spa, *spb;
    int cmpr, cmpr1, idx;

    ndeleted = 0;
    for (spa = session_findfirst(cf, call_id); spa != NULL;)
    {
        medianum = 0;
        if ((cmpr1 = compare_session_tags(spa->tag, from_tag, &medianum)) != 0)
        {
            idx = 1;
            cmpr = cmpr1;
        }
        else if (to_tag != NULL &&
                 (cmpr1 = compare_session_tags(spa->tag, to_tag, &medianum)) != 0)
        {
            idx = 0;
            cmpr = cmpr1;
        }
        else
        {
            spa = session_findnext(spa);
            continue;
        }

        if (weak)
            spa->weak[idx] = 0;
        else
            spa->strong = 0;

        /*
         * This seems to be stable from reiterations, the only side
         * effect is less efficient work.
         */
        if (spa->strong || spa->weak[0] || spa->weak[1])
        {
            rtpp_log_write(RTPP_LOG_INFO, spa->log,
                           "delete: medianum=%u: removing %s flag, seeing flags to"
                           " continue session (strong=%d, weak=%d/%d)",
                           medianum,
                           weak ? ( idx ? "weak[1]" : "weak[0]" ) : "strong",
                           spa->strong, spa->weak[0], spa->weak[1]);
            /* Skipping to next possible stream for this call */
            ++ndeleted;
            spa = session_findnext(spa);
            continue;
        }
        rtpp_log_write(RTPP_LOG_INFO, spa->log,
                       "forcefully deleting session %u on ports %d/%d",
                       medianum, spa->ports[0], spa->ports[1]);
        /* Search forward before we do removal */
        spb = spa;
        spa = session_findnext(spa);
        remove_session(cf, spb);
        ++ndeleted;
        if (cmpr != 2)
        {
            break;
        }
    }
    if (ndeleted == 0)
    {
        return -1;
    }
    return 0;
}

static void handle_noplay(struct cfg *cf, struct rtpp_session *spa, int idx)
{

    if (spa->rtps[idx] != NULL)
    {
        rtp_server_free(spa->rtps[idx]);
        spa->rtps[idx] = NULL;
        rtpp_log_write(RTPP_LOG_INFO, spa->log,
                       "stopping player at port %d", spa->ports[idx]);
        if (spa->rtps[0] == NULL && spa->rtps[1] == NULL)
        {
            assert(cf->rtp_servers[spa->sridx] == spa);
            cf->rtp_servers[spa->sridx] = NULL;
            spa->sridx = -1;
        }
    }
}

static int handle_play(struct cfg *cf, struct rtpp_session *spa, int idx, char *codecs,
            char *pname, int playcount)
{
    int n;
    char *cp;

    while (*codecs != '\0')
    {
        n = strtol(codecs, &cp, 10);
        if (cp == codecs)
            break;
        codecs = cp;
        if (*codecs != '\0')
            codecs++;
        spa->rtps[idx] = rtp_server_new(pname, (rtp_type_t)n, playcount);
        if (spa->rtps[idx] == NULL)
            continue;
        rtpp_log_write(RTPP_LOG_INFO, spa->log,
                       "%d times playing prompt %s codec %d", playcount, pname, n);
        if (spa->sridx == -1)
            append_server(cf, spa);
        return 0;
    }
    rtpp_log_write(RTPP_LOG_ERR, spa->log, "can't create player");
    return -1;
}

static void handle_copy(struct cfg *cf, struct rtpp_session *spa, int idx, char *rname)
{

    if (spa->rrcs[idx] == NULL)
    {
        spa->rrcs[idx] = ropen(cf, spa, rname, idx);
        rtpp_log_write(RTPP_LOG_INFO, spa->log,
                       "starting recording RTP session on port %d", spa->ports[idx]);
    }
    if (spa->rtcp->rrcs[idx] == NULL && cf->rrtcp != 0)
    {
        spa->rtcp->rrcs[idx] = ropen(cf, spa->rtcp, rname, idx);
        rtpp_log_write(RTPP_LOG_INFO, spa->log,
                       "starting recording RTCP session on port %d", spa->rtcp->ports[idx]);
    }
}

static int handle_record(struct cfg *cf, char *call_id, char *from_tag, char *to_tag)
{
    int nrecorded, idx;
    struct rtpp_session *spa;

    nrecorded = 0;
    for (spa = session_findfirst(cf, call_id); spa != NULL;
        spa = session_findnext(spa))
    {
        if (compare_session_tags(spa->tag, from_tag, NULL) != 0)
        {
            idx = 1;
        }
        else if (to_tag != NULL &&
                 (compare_session_tags(spa->tag, to_tag, NULL)) != 0)
        {
            idx = 0;
        }
        else
        {
            continue;
        }
        nrecorded++;
        handle_copy(cf, spa, idx, NULL);
        handle_copy(cf, spa, NOT(idx), NULL);
    }
    return(nrecorded == 0 ? -1 : 0);
}

static void handle_query(struct cfg *cf, int fd, struct sockaddr_storage *raddr,
             socklen_t rlen, char *cookie, struct rtpp_session *spa, int idx)
{
    char buf[1024 * 8];
    int len;

    if (cookie != NULL)
    {
        len = sprintf(buf, "%s %d %lu %lu %lu %lu\n", cookie, get_ttl(spa),
                      spa->pcount[idx], spa->pcount[NOT(idx)], spa->pcount[2],
                      spa->pcount[3]);
    }
    else
    {
        len = sprintf(buf, "%d %lu %lu %lu %lu\n", get_ttl(spa),
                      spa->pcount[idx], spa->pcount[NOT(idx)], spa->pcount[2],
                      spa->pcount[3]);
    }
    doreply(cf, fd, buf, len, raddr, rlen);
}

/**
 * bind_to_device - Bind socket to given network interface (FRN4811)
 *
 * @param[in] cf        - Config
 * @param[in] fd        - File Descriptor
 * @param[in] networkId - Network Id (interface name)
 *
 * @return 0 (success), -1 (failure)
 *
 */
static int bind_to_device(struct cfg *cf, int fd, char *networkId)
{
    int retval = -1;
    struct ifreq ifReq;

    if ( (networkId == NULL) || (networkId[0] == '0') )
    {
        // Ignore if network id is "0"
        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Invalid Network Id (%s)", networkId);
        return retval;
    }

    if ( fd == -1 )
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "Invalid FD (%d) ", fd);
        return retval;
    }

    if(strlen(networkId) >= (sizeof(ifReq.ifr_name)-1) )
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog,
                       "NetworkID/Interface(%s) Name(%d) is Greater than System Interface Length(%d)",
                       networkId,strlen(networkId), sizeof(ifReq.ifr_name)-1);
        return retval;
    }
    // Get the interface index and then set sock opt to bind to interface
    memset(&ifReq, 0, sizeof(ifReq));
    sprintf(ifReq.ifr_name,"%s", networkId);
    // Get the ifindex
    retval = ioctl(fd, SIOCGIFINDEX, &ifReq);
    if (retval == 0)
    {
        // Bind the socket to the given interface
        retval = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifReq, sizeof(ifReq));

        if (retval == 0)
        {
            rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Finished binding fd %d to %s",
                           fd, networkId);
        }
        else
        {
            rtpp_log_write(RTPP_LOG_ERR, cf->glog, "Failed to bind fd %d to %s; Error: %s",
                           fd, networkId, strerror(errno));
        }
    }
    else
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "ioctl failed for if %s; Error: %s",
                       ifReq.ifr_name, strerror(errno));
    }

    return(retval);
}






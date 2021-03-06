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
 * $Id: rtpp_record.c,v 1.12 2008/11/03 05:52:24 sobomax Exp $
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define _RTPP_RECORD_PRIVATE_
#include "rtpp_log.h"
#include "rtpp_record.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

#include <sys/un.h> // sockaddr_un
//
// the following are declarations for use with ctrace tracing
//
int g_socket_fd = -1;

// Trace Message Header
#define TRACE_SOCKET_NAME "/var/lib/nettrace/nettrace.socket"

struct ip_addr{
    unsigned int af;    /* address family: AF_INET6 or AF_INET */
    unsigned int len;   /* address len, 16 or 4 */
    union {             /* 64 bits aligned address */
        struct in_addr  ip4;
        struct in6_addr ip6;
    }u;
};

typedef struct __attribute__((packed)) tag_trace_header
{       /* Warning: update TRACE_HEADER_LEN 72                          */
        unsigned long int       tv_sec;     /* 04                                                           */
        unsigned long int       tv_usec;    /* 04                                                           */
        struct ip_addr          srcip;      /* 24 source info                                               */
        struct ip_addr          dstip;      /* 24 destination info                                          */
        unsigned short int      srcport;    /* 02                                                           */
        unsigned short int      dstport;    /* 02                                                           */
        unsigned short int      msglen;     /* 02 message length                                            */
        unsigned char           transport;  /* 01 transport                                                 */
        uint64_t                dummy_8;    /* 01 dummy value used to keep struct size multiple of 4 and 3  */
        uint8_t                 dummy_1;    /* 01 dummy value used to keep struct size multiple of 4 and 3  */
} trace_header;

#define TRACE_HEADER_LEN  72
#define TRACE_MESSAGE_LEN 2048
#define TRACE_HEADER_LEN_ENCODED  ((TRACE_HEADER_LEN*4)/3)
#define TRACE_MESSAGE_LEN_ENCODED (((TRACE_MESSAGE_LEN*4)/3)+2)
#define TRACE_BUFFER_LEN          (TRACE_HEADER_LEN_ENCODED+TRACE_MESSAGE_LEN_ENCODED+1)

typedef union tag_trace {
    struct {
        trace_header header;
        unsigned char data[TRACE_MESSAGE_LEN+2];
    } msg;
    unsigned char data[TRACE_HEADER_LEN+TRACE_MESSAGE_LEN+2];
} trace;

static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


#define TRACE_SOCKET_NAME "/var/lib/nettrace/nettrace.socket"
//
// end ctrace declarations/definitions
//

enum record_mode {MODE_LOCAL_PKT, MODE_REMOTE_RTP, MODE_LOCAL_PCAP}; /* MODE_LOCAL_RTP/MODE_REMOTE_PKT? */

struct rtpp_record_channel {
    char spath[PATH_MAX + 1];
    char rpath[PATH_MAX + 1];
    int fd;
    int needspool;
    char rbuf[4096];
    int rbuf_len;
    enum record_mode mode;
};

#define RRC_CAST(x) ((struct rtpp_record_channel *)(x))

void *
ropen(struct cfg *cf, struct rtpp_session *sp, char *rname, int orig)
{
    struct rtpp_record_channel *rrc;
    const char *sdir;
    char *cp, *tmp;
    int n, port, rval;
    struct sockaddr_storage raddr;
    pcap_hdr_t pcap_hdr;

    rrc = (struct rtpp_record_channel *)malloc(sizeof(*rrc));
    if (rrc == NULL) {
    rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "can't allocate memory");
    return NULL;
    }
    memset(rrc, 0, sizeof(*rrc));

    if (rname != NULL && strncmp("udp:", rname, 4) == 0) {
    tmp = strdup(rname + 4);
    if (tmp == NULL) {
        rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "can't allocate memory");
        return NULL;
    }
    rrc->mode = MODE_REMOTE_RTP;
    rrc->needspool = 0;
    cp = strrchr(tmp, ':');
    if (cp == NULL) {
        rtpp_log_write(RTPP_LOG_ERR, sp->log, "remote recording target specification should include port number");
        free(rrc);
        free(tmp);
        return NULL;
    }
    *cp = '\0';
    cp++;

    if (sp->rtcp == NULL) {
        /* Handle RTCP (increase target port by 1) */
        port = atoi(cp);
        if (port <= 0 || port > ((sp->rtcp != NULL) ? 65534 : 65535)) {
        rtpp_log_write(RTPP_LOG_ERR, sp->log, "invalid port in the remote recording target specification");
        free(rrc);
        free(tmp);
        return NULL;
        }
        sprintf(cp, "%d", port + 1);
    }

    n = resolve(sstosa(&raddr), AF_INET, tmp, cp, AI_PASSIVE);
    if (n != 0) {
        rtpp_log_write(RTPP_LOG_ERR, sp->log, "ropen: getaddrinfo: %s", gai_strerror(n));
        free(rrc);
        free(tmp);
        return NULL;
    }
    rrc->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rrc->fd == -1) {
        rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "ropen: can't create socket");
        free(rrc);
        free(tmp);
        return NULL;
    }
    if (connect(rrc->fd, sstosa(&raddr), SA_LEN(sstosa(&raddr))) == -1) {
        rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "ropen: can't connect socket");
        close(rrc->fd);
        free(rrc);
        free(tmp);
        return NULL;
    }
    free(tmp);
    return (void *)(rrc);
    }

    if (cf->rdir == NULL) {
    rtpp_log_write(RTPP_LOG_ERR, sp->log, "directory for saving local recordings is not configured");
    free(rrc);
    return NULL;
    }

    if (cf->record_pcap != 0) {
    rrc->mode = MODE_LOCAL_PCAP;
    } else {
    rrc->mode = MODE_LOCAL_PKT;
    }

    if (cf->sdir == NULL) {
    sdir = cf->rdir;
    rrc->needspool = 0;
    } else {
    sdir = cf->sdir;
    rrc->needspool = 1;
    if (rname == NULL) {
        sprintf(rrc->rpath, "%s/%s=%s.%c.%s", cf->rdir, sp->call_id, sp->tag,
          (orig != 0) ? 'o' : 'a', (sp->rtcp != NULL) ? "rtp" : "rtcp");
    } else {
        sprintf(rrc->rpath, "%s/%s.%s", cf->rdir, rname,
          (sp->rtcp != NULL) ? "rtp" : "rtcp");
    }
    }
    if (rname == NULL) {
    sprintf(rrc->spath, "%s/%s=%s.%c.%s", sdir, sp->call_id, sp->tag,
      (orig != 0) ? 'o' : 'a', (sp->rtcp != NULL) ? "rtp" : "rtcp");
    } else {
    sprintf(rrc->spath, "%s/%s.%s", sdir, rname,
      (sp->rtcp != NULL) ? "rtp" : "rtcp");
    }
    rrc->fd = open(rrc->spath, O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);
    if (rrc->fd == -1) {
    rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "can't open file %s for writing",
      rrc->spath);
    free(rrc);
    return NULL;
    }

    if (rrc->mode == MODE_LOCAL_PCAP) {
    pcap_hdr.magic_number = PCAP_MAGIC;
    pcap_hdr.version_major = PCAP_VER_MAJR;
    pcap_hdr.version_minor = PCAP_VER_MINR;
    pcap_hdr.thiszone = 0;
    pcap_hdr.sigfigs = 0;
    pcap_hdr.snaplen = 65535;
    pcap_hdr.network = DLT_NULL;
    rval = write(rrc->fd, &pcap_hdr, sizeof(pcap_hdr));
    if (rval == -1) {
        close(rrc->fd);
        rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "%s: error writing header",
          rrc->spath);
        free(rrc);
        return NULL;
    }
    if (rval < sizeof(pcap_hdr)) {
        close(rrc->fd);
        rtpp_log_write(RTPP_LOG_ERR, sp->log, "%s: short write writing header",
          rrc->spath);
        free(rrc);
        return NULL;
    }
    }

    return (void *)(rrc);
}

static int
flush_rbuf(struct rtpp_session *sp, void *rrc)
{
    int rval;

    rval = write(RRC_CAST(rrc)->fd, RRC_CAST(rrc)->rbuf, RRC_CAST(rrc)->rbuf_len);
    if (rval != -1) {
    RRC_CAST(rrc)->rbuf_len = 0;
    return 0;
    }

    rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "error while recording session (%s)",
      (sp->rtcp != NULL) ? "RTP" : "RTCP");
    /* Prevent futher writing if error happens */
    close(RRC_CAST(rrc)->fd);
    RRC_CAST(rrc)->fd = -1;
    return -1;
}

static int
prepare_pkt_hdr_adhoc(struct rtpp_session *sp, struct rtp_packet *packet, struct pkt_hdr_adhoc *hdrp)
{

    memset(hdrp, 0, sizeof(*hdrp));
    hdrp->time = packet->rtime;
    if (hdrp->time == -1) {
    rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "can't get current time");
    return -1;
    }
    switch (sstosa(&packet->raddr)->sa_family) {
    case AF_INET:
    hdrp->addr.in4.sin_family = sstosa(&packet->raddr)->sa_family;
    hdrp->addr.in4.sin_port = satosin(&packet->raddr)->sin_port;
    hdrp->addr.in4.sin_addr = satosin(&packet->raddr)->sin_addr;
    break;

    case AF_INET6:
    hdrp->addr.in6.sin_family = sstosa(&packet->raddr)->sa_family;
    hdrp->addr.in6.sin_port = satosin6(&packet->raddr)->sin6_port;
    hdrp->addr.in6.sin_addr = satosin6(&packet->raddr)->sin6_addr;
    break;

    default:
    abort();
    }

    hdrp->plen = packet->size;
    return 0;
}

static uint16_t ip_id = 0;

static int
prepare_pkt_hdr_pcap(struct rtpp_session *sp, struct rtp_packet *packet, struct pkt_hdr_pcap *hdrp)
{

    if (packet->rtime == -1) {
    rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "can't get current time");
    return -1;
    }

    if (sstosa(&packet->raddr)->sa_family != AF_INET) {
    rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "only AF_INET pcap format is supported");
    return -1;
    }

    memset(hdrp, 0, sizeof(*hdrp));
    dtime2ts(packet->rtime, &(hdrp->pcaprec_hdr.ts_sec), &(hdrp->pcaprec_hdr.ts_usec));
    hdrp->pcaprec_hdr.orig_len = hdrp->pcaprec_hdr.incl_len = sizeof(*hdrp) -
      sizeof(hdrp->pcaprec_hdr) + packet->size;

    hdrp->family = sstosa(&packet->raddr)->sa_family;

    /* Prepare fake IP header */
    hdrp->iphdr.ip_v = 4;
    hdrp->iphdr.ip_hl = sizeof(hdrp->iphdr) >> 2;
    hdrp->iphdr.ip_len = htons(sizeof(hdrp->iphdr) + sizeof(hdrp->udphdr) + packet->size);
    hdrp->iphdr.ip_src = satosin(&(packet->raddr))->sin_addr;
    hdrp->iphdr.ip_dst = satosin(packet->laddr)->sin_addr;
    hdrp->iphdr.ip_p = IPPROTO_UDP;
    hdrp->iphdr.ip_id = htons(ip_id++);
    hdrp->iphdr.ip_ttl = 127;
    hdrp->iphdr.ip_sum = rtpp_in_cksum(&(hdrp->iphdr), sizeof(hdrp->iphdr));

    /* Prepare fake UDP header */
    hdrp->udphdr.source = satosin(&packet->raddr)->sin_port;
    hdrp->udphdr.dest = htons(packet->rport);
    hdrp->udphdr.len = htons(sizeof(hdrp->udphdr) + packet->size);

    return 0;
}

void
rwrite(struct rtpp_session *sp, void *rrc, struct rtp_packet *packet)
{
    struct iovec v[2];
    union {
    struct pkt_hdr_pcap pcap;
    struct pkt_hdr_adhoc adhoc;
    } hdr;
    int rval, hdr_size;
    int (*prepare_pkt_hdr)(struct rtpp_session *, struct rtp_packet *, void *);

    if (RRC_CAST(rrc)->fd == -1)
    return;

    switch (RRC_CAST(rrc)->mode) {
    case MODE_REMOTE_RTP:
    send(RRC_CAST(rrc)->fd, packet->data.buf, packet->size, 0);
    return;

    case MODE_LOCAL_PKT:
    hdr_size = sizeof(hdr.adhoc);
    prepare_pkt_hdr = (int (*)(rtpp_session*, rtp_packet*, void*))&prepare_pkt_hdr_adhoc;
    break;

    case MODE_LOCAL_PCAP:
    hdr_size = sizeof(hdr.pcap);
    prepare_pkt_hdr = (int (*)(rtpp_session*, rtp_packet*, void*))&prepare_pkt_hdr_pcap;
    break;
    }

    /* Check if the write buffer has necessary space, and flush if not */
    if ((RRC_CAST(rrc)->rbuf_len + hdr_size + packet->size > sizeof(RRC_CAST(rrc)->rbuf)) && RRC_CAST(rrc)->rbuf_len > 0)
    if (flush_rbuf(sp, rrc) != 0)
        return;

    /* Check if received packet doesn't fit into the buffer, do synchronous write  if so */
    if (RRC_CAST(rrc)->rbuf_len + hdr_size + packet->size > sizeof(RRC_CAST(rrc)->rbuf)) {
    if (prepare_pkt_hdr(sp, packet, (void *)&hdr) != 0)
        return;

    v[0].iov_base = (void *)&hdr;
    v[0].iov_len = hdr_size;
    v[1].iov_base = packet->data.buf;
    v[1].iov_len = packet->size;

    rval = writev(RRC_CAST(rrc)->fd, v, 2);
    if (rval != -1)
        return;

    rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "error while recording session (%s)",
      (sp->rtcp != NULL) ? "RTP" : "RTCP");
    /* Prevent futher writing if error happens */
    close(RRC_CAST(rrc)->fd);
    RRC_CAST(rrc)->fd = -1;
    return;
    }
    if (prepare_pkt_hdr(sp, packet, (void *)(RRC_CAST(rrc)->rbuf + RRC_CAST(rrc)->rbuf_len)) != 0)
    return;
    RRC_CAST(rrc)->rbuf_len += hdr_size;
    memcpy(RRC_CAST(rrc)->rbuf + RRC_CAST(rrc)->rbuf_len, packet->data.buf, packet->size);
    RRC_CAST(rrc)->rbuf_len += packet->size;
}

void
rclose(struct rtpp_session *sp, void *rrc, int keep)
{

    if (RRC_CAST(rrc)->mode != MODE_REMOTE_RTP && RRC_CAST(rrc)->rbuf_len > 0)
    flush_rbuf(sp, rrc);

    if (RRC_CAST(rrc)->fd != -1)
    close(RRC_CAST(rrc)->fd);

    if (RRC_CAST(rrc)->mode == MODE_REMOTE_RTP)
    return;

    if (keep == 0) {
    if (unlink(RRC_CAST(rrc)->spath) == -1)
        rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "can't remove "
          "session record %s", RRC_CAST(rrc)->spath);
    } else if (RRC_CAST(rrc)->needspool == 1) {
    if (rename(RRC_CAST(rrc)->spath, RRC_CAST(rrc)->rpath) == -1)
        rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "can't move "
          "session record from spool into permanent storage");
    }

    free(rrc);
}

//
// ctrace interfaces begin
//
void r_rtp_ctrace(struct rtpp_session *sp,int transport,
                         struct rtp_packet *packet)
{

    if(packet == NULL || sp==NULL || packet->size==0)
    {
      return;
    }

    int i, j;
    union {
        trace_header header;
        unsigned char data[TRACE_HEADER_LEN];
    } un;
    struct timeval now;
    char buf[TRACE_BUFFER_LEN+16];
    int err;
    unsigned char *msg=0;

    int len=packet->size;

    /* truncate the message */
    if (len > TRACE_MESSAGE_LEN)
        len = TRACE_MESSAGE_LEN;

    /* fill the message header */
    gettimeofday(&now, NULL);
    un.header.tv_sec = now.tv_sec;
    un.header.tv_usec = now.tv_usec;

    switch (sstosa(&packet->raddr)->sa_family)
    {
      case AF_INET:
        un.header.srcip.af = un.header.dstip.af = sstosa(&packet->raddr)->sa_family;
        un.header.srcport = ntohs(satosin(&packet->raddr)->sin_port);
        un.header.srcip.u.ip4.s_addr = satosin(&packet->raddr)->sin_addr.s_addr;
        un.header.srcip.len=4;

        un.header.dstip.af = sstosa(packet->laddr)->sa_family;
        un.header.dstport = packet->rport;
        un.header.dstip.u.ip4.s_addr = satosin(packet->laddr)->sin_addr.s_addr;
        un.header.dstip.len=4;
      break;

      case AF_INET6:
        un.header.srcip.af = un.header.dstip.af = sstosa(&packet->raddr)->sa_family;
        un.header.srcport = ntohs(satosin6(&packet->raddr)->sin6_port);
        memcpy(un.header.srcip.u.ip6.s6_addr,
              satosin6(&packet->raddr)->sin6_addr.s6_addr,
              sizeof(un.header.srcip.u.ip6.s6_addr));
        un.header.srcip.len=16;

        un.header.dstport = packet->rport;
        memcpy(un.header.dstip.u.ip6.s6_addr,
              satosin6(packet->laddr)->sin6_addr.s6_addr,
              sizeof(un.header.dstip.u.ip6.s6_addr));
        un.header.dstip.len=16;
      break;

      default:
        break;
    }

    msg = packet->data.buf;
    un.header.msglen = len;
    un.header.transport = transport;
    un.header.dummy_1 = 0;
    un.header.dummy_8 = 0;
    strcpy(buf, "@NETWORKTRACE@");

    /* encode the message */
    for (i=0, j=14; i<TRACE_HEADER_LEN; i+=3, j+=4)
    {
        buf[j] =   (unsigned char ) cb64[ un.data[i] >> 2 ];
        buf[j+1] = (unsigned char ) cb64[ ((un.data[i] & 0x03) << 4) | ((un.data[i+1] & 0xf0) >> 4) ];
        buf[j+2] = (unsigned char ) cb64[ ((un.data[i+1] & 0x0f) << 2) | ((un.data[i+2] & 0xc0) >> 6) ];
        buf[j+3] = (unsigned char ) cb64[ un.data[i+2] & 0x3f ];
    }
    for (i=0; i<len; i+=3, j+=4)
    {
        buf[j] =   (unsigned char ) cb64[ msg[i] >> 2 ];
        buf[j+1] = (unsigned char ) cb64[ ((msg[i] & 0x03) << 4) | ((msg[i+1] & 0xf0) >> 4) ];
        buf[j+2] = (unsigned char ) cb64[ ((msg[i+1] & 0x0f) << 2) | ((msg[i+2] & 0xc0) >> 6) ];
        buf[j+3] = (unsigned char ) cb64[ msg[i+2] & 0x3f ];
    }
    buf[j++]='\n';
    buf[j]='\0';

     if (g_socket_fd < 0)
    {
        if (r_rtp_ctrace_connect(sp))
        {
            return;
        }
    }

    if (send(g_socket_fd, buf, j, MSG_DONTWAIT|MSG_NOSIGNAL) < 0)
    {
        err = errno;

        /* Problem sending message to CTRACE, discard the message (this should not happen besides a problem
        in the socket or in the CTRACE application (i.e. buffer full or application restart)... hopeful the next message will succeed) */
        rtpp_log_write(RTPP_LOG_ERR, sp->log,"osb trace: can't send message: %s", strerror(err));

        if (EAGAIN != err)
        {
            /* Disconnect in case of unrecoverable errors */
            close(g_socket_fd);
            g_socket_fd = -1;
        }
    }

}

int r_rtp_ctrace_connect (struct rtpp_session *sp)
{
    int     len;
    struct  sockaddr_un name;
    int     flags;
    socklen_t rcv_buffer_sz = 0x200000;
    socklen_t snd_buffer_sz = 0x200000;

    if (g_socket_fd != -1)
        close (g_socket_fd);
    g_socket_fd = -1;

    if (access(TRACE_SOCKET_NAME, F_OK) == 0)
    {
        /*------------------------------*/
        /* Create the socket.           */
        /*------------------------------*/
        g_socket_fd = socket (PF_LOCAL, SOCK_STREAM, 0);
        name.sun_family = AF_LOCAL;
        strcpy (name.sun_path, TRACE_SOCKET_NAME);

        /*----------------------------------*/
        /* Set socket to non-blocking       */
        /*----------------------------------*/
        if ((flags = fcntl(g_socket_fd, F_GETFL, 0)) < 0)
        {
             rtpp_log_write(RTPP_LOG_ERR, sp->log,"Can't get flags");
            close (g_socket_fd);
            return 1;
        }
        if (fcntl(g_socket_fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
             rtpp_log_write(RTPP_LOG_ERR, sp->log,"Can't set flags");
            close (g_socket_fd);
            return 1;
        }

        /*----------------------------------*/
        /* Set snd/rcv buffer sizes         */
        /*----------------------------------*/
        if(setsockopt(g_socket_fd, SOL_SOCKET, SO_SNDBUF, (char *) &snd_buffer_sz, sizeof(socklen_t)) == -1)
        {
             rtpp_log_write(RTPP_LOG_ERR, sp->log,"Can't set SO_SNDBUF on socket");
            close(g_socket_fd);
            return 1;
        }
        if(setsockopt(g_socket_fd, SOL_SOCKET, SO_RCVBUF, (char *) &rcv_buffer_sz, sizeof(socklen_t)) == -1)
        {
             rtpp_log_write(RTPP_LOG_ERR, sp->log,"Can't set SO_RCVBUF on socket");
            close(g_socket_fd);
            return 1;
        }

        /*------------------------------*/
        /* Connect the socket.          */
        /*------------------------------*/
        len = (int)(strlen(name.sun_path)+sizeof(name.sun_family));

        if (connect (g_socket_fd, (struct sockaddr *)&name, len) < 0)
        {
             rtpp_log_write(RTPP_LOG_ERR, sp->log,"Can't connect");
            close (g_socket_fd);
            return 1;
        }
    }
    else
    {
         rtpp_log_write(RTPP_LOG_ERR, sp->log,"Unable to open %s", TRACE_SOCKET_NAME);
        return 1;
    }

    return 0;
}

void r_rtp_ctrace_disconnect ()
{
    if (g_socket_fd != -1)
        close (g_socket_fd);
    g_socket_fd = -1;
}
// ctrace interfaces end
//

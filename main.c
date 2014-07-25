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
 * $Id: main.c,v 1.87.2.3 2009/10/06 10:26:17 sobomax Exp $
 *
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include "rtp.h"
#include "rtp_resizer.h"
#include "rtp_server.h"
#include "rtpp_defines.h"
#include "rtpp_command.h"
#include "rtpp_log.h"
#include "rtpp_record.h"
#include "rtpp_session.h"
#include "rtpp_util.h"
#include "rtpp_dtls.h"
#include "rtpp_stun.h"

// #define DEBUG
/* To enable the SRTP DEBUG logs from the library*/
//#define DEBUG_SRTP

struct rtp_data_list* active_resized_sp_list = NULL;
int g_use_timed_resizer=1;

#ifdef DEBUG
const char *tfn = "/tmp/rtppdbg.log";
FILE *tfp = NULL;

inline unsigned int char_to_index(unsigned char c)
{
    if(c >= '0' && c <= '9')return (c - '0');
    if(c >= 'A' && c <= 'F')return (c - 'A' + 10);
    if(c >= 'a' && c <= 'f')return (c - 'a' + 10);
}
static unsigned char *
hex_to_bin(unsigned char *dest, size_t dest_len, unsigned char *src, size_t src_len)
{
    static const unsigned char lnv[16] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    static const unsigned char unv[16] =
    {
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0
    };

    size_t max = src_len / 2;
    if(max > dest_len)max = dest_len;

    size_t sidx, didx;
    for(sidx = 0, didx = 0; didx < dest_len && sidx < src_len; ++didx, sidx += 2)
    {
        dest[didx] = unv[char_to_index(src[sidx])] + lnv[char_to_index(src[sidx+1])];
    }
    for(;didx < dest_len; ++didx)dest[didx] = '\0'; // Pad remainder with 0

    return dest;
}

static unsigned char *bin_to_hex(unsigned char *dest, size_t dest_len, unsigned char *src, size_t src_len)
{
    if(dest_len < 3)
    {
        if(dest_len > 0)
            dest[0] = '\0';
        return dest;
    }

    size_t max = (dest_len - 1)/2;
    if(max > src_len)max = src_len;

    size_t didx = 0;
    for(size_t idx = 0; idx < max; ++idx)
    {
        unsigned char c = src[idx] >> 4;
        if(c < 10)
            dest[didx++] = ('0' + c);
        else
            dest[didx++] = ('A' + (c - 10));

        c = src[idx] & 0x0f;
        if(c < 10)
            dest[didx++] = ('0' + c);
        else
            dest[didx++] = ('A' + (c - 10));
    }
    dest[didx] = '\0';

    return dest;
}

#endif
static const char *cmd_sock = CMD_SOCK;
static const char *pid_file = PID_FILE;
rtpp_log_t glog;
int g_rtp_ctrace_enabled=0;

static void usage(void);
static void send_packet(struct cfg *, struct rtpp_session *, int,
  struct rtp_packet *);
static void set_capabilities(struct cfg *cf);


static void usage(void)
{

    fprintf(stderr, "usage: rtpproxy [-2fvFiPa] [-l addr1[/addr2]] "
      "[-6 addr1[/addr2]] [-s path]\n\t[-t tos[/vtos]] [-r rdir [-S sdir]] [-T ttl] "
      "[-L nfiles] [-m port_min]\n\t[-M port_max] [-v port_min]\n\t[-V port_max] [-u uname[:gname]] "
      "[-n timeout_socket] [-d log_level[:log_facility]]\n");
    exit(1);
}

static void
fatsignal(int sig)
{

    rtpp_log_write(RTPP_LOG_INFO, glog, "got signal %d", sig);
    exit(0);
}

static void
ehandler(void)
{

    unlink(cmd_sock);
    unlink(pid_file);
    rtp_transcoder_shutdown();
    rtpp_log_write(RTPP_LOG_INFO, glog, "rtpproxy ended");
    rtpp_log_close(glog);
}

/**
 * set_capabilities - Set process capabilities
 *
 * @param cf (in) - Config
 *
 * Notes: Added for FRN4811.
 */
static void set_capabilities(struct cfg *cf)
{
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct   data;

    memset(&header, 0, sizeof(header));
    memset(&data, 0, sizeof(data));

    header.version = _LINUX_CAPABILITY_VERSION;
    header.pid = getpid();

   /*
    *  Mask all process capabilities except for CAP_NET_RAW & CAP_NET_ADMIN
    * (Needed for SO_BINDTODEVICE - FRN4811 and TOS)
    */
    data.effective    = (1U << CAP_NET_RAW);
    data.permitted    = (1U << CAP_NET_RAW);
    data.inheritable  = (1U << CAP_NET_RAW);
    data.effective   |= (1U << CAP_NET_ADMIN);
    data.permitted   |= (1U << CAP_NET_ADMIN);
    data.inheritable |= (1U << CAP_NET_ADMIN);

    if (syscall(SYS_capset, &header, &data) < 0)
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog,
                "Failed to set process capability" );
    }
}

static void init_config(struct cfg *cf, int argc, char **argv)
{
    int ch, i;
    char *bh[2], *bh6[2], *cp;
    struct passwd *pp;
    struct group *gp;
    short cmdvidmin, cmdvidmax, avdiv;

    bh[0] = bh[1] = bh6[0] = bh6[1] = NULL;
    cmdvidmin = cmdvidmax = avdiv = 0;

    cf->port_min = PORT_MIN;
    cf->port_max = PORT_MAX;

    // video port valid only if specified in command line
    cf->video_port_min = 0;
    cf->video_port_max = 0;

    cf->max_ttl = SESSION_TIMEOUT;
    cf->tos = DEF_AUD_TOS;
    cf->video_tos = DEF_VIDEO_TOS;
    cf->rrtcp = 1;
    cf->ttl_mode = TTL_UNIFIED;
    cf->log_level = -1;
    cf->log_facility = -1;

    cf->timeout_handler.socket_name = NULL;
    cf->timeout_handler.fd = -1;
    cf->timeout_handler.connected = 0;

    if (getrlimit(RLIMIT_NOFILE, &(cf->nofile_limit)) != 0) {
    err(1, "getrlimit");
    exit(1);
    }

    while ((ch = getopt(argc, argv, "vf2Rl:6:s:S:t:r:p:T:L:m:M:y:Y:u:Fin:Pad:Z:")) != -1)
    switch (ch) {
    case 'f':
        cf->nodaemon = 1;
        break;

    case 'l':
        bh[0] = optarg;
        bh[1] = strchr(bh[0], '/');
        if (bh[1] != NULL) {
        *bh[1] = '\0';
        bh[1]++;
        cf->bmode = 1;
        }
        break;

    case '6':
        bh6[0] = optarg;
        bh6[1] = strchr(bh6[0], '/');
        if (bh6[1] != NULL) {
        *bh6[1] = '\0';
        bh6[1]++;
        cf->bmode = 1;
        }
        break;

    case 's':
        if (strncmp("udp:", optarg, 4) == 0) {
        cf->umode = 1;
        optarg += 4;
        } else if (strncmp("udp6:", optarg, 5) == 0) {
        cf->umode = 6;
        optarg += 5;
        } else if (strncmp("unix:", optarg, 5) == 0) {
        cf->umode = 0;
        optarg += 5;
        }
        cmd_sock = optarg;
        break;

    case 't':
      {
        char* tstr = optarg;

        char* tosval  = rtpp_strsep(&tstr, "/");
        if(tosval != NULL) cf->tos = atoi(tosval);

        tosval = rtpp_strsep(&tstr, "/");
        if(tosval != NULL) cf->video_tos = atoi(tosval);

        if (cf->tos > 255)
          errx(1, "%d: TOS is too large", cf->tos);
        if (cf->video_tos > 255)
          errx(1, "%d: Video TOS is too large", cf->video_tos);
       }
       break;

    case '2':
        cf->dmode = 1;
        break;

    case 'v':
        printf("Basic version: %d\n", CPROTOVER);
        for (i = 1; proto_caps[i].pc_id != NULL; ++i) {
        printf("Extension %s: %s\n", proto_caps[i].pc_id,
            proto_caps[i].pc_description);
        }
        exit(0);
        break;

    case 'r':
        cf->rdir = optarg;
        break;

    case 'S':
        cf->sdir = optarg;
        break;

    case 'R':
        cf->rrtcp = 0;
        break;

    case 'p':
        pid_file = optarg;
        break;

    case 'T':
        cf->max_ttl = atoi(optarg);
        break;

    case 'L':
        cf->nofile_limit.rlim_cur = cf->nofile_limit.rlim_max = atoi(optarg);
        if (setrlimit(RLIMIT_NOFILE, &(cf->nofile_limit)) != 0) {
        err(1, "setrlimit");
        exit(1);
        }
        if (getrlimit(RLIMIT_NOFILE, &(cf->nofile_limit)) != 0) {
        err(1, "getrlimit");
        exit(1);
        }
        if ((int)cf->nofile_limit.rlim_max < atoi(optarg))
        warnx("limit allocated by setrlimit (%d) is less than "
          "requested (%d)", (int) cf->nofile_limit.rlim_max,
          atoi(optarg));
        break;

    case 'm':
        cf->port_min = atoi(optarg);
        break;

    case 'M':
        cf->port_max = atoi(optarg);
        break;

    case 'y':
        cf->video_port_min = atoi(optarg);
        cmdvidmin = 1;
        break;

    case 'Y':
        cf->video_port_max = atoi(optarg);
        cmdvidmax = 1;
        break;

    case 'u':
        cf->run_uname = optarg;
        cp = strchr(optarg, ':');
        if (cp != NULL) {
        if (cp == optarg)
            cf->run_uname = NULL;
        cp[0] = '\0';
        cp++;
        }
        cf->run_gname = cp;
        cf->run_uid = -1;
        cf->run_gid = -1;
        if (cf->run_uname != NULL) {
        pp = getpwnam(cf->run_uname);
        if (pp == NULL)
            err(1, "can't find ID for the user: %s", cf->run_uname);
        cf->run_uid = pp->pw_uid;
        if (cf->run_gname == NULL)
            cf->run_gid = pp->pw_gid;
        }
        if (cf->run_gname != NULL) {
        gp = getgrnam(cf->run_gname);
        if (gp == NULL)
            err(1, "can't find ID for the group: %s", cf->run_gname);
        cf->run_gid = gp->gr_gid;
        }
        break;

    case 'F':
        cf->no_check = 1;
        break;

    case 'i':
        cf->ttl_mode = TTL_INDEPENDENT;
        break;

    case 'n':
        if(strncmp("unix:", optarg, 5) == 0)
        optarg += 5;
        if(strlen(optarg) == 0)
        errx(1, "timeout notification socket name too short");
        cf->timeout_handler.socket_name = (char *)malloc(strlen(optarg) + 1);
        if(cf->timeout_handler.socket_name == NULL)
        err(1, "can't allocate memory");
        strcpy(cf->timeout_handler.socket_name, optarg);
        break;

    case 'P':
        cf->record_pcap = 1;
        break;

    case 'a':
        cf->record_all = 1;
        break;

    case 'd':
        cp = strchr(optarg, ':');
        if (cp != NULL) {
        cf->log_facility = rtpp_log_str2fac(cp + 1);
        if (cf->log_facility == -1)
            errx(1, "%s: invalid log facility", cp + 1);
        *cp = '\0';
        }
        cf->log_level = rtpp_log_str2lvl(optarg);
        if (cf->log_level == -1)
        errx(1, "%s: invalid log level", optarg);
        break;

    case 'Z':
        g_use_timed_resizer = atoi(optarg);
        break;

    case '?':
    default:
        usage();
    }
    if (cf->rdir == NULL && cf->sdir != NULL) {
    errx(1, "-S switch requires -r switch");
    exit(1);
    }

    if (cf->no_check == 0 && getuid() == 0 && cf->run_uname == NULL) {
    if (cf->umode != 0) {
        errx(1, "running this program as superuser in a remote control "
          "mode is strongly not recommended, as it poses serious security "
          "threat to your system. Use -u option to run as an unprivileged "
          "user or -F is you want to run as a superuser anyway.");
        exit(1);
    } else {
        warnx("WARNING!!! Running this program as superuser is strongly "
          "not recommended, as it may pose serious security threat to "
          "your system. Use -u option to run as an unprivileged user "
          "or -F to surpress this warning.");
    }
    }

    if(cmdvidmin && cmdvidmax)
    {
        avdiv = 1;
    }

    /* make sure that port_min and port_max are even */
    if ((cf->port_min % 2) != 0)
    cf->port_min++;
    if ((cf->port_max % 2) != 0) {
    cf->port_max--;
    } else {
    /*
     * If port_max is already even then there is no
     * "room" for the RTCP port, go back by two ports.
     */
    cf->port_max -= 2;
    }

    if (cf->port_min <= 0 || cf->port_min > 65535) {
    errx(1, "invalid value of the port_min argument, "
      "not in the range 1-65535");
    exit(1);
    }
    if (cf->port_max <= 0 || cf->port_max > 65535) {
    errx(1, "invalid value of the port_max argument, "
      "not in the range 1-65535");
    exit(1);
    }
    if (cf->port_min > cf->port_max) {
    errx(1, "port_min should be less than port_max");
    exit(1);
    }

    if(avdiv)
    {
        /* make sure that video_port_min and video_port_max are even */
        if ((cf->video_port_min % 2) != 0)
          cf->video_port_min++;
          if ((cf->video_port_max % 2) != 0) {
          cf->video_port_max--;
        } else {
          /*
           * If video_port_max is already even then there is no
           * "room" for the RTCP port, go back by two ports.
           */
          cf->video_port_max -= 2;
        }

        if (cf->video_port_min <= 0 || cf->video_port_min > 65535 || cf->video_port_min < cf->port_max) {
          errx(1, "invalid value of the video_port_min argument");
          exit(1);
        }
        if (cf->video_port_max <= 0 || cf->video_port_max > 65535) {
          errx(1, "invalid value of the video_port_max argument");
          exit(1);
        }
        if (cf->video_port_min > cf->video_port_max) {
          errx(1, "video_port_min should be less than video_port_max");
          exit(1);
        }
        // init port table for video
        init_video_port_table(cf);
    }

    unsigned int session_count =  (((cf->port_max - cf->port_min + 1) * 2) + 1);
    if(avdiv)
    {
        session_count += (((cf->video_port_max - cf->video_port_min + 1) * 2) + 1);
    }

    cf->sessions = (struct rtpp_session**)malloc((sizeof cf->sessions[0]) * session_count);
    cf->rtp_servers = (struct rtpp_session**) malloc((sizeof cf->rtp_servers[0]) * session_count);
    cf->pfds = (struct pollfd *)malloc((sizeof cf->pfds[0]) * session_count);

    if (bh[0] == NULL && bh[1] == NULL && bh6[0] == NULL && bh6[1] == NULL) {
    if (cf->umode != 0){
        errx(1, "explicit binding address has to be specified in UDP "
          "command mode");
        exit(1);
    }
    bh[0] = (char *)"*";
    }

    for (i = 0; i < 2; i++) {
    if (bh[i] != NULL && *bh[i] == '\0')
        bh[i] = NULL;
    if (bh6[i] != NULL && *bh6[i] == '\0')
        bh6[i] = NULL;
    }

    i = ((bh[0] == NULL) ? 0 : 1) + ((bh[1] == NULL) ? 0 : 1) +
      ((bh6[0] == NULL) ? 0 : 1) + ((bh6[1] == NULL) ? 0 : 1);
    if (cf->bmode != 0) {
    if (bh[0] != NULL && bh6[0] != NULL) {
        errx(1, "either IPv4 or IPv6 should be configured for external "
          "interface in bridging mode, not both");
        exit(1);
    }
    if (bh[1] != NULL && bh6[1] != NULL) {
        errx(1, "either IPv4 or IPv6 should be configured for internal "
          "interface in bridging mode, not both");
        exit(1);
    }
    if (i != 2) {
        errx(1, "incomplete configuration of the bridging mode - exactly "
          "2 listen addresses required, %d provided", i);
        exit(1);
    }
    } else if (i != 1) {
    errx(1, "exactly 1 listen addresses required, %d provided", i);
    exit(1);
    }

    for (i = 0; i < 2; i++) {
    cf->bindaddr[i] = NULL;
    if (bh[i] != NULL) {
        cf->bindaddr[i] =(struct sockaddr*)malloc(sizeof(struct sockaddr_storage));
        setbindhost(cf->bindaddr[i], AF_INET, bh[i], SERVICE);
        continue;
    }
    if (bh6[i] != NULL) {
        cf->bindaddr[i] =(struct sockaddr*) malloc(sizeof(struct sockaddr_storage));
        setbindhost(cf->bindaddr[i], AF_INET6, bh6[i], SERVICE);
        continue;
    }
    }
    if (cf->bindaddr[0] == NULL) {
    cf->bindaddr[0] = cf->bindaddr[1];
    cf->bindaddr[1] = NULL;
    }

}

static int init_controlfd(struct cfg *cf)
{
    struct sockaddr_un ifsun;
    struct sockaddr_storage ifsin;
    char *cp;
    int i, controlfd, flags;

    if (cf->umode == 0) {
    unlink(cmd_sock);
    memset(&ifsun, '\0', sizeof ifsun);
#if defined(HAVE_SOCKADDR_SUN_LEN)
    ifsun.sun_len = strlen(cmd_sock);
#endif
    ifsun.sun_family = AF_LOCAL;
    strcpy(ifsun.sun_path, cmd_sock);
    controlfd = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (controlfd == -1) {
        err(1, "can't create socket");
        exit(1);
    }
    setsockopt(controlfd, SOL_SOCKET, SO_REUSEADDR, &controlfd,
      sizeof controlfd);
    if (bind(controlfd, sstosa(&ifsun), sizeof ifsun) < 0) {
        err(1, "can't bind to a socket");
        exit(1);
    }
    if ((cf->run_uname != NULL || cf->run_gname != NULL) &&
      chown(cmd_sock, cf->run_uid, cf->run_gid) == -1) {
        err(1, "can't set owner of the socket");
        exit(1);
    }
    if (listen(controlfd, 32) != 0) {
        err(1, "can't listen on a socket");
        exit(1);
    }
    } else {
    cp = (char *)strrchr(cmd_sock, ':');
    if (cp != NULL) {
        *cp = '\0';
        cp++;
    }
    if (cp == NULL || *cp == '\0')
        cp = (char *)CPORT;
    i = (cf->umode == 6) ? AF_INET6 : AF_INET;
    setbindhost(sstosa(&ifsin), i, cmd_sock, cp);
    controlfd = socket(i, SOCK_DGRAM, 0);
    if (controlfd == -1) {
        err(1, "can't create socket");
        exit(1);
    }
    if (bind(controlfd, sstosa(&ifsin), SS_LEN(&ifsin)) < 0) {
        err(1, "can't bind to a socket");
        exit(1);
    }
    }
    flags = fcntl(controlfd, F_GETFL);
    fcntl(controlfd, F_SETFL, flags | O_NONBLOCK);

    {
        struct group *gp;
        int ret;
        if( cf->run_gname != NULL ) {
            gp = getgrnam(cf->run_gname);

            if (gp == NULL)
                err(1, "can't find ID for the group: %s, %m", cf->run_gname);
            else
                ret=chown( cmd_sock, -1, gp->gr_gid );
        }

        ret=chmod( cmd_sock, 0775 );
    }

    return controlfd;
}

static void process_rtp_servers(struct cfg *cf, double dtime)
{
    int j, k, sidx, len, skipfd;
    struct rtpp_session *sp;

    skipfd = 0;
    for (j = 0; j < cf->rtp_nsessions; j++) {
    sp = cf->rtp_servers[j];
    if (sp == NULL) {
        skipfd++;
        continue;
    }
    if (skipfd > 0) {
        cf->rtp_servers[j - skipfd] = cf->rtp_servers[j];
        sp->sridx = j - skipfd;
    }
    for (sidx = 0; sidx < 2; sidx++) {
        if (sp->rtps[sidx] == NULL || sp->addr[sidx] == NULL)
        continue;
        while ((len = rtp_server_get(sp->rtps[sidx], dtime)) != RTPS_LATER) {
        if (len == RTPS_EOF) {
            rtp_server_free(sp->rtps[sidx]);
            sp->rtps[sidx] = NULL;
            if (sp->rtps[0] == NULL && sp->rtps[1] == NULL) {
            assert(cf->rtp_servers[sp->sridx] == sp);
            cf->rtp_servers[sp->sridx] = NULL;
            sp->sridx = -1;
            }
            break;
        }
        for (k = (cf->dmode && len < LBR_THRS) ? 2 : 1; k > 0; k--) {
            sendto(sp->fds[sidx], sp->rtps[sidx]->buf, len, 0,
              sp->addr[sidx], SA_LEN(sp->addr[sidx]));
        }
        }
    }
    }
    cf->rtp_nsessions -= skipfd;
}

/* demultiplex received packets, return one of the three types: rtp, stun, dtls */
/* refer to RFC5764 */
static char demux(const struct rtp_packet *packet)
{

    assert(packet != NULL);
    uint8_t first_byte= packet->data.buf[0];
#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_DBUG, glog,"Recieved Message size:%d first byte:%d (0x%x)\n",packet->size,first_byte,first_byte);
#endif
    if(first_byte > 127 && first_byte < 192) {

        //return PACKET_TYPE_RTP;
        return 'R';
    } else if(first_byte > 19 && first_byte < 64) {
        //return PACKET_TYPE_DTLS;
        return 'D';
    } else if(first_byte < 2) {
        //return PACKET_TYPE_STUN;
        return 'S';
    } else {
        //return PACKET_TYPE_INVALID;
        return 'I';
    }
}

#if 0
    if(sp->stream[ridx]->state == DTLS_STATE_OPEN || 
        return 1;    
            return 1; 
static int process_dtls_events(struct cfg *cf, struct rtpp_session *sp, int ridx, double dtime)
{
    int ret;
    rtpp_stream *st = sp->stream[ridx];
    if(!st)
      return 0;
    if(st->event & DTLS_OPEN) {
        if(st->state == DTLS_STATE_ACCEPTED) {
            if(begin_ssl_handshake(st)) {
                ret = create_srtp_context(cf, sp, ridx, st->server_write_key, st->suite, st->snd_ssrc, st->fix_srtp_seq, 1);
                ret &= create_srtp_context(cf, sp, ridx, st->client_write_key, st->suite, st->rcv_ssrc, st->fix_srtp_seq, 0);
                sp->dtls_pending = false;
                if(!ret)
                    return 0;
                else {
                    sp->secure = 1;
                    return 1;
                }
            }
        }
    }
    if(st->event & (DTLS_READ|DTLS_WRITE)) {
        if(st->state == DTLS_STATE_STARTED) {
            if(continue_ssl_handshake(st)) {
                ret = create_srtp_context(cf, sp, ridx, st->server_write_key, st->suite, st->snd_ssrc, st->fix_srtp_seq, 1);
                ret &= create_srtp_context(cf, sp, ridx, st->client_write_key, st->suite, st->rcv_ssrc, st->fix_srtp_seq, 0);
                sp->dtls_pending = false;
                if(!ret)
                    return 0;
                else {
                    sp->secure = 1;
                    return 1;
                }
            }
        }
    }
    if(st->event & DTLS_CLOSE) {
        if(st->state == DTLS_STATE_STARTED || st->state == DTLS_STATE_OPEN) {
            if(dtls_close(st))
                sp->dtls_pending = false;
                return 1;
        }
    }
    return 0;
}
#endif

static void
process_resz_packets(struct cfg *cf, rtp_data_list* plist)
{
    uint32_t curtime = getitime_millis();
    int i=0;

    if(plist)
    {
        if(!plist->node_count)
        {
            return; // return as soon as possible
        }

        rtp_data_node* cur = (rtp_data_node*)plist->head;
        rtp_data_node* tmp = NULL;
        for(i=0; i < plist->node_count; i++)
        {
          if(cur==NULL) break;

          tmp = cur->next; // save next node ptr

          timed_session_pkt* pTpkt = (timed_session_pkt*)(cur->data);

          if(pTpkt && pTpkt->sp && pTpkt->cf && pTpkt->packet)
          {
            if( curtime >= pTpkt->time_to_send_ms)
            {
               // send packet and remove it from list
               send_packet(pTpkt->cf, pTpkt->sp, pTpkt->idx, pTpkt->packet);
#ifdef DEBUG
               rtpp_log_write(RTPP_LOG_INFO, cf->glog, "sending packet seq=%d at %u  storedts %u ",
                 ntohs(pTpkt->packet->data.header.seq), curtime, pTpkt->time_to_send_ms);
#endif
               rtp_packet_free(pTpkt->packet);
               rtp_data_list_remove(cur->data, plist);
            }
          }
          cur=tmp;
        }
    }
}

int rtpp_handle_dtls_packet(struct rtpp_session *sp, int ridx, struct rtp_packet *packet)
{
   return rtpp_dtls_handle_dtls_packet(sp, ridx, packet);
}

static void
rxmit_packets(struct cfg *cf, struct rtpp_session *sp, int ridx,
  double dtime)
{
    int ndrain, i, port, ret;
    char ptype;
    struct rtp_packet *packet = NULL;
    ret=0;

    /* Repeat since we may have several packets queued on the same socket */
    for (ndrain = 0; ndrain < 5; ndrain++) {
        if (packet != NULL){
            rtp_packet_free(packet);
        }
        packet = rtp_recv(sp->fds[ridx]);
        if (packet == NULL){
            break;
        }
        // demux the packets we receive and send them to thier corresponding handlers
        // can be one of the three: rtp, stun, dtls
        ptype = demux(packet);

        switch (ptype)
        {
            case 'R':
                // for RTP packets simply forward
                break;
            case 'D':
                ret = rtpp_handle_dtls_packet(sp, ridx, packet);
                continue;
            case 'S':
                ret= rtpp_stun_handle_msg(sp, ridx,  packet);
                if(ret == RTPP_STUN_STATUS_MEM_FAIL)
                {
                     rtpp_log_write(RTPP_LOG_ERR, sp->log,"STUN Mem Alloc Failed remvoing session");
                     remove_session(cf, GET_RTP(sp));
                     goto end;
                }
                continue;
            case 'I':
            default:
                // unrecognized packets -> forward;
                break;
        }
#ifdef DEBUG
    if(tfp)
    {
        fprintf(tfp, "After rtp_recv: packet on FD:port %d:%d with SEQ:%u from %s:%d\n",
                sp->fds[ridx], sp->ports[ridx], ntohs(packet->data.header.seq),
                addr2char(sstosa(&packet->raddr)), addr2port(sstosa(&packet->raddr)));
    }
#endif

    if( sp->drop_rtp_packets)
    {
#ifdef DEBUG
    if(tfp)
    {
        fprintf(tfp, "Dropping packet with SEQ:%u from %s:%d\n",
                ntohs(packet->data.header.seq),
                addr2char(sstosa(&packet->raddr)),
                addr2port(sstosa(&packet->raddr)));
    }
#endif
       continue;
    }
    if(!packet->size) // got empty udp packet or invalid pkt size
    {
       rtpp_log_write(RTPP_LOG_INFO, sp->log,
         "Got invalid packet data size on FD:port %d:%d from %s:%d. Dropping..",
         sp->fds[ridx], sp->ports[ridx],
         addr2char(sstosa(&packet->raddr)), addr2port(sstosa(&packet->raddr)));
       continue;
    }

    
    packet->laddr = sp->laddr[ridx];
    packet->rport = sp->ports[ridx];
    packet->rtime = dtime;
#ifdef DEBUG
    if(tfp)
    {
            fprintf(tfp, "Received packet on FD:port %d:%d with SEQ:%u from %s:%d\n",
                sp->fds[ridx], sp->ports[ridx], ntohs(packet->data.header.seq),
                addr2char(sstosa(&packet->raddr)), addr2port(sstosa(&packet->raddr)));
    }
#endif

    i = 0;
    if (sp->addr[ridx] != NULL) {
#ifdef DEBUG
          rtpp_log_write(RTPP_LOG_INFO, sp->log,
          "%s's sp->addr[ridx] != NULL address filled in: %s:%d (%s) addr[%d]:%s:%d",
          (ridx == 0) ? "callee" : "caller",
          addr2char(sstosa(&packet->raddr)), port,
          (sp->rtp == NULL) ? "RTP" : "RTCP",ridx,addr2char(sp->addr[ridx]),addr2port(sp->addr[ridx]));
#endif
        /* Check that the packet is authentic, drop if it isn't */
        if (sp->asymmetric[ridx] == 0) {
        if (memcmp(sp->addr[ridx], &packet->raddr, packet->rlen) != 0) {
            if (sp->canupdate[ridx] == 0) {
            /*
             * Continue, since there could be good packets in
             * queue.
             */
            continue;
            }
            /* Signal that an address has to be updated */
            i = 1;
        } else if (sp->canupdate[ridx] != 0 &&
          sp->last_update[ridx] != 0 &&
          dtime - sp->last_update[ridx] > UPDATE_WINDOW) {
            sp->canupdate[ridx] = 0;
        }
        } else {
        /*
         * For asymmetric clients don't check
         * source port since it may be different.
         */
        if (!ishostseq(sp->addr[ridx], sstosa(&packet->raddr)))
            /*
             * Continue, since there could be good packets in
             * queue.
             */
            continue;
        }
        sp->pcount[ridx]++;
    } else {
        sp->pcount[ridx]++;
        sp->addr[ridx] = (struct sockaddr *)malloc(packet->rlen);
        if (sp->addr[ridx] == NULL) {
        sp->pcount[3]++;
        rtpp_log_write(RTPP_LOG_ERR, sp->log,
          "can't allocate memory for remote address - "
          "removing session");
        remove_session(cf, GET_RTP(sp));
        /* Break, sp is invalid now */
        break;
        }
        /* Signal that an address have to be updated. */
        i = 1;
    }

    /*
     * Update recorded address if it's necessary. Set "untrusted address"
     * flag in the session state, so that possible future address updates
     * from that client won't get address changed immediately to some
     * bogus one.
     */
    if (i != 0) {
        sp->untrusted_addr[ridx] = 1;
        memcpy(sp->addr[ridx], &packet->raddr, packet->rlen);

            /*
            RTPPROXY was updating the change in remote IP:PORT only once due to the check below.
            So commented the check below to update remote ip:port until it reach UPDATE_WINDOW of 10 seconds.
            */
            /*
            if (sp->prev_addr[ridx] == NULL || memcmp(sp->prev_addr[ridx],
                                                      &packet->raddr, packet->rlen) != 0) {
                sp->canupdate[ridx] = 0;
            }
            */


        port = ntohs(satosin(&packet->raddr)->sin_port);

        rtpp_log_write(RTPP_LOG_INFO, sp->log,
          "%s's address filled in: %s:%d (%s)",
          (ridx == 0) ? "callee" : "caller",
          addr2char(sstosa(&packet->raddr)), port,
          (sp->rtp == NULL) ? "RTP" : "RTCP");

        /*
         * Check if we have updated RTP while RTCP is still
         * empty or contains address that differs from one we
         * used when updating RTP. Try to guess RTCP if so,
         * should be handy for non-NAT'ed clients, and some
         * NATed as well.
         */
        if (sp->rtcp != NULL && (sp->rtcp->addr[ridx] == NULL ||
          !ishostseq(sp->rtcp->addr[ridx], sstosa(&packet->raddr)))) {
        if (sp->rtcp->addr[ridx] == NULL) {
            sp->rtcp->addr[ridx] = (struct sockaddr *)malloc(packet->rlen);
            if (sp->rtcp->addr[ridx] == NULL) {
            sp->pcount[3]++;
            rtpp_log_write(RTPP_LOG_ERR, sp->log,
              "can't allocate memory for remote address - "
              "removing session");
            remove_session(cf, sp);
            /* Break, sp is invalid now */
            break;
            }
        }
        memcpy(sp->rtcp->addr[ridx], &packet->raddr, packet->rlen);
        satosin(sp->rtcp->addr[ridx])->sin_port = htons(port + 1);
        /* Use guessed value as the only true one for asymmetric clients */
        sp->rtcp->canupdate[ridx] = NOT(sp->rtcp->asymmetric[ridx]);
        rtpp_log_write(RTPP_LOG_INFO, sp->log, "guessing RTCP port "
          "for %s to be %d",
          (ridx == 0) ? "callee" : "caller", port + 1);
        }
    }
    if(sp->secure)
    {
#ifdef DEBUG
        if(tfp)
        {
            fprintf(tfp, "Calling unprotect for %s Session %p, ridx %d, From FD %d, Policy:srtp %p:%p\n",
                    ((sp->rtp)?"RTP":"SRTP"), sp, ridx, sp->fds[ridx],
                    sp->srtp[ridx].rcv_hdl.policy, sp->srtp[ridx].rcv_hdl.srtp);
            unsigned char hdrstr[128];
            fprintf(tfp, "Packet header:\n%s\n", bin_to_hex(hdrstr, 66, (unsigned char *)packet->data.buf, 32));

                fprintf(tfp, "Version:%d p:%d x:%d cc:%d m:%d pt:%d seq:%u ts:%u ssrc:(%08x)%u\n",
                    packet->data.header.version,
                    packet->data.header.p,
                    packet->data.header.x,
                    packet->data.header.cc,
                    packet->data.header.m,
                    packet->data.header.pt,
                    packet->data.header.seq,
                    packet->data.header.ts,
                    packet->data.header.ssrc,
                    packet->data.header.ssrc);
        }
#endif
        ret = rtpp_srtp_unprotect(&sp->srtp[ridx].rcv_hdl,(void *)packet->data.buf, (int *)&packet->size,((sp->rtp == NULL)?0:1));
        if(ret == rtpp_srtp_err_status_fail)
        {
                rtpp_log_write(RTPP_LOG_DBUG, sp->log, "Failed to decrypt SRTP Packet from %s:%d seq:%u ssrc:(%08x) ridx:%d",
                           addr2char(sstosa(&packet->raddr)), ntohs(satosin(&packet->raddr)->sin_port),
                        ntohs(packet->data.header.seq),ntohl(packet->data.header.ssrc), ridx);
            goto end;
        }

    }

    // trace the packet if necessary
    // after transcoding and before encrypting
    if(g_rtp_ctrace_enabled)
    {
       r_rtp_ctrace(sp,1,packet);
    }
    if (sp->rrcs[ridx] != NULL && GET_RTP(sp)->rtps[ridx] == NULL)
    {
      rwrite(sp,sp->rrcs[ridx], packet);
    }

    if (sp->resizers[ridx].output_nsamples || sp->transcode )
    {
        if( packet->data.header.pt == PT_CODEC_COMFORT_NOISE )
        {
          goto end;
        }
    }

    if (sp->transcode)
    {

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_INFO, sp->log, "transcode:%d "
          "for %s to be %d",sp->transcode,
          (ridx == 0) ? "callee" : "caller", port + 1);
#endif
       //ret= rtp_transcoder_transcode(&sp->trans[ridx], sp, (char *)packet->data.buf, (int *)&packet->size,ridx);
       ret= rtp_transcoder_decode_to_linear(&sp->trans[ridx], sp, (char *)packet->data.buf, (int *)&packet->size,ridx);

       if(ret != RTPP_TRANSCODER_OK && ret != RTPP_TRANSCODER_INVALID_PAYLOAD)
         goto end;
       if(ret == RTPP_TRANSCODER_INVALID_PAYLOAD)
       {
         goto send;
       }
       else
       {
         packet->data.header.pt = RTP_LINEAR;
#ifdef DEBUG
         rtpp_log_write(RTPP_LOG_DBUG, sp->log, "ssrc:0x%x seq:%d After linear conversion packet->size = %d ",
         ntohl( packet->data.header.ssrc), ntohs(packet->data.header.seq), packet->size);
#endif
         if(g_rtp_ctrace_enabled)
         {
             r_rtp_ctrace(sp,1,packet);
         }
       }
    }

#ifdef DEBUG
    rtpp_log_ewrite(RTPP_LOG_INFO, cf->glog,
              "ts:%u, seq:%u, rxmit_packets sp fd:%d sp->ports[%d]:%d laddr:%s, addr:%s",
              ntohl(packet->ts), ntohs(packet->data.header.seq), sp->fds[ridx], ridx,sp->ports[ridx],
              addr2char(sp->laddr[ridx]),addr2char(sp->addr[ridx]));
#endif

    if (sp->resizers[ridx].output_nsamples)
    {
      if(packet->data.header.m)
      {
          // set marker indicator before enqueue
          // used only if using timed resizer list
          sp->marker_status[ridx]=1;
      }
      rtp_resizer_enqueue(cf,&sp->resizers[ridx], &packet);
    }

send:
    if (packet != NULL)
        send_packet(cf, sp, ridx, packet);
    }
end:
    if (packet != NULL)
    rtp_packet_free(packet);
#ifdef DEBUG
    if(tfp)fflush(tfp);
#endif
}

static void
send_packet(struct cfg *cf, struct rtpp_session *sp, int ridx,
  struct rtp_packet *packet)
{
    int i, sidx, ret;

    GET_RTP(sp)->ttl[ridx] = cf->max_ttl;

    /* Select socket for sending packet out. */
    sidx = (ridx == 0) ? 1 : 0;

#ifdef DEBUG
    rtpp_log_ewrite(RTPP_LOG_INFO, cf->glog,
           "ts:%u seq:%u send_packets sp fd:%d sp->ports[%d]:%d laddr:%s addr:%s",
           ntohl(packet->ts), ntohs(packet->data.header.seq), sp->fds[sidx],sidx,sp->ports[sidx],
           addr2char(sp->laddr[sidx]),addr2char(sp->addr[sidx]));
#endif


    if(sp->transcode && sp->trans[ridx].invalid_pt==0) //encode here before sending
    {
       // use ridx
       // set paytype to to_codec if resized.
       //if (sp->resizers[ridx].output_nsamples > 0)
       //{
       //    packet->data.header.pt = sp->trans[ridx].to_payload_id;
       //}

#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log, "ssrc:0x%x seq:%d Inside send_packet packet->size = %d ",
         ntohl( packet->data.header.ssrc), ntohs(packet->data.header.seq),  packet->size);
#endif
       ret=rtp_transcoder_encode_to_codec(&sp->trans[ridx],
         sp, (char *)packet->data.buf, (int *)&packet->size, ridx);

       if(ret != RTPP_TRANSCODER_OK)
       {
           rtpp_log_write(RTPP_LOG_ERR, sp->log, "transcode failed. Dropping packet");
           return;
       }
    }

    /*
     * Check that we have some address to which packet is to be
     * sent out, drop otherwise.
     */
    if (sp->addr[sidx] == NULL || GET_RTP(sp)->rtps[sidx] != NULL) {
#ifdef DEBUG
        if(tfp) { fprintf(tfp, "Dropping packet\n"); }
#endif
    sp->pcount[3]++;
    } else {
    sp->pcount[2]++;
    for (i = (cf->dmode && packet->size < LBR_THRS) ? 2 : 1; i > 0; i--) {
#ifdef DEBUG
        if(tfp)
        {
            fprintf(tfp, "Sending packet on FD:port %d:%d to addr:port %s:%d\n",
                    sp->fds[sidx], sp->ports[sidx],
                    addr2char(sp->addr[sidx]), addr2port(sp->addr[sidx]));
        }
#endif
        if(sp->secure)
        {
            // Before encrypting the RTP packet, change the SSRC to match the expected SSRC, if appropriate.

#if 0
            uint32_t ssrc;
            extern int get_ssrc_from_policy(void *, uint32_t *);
            if(get_ssrc_from_policy(sp->srtp[sidx].snd_hdl.policy, &ssrc))
            {
#ifdef DEBUG
                if(tfp)
                {
                    fprintf(tfp, "Changing packet ssrc from 0x%x(%u) to 0x%x(%u)\n",
                            packet->data.header.ssrc, packet->data.header.ssrc, ssrc, ssrc);
                }
#endif
                packet->data.header.ssrc = ssrc;
            }
#endif
#ifdef DEBUG
            if(tfp)
            {
                fprintf(tfp, "Calling protect for Session: %p, sidx %d, FD:port %d:%d, Policy:srtp %p:%p seq:%d, packet len:%d\n",
                        sp, sidx, sp->fds[sidx], sp->ports[sidx], sp->srtp[sidx].snd_hdl.policy,
                        sp->srtp[sidx].snd_hdl.srtp, ntohs(packet->data.header.seq), (int)packet->size);
            }
#endif
            rtpp_srtp_protect(&sp->srtp[sidx].snd_hdl,(void *)packet->data.buf, (int *)&packet->size,((sp->rtp == NULL)?0:1));
        }
#ifdef DEBUG
        if(tfp)
        {
            unsigned char hdrstr[1024];
            fprintf(tfp, "Raw header just before send: %s\n", bin_to_hex(hdrstr, sizeof(hdrstr), packet->data.buf, packet->size));
        }
#endif

        sendto(sp->fds[sidx], packet->data.buf, packet->size, 0, sp->addr[sidx],
          SA_LEN(sp->addr[sidx]));

    }
    }
}

static void
process_rtp(struct cfg *cf, double dtime, int alarm_tick)
{
    int readyfd, skipfd, ridx;
    struct rtpp_session *sp;
    struct rtp_packet *packet;
    unsigned int diff=0;

    /* Relay RTP/RTCP */
    skipfd = 0;
    for (readyfd = 1; readyfd < cf->nsessions; readyfd++) {
    sp = cf->sessions[readyfd];

    if (alarm_tick != 0 && sp != NULL && sp->rtcp != NULL &&
      sp->sidx[0] == readyfd) {
        if (get_ttl(sp) == 0) {
        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "session timeout");
        do_timeout_notification(sp, 1);
        remove_session(cf, sp);
        }
        else if( sp->isCallOnHold != 1 ) { /* if call is on hold, skip decrementing ttl */
        if (sp->ttl[0] != 0)
            sp->ttl[0]--;
        if (sp->ttl[1] != 0)
            sp->ttl[1]--;
        }
    }

    if (cf->pfds[readyfd].fd == -1) {
#ifdef DEBUG
        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "Deleted session, count and move one");
#endif
        /* Deleted session, count and move one */
        skipfd++;
        continue;
    }

    /* Find index of the call leg within a session */
    for (ridx = 0; ridx < 2; ridx++)
        if (cf->pfds[readyfd].fd == sp->fds[ridx])
        break;
    /*
     * Can't happen.
     */
    assert(ridx != 2);

    /* Compact pfds[] and sessions[] by eliminating removed sessions */
    if (skipfd > 0) {
        cf->pfds[readyfd - skipfd] = cf->pfds[readyfd];
        cf->sessions[readyfd - skipfd] = cf->sessions[readyfd];
        sp->sidx[ridx] = readyfd - skipfd;;

    }
    if (sp->complete != 0) {
      // rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog,
      //  "rxmit_packets fd:%d, event:%d",cf->pfds[readyfd].fd, cf->pfds[readyfd].revents);
       if ((cf->pfds[readyfd].revents & POLLIN) != 0)
       {
          rxmit_packets(cf, sp, ridx, dtime);
       }
        if (sp->resizers[ridx].output_nsamples > 0)
        {
          if(g_use_timed_resizer)
          {
              static timed_session_pkt tpkt;
              while ((packet = rtp_resizer_get(cf,&sp->resizers[ridx], dtime)) != NULL)
              {
                // check if marker bit is set
                // only one resized pkt must have marker
                // subsequent need not have marker bit.
                if(packet->data.header.m==1)
                {
                  if(sp->marker_status[ridx]==1)
                  {
                      sp->marker_status[ridx]=0;
                  }
                  else
                    packet->data.header.m=0;
                }

                // find ts increment value based on sample size
                // we only div once by clockrate 8k
                // if it is transcoded, extra div by 2
                // if it is direct codec-to-codec with resizing
                if(packet->data.header.pt==RTP_LINEAR)
                {
                  diff=(sp->resizers[ridx].output_nsamples)/16; //  extra div by 2
                }
                else
                {
                  diff=(sp->resizers[ridx].output_nsamples)/8;
                }

                // logic for timestamp
                if(sp->incr_pkt_ts[ridx]==0)
                {
                  // if first time, set current time for first packet in list
                  sp->incr_pkt_ts[ridx] = getitime_millis();
                }
                else if( sp->rsz_pckt_list[ridx].node_count == 0
                      && (getitime_millis() - sp->incr_pkt_ts[ridx] > diff))
                {
                  // if it has been a while and we had already sent all packets in list
                  // set time to current time
                  sp->incr_pkt_ts[ridx] = getitime_millis();
                }
                else
                {
                  // increment pkt timestamp
                  sp->incr_pkt_ts[ridx]+=diff;
                }
                rtpp_log_write(RTPP_LOG_DBUG, cf->glog, "nsamp=%d packet->size=%d seq=%u math=%u sp->incr_pkt_ts[ridx] after=%u",
                 sp->resizers[ridx].output_nsamples, packet->size,  ntohs(packet->data.header.seq), diff, sp->incr_pkt_ts[ridx]);

                // fill pkt data
                memset(&tpkt, 0, sizeof(timed_session_pkt));
                tpkt.cf = cf;
                tpkt.sp = sp;
                tpkt.idx = ridx;
                tpkt.packet = packet;
                tpkt.time_to_send_ms = sp->incr_pkt_ts[ridx];
                // add packet to resized packet list
                rtp_data_list_append(&tpkt,sizeof(timed_session_pkt),&(sp->rsz_pckt_list[ridx]));
              }
          }
          else
          {
              // no need to go to timed resize list logic,
              // just send packets when received from resizer
              // and free packet
              while ((packet = rtp_resizer_get(cf,&sp->resizers[ridx], dtime)) != NULL)
              {
                  send_packet(cf, sp, ridx, packet);
                  rtp_packet_free(packet);
              }
          }
        }
#if 0
            if (sp->dtls_pending) {
                process_dtls_events(cf, sp, ridx, dtime);
            }
#endif
      }
    }
    /* Trim any deleted sessions at the end */
    cf->nsessions -= skipfd;
}

static void process_commands(struct cfg *cf, double dtime)
{
    int controlfd, i;
    socklen_t rlen;
    struct sockaddr_un ifsun;

    if ((cf->pfds[0].revents & POLLIN) == 0)
      return;



    do {
    if (cf->umode == 0) {
        rlen = sizeof(ifsun);
        controlfd = accept(cf->pfds[0].fd, sstosa(&ifsun), &rlen);
        if (controlfd == -1) {
        if (errno != EWOULDBLOCK)
            rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog,
              "can't accept connection on control socket");
        break;
        }
    } else {
        controlfd = cf->pfds[0].fd;
    }

    i = handle_command(cf, controlfd, dtime);
    if (cf->umode == 0) {
        close(controlfd);
    }
    } while (i == 0);
}

int main(int argc, char **argv)
{
    int i, len, timeout, controlfd, alarm_tick;
    double sptime, eptime, last_tick_time;
    unsigned long delay;
    struct cfg cf;
    char buf[256];

    ssize_t write_cnt;
    short int level;
#ifdef DEBUG
    tfp = fopen(tfn, "w");
#endif

    memset(&cf, 0, sizeof(cf));
    init_config(&cf, argc, argv);
    seedrandom();

    init_hash_table(&cf);
    init_port_table(&cf);

    controlfd = init_controlfd(&cf);

    if (cf.nodaemon == 0) {
    if (rtpp_daemon(0, 0) == -1)
        err(1, "can't switch into daemon mode");
        /* NOTREACHED */
    }


    glog = cf.glog = rtpp_log_open(&cf, "rtpproxy", NULL, LF_REOPEN);
    atexit(ehandler);
    level= cf.log_level;
    cf.log_level= RTPP_LOG_INFO;
    rtpp_log_write(RTPP_LOG_INFO, cf.glog, "rtpproxy started, pid %d", getpid());
    cf.log_level = level;

    rtpp_log_write(RTPP_LOG_INFO, cf.glog, "TOS Audio = %x Video = %x ", cf.tos, cf.video_tos);
    rtpp_log_write(RTPP_LOG_INFO, cf.glog, "Audio port Min = %d Max = %d", cf.port_min,cf.port_max);
    rtpp_log_write(RTPP_LOG_INFO, cf.glog, "Video port Min = %d Max = %d", cf.video_port_min, cf.video_port_max);

    i = open(pid_file, O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);
    if (i >= 0) {
        len = sprintf(buf, "%u\n", (unsigned int)getpid());
        write_cnt= write(i, buf, len);
        close(i);
    }
    else {
        rtpp_log_ewrite(RTPP_LOG_ERR, cf.glog, "can't open pidfile for writing");
    }
    if (rtp_transcoder_init(&cf) <0) {
        rtpp_log_ewrite(RTPP_LOG_ERR, cf.glog, "Transcoder Init Failed");
    }
    else {
        rtpp_log_ewrite(RTPP_LOG_INFO, cf.glog, "Transcoder Init Success");
    }
   /*
    * Loglevel DEBUG generates too many logs, So making loglevel ERROR for SRTP as
    * default. DEBUG level has to be manually enabled using DEBUG_SRTP macro.
    */
#ifdef DEBUG_SRTP
    if(rtpp_srtp_init(cf.log_level) <0)
#else
    if (rtpp_srtp_init(RTPP_LOG_ERR) <0)
#endif
    {
        rtpp_log_ewrite(RTPP_LOG_ERR, cf.glog, "SRTP LIB Init Failed");
    }
    else {
            rtpp_log_ewrite(RTPP_LOG_INFO, cf.glog, "SRTP LIB Init Success");
    }

    // OpenSSL init
    rtpp_dtls_init_openssl(&cf);

    signal(SIGHUP, fatsignal);
    signal(SIGINT, fatsignal);
    signal(SIGKILL, fatsignal);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, fatsignal);
    signal(SIGXCPU, fatsignal);
    signal(SIGXFSZ, fatsignal);
    signal(SIGVTALRM, fatsignal);
    signal(SIGPROF, fatsignal);
    signal(SIGUSR1, fatsignal);
    signal(SIGUSR2, fatsignal);

    /* Let process keep the Capabilities after the uid switch (FRN4811) */
    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

    if (cf.run_uname != NULL || cf.run_gname != NULL) {
    if (drop_privileges(&cf) != 0) {
        rtpp_log_ewrite(RTPP_LOG_ERR, cf.glog,
          "can't switch to requested user/group");
        exit(1);
    }
    }

    /* Set capabilities (FRN4811) */
    set_capabilities(&cf);

    cf.pfds[0].fd = controlfd;
    cf.pfds[0].events = POLLIN;
    cf.pfds[0].revents = 0;

    cf.sessions[0] = NULL;
    cf.nsessions = 1;
    cf.rtp_nsessions = 0;

    sptime = 0;
    last_tick_time = 0;

    rtpp_log_write(RTPP_LOG_INFO, cf.glog, "Timed resizer list enabled ? = %d", g_use_timed_resizer);

    if(g_use_timed_resizer)
    {
      rtp_data_list_allocate(&active_resized_sp_list);
    }

    for (;;) {
        if (cf.rtp_nsessions > 0 || cf.nsessions > 1)
            timeout = RTPS_TICKS_MIN;
        else
            timeout = TIMETICK * 1000;
        eptime = getdtime();
        delay = (eptime - sptime) * 1000000.0;
        if (delay < (1000000 / POLL_LIMIT)) {
            usleep((1000000 / POLL_LIMIT) - delay);
            sptime = getdtime();

        } else {
            sptime = eptime;
        }
        i = poll(cf.pfds, cf.nsessions, timeout);
        if (i < 0 && errno == EINTR)
            continue;

        eptime = getdtime();
        if (cf.rtp_nsessions > 0) {
            process_rtp_servers(&cf, eptime);
        }
        if (eptime > last_tick_time + TIMETICK) {

            alarm_tick = 1;
            last_tick_time = eptime;
        } else {
            alarm_tick = 0;
        }

        process_rtp(&cf, eptime, alarm_tick);

        if (i > 0) {
            process_commands(&cf, eptime);
        }

        if(g_use_timed_resizer)
        {
            // look for active sessions with resizers and
            // send any scheduled resized packets
            rtp_data_node* cur = (rtp_data_node*)active_resized_sp_list->head;
            int n=0;
            for(n=0; n < active_resized_sp_list->node_count; n++)
            {
              if(cur==NULL) break;
              struct active_rsz_sp* spnode = (active_rsz_sp*)(cur->data);
              if(spnode && spnode->rsz_sp)
              {
                   process_resz_packets(&cf, &(spnode->rsz_sp->rsz_pckt_list[0]));
                   process_resz_packets(&cf, &(spnode->rsz_sp->rsz_pckt_list[1]));
              }
              cur=cur->next;
            }
        }

  }
  exit(0);
}

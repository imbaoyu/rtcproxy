
#ifndef _RTPP_SRTP_H_
#define _RTPP_SRTP_H_
#include <srtp_wrapper.h>

#define rtpp_srtp_err_status_ok 0
#define rtpp_srtp_err_status_fail -1
#define rtpp_srtp_err_status_handle_null -2

typedef unsigned char		uint8_t;
typedef unsigned short int	uint16_t;
typedef unsigned int		uint32_t;

typedef struct rtpp_srtp_handle
{

	srtpw_srtp_policy *policy;
	srtpw_srtp        *srtp;
    int last_err;
    int fix_seq;/* Fix Error due to Index Too OLD*/
	unsigned short seq;
    unsigned short orig_seq;
    short int first_packet;
    unsigned long int prev_ts;
}rtpp_srtp_handle;

typedef struct rtpp_srtp_context
{
	rtpp_srtp_handle rcv_hdl;
    rtpp_srtp_handle snd_hdl;

}rtpp_srtp_ctxt;

int rtpp_srtp_init(int log_level);
int rtpp_srtp_init_context(rtpp_srtp_ctxt *ctxt);
int rtpp_srtp_destroy_policy(rtpp_srtp_handle *hndl);
int rtpp_srtp_free_context(rtpp_srtp_ctxt *ctxt);
int rtpp_srtp_create_context(struct rtpp_session *sp, int kidx,
                unsigned char *key, short int suite, uint32_t ssrc,
                int fix_srtp_seq, unsigned int snd);
int rtpp_srtp_unprotect(rtpp_srtp_handle *hdl, void *buf, int *len, int rtcp);
int rtpp_srtp_protect(rtpp_srtp_handle *hdl, void *buf, int *len, int rtcp);
int rtpp_srtp_protect_rtcp(rtpp_srtp_handle *hdl, void *buf, int *len);
int rtpp_srtp_validate_key(unsigned char *input_key);
int rtpp_srtp_session_print_policy(srtpw_srtp *psrtp);
#endif

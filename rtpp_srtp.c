#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "rtpp_util.h"
#include "rtp.h"
#include "rtpp_log.h"
#include "rtpp_defines.h"
#include "rtpp_session.h"

#define CHECK_SEQ_OVERFLOW(seq) ((seq > RTP_MAX_SEQ)?RTP_MIN_SEQ:seq)

//#define NO_LOG

#ifdef NO_LOG
   #define srtp_log(level, handle, format, ...)
#else
   #define srtp_log(level, handle, format, ...) rtpp_log_write(level, handle, format, __VA_ARGS__)
#endif
extern rtpp_log_t glog;

int rtpp_srtp_init(int log_level)
{
    srtpw_srtp_set_log_level(log_level);
    return srtpw_srtp_init();
}

int rtpp_srtp_init_context(rtpp_srtp_ctxt *ctxt)
{

    memset(&ctxt->rcv_hdl,0,sizeof(rtpp_srtp_handle));
    memset(&ctxt->snd_hdl,0,sizeof(rtpp_srtp_handle));
    return rtpp_srtp_err_status_ok;

}
int rtpp_srtp_destroy_policy(rtpp_srtp_handle *hndl)
{

    return srtpw_srtp_destroy_policy(&hndl->policy);

}
int rtpp_srtp_free_context(rtpp_srtp_ctxt *ctxt)
{

    srtpw_srtp_destroy_policy(&ctxt->rcv_hdl.policy);
    srtpw_srtp_destroy_policy(&ctxt->snd_hdl.policy);
    srtpw_srtp_destroy(ctxt->rcv_hdl.srtp);
    srtpw_srtp_destroy(ctxt->snd_hdl.srtp);
    ctxt->rcv_hdl.policy=NULL;
    ctxt->snd_hdl.srtp = NULL;
    ctxt->snd_hdl.policy=NULL;
    ctxt->rcv_hdl.srtp = NULL;

    return rtpp_srtp_err_status_ok;

}

int rtpp_create_srtp_context(rtpp_srtp_handle *hndl, unsigned char *key,
                             int suite , int ssrc, int ssrc_inbound)
{
    int ret;
    if (hndl->policy == NULL)
    {
        if ((ret = srtpw_srtp_create_policy(&hndl->policy))!= srtpw_err_status_ok)
        {
            rtpp_log_write(RTPP_LOG_ERR, glog, "rtpp_create_srtp_context"
                           "srtpw_srtp_create_policy Err:%d ", ret);
            return ret;
        }
    }
    if ((ret = srtpw_set_crypto_policy(hndl->policy,suite,key,ssrc,ssrc_inbound))
        != srtpw_err_status_ok)
    {
        rtpp_log_write(RTPP_LOG_ERR, glog, "srtpw_set_crypto_policy"  " Err:%d ", ret);
        return ret;
    }
    if ((ret= srtpw_srtp_create(&hndl->srtp,hndl->policy))!= srtpw_err_status_ok)
    {
        rtpp_log_write(RTPP_LOG_ERR, glog, "srtpw_srtp_create"  " Err:%d ", ret);
        return ret;
    }
    rtpp_log_write(RTPP_LOG_DBUG, glog, "rtpp_create_srtp_context created");
    return rtpp_srtp_err_status_ok;
}


int rtpp_srtp_unprotect(rtpp_srtp_handle *hdl, void *buf, int *len, int rtcp)
{
    if (hdl->srtp!=NULL)
        return srtpw_srtp_unprotect(hdl->srtp, buf, len, rtcp);
    return rtpp_srtp_err_status_handle_null;
}

int rtpp_srtp_protect_rtcp(rtpp_srtp_handle *hdl, void *buf, int *len)
{
    rtcp_hdr_t *hdr = (rtcp_hdr_t *)buf;
    int status = rtpp_srtp_err_status_ok;
    int res    = 0;
    uint32_t ssrc = 0;
    uint32_t hdr_ssrc = ntohl(hdr->ssrc);
    uint16_t seq = 0;
    if (hdl->srtp == NULL || hdl->policy == NULL)
        return rtpp_srtp_err_status_handle_null;

    if (srtpw_get_ssrc_from_policy(hdl->policy, &ssrc) == srtpw_err_status_ok)
    {

        rtpp_log_write(RTPP_LOG_DBUG, glog, "RTCP policy:0x%x Modify packet ssrc from 0x%x to 0x%x last_err:%d\n",
                       hdl->policy,hdr_ssrc, ssrc, hdl->last_err);

        hdr->ssrc = htonl(ssrc);

        rtpp_log_write(RTPP_LOG_DBUG, glog, "RTCP SRTP protect: fix ssrc from 0x%x to 0x%x \n",
                   hdr_ssrc, ssrc);

        res = srtpw_srtp_protect(hdl->policy, hdl->srtp, buf, len, 1);

        if (res != srtpw_err_status_ok)
        {

          rtpp_log_write(RTPP_LOG_DBUG, glog, " RTCP policy:0x%x Error packet ssrc from 0x%x to to 0x%x last_err:%d res:%d\n",
                       hdl->policy,hdr_ssrc, ssrc, hdl->last_err, res);

          /* To Print the error only once*/
          if (hdl->last_err != res)
          {
              rtpp_log_write(RTPP_LOG_INFO, glog, " RTCP err:%s ssrc from 0x%x to to 0x%x \n",
                             srtpw_srtp_errstr(res),hdr_ssrc,ssrc );
              hdl->last_err = res;
          }
          status = rtpp_srtp_err_status_fail;
        }
    }
    else
    {
      status = rtpp_srtp_err_status_fail;
    }

    return status;
}

int rtpp_srtp_protect(rtpp_srtp_handle *hdl, void *buf, int *len, int rtcp)
{

    if (rtcp)
    {
        rtcp_hdr_t *hdr = (rtcp_hdr_t *)buf;

        int res = 0;
        uint32_t ssrc = 0;
        uint32_t hdr_ssrc = ntohl(hdr->ssrc);

        //uint16_t seq = 0;
        if (hdl->srtp == NULL || hdl->policy == NULL)
            return rtpp_srtp_err_status_handle_null;

        if (srtpw_get_ssrc_from_policy(hdl->policy, &ssrc) == srtpw_err_status_ok)
        {

            rtpp_log_write(RTPP_LOG_DBUG, glog, "policy:0x%x Modify packet ssrc from 0x%x to 0x%x hdr->type:%u hdr->rc:%u", 
                           hdl->policy, hdr_ssrc, ssrc, ntohs(hdr->type), ntohs(hdr->rc));
            hdr->ssrc = htonl(ssrc);
        }

        rtpp_log_write(RTPP_LOG_DBUG, glog, "SRTCP protect: ssrc from 0x%x to 0x%x hdr->type:%u hdr->rc:%u\n",
                       hdr_ssrc, ssrc, ntohs(hdr->type), ntohs(hdr->rc));

        res = srtpw_srtp_protect(hdl->policy, hdl->srtp, buf, len, rtcp);

        if (res != srtpw_err_status_ok)
        {

            rtpp_log_write(RTPP_LOG_DBUG, glog, " policy:0x%x Error packet ssrc from 0x%x to to 0x%x hdr->type:%u hdr->rc=%u\n", 
                           hdl->policy, hdr_ssrc, ssrc, ntohs(hdr->type), hdr->rc);

            /* To Print the error only once*/
            if (hdl->last_err != res)
            {
                rtpp_log_write(RTPP_LOG_ERR, glog, "err:%s ssrc from 0x%x to to 0x%x \n",
                               srtpw_srtp_errstr(res),hdr_ssrc,ssrc);
                hdl->last_err = res;
            }

            return rtpp_srtp_err_status_fail;

        }

        return rtpp_srtp_err_status_ok;

    }

    else
    {
        rtp_hdr_t *hdr = (rtp_hdr_t *)buf;

        int res = 0;
        uint32_t ssrc = 0;
        uint32_t hdr_ssrc = ntohl(hdr->ssrc);

        uint16_t seq = 0;
        if (hdl->srtp == NULL || hdl->policy == NULL)
            return rtpp_srtp_err_status_handle_null;

        rtpp_log_write(RTPP_LOG_DBUG, glog, "SRTP protect: ssrc 0x%x orig_seq:%d", hdr_ssrc, hdl->orig_seq);

        if (srtpw_get_ssrc_from_policy(hdl->policy, &ssrc) == srtpw_err_status_ok)
        {

            rtpp_log_write(RTPP_LOG_DBUG, glog, "policy:0x%x Modify packet ssrc from 0x%x to 0x%x hdr.seq:%d hdl->seq=%d last_err:%d\n",
                           hdl->policy,hdr_ssrc, ssrc, ntohs(hdr->seq), hdl->seq, hdl->last_err);
            hdr->ssrc = htonl(ssrc);
        }

        if (!hdl->first_packet)
        {
            /* RESET SEQ NUM to 1 if inital seq num is > 32768*/
            if (hdl->fix_seq && hdl->seq==0 && (ntohs(hdr->seq) > RTP_MID_SEQ))
            {
                hdl->seq=RTP_MIN_SEQ;
            }
            hdl->first_packet = 1;
        }
        if (hdl->fix_seq && hdl->seq != 0)
        {
            rtpp_log_write(RTPP_LOG_DBUG, glog, "SRTP protect: fix_seq ssrc from 0x%x to 0x%x hdl->seq:%d hdr->seq:%d\n",
                           hdr_ssrc, ssrc, hdl->seq, ntohs(hdr->seq));
            hdr->seq      = htons(hdl->seq);
            hdl->seq      = CHECK_SEQ_OVERFLOW(hdl->seq + 1);

        }

    if(rtcp)
    {
       rtpp_log_write(RTPP_LOG_DBUG, glog, "RTCP protect: ssrc 0x%x ", hdr_ssrc);
       return rtpp_srtp_protect_rtcp(hdl, buf, len);
    }

        rtpp_log_write(RTPP_LOG_DBUG, glog, "SRTP protect: fix_seq ssrc from 0x%x to 0x%x hdl->seq:%d hdr->seq:%d\n",
                       hdr_ssrc, ssrc, hdl->seq, ntohs(hdr->seq));

        res = srtpw_srtp_protect(hdl->policy, hdl->srtp, buf, len, rtcp);
        if (res != srtpw_err_status_ok)
        {

            rtpp_log_write(RTPP_LOG_DBUG, glog, " policy:0x%x Error packet ssrc from 0x%x to to 0x%x hdr.seq:%d hdl->seq=%d last_err:%d res:%d\n",
                           hdl->policy,hdr_ssrc, ssrc, ntohs(hdr->seq), hdl->seq, hdl->last_err, res);

            /* To Print the error only once*/
            if (hdl->last_err != res)
            {
                rtpp_log_write(RTPP_LOG_ERR, glog, "err:%s ssrc from 0x%x to to 0x%x  seq:%u\n",
                               srtpw_srtp_errstr(res),hdr_ssrc,ssrc, ntohs(hdr->seq));
                hdl->last_err = res;
            }

            if ((res == srtpw_err_status_replay_old || res == srtpw_err_status_replay_fail) && hdl->fix_seq && !rtcp)
            {

#ifdef DEBUG
                rtpp_log_write(RTPP_LOG_DBUG, glog, "  changing the seq from %d to %d for ssrc:0x%x orgi_seq:%d\n",
                               ntohs(hdr->seq),seq, ssrc,hdl->orig_seq );
#endif

                hdl->seq = CHECK_SEQ_OVERFLOW(hdl->orig_seq +1);
                hdr->seq = htons(hdl->seq);
                if ((res= srtpw_srtp_protect(hdl->policy, hdl->srtp, buf, len, rtcp)) != srtpw_err_status_ok)
                {
                    rtpp_log_write(RTPP_LOG_ERR, glog, "SRTP protect:%s ssrc from 0x%x to 0x%x seq:%d\n",
                                   srtpw_srtp_errstr(res),hdr_ssrc,ssrc, ntohs(hdr->seq));
                    hdl->last_err = res;
                    res = rtpp_srtp_err_status_fail;
                }
            }
            else return rtpp_srtp_err_status_fail;


        }
        hdl->orig_seq = ntohs(hdr->seq);
        hdl->prev_ts  = ntohl(hdr->ts);
        if (res == rtpp_srtp_err_status_fail)
            return res;
        return rtpp_srtp_err_status_ok;


    }
}
int rtpp_srtp_validate_key(unsigned char *input_key)
{
    if (input_key == NULL)
        return rtpp_srtp_err_status_ok;
    return srtpw_validate_key(input_key);
}

int rtpp_srtp_session_print_policy(srtpw_srtp *psrtp)
{
    if (psrtp)
        return srtpw_session_print_policy(psrtp);
    return rtpp_srtp_err_status_fail;
}

int rtpp_srtp_create_context(struct rtpp_session *sp, int kidx,
                unsigned char *key, short int suite, uint32_t ssrc,
                int fix_srtp_seq, unsigned int snd)
{
        assert(sp != NULL);
        assert(key != NULL);
        assert(snd < 2);
        rtpp_srtp_handle *phdl = NULL;
    if (snd)
                phdl = &(sp->srtp[kidx].snd_hdl);
        else
                phdl = &(sp->srtp[kidx].rcv_hdl);
    if (phdl == NULL)
        return 0;
    if (phdl->policy)
        {
                srtpw_srtp_destroy_policy(&phdl->policy);
                phdl->policy = NULL;
        }
    if (phdl->srtp)
    {
                srtpw_srtp_destroy(phdl->srtp);
                phdl->srtp = NULL;
        }
        rtpp_log_write(RTPP_LOG_DBUG, sp->log, "rtpp_create_srtp_context"
                        " idx:%d snd:%u key=%s ssrc=%u suite:%d ",kidx, snd, srtpw_octet_string_hex_string(key,SRTP_MASTER_KEY_LEN), ssrc, suite);

        if (rtpp_create_srtp_context(phdl, key, suite, ssrc,!snd) != rtpp_srtp_err_status_ok)
        {
                rtpp_log_write(RTPP_LOG_ERR, sp->log, "rtpp_create_srtp_context failed"
                                "key=%s ssrc=%u suite:%d ", srtpw_octet_string_hex_string(key,SRTP_MASTER_KEY_LEN), ssrc, suite);
        return 0;
    }
        sp->secure = 1;
    if (snd)
                phdl->fix_seq = fix_srtp_seq;
    return 1;
}



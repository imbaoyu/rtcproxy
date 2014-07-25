/*
 * Copyright (c) 2006 Stefan Sayer
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
 * $Id: rtp_transcoder.c,v 1.6 2006/02/23 00:15:24 sayer Exp $
 *
 */
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "rtpp_util.h"
#include "rtp.h"
#include "rtpp_log.h"
#include "rtpp_defines.h"
#include "rtp_transcoder.h"
#include "rtpp_trans_plugin.h"

#include "rtpp_session.h"

extern rtpp_log_t glog;


#define PCM16           signed short
#define BYTES_PER_SAMPLE 2  // sizeof(PCM16)

const char* G711U_CODEC_STR = "711u";
const char* G711U_CODEC_CHR = "0";

const char* G711A_CODEC_STR = "711a";
const char* G711A_CODEC_CHR = "8";

const char* G729_CODEC_STR= "729";
const char* G729_CODEC_CHR = "9";

const char* GSM0610_CODEC_CHR = "G";

const char* LINEAR_CODEC_CHR = "L";

const char* ILBC_CODEC_STR = "ilbc";
const char* ILBC_CODEC_CHR = "I";

const char* G722_CODEC_STR = "722";
const char* G722_1_CODEC_STR = "7221";
const char* G722_2_CODEC_STR = "7222";
const char* ISAC_CODEC_STR = "isac";
const char* AMRNBGSM_CODEC_STR = "gsm";

const int RTP_TRANS_FMT_CNAME=1;
const int RTP_TRANS_FMT_PAYNUM=2;
const int RTP_TRANS_FMT_CLKRATE=3;
const int RTP_TRANS_FMT_BITRATE=4;
const int RTP_TRANS_FMT_MODE=5;

extern struct rtp_data_list* active_resized_sp_list;
extern int g_use_timed_resizer;

//#define DEBUG
int rtp_transcoder_init(struct cfg *cf)
{
    char *path=(char *)"/usr/lib/audio";
    return trans_plugin_load_codec_plugins(path);
}

void rtp_transcoder_shutdown()
{
    trans_plugin_release();
}


struct rtp_transcoder *rtp_transcoder_new(struct rtpp_session* sp,char from_payload_id, int from_codec_id,
                                          itrans_codec_create_info* format_parameters_from,
                                          char to_payload_id,   int to_codec_id,
                                          itrans_codec_create_info* format_parameters_to,
                                          int idx)
{
    struct rtp_transcoder *rt;

    rt = (struct rtp_transcoder *)malloc(sizeof(*rt));
    if (rt == NULL)
        return NULL;

    memset(rt, 0, sizeof(*rt));

    if (!rtp_transcoder_update(rt,sp, from_payload_id, from_codec_id,
                               format_parameters_from,
                               to_payload_id, to_codec_id,
                               format_parameters_to,idx))
    {
        free(rt);
        return NULL;
    }

    return rt;
}

// ===================================================================
// rtp_transcoder_update Codec plugin initialization.
// ===================================================================
int rtp_transcoder_update(struct rtp_transcoder* rt, struct rtpp_session* sp,
                          char from_payload_id, int from_codec_id,
                          itrans_codec_create_info* format_parameters_from,
                          char to_payload_id,   int to_codec_id,
                          itrans_codec_create_info* format_parameters_to,
                          int idx) {

    itrans_codec_info fmtinfo[8];
    unsigned int i;

    rtpp_log_write(RTPP_LOG_INFO, sp->log, "rtp_transcoder_update "
                   " ct_f=%d pt_f=%d ==> ct_t=%d pt_t=%d ", from_codec_id,from_payload_id,to_codec_id,to_payload_id);
    rt->had_packet = 0;
    rt->linear_ts=0;
    rt->invalid_pt=0;

    if (from_codec_id)
    {
    // free the old codec...
        if ((rt->codec_from != NULL) && (rt->codec_from->itrans_free != NULL))
            rt->codec_from->itrans_free(rt->handle_from);

        rt->from_payload_id = from_payload_id;
    // get the codec
        rt->codec_from = trans_plugin_get_codec(from_codec_id);
        if (rt->codec_from == NULL)
        {
            rtpp_log_write(RTPP_LOG_ERR, sp->log, "rtp_transcoder_update failed in trans_plugin_get_codec for codec_from:%d",from_codec_id);
            return RTPP_TRANSCODER_ERROR;
        }

    // init the codec
        if (rt->codec_from->itrans_create != NULL)
        {
            rt->handle_from = rt->codec_from->itrans_create(format_parameters_from,
                                                            fmtinfo);
            for (i=0; fmtinfo[i].id!=0;i++)
            {
                if (fmtinfo[i].id == ITRANS_TYPE_FRAME_SIZE)
                {
                    rt->from_framelength = fmtinfo[i].value * 2; // sizeof(PCM16)
#ifdef DEBUG
                    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                                   "transcode_init: from_framelength %d",
                                   rt->from_framelength);
#endif
                }
                if (fmtinfo[i].id == ITRANS_TYPE_ENCODED_FRAME_SIZE)
                {
                    rt->from_encodedsize = fmtinfo[i].value;
                }
                if (fmtinfo[i].id == ITRANS_TYPE_SAMPLES_PER_FRAME)
                {
                    rt->from_samples_per_frame = fmtinfo[i].value;
                }
            }
        }
#ifdef DEBUG
        rtpp_log_write(RTPP_LOG_INFO, glog, "rtp_trancoder_update: from %d/%d",
                       from_codec_id, from_payload_id);
#endif
    }

    if (to_codec_id)
    {
    // free the old codec...
        if ((rt->codec_to != NULL) && (rt->codec_to->itrans_free != NULL))
            rt->codec_to->itrans_free(rt->handle_to);

        memset(fmtinfo, 0, sizeof(*fmtinfo));

        rt->to_payload_id   = to_payload_id;
    // get the codec
        rt->codec_to   = trans_plugin_get_codec(to_codec_id);
        if (rt->codec_to == NULL)
        {
            rtpp_log_write(RTPP_LOG_ERR, sp->log, "rtp_transcoder_update failed in trans_plugin_get_codec for codec_to:%d",to_codec_id);
            return RTPP_TRANSCODER_ERROR;
        }

    // init the codecs
        if (rt->codec_to->itrans_create != NULL)
        {
            rt->handle_to = rt->codec_to->itrans_create(format_parameters_to,
                                                        fmtinfo);
            for (i=0; fmtinfo[i].id!=0;i++)
            {
                if (fmtinfo[i].id == ITRANS_TYPE_FRAME_SIZE)
                {
                    rt->to_framelength = fmtinfo[i].value * 2; // sizeof(PCM16);
#ifdef DEBUG
                    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                                   "transcode_init: to_framelength %d",
                                   rt->to_framelength);
#endif
                }
                if (fmtinfo[i].id == ITRANS_TYPE_ENCODED_FRAME_SIZE)
                {
                    rt->to_encodedsize = fmtinfo[i].value;
                }
                if (fmtinfo[i].id == ITRANS_TYPE_SAMPLES_PER_FRAME)
                {
                    rt->to_samples_per_frame = fmtinfo[i].value;
                }
            }
        }
#ifdef DEBUG
        rtpp_log_write(RTPP_LOG_INFO, glog, "rtp_trancoder_update: to %d/%d",
                       to_codec_id, to_payload_id);
#endif
    }

    rt->audio_end = rt->pcmbuf;


    rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   " rtp_trancoder_update Initialized : From PT %d  from_samples_per_frame= %d To PT %d to_samples_per_frame=%d",
                     rt->from_payload_id, rt->from_samples_per_frame, rt->to_payload_id, rt->to_samples_per_frame);

    return RTPP_TRANSCODER_OK;
}

void rtp_transcoder_free(struct rtp_transcoder *rt,struct cfg *cf) {

    if(cf)
    {
      rtpp_log_write(RTPP_LOG_INFO, cf->glog,
                   "delete transcoding modules codec_to:0x%x, codec_from:0x%x\n",rt->codec_to,rt->codec_from);
    }
    if (rt->codec_to != NULL)
        if (rt->codec_to->itrans_free != NULL)
            rt->codec_to->itrans_free(rt->handle_to);
    if (rt->codec_from != NULL)
        if (rt->codec_from->itrans_free != NULL)
            rt->codec_from->itrans_free(rt->handle_from);
    rt->codec_to =NULL;
    rt->codec_from = NULL;
}

// ===================================================================
// rtp_transcoder_decode_to_linear Convert input packet to linear packet
// linear packet size output will be mode*8*2
// For example 30ms -> 480bytes
//             20ms -> 320bytes
// ===================================================================
int rtp_transcoder_decode_to_linear(struct rtp_transcoder *rt, struct rtpp_session* sp,
                             char* buf, int* len, int idx)
{

    unsigned int audio_len;
    unsigned short rtp_seq;
    uint32_t rtp_ts;
    char* rtpp_audio_offset;
    rtp_hdr_t *rtp;
    div_t blocks;
    int i=0;
    int foundCodec=0;
    int doResample=0;
    int activeCodecIndex=0;
    int tsIncr = 0;

    if(sp == NULL)
        return 0;

    if (rt == NULL )
    {
        rtpp_log_write(RTPP_LOG_ERR, sp->log,
                       "transcode: Session not initialized.");
        return 0;
    }

    if ((rt->codec_from == NULL) || (rt->codec_to == NULL))
    {
        rtpp_log_write(RTPP_LOG_ERR, sp->log,
                       "transcode: codec not initialized.");
        return 0;
    }

    rtp = (rtp_hdr_t *)buf;
    rtp_seq = ntohs(rtp->seq);
    rtp_ts  = ntohl(rtp->ts);

    if (rtp->pt != rt->from_payload_id)
    {

        if (rt->disable_comfort_noise && rtp->pt == rt->cn_payload_id) /* Drop Comfort Noise Packet*/
        {
            return RTPP_TRANSCODER_RTP_DROP;
        }
        rtpp_log_write(RTPP_LOG_WARN, sp->log,
                       "transcode: expected payload %d, received %d",
                       rt->from_payload_id, rtp->pt );

        // here, check if we have the payload type in the array...
        for(i=0;i<sp->rtp_trans_codeclists[idx].numFromCodecs;i++)
        {
          if(sp->rtp_trans_codeclists[idx].
                            rtp_transcoder_FromCodecDetails[i].payloadNum == rtp->pt)

          {
              foundCodec=1;
              activeCodecIndex=i;
              break;
          }
        }
        if(foundCodec == 0)
        {
          rt->invalid_pt=1;
          return RTPP_TRANSCODER_INVALID_PAYLOAD;
        }
        else
        {
          // alternative codec found.
          // set current codec to activeCodecIndex. Re-init.
          int reinitVal = rtp_transcoder_reinit(sp, idx, activeCodecIndex);
          if(reinitVal != RTPP_TRANSCODER_OK)
          {
            rt->invalid_pt=1;
            return RTPP_TRANSCODER_INVALID_PAYLOAD;
          }
          else
          {
            rt->invalid_pt=0;
            rt->had_packet=0;
          }
        }
    }
    else
    {
       rt->invalid_pt=0;
    }

    // send to resizer transcode if resizing..
    if (sp->resizers[idx].output_nsamples > 0)
    {
      return rtp_transcoder_decode_to_linear_wresize( rt,  sp,
                              buf, len, idx);

    }

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   "Enter transcode: (%u, %u, rtp_ts:%u rt->end_ts:%u)",
                   rtp_seq, rt->last_seq, rtp_ts, rt->end_ts );
#endif
    if (rt->had_packet == 0)
    {
        rt->audio_end = rt->pcmbuf;
        rt->begin_ts = rt->end_ts = rtp_ts;
        rt->to_seq = ntohs(rtp->seq);
        //rt->had_packet = 1;
        rt->to_ts =0;
        rt->linear_ts = 0;
        rt->invalid_pt=0;
    }
    else if (rtp->m || (rtp_seq != rt->last_seq+1) ||
             (rtp_ts != rt->end_ts) )
    {
        if (rtp_seq != rt->last_seq+1)
        {
#ifdef DEBUG
            rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "transcode: packetloss (%u, %u, %u samples)",
                           rtp_seq, rt->last_seq+1, rtp_ts - rt->end_ts);
#endif
      // packetloss -> update seq
            if ((rt->to_framelength != 0) && (rt->from_framelength != 0))
            {
                rt->to_seq += (rtp_seq - rt->last_seq) *
                              rt->from_framelength/rt->to_framelength;
                tsIncr =  (rtp_seq - rt->last_seq) *
                              rt->from_framelength/rt->to_framelength;
            }
            else
            {
                rt->to_seq +=  rtp_seq - rt->last_seq;
                tsIncr =  rtp_seq - rt->last_seq;
            }

        }
        else if (rtp_ts != rt->end_ts)
        {
#ifdef DEBUG
            rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "transcode: silence %u samples",
                           rtp_ts - rt->end_ts);
#endif
        }
    // packet loss/silence -> drop buffered audio
#ifdef DEBUG
        rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "updating rt->audio_end with pcmbuf audio_end:0x%x, pcmbuf:0x%x",
                       rt->audio_end, rt->pcmbuf);
#endif
        rt->audio_end = rt->pcmbuf;
        rt->begin_ts = rt->end_ts ;

    }
    // Wideband to Narrowband interwork
    int frmArrnum = sp->rtp_trans_codeclists[idx].activeFrmCodec;
    int toArrnum = sp->rtp_trans_codeclists[idx].activeToCodec;

    int frmCR = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[frmArrnum].clockRate;
    int toCR =  sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[toArrnum].clockRate;

    // resample only if CR different
    if(frmCR == 2*toCR || toCR == 2*frmCR)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Resampling necessary frmCR= %d toCR=%d",frmCR,toCR);
#endif
       doResample=1;
    }
    else if(frmCR == 4*toCR || toCR == 4*frmCR)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Resampling necessary frmCR= %d toCR=%d",frmCR,toCR);
#endif
       doResample=2;
    }
    else
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Resampling NOT necessary frmCR= %d toCR=%d",frmCR,toCR);
#endif
    }

    if(rt->from_samples_per_frame != rt->to_samples_per_frame)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Updating  ts= %d",rt->to_samples_per_frame);
#endif
       rt->begin_ts = rt->to_ts = rt->to_ts + rt->to_samples_per_frame;
    }


    rt->last_seq  =  rtp_seq;

    audio_len = *len - RTP_HDR_LEN(rtp);
#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                   "tr: got audio %d from TS %u (in buffer %d from TS %u to TS %u)",
                   audio_len, rtp_ts, rt->audio_end - rt->pcmbuf,
                   rt->begin_ts, rt->end_ts);
#endif
    rtpp_audio_offset = buf + RTP_HDR_LEN(rtp);
    audio_len = rt->codec_from->codec2linear( rt->handle_from, (unsigned char *)rt->audio_end, (unsigned char *)rtpp_audio_offset,
                                              audio_len, doResample, 8000);

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                   " audio len after codec2linear: %d",
                   audio_len);
#endif

    if (audio_len <= 0)
    {
        if (audio_len < 0)
            rtpp_log_write(RTPP_LOG_ERR, sp->log,
                           "transcode: codec_from->codec2linear failed.");
        return RTPP_TRANSCODER_TYPE2INT_FAILED;
    }
    rt->end_ts += rt->from_samples_per_frame;//audio_len / BYTES_PER_SAMPLE;
    rt->audio_end += audio_len;

    if(rt->had_packet==1)
    {
      int outnsamples=  audio_len;
      if(tsIncr)
        rt->linear_ts +=  outnsamples + outnsamples*tsIncr;
      else
        rt->linear_ts  += outnsamples;

      if(rt->linear_ts == UINT_MAX)
      {
         // reset timestamp
         rt->linear_ts=0;
      }
    }
    else
      rt->had_packet=1;

    rtp->ts = htonl(rt->begin_ts);  // update packet ts
    *len = audio_len+ RTP_HDR_LEN(rtp);
    memcpy(rtpp_audio_offset,rt->pcmbuf,audio_len); // copy pcmbuf to rtp packet

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                   "Exit transcode: (%u, %u, rtp_ts:%u rt->end_ts:%u)",
                   rtp_seq, rt->last_seq, rtp_ts, rt->end_ts);
#endif

    return RTPP_TRANSCODER_OK;

}

// ===================================================================
// rtp_transcoder_encode_to_codec Convert input packet to encoded packet
// of target codec.
// linear packet size input will be mode*8
// For example 30ms -> 480bytes
//             20ms -> 320bytes
// output packet size will be based on the codec and ptime
//     example 729 -> 20bytes for 20ms
//             711u-> 160bytes for 20ms
// ===================================================================

int rtp_transcoder_encode_to_codec(struct rtp_transcoder *rt, struct rtpp_session* sp,
                             char* buf, int* len, int idx)
{
    unsigned int audio_len;
    uint32_t rtp_ts;
    char* rtpp_audio_offset;
    rtp_hdr_t *rtp;
    div_t blocks;
    int i=0;
    int foundCodec=0;
    int doResample=0;

    if(sp == NULL)
        return 0;

    if (rt == NULL )
    {
        rtpp_log_write(RTPP_LOG_ERR, sp->log,
                       "transcode: Session not initialized.");
        return 0;
    }
    if (sp->resizers[idx].output_nsamples > 0)
    {
      return rtp_transcoder_encode_to_codec_wresize( rt,  sp,
                              buf, len, idx);

    }

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   "rtp_transcoder_encode_to_codec input len = %d ", *len );
#endif

    if ((rt->codec_from == NULL) || (rt->codec_to == NULL))
    {
        rtpp_log_write(RTPP_LOG_ERR, sp->log,
                       "transcode: codec not initialized.");
        return 0;
    }

    rtp = (rtp_hdr_t *)buf;
    rtpp_audio_offset = buf + RTP_HDR_LEN(rtp);


    // Wideband to Narrowband interwork
    int frmArrnum = sp->rtp_trans_codeclists[idx].activeFrmCodec;
    int toArrnum = sp->rtp_trans_codeclists[idx].activeToCodec;

    int frmCR = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[frmArrnum].clockRate;
    int toCR =  sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[toArrnum].clockRate;

    // resample only i
    if(frmCR == 2*toCR || toCR == 2*frmCR)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Resampling necessary frmCR= %d toCR=%d",frmCR,toCR);
#endif
       doResample=1;
    }
    else if(frmCR == 4*toCR || toCR == 4*frmCR)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Resampling necessary frmCR= %d toCR=%d",frmCR,toCR);
#endif
       doResample=2;
    }
    else
      doResample=0;


    if (rt->to_framelength)
    {
        blocks = div(rt->audio_end - rt->pcmbuf, rt->to_framelength);

        if (blocks.quot)
        {
            audio_len = rt->codec_to->linear2codec(rt->handle_to, (unsigned char *)rtpp_audio_offset, (unsigned char *)rt->pcmbuf,
                                                   blocks.quot * rt->to_framelength, doResample, 8000);
            if (blocks.rem)
            {
                memmove(rt->pcmbuf, rt->pcmbuf +  blocks.quot * rt->to_framelength, blocks.rem);
            }

        }
        else
            audio_len = 0;

        rt->audio_end = rt->pcmbuf + blocks.rem;
        rt->begin_ts = rt->end_ts - blocks.rem / BYTES_PER_SAMPLE;
    // or: rt->begin_ts += blocks.quot * rt->to_framelength / BYTES_PER_SAMPLE;
    }
    else
    {
    // all available audio is sent out
        audio_len = rt->codec_to->linear2codec( rt->handle_to, (unsigned char *)rtpp_audio_offset, (unsigned char *)rt->pcmbuf,
                                                rt->audio_end - rt->pcmbuf,
                                                1, 8000);
        rt->audio_end = rt->pcmbuf; // clear buffer
        rt->begin_ts = rt->end_ts;
    }

    if (audio_len <= 0)
    {
        if (audio_len < 0)
            rtpp_log_write(RTPP_LOG_ERR, sp->log,
                           "transcode: codec_to->linear2codec failed.");
        return RTPP_TRANSCODER_INT2TYPE_FAILED;
    }

    rtp->seq = htons(rt->to_seq);   // update packet seqno
    rt->to_seq++;

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                   "ssrc:0x%x seq:%d transcoded from payload %d to %d,"
                   "size %d (%d) to %d (%d) ts %u (buffering %d).\n",
                   ntohl(rtp->ssrc), ntohs(rtp->seq),
                   rt->from_payload_id, rt->to_payload_id, *len,*len - RTP_HDR_LEN(rtp),
                   audio_len + RTP_HDR_LEN(rtp), audio_len,
                   ntohl(rtp->ts),
                   rt->audio_end - rt->pcmbuf);
    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                   "Exit transcode: ( %u, rt->end_ts:%u)",
                    rt->last_seq,  rt->end_ts);
#endif
    *len = audio_len + RTP_HDR_LEN(rtp);

    rtp->pt = rt->to_payload_id;
    return RTPP_TRANSCODER_OK;
}

// ===================================================================
// rtp_set_comfort_noise
// ===================================================================

int rtp_set_comfort_noise(struct rtp_transcoder *rt, char payload, short int disable)
{
    rt->disable_comfort_noise = disable;
    rt->cn_payload_id = payload;
    return RTPP_TRANSCODER_OK;
}

// ===================================================================
// rtp_get_codec_type
//
// This version of rtp_get_codec_type takes String input
// could be single char for backward compat or Codec Name.
//
// ===================================================================
int rtp_get_codec_type(char* ch , int payload)
{

    if(!ch) return -1;

    int szNm = 32;
    char codecName[szNm];
    memset(codecName,'\0', szNm);
    strncpy(codecName, ch, sizeof(codecName));


       if( strncmp(codecName, GSM0610_CODEC_CHR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_GSM0610;
            else
                return CODEC_GSM0610;
       }
       else if( strncmp(codecName, LINEAR_CODEC_CHR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_LINEAR;
       }
       else if( strncmp(codecName, G711U_CODEC_STR, szNm) ==0||
          strncmp(codecName, G711U_CODEC_CHR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_ULAW;
            else
                return CODEC_ULAW;
       }
       else if( strncmp(codecName, G711A_CODEC_STR, szNm) ==0||
          strncmp(codecName, G711A_CODEC_CHR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_ALAW;
            else
                return CODEC_ALAW;
       }
       else if( strncmp(codecName, G729_CODEC_STR, szNm) ==0||
          strncmp(codecName, G729_CODEC_CHR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_G729_FP;
            else
                return CODEC_G729_FP;
       }
       else if(strncmp(codecName, ILBC_CODEC_STR, szNm) ==0 ||
          strncmp(codecName, ILBC_CODEC_CHR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_ILBC;
            else
                return CODEC_ILBC;
       }
       else if(strncmp(codecName, ISAC_CODEC_STR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_ISAC;
            else
                return CODEC_ISAC;
       }
       else if(strncmp(codecName, G722_CODEC_STR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_G722;
            else
                return CODEC_G722;
       }
       else if(strncmp(codecName, G722_1_CODEC_STR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_G722_1;
            else
                return CODEC_G722_1;
       }
       else if(strncmp(codecName, G722_2_CODEC_STR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_G722_2;
            else
                return CODEC_G722_2;
       }
       else if(strncmp(codecName, AMRNBGSM_CODEC_STR, szNm) ==0)
       {
            if (payload)
                return PT_CODEC_AMRNBGSM;
            else
                return CODEC_AMRNBGSM;
       }
       return -1;
}

// ===================================================================
// rtp_get_codec_lists
// IF OLD CODEC COMMAND, PROCESS LIKE OLD BRANCH COMMAND
// ELSE ASSUMING NEW CODEC STRING IN THE FORMAT
// CODECNAME_PAYLOADNUM_CLOCKRATE_BITRATE_PTIME
// CODECS IN A LIST SEPARATED BY PIPE
// FROM AND TO CODEC LIST SEPARATED BY COMMA
// EXAMPLE:
// trans:g7111_110_16_32_0|g722_9_16_64_0|ilbc_97_8_0_20|g7111_110_32_48_0,g722_9_16_64_0|ilbc_97_8_0_30|isac_103_16_0_0|g7222_111_16_64_0_0
// ===================================================================

int rtp_get_codec_lists(char* codecStr ,
                        char* oldPayloadStr,
                        struct rtpp_session* sp,
                        int idx,
                        int* codec_from,
                        int* payload_from,
                        int* codec_to,
                        int* payload_to,
                        int* codec_from_nidx,
                        int* payload_from_nidx,
                        int* codec_to_nidx,
                        int* payload_to_nidx)
{


    *codec_from= *payload_from= *codec_to= *payload_to=-1;
    *codec_from_nidx=*payload_from_nidx= *codec_to_nidx= *payload_to_nidx=-1;

    if( !codecStr || !sp )
      return -1;

    char codecCopy[CODEC_NAME_LEN];
    memset(codecCopy,'\0',CODEC_NAME_LEN);
    strncpy(codecCopy,codecStr,min(CODEC_NAME_LEN,strlen(codecStr)));
    char* pCodec = codecCopy;

    int pay=0, cr=0, br=0, mode=0;
    int nidx=NOT(idx);

    sp->rtp_trans_codeclists[idx].numFromCodecs=0;
    sp->rtp_trans_codeclists[nidx].numFromCodecs=0;

    sp->rtp_trans_codeclists[idx].numToCodecs=0;
    sp->rtp_trans_codeclists[nidx].numToCodecs=0;

    // check if old Branch command and fill  structure accordingly
    if(strstr(pCodec,"_") == NULL)
    {
       rtpp_log_write(RTPP_LOG_INFO, sp->log,
                       "--> rtp_get_codec_lists : old command format : %s",pCodec);

        char *codecid=NULL;
        if ((codecid = rtpp_strsep(&pCodec, ",")) != NULL)
        {
            rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "Codec From :%s",codecid);
            *codec_from= rtp_get_codec_type(codecid,0);
            *payload_from= rtp_get_codec_type(codecid,1);

      strcpy(sp->rtp_trans_codeclists[idx].
        rtp_transcoder_FromCodecDetails[0].codecName,
        pCodec);
      strcpy(sp->rtp_trans_codeclists[nidx].
        rtp_transcoder_ToCodecDetails[0].codecName,
        pCodec);

            codecid =pCodec;
            rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "Codec To :%s ",codecid);

            *codec_to= rtp_get_codec_type(codecid,0);
            *payload_to= rtp_get_codec_type(codecid,1);

      strcpy(sp->rtp_trans_codeclists[idx].
        rtp_transcoder_ToCodecDetails[0].codecName,
        pCodec);
      strcpy(sp->rtp_trans_codeclists[nidx].
        rtp_transcoder_FromCodecDetails[0].codecName,
        pCodec);

        }

      if (oldPayloadStr != NULL && strlen(oldPayloadStr) != 0 )
      {
        char *payld=NULL;
        *payload_from=*payload_to=-1;
        rtpp_log_write(RTPP_LOG_INFO, sp->log,
                       "Payload s_trans_payload:%s ",oldPayloadStr);
        if ((payld = rtpp_strsep(&oldPayloadStr, ",")) != NULL)
        {
            rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "Payload From :%s len:%d",payld,strlen(payld));
            *payload_from = atoi(payld);
            payld =oldPayloadStr;
            rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "Payload To :%s ",payld);
            *payload_to = atoi(payld);
        }

      }
      // fill new structure with values
      sp->rtp_trans_codeclists[idx].numFromCodecs = 1;
      sp->rtp_trans_codeclists[nidx].numToCodecs = 1;

      sp->rtp_trans_codeclists[idx].
        rtp_transcoder_FromCodecDetails[0].payloadNum
        = *payload_from;
      sp->rtp_trans_codeclists[nidx].
        rtp_transcoder_FromCodecDetails[0].payloadNum
        = *payload_to;

      sp->rtp_trans_codeclists[idx].
        rtp_transcoder_ToCodecDetails[0].payloadNum
        = *payload_to;
      sp->rtp_trans_codeclists[nidx].
        rtp_transcoder_ToCodecDetails[0].payloadNum
        = *payload_from;

                 rtpp_log_write(RTPP_LOG_INFO, sp->log,
                                "rtp_get_codec_lists cod_f=%d pay_f=%d ==> cod_t=%d pay_t=%d  ",
                                *codec_from,*payload_from,*codec_to,*payload_to );

      return 0;
    } // end old Branch command

    // look for comma delimiter
    static char codecList1[CODEC_NAME_LEN];
    static char codecList2[CODEC_NAME_LEN];

    memset(codecList1,'\0',CODEC_NAME_LEN);
    memset(codecList2,'\0',CODEC_NAME_LEN);

    char* ptmp = rtpp_strsep(&pCodec, ",");
    if(!ptmp)
      return -1;
    strncpy(codecList1,ptmp,min(CODEC_NAME_LEN,strlen(ptmp)));
    char* pCodecList1 = codecList1;

    ptmp = rtpp_strsep(&pCodec, ",");
    if(!ptmp)
      return -1;
    strncpy(codecList2,ptmp,min(CODEC_NAME_LEN,strlen(ptmp)));
    char* pCodecList2 = codecList2;


          // "From" codec for idx, "To" for nidx
          // get multiple codecs that might be in between pipe sign
          char* codecToken  = rtpp_strsep(&pCodecList1, "|");

          int codecNum=0;

          while (codecToken != NULL)
          {
              // read codec attributes
              char* codecFormatToken = rtpp_strsep(&codecToken, "_");
              int fidx=1;
              while (codecFormatToken != NULL)
              {
                switch(fidx)
                {
                    case RTP_TRANS_FMT_CNAME:
                      strncpy(sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[codecNum].codecName,codecFormatToken,
                        min(CODEC_NAME_LEN,strlen(codecFormatToken)));
                      strncpy(sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_ToCodecDetails[codecNum].codecName,codecFormatToken,
                        min(CODEC_NAME_LEN,strlen(codecFormatToken)));
                      break;

                    case RTP_TRANS_FMT_PAYNUM:
                      pay = atoi(codecFormatToken);
                      sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[codecNum].payloadNum
                        = pay;
                      sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_ToCodecDetails[codecNum].payloadNum
                        = pay;
                      break;

                    case RTP_TRANS_FMT_CLKRATE:
                      cr = atoi(codecFormatToken);
                      sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[codecNum].clockRate
                        = cr;
                      sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_ToCodecDetails[codecNum].clockRate
                        = cr;
                      break;

                    case RTP_TRANS_FMT_BITRATE:
                      br = atoi(codecFormatToken);
                      sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[codecNum].bitRate
                        = br;
                      sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_ToCodecDetails[codecNum].bitRate
                        = br;
                      break;

                    case RTP_TRANS_FMT_MODE:
                      mode = atoi(codecFormatToken);

                      if(strncmp( sp->rtp_trans_codeclists[idx].rtp_transcoder_FromCodecDetails[codecNum].codecName,
                          ISAC_CODEC_STR, 16) ==0)
                      {
                         if(mode !=30 && mode != 60)
                         {
                             mode =  30;
                         }
                      }
                      else if(strncmp( sp->rtp_trans_codeclists[idx].rtp_transcoder_FromCodecDetails[codecNum].codecName,
                          ILBC_CODEC_STR, 16) ==0)
                      {
                         if(mode !=30 && mode != 20)
                         {
                             mode =  30;
                         }
                      }
                      else if(strncmp( sp->rtp_trans_codeclists[idx].rtp_transcoder_FromCodecDetails[codecNum].codecName,
                          G722_1_CODEC_STR, 16) ==0)
                      {
                         if(mode !=20)
                         {
                             mode =  20;
                         }
                      }
                      else
                      {
                         if(mode == 0)
                           mode = 20;
                      }
                      sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[codecNum].mode
                        = mode;
                      sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_ToCodecDetails[codecNum].mode
                        = mode;
                      break;

                    default:
                      break;
                }
                fidx++;
                codecFormatToken =  rtpp_strsep(&codecToken, "_");
              }//while codecformat

              sp->rtp_trans_codeclists[idx].numFromCodecs++;
              sp->rtp_trans_codeclists[nidx].numToCodecs++;
              codecNum++;
            codecToken  = rtpp_strsep(&pCodecList1, "|");
          }// while codec pipe token

        rtpp_log_write(RTPP_LOG_INFO, sp->log,
                       "Num codecs in list 1 = :%d ",sp->rtp_trans_codeclists[idx].numFromCodecs);

        if(codecNum == 0) return -1;

        // "To" codec list for idx, "From" for nidx

          // get multiple codecs that might between in between pipe sign
        codecToken  = rtpp_strsep(&pCodecList2, "|");
        codecNum=0;

          while (codecToken != NULL)
          {
              // read codec attributes
              char* codecFormatToken = rtpp_strsep(&codecToken, "_");
              int fidx=1;
              while (codecFormatToken != NULL)
              {
                switch(fidx)
                {
                    case RTP_TRANS_FMT_CNAME:
                      strcpy(sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[codecNum].codecName,
                        codecFormatToken);
                      strcpy(sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_FromCodecDetails[codecNum].codecName,
                        codecFormatToken);
                      break;

                    case RTP_TRANS_FMT_PAYNUM:
                      pay = atoi(codecFormatToken);
                      sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[codecNum].payloadNum
                        = pay;
                      sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_FromCodecDetails[codecNum].payloadNum
                        = pay;
                      break;

                    case RTP_TRANS_FMT_CLKRATE:
                      cr = atoi(codecFormatToken);
                      sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[codecNum].clockRate
                        = cr;
                      sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_FromCodecDetails[codecNum].clockRate
                        = cr;
                      break;

                    case RTP_TRANS_FMT_BITRATE:
                      br = atoi(codecFormatToken);
                      sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[codecNum].bitRate
                        = br;
                      sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_FromCodecDetails[codecNum].bitRate
                        = br;
                      break;

                    case RTP_TRANS_FMT_MODE:
                      mode = atoi(codecFormatToken);

                      if(strncmp( sp->rtp_trans_codeclists[idx].rtp_transcoder_ToCodecDetails[codecNum].codecName,
                          ISAC_CODEC_STR, 16) ==0)
                      {
                         if(mode !=30 && mode != 60)
                         {
                             mode =  30;
                         }
                      }
                      else if(strncmp( sp->rtp_trans_codeclists[idx].rtp_transcoder_ToCodecDetails[codecNum].codecName,
                          ILBC_CODEC_STR, 16) ==0)
                      {
                         if(mode !=30 && mode != 20)
                         {
                             mode =  30;
                         }
                      }
                      else if(strncmp( sp->rtp_trans_codeclists[idx].rtp_transcoder_ToCodecDetails[codecNum].codecName,
                          G722_1_CODEC_STR, 16) ==0)
                      {
                         if(mode !=20)
                         {
                             mode =  20;
                         }
                      }
                      else
                      {
                         if(mode == 0)
                           mode = 20;
                      }
                      sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[codecNum].mode
                        = mode;
                      sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_FromCodecDetails[codecNum].mode
                        = mode;
                      break;

                    default:
                      break;
                } // switch format
                fidx++;
                codecFormatToken = rtpp_strsep(&codecToken, "_");
              } //while codecformat

              sp->rtp_trans_codeclists[idx].numToCodecs++;
              sp->rtp_trans_codeclists[nidx].numFromCodecs++;
              codecNum++;
            codecToken = rtpp_strsep(&pCodecList2, "|");
          }// while codec pipe token

         rtpp_log_write(RTPP_LOG_INFO, sp->log,
                       "Num codecs in list 2 = :%d ",sp->rtp_trans_codeclists[idx].numToCodecs);

        if(codecNum == 0) return -1;
        // end second list

        // From, To, set to the ones from "idx" and top codec
        *codec_from=  rtp_get_codec_type(sp->rtp_trans_codeclists[idx].
                       rtp_transcoder_FromCodecDetails[0].codecName,
                       0);

        *payload_from= sp->rtp_trans_codeclists[idx].
                       rtp_transcoder_FromCodecDetails[0].payloadNum;

        *codec_to= rtp_get_codec_type(sp->rtp_trans_codeclists[idx].
                       rtp_transcoder_ToCodecDetails[0].codecName,
                       0);

        *payload_to= sp->rtp_trans_codeclists[idx].
                       rtp_transcoder_ToCodecDetails[0].payloadNum;


        *codec_from_nidx = rtp_get_codec_type(sp->rtp_trans_codeclists[nidx].
                       rtp_transcoder_FromCodecDetails[0].codecName,
                       0);

        *payload_from_nidx= sp->rtp_trans_codeclists[nidx].
                       rtp_transcoder_FromCodecDetails[0].payloadNum;

        *codec_to_nidx= rtp_get_codec_type(sp->rtp_trans_codeclists[nidx].
                       rtp_transcoder_ToCodecDetails[0].codecName,
                       0);

        *payload_to_nidx= sp->rtp_trans_codeclists[nidx].
                       rtp_transcoder_ToCodecDetails[0].payloadNum;

     sp->rtp_trans_codeclists[idx].activeFrmCodec = 0;
     sp->rtp_trans_codeclists[idx].activeToCodec = 0;
     sp->rtp_trans_codeclists[nidx].activeFrmCodec = 0;
     sp->rtp_trans_codeclists[nidx].activeToCodec = 0;

#ifdef DEBUG
      rtp_trans_printCodecArrays(sp,idx);
      rtp_trans_printCodecArrays(sp,nidx);
#endif
        rtpp_log_write(RTPP_LOG_INFO,  sp->log,
                               "Forward cod_f=%d pay_f=%d ==> cod_t=%d pay_t=%d  ",
                               *codec_from,*payload_from,*codec_to,*payload_to );
        rtpp_log_write(RTPP_LOG_INFO,  sp->log,
                               "Reverse cod_f=%d pay_f=%d ==> cod_t=%d pay_t=%d  ",
                               *codec_from_nidx,*payload_from_nidx,*codec_to_nidx,*payload_to_nidx );

      return 0;
}

// ===================================================================
// rtp_trans_fillCodecInfo
// this is only here for easy use in rtp_command file to process transcode command
// ===================================================================
void rtp_trans_fillCodecInfo(itrans_codec_create_info*  idxFrmInfo,
                             itrans_codec_create_info*  idxToInfo,
                             itrans_codec_create_info*  nidxFrmInfo,
                             itrans_codec_create_info*  nidxToInfo,
                             struct rtpp_session* sp, int idx)
{
    int nidx = NOT(idx);

    // we fill the codecInfo for creation
    if(idxFrmInfo && idxToInfo && sp)
    {
      idxFrmInfo->clockrate = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[0].clockRate;

      idxFrmInfo->bitrate = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[0].bitRate;

      idxFrmInfo->mode = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[0].mode;


      idxToInfo->clockrate = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[0].clockRate;

      idxToInfo->bitrate = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[0].bitRate;

      idxToInfo->mode = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[0].mode;
    }
    if(nidxFrmInfo && nidxToInfo && sp)
    {
      nidxFrmInfo->clockrate = sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_FromCodecDetails[0].clockRate;

      nidxFrmInfo->bitrate = sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_FromCodecDetails[0].bitRate;

      nidxFrmInfo->mode = sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_FromCodecDetails[0].mode;


      nidxToInfo->clockrate = sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_ToCodecDetails[0].clockRate;

      nidxToInfo->bitrate = sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_ToCodecDetails[0].bitRate;

      nidxToInfo->mode = sp->rtp_trans_codeclists[nidx].
                        rtp_transcoder_ToCodecDetails[0].mode;
    }
}

// ===================================================================
// rtp_trans_printCodecArrays
// print codec - called after parsing codec T command - for debug purposes
// ===================================================================
void rtp_trans_printCodecArrays(struct rtpp_session* sp, int idx)
{
    if(!sp) return;
    int i=0;

    rtpp_log_write(RTPP_LOG_DBUG, sp->log, "Codec From List for pidx : %d", idx);

    for(i=0;i<sp->rtp_trans_codeclists[idx].numFromCodecs;i++)
    {
      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "=== %d ===", i);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "name:%s", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[i].codecName);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "pl:%d", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[i].payloadNum);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "cr:%d", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[i].clockRate);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "br:%d", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[i].bitRate);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "mode:%d", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[i].mode);
    }

    rtpp_log_write(RTPP_LOG_DBUG, sp->log, "Codec To List for pidx : %d", idx);

    for(i=0;i<sp->rtp_trans_codeclists[idx].numToCodecs;i++)
    {
      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "=== %d ===", i);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "name:%s", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[i].codecName);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "pl:%d", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[i].payloadNum);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "cr:%d", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[i].clockRate);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "br:%d", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[i].bitRate);

      rtpp_log_write(RTPP_LOG_DBUG, sp->log, "mode:%d", sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[i].mode);
    }
}

// ===================================================================
// rtp_transcoder_decode_to_linear_wresize
// same as "decodeto linear" function except
// with manipulation for timestamp
// ===================================================================
int rtp_transcoder_decode_to_linear_wresize(struct rtp_transcoder *rt, struct rtpp_session* sp,
                             char* buf, int* len, int idx)
{

    int audio_len;
    unsigned short rtp_seq;
    uint32_t rtp_ts;
    char* rtpp_audio_offset;
    rtp_hdr_t *rtp;
    div_t blocks;
    int i=0;
    int doResample=1;//always 1 if resizing, because rtpresizer works only with 8k data
    int tsIncr = 0;

    if(sp == NULL)
        return 0;

    if (rt == NULL)
    {
        rtpp_log_write(RTPP_LOG_ERR, sp->log,
                       "transcoder not initialized.");
        return 0;
    }

    if ((rt->codec_from == NULL) || (rt->codec_to == NULL))
    {
        rtpp_log_write(RTPP_LOG_ERR, sp->log,
                       "transcode: codec not initialized.");
        return 0;
    }

    rtp = (rtp_hdr_t *)buf;
    rtp_seq = ntohs(rtp->seq);
    rtp_ts  = ntohl(rtp->ts);

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   "ssrc:0x%x seq:%d Enter transcode: (%u, %u, rtp_ts:%u rt->end_ts:%u)",
                   ntohl(rtp->ssrc), ntohs(rtp->seq), rtp_seq, rt->last_seq, rtp_ts, rt->end_ts );
#endif
    if (rt->had_packet == 0)
    {
        rt->audio_end = rt->pcmbuf;
        rt->begin_ts = rt->end_ts = rtp_ts;
        rt->to_seq = ntohs(rtp->seq);
        rt->to_ts =0;
        rt->linear_ts = 0;
        rt->invalid_pt=0;

    }
    else if (rtp->m || (rtp_seq != rt->last_seq+1) ||
             (rtp_ts != rt->end_ts) )
    {

        if (rtp_seq != rt->last_seq+1)
        {
#ifdef DEBUG
            rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "ssrc:0x%x seq:%d transcode: packetloss (%u, %u, %u samples)",
                           ntohl(rtp->ssrc), ntohs(rtp->seq), rtp_seq, rt->last_seq+1, rtp_ts - rt->end_ts);
#endif
      // packetloss -> update seq
            if ((rt->to_framelength != 0) && (rt->from_framelength != 0))
            {
                rt->to_seq += (rtp_seq - rt->last_seq) *
                              rt->from_framelength/rt->to_framelength;
                tsIncr =  (rtp_seq - rt->last_seq) *
                              rt->from_framelength/rt->to_framelength;
            }
            else
            {
                rt->to_seq +=  rtp_seq - rt->last_seq;
                tsIncr =  rtp_seq - rt->last_seq;
            }

        }
        else if (rtp_ts != rt->end_ts)
        {
#ifdef DEBUG
            rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "transcode: silence %u samples",
                           rtp_ts - rt->end_ts);
#endif
        }
    // packet loss/silence -> drop buffered audio
#ifdef DEBUG
        rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "ssrc:0x%x seq:%d updating rt->audio_end with pcmbuf audio_end:0x%x, pcmbuf:0x%x",
                       ntohl(rtp->ssrc), ntohs(rtp->seq), rt->audio_end, rt->pcmbuf);
#endif
        rt->audio_end = rt->pcmbuf;


    }

    rt->last_seq  =  rtp_seq;

    audio_len = *len - RTP_HDR_LEN(rtp);
#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                   "ssrc:0x%x seq:%d tr: got audio length %d : from_TS=%u (in buffer %d begin_TS=%u  end_TS=%u)",
                   ntohl(rtp->ssrc), ntohs(rtp->seq), audio_len, rtp_ts, rt->audio_end - rt->pcmbuf,
                   ntohl(rt->begin_ts), ntohl(rt->end_ts));
#endif
    rtpp_audio_offset = buf + RTP_HDR_LEN(rtp);


    // Wideband to Narrowband interwork
    int frmArrnum = sp->rtp_trans_codeclists[idx].activeFrmCodec;
    int toArrnum = sp->rtp_trans_codeclists[idx].activeToCodec;

    int frmCR = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[frmArrnum].clockRate;
    int toCR =  sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[toArrnum].clockRate;

    // resample only if CR different
    if(frmCR == 2*toCR || toCR == 2*frmCR)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Resampling necessary frmCR= %d toCR=%d",frmCR,toCR);
#endif
       doResample=1;
    }
    else if(frmCR == 4*toCR || toCR == 4*frmCR)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Resampling necessary frmCR= %d toCR=%d",frmCR,toCR);
#endif
       doResample=2;
    }

    audio_len = rt->codec_from->codec2linear( rt->handle_from, (unsigned char *)rt->audio_end, (unsigned char *)rtpp_audio_offset,
                                              audio_len, doResample, 8000);

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                   "ssrc:0x%x seq:%d tr:  audio len after codec2linear: %d",
                   ntohl(rtp->ssrc), ntohs(rtp->seq), audio_len);
#endif

    if (audio_len <= 0)
    {
        if (audio_len < 0)
            rtpp_log_write(RTPP_LOG_ERR, sp->log,
                           "transcode: codec_from->codec2linear failed.");
        return RTPP_TRANSCODER_TYPE2INT_FAILED;
    }
    rt->end_ts += rt->from_samples_per_frame;//audio_len / BYTES_PER_SAMPLE;
    rt->audio_end += audio_len;

    *len = (audio_len) + RTP_HDR_LEN(rtp); // add header length

    memcpy(rtpp_audio_offset,rt->pcmbuf,audio_len); // copy pcmbuf to rtp packet

    // adjust timestamp

    if(rt->had_packet==1)
    {
      int outnsamples=  audio_len;

#ifdef DEBUG
      rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "ssrc:0x%x seq:%d outnsamples=%d old LINEAR_TS = %u",  ntohl(rtp->ssrc), ntohs(rtp->seq),outnsamples, rt->linear_ts);

#endif
      if(tsIncr)
        rt->linear_ts +=  outnsamples + outnsamples*tsIncr;
      else
        rt->linear_ts  += outnsamples;

      if(rt->linear_ts == UINT_MAX)
      {
         // reset timestamp
         rt->linear_ts=0;
      }

#ifdef DEBUG
      rtpp_log_write(RTPP_LOG_INFO, sp->log,
                           "ssrc:0x%x seq:%d outnsamples=%d LINEAR_TS = %u",  ntohl(rtp->ssrc), ntohs(rtp->seq),outnsamples, rt->linear_ts);
#endif

    }
    else
      rt->had_packet = 1;


    rtp->ts = htonl(rt->linear_ts);

    rt->audio_end = rt->pcmbuf;

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   "ssrc:0x%x seq:%d Exit transcode: (seq %u, last_seq %u, rtp->ts:%u rtp_ts:%u rt->end_ts:%u)",
                   ntohl(rtp->ssrc), ntohs(rtp->seq), rtp_seq, ntohs(rt->last_seq), ntohl(rtp->ts), rtp_ts, ntohl(rt->end_ts));
#endif
    return RTPP_TRANSCODER_OK;

}

// ===================================================================
// rtp_transcoder_encode_to_codec_wresize
// same as "encode to codec" function except
// with manipulation of timestamp
// ===================================================================
int rtp_transcoder_encode_to_codec_wresize(struct rtp_transcoder *rt, struct rtpp_session* sp,
                             char* buf, int* len, int idx)
{

    unsigned int audio_len;
    uint32_t rtp_ts;
    char* rtpp_audio_offset;
    rtp_hdr_t *rtp;
    div_t blocks;
    int i=0;
    int doResample=1; //always 1 if resizing, because rtpresizer works only with 8k data

    if (rt == NULL || sp == NULL)
    {
        rtpp_log_write(RTPP_LOG_ERR, sp->log,
                       "transcode: Session not initialized.");
        return 0;
    }


    if ((rt->codec_from == NULL) || (rt->codec_to == NULL))
    {
        rtpp_log_write(RTPP_LOG_ERR, sp->log,
                       "transcode: codec not initialized.");
        return 0;
    }


    rtp = (rtp_hdr_t *)buf;
    rtpp_audio_offset = buf + RTP_HDR_LEN(rtp);
    unsigned int inlen = (*len) - RTP_HDR_LEN(rtp);

    if(rt->from_samples_per_frame != rt->to_samples_per_frame)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "ssrc:0x%x seq:%d Updating  ts=>to_samples_per_frame=>%d old rt->to_ts = %u",
                       ntohl(rtp->ssrc), ntohs(rtp->seq),
                       rt->to_samples_per_frame, rt->to_ts);
#endif
       rt->to_ts = rt->to_ts + rt->to_samples_per_frame;

       if(rt->to_ts == UINT_MAX)
       {
          // reset timestamp
          rt->to_ts=0;
       }
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "ssrc:0x%x seq:%d New rt->to_ts = %u",
                       ntohl(rtp->ssrc), ntohs(rtp->seq),
                       rt->to_ts);
#endif
    }

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   " ssrc:0x%x seq:%d encode_to_codec_wresize input len = %d to_ts=%u",
                     ntohl(rtp->ssrc), ntohs(rtp->seq), inlen , rt->to_ts);

    rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   " ssrc:0x%x seq:%d rt->from_samples_per_frame = %d rt->to_samples_per_frame=%d",
                     ntohl(rtp->ssrc), ntohs(rtp->seq),
                     rt->from_samples_per_frame, rt->to_samples_per_frame);
#endif

    if(inlen > 0)
    {
#ifdef DEBUG
      rtpp_log_write(RTPP_LOG_INFO, sp->log,
                       "ssrc:0x%x seq:%d. ==> calling linear2codec  pt:%d  inlen = %d ",
                       ntohl(rtp->ssrc), ntohs(rtp->seq), rt->from_payload_id, inlen );
#endif
      // get pcmbuf from rtp buf which was resized before getting here.
      memcpy(rt->pcmbuf,rtpp_audio_offset,inlen);

      // all available audio is sent out

    // Wideband to Narrowband interwork
    int frmArrnum = sp->rtp_trans_codeclists[idx].activeFrmCodec;
    int toArrnum = sp->rtp_trans_codeclists[idx].activeToCodec;

    int frmCR = sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_FromCodecDetails[frmArrnum].clockRate;
    int toCR =  sp->rtp_trans_codeclists[idx].
                        rtp_transcoder_ToCodecDetails[toArrnum].clockRate;

    // resample only if CR different
    if(frmCR == 2*toCR || toCR == 2*frmCR)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Resampling necessary frmCR= %d toCR=%d",frmCR,toCR);
#endif
       doResample=1;
    }
    else if(frmCR == 4*toCR || toCR == 4*frmCR)
    {
#ifdef DEBUG
       rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "Resampling necessary frmCR= %d toCR=%d",frmCR,toCR);
#endif
       doResample=2;
    }

          audio_len = rt->codec_to->linear2codec( rt->handle_to, (unsigned char *)rtpp_audio_offset, (unsigned char *)rt->pcmbuf,
                                                 inlen,
                                                doResample, 8000);

      if (audio_len <= 0)
      {
        if (audio_len < 0)
            rtpp_log_write(RTPP_LOG_ERR, sp->log,
                           "transcode: codec_to->linear2codec failed.");
        return RTPP_TRANSCODER_INT2TYPE_FAILED;
      }
#ifdef DEBUG

      rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                       "ssrc:0x%x seq:%d. ==> calling linear2codec  out audio_len = %d ",
                       ntohl(rtp->ssrc), ntohs(rtp->seq), audio_len );
#endif

    }

    rtp->seq = htons(rt->to_seq);   // update packet seqno
    rt->to_seq++;
    rtp->ts = htonl(rt->to_ts);

#ifdef DEBUG
    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                   "ssrc:0x%x seq:%d transcoded from payload %d to %d,"
                   "size %d (%d) to %d (%d) ts %u (buffering %d).\n",
                   ntohl(rtp->ssrc), ntohs(rtp->seq),
                   rt->from_payload_id, rt->to_payload_id, *len,*len - RTP_HDR_LEN(rtp),
                   audio_len + RTP_HDR_LEN(rtp), audio_len,
                   ntohl(rtp->ts),
                   rt->audio_end - rt->pcmbuf);

    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
                   "ssrc:0x%x seq:%d Exit transcode: ( %u, rt->end_ts:%u)",
                    ntohl(rtp->ssrc), ntohs(rtp->seq), rt->last_seq,  rt->end_ts);
#endif

    *len = audio_len + RTP_HDR_LEN(rtp);

    rtp->pt = rt->to_payload_id;
    return RTPP_TRANSCODER_OK;
}


int rtp_transcoder_reinit(struct rtpp_session* sp, int idx, int activeCodecIndex)
{

  int retVal = RTPP_TRANSCODER_OK;
  int nidx=NOT(idx);

  int newCodec, newPayload;
  itrans_codec_create_info newcodecInfo;

  if( sp == NULL )
    return -1;

  rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   " rtp_transcoder_reinit ==> incoming idx=%d ", idx);
  rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   " rtp_transcoder_reinit ==> activeCodecIndex=%d ", activeCodecIndex);

  struct rtp_transcoder *rtIdx =  &(sp->trans[idx]);
  struct rtp_transcoder *rtNIdx = &(sp->trans[nidx]);

  if( rtIdx == NULL || rtNIdx == NULL)
    return -1;

  newcodecInfo.clockrate = sp->rtp_trans_codeclists[idx].
                    rtp_transcoder_FromCodecDetails[activeCodecIndex].clockRate;

  newcodecInfo.bitrate = sp->rtp_trans_codeclists[idx].
                    rtp_transcoder_FromCodecDetails[activeCodecIndex].bitRate;

  newcodecInfo.mode = sp->rtp_trans_codeclists[idx].
                    rtp_transcoder_FromCodecDetails[activeCodecIndex].mode;


  newPayload = sp->rtp_trans_codeclists[idx].
                       rtp_transcoder_FromCodecDetails[activeCodecIndex].payloadNum;

  newCodec =  rtp_get_codec_type(sp->rtp_trans_codeclists[idx].
                       rtp_transcoder_FromCodecDetails[activeCodecIndex].codecName,
                       0);

  //============ create from codec for idx
  retVal = rtp_transcoder_update(rtIdx, sp,
                  newPayload, newCodec,&newcodecInfo,
                  0, 0, NULL,
                  idx);

  if(retVal != RTPP_TRANSCODER_OK)
  {
     return -1;
  }
  // change active from codec for idx
  sp->rtp_trans_codeclists[idx].activeFrmCodec = activeCodecIndex;

  //============ create to codec for !idx
  retVal = rtp_transcoder_update(rtNIdx, sp,
                  0, 0, NULL,
                  newPayload, newCodec, &newcodecInfo,
                  nidx);

  if(retVal != RTPP_TRANSCODER_OK)
  {
     return -1;
  }
  // change active to codec index for nidx
  sp->rtp_trans_codeclists[nidx].activeToCodec = activeCodecIndex;


  //============ Check if we need resizer samples re-init

  // cleanup any resizer data left
  // remove session from active resizer list
  memset(&sp->resizers[idx], 0, sizeof(rtp_resizer));
  rtp_resizer_free(&sp->resizers[idx]);
  memset(&sp->resizers[!idx], 0, sizeof(rtp_resizer));
  rtp_resizer_free(&sp->resizers[!idx]);
  remove_session_frm_active_rsz_lst(sp);
  rtpp_log_write(RTPP_LOG_INFO, sp->log, "Cleaned up resizer lists");

  int to_codec_idx = sp->rtp_trans_codeclists[idx].activeToCodec;
  int to_mode = sp->rtp_trans_codeclists[idx].
                    rtp_transcoder_ToCodecDetails[to_codec_idx].mode;
  rtpp_log_write(RTPP_LOG_INFO, sp->log,
                         "Process transcode Re-Init.newcodecInfo.mode = %d to_mode = %d  ",
                         newcodecInfo.mode, to_mode);


  if(newcodecInfo.mode != to_mode)
  {
        rtpp_log_write(RTPP_LOG_INFO, sp->log,
                       "Process transcode Re-Init. Calculate Resize time.");

        int requested_nsamples_from = (newcodecInfo.mode/10) * 80;
        int requested_nsamples_to = (to_mode/10) * 80;

        if(requested_nsamples_to > 0)
        {
          sp->resizers[idx].output_nsamples = requested_nsamples_to*2;
          rtpp_log_write(RTPP_LOG_INFO, sp->log, "RTP packets from %s "
                           "will be resized to %d bytes",
                           (idx == 0) ? "callee" : "caller", sp->resizers[idx].output_nsamples );
        }
        if(requested_nsamples_from > 0)
        {
          sp->resizers[!idx].output_nsamples = requested_nsamples_from*2;
          rtpp_log_write(RTPP_LOG_INFO, sp->log, "RTP packets from %s "
                           "will be resized to %d bytes",
                           (!idx == 0) ? "callee" : "caller", sp->resizers[!idx].output_nsamples );
        }

        if(g_use_timed_resizer
         && (sp->resizers[idx].output_nsamples || sp->resizers[!idx].output_nsamples))
        {
            // clean any prev resize list data
            active_rsz_sp spnode;
            spnode.rsz_sp = sp;
            rtp_data_list_append(&spnode, sizeof(active_rsz_sp), active_resized_sp_list );
            rtpp_log_write(RTPP_LOG_INFO,sp->log,
                       "added session to active resized-packet session list ");
        }
  }

  rtpp_log_write(RTPP_LOG_INFO, sp->log,
                   " rtp_transcoder_reinit Initialized : rtp_transcoder_reinit : Active Codec Index changed to...%d",
                     activeCodecIndex);
  return retVal;
}
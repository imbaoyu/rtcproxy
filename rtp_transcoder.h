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
 * $Id: rtp_transcoder.h,v 1.5 2006/02/23 00:15:24 sayer Exp $
 *
 */

#ifndef _RTP_TRANSCODER_H_
#define _RTP_TRANSCODER_H_

#include "trans/itrans.h"

#include <sys/types.h>
/* #include <stdio.h> */

#define RTPP_TRANSCODER_OK 0
#define RTPP_TRANSCODER_ERROR 1
#define RTPP_TRANSCODER_RTP_DROP 2
#define RTPP_TRANSCODER_INVALID_PAYLOAD 3
#define RTPP_TRANSCODER_INT2TYPE_FAILED 4
#define RTPP_TRANSCODER_TYPE2INT_FAILED 5
#define RTPP_DEFAULT_PTIME 20

#define CODEC_NAME_LEN 256

#define RTP_TRANS_MAX_CODEC_SUP 12
#define RTP_TRANS_FROM          0
#define RTP_TRANS_TO            1

struct rtpp_session;

typedef struct rtp_transcoder_codecDetails
{

  char codecName[CODEC_NAME_LEN];
  int payloadNum;
  int clockRate;
  int bitRate;
  int mode;
} rtp_transcoder_codecDetails;

typedef struct rtp_transcoder_codecLists
{
    // number of codecs in from and to array - from/to depending on pidx.
    int numFromCodecs;
    int numToCodecs;

    int activeFrmCodec;
    int activeToCodec;

    // from codec list and to codec list - from/to depending on pidx.
    rtp_transcoder_codecDetails rtp_transcoder_FromCodecDetails[RTP_TRANS_MAX_CODEC_SUP];
    rtp_transcoder_codecDetails rtp_transcoder_ToCodecDetails[RTP_TRANS_MAX_CODEC_SUP];
} rtp_transcoder_codecLists;

struct rtp_transcoder {
  char to_payload_id;//current to codec
  char from_payload_id; //current from codec

  long handle_from;
  itrans_transcode* codec_from; //current from codec
  unsigned int from_framelength;
  unsigned int from_encodedsize;
  unsigned int from_clockrate;
  unsigned int from_bitrate;

  long handle_to;
  itrans_transcode* codec_to; //current to codec
  unsigned int to_framelength;
  unsigned int to_encodedsize;
  unsigned int to_clockrate;
  unsigned int to_bitrate;

  char pcmbuf[1024*10];
  unsigned short last_seq;
  unsigned short to_seq;
  uint32_t begin_ts;
  uint32_t end_ts;
  char* audio_end;
  unsigned int to_ts;

  short int had_packet;
  short int disable_comfort_noise;
  char cn_payload_id;

  uint32_t linear_ts; // to help with ptime resizing
  short int invalid_pt;

  unsigned int from_samples_per_frame;
  unsigned int to_samples_per_frame;
/*   FILE* tstfile; */
};
int rtp_transcoder_init(struct cfg *);
struct rtp_transcoder *rtp_transcoder_new(struct rtpp_session* sp,char from_payload_id, int from_codec_id,
                      itrans_codec_create_info* format_parameters_from,
                      char to_payload_id,   int to_codec_id,
                      itrans_codec_create_info* format_parameters_to, int idx);

int rtp_transcoder_update(struct rtp_transcoder* rt, struct rtpp_session* sp,
              char from_payload_id, int from_codec_id,
              itrans_codec_create_info* format_parameters_from,
              char to_payload_id,   int to_codec_id,
              itrans_codec_create_info* format_parameters_to, int idx);

int rtp_transcoder_reinit(struct rtpp_session* sp,
                           int idx, int activeCodecIndex);

void rtp_transcoder_free(struct rtp_transcoder* rt, struct cfg *cf);

int rtp_server_transcode(struct rtp_transcoder* rt, struct rtpp_session* sp, char* buf);

int rtp_transcoder_encode_to_codec(struct rtp_transcoder *rt, struct rtpp_session* sp,  char* buf, int* len, int idx) ;
int rtp_transcoder_decode_to_linear(struct rtp_transcoder *rt, struct rtpp_session* sp,  char* buf, int* len, int idx) ;

int rtp_transcoder_encode_to_codec_wresize(struct rtp_transcoder *rt, struct rtpp_session* sp,  char* buf, int* len, int idx) ;
int rtp_transcoder_decode_to_linear_wresize(struct rtp_transcoder *rt, struct rtpp_session* sp,  char* buf, int* len, int idx) ;

int rtp_set_comfort_noise(struct rtp_transcoder *rt, char payload, short int enable);

void rtp_trans_printCodecArrays(struct rtpp_session* sp, int idx);

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
                        int* payload_to_nidx);

void rtp_trans_fillCodecInfo(itrans_codec_create_info*  idxFrmInfo,
                             itrans_codec_create_info*  idxToInfo,
                             itrans_codec_create_info*  nidxFrmInfo,
                             itrans_codec_create_info*  nidxToInfo,
                             struct rtpp_session* sp, int idx);


void rtp_transcoder_shutdown();

#endif

/*
 * Copyright (c) 2007 Sippy Software, Inc., http://www.sippysoft.com
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
 * $Id: rtp_resizer.c,v 1.6 2009/01/12 11:36:40 sobomax Exp $
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "rtp.h"
#include "rtpp_defines.h"
#include "rtp_resizer.h"

static int
max_nsamples(int codec_id)
{

    switch (codec_id)
    {
    case RTP_GSM:
        return 160; /* 20ms */
    default:
        return 0; /* infinite */
    }
}

void
rtp_resizer_free(struct rtp_resizer *rtp_resize)
{
    struct rtp_packet *p;
    struct rtp_packet *p1;

    p = rtp_resize->queue.first;
    while (p != NULL) {
        p1 = p;
        p = p->next;
        rtp_packet_free(p1);
    }
}

void
rtp_resizer_enqueue(struct cfg *cf, struct rtp_resizer *rtp_resize, struct rtp_packet **pkt)
{
   //rtpp_log_ewrite(RTPP_LOG_INFO, cf->glog,"ssrc:0x%x seq:%d ====> rtp_resizer_enqueue ENTER \n",
//     ntohl( (*pkt)->data.header.ssrc), ntohs((*pkt)->data.header.seq) );

    struct rtp_packet   *p;
    uint32_t            ref_ts, internal_ts;
    int                 delta;


    if (rtp_packet_parse(*pkt) != RTP_PARSER_OK)
    {
        return;
    }

    if ((*pkt)->nsamples == RTP_NSAMPLES_UNKNOWN)
    {
      return;
    }

    if (rtp_resize->last_sent_ts_inited && ts_less((*pkt)->ts, rtp_resize->last_sent_ts))
    {
        // Packet arrived too late. Drop it.
        rtpp_log_ewrite(RTPP_LOG_INFO, cf->glog,"ssrc:0x%x seq:%d rtp_resizer_enqueue  Packet arrived too late. Drop.\n",
           ntohl( (*pkt)->data.header.ssrc), ntohs((*pkt)->data.header.seq));

        rtp_packet_free(*pkt);
        *pkt = NULL;

        return;
    }
    internal_ts = (*pkt)->rtime * 8000.0;
    if (!rtp_resize->tsdelta_inited) {
        rtp_resize->tsdelta = (*pkt)->ts - internal_ts + 40;
        rtp_resize->tsdelta_inited = 1;
    }
    else {
        ref_ts = internal_ts + rtp_resize->tsdelta;
        if (ts_less(ref_ts, (*pkt)->ts)) {
            rtp_resize->tsdelta = (*pkt)->ts - internal_ts + 40;
/*            printf("Sync forward\n"); */
        }
        else if (ts_less((*pkt)->ts + rtp_resize->output_nsamples + 160, ref_ts))
        {
            delta = (ref_ts - ((*pkt)->ts + rtp_resize->output_nsamples + 160)) / 2;
            rtp_resize->tsdelta -= delta;
/*            printf("Sync backward\n"); */
        }
    }
    if (rtp_resize->queue.last != NULL)
    {
        p = rtp_resize->queue.last;
        while (p != NULL && ts_less((*pkt)->ts, p->ts))
             p = p->prev;

        if (p == NULL) /* head reached */
        {
            (*pkt)->next = rtp_resize->queue.first;
            (*pkt)->prev = NULL;
            rtp_resize->queue.first->prev = *pkt;
            rtp_resize->queue.first = *pkt;
        }
        else if (p == rtp_resize->queue.last) /* tail of the queue */
        {
            (*pkt)->prev = rtp_resize->queue.last;
            (*pkt)->next = NULL;
            rtp_resize->queue.last->next = *pkt;
            rtp_resize->queue.last = *pkt;
        }
        else { /* middle of the queue */
            (*pkt)->next = p->next;
            (*pkt)->prev = p;
            (*pkt)->next->prev = (*pkt)->prev->next = *pkt;
        }
    }
    else {
        rtp_resize->queue.first = rtp_resize->queue.last = *pkt;
        (*pkt)->prev = NULL;
    (*pkt)->next = NULL;
    }
    rtp_resize->nsamples_total += (*pkt)->nsamples;

    rtpp_log_ewrite(RTPP_LOG_DBUG, cf->glog,"ssrc:0x%x seq:%d ====> rtp_resizer_enqueue rtp_resize->nsamples_total = %d \n",
      ntohl( (*pkt)->data.header.ssrc), ntohs((*pkt)->data.header.seq),rtp_resize->nsamples_total);

    *pkt = NULL; /* take control over the packet */
}

static void
detach_queue_head(struct rtp_resizer *rtp_resize)
{

    rtp_resize->queue.first = rtp_resize->queue.first->next;
    if (rtp_resize->queue.first == NULL)
    rtp_resize->queue.last = NULL;
    else
    rtp_resize->queue.first->prev = NULL;
}

static void
append_packet(struct rtp_packet *dst, struct rtp_packet *src)
{

    memcpy(&dst->data.buf[dst->data_offset + dst->data_size],
      &src->data.buf[src->data_offset], src->data_size);
    dst->nsamples += src->nsamples;
    dst->data_size += src->data_size;
    dst->size += src->data_size;
    dst->appendable = src->appendable;
}

static void
append_chunk(struct rtp_packet *dst, struct rtp_packet *src, const struct rtp_packet_chunk *chunk)
{

    /* Copy chunk */
    memcpy(&dst->data.buf[dst->data_offset + dst->data_size],
      &src->data.buf[src->data_offset], chunk->bytes);
    dst->nsamples += chunk->nsamples;
    dst->data_size += chunk->bytes;
    dst->size += chunk->bytes;

    /* Truncate the source packet */
    src->nsamples -= chunk->nsamples;
    rtp_packet_set_ts(src, src->ts + chunk->nsamples);
    src->data_size -= chunk->bytes;
    src->size -= chunk->bytes;
    memmove(&src->data.buf[src->data_offset],
      &src->data.buf[src->data_offset + chunk->bytes], src->data_size);
}

static void
move_chunk(struct rtp_packet *dst, struct rtp_packet *src, const struct rtp_packet_chunk *chunk)
{
    /* Copy chunk */
    memcpy(&dst->data.buf[dst->data_offset],
      &src->data.buf[src->data_offset], chunk->bytes);
    dst->nsamples = chunk->nsamples;
    dst->data_size = chunk->bytes;
    dst->size = dst->data_size + dst->data_offset;

    /* Truncate the source packet */
    src->nsamples -= chunk->nsamples;
    rtp_packet_set_ts(src, src->ts + chunk->nsamples);
    src->data_size -= chunk->bytes;
    src->size -= chunk->bytes;
    memmove(&src->data.buf[src->data_offset],
      &src->data.buf[src->data_offset + chunk->bytes], src->data_size);
}

struct rtp_packet *
rtp_resizer_get(struct cfg *cf,struct rtp_resizer *rtp_resize, double dtime)
{
    struct rtp_packet *ret = NULL;
    struct rtp_packet *p;
    uint32_t    ref_ts;
    int         count = 0;
    int         split = 0;
    int         nsamples_left;
    int         output_nsamples;
    int         max;
    struct      rtp_packet_chunk chunk;


    if (rtp_resize->queue.first == NULL)
    {
        return NULL;
    }

    ref_ts = (dtime * 8000.0) + rtp_resize->tsdelta;

    // Wait untill enough data has arrived or timeout occured
    /*if (rtp_resize->nsamples_total < rtp_resize->output_nsamples  ||
      ts_less(ref_ts, rtp_resize->queue.first->ts + rtp_resize->output_nsamples + 160))
    {
        return NULL;
    }*/

    if (rtp_resize->nsamples_total < rtp_resize->output_nsamples)
      return NULL;

    output_nsamples = rtp_resize->output_nsamples;
    max = max_nsamples(rtp_resize->queue.first->data.header.pt);
    if (max > 0 && output_nsamples > max)
        output_nsamples = max;

    /* Aggregate the output packet */
    while ((ret == NULL || ret->nsamples < output_nsamples) && rtp_resize->queue.first != NULL)
    {
        p = rtp_resize->queue.first;
         rtpp_log_ewrite(RTPP_LOG_DBUG, cf->glog,"====>  rtp_resizer_get seq=%u  nsamples=%d datasize=%d output_nsamples=%d\n",
           ntohs(p->data.header.seq), p->nsamples, p->data_size, output_nsamples);

        if (ret == NULL)
        {
            /* Look if the first packet is to be split */
            if (p->nsamples > output_nsamples)
            {
                           rtp_packet_first_chunk_find(p, &chunk, output_nsamples);
                           if (chunk.whole_packet_matched)
                           {
                              ret = p;
                              detach_queue_head(rtp_resize);
                            }
                            else
                            {
                              ret = rtp_packet_alloc();
                              if (ret == NULL)
                              {
                               break;
                              }
                              memcpy(ret, p, offsetof(struct rtp_packet, data.buf));
                              // to copy header because it is inside a union
                              memcpy(&(ret->data.header),  &(p->data.header), sizeof(rtp_hdr_t));
                              move_chunk(ret, p, &chunk);
                              ++split;
                            }
                            if (!rtp_resize->seq_initialized) {
                                rtp_resize->seq = ret->seq;
                                rtp_resize->seq_initialized = 1;
                            }
                            ++count;
                            break;
               }
        }
        else /* ret != NULL */
        {
            /* detect holes and payload changes in RTP stream */
            if ((ret->ts + ret->nsamples) != p->ts ||
                ret->data.header.pt != p->data.header.pt)
            {
                rtpp_log_ewrite(RTPP_LOG_DBUG, cf->glog,
                    "ssrc:0x%x seq:%d ====>  rtp_resizer_get calculation ret->ts + ret->nsamples=%d p->ts=%d ret->data.header.pt=%d  p->data.header.pt=%d \n",
                    ntohl( ret->data.header.ssrc), ntohs(ret->data.header.seq), ret->ts + ret->nsamples, p->ts, ret->data.header.pt, p->data.header.pt);

                break;
            }
            nsamples_left = output_nsamples - ret->nsamples;

            /* Break the input packet into pieces to create output packet
             * of specified size */
            if (nsamples_left > 0 && nsamples_left < p->nsamples)
            {
              rtp_packet_first_chunk_find(p, &chunk, nsamples_left);
              if (chunk.whole_packet_matched)
              {
                /* Prevent RTP packet buffer overflow */
                if ((ret->size + p->data_size) > sizeof(ret->data.buf))
                {
                  break;
                }
                append_packet(ret, p);
                detach_queue_head(rtp_resize);
                rtp_packet_free(p);
              }
              else
              {
                /* Prevent RTP packet buffer overflow */
               if ((ret->size + chunk.bytes) > sizeof(ret->data.buf))
               {
                 break;
               }
               /* Append chunk to output */
               append_chunk(ret, p, &chunk);
               ++split;
              }
        ++count;
        break;
            } // if nsamples
        } // else ret!=null
        ++count;

        /*
         * Prevent RTP packet buffer overflow
         */
        if (ret != NULL && (ret->size + p->data_size) > sizeof(ret->data.buf))
            break;

        /* Detach head packet from the queue */
       detach_queue_head(rtp_resize);

        /*
         * Add the packet to the output
         */
        if (ret == NULL) {
            ret = p; /* use the first packet as the result container */
            if (!rtp_resize->seq_initialized) {
                rtp_resize->seq = p->seq;
                rtp_resize->seq_initialized = 1;
            }
        }
        else {
        append_packet(ret, p);
            rtp_packet_free(p);
        }
    /* Send non-appendable packet immediately */
    if (!ret->appendable)
        break;
    }
    if (ret != NULL) {
    rtp_resize->nsamples_total -= ret->nsamples;
    rtp_packet_set_seq(ret, rtp_resize->seq);
    ++rtp_resize->seq;
    rtp_resize->last_sent_ts_inited = 1;


    if(ret->data.header.pt==RTP_LINEAR)
    {
         rtp_resize->last_sent_ts = ret->ts + ret->nsamples/2;
    }
    else
    {
         rtp_resize->last_sent_ts = ret->ts + ret->nsamples;
    }

    rtpp_log_ewrite(RTPP_LOG_DBUG, cf->glog, "ssrc:0x%x seq:%d nsamples_total=%d, nsamples=%d, last_sent_ts=%d \n",
      ntohl( ret->data.header.ssrc), ntohs(ret->data.header.seq), rtp_resize->nsamples_total, ret->nsamples, rtp_resize->last_sent_ts);

    rtpp_log_ewrite(RTPP_LOG_DBUG, cf->glog, "ssrc:0x%x seq:%d Payload %d, data_size=%d %d packets aggregated, %d splits done, final size %dms output_nsamples=%d\n",
      ntohl( ret->data.header.ssrc), ntohs(ret->data.header.seq), ret->data.header.pt, ret->data_size,  count, split, ret->nsamples / 8, output_nsamples);

    }
    return ret;
}

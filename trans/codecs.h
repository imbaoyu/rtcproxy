
#ifndef _codecs_h_
#define _codecs_h_

// These are codec types. Do not confuse with payload types in rtpp_defines.h
// SSM sends both. payload type is not mandatory
// This is only for plugin. not SSM codec type.
#define CODEC_PCM16    0
#define CODEC_ULAW     1
#define CODEC_ALAW     2
#define CODEC_GSM0610  3

#define CODEC_ILBC     4
#define CODEC_MP3      5
#define CODEC_SPEEX_NB 6
#define CODEC_G729_FP  7

#define CODEC_ISAC 8
#define CODEC_G722 9
#define CODEC_G722_1 10 /*RFC3047*/
#define CODEC_G722_2 11 /*AMR WB*/
#define CODEC_AMRNBGSM 12 /*AMR NB GSMAMR*/

#endif

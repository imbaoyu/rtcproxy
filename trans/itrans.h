
#ifndef _itrans_h_
#define _itrans_h_
#include <stdio.h>

typedef enum itrans_type
{
    ITRANS_TYPE_BEGIN,
    ITRANS_TYPE_FRAME_LENGTH,
    ITRANS_TYPE_FRAME_SIZE,
    ITRANS_TYPE_ENCODED_FRAME_SIZE,
    ITRANS_TYPE_SAMPLES_PER_FRAME,
    ITRANS_TYPE_END

}ITRANS_TYPE;


typedef int (*itrans_do_transcode)( long codec_hdl,
                 unsigned char* out,
                 unsigned char* in,
                 unsigned int   size,
                 unsigned int   spare1,
                 long   spare2);


typedef struct _itrans_codec_info{
    int id;
    int value;
} itrans_codec_info;

typedef struct _itrans_codec_create_info {
  int clockrate;
  int bitrate;
  int mode;
} itrans_codec_create_info;

typedef long (*itrans_transcode_create)(itrans_codec_create_info* params,
                  itrans_codec_info* itrans_info);

typedef void (*itrans_transcode_free)(long h_codec);


typedef struct _itrans_transcode {

    int codec_id;

    int sample_size;

    itrans_do_transcode linear2codec;
    itrans_do_transcode codec2linear;

    itrans_transcode_create itrans_create;
    itrans_transcode_free itrans_free;

}itrans_transcode;

typedef struct itrans_plugin_st {
    char* plugin_name;
    itrans_transcode  *transcodecs;
}itrans_plugin;


#define BEGIN_PLUGINS(plugin_name) \
           itrans_plugin trans_plugin = { \
                plugin_name,

#define END_PLUGINS \
            };


#define BEGIN_TRANS_CODECS \
                (itrans_transcode[]) {


#define END_TRANS_CODECS \
                    { -1, 0, 0, 0, 0, 0 } \
                },

#define TRANS_CODEC(codec_id,sample_size,linear2codec,codec2linear,itrans_create,itrans_free) \
                    { codec_id, sample_size, linear2codec, codec2linear, itrans_create, itrans_free },




#endif








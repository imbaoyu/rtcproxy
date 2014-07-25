
#ifndef _transPlugin_h_
#define _transPlugin_h_

#include "itrans.h"
int trans_plugin_load_codec_plugins(char *dir);
void trans_plugin_release();
itrans_transcode* trans_plugin_get_codec(int codec_id);

#endif



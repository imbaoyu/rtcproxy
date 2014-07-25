
#include "rtpp_log.h"
#include "rtpp_defines.h"
#include "rtpp_trans_plugin.h"

extern rtpp_log_t glog;

#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>

#include <string>
#include <map>
#include <vector>

using std::string;
using std::map;
using std::vector;

std::vector<void*> lib_plugins;
std::map<int,itrans_transcode*> transcodecs;

int load_lib_plugin(const char* file);
int load_audio_plugIn(itrans_plugin* trans_plugins);

int trans_plugin_load_codec_plugins(char *directory)
{
    int err=0;
    struct dirent* entry;
    DIR* pDIR = opendir(directory);
    std::string path(directory);

    if(!pDIR){
	 rtpp_log_write(RTPP_LOG_ERR, glog,"plug-ins loader (%s): %s\n",directory,strerror(errno));
	return -1;
    }

    rtpp_log_write(RTPP_LOG_INFO, glog,"loading directory %s ...\n",directory);
    while( ((entry = readdir(pDIR)) != NULL) && (err == 0) ){

	string plugin_file = path + "/" + string(entry->d_name);
	
	if ( !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
	    continue;
	}

	if( plugin_file.find(".so",plugin_file.length()-3) == string::npos ){
	    continue;
	}

	rtpp_log_write(RTPP_LOG_INFO, glog,"loading %s ...\n",plugin_file.c_str());
	if( (err = load_lib_plugin(plugin_file.c_str())) < 0 )
	     rtpp_log_write(RTPP_LOG_ERR, glog,"while loading plug-in '%s'\n",plugin_file.c_str());
    }

    closedir(pDIR);
    return err;
}

int load_lib_plugin(const char* file)
{
    void* plugin_hndl = dlopen(file,RTLD_NOW);

    if(!plugin_hndl){
	 rtpp_log_write(RTPP_LOG_ERR, glog,"transPlugIn::loadPlugIn: %s\n",dlerror());
	return -1;
    }
	itrans_plugin* plugin = (itrans_plugin*)dlsym(plugin_hndl,"trans_plugin");
	if(load_audio_plugIn(plugin))
	  goto error;

    lib_plugins.push_back(plugin_hndl);
    return 0;

 error:
    dlclose(plugin_hndl);
    return -1;
}


int load_audio_plugIn(itrans_plugin* trans_plugins)
{
    if(trans_plugins ==NULL){
         rtpp_log_write(RTPP_LOG_ERR, glog,"audio plug-in doesn't contain any trans_plugins !\n");
        return -1;
    }
    itrans_transcode* trans_codec = trans_plugins->transcodecs;


    for(;;trans_codec++){
    	if(trans_codec->codec_id < 0) break;

    	if(transcodecs.find(trans_codec->codec_id) != transcodecs.end()){
    	     rtpp_log_write(RTPP_LOG_ERR, glog,"codec_id (%i) already supported\n",trans_codec->codec_id);
    	    break;
    	}
    	transcodecs.insert(std::make_pair(trans_codec->codec_id,trans_codec));
    	rtpp_log_write(RTPP_LOG_INFO, glog,"codec codec_id %i inserted\n",trans_codec->codec_id);
    }
    return 0;

}


itrans_transcode* trans_plugin_get_codec(int codec_id)
{
    map<int,itrans_transcode*>::iterator itr = transcodecs.find(codec_id);
    if(itr != transcodecs.end())
        return itr->second;

    return NULL;
}


void trans_plugin_release()
{
   for(vector<void*>::iterator it_plugins=lib_plugins.begin();it_plugins!=lib_plugins.end();++it_plugins)
   dlclose(*it_plugins);

}


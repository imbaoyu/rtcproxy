#ifndef _RTPP_MEM_H_
#define _RTPP_MEM_H_

#include "rtpp_defines.h"

// max allowed  nodes
#define RTP_LIST_MAX_NODES 50000
#define RTP_NODE_DATA_SZ 1024
#define MAX_MEM_FREE_NODES 5000

// node storage for any data type
typedef struct rtp_data_node {
   unsigned char data[RTP_NODE_DATA_SZ];
   struct rtp_data_node* next;
}rtp_data_node;

// generic linked list structure
typedef struct rtp_data_list{
  rtp_data_node* head;
  rtp_data_node* tail;
  int node_count;
}rtp_data_list;

typedef struct timed_session_pkt
{
    struct rtpp_session* sp;
    struct cfg* cf;
    int idx;
    struct rtp_packet* packet;
    uint32_t time_to_send_ms;
}timed_session_pkt;

typedef struct active_rsz_sp
{
    struct rtpp_session* rsz_sp;
}active_rsz_sp;


// functions for working on linked list
// create, append, remove, destroy
rtp_data_node*  rtp_node_mem_alloc(int data_sz);
void rtp_node_mem_free(rtp_data_node* p_node);
void rtp_data_list_allocate(rtp_data_list** p_list);
void rtp_data_list_append(void* data, int data_sz, rtp_data_list* p_list);
void rtp_data_list_remove(void* data, rtp_data_list* p_list);
void rtp_data_list_destroy(rtp_data_list* p_list);
void rtp_data_list_init(rtp_data_list* p_list);


#endif
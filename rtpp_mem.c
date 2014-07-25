/*HOC*****************************************************************************/
/*                                                                               */
/*  HISTORY OF CHANGE:                        VARIANT:8.0                       */
/*                                                                               */
/*------------------------------------------------------------+----------+-------*/
/*VERS| DATE | CHANGES                                        | VGNO     |  AUTH */
/*    |DDMMYY|                                                |          |       */
/*----+------+------------------------------------------------+----------+-------*/
/*001 |170611|Created file for memory mgmt                    |CQ00263177|  VR   */
/*********************************************************************************/

#include "rtpp_mem.h"
#include <sys/types.h>
#include <sys/time.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

static struct rtp_data_node* rtp_data_mem_pool = NULL;
int rtp_data_mempool_freecnt = 0;

// ===================================================================
// rtp_node_mem_alloc
// allocates or assigns previously freed data
// like rtp_packet_alloc
// input size for the generic void* data type in the node
// this is only if you want to creare mem for the list
// otherwise, use init function
// ===================================================================

rtp_data_node*
rtp_node_mem_alloc()
{
    rtp_data_node *p_node;

    p_node = rtp_data_mem_pool;
    if (p_node != NULL)
    {
        rtp_data_mem_pool = p_node->next;
        rtp_data_mempool_freecnt--;
    }
    else
    {
        p_node = ( rtp_data_node *)malloc(sizeof(rtp_data_node));
    }
    if(p_node)
    {
      memset(p_node,0,sizeof(rtp_data_node));
    }
    return p_node;
}

// ===================================================================
// rtp_data_list_init
// init list
// ===================================================================
void rtp_data_list_init(struct rtp_data_list* p_list)
{
    if(!p_list)
      return;
   p_list->head = NULL;
   p_list->tail = NULL;
   p_list->node_count=0;
}

// ===================================================================
// rtp_node_mem_free
// similar to rtp_packet_free
// ===================================================================

void
rtp_node_mem_free(struct rtp_data_node *p_node)
{
    if(p_node)
    {
      p_node->next = rtp_data_mem_pool;
      rtp_data_mem_pool = p_node;
      rtp_data_mempool_freecnt++;
    }

    if(rtp_data_mempool_freecnt > MAX_MEM_FREE_NODES)
    {
       // if we have too many free nodes allocated
       // clean up all free nodes and set pool back to empty.
       rtp_data_node *p_head = rtp_data_mem_pool;
       rtp_data_node *ptmp = p_head;
       while (p_head != NULL)
       {
          ptmp = p_head->next;
          free(p_head);
          p_head = ptmp;
          rtp_data_mempool_freecnt--;
       }
       rtp_data_mem_pool = NULL;
    }
}

// ===================================================================
// rtp_data_list_allocate
// allocates space for a new linked list
// ===================================================================

void rtp_data_list_allocate(struct rtp_data_list** p_list)
{
   *p_list = (struct rtp_data_list*)(malloc(sizeof(struct rtp_data_list)));
   (*p_list)->head = NULL;
   (*p_list)->tail = NULL;
   (*p_list)->node_count = 0;
}

// ===================================================================
// rtp_data_list_append
// add node data to the end of the list
// ===================================================================

void rtp_data_list_append(void *data, int data_sz, rtp_data_list *p_list)
{

  if(!data || !data_sz || !p_list)
    return;

  if(p_list->node_count > RTP_LIST_MAX_NODES)
  {
      // too many packets queued. cleanup before adding a node
      rtp_data_list_destroy(p_list);
  }

  rtp_data_node *newNode = rtp_node_mem_alloc();
  if(!newNode)
    return;

  memset(&(newNode->data),0,RTP_NODE_DATA_SZ);
  memcpy(&(newNode->data),data,data_sz);
  newNode->next = NULL;

  if(p_list->node_count == 0) // list empty, create node
  {
    p_list->head = p_list->tail = newNode;
    p_list->node_count++;
  }
  else // add node to non-empty list
  {
    p_list->tail->next = newNode;
    p_list->tail = newNode;
    p_list->node_count++;
  }
}

// ===================================================================
// rtp_data_list_remove
// remove  node data from anywhere in the list, node identified by pointer
// ===================================================================

void rtp_data_list_remove(void *data, struct rtp_data_list *p_list)
{
    if(!p_list || !data)
      return;

    rtp_data_node *prev = NULL;
    rtp_data_node *cur = p_list->head;

    while (cur != NULL)
    {
        if (cur->data == data)
        {
            if (p_list->head == cur)
              p_list->head = cur->next;

            if (p_list->tail == cur)
              p_list->tail = prev;

            if (prev != NULL)
              prev->next = cur->next;

            rtp_node_mem_free(cur);
            p_list->node_count--;
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

// ===================================================================
// rtp_data_list_destroy
// remove all nodes from list
// if any memory had been allocated, it will be in the pool
// when will the pool free it ?
// ===================================================================

void rtp_data_list_destroy(struct rtp_data_list* p_list)
{
    if(!p_list)
      return;

    rtp_data_node *cur = p_list->head;
    while(cur != NULL)
    {
      rtp_data_node* ptmp = cur->next;
      rtp_node_mem_free(cur);
      cur = ptmp;
      p_list->node_count--;
    }
}

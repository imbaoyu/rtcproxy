#ifndef _RTPP_STUN_H
#define _RTPP_STUN_H

#include "re.h"
#define STUN_DEBUG

#define RTPP_STUN_USERNAME_LEN     64

#define RTPP_STUN_RESERVE_ID       0  /* Reserved Idx incase no ids available*/
#define RTPP_STUN_START_ID         1
#define RTPP_STUN_MAX_SAVED_IDS    5
#define RTPP_STUN_MAX_RESERVE_USED 5


typedef enum {
    /* Add error case above this line by redefining the value RTPP_STUN_STATUS_START*/
  RTPP_STUN_STATUS_START = -12,
  RTPP_STUN_STATUS_NOT_STUN,
  RTPP_STUN_STATUS_INCOMPLETE_STUN,
  RTPP_STUN_STATUS_BAD_REQUEST,
  RTPP_STUN_STATUS_UNAUTHORIZED_BAD_REQUEST,
  RTPP_STUN_STATUS_UNAUTHORIZED,
  RTPP_STUN_STATUS_UNMATCHED_RESPONSE,
  RTPP_STUN_STATUS_UNKNOWN_REQUEST_ATTRIBUTE,
  RTPP_STUN_STATUS_UNKNOWN_ATTRIBUTE,
  RTPP_STUN_STATUS_MEM_FAIL,
  RTPP_STUN_STATUS_SOCK_FAIL,
  RTPP_STUN_STATUS_FAIL = -1,
  RTPP_STUN_STATUS_OK

} rtpp_stun_status;


typedef enum {
  RTPP_STUN_FLAG_SHORT_TERM_CREDENTIALS    = (1 << 0),
  RTPP_STUN_FLAG_LONG_TERM_CREDENTIALS     = (1 << 1),
  RTPP_STUN_FLAG_USE_FINGERPRINT           = (1 << 2),
  RTPP_STUN_FLAG_ADD_SOFTWARE              = (1 << 3),
  RTPP_STUN_FLAG_IGNORE_CREDENTIALS        = (1 << 4),
  RTPP_STUN_FLAG_NO_INDICATION_AUTH        = (1 << 5),
  RTPP_STUN_FLAG_FORCE_VALIDATER           = (1 << 6),
  RTPP_STUN_FLAG_NO_ALIGNED_ATTRIBUTES     = (1 << 7),
  RTPP_STUN_FLAG_IGNORE_TID                = (1 << 8),
} rttp_stun_flags;


typedef enum {
  RTPP_STUN_COMPAT_RFC3489,
  RTPP_STUN_COMPAT_RFC5389,
  RTPP_STUN_COMPAT_WLM2009,
  RTPP_STUN_COMPAT_OC2007,
  RTPP_STUN_COMPAT_LAST = RTPP_STUN_COMPAT_OC2007
} rttp_stun_compat;



typedef  uint8_t stun_trans_id[STUN_TID_SIZE];



typedef struct {
  stun_trans_id id;
  stun_method method;
  uint8_t *key;
  size_t key_len;
  bool valid;
} stun_agent_saved_tids;

typedef struct _stun_agent_t {
  rttp_stun_compat compat;
  stun_agent_saved_tids tids[RTPP_STUN_MAX_SAVED_IDS];
  uint32_t usage_flags;
  const char *software_attr;
  uint8_t max_reserve_tid_count;
}rtpp_stun_agent;


int rtpp_stun_handle_msg(struct rtpp_session *sp, int ridx,  struct rtp_packet *packet);
int rtpp_stun_agent_remove(struct rtpp_session *sp);
int rtpp_stun_agent_init(struct rtpp_session *sp);


#endif /* _STUN_AGENT_H */

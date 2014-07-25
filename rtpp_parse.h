#ifndef _RTPP_PARSE_H_
#define _RTPP_PARSE_H_


// VLAN Support (FRN4811)
#define MAX_ARGS_IN_UPDATE_CMD  	32//16
#define MAX_ARGS_IN_LOOKUP_CMD  	30//14
#define MAX_ARGS_IN_WCANDIDATE_CMD	28
#define MAX_ARGS_IN_PLAY_CMD    12

#define PORT_ARG_PREFIX             "port:"
#define PAYLOAD_ARG_PREFIX          "payload:"
#define TRANS_ARG_PREFIX            "trans:"
#define SEND_ARG_PREFIX             "send:"
#define PSEND_ARG_PREFIX            "psend:"
#define RCV_ARG_PREFIX              "rcv:"
#define PRCV_ARG_PREFIX             "prcv:"
#define SEND_FP_ARG_PREFIX          "dsend:"
#define PSEND_FP_ARG_PREFIX         "pdsend:"
#define RCV_FP_ARG_PREFIX           "drcv:"
#define PRCV_FP_ARG_PREFIX          "pdrcv:"
#define PTIME_ARG_PREFIX            "ptime:"
#define CN_ARG_PREFIX               "cn:"
#define BRIDGE_ARG_IP4_PREFIX       "ip4:"
#define BRIDGE_ARG_IP6_PREFIX       "ip6:"
#define ICE_LOCAL_USER_PREFIX		"iceL:"
#define ICE_REMOTE_USER_PREFIX		"iceR:"
#define ICE_RTP_CANDIDATE_PREFIX	"iceRtpR:"
#define ICE_RTCP_CANDIDATE_PREFIX	"iceRtcpR:"
#define FINGERPRINT_ARG_PREFIX	    "fingerprint:"
#define QOS_ARG_PREFIX	            "qos:"

#define PORT_ARG_PREFIX_LEN        (sizeof(PORT_ARG_PREFIX)-1)
#define PAYLOAD_ARG_PREFIX_LEN     (sizeof(PAYLOAD_ARG_PREFIX)-1)
#define TRANS_ARG_PREFIX_LEN       (sizeof(TRANS_ARG_PREFIX)-1)
#define SEND_ARG_PREFIX_LEN        (sizeof(SEND_ARG_PREFIX)-1)
#define PSEND_ARG_PREFIX_LEN       (sizeof(PSEND_ARG_PREFIX)-1)
#define RCV_ARG_PREFIX_LEN         (sizeof(RCV_ARG_PREFIX)-1)
#define PRCV_ARG_PREFIX_LEN        (sizeof(PRCV_ARG_PREFIX)-1)
#define SEND_FP_ARG_PREFIX_LEN      (sizeof(SEND_FP_ARG_PREFIX)-1)
#define PSEND_FP_ARG_PREFIX_LEN     (sizeof(PSEND_FP_ARG_PREFIX)-1)
#define RCV_FP_ARG_PREFIX_LEN       (sizeof(RCV_FP_ARG_PREFIX)-1)
#define PRCV_FP_ARG_PREFIX_LEN      (sizeof(PRCV_FP_ARG_PREFIX)-1)
#define PTIME_ARG_PREFIX_LEN       (sizeof(PTIME_ARG_PREFIX)-1)
#define CN_ARG_PREFIX_LEN          (sizeof(CN_ARG_PREFIX)-1)
#define BRIDGE_ARG_IP4_PREFIX_LEN  (sizeof(BRIDGE_ARG_IP4_PREFIX)-1)
#define BRIDGE_ARG_IP6_PREFIX_LEN  (sizeof(BRIDGE_ARG_IP6_PREFIX)-1)
#define ICE_LOCAL_USER_PREFIX_LEN	    (sizeof(ICE_LOCAL_USER_PREFIX)-1)
#define ICE_REMOTE_USER_PREFIX_LEN		(sizeof(ICE_REMOTE_USER_PREFIX)-1)
#define ICE_RTP_CANDIDATE_PREFIX_LEN	(sizeof(ICE_RTP_CANDIDATE_PREFIX)-1)
#define ICE_RTCP_CANDIDATE_PREFIX_LEN	(sizeof(ICE_RTCP_CANDIDATE_PREFIX)-1)
#define FINGERPRINT_ARG_PREFIX_LEN      (sizeof(FINGERPRINT_ARG_PREFIX)-1)
#define QOS_ARG_PREFIX_LEN	            (sizeof(QOS_ARG_PREFIX)-1)

#define IPV4_TYPE_IN_CMD        "ip4"
#define IPV6_TYPE_IN_CMD        "ip6"
#define MAX_NETWORK_ID_LEN      16  // Same as IFNAMSZ
#define MAX_IP_ADDR_LEN         128

typedef enum
{
   SRTP_KEY_PARAM_POS = 1,
   SRTP_SSRC_PARAM_POS,
   SRTP_SUITE_PARAM_POS,
   SRTP_ATTR_PARAM_POS /* DTLS setup attribute*/
     
}srtp_parm_pos;

typedef enum
{
   /* DTLS setup attribute rtpp_dtls.h*/
   RTPP_ATTR_XXX = RTPP_DTLS_ATTR_END
   
}rtpp_srtp_attr;

int is_optional_arg_present(char *arg);
int is_optional_arg_not_present(char *arg);
int  rtpp_parse_bridge_modifier(struct cfg *cfg, char *arg, int *isIpV6, char *networkId, char *ipAddr);
void rtpp_parse_ice_user(struct cfg *, char *, struct ice_user **, int remote);
void rtpp_parse_ice_remote_candidate(struct cfg *, char *, struct remote_ice_candidate **);
void rtpp_parse_srtp_cmd(struct cfg *cf, char* s_str, unsigned char*& key, unsigned char*& fp, uint32_t& ssrc, short int& suite,short int& attr);

#endif

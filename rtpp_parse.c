#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "rtpp_util.h"
#include "rtp.h"
#include "rtpp_log.h"
#include "rtpp_defines.h"
#include "rtpp_session.h"
#include "rtpp_dtls.h"
#include "rtpp_parse.h"

/* Functions to Parse rtpproxy commands */


/**
 * is_optional_arg_present - Checks if any of the following optional arg is present:
 *                                      payload, rcv, prcv, send, psend, trans, ip4/ip6
 *
 * @param arg (in)     - Argument
 *
 * @return 1 (if present), 0 (if not present)
 */
int is_optional_arg_present(char *arg)
{
    int ret_val = 0;

    if ( (strstr(arg, PAYLOAD_ARG_PREFIX) != NULL) ||
         (strstr(arg, RCV_ARG_PREFIX) != NULL) ||
         (strstr(arg, QOS_ARG_PREFIX) != NULL) ||
         (strstr(arg, TRANS_ARG_PREFIX) != NULL) ||
         (strstr(arg, SEND_ARG_PREFIX) != NULL) ||
         (strstr(arg, PRCV_ARG_PREFIX) != NULL) ||
         (strstr(arg, PSEND_ARG_PREFIX) != NULL) ||
         (strstr(arg, BRIDGE_ARG_IP4_PREFIX) != NULL) ||
         (strstr(arg, BRIDGE_ARG_IP6_PREFIX) != NULL) ||
         (strstr(arg, PTIME_ARG_PREFIX) != NULL) ||
         (strstr(arg, ICE_LOCAL_USER_PREFIX) != NULL) ||
         (strstr(arg, ICE_REMOTE_USER_PREFIX) != NULL) ||
         (strstr(arg, ICE_RTP_CANDIDATE_PREFIX) != NULL) ||
         (strstr(arg, ICE_RTCP_CANDIDATE_PREFIX) != NULL) )
    {
        ret_val = 1;
    }

    return ret_val;
}

/**
 * is_optional_arg_not_present - Checks if the following optional args are NOT present:
 *                                       payload, rcv, prcv, send, psend, trans, ip4/ip6
 *
 * @param arg (in)     - Argument
 *
 * @return 1 (not present), 0 (false)
 */
int is_optional_arg_not_present(char *arg)
{
    int ret_val = 0;

    if ( (strstr(arg, PAYLOAD_ARG_PREFIX) == NULL) &&
         (strstr(arg, QOS_ARG_PREFIX) == NULL) &&
         (strstr(arg, RCV_ARG_PREFIX) == NULL) &&
         (strstr(arg, TRANS_ARG_PREFIX) == NULL) &&
         (strstr(arg, SEND_ARG_PREFIX) == NULL) &&
         (strstr(arg, PRCV_ARG_PREFIX) == NULL) &&
         (strstr(arg, PSEND_ARG_PREFIX) == NULL) &&
         (strstr(arg, BRIDGE_ARG_IP4_PREFIX) == NULL) &&
         (strstr(arg, BRIDGE_ARG_IP6_PREFIX) == NULL) &&
         (strstr(arg, PTIME_ARG_PREFIX) == NULL) &&
         (strstr(arg, ICE_LOCAL_USER_PREFIX) == NULL) &&
         (strstr(arg, ICE_REMOTE_USER_PREFIX) == NULL) &&
         (strstr(arg, ICE_RTP_CANDIDATE_PREFIX) == NULL) &&
         (strstr(arg, ICE_RTCP_CANDIDATE_PREFIX) == NULL) )
    {
        ret_val = 1;
    }

    return ret_val;
}


/**
 * rtpp_parse_bridge_modifier - Handles the bridge modifier "B/b" in UPDATE and LOOKUP commands
 *                         Argument format: ip4/6:netId-ipAddr
 *
 * @param[in] cf      - Config
 * @param[in] arg     - Bridge modifier argument (from the command)
 *
 * @param[out] isIpV6 - 1 if IPV6
 * @param[out] netId  - Network Id (if name)
 * @param[out] ipAddr - IP address
 *
 * @return 0 (success), -1 (failure)
 *
 * Notes: Added for FRN4811
 */
int rtpp_parse_bridge_modifier(struct cfg *cf, char *arg, int *isIpV6, char *netId, char *ipAddr)
{
    if (arg == NULL)
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "Bridge modifier argument is NULL");
        return -1;
    }

    rtpp_log_write(RTPP_LOG_DBUG, cf->glog, "Bridge modifier argument = %s", arg);

    // Get IP ver (ip4 or ip6)
    char *pColon = strchr(arg, ':');
    if (pColon == NULL)
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "IP addr version not present");
        return -1;
    }

    char ipVer[4];
    strncpy(ipVer, arg, 3);
    ipVer[3] = '\0';

    if (strcasecmp(ipVer, IPV4_TYPE_IN_CMD) == 0)
    {
        *isIpV6 = 0;
    }
    else if (strcasecmp(ipVer, IPV6_TYPE_IN_CMD) == 0)
    {
        *isIpV6 = 1;
    }
    else
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "IP version (%s) invalid", ipVer);
        return -1;
    }

    // Get network id
    char *pHyphen = strchr(pColon, '-');
    if (pHyphen == NULL)
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "Network Id not present");
        return -1;
    }

    // Copy network id
    char *netIdStart = pColon + 1;  // Exclude :
    int len = pHyphen - netIdStart;

    if (len <= 0 || len > MAX_NETWORK_ID_LEN)
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "Invalid network Id length (%d)", len);
        return -1;
    }

    // Copy network id
    strncpy(netId, netIdStart, len);
    *(netId+len) = '\0';

    // Get IP address
    char *ipAddrStart = pHyphen + 1;     // Exclude -
    len = strlen(ipAddrStart);

    if (len <= 0 || len > MAX_IP_ADDR_LEN)
    {
        rtpp_log_write(RTPP_LOG_ERR, cf->glog, "IP address not present");
        return -1;
    }

    // Copy IP address
    strncpy(ipAddr, ipAddrStart, len);
    *(ipAddr+len) = '\0';

    rtpp_log_write(RTPP_LOG_DBUG, cf->glog, "Ver: %s, NetworkId: %s, IP address: %s", ipVer, netId, ipAddr);

    return 0;
}


// ICE support
void rtpp_parse_ice_user(struct cfg *cf, char *user_arg, struct ice_user **l_user, int remote)
{
    assert(user_arg != NULL);

    if ((*l_user) == NULL)
    {
        *l_user = (struct ice_user *)malloc(sizeof(struct ice_user));
    }

    char *pColon = strchr(user_arg, ':');
    char *pComma = strchr(user_arg, ',');

    if (remote == 0)
    { // local username and password


        (*l_user)->local_user_name = strdup(strtok(pColon+1, ","));
        (*l_user)->local_password = strdup(pComma+1);

        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "rtpp_parse_ice_user local username: %s, password: %s",
                       (*l_user)->local_user_name,
                       (*l_user)->local_password);

    }
    else if (remote == 1)
    { //common username and password for remote candidates

        (*l_user)->remote_user_name = strdup(strtok(pColon+1, ","));
        (*l_user)->remote_password = strdup(pComma+1);

        rtpp_log_write(RTPP_LOG_INFO, cf->glog, "rtpp_parse_ice_user remote username: %s, password: %s",
                       (*l_user)->remote_user_name,
                       (*l_user)->remote_password);

    }

}


void rtpp_parse_ice_remote_candidate(struct cfg *cf, char *candidate_arg, struct remote_ice_candidate **r_candidate)
{
    assert(candidate_arg != NULL);
    struct remote_ice_candidate *new_candidate = (struct remote_ice_candidate *)malloc(sizeof(struct remote_ice_candidate));

    char *pColon = strchr(candidate_arg, ':');

    new_candidate->addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    memset(new_candidate->addr, 0, sizeof(struct sockaddr_in));
    new_candidate->addr->sin_family = AF_INET;
    new_candidate->addr->sin_addr.s_addr = inet_addr(strtok(pColon+1, ","));

    new_candidate->port = atoi(strtok(NULL, ","));
    new_candidate->addr->sin_port = htons(new_candidate->port);

    new_candidate->priority = strtod(strtok(NULL, "\0"), NULL);

    new_candidate->prev = NULL;
    new_candidate->next = NULL;

    append_ice_candidate(cf, r_candidate, &new_candidate);

    rtpp_log_write(RTPP_LOG_INFO, cf->glog, "rtpp_parse_ice_remote_candidate addr: %s, port: %u, priority: %f ",
                   inet_ntoa(new_candidate->addr->sin_addr),
                   new_candidate->port,
                   new_candidate->priority);

}
//================================================================
//
// This function parses string value in srtp cmd , delimited by ","
// and fills values for key, ssrc and suite.
// input command string
// output ssrc and suite
//
//================================================================

void rtpp_parse_srtp_cmd(struct cfg *cf, char* s_str, unsigned char*& key, unsigned char*& fp, uint32_t& ssrc, short int& suite,short int& attr)
{
   int i = 1;
   char *temp;

    if (!s_str || !cf)
     return ;

    if (strlen(s_str) == 0)
     return ;

   char* token = rtpp_strsep(&s_str, ",");
   while (token != NULL)
   {
        switch (i)
      {
        case SRTP_KEY_PARAM_POS:
          key =(unsigned char*)(token);
          rtpp_log_write(RTPP_LOG_INFO, cf->glog,"01111 KEY %s\n", key);
          if (strncmp(FINGERPRINT_ARG_PREFIX, (char *)key, FINGERPRINT_ARG_PREFIX_LEN) == 0)
          {
             fp = key;
             fp += FINGERPRINT_ARG_PREFIX_LEN;
             key = NULL;
             rtpp_log_write(RTPP_LOG_INFO, cf->glog," FOund FInger Print %s\n", fp);
          }
          break;

        case SRTP_SSRC_PARAM_POS:
          ssrc = strtoul(token, 0, 0);
          break;
        case SRTP_SUITE_PARAM_POS:
          suite=atoi(token);
          break;
        case SRTP_ATTR_PARAM_POS:
          attr=atoi(token);
          break;
        default:
          break;
      }
      i++;
      token = rtpp_strsep(&s_str, ",");
   }
   return;

}


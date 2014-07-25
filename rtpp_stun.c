#include "rtpp_defines.h"
#include "rtpp_log.h"
#include "rtpp_record.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

//#define NO_LOG

#ifdef NO_LOG
   #define stun_log(level, handle, format, ...) ((level == RTPP_LOG_ERR)?rtpp_log_write(level, handle, format, __VA_ARGS__);
#else
   #define stun_log(level, handle, format, ...) rtpp_log_write(level, handle, format, __VA_ARGS__)
   #define stun_log_noarg(level, handle, format, ...) rtpp_log_write(level, handle, format)
#endif


int rtpp_stun_finish_msg(struct rtpp_session *sp, int method, uint8_t *key, size_t key_len,uint8_t *send_tid )
{
    rtpp_stun_agent *agent = sp->agent;
    int saved_id_idx = 0;
    for (saved_id_idx = RTPP_STUN_START_ID; saved_id_idx < RTPP_STUN_MAX_SAVED_IDS; saved_id_idx++)
    {
        if (agent->tids[saved_id_idx].valid == false)
        {
            break;
        }
    }
    if (saved_id_idx == RTPP_STUN_MAX_SAVED_IDS)
    {
        /* !! This means ids are full, the response are not recieved for the request send out network error */
        stun_log(RTPP_LOG_INFO, sp->log, "No space to store the ids, using the reserved idx :%d for tid:%s\n",RTPP_STUN_RESERVE_ID,send_tid);
        saved_id_idx = RTPP_STUN_RESERVE_ID;
        agent->max_reserve_tid_count++;
        if (agent->max_reserve_tid_count > RTPP_STUN_MAX_RESERVE_USED)
        {
            for (saved_id_idx = RTPP_STUN_RESERVE_ID; saved_id_idx < RTPP_STUN_MAX_SAVED_IDS; saved_id_idx++)
            {
                /* Reached Max No of Reserves Used, Don't expect any response*/
                agent->tids[saved_id_idx].method = (stun_method)0x0;
                agent->tids[saved_id_idx].valid = false;
                agent->tids[saved_id_idx].key = NULL;
                agent->tids[saved_id_idx].key_len= 0;
            }
            saved_id_idx = RTPP_STUN_START_ID;
        }
    }
    memcpy(agent->tids[saved_id_idx].id,send_tid,STUN_TID_SIZE);
    agent->tids[saved_id_idx].method = STUN_METHOD_BINDING;
    agent->tids[saved_id_idx].key = (uint8_t *) key;
    agent->tids[saved_id_idx].key_len = key_len;
    agent->tids[saved_id_idx].valid = true;
    return RTPP_STUN_STATUS_OK;

}
int rtpp_stun_msg_vailidate(rtpp_stun_agent *agent,struct rtpp_session *sp, stun_msg *msg, void *user_data)
{
    const uint8_t *msg_id = NULL;
    uint8_t *key = NULL;
    size_t key_len;
    struct stun_attr *errcode;
    int sent_id_idx;

    struct stun_attr *mi, *user;
    if (agent->compat == RTPP_STUN_COMPAT_RFC5389 && 
        !stun_msg_mcookie(msg))
    {
        stun_log_noarg(RTPP_LOG_INFO, sp->log, "STUN Msg Error no cookie!, discard\n");
        return RTPP_STUN_STATUS_BAD_REQUEST;
    }

    if (agent->compat == RTPP_STUN_COMPAT_RFC5389 &&
        agent->usage_flags & RTPP_STUN_FLAG_USE_FINGERPRINT)
    {
        /* Looks for FINGERPRINT */
        if (stun_msg_chk_fingerprint (msg))
        {
            stun_log_noarg(RTPP_LOG_INFO, sp->log, "STUN Msg Error no FINGERPRINT attribute!, discard");
            return RTPP_STUN_STATUS_BAD_REQUEST;
        }
    }

    if (stun_msg_class(msg) == STUN_CLASS_SUCCESS_RESP ||
        stun_msg_class(msg) == STUN_CLASS_ERROR_RESP)
    {
        if (agent->usage_flags & RTPP_STUN_FLAG_IGNORE_TID)
            return RTPP_STUN_STATUS_OK;

        stun_log_noarg(RTPP_LOG_INFO, sp->log, "STUN Msg Response \n");
        msg_id= stun_msg_tid(msg);
        if (!msg_id)
            return RTPP_STUN_STATUS_UNMATCHED_RESPONSE;
        stun_log(RTPP_LOG_INFO, sp->log, "STUN Msg Response tid:(%s)\n",msg_id);
        for (sent_id_idx = 0; sent_id_idx < RTPP_STUN_MAX_SAVED_IDS; sent_id_idx++)
        {
            if (agent->tids[sent_id_idx].valid == true &&
                agent->tids[sent_id_idx].method == stun_msg_method (msg) &&
                memcmp (msg_id, agent->tids[sent_id_idx].id,sizeof(agent->tids[sent_id_idx].id)) == 0)
            {
                key = agent->tids[sent_id_idx].key;
                key_len = agent->tids[sent_id_idx].key_len;
                /* Recieved the Response now reset it */
                stun_log_noarg(RTPP_LOG_INFO, sp->log, "Recieved the Response now Reset it \n");
                agent->tids[sent_id_idx].method = (stun_method)0;
                agent->tids[sent_id_idx].valid = false;
                agent->tids[sent_id_idx].key = NULL;
                agent->tids[sent_id_idx].key_len= 0;

                break;
            }
        }
        if (sent_id_idx == RTPP_STUN_MAX_SAVED_IDS)
        {
            stun_log_noarg(RTPP_LOG_INFO, sp->log, "Reached RTPP_STUN_MAX_SAVED_IDS");
            return RTPP_STUN_STATUS_UNMATCHED_RESPONSE;
        }
    }
    int ignore_credentials =
    (agent->usage_flags & RTPP_STUN_FLAG_IGNORE_CREDENTIALS) ||
    (stun_msg_class (msg) == STUN_CLASS_ERROR_RESP &&
     (errcode = stun_msg_attr(msg, STUN_ATTR_ERR_CODE)) != NULL &&
     (errcode->v.err_code.code == 400 || errcode->v.err_code.code == 401)) ||
    (stun_msg_class (msg) == STUN_CLASS_INDICATION &&
     (agent->usage_flags & RTPP_STUN_FLAG_NO_INDICATION_AUTH));



    if (key == NULL &&
        ignore_credentials == 0 &&
        (stun_msg_class (msg) == STUN_CLASS_REQUEST ||
         stun_msg_class (msg) == STUN_CLASS_INDICATION) &&
        (((agent->usage_flags & RTPP_STUN_FLAG_SHORT_TERM_CREDENTIALS) &&
          (!stun_msg_attr(msg, STUN_ATTR_USERNAME)||
           !stun_msg_attr(msg, STUN_ATTR_MSG_INTEGRITY))) ||
         ((agent->usage_flags & RTPP_STUN_FLAG_IGNORE_CREDENTIALS) == 0 &&
          !stun_msg_attr(msg, STUN_ATTR_USERNAME) &&
          !stun_msg_attr(msg, STUN_ATTR_MSG_INTEGRITY))))
    {
        stun_log_noarg(RTPP_LOG_INFO, sp->log, "Error RTPP_STUN_UNAUTHORIZED_BAD_REQUEST");
        return RTPP_STUN_STATUS_UNAUTHORIZED_BAD_REQUEST;
    }


    if (stun_msg_attr(msg, STUN_ATTR_MSG_INTEGRITY) &&
        ((key == NULL && ignore_credentials == 0) ||
         (agent->usage_flags & RTPP_STUN_FLAG_FORCE_VALIDATER)))
    {
        user  = stun_msg_attr(msg, STUN_ATTR_USERNAME);
        if (user == NULL)
        {
            stun_log_noarg(RTPP_LOG_INFO, sp->log, "Error key NULL and MI Present, RTPP_STUN_UNAUTHORIZED");
            return RTPP_STUN_STATUS_UNAUTHORIZED;
        }
    }

    if (ignore_credentials == 0 && key != NULL && key_len > 0)
    {
        mi = stun_msg_attr(msg, STUN_ATTR_MSG_INTEGRITY);
        if (mi)
        {
            user = stun_msg_attr(msg, STUN_ATTR_USERNAME);
            if (stun_msg_chk_mi(msg, (const uint8_t *)key, key_len))
            {
                stun_log(RTPP_LOG_ERR, sp->log,"UNAUTHORIZED: bad password for user '%s' \n", user->v.username);
                return RTPP_STUN_STATUS_UNAUTHORIZED;
            }
        }
    }
    return RTPP_STUN_STATUS_OK;
}

//int handle_stun_packet_ext(int fd, struct sockaddr_in *src, char *buf,int size)
int rtpp_stun_handle_msg(struct rtpp_session *sp, int ridx,  struct rtp_packet *packet)
{

    struct mbuf *mb;
    struct stun_unknown_attr ua;
    struct stun_attr *attr, *user;
    struct stun_msg *msg;
    int proto = IPPROTO_UDP;
    void  *us;
    struct sa sock_sa;
    int ret =0;
    int validation = 0;
    rtpp_stun_agent *agent=sp->agent;

    struct sockaddr *p_sockaddr = (struct sockaddr*)&(packet->raddr);
    uint32_t priority = 0;
    uint32_t tie_breaker;
    int controlling = 0;
    int local_len = 0;
    int remote_len = 0;
    int send_ice_check = 0;
    bool allow_rtp_packets = true;
    bool use_candidate = false;

    struct remote_ice_candidate *candidate = NULL;
    int attr_type=0;
    uint8_t send_tid[STUN_TID_SIZE];
    attr = user = NULL;
    if (!sp || !packet || !agent)
    {
        stun_log_noarg(RTPP_LOG_INFO, sp->log,"SP or Packet or Agent NULL\n");
        return RTPP_STUN_STATUS_MEM_FAIL;
    }
    us = udp_sock_init(sp->fds[ridx], AF_INET);
    if (us == NULL)
    {
        stun_log_noarg(RTPP_LOG_ERR, sp->log,"udp_sock_init Failed \n");
        return RTPP_STUN_STATUS_SOCK_FAIL;
    }
    stun_log(RTPP_LOG_INFO, sp->log,"Rcvd STUN Msg sp:%p from %s's address %s:%d (%s)\n", sp,
                   (ridx == 0) ? "callee" : "caller",
                    addr2char(sstosa(&packet->raddr)), ntohs(satosin(&packet->raddr)->sin_port),
                   (sp->rtp == NULL) ? "RTP" : "RTCP");
    mb = mbuf_alloc(0); /* default is 512 Bytes */
    if (!mb)
        return RTPP_STUN_STATUS_MEM_FAIL;
    /* If the packet size is greater than stun default size, mbuf_write_mem shall realloc with new size*/
    mbuf_write_mem(mb, (uint8_t *)packet->data.buf,packet->size);
    mb->pos = 0;

    sa_set_sa(&sock_sa,(const struct sockaddr *)&packet->raddr);
    if ((ret= stun_msg_decode(&msg, mb, &ua))!=0)
    {
        stun_log(RTPP_LOG_ERR, sp->log,"STUN Message Decode Error 0x%x\n", ret);
        ret = RTPP_STUN_STATUS_FAIL;
        goto msg_fail;
    }
    stun_log(RTPP_LOG_INFO, sp->log,"STUN %s %s\n",stun_class_name(stun_msg_class (msg)),stun_method_name(stun_msg_method(msg)));

    validation = rtpp_stun_msg_vailidate(agent, sp, msg,NULL);
    if (validation == RTPP_STUN_STATUS_UNKNOWN_REQUEST_ATTRIBUTE)
    {
        stun_log_noarg(RTPP_LOG_INFO, sp->log, "STUN request include unknown attribute, discard");
        goto msg_ignore;

    }
    else if ((validation != RTPP_STUN_STATUS_OK) || (stun_msg_class (msg) != STUN_CLASS_REQUEST))
        goto msg_ignore;
    /* Process the Request from here onwards */
    if (sp->ice_u[ridx]->local_user_name == NULL || sp->ice_u[ridx]->remote_user_name == NULL)
    {
        stun_log_noarg(RTPP_LOG_INFO, sp->log, "STUN request coming too early, ignore");
        goto msg_ignore;
    }
    local_len = (uint8_t)strlen(sp->ice_u[ridx]->local_user_name);
    remote_len = (uint8_t)strlen(sp->ice_u[ridx]->remote_user_name);

    char stored_username[local_len + remote_len + 1];

    stored_username[0] = '\0';
    strcat(stored_username, sp->ice_u[ridx]->local_user_name);
    strcat(stored_username, ":");
    strcat(stored_username, sp->ice_u[ridx]->remote_user_name);

    switch (stun_msg_method(msg))
    {
    
    case STUN_METHOD_BINDING:
        if ((user = stun_msg_attr(msg, STUN_ATTR_USERNAME)) == NULL)
        {
            stun_log_noarg(RTPP_LOG_INFO, sp->log, "Received STUN binding request with no username, ignore");
            goto msg_ignore;
        }

        if (stun_msg_attr(msg, STUN_ATTR_CONTROLLING))
        {
            controlling = 0;
            if (!stun_msg_attr(msg, STUN_ATTR_USE_CAND))
                allow_rtp_packets = false;
            else
            {
                use_candidate = true;
                if (sp->addr[ridx] == NULL)
                {
                    sp->addr[ridx] = (struct sockaddr *)malloc(packet->rlen);
                    if (sp->addr[ridx] == NULL)
                    {
                        stun_log_noarg(RTPP_LOG_ERR, sp->log,
                                       "STUN can't allocate memory for remote address - "
                                       "removing session");
                        ret = RTPP_STUN_STATUS_MEM_FAIL;
                        goto msg_fail;
                    }
                    bzero(sp->addr[ridx],packet->rlen);
                }
                stun_log(RTPP_LOG_INFO, sp->log,
                              "Check for %s's address : %s:%d (%s) addr[%d]:%s:%d",
                              (ridx == 0) ? "callee" : "caller",
                              addr2char(sstosa(&packet->raddr)), ntohs(satosin(&packet->raddr)->sin_port),
                              (sp->rtp == NULL) ? "RTP" : "RTCP",
                               ridx,addr2char(sp->addr[ridx]),addr2port(sp->addr[ridx]));

                if (use_candidate && (!ishostseq(sp->addr[ridx], sstosa(&packet->raddr)) || 
                                      (ishostseq(sp->addr[ridx], sstosa(&packet->raddr)) && (addr2port(sp->addr[ridx]) != addr2port(&packet->raddr)))))
                {
                    memcpy(sp->addr[ridx], &packet->raddr, packet->rlen);
                    stun_log(RTPP_LOG_INFO, sp->log,
                                   "STUN %s's address filled in: %s:%d (%s)",
                                   (ridx == 0) ? "callee" : "caller",
                                   addr2char(sstosa(&packet->raddr)), ntohs(satosin(&packet->raddr)->sin_port),
                                   (sp->rtp == NULL) ? "RTP" : "RTCP");
                }

            }
        }
        else if (stun_msg_attr(msg, STUN_ATTR_CONTROLLED))
        {
            controlling = 1;
        }
        if ((attr=stun_msg_attr(msg, STUN_ATTR_PRIORITY)))
        {
            priority = attr->v.uint32;
        }

        if (strncmp((const char*)user->v.username, stored_username, strlen(user->v.username)))
        {
            stun_log(RTPP_LOG_INFO, sp->log, "username does not match rtp session, discard stored-user=%s attr_user=%s\n",stored_username, user->v.username);
            goto msg_ignore;
        }
        if (stun_msg_chk_mi(msg, (const uint8_t *)sp->ice_u[ridx]->local_password, strlen(sp->ice_u[ridx]->local_password)))
        {
            stun_log(RTPP_LOG_INFO, sp->log,"auth: bad password for user '%s'\n", user->v.username);

        }
        (void)stun_reply(proto, us, &sock_sa, 0, msg, (const uint8_t *)sp->ice_u[ridx]->local_password,
                         strlen(sp->ice_u[ridx]->local_password), true, 2,
                         STUN_ATTR_XOR_MAPPED_ADDR, &packet->raddr,
                         STUN_ATTR_MAPPED_ADDR, &packet->raddr);
        send_ice_check = 1; 
        break;
    default:
        stun_log(RTPP_LOG_INFO, sp->log,"not supported 0x%04x\n", stun_msg_method(msg));
        goto msg_bad;
        break;
    }
    if (send_ice_check == 0)
    {
        goto msg_ignore;
    }


    candidate = find_ice_candidate(sp, ridx, p_sockaddr, SA_LEN(p_sockaddr));
    if (candidate != NULL)
    {
        stun_log(RTPP_LOG_INFO, sp->log, "Find candidate (ridx = %u). addr:%s port:%u priority:%f username:%s password:%s Sending ICE check", 
                       ridx, inet_ntoa(candidate->addr->sin_addr), candidate->port, candidate->priority, sp->ice_u[ridx]->remote_user_name, sp->ice_u[ridx]->remote_password);

        char send_username[local_len + remote_len];
        send_username[0] = '\0';
        strcat(send_username, sp->ice_u[ridx]->remote_user_name);
        strcat(send_username, ":");
        strcat(send_username, sp->ice_u[ridx]->local_user_name);
        tie_breaker = (uint32_t)random();
        mb->pos = 0;
        mb->end = 0;
        RAND_bytes (send_tid, STUN_TID_SIZE);
        if (controlling)
        {
            attr_type = STUN_ATTR_CONTROLLING;
            ret = stun_msg_encode(mb, STUN_METHOD_BINDING, STUN_CLASS_REQUEST,
                                  send_tid, NULL, 
                                  (uint8_t *)sp->ice_u[ridx]->remote_password, str_len(sp->ice_u[ridx]->remote_password),
                                  true, 0x00, 
                                  4,
                                  STUN_ATTR_USERNAME, send_username,
                                  STUN_ATTR_PRIORITY, &priority,
                                  attr_type, &tie_breaker,
                                  STUN_ATTR_USE_CAND, true);
        }
        else
        {
            attr_type =  STUN_ATTR_CONTROLLED;
            ret = stun_msg_encode(mb, STUN_METHOD_BINDING, STUN_CLASS_REQUEST,
                                  send_tid, NULL, 
                                  (uint8_t *)sp->ice_u[ridx]->remote_password, str_len(sp->ice_u[ridx]->remote_password),
                                  true, 0x00, 
                                  3,
                                  STUN_ATTR_USERNAME, send_username,
                                  STUN_ATTR_PRIORITY, &priority,
                                  attr_type, &tie_breaker);
        }


        if (ret)
        {
            stun_log(RTPP_LOG_ERR, sp->log,"stun_msg_encode Error (0x%x) mb->size:%d pos:%d end:%d\n", ret,mb->size,mb->pos,mb->end);
            goto msg_fail;
        }
        stun_log(RTPP_LOG_INFO, sp->log,"stun_msg_encode ret=0x%x mb->size:%d pos:%d end:%d\n", ret,mb->size,mb->pos,mb->end);
        mb->pos = 0;
        ret= udp_send((struct udp_sock *)us, &sock_sa,mb);
        if (ret)
        {
            stun_log(RTPP_LOG_ERR, sp->log,"udp_send Failed (0x%x) \n", ret);
            goto msg_fail;
        }
        if (!(agent->usage_flags & RTPP_STUN_FLAG_IGNORE_TID))
            rtpp_stun_finish_msg(sp, STUN_METHOD_BINDING, 
                                 (uint8_t*)sp->ice_u[ridx]->remote_password, 
                                 (size_t)strlen(sp->ice_u[ridx]->remote_password),send_tid);
        /* Start TLS as client when rtpproxy as Controlled Party.*/
        //rtpp_dtls_set_mode(sp,ridx,!controlling);
        if (allow_rtp_packets && sp->drop_rtp_packets == RTPP_STUN_DROP_RTP)
            sp->drop_rtp_packets = 0;

        if (use_candidate && sp->dtls_pending && sp->stream[ridx] != NULL)
        {
            stun_log(RTPP_LOG_ERR, sp->log,"STUN setting DTLS sp:%p idx:%d\n", sp, ridx);
            rtpp_dtls_setup_connection(sp, ridx);
        }
    }
    else
    {
        stun_log(RTPP_LOG_INFO, sp->log, "Can't find corresponding remote candidate (ridx = %u) . No ICE check will be performed.", ridx);
    }

    mem_deref(mb);
    return 0;
msg_bad:
    stun_ereply(proto, us, &sock_sa, 0, msg,
                400, "Bad Request",
                (uint8_t *)sp->ice_u[ridx]->local_password, strlen(sp->ice_u[ridx]->local_password), true, 1,
                STUN_ATTR_SOFTWARE, stun_software);
msg_fail:
msg_ignore:
    mem_deref(mb);
    return ret;

}

int rtpp_stun_agent_init(struct rtpp_session *sp)
{
    struct rtpp_session *spb;
    if (sp == NULL || sp->agent)
        return RTPP_STUN_STATUS_FAIL;

    spb = sp->rtcp;
    sp->agent = (rtpp_stun_agent *)malloc(sizeof(rtpp_stun_agent));
    if (sp->agent == NULL)
        return RTPP_STUN_STATUS_MEM_FAIL;

    spb->agent = sp->agent;

    stun_log(RTPP_LOG_INFO, sp->log, "Initalize stun agent for sp:0x%x\n",sp);
    bzero(sp->agent,sizeof(rtpp_stun_agent));
    sp->agent->compat = RTPP_STUN_COMPAT_RFC5389;
    sp->agent->usage_flags = RTPP_STUN_FLAG_USE_FINGERPRINT | RTPP_STUN_FLAG_IGNORE_TID;
    sp->agent->software_attr = NULL;

    return RTPP_STUN_STATUS_OK;
}
int rtpp_stun_agent_remove(struct rtpp_session *sp)
{

    if (!sp || sp->agent == NULL)
        return RTPP_STUN_STATUS_FAIL;
    free(sp->agent);
    sp->agent = NULL;
    return RTPP_STUN_STATUS_OK;
}

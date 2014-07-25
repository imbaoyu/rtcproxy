

#define SRTP_WRAPPER_LOCAL
#include <arpa/inet.h>
#include <srtp_wrapper.h>
#include <srtp.h>
#include <srtp_priv.h>

#include "rtp.h"

#define srtpw_log   err_report


char *srtpw_octet_string_hex_string(const void *str, int length) 
{
    return octet_string_hex_string(str,length);
}

//#define DEBUG

const char *srtpw_srtp_errstr(int err)
{
    switch (err)
    {
    case err_status_ok:
        return "nothing to report";
    case err_status_fail:
        return "unspecified failure";
    case err_status_bad_param:
        return "unsupported parameter";
    case err_status_alloc_fail:
        return "couldn't allocate memory";
    case err_status_dealloc_fail:
        return "couldn't deallocate properly";
    case err_status_init_fail:
        return "couldn't initialize";
    case err_status_terminus:
        return "can't process as much data as requested";
    case err_status_auth_fail:
        return "authentication failure";
    case err_status_cipher_fail:
        return "cipher failure";
    case err_status_replay_fail:
        return "replay check failed (bad index)";
    case err_status_replay_old:
        return "replay check failed (index too old)";
    case err_status_algo_fail:
        return "algorithm failed test routine";
    case err_status_no_such_op:
        return "unsupported operation";
    case err_status_no_ctx:
        return "no appropriate context found";
    case err_status_cant_check:
        return "unable to perform desired validation";
    case err_status_key_expired:
        return "can't use key any more";
    default:
        return "unknown";
    }
}

inline unsigned int char_to_index(unsigned char c)
{
    if (c >= '0' && c <= '9')return(c - '0');
    if (c >= 'A' && c <= 'F')return(c - 'A' + 10);
    if (c >= 'a' && c <= 'f')return(c - 'a' + 10);
    return 0;
}
unsigned char *
hex_to_bin(unsigned char *dest, size_t dest_len, const unsigned char *src, size_t src_len)
{
    static const unsigned char lnv[16] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    static const unsigned char unv[16] =
    {
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0
    };

    size_t max = src_len / 2;
    if (max > dest_len)max = dest_len;

    size_t sidx, didx;
    for (sidx = 0, didx = 0; didx < dest_len && sidx < src_len; ++didx, sidx += 2)
    {
        dest[didx] = unv[char_to_index(src[sidx])] + lnv[char_to_index(src[sidx+1])];
    }
    for (;didx < dest_len; ++didx)dest[didx] = '\0'; // Pad remainder with 0

    return dest;
}

static int g_init_done =0;
static srtpw_srtp_event_handler_func_t *srtpw_srtp_event_handler = NULL;

srtpw_err_status_t srtpw_get_ssrc_from_policy(void *p, uint32_t *ssrc)
{
    if (((srtp_policy_t *)p)->ssrc.type == ssrc_specific)
    {
        *ssrc = ((srtp_policy_t *)p)->ssrc.value;
        return srtpw_err_status_ok;
    }
    *ssrc = 0;
    return srtpw_err_status_fail;
}

srtpw_err_status_t srtpw_srtp_create_policy(void **srtp_policy )
{

    if (*srtp_policy == NULL)
    {

        *srtp_policy = calloc(1, sizeof(srtp_policy_t));
        if (*srtp_policy ==NULL)
            return srtpw_err_status_alloc_fail;
        srtpw_log(err_level_info, "srtpw_srtp_create_policy done <0x%x>\n",*srtp_policy);
    }

    return srtpw_err_status_ok;
}

srtpw_err_status_t srtpw_srtp_destroy_policy(void **p)
{
    srtp_policy_t *policy =(srtp_policy_t *)*p;
    if (policy && policy->key)
    {
        free(policy->key);
        policy->key = NULL;
    }
    srtpw_log(err_level_info, "srtpw_srtp_destroy_policy <0x%x>\n",policy);
    free(policy);
    *p = NULL;
    return srtpw_err_status_ok;
}

srtpw_err_status_t srtpw_srtp_install_event_handler(srtpw_srtp_event_handler_func_t func) 
{

    /* 
     * note that we accept NULL arguments intentionally - calling this
     * function with a NULL arguments removes an event handler that's
     * been previously installed
     */

    /* set global event handling function */
    srtpw_srtp_event_handler = func;
    return err_status_ok;
}
//srtpw_err_status_t srtpw_srtp_install_log_handler(void *p) 
srtpw_err_status_t srtpw_srtp_set_log_level(int level) 
{

    /* 
     * note that we accept NULL arguments intentionally - calling this
     * function with a NULL arguments removes an event handler that's
     * been previously installed
     */
    err_reporting_set_level(level);
    return err_status_ok;
}


void srtpw_srtp_event_cb(srtp_event_data_t *data)
{
    switch (data->event)
    {
    case event_ssrc_collision:
        srtpw_log(err_level_info, "SSRC collision\n");
        break;
    case event_key_soft_limit:
        srtpw_log(err_level_info, "event_key_soft_limit\n");
        break;
    case event_key_hard_limit:
        srtpw_log(err_level_info, "event_key_hard_limit\n");
        break;
    case event_packet_index_limit:
        srtpw_log(err_level_info, "event_packet_index_limit\n");
        break;
    }
    if (srtpw_srtp_event_handler)
        srtpw_srtp_event_handler(data->event);
}

srtpw_err_status_t srtpw_srtp_init()
{
    if (g_init_done)
    {
        return -1;
    }
    if (srtp_init() != err_status_ok)
    {
        return -1;
    }
    srtp_install_event_handler(srtpw_srtp_event_cb);
    srtpw_log(err_level_info, "srtpw_srtp_init from srtp_wrapper");
    g_init_done =1;
    return err_status_ok;
}


srtpw_err_status_t srtpw_srtp_create(srtpw_srtp **srtp, srtpw_srtp_policy *srtp_policy)
{
    int status=0;
    /*
     * create a session with a single stream using the default srtp
     * policy and with the SSRC value 0xcafebabe
     */
    srtp_policy_t *policy =(srtp_policy_t *)srtp_policy;
    srtpw_log(err_level_info, "srtpw_srtp_create:  policy:0x%x",policy);
#if 0

    crypto_policy_set_rtp_default(&policy->rtp);
    crypto_policy_set_rtcp_default(&policy->rtcp);
    policy->ssrc.type  = ssrc_specific;
    policy->ssrc.value = 0;
    policy->key  = NULL;
#endif
    policy->next = NULL;

    status = srtp_create((srtp_t *)srtp,policy);
    return status;
}

srtpw_err_status_t srtpw_srtp_destroy(srtpw_srtp *srtp)
{
    if ((srtp_t)srtp)
    {
        srtp_dealloc((srtp_t)srtp);
    }
    return srtpw_err_status_ok;
}

srtpw_err_status_t srtpw_srtp_unprotect(srtpw_srtp *srtp, void *buf, int *len, int rtcp)
{
    int res;

    if ((res = rtcp ? srtp_unprotect_rtcp((srtp_t)srtp, buf, len) : 
         srtp_unprotect((srtp_t)srtp, buf, len)) != err_status_ok && res != err_status_replay_fail)
    {
        srtpw_log(err_level_debug, "SRTP unprotect: failed :%d \n", res);
        return -1;
    }
    return *len;
}

srtpw_err_status_t srtpw_srtp_protect(srtpw_srtp_policy *p, srtpw_srtp *srtp, void *buf, int *len,int rtcp)
{
    int res;
#ifdef DEBUG
    srtpw_log(err_level_debug,"reference packet before protection:\n%s",          
                      octet_string_hex_string((uint8_t *)buf, *len));
#endif
    return (res = rtcp ? srtp_protect_rtcp((srtp_t)srtp, buf, len) : srtp_protect((srtp_t)srtp, buf, len));
   
}

srtpw_err_status_t srtpw_srtp_add_stream(srtpw_srtp *srtp, srtpw_srtp_policy *policy)
{
    return err_status_ok;

}

srtpw_err_status_t srtpw_srtp_change_source(srtpw_srtp *srtp, unsigned int from_ssrc, unsigned int to_ssrc)
{
    return err_status_ok;

}

static srtpw_err_status_t srtpw_policy_set_suite(crypto_policy_t *p, enum srtpw_srtp_suite suite)
{
    switch (suite)
    {
    case SRTPW_AES_CM_128_HMAC_SHA1_80:
        p->cipher_type = AES_128_ICM;
        p->cipher_key_len = 30;
        p->auth_type = HMAC_SHA1;
        p->auth_key_len = 20;
        p->auth_tag_len = 10;
        p->sec_serv = sec_serv_conf_and_auth;
        //p->sec_serv =sec_serv_conf;
        return 0;

    case SRTPW_AES_CM_128_HMAC_SHA1_32:
        p->cipher_type = AES_128_ICM;
        p->cipher_key_len = 30;
        p->auth_type = HMAC_SHA1;
        p->auth_key_len = 20;
        p->auth_tag_len = 4;
        p->sec_serv = sec_serv_conf_and_auth;
        return 0;

    default:
        return -1;
    }
}

srtpw_err_status_t srtpw_srtp_policy_set_suite(srtpw_srtp_policy *p, enum srtpw_srtp_suite suite)
{
    srtp_policy_t *policy =(srtp_policy_t *)p;
    return srtpw_policy_set_suite(&policy->rtp, suite) | srtpw_policy_set_suite(&policy->rtcp, suite);
}

srtpw_err_status_t srtpw_srtp_policy_set_master_key(srtpw_srtp_policy *p, const unsigned char *key, 
                                                    size_t key_len, const unsigned char *salt, size_t salt_len)
{
    size_t size = key_len + salt_len;
    unsigned char *master_key;
    srtp_policy_t *policy =(srtp_policy_t *)p;

    if(size > SRTP_MAX_KEY_LEN)
        return -1;

    if (policy->key)
    {
        free(policy->key);
        policy->key = NULL;
    }
   
    if (!(master_key = calloc(1, SRTP_MAX_KEY_LEN+1)))
    {
        return -1;
    }

    memcpy(master_key, key, key_len);
    memcpy(master_key + key_len, salt, salt_len);

    policy->key = master_key;

    return 0;
}

srtpw_err_status_t srtpw_srtp_policy_set_ssrc(srtpw_srtp_policy *p, unsigned long ssrc, int inbound)
{
    srtp_policy_t *policy =(srtp_policy_t *)p;
    if (ssrc)
    {
        policy->ssrc.type = ssrc_specific;
        policy->ssrc.value = ssrc;
    }
    else
    {

        policy->ssrc.type = inbound ? ssrc_any_inbound : ssrc_any_outbound;
    }
    return 0;
}

srtpw_err_status_t srtpw_set_crypto_policy(srtpw_srtp_policy *p, int suite, 
                                           const unsigned char *master_key, unsigned long ssrc, int inbound)
{
    srtp_policy_t *policy =(srtp_policy_t *)p;
    const unsigned char *master_salt = master_key + 2*SRTP_MASTERKEY_LEN;
    unsigned char buffer[2*SRTP_MASTERKEY_LEN+1];
    strncpy((char *)buffer, (const char *)master_key, 2*SRTP_MASTERKEY_LEN); buffer[2*SRTP_MASTERKEY_LEN] = '\0';
    srtpw_log(err_level_info, "srtpw_set_crypto_policy master_key:%s, master_salt:%s, %s ssrc:(0x%08x)%u\n",
              srtpw_octet_string_hex_string(buffer,2*SRTP_MASTERKEY_LEN),master_salt,(inbound?"Inbound":"Outbound"), ssrc, ssrc);
    // Convert Master key and SALT to binary format from HEX format before setting
    uint8_t mk[SRTP_MASTERKEY_LEN + 1], ms[SRTP_MASTERSALT_LEN + 1];
    hex_to_bin(mk, SRTP_MASTERKEY_LEN, master_key, 2*SRTP_MASTERKEY_LEN);mk[SRTP_MASTERKEY_LEN] = '\0';
    hex_to_bin(ms, SRTP_MASTERSALT_LEN, master_key + (2*SRTP_MASTERKEY_LEN), 2*SRTP_MASTERSALT_LEN); ms[SRTP_MASTERSALT_LEN] = '\0';
    if (srtpw_srtp_policy_set_master_key(policy, mk, SRTP_MASTERKEY_LEN, ms, SRTP_MASTERSALT_LEN) < 0)
    {
        return -1;
    }

    if (srtpw_srtp_policy_set_suite(policy, suite))
    {
        return -1;
    }

    srtpw_srtp_policy_set_ssrc(policy, ssrc, inbound);

    return 0;
}

srtpw_err_status_t srtpw_validate_key(unsigned char *input_key)
{
    char key[SRTP_MAX_KEY_LEN];
    int len;

    /*
     * read key from hexadecimal  into an octet string
     */
    len = hex_string_to_octet_string((char *)key, (char *)input_key, SRTP_MASTER_KEY_LEN*2);

    /* check that hex string is the right length */
    if (len < SRTP_MASTER_KEY_LEN*2)
    {
        srtpw_log(err_level_error,
                  "error: too few digits in key/salt "
                  "(should be %d hexadecimal digits, found %d)\n",
                  SRTP_MASTER_KEY_LEN*2, len);
        return srtpw_err_status_bad_param;
    }
    if (strlen((const char *)input_key) > SRTP_MASTER_KEY_LEN*2)
    {
        srtpw_log(err_level_error,
                  "error: too many digits in key/salt "
                  "(should be %d hexadecimal digits, found %u)\n",
                  SRTP_MASTER_KEY_LEN*2, (unsigned)strlen((const char *)input_key));
        return srtpw_err_status_bad_param;
    }

    srtpw_log(err_level_info,"set master key/salt to %s/", octet_string_hex_string(key, SRTP_MASTERKEY_LEN));
    srtpw_log(err_level_info,"%s\n", octet_string_hex_string(key+SRTP_MASTERKEY_LEN, SRTP_MASTERSALT_LEN));
    return srtpw_err_status_ok;

}

srtpw_err_status_t srtpw_session_print_policy(srtpw_srtp *psrtp) 
{
    char *serv_descr[4] = {
        "none",
        "confidentiality",
        "authentication",
        "confidentiality and authentication"
    };
    char *direction[3] = {
        "unknown",
        "outbound",
        "inbound"
    };
    srtp_t srtp =(srtp_t) psrtp;
    srtp_stream_t stream;

    /* sanity checking */
    if (srtp == NULL)
        return err_status_fail;

    /* if there's a template stream, print it out */
    if (srtp->stream_template != NULL)
    {
        stream = srtp->stream_template;
        srtpw_log(err_level_info,"# SSRC:          any %s\r\n"
                  "# rtp cipher:    %s\r\n"
                  "# rtp auth:      %s\r\n"
                  "# rtp services:  %s\r\n" 
                  "# rtcp cipher:   %s\r\n"
                  "# rtcp auth:     %s\r\n"
                  "# rtcp services: %s\r\n",
                  direction[stream->direction],
                  stream->rtp_cipher->type->description,
                  stream->rtp_auth->type->description,
                  serv_descr[stream->rtp_services],
                  stream->rtcp_cipher->type->description,
                  stream->rtcp_auth->type->description,
                  serv_descr[stream->rtcp_services]);
    }

    /* loop over streams in session, printing the policy of each */
    stream = srtp->stream_list;
    while (stream != NULL)
    {
        if (stream->rtp_services > sec_serv_conf_and_auth)
            return err_status_bad_param;

        srtpw_log(err_level_info,"# SSRC:          0x%08x\r\n"
                  "# rtp cipher:    %s\r\n"
                  "# rtp auth:      %s\r\n"
                  "# rtp services:  %s\r\n" 
                  "# rtcp cipher:   %s\r\n"
                  "# rtcp auth:     %s\r\n"
                  "# rtcp services: %s\r\n",
                  stream->ssrc,
                  stream->rtp_cipher->type->description,
                  stream->rtp_auth->type->description,
                  serv_descr[stream->rtp_services],
                  stream->rtcp_cipher->type->description,
                  stream->rtcp_auth->type->description,
                  serv_descr[stream->rtcp_services]);

        /* advance to next stream in the list */
        stream = stream->next;
    } 
    return err_status_ok;
}
unsigned short srtpw_get_local_seq_num(srtpw_srtp *psrtp, unsigned long ssrc)
{
    return srtp_get_local_seq_num((srtp_t)psrtp,ssrc);
}


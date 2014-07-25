#include <err.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "rtpp_defines.h"
#include "rtpp_srtp.h"
#include "rtpp_dtls.h"
#include "rtpp_util.h"
#include "rtpp_session.h"
#include "rtpp_command.h"

#define DEBUG_DTLS
//#define DEBUG_DTLS_SETUP
//#define NO_LOG

#ifdef NO_LOG
    #define dtls_log(level, handle, format, ...)
#else
    #define dtls_log(level, handle, format, ...) rtpp_log_write(level, handle, format, __VA_ARGS__)
#endif

extern          rtpp_log_t glog;
const char    * default_srtp_profile = "SRTP_AES128_CM_SHA1_80";
const char    * dtls_srtp_export_label = "EXTRACTOR-dtls_srtp";

/* Global Variable stre the DTLS context */
dtls_context    dtls_ctx;

struct srtp_cipher_map_entry srtp_cipher_map[] = {
    {1, "SRTP_AES128_CM_SHA1_80"},
    {2, "SRTP_AES128_CM_SHA1_32"},
    {0, NULL}
};

/* id callback */
unsigned long id_f()
{
    return getpid();
}
const char *dtls_state_str(int state)
{
    switch (state)
    {
    case DTLS_STATE_NONE:
        return "DTLS_STATE_NONE";
    case DTLS_STATE_INIT_FAILED:
        return "DTLS_STATE_INIT_FAILED";
    case DTLS_STATE_INIT_DONE:
        return "DTLS_STATE_INIT_DONE";
    case DTLS_STATE_ACCEPTING:
        return "DTLS_STATE_ACCEPTING";
    case DTLS_STATE_CONNECTING:
        return "DTLS_STATE_CONNECTING";
    case DTLS_STATE_ESTABLISHED:
        return "DTLS_STATE_ESTABLISHED";
    case DTLS_STATE_CLOSED:
        return "DTLS_STATE_CLOSED";
    }
    return "NONE";
}

const char *dtls_attr_str(int attr)
{
    switch (attr)
    {
    case RTPP_DTLS_ATTR_NONE:
        return "DTLS_ATTR_NONE";
    case RTPP_DTLS_ATTR_SETUP_ACTIVE:
        return "RTPP_DTLS_ATTR_SETUP_ACTIVE";
    case RTPP_DTLS_ATTR_SETUP_PASSIVE:
        return "RTPP_DTLS_ATTR_SETUP_PASSIVE";
    case RTPP_DTLS_ATTR_SETUP_ACTPASS:
        return "RTPP_DTLS_ATTR_SETUP_ACTPASS";
    case RTPP_DTLS_ATTR_SETUP_HOLDCONN:
        return "RTPP_DTLS_ATTR_SETUP_HOLDCONN";
    }
    return "NONE";
}
void dtls_report_error(SSL* ssl, int result)
{
    if (result <= 0)
    {
        int error = SSL_get_error(ssl, result);

        switch (error)
        {
        case SSL_ERROR_ZERO_RETURN:
            rtpp_log_write(RTPP_LOG_INFO, glog,"SSL_ERROR_ZERO_RETURN" );
            break;
        case SSL_ERROR_NONE:
            rtpp_log_write(RTPP_LOG_INFO, glog,"SSL_ERROR_NONE" );
            break;
        case SSL_ERROR_WANT_READ:
            rtpp_log_write(RTPP_LOG_INFO, glog,"SSL_ERROR_WANT_READ" );
            break;
        default:
            rtpp_log_write(RTPP_LOG_INFO, glog,"Error: %d", error );
            break;
        }
    }
}
bool dtls_verify_digest(rtpp_stream* st, const X509 *cert) 
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digest_length;
    if (compute_digest(cert, st->remote_fp_algorithm, 
                       digest, sizeof(digest), &digest_length))
    {


#ifdef DEBUG_DTLS
        char *fp   = NULL;
        fp_to_hex(digest,digest_length,&fp);
        rtpp_log_write(RTPP_LOG_INFO, glog,"fingerprint recvd [%s] \n", fp);
        free(fp);
        fp = NULL;
        fp_to_hex((const unsigned char *)st->remote_fp_value,st->remote_fp_len,&fp);
        rtpp_log_write(RTPP_LOG_INFO, glog,"fingerprint from the command [%s] \n", fp);
        free(fp);
        rtpp_log_write(RTPP_LOG_INFO, glog,"fingerprint digest_len:%d remote cmd len:%d \n",
                       digest_length, st->remote_fp_len );
#endif
        if (strncmp((const char *)digest, (const char *)st->remote_fp_value, 
                    min(digest_length,st->remote_fp_len)) != 0)
        {
            rtpp_log_write(RTPP_LOG_INFO, glog,"fingerprint verification failed st:%p fd:%d ssl:%\n",st, st->fd, st->ssl);
            return false;
        }
        return true;

    }
    rtpp_log_write(RTPP_LOG_INFO, glog,"fingerprint verification compute_digest failed st:%p fd:%d ssl:%\n",st, st->fd, st->ssl);
    return false;
}

/* Call Backs */
int dtls_verify_cb(int ok, X509_STORE_CTX* store) {

    SSL *ssl = (SSL*)X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
    rtpp_stream *st = (rtpp_stream*)SSL_get_app_data(ssl);
    int depth = X509_STORE_CTX_get_error_depth(store);
    X509* cert = X509_STORE_CTX_get_current_cert(store);
    int override = 1;
    char buf[512];
    int err = X509_STORE_CTX_get_error(store);

    bzero(buf, 512);
    X509_NAME_oneline(X509_get_subject_name(cert),buf,sizeof(buf));
    rtpp_log_write(RTPP_LOG_INFO, glog, "depth[%d] subject = %s\n", depth, buf);
    bzero(buf, 512);
    X509_NAME_oneline(X509_get_issuer_name(cert),buf,sizeof(buf));
    rtpp_log_write(RTPP_LOG_INFO, glog, "depth[%d] issuer = %s\n", depth, buf);
    rtpp_log_write(RTPP_LOG_INFO, glog, "verify error:ok=%d num=%d:%s\n", ok,err, X509_verify_cert_error_string(err));  
    rtpp_log_write(RTPP_LOG_INFO, glog, "depth:%d, error code is %d\n", depth,store->error);

    switch (err)
    {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        rtpp_log_write(RTPP_LOG_INFO, glog, "issuer= %s\n",buf);
        break;

    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_CERT_NOT_YET_VALID:
        rtpp_log_write(RTPP_LOG_INFO, glog, "notBefore\n");
        break;

    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_CERT_HAS_EXPIRED:
        rtpp_log_write(RTPP_LOG_INFO, glog, "notAfter\n");
        break;

    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
        rtpp_log_write(RTPP_LOG_INFO, glog, "unable to decrypt cert signature\n");
        break;

    case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
        rtpp_log_write(RTPP_LOG_INFO, glog, "Critical Extension\n");
        break;
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
        rtpp_log_write(RTPP_LOG_INFO, glog, "unable to decode issuer public key\n");
        break;

    case X509_V_ERR_OUT_OF_MEM:
        rtpp_log_write(RTPP_LOG_ERR, glog, "Out of memory \n");
        break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
         if (st->remote_fp_algorithm && st->remote_fp_value)
         { 
            ok = 1;
            rtpp_log_write(RTPP_LOG_INFO, glog,"{%d}fingerprint verification st:%p fd:%d ssl:%p\n",depth, st, st->fd, ssl);
            if(!dtls_verify_digest(st,cert))
            {
                //override = 0;/* should be Zero*/
                ok = 0;
            }
                
        }
        rtpp_log_write(RTPP_LOG_INFO, glog, "Self signed certificate issue\n");
        break;
    case X509_V_ERR_CERT_REVOKED:
        rtpp_log_write(RTPP_LOG_INFO, glog, "certitifcate revoked\n");
        break;
    case X509_V_ERR_INVALID_CA:
        rtpp_log_write(RTPP_LOG_INFO, glog, "invalid CA\n");
        break;
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        rtpp_log_write(RTPP_LOG_INFO, glog, "path length exceeded\n");
        break;
    case X509_V_ERR_INVALID_PURPOSE:
        rtpp_log_write(RTPP_LOG_INFO, glog, "invalid purpose\n");
        break;
    case X509_V_ERR_CERT_UNTRUSTED:
    case X509_V_ERR_CERT_REJECTED:
        rtpp_log_write(RTPP_LOG_INFO, glog, "certificate untrusted/rejected\n");
        break;
    default:
        rtpp_log_write(RTPP_LOG_INFO, glog, "default: error code is %d (check x509_vfy.h)\n", store->error);
        break;
    }
    if (!ok)
    {
        if (override)
        {
            rtpp_log_write(RTPP_LOG_INFO, glog, "something wrong with the cert[%d]!!! error code:%d (x509_vfy.h) Ignoring for Now\n",depth, store->error);
            ok=1;
        }
        else
            rtpp_log_write(RTPP_LOG_INFO, glog, "verify error:num=%d:%s depth:%d\n", err, X509_verify_cert_error_string(err),depth);  
    }
    rtpp_log_write(RTPP_LOG_INFO, glog, "verify return:%d\n", ok);
    return ok;
}


int dtls_generate_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    struct sockaddr *peer;

    rtpp_stream *st = (rtpp_stream*)SSL_get_app_data(ssl);

    rtpp_log_write(RTPP_LOG_INFO, glog," st:%p ssl:%p fd:%d\n",st,ssl,st->fd);
    peer = *(st->addr);

    /* Initialize a random secret */
    if (!st->cookie_initialized)
    {
        if (!RAND_bytes(st->cookie_secret, COOKIE_SECRET_LENGTH))
        {
            rtpp_log_write(RTPP_LOG_INFO, glog,"error setting random cookie secret\n");
            return 0;
        }
        st->cookie_initialized = 1;
    }
    rtpp_log_write(RTPP_LOG_INFO, glog,"peer addr:%s :%d\n", 
                   addr2char(sstosa(peer)), addr2port(sstosa(peer)));
    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer->sa_family)
    {
    case AF_INET:
        length += sizeof(struct in_addr);
        break;
    case AF_INET6:
        length += sizeof(struct in6_addr);
        break;
    default:
        OPENSSL_assert(0);
        break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog,"out of memory\n");
        return 0;
    }

    switch (peer->sa_family)
    {
    case AF_INET:
        memcpy(buffer,
               &satosin(peer)->sin_port,
               sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t),
               &satosin(peer)->sin_addr,
               sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(buffer,
               &satosin6(peer)->sin6_port,
               sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t),
               &satosin6(peer)->sin6_addr,
               sizeof(struct in6_addr));
        break;
    default:
        OPENSSL_assert(0);
        break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) st->cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char*) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

int dtls_verify_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    struct sockaddr *peer;
    rtpp_stream *st = (rtpp_stream*)SSL_get_app_data(ssl);

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!st->cookie_initialized)
        return 0;

    rtpp_log_write(RTPP_LOG_INFO, glog," st:%p ssl:%p fd:%d\n",st,ssl,st->fd);
    if (*(st->addr) == NULL)
        return 0;
    peer = *(st->addr);

    rtpp_log_write(RTPP_LOG_INFO, glog," peer addr:%s :%d\n", 
                   addr2char(sstosa(peer)), addr2port(sstosa(peer)));
    //memcpy(&peer,*(st->addr),sizeof(peer));
    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer->sa_family)
    {
    case AF_INET:
        length += sizeof(struct in_addr);
        break;
    case AF_INET6:
        length += sizeof(struct in6_addr);
        break;
    default:
        OPENSSL_assert(0);
        break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog,"out of memory\n");
        return 0;
    }

    switch (peer->sa_family)
    {
    case AF_INET:
        memcpy(buffer,
               &satosin(peer)->sin_port,
               sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t),
               &satosin(peer)->sin_addr,
               sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(buffer,
               &satosin6(peer)->sin6_port,
               sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t),
               &satosin6(peer)->sin6_addr,
               sizeof(struct in6_addr));
        break;
    default:
        OPENSSL_assert(0);
        break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) st->cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char*) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog,"Verified Cookie\n");
        return 1;
    }
    rtpp_log_write(RTPP_LOG_INFO, glog,"Verify Cookie Failed\n");
    return 0;
}

/* End Call Backs */

bool dtls_get_srtp_cipher(rtpp_stream *st, int16_t *suite) {

    SRTP_PROTECTION_PROFILE *srtp_profile = SSL_get_selected_srtp_profile(st->ssl);
    if (!srtp_profile)
        return false;
    rtpp_log_write(RTPP_LOG_INFO, glog, "get suite %s\n",srtp_profile->name);
    for (srtp_cipher_map_entry *entry = srtp_cipher_map; entry->srtp_profile_name; ++entry)
    {
        if (!strcmp(entry->srtp_profile_name, srtp_profile->name))
        {
            *suite = entry->suite;
            rtpp_log_write(RTPP_LOG_INFO, glog, "get suite: %d\n",*suite);
            return true;
        }
    }
    return false;
}

int dtls_setup_srtp_session_keys(rtpp_stream *st)
{
    //TODO: probably an exception candidate

    unsigned char material[SRTP_MASTER_KEY_LEN << 1];
    size_t offset, s_offset, c_offset;
    int ret = 0;
    int16_t suite = 0;
    rtpp_session *sp = NULL;

    if (!dtls_get_srtp_cipher(st,&st->suite))
        rtpp_log_write(RTPP_LOG_INFO, glog," Failed to get the suite\n", sp,st->idx,suite);
    suite = st->suite;
#if 0
    srtp_profile_t profile = st->suite;
    int key_len = srtp_profile_get_master_key_length(profile);
    int salt_len = srtp_profile_get_master_salt_length(profile);
#endif
    if (!SSL_export_keying_material(
                                   st->ssl,
                                   material,
                                   sizeof(material),
                                   "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0))
    {
        rtpp_log_write(RTPP_LOG_INFO, glog," SRTP KEY Export Failed st:%p\n", st);
        return 0;
    }
    offset = s_offset = c_offset = 0;

    bzero(st->snd_key,SRTP_MAX_KEY_LEN);
    bzero(st->rcv_key,SRTP_MAX_KEY_LEN);
    offset = 0;
    memcpy(&st->snd_key[c_offset], &material[offset], SRTP_MASTER_KEY_KEY_LEN);
    offset += SRTP_MASTER_KEY_KEY_LEN;
    c_offset += SRTP_MASTER_KEY_KEY_LEN;

    memcpy(&st->rcv_key[s_offset], &material[offset], SRTP_MASTER_KEY_KEY_LEN);
    offset += SRTP_MASTER_KEY_KEY_LEN;
    s_offset += SRTP_MASTER_KEY_KEY_LEN;

    memcpy(&st->snd_key[c_offset], &material[offset], SRTP_MASTER_KEY_SALT_LEN);

    offset += SRTP_MASTER_KEY_SALT_LEN;
    c_offset += SRTP_MASTER_KEY_SALT_LEN;

    memcpy(&st->rcv_key[s_offset], &material[offset], SRTP_MASTER_KEY_SALT_LEN);
    offset += SRTP_MASTER_KEY_SALT_LEN;
    s_offset += SRTP_MASTER_KEY_SALT_LEN;

    rtpp_log_write(RTPP_LOG_INFO, glog," offset:%d c_offset:%d client key:%s\n",
                   offset,c_offset,srtpw_octet_string_hex_string(st->snd_key,SRTP_MASTER_KEY_LEN));
    rtpp_log_write(RTPP_LOG_INFO, glog," offset:%d s_offset:%d server key:%s\n",
                   offset,s_offset,srtpw_octet_string_hex_string(st->rcv_key,SRTP_MASTER_KEY_LEN));

    sp = (rtpp_session *)st->sp;

    if (!sp)
        return 0;
    strcpy((char *)st->snd_key,srtpw_octet_string_hex_string(st->snd_key,SRTP_MASTER_KEY_LEN));
    strcpy((char *)st->rcv_key,srtpw_octet_string_hex_string(st->rcv_key,SRTP_MASTER_KEY_LEN));

    rtpp_log_write(RTPP_LOG_INFO, glog," Creating srtp context sp:%p idx:%d suite:%d\n", sp,st->idx,suite);
    rtpp_log_write(RTPP_LOG_INFO, glog," Creating srtp context snd_key:%s rcv_key:%s\n",st->snd_key, st->rcv_key);
    if (rtpp_srtp_validate_key(st->rcv_key) || rtpp_srtp_validate_key(st->snd_key))
    {
        rtpp_log_write(RTPP_LOG_INFO, glog,"SRTP hex Key Validation Failed\n");
    }
    ret  = rtpp_srtp_create_context(sp, st->idx, st->snd_key, suite, st->snd_ssrc, st->fix_srtp_seq, 1);                 
    ret &= rtpp_srtp_create_context(sp, st->idx, st->rcv_key, suite, st->rcv_ssrc, st->fix_srtp_seq, 0);    
    if (!ret)
        return 0;
    sp->dtls_pending = false;
    sp->secure = 1;

    return 1;   
}

int dtls_setup_srtp_keys(rtpp_stream *st)
{
    dtls_setup_srtp_session_keys(st);
    return 0;

}
void dtls_init_stream(rtpp_stream *st, int fd, struct sockaddr **addr) 
{

    memset(st, 0, sizeof(rtpp_stream));
    st->fd = fd;
    st->addr = addr;

    st->state = DTLS_STATE_NONE;
    st->event = 0;
}

void rtpp_dtls_free_stream(rtpp_stream* st) 
{

    if (st->remote_fp_value != NULL)
    {
        free(st->remote_fp_value);
    }
    if (st->local_fp_value != NULL)
    {
        free(st->local_fp_value);
    }

    if (st->ssl != NULL)
    {
        SSL_free(st->ssl);
    }
    st->state = DTLS_STATE_CLOSED;
    st->ssl = NULL;
    st->ctx = NULL;
    /* Local Identity is stored in config so don't delete it*/
    st->local_identity = NULL;
    st->local_fp_value = NULL;
    st->remote_fp_value = NULL;
}

bool dtls_set_fingerprint(rtpp_stream *st, int digest_algo,
                     unsigned char *digest, size_t digest_len, bool local) 
{
    char *fp = NULL;
    char fp_len =0;
    //rtpp_log_write(RTPP_LOG_INFO, glog,"0 %s_fingerprint:%s fp_len:%d len:%d\n",local?"L":"R",digest, fp_len,(digest_len+1)/3);
    if (!digest_algo || digest == NULL || !digest_len )
        return false;
    //sp->stream[kidx]->local_fp_value = strdup((const char *)local_fp);
    fp_len= hex_to_fp(digest, digest_len, &fp);
    //sp->stream[kidx]->state = DTLS_STATE_OFFERED;
    rtpp_log_write(RTPP_LOG_INFO, glog,"00 %s_fingerprint:%s fp_len:%d len:%d\n",local?"L":"R",digest, fp_len,(digest_len+1)/3);

    if (fp == NULL)
        return false;
    if (local)
    {
        RTPP_DTLS_FREE(st->local_fp_value);
        st->local_fp_value = fp;
        st->local_fp_len   = fp_len;
        st->local_fp_algorithm = digest_algo;
    }
    else
    {
        //TODO: compare the previous value of 
        //  remote finger print to start DTLS nego again.
        RTPP_DTLS_FREE(st->remote_fp_value);
        st->remote_fp_value = fp;
        st->remote_fp_len   = fp_len;
        st->remote_fp_algorithm = digest_algo;
    }

    //st->state = DTLS_STATE_ACCEPTED;
    return 0;

}
#define dtls_set_remote_fingerprint(st,algo,digest,digest_len) dtls_set_fingerprint(st,algo,digest,digest_len, 0)
#define dtls_set_local_fingerprint(st,algo,digest,digest_len)  dtls_set_fingerprint(st,algo,digest,digest_len, 1)


SSL_CTX *get_dtls_context(dtls_context *dtls_ctx, rtpp_stream *st) {

    SSL_CTX *ctx = NULL;
    if (st->snd_attr == RTPP_DTLS_ATTR_SETUP_ACTIVE)
    {// TODO:: method version check DTLSV1.0 or DTLSV1.2
        ctx = dtls_ctx->client_ctx;
        // TODO ? set to expect our own certificate from peer
    }
    else
    {
        ctx = dtls_ctx->server_ctx;
    }
    if (ctx == NULL)
        return NULL;

    return ctx;
}

int dtls_init_ssl_parameters(rtpp_stream *st)
{
    BIO     *bio_rd, *bio_wr;
    SSL_CTX *ctx =NULL;
    SSL     *ssl = NULL;
    int      verify;

    bio_rd = bio_wr = NULL;

    if (!st || !st->ctx)
        return -1;
    ctx = st->ctx;

    ssl = SSL_new(ctx);
    if (!ssl)
        return -1;
    rtpp_log_write(RTPP_LOG_INFO, glog,"0 st:%p fd:%d ssl:%p init_ssl_parameters \n",st, st->fd, ssl);

    /* set up the memory-buffer BIOs */
    bio_rd = BIO_new(BIO_s_mem());
    if (!bio_rd)
        return -1;
    bio_wr = BIO_new(BIO_s_mem());
    if (!bio_wr)
        return -1;
    BIO_set_nbio(bio_rd,1);
    BIO_set_nbio(bio_wr,1);
    BIO_set_mem_eof_return(bio_rd, -1);
    BIO_set_mem_eof_return(bio_wr, -1);
    /* bind them together */
    SSL_set_bio(ssl, bio_rd, bio_wr);
    /* if on the client: SSL_set_connect_state(con); */

    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
    //SSL_set_mode(st->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    //SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    //SSL_set_mtu(ssl, 1472);
    // 
    //dtls_cfg.dtls_rekey;
    verify = dtls_ctx.verify?(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT):SSL_VERIFY_NONE;
    SSL_set_verify(ssl, verify, NULL);
    // SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    //SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    st->suite = dtls_ctx.srtp_suite;
    rtpp_log_write(RTPP_LOG_INFO, glog,"verify:%d suite:%d rekey:%d\n",verify, st->suite,dtls_ctx.dtls_rekey);

    if (st->snd_attr == RTPP_DTLS_ATTR_SETUP_ACTIVE)
    {
        SSL_set_connect_state(ssl);
    }
    else
    {
        SSL_set_accept_state(ssl);
    }
    st->ssl = ssl;
    /* store stream stucture in the SSL context */
    SSL_set_app_data(ssl, st);
    return 0;
}

int dtls_init(rtpp_stream *st)
{
    int rc= 0;
    if (st->state == DTLS_STATE_CLOSED)
        goto init_done;
    if (st->state != DTLS_STATE_NONE )
        return 1;
    if (dtls_ctx.init_failed)
    {
        st->init_failed = true;
        st->state = DTLS_STATE_INIT_FAILED;
        rtpp_log_write(RTPP_LOG_INFO, glog,"dtls context Init failed,so returning st:%p\n",st);
        return 0;
    }
    rtpp_log_write(RTPP_LOG_INFO, glog,"Init dtls context for st:%p\n",st);

    st->ctx = get_dtls_context(&dtls_ctx,st);
    if (!st->ctx)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog,"get_dtls_context failed\n");
        st->init_failed = true;
        st->state = DTLS_STATE_INIT_FAILED;
        return 0;
    }
    rc = dtls_init_ssl_parameters(st);
    if (rc)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog,"dtls_init_ssl_parameters failed\n");
        st->init_failed = true;
        st->state = DTLS_STATE_INIT_FAILED;
        return 0;
    }
    init_done:
    st->state = DTLS_STATE_INIT_DONE;
    st->init_failed = false;
    st->client_hello_retran_cnt = 0;
    rtpp_log_write(RTPP_LOG_INFO, glog,"Init dtls stream for st:%p\n",st);
    return 1;
}


int dtls_start_client_handshake(rtpp_stream *st)
{
    int   r   = 0;
    int   err = 0;
    SSL * ssl = NULL;

    if (!st || !st->ssl)
        return 0;

    ssl = st->ssl;
    rtpp_log_write(RTPP_LOG_INFO, glog," Start Client Handshake\n");
    r=SSL_do_handshake(ssl);
    st->state = DTLS_STATE_CONNECTING;
    st->client_hello_retran_cnt++;
    // Now handle handshake errors */
    switch (err=SSL_get_error(ssl,r))
    {
    case SSL_ERROR_NONE:

        rtpp_log_write(RTPP_LOG_INFO, glog,"Start Handshake Done\n");
        break;
    case SSL_ERROR_WANT_READ:
        // There are two cases here:
        // (1) We didn't get enough data. In this case we leave the
        //     timers alone and wait for more packets.
        // (2) We did get a full flight and then handled it, but then
        //     wrote some more message and now we need to flush them
        //     to the network and now reset the timers
        //
        // If data was written then this means we got a complete
        // something or a retransmit so we need to reset the timer
        rtpp_log_write(RTPP_LOG_INFO, glog," Handshake WANT READ\n");

        break;
    case SSL_ERROR_WANT_WRITE:
        rtpp_log_write(RTPP_LOG_INFO, glog," Handshake WANT WRITE %d\n",err);
        break;
    default:
        rtpp_log_write(RTPP_LOG_INFO, glog," Handshake ERROR %d\n", err);
        // Note: need to fall through to propagate alerts, if any
        return 0;
        break;
    }
    return 1;
}


int dtls_process_pending_bytes(rtpp_stream *st)
{
    char buf[BUFSIZE]="\0";
    BIO *bio_wr = NULL;
    char *pbuf = buf;
    struct sockaddr_in *to;

    if (!st->ssl)
        return -1;

    bio_wr = SSL_get_wbio(st->ssl);
    if (!bio_wr)
        return -1;
    while (1)
    {
        size_t pending = BIO_ctrl_pending(bio_wr);
        if (pending > 0)
        {
            bzero(buf,BUFSIZE);
            rtpp_log_write(RTPP_LOG_INFO, glog,"BIO_ctrl_pending(bio_wr) == %d (max buf:%d)\n" , pending,BUFSIZE );

            //  BIO_read() attempts to read len bytes from BIO b and places the data in buf.
            int bytes_to_send = BIO_read(bio_wr, (void*)pbuf, sizeof(buf) > pending ? pending : sizeof(buf));
            if (bytes_to_send > 0)
            {
                rtpp_log_write(RTPP_LOG_INFO, glog,"BIO_read(bio_wr) == %d\n", bytes_to_send );

                int sent = 0;
                while (1)
                {
                    to = (struct sockaddr_in *)*(st->addr);
                    rtpp_log_write(RTPP_LOG_INFO, glog,"dtls udp send %d encoded bytes to fd:%d %s:%d\n", bytes_to_send,st->fd, (char *)inet_ntoa(to->sin_addr), ntohs(to->sin_port));
                    int rc = sendto(st->fd, pbuf+sent, bytes_to_send, 0, *(st->addr), SA_LEN(*(st->addr)));
                    if (rc == -1)
                    {
                        rtpp_log_write(RTPP_LOG_INFO, glog,"sendto == %d failed\n", rc );
                        break;
                    }
                    else
                    {
                        rtpp_log_write(RTPP_LOG_INFO, glog,"sendto == %d success\n", rc );
                        sent += rc;
                        bytes_to_send -= rc;
                        if (bytes_to_send == 0)
                            break;
                    }
                }
            }
            else if (!BIO_should_retry(bio_wr))
            {// BIO_should_retry() is true if the call that produced this condition should then be retried at a later time.
                dtls_report_error(st->ssl, bytes_to_send);
            }
        }
        else
        {
            rtpp_log_write(RTPP_LOG_INFO, glog,"BIO_ctrl_pending(bio_wr) == 0\n" );
            break;
        }
    }
    return 0;
}
bool dtls_shutdown(rtpp_stream *st, int pending)
{
    if (!st->ssl) return 0;

    SSL_shutdown(st->ssl);
    if (pending)
        dtls_process_pending_bytes(st);
    SSL_clear(st->ssl);
    st->state = DTLS_STATE_CLOSED;
    return true;
}
int dtls_start_client(rtpp_stream *st)
{
    int ret =0;
    if (!st || st->init_failed)
        return 0;
    rtpp_log_write(RTPP_LOG_INFO, glog,"st:%p dtls state:%s snd_attr:%s rcv_attr:%s\n",st, 
                   dtls_state_str(st->state), dtls_attr_str(st->snd_attr),dtls_attr_str(st->rcv_attr));
    /* Client Hello Count to send client hello two times */
    //if (st->state > DTLS_STATE_CONNECTING || (st->client_hello_count >= 2 && st->state != DTLS_STATE_INIT_DONE) || st->snd_attr != RTPP_DTLS_ATTR_SETUP_ACTIVE)
    //if (st->client_hello_retran_cnt >= CLIENT_HELLO_MAX_RETRANS || st->state >= DTLS_STATE_ESTABLISHED || st->snd_attr != RTPP_DTLS_ATTR_SETUP_ACTIVE)
    if (st->state != DTLS_STATE_INIT_DONE || st->snd_attr != RTPP_DTLS_ATTR_SETUP_ACTIVE)
    {
        //rtpp_log_write(RTPP_LOG_INFO, glog,"dtls_start_client started/failed\n");
        return 0;
    }
    ret = dtls_start_client_handshake(st);
    if (!ret)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog,"dtls_start_client_handshake failed\n");
        return 0;
    }
    //st->client_hello_count++;
    return dtls_process_pending_bytes(st);


}
int dtls_do_retransmission(rtpp_stream *st)
{

    if (!st || !st->ssl || (st->state != DTLS_STATE_ACCEPTING && st->state != DTLS_STATE_CONNECTING) )
        return 0;

    if ((SSL_version(st->ssl) == DTLS1_VERSION) && DTLSv1_handle_timeout(st->ssl) > 0)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog,"DTLS Timeout Occured (%p)\n", st);
        return dtls_process_pending_bytes(st);
    }
    return 0;
}
int dtls_process_dtls_msg(rtpp_stream *st, char *buf, int size)
{
    BIO *bio_rd = NULL;
    int r, w = 0;
    if (!st || !st->ssl || !buf || !size || st->init_failed)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog,"Failed stream:%p ssl:%p buf:%p size:%d init:%d\n",
                       DPRINT(st),DPRINT(st->ssl),DPRINT(buf),size,st?st->init_failed:0);
        return -1;
    }

    rtpp_log_write(RTPP_LOG_INFO, glog,"Recvd %d bytes dtls state:%s snd_attr:%s\n",
                   size,dtls_state_str(st->state), dtls_attr_str(st->snd_attr));

    if (st->snd_attr == RTPP_DTLS_ATTR_SETUP_PASSIVE && st->state == DTLS_STATE_INIT_DONE)
        st->state = DTLS_STATE_ACCEPTING;

    bio_rd = SSL_get_rbio(st->ssl);
    if (!bio_rd)
        return -1;
    if (size > 0)
    {
        w = BIO_write(bio_rd, buf, size);
        rtpp_log_write(RTPP_LOG_INFO, glog,"BIO_write %d bytes\n", w);
        while (1)
        {
            r = SSL_read(st->ssl, buf, BUFSIZE);

            if (r > 0)
            {
                rtpp_log_write(RTPP_LOG_INFO, glog,"SSL_read received %d bytes %s\n",r, buf );
            }
            else
            {
                if (SSL_want_read(st->ssl))
                {
                    rtpp_log_write(RTPP_LOG_INFO, glog, "SSL_want_read \n");
                }
                else
                {
                    dtls_report_error(st->ssl, r);
                    if (SSL_get_error(st->ssl, r) == SSL_ERROR_ZERO_RETURN)
                    {
                        rtpp_log_write(RTPP_LOG_INFO, glog,"dtls session closed \n");
                        dtls_shutdown(st, 0);
                        goto send_pending;
                    }
                    rtpp_log_write(RTPP_LOG_INFO, glog,"dtls udp received %d Error  bytes SSL_read\n",r );
                    break;
                }
                rtpp_log_write(RTPP_LOG_INFO, glog,"Handshake finished? state:%d\n",st->state);
                if (st->state != DTLS_STATE_ESTABLISHED && SSL_is_init_finished(st->ssl))
                {
                    rtpp_session *sp = (rtpp_session *)st->sp;
                    rtpp_log_write(RTPP_LOG_INFO, glog,"Handshake has been finished sp:%p st:%p\n",sp, st);

                    if (sp && sp->drop_rtp_packets == RTPP_DTLS_DROP_RTP)
                        sp->drop_rtp_packets = 0;
                    dtls_setup_srtp_keys(st);
                    st->state = DTLS_STATE_ESTABLISHED;
                }
                break;
            }
        }
    }
    else if (size==0)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog," connection closed" );
        return -1;
    }
    send_pending:
    dtls_process_pending_bytes(st);
    return 0;

}



bool dtls_close(rtpp_stream *st) {
    rtpp_dtls_free_stream(st);
    return true;
}
SSL_CTX *dtls_create_ssl_context(dtls_context *dtls_ctx, dtls_versions dtls_version, int client)
{
    SSL_CTX *ctx = NULL;

    if (client)
        ctx = SSL_CTX_new(dtls_ctx->dtls_method[dtls_version].client);
    else
        ctx = SSL_CTX_new(dtls_ctx->dtls_method[dtls_version].server);

    if (ctx == NULL)
        return NULL;

    if (client)
        SSL_CTX_add_client_CA(ctx, dtls_ctx->identity->certificate);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, dtls_verify_cb);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

    if (SSL_CTX_set_tlsext_use_srtp(ctx, default_srtp_profile))
    {
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (dtls_ctx->identity != NULL && !configure_ctx_identity(ctx, dtls_ctx->identity))
    {
        return NULL;
    }
    SSL_CTX_set_cookie_generate_cb(ctx, dtls_generate_cookie_cb);
    SSL_CTX_set_cookie_verify_cb(ctx, dtls_verify_cookie_cb);
    SSL_CTX_set_read_ahead(ctx, 1);

    return ctx;
}
void dtls_init_ssl_methods(dtls_context *dtls_ctx)
{
    dtls_ctx->dtls_method[M_DTLS_V1_0].server = DTLSv1_server_method();
    dtls_ctx->dtls_method[M_DTLS_V1_0].client = DTLSv1_client_method();
#if 0
    dtls_ctx->dtls_method[M_DTLS_V1_2].server = DTLSv1_2_server_method();
    dtls_ctx->dtls_method[M_DTLS_V1_2].client = DTLSv1_2_client_method();
#endif

}
int init_dtls_context(dtls_context *dtls_ctx, dtls_versions dtls_version)
{
    bzero(dtls_ctx,sizeof(dtls_context));
        // setup DTLS identity
    // TODO: use a random string as common name
    dtls_ctx->identity = generate_ssl_identity("rtpproxy");
    dtls_init_ssl_methods(dtls_ctx);
    if ((dtls_ctx->client_ctx = dtls_create_ssl_context(dtls_ctx, dtls_version, 1)) == NULL)
    {
        rtpp_log_write(RTPP_LOG_ERR, glog,"dtls client context create failed \n");
        return -1;
    }
    if ((dtls_ctx->server_ctx = dtls_create_ssl_context(dtls_ctx, dtls_version, 0)) == NULL)
    {
        rtpp_log_write(RTPP_LOG_ERR, glog,"dtls server context create failed \n");
        SSL_CTX_free(dtls_ctx->client_ctx);
        return -1;
    }
    dtls_ctx->verify = true;
    return 0;
}

/* return 1 - consume return 0 - relay */
int rtpp_dtls_handle_dtls_packet(struct rtpp_session *sp, int ridx, struct rtp_packet *packet)
{
    if (!packet || ridx < 0 || !sp->stream[ridx] || !sp->stream[ridx]->ssl )
        return 0;

    //sanity check
    unsigned char* tmp_data = packet->data.buf;
    size_t tmp_size = packet->size;
    size_t record_len = 0;
    while (tmp_size > 0)
    {
        if (tmp_size < DTLS_RECORD_HEADER_LEN)
        {
            return 0; 
        }
        record_len = (tmp_data[11] << 8) | (tmp_data[12]);
        if ((record_len + DTLS_RECORD_HEADER_LEN) > tmp_size)
        {
            return 1;  // Body too short
        }
        tmp_data += record_len + DTLS_RECORD_HEADER_LEN;
        tmp_size -= record_len + DTLS_RECORD_HEADER_LEN;
    }
    BIO_dgram_set_peer(SSL_get_wbio(sp->stream[ridx]->ssl), &packet->raddr);
    dtls_process_dtls_msg(sp->stream[ridx],(char *)packet->data.buf, packet->size);

    return 1;
}

int rtpp_dtls_create_stream(struct cfg *cf, struct rtpp_session *sp, const int kidx) 
{ 
    if (kidx < 0)
        return 1;
    if (sp->stream[kidx] == NULL)
    {
        sp->stream[kidx] = (rtpp_stream *)malloc(sizeof(rtpp_stream));
        if (sp->stream[kidx] == NULL)
        {
            rtpp_log_write(RTPP_LOG_ERR, glog, "create_dtls_stream failed");
            return 0;
        }
    }
    dtls_init_stream(sp->stream[kidx], sp->fds[kidx], &sp->addr[kidx]);
    sp->stream[kidx]->local_identity = dtls_ctx.identity;
    sp->stream[kidx]->sp  = sp;
    sp->stream[kidx]->idx = kidx;
    return 1;    
}

int rtpp_dtls_setup_stream(struct rtpp_session *sp, const int kidx,
                           unsigned char *local_fp, int local_fp_algo, 
                           const uint32_t local_ssrc, uint16_t local_attr,
                           unsigned char *remote_fp,int remote_fp_algo, 
                           const uint32_t remote_ssrc, uint16_t remote_attr, const int fix_srtp_seq) 
{

    if (kidx < 0 || sp->stream[kidx] == NULL)
        return 0;
    if (local_fp)
        dtls_set_local_fingerprint(sp->stream[kidx],local_fp_algo,local_fp,strlen((const char*)local_fp));
    if (remote_fp)
    {
        rtpp_log_write(RTPP_LOG_INFO, glog, "digest:%s\n",remote_fp);
        dtls_set_remote_fingerprint(sp->stream[kidx],remote_fp_algo,remote_fp,strlen((const char*)remote_fp));
    }


    sp->stream[kidx]->rcv_ssrc = remote_ssrc;
    sp->stream[kidx]->snd_ssrc = local_ssrc;
    sp->stream[kidx]->rcv_attr = remote_attr;
    sp->stream[kidx]->snd_attr = local_attr;
    sp->stream[kidx]->fix_srtp_seq = fix_srtp_seq;

    sp->dtls_pending = true;
    rtpp_log_write(RTPP_LOG_INFO, glog, "idx:%d st:%p fd:%d ssl:%p", 
                   kidx, sp->stream[kidx], sp->stream[kidx]->fd, sp->stream[kidx]->ssl);
    rtpp_log_write(RTPP_LOG_INFO, glog, "idx:%d st:%p r_ssrc:%u r_attr:%d l_ssrc:%u l_attr:%d",
                   kidx, sp->stream[kidx],remote_ssrc,remote_attr,local_ssrc,local_attr);

#ifdef DEBUG_DTLS_SETUP
/* DTLS connection will setup before STUN, can be used in future to setup DTLS after setting up the bridge */
    if (sp->complete)
    {
        rtpp_dtls_setup_connection(sp, kidx);
        rtpp_log_write(RTPP_LOG_DBUG, glog, " st:%p idx:%d fd:%d ssl:%p",
                       sp->stream[kidx], kidx, sp->stream[kidx]->fd, sp->stream[kidx]->ssl);
    }
#endif

    return 1;
}



int rtpp_dtls_init_openssl(struct cfg *cf)
{
    rtpp_log_write(RTPP_LOG_INFO, glog,"Init OpenSSL Lib");

    SSL_library_init();
    SSL_load_error_strings();
    //init_ssl_methods();
    OpenSSL_add_all_digests();
    CRYPTO_set_id_callback(id_f);
    if (init_dtls_context(&dtls_ctx, M_DTLS_V1_0) < 0)
    {
        rtpp_log_write(RTPP_LOG_DBUG, glog, "init_dtls_context failed");
        dtls_ctx.init_failed = true;
    }
    return 1;


}
int rtpp_dtls_setup_connection(rtpp_session *sp, int idx)
{
    rtpp_stream *st;
    if (!sp->dtls_pending || !sp->stream[idx])
        return 0;
    rtpp_log_write(RTPP_LOG_DBUG, glog, "sp:%p idx:%d",sp,idx);
    st = sp->stream[idx];
    sp->drop_rtp_packets = RTPP_DTLS_DROP_RTP;
    dtls_init(st);
    dtls_do_retransmission(st);
    dtls_start_client(st);
    return 1;
}



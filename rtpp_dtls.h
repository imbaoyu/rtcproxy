#ifndef _RTPP_DTLS_H_
#define _RTPP_DTLS_H_

#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "ssl_identity.h"


#define COOKIE_SECRET_LENGTH      16
#define DTLSBUFFER_MAX_SIZE       8192
#define DTLS_RECORD_HEADER_LEN    13
#define CLIENT_HELLO_MAX_RETRANS  2   


//#define RTPP_DTLS_FREE(m) (m?{free(m);m = NULL;}:m = NULL;)
#define RTPP_DTLS_FREE(m) {if(m){free(m);m = NULL;}}

#define   SRTP_MASTER_KEY_LEN      30
#define   SRTP_MASTER_KEY_KEY_LEN  16
#define   SRTP_MASTER_KEY_SALT_LEN 14



#define DPRINT(p)                  (p?(void *)p:0)
#define DSPRINT(p)                 (p?(void *)p:"NULL")
#define BUFSIZE                    8192

typedef struct {
    int size;
    int start;
    int end;
    char *elems;
} cbuffer;


typedef enum
{
   RTPP_DTLS_ATTR_NONE,
   RTPP_DTLS_ATTR_SETUP_ACTIVE,
   RTPP_DTLS_ATTR_SETUP_PASSIVE,
   RTPP_DTLS_ATTR_SETUP_ACTPASS,
   RTPP_DTLS_ATTR_SETUP_HOLDCONN,
   RTPP_DTLS_ATTR_END

}rtpp_dtls_attr;

enum dtls_stream_event {
    DTLS_OPEN     = 1,
    DTLS_READ     = 2,
    DTLS_WRITE    = 4,
    DTLS_CLOSE    = 8
};

typedef enum{

   M_DTLS_V1_0,
   M_DTLS_V1_2,
   M_DTLS_V_MAX

}dtls_versions;

typedef struct {

  const SSL_METHOD *client;
  const SSL_METHOD *server;

}dtls_methods;


typedef enum {

	DTLS_STATE_NONE = 0,
    DTLS_STATE_INIT_FAILED,
    DTLS_STATE_INIT_DONE,
	DTLS_STATE_ACCEPTING,
	DTLS_STATE_CONNECTING,
	DTLS_STATE_ESTABLISHED,
    DTLS_STATE_CLOSED

}dtls_conn_state;

struct srtp_cipher_map_entry {
    const int suite;
    const char* srtp_profile_name;
};

typedef struct {

    int fd;
    bool init_failed;
    int8_t event;
    void *sp;
    int16_t idx;
    struct sockaddr **addr;

    int16_t client_hello_retran_cnt;

    uint32_t rcv_ssrc;
    uint32_t snd_ssrc;
    uint16_t rcv_attr;
    uint16_t snd_attr;

    unsigned char snd_key[SRTP_MAX_KEY_LEN];
    unsigned char rcv_key[SRTP_MAX_KEY_LEN];
    int16_t fix_srtp_seq;
    int16_t suite;

    /* DTLS Params */
    ssl_identity* local_identity;
    char *local_fp_value;
    int16_t local_fp_len;
    int16_t local_fp_algorithm;
    char *remote_fp_value;
    uint16_t remote_fp_len;
    int16_t remote_fp_algorithm;

    SSL_CTX *ctx;
    SSL *ssl;
    dtls_conn_state state;

    /* Cookie Support*/
    unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
    bool  cookie_initialized;

} rtpp_stream;

typedef struct dtls_fingerprint_raw
{
   unsigned char fp[EVP_MAX_MD_SIZE];
   size_t len;
}dtls_fingerprint;

typedef struct _dtls_context
{
    //SSL_CTX *ctx;
    bool init_failed;
    SSL_CTX *client_ctx;
    SSL_CTX *server_ctx;

    ssl_identity *identity;
    uint32_t      identity_expire;
    uint32_t      identity_create_time;

    int8_t  verify;
    int16_t srtp_suite;
    int8_t  dtls_rekey; /* Renegotiation */

    dtls_methods  dtls_method[M_DTLS_V_MAX];


}dtls_context;

/* External Interfaces */
int  rtpp_dtls_handle_dtls_packet(struct rtpp_session *sp, int ridx, struct rtp_packet *packet);
int  rtpp_dtls_setup_stream(struct rtpp_session *sp, const int kidx,
                            unsigned char *local_fp, int local_fp_algo, 
                            const uint32_t local_ssrc, uint16_t local_attr,
                            unsigned char *remote_fp,int remote_fp_algo, 
                            const uint32_t remote_ssrc, uint16_t remote_attr, const int fix_srtp_seq) ;
int  rtpp_dtls_create_stream(struct cfg *cf, struct rtpp_session *sp, const int kidx) ;
int  rtpp_dtls_init_openssl(struct cfg *cf);
int  rtpp_dtls_setup_connection(rtpp_session *sp, int idx);
void rtpp_dtls_free_stream(rtpp_stream* st);


#endif

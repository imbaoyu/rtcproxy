#ifndef _SRTPW_SRTP_WRAPPER_H_
#define _SRTPW_SRTP_WRAPPER_H_

#define SRTP_MASTER_LEN 30
#define SRTP_MASTERKEY_LEN 16
#define SRTP_MASTERSALT_LEN ((SRTP_MASTER_LEN) - (SRTP_MASTERKEY_LEN))
#define SRTP_MASTER_LEN64 (((SRTP_MASTER_LEN) * 8 + 5) / 6 + 1)
#define SRTP_MAX_KEY_LEN 64

#define RTP_MAX_SEQ  ((1<<16)-1)
#define RTP_MIN_SEQ  1
#define RTP_MID_SEQ  (1<<15)

/* Crypto suites */
enum srtpw_srtp_suite {
	SRTPW_AES_CM_128_HMAC_SHA1_80 = 1,
	SRTPW_AES_CM_128_HMAC_SHA1_32 = 2,
	SRTPW_F8_128_HMAC_SHA1_80     = 3
};

typedef enum { 
  rtpp_event_ssrc_collision,    /**<
			    * An SSRC collision occured.             
			    */
  srtpw_event_key_soft_limit,    /**< An SRTP stream reached the soft key
			    *   usage limit and will expire soon.	   
			    */
  srtpw_event_key_hard_limit,    /**< An SRTP stream reached the hard 
			    *   key usage limit and has expired.
			    */
  srtpw_event_packet_index_limit /**< An SRTP stream reached the hard 
			    * packet limit (2^48 packets).             
			    */
} srtpw_srtp_event_t;

/*
 * @brief err_status_t defines error codes.
 *
 * The enumeration err_status_t defines error codes.  Note that the
 * value of err_status_ok is equal to zero, which can simplify error
 * checking somewhat.
 *
 */
typedef enum {
  srtpw_err_status_ok           = 0,  /**< nothing to report                       */
  srtpw_err_status_fail         = 1,  /**< unspecified failure                     */
  srtpw_err_status_bad_param    = 2,  /**< unsupported parameter                   */
  srtpw_err_status_alloc_fail   = 3,  /**< couldn't allocate memory                */
  srtpw_err_status_dealloc_fail = 4,  /**< couldn't deallocate properly            */
  srtpw_err_status_init_fail    = 5,  /**< couldn't initialize                     */
  srtpw_err_status_terminus     = 6,  /**< can't process as much data as requested */
  srtpw_err_status_auth_fail    = 7,  /**< authentication failure                  */
  srtpw_err_status_cipher_fail  = 8,  /**< cipher failure                          */
  srtpw_err_status_replay_fail  = 9,  /**< replay check failed (bad index)         */
  srtpw_err_status_replay_old   = 10, /**< replay check failed (index too old)     */
  srtpw_err_status_algo_fail    = 11, /**< algorithm failed test routine           */
  srtpw_err_status_no_such_op   = 12, /**< unsupported operation                   */
  srtpw_err_status_no_ctx       = 13, /**< no appropriate context found            */
  srtpw_err_status_cant_check   = 14, /**< unable to perform desired validation    */
  srtpw_err_status_key_expired  = 15, /**< can't use key any more                  */
  srtpw_err_status_socket_err   = 16, /**< error in use of socket                  */
  srtpw_err_status_signal_err   = 17, /**< error in use POSIX signals              */
  srtpw_err_status_nonce_bad    = 18, /**< nonce check failed                      */
  srtpw_err_status_read_fail    = 19, /**< couldn't read data                      */
  srtpw_err_status_write_fail   = 20, /**< couldn't write data                     */
  srtpw_err_status_parse_err    = 21, /**< error pasring data                      */
  srtpw_err_status_encode_err   = 22, /**< error encoding data                     */
  srtpw_err_status_semaphore_err = 23,/**< error while using semaphores            */
  srtpw_err_status_pfkey_err = 24    ,/**< error while using pfkey                 */
} srtpw_err_status_t;
typedef void srtpw_srtp;
typedef void srtpw_srtp_policy;
typedef void (srtpw_srtp_event_handler_func_t)(srtpw_srtp_event_t data);
typedef int (srtp_log_handler)(int,void * ,const char *, ...);

#ifdef SRTP_WRAPPER_LOCAL
srtpw_err_status_t srtpw_srtp_create_policy(srtpw_srtp_policy **policy);
srtpw_err_status_t srtpw_srtp_destroy_policy(srtpw_srtp_policy **policy);
srtpw_err_status_t srtpw_srtp_create(srtpw_srtp **srtp, srtpw_srtp_policy *policy);
srtpw_err_status_t srtpw_srtp_destroy(srtpw_srtp *srtp);
srtpw_err_status_t srtpw_srtp_unprotect(srtpw_srtp *srtp, void *buf, int *len, int rtcp);
srtpw_err_status_t srtpw_srtp_protect(srtpw_srtp_policy *p, srtpw_srtp *srtp, void *buf, int *len,int rtcp);
srtpw_err_status_t srtpw_srtp_init();
srtpw_err_status_t srtpw_srtp_install_event_handler(srtpw_srtp_event_handler_func_t func);
srtpw_err_status_t srtpw_set_crypto_policy(srtpw_srtp_policy *p, int suite, const unsigned char *master_key, unsigned long ssrc, int inbound);
srtpw_err_status_t srtpw_srtp_policy_set_ssrc(srtpw_srtp_policy *p, unsigned long ssrc, int inbound);
srtpw_err_status_t srtpw_srtp_policy_set_master_key(srtpw_srtp_policy *p, const unsigned char *key, unsigned int  key_len, const unsigned char *salt, unsigned int salt_len);
srtpw_err_status_t srtpw_srtp_policy_set_suite(srtpw_srtp_policy *p, enum srtpw_srtp_suite suite);
srtpw_err_status_t srtpw_srtp_change_source(srtpw_srtp *srtp, unsigned int from_ssrc, unsigned int to_ssrc);
srtpw_err_status_t srtpw_srtp_add_stream(srtpw_srtp *srtp, srtpw_srtp_policy *policy);
srtpw_err_status_t srtpw_srtp_set_log_level(int level);
srtpw_err_status_t srtpw_validate_key(unsigned char *);
srtpw_err_status_t srtpw_session_print_policy(srtpw_srtp *psrtp);
unsigned short     srtpw_get_local_seq_num(srtpw_srtp *psrtp, unsigned long ssrc);
const char*        srtpw_srtp_errstr(int err);
srtpw_err_status_t srtpw_get_ssrc_from_policy(void *p, uint32_t *ssrc);


#else 
extern "C" {
srtpw_err_status_t srtpw_srtp_create_policy(srtpw_srtp_policy **policy);
srtpw_err_status_t srtpw_srtp_destroy_policy(srtpw_srtp_policy **policy);
srtpw_err_status_t srtpw_srtp_create(srtpw_srtp **srtp, srtpw_srtp_policy *policy);
srtpw_err_status_t srtpw_srtp_destroy(srtpw_srtp *srtp);
srtpw_err_status_t srtpw_srtp_unprotect(srtpw_srtp *srtp, void *buf, int *len, int rtcp);
srtpw_err_status_t srtpw_srtp_protect(srtpw_srtp_policy *p, srtpw_srtp *srtp, void *buf, int *len,int rtcp);
srtpw_err_status_t srtpw_srtp_init();
srtpw_err_status_t srtpw_srtp_install_event_handler(srtpw_srtp_event_handler_func_t func);
srtpw_err_status_t srtpw_set_crypto_policy(srtpw_srtp_policy *p, int suite, const unsigned char *master_key, unsigned long ssrc, int inbound);
srtpw_err_status_t srtpw_srtp_policy_set_ssrc(srtpw_srtp_policy *p, unsigned long ssrc, int inbound);
srtpw_err_status_t srtpw_srtp_policy_set_master_key(srtpw_srtp_policy *p, const unsigned char *key, size_t key_len, const unsigned char *salt, size_t salt_len);
srtpw_err_status_t srtpw_srtp_policy_set_suite(srtpw_srtp_policy *p, enum srtpw_srtp_suite suite);
srtpw_err_status_t srtpw_srtp_change_source(srtpw_srtp *srtp, unsigned int from_ssrc, unsigned int to_ssrc);
srtpw_err_status_t srtpw_srtp_add_stream(srtpw_srtp *srtp, srtpw_srtp_policy *policy);
srtpw_err_status_t srtpw_srtp_set_log_level(int level);
srtpw_err_status_t srtpw_validate_key(unsigned char *);
srtpw_err_status_t srtpw_session_print_policy(srtpw_srtp *psrtp);
srtpw_err_status_t srtpw_get_ssrc_from_policy(void *p, unsigned int *ssrc);
unsigned short     srtpw_get_local_seq_num(srtpw_srtp *psrtp, unsigned long ssrc);
const char*        srtpw_srtp_errstr(int err);
char*              srtpw_octet_string_hex_string(const void *str, int length);

}

#endif

#if 0
srtpw_err_status_t srtpw_srtp_add_stream(struct srtpw_srtp *srtp, struct srtpw_srtp_policy *policy);
srtpw_err_status_t srtpw_srtp_change_source(struct srtpw_srtp *srtp, unsigned int from_ssrc, unsigned int to_ssrc);

/* Policy functions */
struct srtpw_srtp_policy *srtpw_srtp_policy_alloc(void);
void srtpw_srtp_policy_destroy(struct srtpw_srtp_policy *policy);
srtpw_err_status_t srtpw_srtp_policy_set_suite(struct srtpw_srtp_policy *policy, enum srtpw_srtp_suite suite);
srtpw_err_status_t srtpw_srtp_policy_set_master_key(struct srtpw_srtp_policy *policy, const unsigned char *key, size_t key_len, const unsigned char *salt, size_t salt_len);
void srtpw_srtp_policy_set_ssrc(struct srtpw_srtp_policy *policy, unsigned long ssrc, int inbound);


#endif


#endif

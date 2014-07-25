#ifndef _SSL_IDENTITY_H_
#define _SSL_IDENTITY_H_

#include "openssl/evp.h"
#include "openssl/x509.h"

typedef struct {
    EVP_PKEY *keypair;
    X509 *certificate;
} ssl_identity;

typedef enum{

   DTLS_DIGEST_MD5     = 4,
   DTLS_DIGEST_SHA_1   = 5,
   DTLS_DIGEST_SHA_224 = 6,
   DTLS_DIGEST_SHA_256 = 7,
   DTLS_DIGEST_SHA_384 = 8,
   DTLS_DIGEST_SHA_512 = 9,
   DTLS_DIGEST_END
}rtpp_dtls_fp_algo;


bool get_digest_evp(int algorithm, const EVP_MD **mdp);
EVP_PKEY* make_key();
X509* make_certificate(EVP_PKEY* pkey, const char* common_name);
X509* make_cert_from_pem(char *pem_str, const int len, int *pem_len);
bool compute_digest(const X509 *x509, int algorithm, unsigned char *digest, size_t size, size_t *len);
char *cert_to_pem(X509 *x509);

ssl_identity *generate_ssl_identity(const char *common_name);
void free_ssl_identity(ssl_identity *id);
bool configure_ctx_identity(SSL_CTX *ctx, ssl_identity *id);
int fp_to_hex(const unsigned char *input, const int i_size, char **output);
int hex_to_fp(const unsigned char *input, const int i_size, char **output);

#endif

#include "assert.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "ssl_identity.h"

static const int KEY_LENGTH = 1024;
// Random bits for certificate serial number
static const int SERIAL_RAND_BITS = 64;
// Certificate validity lifetime
static const int CERTIFICATE_LIFETIME = 60*60*24*365;  // one year, arbitrarily

const char DIGEST_MD5[]     = "md5";
const char DIGEST_SHA_1[]   = "sha-1";
const char DIGEST_SHA_224[] = "sha-224";
const char DIGEST_SHA_256[] = "sha-256";
const char DIGEST_SHA_384[] = "sha-384";
const char DIGEST_SHA_512[] = "sha-512";

EVP_PKEY* make_key() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIGNUM* exponent = BN_new();
    RSA* rsa = RSA_new();
    if (!pkey || !exponent || !rsa ||
            !BN_set_word(exponent, 0x10001) ||  // 65537 RSA exponent
            !RSA_generate_key_ex(rsa, KEY_LENGTH, exponent, NULL) ||
            !EVP_PKEY_assign_RSA(pkey, rsa)) {
        EVP_PKEY_free(pkey);
        BN_free(exponent);
        RSA_free(rsa);
        return NULL;
    }
    BN_free(exponent);
    return pkey;
}

X509* make_certificate(EVP_PKEY* pkey, const char* common_name) {
    X509* x509 = NULL;
    BIGNUM* serial_number = NULL;
    X509_NAME* name = NULL;

    if ((x509 = X509_new()) == NULL)
        goto error;
    if (!X509_set_pubkey(x509, pkey))
        goto error;
    // serial number
    // temporary reference to serial number inside x509 struct
    ASN1_INTEGER* asn1_serial_number;
    if ((serial_number = BN_new()) == NULL ||
            !BN_pseudo_rand(serial_number, SERIAL_RAND_BITS, 0, 0) ||
            (asn1_serial_number = X509_get_serialNumber(x509)) == NULL ||
            !BN_to_ASN1_INTEGER(serial_number, asn1_serial_number))
        goto error;
    if (!X509_set_version(x509, 0L))  // version 1
        goto error;
    if ((name = X509_NAME_new()) == NULL ||
            !X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8,
                (unsigned char*)common_name, -1, -1, 0) ||
            !X509_set_subject_name(x509, name) ||
            !X509_set_issuer_name(x509, name))
        goto error;
    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
            !X509_gmtime_adj(X509_get_notAfter(x509), CERTIFICATE_LIFETIME))
        goto error;
    if (!X509_sign(x509, pkey, EVP_sha1()))
        goto error;
    BN_free(serial_number);
    X509_NAME_free(name);
    return x509;
error:
    BN_free(serial_number);
    X509_NAME_free(name);
    X509_free(x509);
    return NULL;
}

X509* make_cert_from_pem(char *pem_str, const int len, int *pem_len) {
    BIO* bio = BIO_new_mem_buf(pem_str, -1);
    char *ptr;
    if (!bio)
        return NULL;
    (void)BIO_set_close(bio, BIO_NOCLOSE);
    BIO_set_mem_eof_return(bio, 0);
    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, (char*)("\0"));
    int remaining_length = BIO_get_mem_data(bio, &ptr);
    BIO_free(bio);
    if (pem_len)
        *pem_len =  len - remaining_length;
    if (x509)
        return x509;
    else
        return NULL;
}

bool get_digest_evp(int algorithm, const EVP_MD **mdp){
    const EVP_MD* md;
    switch(algorithm){

    case DTLS_DIGEST_MD5:
         md = EVP_md5();
        break;
    case DTLS_DIGEST_SHA_1:
        md = EVP_sha1();
        break;
    case DTLS_DIGEST_SHA_224:
        md = EVP_sha224();
        break;
    case DTLS_DIGEST_SHA_256:
        md = EVP_sha256();
        break;
    case DTLS_DIGEST_SHA_384:
        md = EVP_sha384();
        break;
    case DTLS_DIGEST_SHA_512:
        md = EVP_sha512();
        break;
    default:
        return false;
    }
    assert(EVP_MD_size(md) >= 16);
    *mdp = md;
    return true;
}
bool compute_digest(const X509 *x509,int algorithm, unsigned char *digest, size_t size, size_t *len) {
    const EVP_MD *md;
    unsigned int n;
    if (!get_digest_evp(algorithm, &md))
        return false;
    if (size < (size_t)(EVP_MD_size(md)))
        return false;
    X509_digest(x509, md, digest, &n);
    *len = n;
    return true;
}

char *cert_to_pem(X509 *x509) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio)
        return NULL;
    if (!PEM_write_bio_X509(bio, x509)) {
        BIO_free(bio);
        return NULL;
    }
    BIO_write(bio, "\0", 1);
    char* buffer;
    BIO_get_mem_data(bio, &buffer);
    BIO_free(bio);
    return buffer;
}

ssl_identity *generate_ssl_identity(const char *common_name) {
    ssl_identity *id = (ssl_identity *)malloc(sizeof(ssl_identity));
    id->keypair = make_key();
    if(id->keypair != NULL) {
        id->certificate = make_certificate(id->keypair, common_name);
        if(id->certificate != NULL) {
            return id;
        } else {
            EVP_PKEY_free(id->keypair);
        }
    } 
    free(id);
    return NULL;
}

void free_ssl_identity(ssl_identity *id) {
    if(id->keypair != NULL) {
        EVP_PKEY_free(id->keypair);
    }
    if(id->certificate != NULL) {
        X509_free(id->certificate);
    }
    free(id);
}

bool configure_ctx_identity(SSL_CTX *ctx, ssl_identity *id) {
    if(SSL_CTX_use_certificate(ctx, id->certificate) != 1 || 
            SSL_CTX_use_PrivateKey(ctx, id->keypair) != 1) {
        return false;    
    }
    return true;
}

int fp_to_hex(const unsigned char *input, const int i_size, char **output) {
    assert(input != NULL);
    int i;
    int ret = 0;;
    int o_size = i_size*3;
    if(*output == NULL)
        *output = (char *)malloc(o_size);
    if(*output == NULL)
        return ret;
    for(i=0; i<i_size-1; i++) {
        ret += sprintf(&(*output)[i*3], "%02X:", input[i]);
    }
    ret += sprintf(&(*output)[i*3], "%02X", input[i_size-1]);
    return ret;
}

int hex_to_int(unsigned char c){
    if(c >= 97)
        c=c-32;
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first*10 + second;
    if(result > 9) result--;
    return result;
}
int hex_to_ascii(unsigned char c, unsigned char d){
    int high = hex_to_int(c) * 16;
    int low = hex_to_int(d);
    return high+low;
}
int hex_to_fp(const unsigned char *input, const int i_size, char **output) {


    int i, j, ret;
    int o_size = (i_size+1)/3;
    i = 0;
    j = 0;
    ret = 0;
    
    if(!input || !i_size)
        return 0;

    if(*output == NULL)
        *output = (char *)malloc(o_size);
    if(*output == NULL) return 0;
    ret += sprintf(&(*output)[j], "%c", hex_to_ascii(input[0], input[1]));
    for(i=2; i<i_size; i++){
        if(input[i] == ':')
            continue;
        j++;
        ret += sprintf(&(*output)[j], "%c", hex_to_ascii(input[i], input[i+1]));
        i++;
    }
    return ret;
}



#include "rsa.h"
#include "base64.h"

#include <ctype.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/time.h>

using namespace std;

string base64Encode(const unsigned char *bytes, int len) {

  BIO *bmem = NULL;
  BIO *b64 = NULL;
  BUF_MEM *bptr = NULL;

  b64 = BIO_new(BIO_f_base64());

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, bytes, len);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  string str = string(bptr->data, bptr->length);
  BIO_free_all(b64);
  return str;
}

bool base64Decode(const string &str, unsigned char *bytes, int &len) {

  const char *cstr = str.c_str();
  BIO *bmem = NULL;
  BIO *b64 = NULL;

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf((void *)cstr, strlen(cstr));
  b64 = BIO_push(b64, bmem);
  len = BIO_read(b64, bytes, len);

  BIO_free_all(b64);
  return len > 0;
}

const char *CRsaSign(void *_p_rsa, char *cstr) {

  if (cstr == NULL || strlen(cstr) == 0) {
    return NULL;
  }

  string signed_str;
  RSA *p_rsa = (RSA *)_p_rsa;
  if (p_rsa != NULL) {
    unsigned char hash[SHA_DIGEST_LENGTH] = {0};
    SHA1((unsigned char *)cstr, strlen(cstr), hash);
    unsigned char sign[XRSA_KEY_BITS / 8] = {0};
    unsigned int sign_len = sizeof(sign);
    int r = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sign, &sign_len, p_rsa);
    if (0 != r && sizeof(sign) == sign_len) {
      signed_str = base64Encode(sign, sign_len);
    }
  }
  if (signed_str.length() <= 0) {
    return NULL;
  }
  return signed_str.c_str();
}

int CRsaVerify(void *_p_rsa, char *cstr, char *sign) {
  if (cstr == NULL || strlen(cstr) == 0) {
    return 0;
  }
  if (sign == NULL || strlen(sign) == 0) {
    return 0;
  }
  int result = 0;
  RSA *p_rsa = (RSA *)_p_rsa;
  if (p_rsa != NULL) {
    unsigned char hash[SHA_DIGEST_LENGTH] = {0};
    SHA1((unsigned char *)cstr, strlen(cstr), hash);
    unsigned char sign_cstr[XRSA_KEY_BITS / 8] = {0};
    int len = XRSA_KEY_BITS / 8;
    base64Decode(sign, sign_cstr, len);
    unsigned int sign_len = XRSA_KEY_BITS / 8;
    int r = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH,
                       (unsigned char *)sign_cstr, sign_len, p_rsa);
    if (r > 0) {
      result = 1;
    }
  }
  return result;
}

void *CLoadPrivateKey(char *file) {
  if (file == NULL || strlen(file) == 0) {
    return NULL;
  }
  FILE *hPriKeyFile = NULL;
  hPriKeyFile = fopen(file, "rb");
  if (hPriKeyFile == NULL) {
    return NULL;
  }
  RSA *p_rsa = RSA_new();
  if (PEM_read_RSAPrivateKey(hPriKeyFile, &p_rsa, 0, 0) == NULL) {
    return NULL;
  }
  fclose(hPriKeyFile);
  return (void *)p_rsa;
}

void *CLoadPublicKey(char *file) {
  if (file == NULL || strlen(file) == 0) {
    return NULL;
  }
  FILE *f = NULL;
  f = fopen(file, "rb");
  if (f == NULL) {
    return NULL;
  }
  RSA *p_rsa = RSA_new();
  if (PEM_read_RSA_PUBKEY(f, &p_rsa, 0, 0) == NULL) {
    return NULL;
  }
  fclose(f);
  return (void *)p_rsa;
}

void CDestoryKey(void *_p_rsa) {
  if (_p_rsa != NULL) {
    RSA_free((RSA *)_p_rsa);
  }
}
#ifndef _RSA_H_
#define _RSA_H_

#define XRSA_KEY_BITS (1024)

#ifdef __cplusplus
extern "C" {
#endif

const char *CRsaSign(void *_p_rsa, char *cstr);
int CRsaVerify(void *_p_rsa, char *cstr, char *sign);
void *CLoadPrivateKey(char *file);
void *CLoadPublicKey(char *file);

void CDestoryKey(void *_p_rsa);

#ifdef __cplusplus
}
#endif

#endif

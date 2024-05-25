#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

#if defined(_WIN32)
    #if defined(ED25519_BUILD_DLL)
        #define ED25519_DECLSPEC __declspec(dllexport)
    #elif defined(ED25519_DLL)
        #define ED25519_DECLSPEC __declspec(dllimport)
    #else
        #define ED25519_DECLSPEC
    #endif
#else
    #define ED25519_DECLSPEC
#endif


#ifdef __cplusplus
extern "C" {
#endif

#ifndef ED25519_NO_SEED
int ED25519_DECLSPEC ed25519_create_seed(unsigned char *seed);
#endif

#ifndef __XC__
#define unsafe
#endif

void ED25519_DECLSPEC ed25519_create_keypair(unsigned char *unsafe public_key, unsigned char *unsafe private_key, const unsigned char *unsafe seed);
void ED25519_DECLSPEC ed25519_sign(unsigned char *unsafe signature, const unsigned char *unsafe message, size_t message_len, const unsigned char *unsafe public_key, const unsigned char *unsafe private_key);
int ED25519_DECLSPEC ed25519_verify(const unsigned char *unsafe signature, const unsigned char *unsafe message, size_t message_len, const unsigned char *unsafe public_key);
void ED25519_DECLSPEC ed25519_add_scalar(unsigned char *unsafe public_key, unsigned char *unsafe private_key, const unsigned char *unsafe scalar);
void ED25519_DECLSPEC ed25519_key_exchange(unsigned char *unsafe shared_secret, const unsigned char *unsafe public_key, const unsigned char *unsafe private_key);

#ifdef __cplusplus
}
#endif

#endif

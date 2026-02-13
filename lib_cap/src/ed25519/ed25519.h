/*
 * Copyright (c) 2015 Orson Peters <orsonpeters@gmail.com>
 * Portions Copyright (c) 2026 PADL Software Pty Ltd
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the authors be held liable for any damages arising from the
 * use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software in a
 *    product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source distribution.
 *
 */

#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>
#include <stdint.h>

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
int ED25519_DECLSPEC ed25519_create_seed(uint8_t *seed);
#endif

#ifndef __XC__
#define unsafe
#endif

void ED25519_DECLSPEC ed25519_create_keypair(uint8_t *unsafe public_key,
                                             uint8_t *unsafe private_key,
                                             const uint8_t *unsafe seed);
void ED25519_DECLSPEC ed25519_sign(uint8_t *unsafe signature,
                                   const uint8_t *unsafe message,
                                   size_t message_len,
                                   const uint8_t *unsafe public_key,
                                   const uint8_t *unsafe private_key);
int ED25519_DECLSPEC ed25519_verify(const uint8_t *unsafe signature,
                                    const uint8_t *unsafe message,
                                    size_t message_len,
                                    const uint8_t *unsafe public_key);
void ED25519_DECLSPEC ed25519_add_scalar(uint8_t *unsafe public_key,
                                         uint8_t *unsafe private_key,
                                         const uint8_t *unsafe scalar);
void ED25519_DECLSPEC ed25519_key_exchange(uint8_t *unsafe shared_secret,
                                           const uint8_t *unsafe public_key,
                                           const uint8_t *unsafe private_key);

typedef struct sha512_context_ {
  uint64_t length, state[8];
  size_t curlen;
  uint8_t buf[128];
} sha512_context;

typedef struct ed25519_context_ {
  sha512_context hash;
} ed25519_context;

void ED25519_DECLSPEC ed25519ph_init(ed25519_context *unsafe ctx);
void ED25519_DECLSPEC ed25519ph_update(ed25519_context *unsafe ctx,
                                       const uint8_t *unsafe message,
                                       size_t message_len);
// the "context" string is an optional (may be NULL) string of up to 255 octets
// that indicates the context in which the sign/verify operation is being used
// note also that these functions are destructive; they can only be called once
void ED25519_DECLSPEC ed25519ph_sign(ed25519_context *unsafe ctx,
                                     uint8_t *unsafe signature,
                                     const uint8_t *unsafe context,
                                     uint8_t context_len,
                                     const uint8_t *unsafe public_key,
                                     const uint8_t *unsafe private_key);
int ED25519_DECLSPEC ed25519ph_verify(ed25519_context *unsafe ctx,
                                      const uint8_t *unsafe signature,
                                      const uint8_t *unsafe context,
                                      uint8_t context_len,
                                      const uint8_t *unsafe public_key);

void ED25519_DECLSPEC ed25519ctx_sign(uint8_t *unsafe signature,
                                      const uint8_t *unsafe context,
                                      uint8_t context_len,
                                      const uint8_t *unsafe message,
                                      size_t message_len,
                                      const uint8_t *unsafe public_key,
                                      const uint8_t *unsafe private_key);
int ED25519_DECLSPEC ed25519ctx_verify(const uint8_t *unsafe signature,
                                       const uint8_t *unsafe context,
                                       uint8_t context_len,
                                       const uint8_t *unsafe message,
                                       size_t message_len,
                                       const uint8_t *unsafe public_key);

#ifndef __XC__
#undef unsafe
#endif

#ifdef __cplusplus
}
#endif

#endif

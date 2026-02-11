/*
 * Copyright (c) 2026 PADL Software Pty Ltd
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

#include "ed25519-private.h"

#define Flag_Ed25519ctx 0
#define Flag_Ed25519ph 1

void ed25519ph_init(ed25519_context *ctx) { sha512_init(&ctx->hash); }

void ed25519ph_update(ed25519_context *ctx,
                      const uint8_t *message,
                      size_t message_len) {
  sha512_update(&ctx->hash, message, message_len);
}

void ed25519ph_sign(ed25519_context *ctx,
                    uint8_t *signature,
                    const uint8_t *context,
                    uint8_t context_len,
                    const uint8_t *public_key,
                    const uint8_t *private_key) {
  static const uint8_t flag = Flag_Ed25519ph;
  uint8_t digest[64];

  sha512_final(&ctx->hash, digest);
  __ed25519ctx_sign(signature, digest, sizeof(digest), public_key,
                    private_key, &flag, context, context_len);
}

int ed25519ph_verify(ed25519_context *ctx,
                     const uint8_t *signature,
                     const uint8_t *context,
                     uint8_t context_len,
                     const uint8_t *public_key) {
  static const uint8_t flag = Flag_Ed25519ph;
  uint8_t digest[64];

  sha512_final(&ctx->hash, digest);
  return __ed25519ctx_verify(signature, digest, sizeof(digest), public_key,
                             &flag, context, context_len);
}

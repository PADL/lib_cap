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

#include "ed25519-private.h"

void __ed25519ctx_sign(
    uint8_t *signature,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *public_key,
    const uint8_t *private_key,
    const uint8_t *flag, /* non-NULL indicates ed25519ctx/ed25519ph */
    const uint8_t *context,
    uint8_t context_len) {
  sha512_context hash;
  uint8_t hram[64];
  uint8_t r[64];
  ge_p3 R;

  sha512_init(&hash);
  if (flag) {
    sha512_update(&hash, dom2_prefix, sizeof(dom2_prefix));
    sha512_update(&hash, flag, sizeof(*flag));
    sha512_update(&hash, &context_len, sizeof(context_len));
    if (context)
      sha512_update(&hash, context, context_len);
  }
  sha512_update(&hash, private_key + 32, 32);
  sha512_update(&hash, message, message_len);
  sha512_final(&hash, r);

  sc_reduce(r);
  ge_scalarmult_base(&R, r);
  ge_p3_tobytes(signature, &R);

  sha512_init(&hash);
  if (flag) {
    sha512_update(&hash, dom2_prefix, sizeof(dom2_prefix));
    sha512_update(&hash, flag, sizeof(*flag));
    sha512_update(&hash, &context_len, sizeof(context_len));
    if (context)
      sha512_update(&hash, context, context_len);
  }
  sha512_update(&hash, signature, 32);
  sha512_update(&hash, public_key, 32);
  sha512_update(&hash, message, message_len);
  sha512_final(&hash, hram);

  sc_reduce(hram);
  sc_muladd(signature + 32, hram, private_key, r);
}

void ed25519_sign(uint8_t *signature,
                  const uint8_t *message,
                  size_t message_len,
                  const uint8_t *public_key,
                  const uint8_t *private_key) {
  __ed25519ctx_sign(signature, message, message_len, public_key, private_key,
                    NULL, NULL, 0);
}

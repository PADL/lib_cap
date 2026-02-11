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

uint8_t dom2_prefix[32] = "SigEd25519 no Ed25519 collisions";

static int consttime_equal(const uint8_t *x, const uint8_t *y) {
  uint8_t r = 0;

  r = x[0] ^ y[0];
#define F(i) r |= x[i] ^ y[i]
  F(1);
  F(2);
  F(3);
  F(4);
  F(5);
  F(6);
  F(7);
  F(8);
  F(9);
  F(10);
  F(11);
  F(12);
  F(13);
  F(14);
  F(15);
  F(16);
  F(17);
  F(18);
  F(19);
  F(20);
  F(21);
  F(22);
  F(23);
  F(24);
  F(25);
  F(26);
  F(27);
  F(28);
  F(29);
  F(30);
  F(31);
#undef F

  return !r;
}

int __ed25519ctx_verify(
    const uint8_t *signature,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *public_key,
    const uint8_t *flag, /* non-NULL indicates ed25519ctx/ed25519ph */
    const uint8_t *context,
    uint8_t context_len) {
  uint8_t h[64];
  uint8_t checker[32];
  sha512_context hash;
  ge_p3 A;
  ge_p2 R;

  if (signature[63] & 224) {
    return 0;
  }

  if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
    return 0;
  }

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
  sha512_final(&hash, h);

  sc_reduce(h);
  ge_double_scalarmult_vartime(&R, h, &A, signature + 32);
  ge_tobytes(checker, &R);

  if (!consttime_equal(checker, signature)) {
    return 0;
  }

  return 1;
}

int ed25519_verify(const uint8_t *signature,
                   const uint8_t *message,
                   size_t message_len,
                   const uint8_t *public_key) {
  return __ed25519ctx_verify(signature, message, message_len, public_key, NULL,
                             NULL, 0);
}

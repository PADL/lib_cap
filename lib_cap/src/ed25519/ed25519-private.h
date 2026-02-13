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

#ifndef ED25519_PRIVATE_H
#define ED25519_PRIVATE_H

#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"

extern uint8_t dom2_prefix[32];

void __ed25519ctx_sign(
    uint8_t *signature,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *public_key,
    const uint8_t *private_key,
    const uint8_t *flag, /* non-NULL indicates ed25519ctx/ed25519ph */
    const uint8_t *context,
    uint8_t context_len);

int __ed25519ctx_verify(
    const uint8_t *signature,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *public_key,
    const uint8_t *flag, /* non-NULL indicates ed25519ctx/ed25519ph */
    const uint8_t *context,
    uint8_t context_len);

#define Flag_Ed25519ctx 0
#define Flag_Ed25519ph 1

#endif

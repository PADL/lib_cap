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

#endif

#include "ed25519-private.h"

void ed25519ph_init(ed25519_context *ctx) {
    sha512_init(&ctx->hash);
}

void ed25519ph_update(ed25519_context *ctx, const uint8_t *message, size_t message_len) {
    sha512_update(&ctx->hash, message, message_len);
}

void ed25519ph_sign(   
    ed25519_context *ctx,
    uint8_t *signature,
    const uint8_t *context,
    uint8_t context_len,
    const uint8_t *public_key,
    const uint8_t *private_key) {
    uint8_t message[64];
    uint8_t flag = 1;

    sha512_final(&ctx->hash, message);
    __ed25519ctx_sign(signature, message, sizeof(message), public_key, private_key, &flag, context, context_len);
}

int ed25519ph_verify(
    ed25519_context *ctx,
    const uint8_t *signature,
    const uint8_t *context,
    uint8_t context_len,
    const uint8_t *public_key) {
    uint8_t message[64];
    uint8_t flag = 1;

    sha512_final(&ctx->hash, message);
    return __ed25519ctx_verify(signature, message, sizeof(message), public_key, &flag, context, context_len);
}

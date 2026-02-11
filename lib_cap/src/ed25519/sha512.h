#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

int sha512_init(sha512_context * md);
int sha512_final(sha512_context * md, uint8_t *out);
int sha512_update(sha512_context * md, const uint8_t *in, size_t inlen);
int sha512(const uint8_t *message, size_t message_len, uint8_t *out);

#endif

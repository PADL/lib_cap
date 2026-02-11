#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

/* state */
typedef struct sha512_context_ {
    uint64_t  length, state[8];
    size_t curlen;
    uint8_t buf[128];
} sha512_context;


int sha512_init(sha512_context * md);
int sha512_final(sha512_context * md, uint8_t *out);
int sha512_update(sha512_context * md, const uint8_t *in, size_t inlen);
int sha512(const uint8_t *message, size_t message_len, uint8_t *out);

#endif

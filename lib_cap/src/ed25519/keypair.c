#include "ed25519.h"
#include "sha512.h"
#include "ge.h"

void ed25519_create_keypair(uint8_t *public_key,
                            uint8_t *private_key,
                            const uint8_t *seed) {
  ge_p3 A;

  sha512(seed, 32, private_key);
  private_key[0] &= 248;
  private_key[31] &= 63;
  private_key[31] |= 64;

  ge_scalarmult_base(&A, private_key);
  ge_p3_tobytes(public_key, &A);
}

#include "ed25519.h"

#ifndef ED25519_NO_SEED

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#include <errno.h>
#else
#include <stdio.h>
#endif

#define SEED_LEN 32

int ed25519_create_seed(uint8_t *seed) {
  int ret;

#ifdef _WIN32
  HCRYPTPROV prov;

  if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT)) {
    return 1;
  }

  if (!CryptGenRandom(prov, SEED_LEN, seed)) {
    CryptReleaseContext(prov, 0);
    return 1;
  }

  CryptReleaseContext(prov, 0);
  ret = 0;
#elif defined(__linux__)
  size_t nbytes = SEED_LEN;

  ret = 0;

  while (nbytes) {
    ssize_t nread = getrandom(&seed[SEED_LEN - nbytes], nbytes, 0);
    if (nread < 0) {
      if (errno == EINTR)
        continue;
      else {
        ret = 1;
        break;
      }
    }
    nbytes -= nread;
  }
#else
  FILE *f = fopen("/dev/urandom", "rb");

  if (f == NULL) {
    return 1;
  }

  if (fread(seed, 1, SEED_LEN, f) != SEED_LEN) {
    fprintf(stderr, "failed to read from entropy source\n");
    ret = 1;
  } else {
    ret = 0;
  }

  fclose(f);
#endif

  return ret;
}

#endif

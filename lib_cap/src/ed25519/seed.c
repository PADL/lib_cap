#include "ed25519.h"

#ifndef ED25519_NO_SEED

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

int ed25519_create_seed(unsigned char *seed) {
    int ret;

#ifdef _WIN32
    HCRYPTPROV prov;

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))  {
        return 1;
    }

    if (!CryptGenRandom(prov, 32, seed))  {
        CryptReleaseContext(prov, 0);
        return 1;
    }

    CryptReleaseContext(prov, 0);
    ret = 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");

    if (f == NULL) {
        return 1;
    }

    if (fread(seed, 1, 32, f) != 32) {
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

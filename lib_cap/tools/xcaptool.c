// Copyright 2024 PADL Software Pty Ltd.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>

#include "cap_internal.h"
#include "base64.h"

#ifdef __linux__
int memset_s(void *s, size_t smax, int c, size_t n) {
  volatile uint8_t *p = s;

  while (n--)
    *p++ = c;

  return 0;
}
#endif

static struct option longopts[] = {
    {"command", required_argument, NULL, 'c'},
    {"private-key-file", required_argument, NULL, 'p'},
    {"public-key-file", required_argument, NULL, 'P'},
    {"mac-address", optional_argument, NULL, 'm'},
    {"serial", optional_argument, NULL, 's'},
    {"capability-flags", optional_argument, NULL, 'f'},
    {"verbose", optional_argument, NULL, 'v'},
    {NULL, 0, NULL, 0},
};

typedef enum { INVALID = -1, GENERATE = 0, SIGN, VERIFY } command_t;

static const char *commands[] = {
    [GENERATE] = "generate", [SIGN] = "sign", [VERIFY] = "verify"};

static void __attribute__((__noreturn__)) usage(const char *argv0) {
  fprintf(
      stderr,
      "usage: %s [--command=generate|sign|verify] [--private-key-file=path]\n"
      "          [--public-key-file=path] [--mac-address=aa:bb:cc:dd:ee:ff]\n"
      "          [--serial=0x12345678] [--capability-flags=0x...] [--verbose]\n",
      argv0);
  exit(EINVAL);
}

static command_t cmd = INVALID;
static uint8_t zero_mac[6];
static uint8_t mac_address[6];
static uint32_t serial;
static uint64_t capability_flags;
static FILE *pubkey, *privkey;
static int verbose;

uint8_t public_key[32], private_key[64];

static int generate(const char *argv0) {
  static uint8_t zeros[32];
  uint8_t seed[32];

  memset(seed, 0, sizeof(seed));

  if (ed25519_create_seed(seed)) {
    fprintf(stderr, "%s: error while generating seed\n", argv0);
    return -errno;
  }

  assert(memcmp(seed, zeros, sizeof(seed)) != 0);

  ed25519_create_keypair(public_key, private_key, seed);
  memset_s(seed, sizeof(seed), 0, sizeof(seed));

  if (fwrite(public_key, sizeof(public_key), 1, pubkey) != 1 ||
      fwrite(private_key, sizeof(private_key), 1, privkey) != 1) {
    int err = -errno;
    fprintf(stderr, "%s: failed to write keypair: %s\n", argv0, strerror(-err));
    return err;
  }

  return 0;
}

static int read_public_key(const char *argv0) {
  if (fread(public_key, sizeof(public_key), 1, pubkey) != 1) {
    int err = -errno;
    fprintf(stderr, "%s: failed to read public key: %s\n", argv0,
            strerror(-err));
    return -err;
  }

  return 0;
}

static int read_private_key(const char *argv0) {
  if (fread(private_key, sizeof(private_key), 1, privkey) != 1) {
    int err = -errno;
    fprintf(stderr, "%s: failed to read private key: %s\n", argv0,
            strerror(-err));
    return -err;
  }

  return 0;
}

static uint8_t key_usage[14] = CAP_KEY_USAGE;

static void make_payload(uint32_t serial,
                         const uint8_t mac_address[6],
                         uint64_t capability_flags,
                         uint8_t payload[CAP_PAYLOAD_LEN]) {
  memcpy(payload, key_usage, sizeof(key_usage));

  payload[sizeof(key_usage)] = (serial >> 0) & 0xff;
  payload[sizeof(key_usage) + 1] = (serial >> 8) & 0xff;
  payload[sizeof(key_usage) + 2] = (serial >> 16) & 0xff;
  payload[sizeof(key_usage) + 3] = (serial >> 24) & 0xff;

  memcpy(&payload[sizeof(key_usage) + 4], mac_address, 6);

  payload[sizeof(key_usage) + 10] = (capability_flags >> 0) & 0xff;
  payload[sizeof(key_usage) + 11] = (capability_flags >> 8) & 0xff;
  payload[sizeof(key_usage) + 12] = (capability_flags >> 16) & 0xff;
  payload[sizeof(key_usage) + 13] = (capability_flags >> 24) & 0xff;
  payload[sizeof(key_usage) + 14] = (capability_flags >> 32) & 0xff;
  payload[sizeof(key_usage) + 15] = (capability_flags >> 40) & 0xff;
  payload[sizeof(key_usage) + 16] = (capability_flags >> 48) & 0xff;
  payload[sizeof(key_usage) + 17] = (capability_flags >> 56) & 0xff;

  assert(sizeof(key_usage) + 18 == CAP_PAYLOAD_LEN);
}

// "xmoscapability" || serial || mac_address || capability_flags
static void make_capability(uint32_t serial,
                            const uint8_t mac_address[6],
                            uint64_t capability_flags,
                            uint8_t capability[72],
                            const uint8_t *public_key,
                            const uint8_t *private_key) {
  uint8_t payload[CAP_PAYLOAD_LEN];

  make_payload(serial, mac_address, capability_flags, payload);
  memcpy(capability, &payload[24], 8);
  ed25519_sign(&capability[8], payload, CAP_PAYLOAD_LEN, public_key,
               private_key);
}

static int sign(const char *argv0) {
  int ret;
  uint8_t capability[72];
  char *cap_string;

  ret = read_public_key(argv0);
  if (ret)
    return ret;

  ret = read_private_key(argv0);
  if (ret)
    return ret;

  make_capability(serial, mac_address, capability_flags, capability, public_key,
                  private_key);

  if (base64_encode(capability, sizeof(capability), &cap_string) < 0)
    return -errno;

  if (verbose) {
    printf("# Serial number: %08x\n", serial);
    printf("# MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_address[0],
           mac_address[1], mac_address[2], mac_address[3], mac_address[4],
           mac_address[5]);
    printf("# Capability flags: %016llx\n", capability_flags);
  }
  printf("%s\n", cap_string);

  free(cap_string);

  return 0;
}

static int verify(const char *argv0) {
  uint8_t capability[72];
  uint8_t payload[CAP_PAYLOAD_LEN];
  char buf[BUFSIZ];
  int read = 0;
  int ret;

  ret = read_public_key(argv0);
  if (ret)
    return ret;

  while (fgets(buf, sizeof(buf), stdin) != NULL) {
    size_t len;

    if (buf[0] == '#')
      continue;

    len = strlen(buf);

    if (buf[len - 1] == '\n') {
      len--;
      buf[len] = '\0';
    }

    if (len != 96) {
      fprintf(stderr, "%s: invalid capability string '%s'\n", argv0, buf);
      return -ERANGE;
    }

    read++;
    break;
  }

  if (!read)
    return -ENOENT;

  if (base64_decode(buf, capability) < 0)
    return -errno;

  memcpy(payload, key_usage, sizeof(key_usage));

  payload[sizeof(key_usage)] = (serial >> 0) & 0xff;
  payload[sizeof(key_usage) + 1] = (serial >> 8) & 0xff;
  payload[sizeof(key_usage) + 2] = (serial >> 16) & 0xff;
  payload[sizeof(key_usage) + 3] = (serial >> 24) & 0xff;

  memcpy(&payload[sizeof(key_usage) + 4], mac_address, 6);
  memcpy(&payload[sizeof(key_usage) + 10], capability, 8);

  assert(sizeof(key_usage) + 18 == CAP_PAYLOAD_LEN);

  if (!ed25519_verify(&capability[8], payload, CAP_PAYLOAD_LEN, public_key)) {
    fprintf(stderr, "%s: capability verification failed\n", argv0);
    return -EPERM;
  }

  if (verbose) {
    printf("%016llx\n", capability_flags);
  }

  return 0;
}

int main(int argc, char *argv[]) {
  int ch;
  const char *privkey_path = NULL, *pubkey_path = NULL;
  int ret;

  umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

  while ((ch = getopt_long(argc, argv, "cpPmsfv", longopts, NULL)) != -1) {
    switch (ch) {
    case 'c': {
      int i;
      if (cmd != INVALID)
        usage(argv[0]);
      for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        if (strcmp(commands[i], optarg) == 0) {
          cmd = (command_t)i;
        }
      }
      if (cmd == INVALID)
        usage(argv[0]);
      break;
    }
    case 'p':
      privkey_path = optarg;
      break;
    case 'P':
      pubkey_path = optarg;
      break;
    case 'm':
      if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%*c", &mac_address[0],
                 &mac_address[1], &mac_address[2], &mac_address[3],
                 &mac_address[4], &mac_address[5]) != 6)
        usage(argv[0]);
      break;
    case 's':
      if (strncasecmp(optarg, "0x", 2) == 0) {
        if (sscanf(&optarg[2], "%x%*c", &serial) != 1)
          usage(argv[0]);
      } else {
        serial = atoi(optarg);
      }
      break;
    case 'f':
      if (strncasecmp(optarg, "0x", 2) == 0) {
        if (sscanf(&optarg[2], "%llx%*c", &capability_flags) != 1)
          usage(argv[0]);
      } else {
        capability_flags = atoll(optarg);
      }
      break;
    case 'v':
      verbose = 1;
      break;
    default:
      usage(argv[0]);
      break;
    }
  }

  if (cmd != VERIFY) {
    if (privkey_path == NULL)
      usage(argv[0]);
    privkey = fopen(privkey_path, (cmd == GENERATE) ? "w" : "r");
    if (privkey == NULL) {
      int err = -errno;
      fprintf(stderr, "%s: failed to open private key %s: %s\n", argv[0],
              privkey_path, strerror(-err));
      exit(-err);
    }
  }

  if (pubkey_path == NULL)
    usage(argv[0]);
  pubkey = fopen(pubkey_path, (cmd == GENERATE) ? "w" : "r");
  if (pubkey == NULL) {
    int err = -errno;
    fprintf(stderr, "%s: failed to open public key %s: %s\n", argv[0],
            pubkey_path, strerror(-err));
    exit(-err);
  }

  if (cmd == GENERATE) {
    ret = generate(argv[0]);
  } else if (cmd == SIGN || cmd == VERIFY) {
    if (cmd == SIGN && serial == 0 && memcmp(mac_address, zero_mac, 6) == 0) {
      fprintf(stderr,
              "%s: will not issue capability if both serial and MAC address "
              "are unspecified\n",
              argv[0]);
      exit(EINVAL);
    }

    ret = (cmd == SIGN) ? sign(argv[0]) : verify(argv[0]);
  } else {
    ret = -EINVAL;
  }

  memset_s(private_key, sizeof(private_key), 0, sizeof(private_key));

  fclose(pubkey);
  if (privkey)
    fclose(privkey);

  if (ret == -EINVAL)
    usage(argv[0]);

  exit(-ret);
}

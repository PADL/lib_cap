// Copyright 2024 PADL Software Pty Ltd.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.

#include <inttypes.h>
#include <string.h>
#include <otp_board_info.h>

#include <cap.h>

#include "cap_internal.h"

static uint8_t key_usage[14] = CAP_KEY_USAGE;

static inline int _cap_verify_signature(const uint8_t signature[64],
                                        unsigned int payload_len,
                                        const uint8_t payload[payload_len],
                                        const uint8_t public_key[32]) {
  return ed25519_verify(signature, payload, payload_len, public_key);
}

int _cap_validate_internal(const uint8_t capability[72],
                           uint32_t serial,
                           const uint8_t mac_address[6],
                           const uint8_t public_key[32],
                           uint64_t &capability_flags) {
  uint8_t payload[CAP_PAYLOAD_LEN];

  capability_flags = 0;

  // data to be signed is
  // "xmoscapability" || serial || mac_address || capability_flags

  memcpy(payload, key_usage, sizeof(key_usage));
  for (unsigned int i = 0; i < sizeof(serial); i++)
    payload[sizeof(key_usage) + i] = (serial, uint8_t[])[i];

  memcpy(&payload[sizeof(key_usage) + sizeof(serial)], mac_address, 6);
  memcpy(&payload[sizeof(key_usage) + sizeof(serial) + 6], capability, 8);

  if (!_cap_verify_signature(&capability[8], sizeof(payload), payload,
                             public_key))
    return 0;

  for (unsigned int i = 0; i < sizeof(capability_flags); i++)
    (capability_flags, uint8_t[])[i] = capability[i];

  return 1;
}

// read serial, MAC address and public key from OTP and call
// _cap_validate_internal()
int cap_validate(otp_ports_t &ports,
                 const uint8_t capability[72],
                 uint32_t &serial,
                 uint32_t mac_index,
                 uint8_t mac_address[6],
                 uint64_t &capability_flags) {
  uint8_t public_key[32];

  serial = 0;
  memset(mac_address, 0, 6);
  capability_flags = 0;

  if (!_cap_otp_get_board_info(ports, serial, mac_index, mac_address,
                               public_key))
    return 0;

  if (!_cap_validate_internal(capability, serial, mac_address, public_key,
                              capability_flags))
    return 0;

  return 1;
}

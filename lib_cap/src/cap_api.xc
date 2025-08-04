// Copyright 2024 PADL Software Pty Ltd.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.

#include <inttypes.h>
#include <string.h>
#if LIBCAP_OTP
#include <otp_board_info.h>
#endif

#include <cap.h>

#include "cap_internal.h"

static uint8_t key_usage[] = CAP_KEY_USAGE;

[[always_inline]] static inline int
_cap_verify_signature(const uint8_t signature[64],
                      unsigned int payload_len,
                      const uint8_t payload[payload_len],
                      const uint8_t public_key[32]) {
  return ed25519_verify(signature, payload, payload_len, public_key);
}

static inline int
_cap_validate_internal(const uint8_t capability[CAPABILITY_LEN],
                       uint64_t vendor_id,
                       uint32_t serial,
                       const uint8_t mac_address[6],
                       const uint8_t public_key[32],
                       uint64_t &capability_flags) {
  uint8_t payload[CAP_PAYLOAD_LEN];

  capability_flags = 0;

  // the capability itself has the format
  // vendor_id || capability_flags || ed25519_signature

  // data to be signed is
  // "xmos\0" || 0x1 || vendor_id || serial || mac_address || capability_flags
  memcpy(payload, key_usage, sizeof(key_usage));

  for (unsigned int i = 0; i < sizeof(vendor_id); i++)
    payload[sizeof(key_usage) + i] = (vendor_id, uint8_t[])[i];
  for (unsigned int i = 0; i < sizeof(serial); i++)
    payload[sizeof(key_usage) + sizeof(serial) + i] = (serial, uint8_t[])[i];

  memcpy(&payload[sizeof(key_usage) + sizeof(vendor_id) + sizeof(serial)],
         mac_address, 6);
  memcpy(&payload[sizeof(key_usage) + sizeof(vendor_id) + sizeof(serial) + 6],
         capability, 8);

  if (!_cap_verify_signature(&capability[16], sizeof(payload), payload,
                             public_key))
    return 0;

  for (unsigned int i = 0; i < sizeof(capability_flags); i++)
    (capability_flags, uint8_t[])[i] = capability[i + 8];

  return 1;
}

// first check the vendor_id matches, otherwise no point verifying signature
static int _cap_validate_vendor_id(uint64_t vendor_id,
                                   const uint8_t capability[CAPABILITY_LEN]) {
  uint64_t vendor_id_verify;

  for (unsigned int i = 0; i < sizeof(vendor_id_verify); i++)
    (vendor_id_verify, uint8_t[])[i] = capability[i];

  return (vendor_id == vendor_id_verify);
}

// validate with a public key provided by the caller
int cap_validate_pkey(const uint8_t public_key[32],
                      uint64_t vendor_id,
                      const uint8_t capability[CAPABILITY_LEN],
                      uint32_t serial,
                      uint32_t mac_index,
                      uint8_t mac_address[6],
                      uint64_t &capability_flags) {
  serial = 0;
  memset(mac_address, 0, 6);
  capability_flags = 0;

  if (!_cap_validate_vendor_id(vendor_id, capability))
    return 0;

  if (!_cap_validate_internal(capability, vendor_id, serial, mac_address,
                              public_key, capability_flags))
    return 0;

  return 1;
}

#if LIBCAP_OTP
// read serial, MAC address and public key from OTP and call
// _cap_validate_internal()
int cap_validate_otp(otp_ports_t &ports,
                     uint64_t vendor_id,
                     const uint8_t capability[CAPABILITY_LEN],
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

  return cap_validate_pkey(public_key, vendor_id, capability, serial,
                           mac_index, mac_address, capability_flags);
}
#endif

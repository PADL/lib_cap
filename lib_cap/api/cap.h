// Copyright 2024 PADL Software Pty Ltd.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.

#pragma once

#include <xccompat.h>
#include <otp_board_info.h>

/**
 * Function for validating a "capability" blob against a serial number,
 * MAC address and public key stored in OTP
 */

/**
 * Validate a "capability" from the board information written into OTP memory.
 *
 * A capability is a blob that is cryptographically bound the a 64-bit vendor ID,
 * the device's serial number (if available)and MAC address of choice, a public
 * key that is stored in OTP, and a 64-bit "capability flags" bitmask which is
 * interpreted by the application (it would typically be used to enable/disable
 * certain features and optionally encode an expiration time for evaluation
 * licenses for devices* with RTCs).
 *
 * The vendor ID must be provided by the caller but is also encoded in the
 * capability string to aid in identification.
 *
 * The serial number and MAC address are retrieved so they can be used elsewhere
 * in the application.
 *
 * \param capability Capability blob stored by application.
 * \param vendor_id VendorID
 * \param serial Serial number
 * \param mac_index Index of MAC address to use for validation.
 * \param mac_address MAC address
 * \param capability_flags Opaque capability flags.
 * \return Returns 1 on success, 0 on failure.
 */

#define CAPABILITY_LEN 80

int cap_validate_otp(REFERENCE_PARAM(otp_ports_t, ports),
                     uint64_t vendor_id,
                     const uint8_t capability[CAPABILITY_LEN],
                     REFERENCE_PARAM(uint32_t, serial),
                     uint32_t mac_index,
                     uint8_t mac_address[6],
                     REFERENCE_PARAM(uint64_t, capability_flags));

int cap_validate_pkey(const uint8_t public_key[32],
                      uint64_t vendor_id,
                      const uint8_t capability[CAPABILITY_LEN],
                      REFERENCE_PARAM(uint32_t, serial),
                      uint32_t mac_index,
                      uint8_t mac_address[6],
                      REFERENCE_PARAM(uint64_t, capability_flags));

// Copyright 2014-2021 XMOS LIMITED.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.

#pragma once

#include <inttypes.h>

#include "ed25519/ed25519.h"

#define CAP_KEY_USAGE {'x', 'm', 'o', 's', 'c', 'a', 'p', 'a', 'b', 'i', 'l', 'i', 't', 'y'}

#define CAP_PAYLOAD_LEN 32

#ifdef __XC__
int _cap_otp_get_board_info(REFERENCE_PARAM(otp_ports_t, ports),
                            REFERENCE_PARAM(uint32_t, serial),
                            uint32_t index,
                            uint8_t mac[6],
                            uint8_t public_key[32]);
#endif

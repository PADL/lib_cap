// Copyright 2024 PADL Software Pty Ltd.
// Portions Copyright 2014-2021 XMOS LIMITED.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.

#include <otp_board_info.h>
#include <xs1.h>
#include <xclib.h>
#include <inttypes.h>

/// Size of the OTP in words.
#define OTP_SIZE 0x800

/// OTP control signals.
enum {
  OTP_CTRL_READ = 1 << 0,
  OTP_CTRL_STATUS = 1 << 5,
  OTP_CTRL_RESET_M = 1 << 13
};

typedef struct board_info_header_t {
  uint32_t address;
  uint32_t bitmap;
} board_info_header_t;

/// Read a word from the specified address in the OTP.
static uint32_t otp_read_word(otp_ports_t &ports, uint32_t address) {
  uint32_t value;
  ports.addr <: address;

  // If the application booted from OTP the bootloader may have left
  // differential mode enabled. Reset the mode registers to default settings.
  // There is no need to do this on every read - we could do it just once at the
  // start. However it is good for code size to do this at the same time as the
  // read from OTP since the ports will be in registers for the OTP read.
  ports.ctrl <: OTP_CTRL_RESET_M;
  ports.ctrl <: 0;

  // Start the read command.
  ports.ctrl <: OTP_CTRL_READ;
  // Wait for status to go high. Use peek otherwise the value of the control
  // signals we are driving will become undefined.
  do {
    value = peek(ports.ctrl);
  } while ((value & OTP_CTRL_STATUS) == 0);
  ports.ctrl <: 0;
  // Grab the data.
  ports.data :> value;

  return value;
}

//
// OTP bitmask layout:
//
// 31       23       15       7
// 76543210 76543210 76543210 76543210
// 0VLLLLLM MMSP.... ........ ........
//
// 0 MBZ
// V header valid
// L length
// M number of MAC addresses
// S serial number valid
// P public key valid
//
// OTP layout [item](32-bit words):
//
// [public_key](P?4:0) [serial_number](S?1:0) [mac_address](M*2) [bitmask](4)
//

/// Search the end of the OTP for a valid board info header.
static int otp_board_info_get_header(otp_ports_t &ports,
                                     board_info_header_t &info) {
  int address = OTP_SIZE - 1;
  do {
    uint32_t bitmap = otp_read_word(ports, address);
    uint32_t length;
    // Stop if bitmap has not been written.
    if (bitmap >> 31)
      return 0;
    // If bitmap is valid we are done.
    if (bitmap >> 30) {
      info.address = address;
      info.bitmap = bitmap;
      return 1;
    }
    // Otherwise skip this bitmap and continue searching.
    length = (bitmap >> 25) & 0x1f;
    if (length == 0) {
      // Bailout on invalid length to avoid infinite loop.
      return 0;
    }
    address -= length;
  } while (address >= 0);
  // Got to the start of the OTP without finding a header.
  return 0;
}

static uint32_t otp_board_info_get_num_macs(const board_info_header_t &info) {
  return (info.bitmap >> 22) & 0x7;
}

static int _otp_board_info_get_mac(otp_ports_t &ports,
                                   const board_info_header_t &info,
                                   uint32_t i,
                                   uint8_t mac[6]) {
  uint32_t address;
  uint32_t macaddr[2];
  if (i >= otp_board_info_get_num_macs(info))
    return 0;
  address = info.address - (2 + 2 * i);
  macaddr[0] = byterev(otp_read_word(ports, address + 1));
  macaddr[1] = byterev(otp_read_word(ports, address));
  // Assumes little endian byte order.
  for (uint32_t i = 0; i < 6; i++) {
    mac[i] = (macaddr, uint8_t[])[i + 2];
  }
  return 1;
}

static int otp_board_info_has_serial(const board_info_header_t &info) {
  return (info.bitmap >> 21) & 1;
}

static int _otp_board_info_get_serial(otp_ports_t &ports,
                                      const board_info_header_t &info,
                                      uint32_t &value) {
  uint32_t address;
  if (!otp_board_info_has_serial(info))
    return 0;
  address = info.address - (otp_board_info_get_num_macs(info) * 2 + 1);
  value = otp_read_word(ports, address);
  return 1;
}

static int otp_board_info_has_public_key(const board_info_header_t &info) {
  // TODO: check this bit is free
  return (info.bitmap >> 20) & 1;
}

static int _otp_board_info_get_public_key(otp_ports_t &ports,
                                          const board_info_header_t &info,
                                          uint8_t public_key[32]) {
  if (!otp_board_info_has_public_key(info))
    return 0;

  // layout is public_key || serial number || MAC addresses
  // Ed25519 public key is 32 bytes == 8 words

  uint32_t address = info.address - otp_board_info_get_num_macs(info) * 2;
  if (otp_board_info_has_serial(info))
    address--;

  address -= 8;

  // TODO: check endianness
  for (unsigned int i = 0; i < 8; i++) {
    uint32_t value = byterev(otp_read_word(ports, address + i));
    for (unsigned int j = 0; j < 4; j++)
      public_key[4 * i + j] = (value, uint8_t[])[j];
  }

  return 0;
}

int _cap_otp_get_board_info(otp_ports_t &ports,
                            uint32_t &serial,
                            uint32_t mac_index,
                            uint8_t mac_address[6],
                            uint8_t public_key[32]) {
  board_info_header_t info;

  if (!otp_board_info_get_header(ports, info) ||
      !_otp_board_info_get_mac(ports, info, mac_index, mac_address) ||
      !_otp_board_info_get_public_key(ports, info, public_key))
    return 0;

  // serial number is optional
  if (!_otp_board_info_get_serial(ports, info, serial))
    serial = 0;

  return 1;
}

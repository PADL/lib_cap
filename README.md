# lib\_cap

`lib_cap` is an XMOS library for validating a set of capabilities against a device identity (MAC address and serial number) and key.

## module

Add `lib_cap(>=0.0.1)` to your module dependencies. There is a single API:

```c
int cap_validate(REFERENCE_PARAM(otp_ports_t, ports),
                 uint64_t vendor_id,
                 const uint8_t capability[72],
                 REFERENCE_PARAM(uint32_t, serial),
                 uint32_t mac_index,
                 uint8_t mac_address[6],
                 REFERENCE_PARAM(uint64_t, capability_flags));
```

`cap_validate` _returns_ the serial number and MAC address, for use elsewhere in the application; these are _not_ input parameters. The `capability` argument is the binary capability signed by the `xcaptool` command, and encodes both the capability flags and Ed25519 signature. The capability flags are returned in `capability_flags`.

## xcaptool

Source code is in `lib_cap/tools`.

Examples:

### Generating a keypair

Note: keypairs are stored as their raw values and as such are not compatible with the PKCS encodings used by OpenSSL. We can add support for PKCS if required.

```
xcaptool --command=generate --private-key-file=privkey --public-key-file=pubkey
```

The public key must be burned into the OTP flash. We will provide a script to do this.

### Signing a capability

Signing a capability requires a public/private key pair generated in the preceeding step. Either one or both of the serial number and MAC address must be supplied, to guard against generating a key that could unlock any device.

Serial numbers and capability flags can be provided as decimal or hexadecimal values, the latter prefixed with `0x`.

Capability flags are application defined; typically, they will represent a set of licensed features.

Capabilities are output base64-encoded. They should be decoded to binary before storing on the device.

```
xcaptool --command=sign --private-key-file=privkey --public-key-file=pubkey --serial=0x1234 --mac-address=00:aa:bb:11:cc:ee --capability-flags=0x12345 --vendor-id=0xaabbcc
```

### Verifying a capability

A capability may be verified as follows:

```
xcaptool --command=verify --private-key-file=privkey --public-key-file=pubkey --serial=0x1234 --mac-address=00:aa:bb:11:cc:ee --capability-flags=0x12345 --vendor-id=0xaabbcc
```

This logic is similar to that used by the XMOS library.

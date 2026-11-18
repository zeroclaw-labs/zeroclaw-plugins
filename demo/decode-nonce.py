#!/usr/bin/env python3
"""Decode a Solana durable nonce account and check it against expected values.

Takes the account's base64 data on the command line rather than on stdin, so the
caller can keep stdin free. Layout, 80 bytes total: version u32, state u32,
authority 32, durable blockhash 32, fee-calculator lamports-per-signature u64.
That is the same layout plugins/nonce-status parses, so this is the plugin's
claim checked without the plugin.

    demo/decode-nonce.py <base64-account-data> <expected-fee>

Exits 0 when version, state and fee are what a live initialised nonce must be.
"""

from __future__ import annotations

import base64
import struct
import sys

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    out = bytearray()
    while number:
        number, rem = divmod(number, 58)
        out.append(ALPHABET[rem])
    for byte in raw:
        if byte:
            break
        out.append(ALPHABET[0])
    return bytes(reversed(out)).decode()


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    data = base64.b64decode(argv[1])
    if len(data) != 80:
        print(f"  FAIL  {len(data)} bytes of account data, a nonce account is 80")
        return 1
    version, state = struct.unpack_from("<II", data, 0)
    authority = b58(data[8:40])
    blockhash = b58(data[40:72])
    (fee,) = struct.unpack_from("<Q", data, 72)

    failures = 0
    for label, got, want in (("version", version, 1), ("state", state, 1), ("fee", fee, int(argv[2]))):
        if got == want:
            print(f"  ok    {label} {got}")
        else:
            print(f"  FAIL  {label} {got}, expected {want}")
            failures += 1
    print(f"  note  authority {authority}")
    print(f"  note  durable blockhash {blockhash}, which advances every time a nonce transfer settles")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

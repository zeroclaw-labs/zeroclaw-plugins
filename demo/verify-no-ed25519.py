#!/usr/bin/env python3
"""No SHA-512 in the shipped bytes, therefore no Ed25519 signature.

The capability check proves these components cannot go looking for a key: there is
no `wasi:filesystem` import, so no keypair file can be opened. It cannot prove that
key material never reaches them, because `wasi:cli/environment` and `wasi:cli/stdin`
are imported by Rust's standard library and an operator can put bytes anywhere.

This check closes that gap from the other side. Ed25519 is not merely implemented
with SHA-512, it is defined in terms of it: RFC 8032 section 5.1 specifies SHA-512
for key expansion, for the per-signature nonce and for the challenge, which is
three calls per signature. Section 5.1.7 uses it again for verification. A component that
carries no SHA-512 cannot compute an Ed25519 signature, whatever bytes it is given.

So the claim these two checks make together is precise:

  * it cannot seek a key, because it has no filesystem capability
  * it cannot use a key, because it has no way to compute the signature

What this does not prove, in the same breath as the rest:

  * HTTP egress is imported, so a component could in principle hand bytes to a
    remote signer. That is prevented by the code path, by the absence of any
    mutating RPC method (`demo/verify-rpc-surface.py`) and by host egress policy,
    not by the absence of a hash constant
  * an unknown or obfuscated SHA-512 implementation that never materialises the
    standard constants would evade this. The positive control below is what makes
    that unlikely rather than merely hoped for

The positive control matters more than the negative result. A probe that finds
nothing because it is broken looks exactly like a probe that finds nothing because
there is nothing there. So this asserts that SHA-256 IS present where the code
genuinely needs it, in `spl_transfer_build`, which derives program addresses and
associated token accounts. If that control ever goes missing the run fails, because
at that point a zero for SHA-512 has stopped meaning anything.

Usage:

    python3 demo/verify-no-ed25519.py                      # the staged artifacts
    python3 demo/verify-no-ed25519.py path/to/one.wasm ...  # explicit paths
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

# SHA-512 initial hash values and the first round constants, FIPS 180-4.
SHA512_IV = (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
)
SHA512_K = (
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
)

# SHA-256, the positive control. PDA and associated-token-account derivation need it.
SHA256_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
SHA256_K = (0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
            0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5)

# The artifact that must carry the control, because it derives addresses.
CONTROL_ARTIFACT = "spl_transfer_build.wasm"

PINNED = {
    "nonce_status.wasm": (332052, "6a13fb62"),
    "payment_watch.wasm": (366822, "e9f6b118"),
    "spl_transfer_build.wasm": (406680, "4c1af93e"),
}

DEFAULT_DIR = Path(__file__).resolve().parent / "out" / "staged"


def signed_leb128(value: int) -> bytes:
    """How wasm encodes an `i32.const` or `i64.const` operand."""
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            more = False
        else:
            byte |= 0x80
        out.append(byte)
    return bytes(out)


def encodings(value: int, width: int) -> list[bytes]:
    """Every way a constant of this width can sit in a wasm binary."""
    pack = "<Q" if width == 64 else "<I"
    big = ">Q" if width == 64 else ">I"
    forms = [struct.pack(pack, value), struct.pack(big, value)]
    # A constant folded into code appears as a signed LEB128 operand. A value with
    # the high bit set is emitted as its negative twos-complement counterpart.
    forms.append(signed_leb128(value))
    forms.append(signed_leb128(value - (1 << width)))
    return [form for form in forms if len(form) > 2]


def occurrences(binary: bytes, constants: tuple[int, ...], width: int) -> tuple[int, int]:
    """How many of these constants appear and how many times in total."""
    distinct = total = 0
    for constant in constants:
        found = sum(binary.count(form) for form in encodings(constant, width))
        if found:
            distinct += 1
            total += found
    return distinct, total


def check(path: Path, is_control: bool) -> bool:
    binary = path.read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    problems: list[str] = []

    iv512, iv512_n = occurrences(binary, SHA512_IV, 64)
    k512, k512_n = occurrences(binary, SHA512_K, 64)
    iv256, iv256_n = occurrences(binary, SHA256_IV, 32)
    k256, k256_n = occurrences(binary, SHA256_K, 32)

    if iv512 or k512:
        problems.append(
            f"SHA-512 constants present: {iv512} of 8 IV words, {k512} of 8 round constants."
            " Ed25519 needs SHA-512, so this artifact can no longer claim it cannot sign"
        )
    if is_control and not (iv256 or k256):
        problems.append(
            "the SHA-256 positive control is missing from the artifact that derives addresses,"
            " so this probe proves nothing and the zero above is not evidence"
        )

    expected = PINNED.get(path.name)
    if expected is None:
        problems.append(f"{path.name} is not one of the pinned artifacts")
    else:
        size, prefix = expected
        if len(binary) != size:
            problems.append(f"size {len(binary)} is not the pinned {size}")
        if not digest.startswith(prefix):
            problems.append(f"sha256 {digest[:8]} is not the pinned {prefix}")

    print(f"\n{path.name}  {len(binary)} bytes  sha256 {digest[:8]}")
    print(f"  SHA-512 IV words present:        {iv512} of 8   ({iv512_n} occurrences)")
    print(f"  SHA-512 round constants present: {k512} of 8   ({k512_n} occurrences)")
    print(f"  SHA-256 present, for contrast:   IV {iv256} of 8, K {k256} of 8"
          f"{'   <- positive control' if is_control else ''}")
    for problem in problems:
        print(f"  FAIL {problem}")
    if not problems:
        print("  PASS no SHA-512 in these bytes, so no Ed25519 signature is computable here")
    return not problems


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] if argv else sorted(DEFAULT_DIR.glob("*/*.wasm"))
    if not paths:
        print(f"no components found under {DEFAULT_DIR}, build them first with demo/run-demo.sh")
        return 2
    results = [check(path, path.name == CONTROL_ARTIFACT) for path in paths]
    controls = [path for path in paths if path.name == CONTROL_ARTIFACT]
    if not controls:
        print(f"\nNOTE {CONTROL_ARTIFACT} was not in this run, so the positive control did not run.")
    print(
        f"\n{sum(results)} of {len(results)} components carry no Ed25519 hash primitive."
        " RFC 8032 section 5.1 makes SHA-512 mandatory for Ed25519, so its absence is the claim."
    )
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

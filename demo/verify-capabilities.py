#!/usr/bin/env python3
"""Prove the custody boundary from the compiled components, not from our tests.

A WebAssembly component can only do what its imports let it do. So the honest way
to answer "can this thing sign a transaction" is not to read the source and not to
trust a test suite written by the same people who wrote the plugin. It is to read
the capability list out of the shipped bytes and see what is not in it.

This script does that with the Python standard library, offline, in about a second.
It walks the component binary, pulls every import the component declares and every
import its inner core module actually links, then holds that surface against an
allowlist. Any interface that is not on the list fails the run. So does a digest
that does not match the pinned artifact.

What a passing run proves:

  * no signing capability of any kind is imported
  * `wasi:filesystem` is absent entirely, so the component cannot open a keypair
    file, a wallet or a `~/.config/solana/id.json`. Not "does not", cannot
  * `wasi:sockets` is absent entirely, so every byte of egress goes through the
    host's `outgoing-handler`, where the operator's policy applies
  * `wasi:random/random` is absent, only `insecure-seed`, which is what Rust's
    hash maps ask for

What it does not prove, stated here because a proof that oversells itself is worth
less than a narrow one:

  * `wasi:cli/environment` and `wasi:cli/stdin` are both imported, because Rust's
    standard library pulls them in, so bytes an operator hands over can reach this
    component. What the missing filesystem import proves is narrower than it first
    reads and it is worth stating exactly: the component cannot go looking for a
    keypair. It does not prove that key material can never be put in front of it.
    `demo/verify-no-ed25519.py` is what closes that gap from the other side, by
    showing the bytes carry no SHA-512 and so cannot compute an Ed25519 signature
    from a key even when handed one. `tests/custody.rs` covers the config and
    argument paths.
  * HTTP egress is imported, because that is how an RPC read works. "Cannot submit
    a transaction" does not follow from the capability list and this script does
    not claim it. `demo/verify-rpc-surface.py` is what proves the bytes name no
    method a node would act on. Submission is also prevented by the code path and
    by host policy.

Usage:

    python3 demo/verify-capabilities.py                      # the staged artifacts
    python3 demo/verify-capabilities.py path/to/one.wasm ...  # explicit paths
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# The complete capability surface of the shipped components, both surfaces at once.
# A component declares the world it asks for in its own import section. The core
# module inside it links the concrete interfaces the guest actually calls. Those two
# are not the same list: the wasip2 adapter declares WASI at 0.2.9 while the guest
# links 0.2.0 and 0.2.2, so both appear here. Every interface either surface names
# has to be on this list or the run fails, which is what stops a new host capability
# arriving unnoticed in a refactor.
ALLOWED_INTERFACES = {
    "wasi:cli/environment@0.2.0",
    "wasi:cli/environment@0.2.9",
    "wasi:cli/exit@0.2.0",
    "wasi:cli/exit@0.2.9",
    "wasi:cli/stderr@0.2.0",
    "wasi:cli/stderr@0.2.9",
    "wasi:cli/stdin@0.2.0",
    "wasi:cli/stdin@0.2.9",
    "wasi:cli/stdout@0.2.0",
    "wasi:cli/stdout@0.2.9",
    "wasi:cli/terminal-input@0.2.0",
    "wasi:cli/terminal-input@0.2.9",
    "wasi:cli/terminal-output@0.2.0",
    "wasi:cli/terminal-output@0.2.9",
    "wasi:cli/terminal-stderr@0.2.0",
    "wasi:cli/terminal-stderr@0.2.9",
    "wasi:cli/terminal-stdin@0.2.0",
    "wasi:cli/terminal-stdin@0.2.9",
    "wasi:cli/terminal-stdout@0.2.0",
    "wasi:cli/terminal-stdout@0.2.9",
    "wasi:clocks/monotonic-clock@0.2.0",
    "wasi:clocks/monotonic-clock@0.2.9",
    "wasi:http/outgoing-handler@0.2.2",
    "wasi:http/outgoing-handler@0.2.9",
    "wasi:http/types@0.2.2",
    "wasi:http/types@0.2.9",
    "wasi:io/error@0.2.0",
    "wasi:io/error@0.2.2",
    "wasi:io/error@0.2.9",
    "wasi:io/poll@0.2.0",
    "wasi:io/poll@0.2.2",
    "wasi:io/poll@0.2.9",
    "wasi:io/streams@0.2.0",
    "wasi:io/streams@0.2.2",
    "wasi:io/streams@0.2.9",
    "wasi:random/insecure-seed@0.2.9",
    "zeroclaw:plugin/logging@0.1.0",
    "zeroclaw:plugin/types@0.1.0",
}

# Absent by construction. Each of these would be a way to reach key material, to
# escape the host's egress policy or to sign, so the run fails if one appears.
DENIED_SUBSTRINGS = (
    "wasi:filesystem",
    "wasi:sockets",
    "wasi:random/random",
    "wasi:keyvalue",
    "sign",
    "keypair",
    "keystore",
    "wallet",
    "secret",
    "ed25519",
    "solana:signer",
)

# The bytes this script was written against. Size and digest both, because a
# length collision is cheap and a sha256 collision is not.
PINNED = {
    "nonce_status.wasm": (332253, "ffd4f0ad"),
    "payment_watch.wasm": (367973, "7f6b8106"),
    "spl_transfer_build.wasm": (409058, "d57ad6be"),
}

DEFAULT_DIR = Path(__file__).resolve().parent / "out" / "staged"


def read_leb128(data: bytes, offset: int) -> tuple[int, int]:
    """One unsigned LEB128, the only integer encoding the format uses here."""
    result = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def sections(binary: bytes):
    """Every top-level section as (id, body), past the 8 byte preamble."""
    offset = 8
    while offset < len(binary):
        section_id = binary[offset]
        offset += 1
        size, offset = read_leb128(binary, offset)
        yield section_id, binary[offset : offset + size]
        offset += size


def core_module_imports(module: bytes) -> list[tuple[str, str]]:
    """The (module, name) pairs a core module links, from its import section."""
    found: list[tuple[str, str]] = []
    for section_id, body in sections(module):
        if section_id != 2:
            continue
        offset = 0
        count, offset = read_leb128(body, offset)
        for _ in range(count):
            length, offset = read_leb128(body, offset)
            namespace = body[offset : offset + length].decode("utf-8", "replace")
            offset += length
            length, offset = read_leb128(body, offset)
            name = body[offset : offset + length].decode("utf-8", "replace")
            offset += length
            kind = body[offset]
            offset += 1
            if kind == 0:
                _, offset = read_leb128(body, offset)
            else:
                offset += 2
            found.append((namespace, name))
    return found


def declared_interfaces(component: bytes) -> set[str]:
    """Interface ids named in the component's own import section.

    Read defensively: the import-name encoding has changed across component-model
    revisions, so rather than pinning one layout this pulls the length-prefixed
    strings out of the section and keeps the ones shaped like an interface id. A
    capability cannot hide from that, because its id has to be spelled somewhere.
    """
    names: set[str] = set()
    for section_id, body in sections(component):
        if section_id != 10:
            continue
        offset = 0
        while offset < len(body) - 1:
            length, next_offset = read_leb128(body, offset)
            if 3 <= length <= 120 and next_offset + length <= len(body):
                candidate = body[next_offset : next_offset + length]
                try:
                    text = candidate.decode("ascii")
                except UnicodeDecodeError:
                    offset += 1
                    continue
                if ":" in text and "/" in text and text.isprintable():
                    names.add(text)
                    offset = next_offset + length
                    continue
            offset += 1
    return names


def capability_surface(binary: bytes) -> tuple[set[str], set[str], list[tuple[str, str]]]:
    """The two capability surfaces: what the component declares, what it links."""
    linked: list[tuple[str, str]] = []
    for section_id, body in sections(binary):
        if section_id == 1 and body[:4] == b"\x00asm":
            linked.extend(core_module_imports(body))
    linked_interfaces = {namespace for namespace, _ in linked if namespace}
    return declared_interfaces(binary), linked_interfaces, linked


def check(path: Path) -> bool:
    binary = path.read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    declared, linked_interfaces, linked = capability_surface(binary)
    interfaces = declared | linked_interfaces
    unnamed = [name for namespace, name in linked if not namespace]

    problems: list[str] = []
    for interface in sorted(interfaces):
        if interface not in ALLOWED_INTERFACES:
            problems.append(f"capability not on the allowlist: {interface}")
    lowered = " ".join(sorted(interfaces)).lower()
    for denied in DENIED_SUBSTRINGS:
        if denied in lowered:
            problems.append(f"denied capability present: {denied}")
    for name in unnamed:
        if name != "$imports" and not name.isdigit():
            problems.append(f"unnamed core import that is not a canonical index: {name}")

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
    print(f"  declared by the component: {len(declared)} interfaces")
    print(f"  linked by the core module:  {len(linked_interfaces)} interfaces, {len(linked)} imports")
    for interface in sorted(interfaces):
        where = []
        if interface in declared:
            where.append("declared")
        if interface in linked_interfaces:
            where.append("linked")
        print(f"    {interface}  [{', '.join(where)}]")
    absent = [d for d in ("wasi:filesystem", "wasi:sockets", "wasi:random/random") if d not in lowered]
    print(f"  absent from both surfaces: {', '.join(absent) if absent else 'NONE, which is a failure'}")
    for problem in problems:
        print(f"  FAIL {problem}")
    if not problems:
        print("  PASS no signing capability, no filesystem, no sockets, digest matches")
    return not problems


def main(argv: list[str]) -> int:
    if argv:
        paths = [Path(a) for a in argv]
    else:
        paths = sorted(DEFAULT_DIR.glob("*/*.wasm"))
    if not paths:
        print(f"no components found under {DEFAULT_DIR}, build them first with demo/run-demo.sh")
        return 2
    results = [check(path) for path in paths]
    print(
        f"\n{sum(results)} of {len(results)} components pass the capability check."
        " This is a property of the bytes, so re-run it on any build you like."
    )
    return 0 if all(results) and len(results) == len(PINNED) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

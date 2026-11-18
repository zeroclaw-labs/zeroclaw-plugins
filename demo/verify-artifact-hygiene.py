#!/usr/bin/env python3
"""Prove from the shipped bytes that no key rode along and that each artifact is
the tool it claims to be.

`tests/custody.rs` asserts the custody boundary at source level: no signing crate
in the resolved graph, no key spelling in any compiled file. `tests/tool_identity.rs`
pins the package id an operator configures against the tool name the host
dispatches. Both read the tree. Neither reads the file an operator actually
installs, so neither would notice a key pasted into a build that was never
committed. Neither would notice one plugin's `.wasm` shipped under another
plugin's name. This script is the artifact-level half of those two tests, run
against the bytes with the Python standard library, offline, in about a second.

Two independent proofs.

Proof one: no key material in the shipped data sections. The artifacts are
component-model binaries wrapping core modules, so this walks the top-level
sections, finds the nested core modules and reads their data sections, which is
where Rust puts string literals. Then it looks for the four shapes a key takes
once it is text: PEM or OpenSSH armour, a base58 run long enough to be a keypair,
a bare 64 character hex run and the JSON byte array `solana-keygen` writes.

Proof two: export identity. The component-level export section has to name
exactly the two interfaces a ZeroClaw tool plugin serves and the core module has
to export exactly the canonical ABI functions behind them. The package id plus
the tool name in the data have to be the pair this plugin's `manifest.toml`
declares, with no other suite package id present. That last part is what turns a
swapped or mislabelled artifact red instead of green.

Every threshold below was tuned against the real artifacts and the margin is
printed on every run, because a check that cannot fail is worth nothing. The
tamper cases it was proven against are in the packet.

What a passing run does not prove, stated here because a narrow proof beats one
that oversells itself:

  * a 32 byte secret on its own. Base58 or hex, it is the same encoding of the
    same number of bytes as a public key, so no length and no symbol
    distribution separates the two. The base58 threshold sits at the 64 byte
    keypair form for that reason and a bare seed would walk past it.
  * a key that is not stored as text. Bytes baked into the code section as
    constants, into an element segment or into a table are never read here.
  * a key in a custom section. `component-name` and `producers` are skipped,
    and so is anything a post-processing step staples on.
  * a key that is compressed, encrypted, XORed or split across two segments. A
    substring scan sees plain text or it sees nothing.
  * a key fetched at run time. The claim is about what ships in the file, not
    about what a running plugin could be handed. `verify-capabilities.py` covers
    the other half from the capability list: no filesystem, no sockets, no
    signing import, so there is nowhere to fetch a key from and nothing to do
    with one.

Usage:

    python3 demo/verify-artifact-hygiene.py                       # the staged artifacts
    python3 demo/verify-artifact-hygiene.py path/to/one.wasm ...   # explicit paths
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

# PEM and OpenSSH armour. The header line is the part no encoder omits, so it is
# the whole check: if one of these lands in a data segment, something pasted a
# private key into the build.
KEY_ARMOUR = (
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
    "PuTTY-User-Key-File",
)

BASE58_RUN = re.compile(rb"[1-9A-HJ-NP-Za-km-z]+")
HEX_RUN = re.compile(rb"[0-9a-fA-F]+")
BYTE_ARRAY = re.compile(rb"\[\s*[0-9][0-9,\s]*[0-9]\s*\]")

# Where the base58 threshold comes from, because the obvious number is the wrong
# one. Solana writes keys and addresses in base58 over the Bitcoin alphabet, 58
# symbols, so a character carries log2(58) = 5.86 bits.
#
#   * a 32 byte secret (the ed25519 seed) is 256 bits. 256 / 5.86 = 43.7, so 44
#     characters (43 when the value falls below 58^43)
#   * a 64 byte keypair (seed then public key, what `solana-keygen` holds and
#     what a wallet exports as a single base58 string) is 512 bits.
#     512 / 5.86 = 87.4, so 88 characters (87 at the low end)
#
# 44 is useless as a threshold. Every Solana public key and every program id is
# also 32 bytes. These components embed several on purpose, so a 44 character
# rule fires on the SPL Token program id and on nothing worth knowing about. 87
# is the shortest length no single address can reach, so that is where the line
# sits: it catches the exported-keypair form and it misses a bare seed, which
# the header says out loud.
BASE58_KEYPAIR_MIN = 87

# The addresses this suite embeds by design, each a named constant in
# `solana-core/src/pubkey.rs`. They are masked out before the run scan because
# literals land in a data segment end to end with no separator between them:
# three program ids in a row read as one 149 character base58 run and would trip
# any honest threshold. Masking these four leaves the longest surviving run at
# 77 on all three artifacts, a 10 character margin under the 87 above. The run
# below prints that number every time, so the margin is not a claim in a comment.
PINNED_ADDRESSES = (
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token program
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",  # associated token account program
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",  # SPL Memo program
    "SysvarRecentB1ockHashes11111111111111111111",  # recent blockhashes sysvar
)

# A raw 32 byte key is usually pasted as 64 hex characters, so the length is
# exact. Length alone is not enough here: these components carry itoa's two
# digit decimal table, 400 characters of nothing but digits, which is 337
# overlapping 64 character hex windows. So a window also has to look random. A
# uniform 32 byte key spends about 15.7 of the 16 hex symbols and the chance it
# spends 12 or fewer is under 2e-5, bounded by C(16,12) * (12/16)^64. The
# richest window in the real artifacts spends 10. 13 sits between the two.
HEX_KEY_LEN = 64
HEX_KEY_MIN_SYMBOLS = 13

# `solana-keygen new -o id.json` writes the 64 byte keypair as a JSON array of
# decimal bytes, which is the file people paste into a config by accident. 32 is
# the floor so a bare seed array is caught too. Nothing in the real artifacts is
# shaped like this at all, so this one has no tuning to defend.
BYTE_ARRAY_MIN_ELEMENTS = 32

# The complete component-level export surface of a ZeroClaw tool plugin. Exactly
# these two instances: an extra export is a surface the host never asked for and
# a missing one is a plugin the host cannot call.
EXPECTED_COMPONENT_EXPORTS = {
    "zeroclaw:plugin/plugin-info@0.1.0",
    "zeroclaw:plugin/tool@0.1.0",
}

# The canonical ABI functions the core module has to export to serve those two
# interfaces. `wit_bindgen` spells them `<interface>#<function>`.
EXPECTED_ABI_FUNCTIONS = {
    "zeroclaw:plugin/plugin-info@0.1.0#plugin-name",
    "zeroclaw:plugin/plugin-info@0.1.0#plugin-version",
    "zeroclaw:plugin/tool@0.1.0#description",
    "zeroclaw:plugin/tool@0.1.0#execute",
    "zeroclaw:plugin/tool@0.1.0#name",
    "zeroclaw:plugin/tool@0.1.0#parameters-schema",
}

# Plumbing that is allowed alongside them. `cabi_post_*` frees a returned list
# once the host has copied it out, `cabi_realloc` is the ABI's allocator hook.
ALLOWED_CORE_EXPORTS = (
    {"memory", "cabi_realloc"}
    | EXPECTED_ABI_FUNCTIONS
    | {f"cabi_post_{name}" for name in EXPECTED_ABI_FUNCTIONS}
)

# Every package id in the suite. An artifact has to carry its own and none of the
# others. The hyphenated form is the discriminator rather than the underscored
# tool name, because tool names turn up in prose: `nonce_status` names
# `spl_transfer_build` in its own description, so `spl_transfer_build` is in its
# data legitimately while `spl-transfer-build` is not.
SUITE_PACKAGE_IDS = ("nonce-status", "payment-watch", "spl-transfer-build")

# The bytes this script was written against. Size and digest both, because a
# length collision is cheap and a sha256 collision is not.
PINNED = {
    "nonce_status.wasm": (332253, "ffd4f0ad"),
    "payment_watch.wasm": (367973, "7f6b8106"),
    "spl_transfer_build.wasm": (409058, "d57ad6be"),
}

COMPONENT_PREAMBLE = b"\x00asm\x0d\x00\x01\x00"

REPO_ROOT = Path(__file__).resolve().parent.parent
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


def sections(binary: bytes) -> list[tuple[int, bytes]]:
    """Every top-level section as (id, body), past the 8 byte preamble.

    Strict on purpose, unlike the lenient walk in `verify-capabilities.py`. A key
    scan that shrugs at trailing garbage is a key scan you can defeat by stapling
    bytes onto the end of the file, so a section id out of range or a length that
    runs past the end raises here and the caller reports it as a failure.
    """
    found: list[tuple[int, bytes]] = []
    offset = 8
    while offset < len(binary):
        section_id = binary[offset]
        offset += 1
        if section_id > 12:
            raise ValueError(f"section id {section_id} at offset {offset - 1} is not a section")
        size, offset = read_leb128(binary, offset)
        if offset + size > len(binary):
            raise ValueError(f"section {section_id} claims {size} bytes past the end of the file")
        found.append((section_id, binary[offset : offset + size]))
        offset += size
    return found


def core_modules(component: bytes) -> list[bytes]:
    """The core modules nested in the component, section id 1 with a wasm preamble."""
    return [body for section_id, body in sections(component) if section_id == 1 and body[:4] == b"\x00asm"]


def core_data(module: bytes) -> list[bytes]:
    """Every data segment payload of a core module, from its data section id 11.

    Active segments carry a constant offset expression the payload does not need,
    so it is stepped over to the `end` opcode. Passive segments carry none.
    """
    payloads: list[bytes] = []
    for section_id, body in sections(module):
        if section_id != 11:
            continue
        offset = 0
        count, offset = read_leb128(body, offset)
        for _ in range(count):
            flags, offset = read_leb128(body, offset)
            if flags == 2:
                _memory, offset = read_leb128(body, offset)
            if flags in (0, 2):
                while body[offset] != 0x0B:
                    offset += 1
                offset += 1
            length, offset = read_leb128(body, offset)
            payloads.append(body[offset : offset + length])
            offset += length
    return payloads


def core_exports(module: bytes) -> list[str]:
    """The names a core module exports, from its export section id 7."""
    names: list[str] = []
    for section_id, body in sections(module):
        if section_id != 7:
            continue
        offset = 0
        count, offset = read_leb128(body, offset)
        for _ in range(count):
            length, offset = read_leb128(body, offset)
            names.append(body[offset : offset + length].decode("utf-8", "replace"))
            offset += length
            offset += 1  # export kind
            _index, offset = read_leb128(body, offset)
    return names


def component_exports(component: bytes) -> list[str]:
    """The names the component itself exports, from its export sections id 11.

    Parsed by the layout rather than sniffed out of the bytes, because an export
    is the thing being proved here and a sniffer that misses one reports a clean
    surface it never read. Each entry is a name, a sortidx and an optional type
    ascription. Anything the layout does not account for raises.
    """
    names: list[str] = []
    for section_id, body in sections(component):
        if section_id != 11:
            continue
        offset = 0
        count, offset = read_leb128(body, offset)
        for _ in range(count):
            tag = body[offset]
            offset += 1
            if tag not in (0x00, 0x01):
                raise ValueError(f"export name tag {tag} is not a name")
            length, offset = read_leb128(body, offset)
            names.append(body[offset : offset + length].decode("utf-8", "replace"))
            offset += length
            sort = body[offset]
            offset += 1
            if sort == 0x00:
                offset += 1  # core sort, one more byte
            _index, offset = read_leb128(body, offset)
            ascribed = body[offset]
            offset += 1
            if ascribed == 0x01:
                kind = body[offset]
                offset += 1
                if kind == 0x00:
                    offset += 1  # core type marker
                _type_index, offset = read_leb128(body, offset)
            elif ascribed != 0x00:
                raise ValueError(f"export type ascription {ascribed} is neither absent nor present")
        if offset != len(body):
            raise ValueError(f"export section left {len(body) - offset} bytes unread")
    return names


def base58_runs(data: bytes) -> list[bytes]:
    """Base58 runs left once the addresses this suite embeds on purpose are gone.

    Longest first, masked in descending length so a short address cannot eat part
    of a longer one.
    """
    masked = data
    for address in sorted(PINNED_ADDRESSES, key=len, reverse=True):
        masked = masked.replace(address.encode(), b"\n")
    return sorted(BASE58_RUN.findall(masked), key=len, reverse=True)


def hex_runs_scored(data: bytes) -> tuple[list[tuple[bytes, int]], int]:
    """The richest 64 character window in each long enough hex run, richest first.

    One entry per run rather than one per window. A key pasted into a run of
    digits produces dozens of overlapping hits and a failure report nobody can
    read is a failure report nobody reads. The symbol count is case folded,
    because hex case carries no information.
    """
    scored: list[tuple[bytes, int]] = []
    windows = 0
    for run in HEX_RUN.findall(data):
        if len(run) < HEX_KEY_LEN:
            continue
        best = b""
        best_symbols = 0
        for start in range(len(run) - HEX_KEY_LEN + 1):
            window = run[start : start + HEX_KEY_LEN]
            symbols = len(set(window.lower()))
            if symbols > best_symbols:
                best, best_symbols = window, symbols
        windows += len(run) - HEX_KEY_LEN + 1
        scored.append((best, best_symbols))
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored, windows


def keypair_arrays(data: bytes) -> list[bytes]:
    """Bracketed decimal lists shaped like the JSON a keypair file holds."""
    found: list[bytes] = []
    for literal in BYTE_ARRAY.findall(data):
        parts = literal[1:-1].split(b",")
        if len(parts) < BYTE_ARRAY_MIN_ELEMENTS:
            continue
        if all(part.strip().isdigit() and int(part) <= 255 for part in parts):
            found.append(literal)
    return found


def manifest_names(path: Path) -> tuple[Path, str, str]:
    """The manifest that governs this artifact, plus the package id and wasm_path.

    Staged artifacts sit beside their own manifest, which is the pairing an
    operator installs. A path out of the build directory falls back to the plugin
    the file name points at, so the check still resolves for
    `target-shared/wasm32-wasip2/release/*.wasm`.
    """
    candidates = [
        path.parent / "manifest.toml",
        REPO_ROOT / "plugins" / path.stem.replace("_", "-") / "manifest.toml",
    ]
    for manifest in candidates:
        if not manifest.is_file():
            continue
        fields: dict[str, str] = {}
        for line in manifest.read_text().splitlines():
            stripped = line.strip()
            for key in ("name", "wasm_path"):
                prefix = f"{key} = "
                if stripped.startswith(prefix) and key not in fields:
                    fields[key] = stripped[len(prefix) :].strip().strip('"')
        if "name" in fields and "wasm_path" in fields:
            return manifest, fields["name"], fields["wasm_path"]
    raise FileNotFoundError(
        f"no manifest declaring name and wasm_path beside {path.name} or under plugins/"
    )


def scan_for_keys(data: bytes, problems: list[str]) -> None:
    """Proof one, printed with its own margins so the thresholds stay checkable."""
    print("  no key material in the data sections")

    armour = [header for header in KEY_ARMOUR if header.encode() in data]
    for header in armour:
        problems.append(f"private key armour in the data: {header}")
    print(f"    PEM and OpenSSH armour: {', '.join(armour) if armour else f'none of {len(KEY_ARMOUR)} headers'}")

    runs = base58_runs(data)
    longest = len(runs[0]) if runs else 0
    for run in runs:
        if len(run) >= BASE58_KEYPAIR_MIN:
            problems.append(f"base58 run of {len(run)} could be a 64 byte keypair: {run[:24].decode()}...")
    print(
        f"    base58 runs of {BASE58_KEYPAIR_MIN}+ (a keypair takes 87 to 88):"
        f" {sum(1 for r in runs if len(r) >= BASE58_KEYPAIR_MIN)}, longest run is {longest}"
    )

    scored, windows = hex_runs_scored(data)
    richest = scored[0][1] if scored else 0
    for window, symbols in scored:
        if symbols >= HEX_KEY_MIN_SYMBOLS:
            problems.append(f"64 character hex run spending {symbols} symbols: {window.decode()}")
    print(
        f"    hex runs of {HEX_KEY_LEN} spending {HEX_KEY_MIN_SYMBOLS}+ of the 16 symbols:"
        f" {sum(1 for _, s in scored if s >= HEX_KEY_MIN_SYMBOLS)} of {len(scored)} runs"
        f" ({windows} windows), richest spends {richest}"
    )

    arrays = keypair_arrays(data)
    for literal in arrays:
        problems.append(f"JSON byte array shaped like a keypair file: {literal[:32].decode()}...")
    print(f"    JSON byte arrays of {BYTE_ARRAY_MIN_ELEMENTS}+ elements in 0..255: {len(arrays)}")


def check_identity(path: Path, binary: bytes, data: bytes, problems: list[str]) -> None:
    """Proof two: the export surface and the two names have to be this plugin's."""
    print("  export identity")

    exported = component_exports(binary)
    print(f"    component exports: {', '.join(sorted(exported)) if exported else 'NONE'}")
    for name in sorted(set(exported) - EXPECTED_COMPONENT_EXPORTS):
        problems.append(f"component exports {name}, which is not part of a tool plugin")
    for name in sorted(EXPECTED_COMPONENT_EXPORTS - set(exported)):
        problems.append(f"component does not export {name}, so the host cannot call it")

    modules = core_modules(binary)
    module_exports = [core_exports(module) for module in modules]
    guests = [index for index, names in enumerate(module_exports) if "memory" in names]
    if len(guests) != 1:
        problems.append(f"expected one guest core module exporting memory, found {len(guests)}")
    guest = module_exports[guests[0]] if len(guests) == 1 else []
    for name in sorted(EXPECTED_ABI_FUNCTIONS - set(guest)):
        problems.append(f"the guest module does not export {name}")
    for name in sorted(set(guest) - ALLOWED_CORE_EXPORTS):
        problems.append(f"the guest module exports {name}, which is not on the ABI list")
    for index, names in enumerate(module_exports):
        if index in guests:
            continue
        for name in names:
            if name != "$imports" and not name.isdigit():
                problems.append(f"adapter module exports {name}, which is not a canonical index")
    print(
        f"    canonical ABI: {len(EXPECTED_ABI_FUNCTIONS & set(guest))} of"
        f" {len(EXPECTED_ABI_FUNCTIONS)} functions present, {len(guest)} guest exports,"
        f" {sum(len(n) for n in module_exports) - len(guest)} adapter exports"
    )

    manifest, package_id, wasm_path = manifest_names(path)
    tool_name = package_id.replace("-", "_")
    shown = manifest.relative_to(REPO_ROOT) if REPO_ROOT in manifest.parents else manifest
    print(f"    {shown} declares {package_id} -> {wasm_path}")
    if wasm_path != path.name:
        problems.append(f"the manifest ships {wasm_path}, this file is {path.name}")
    if wasm_path != f"{tool_name}.wasm":
        problems.append(f"wasm_path {wasm_path} is not {tool_name}.wasm, the documented transform")

    own = data.count(package_id.encode())
    tool = data.count(tool_name.encode())
    print(f"    in the data: package id {package_id} x{own}, tool name {tool_name} x{tool}")
    if not own:
        problems.append(f"the data carries no {package_id}, so these are not that package's bytes")
    if not tool:
        problems.append(f"the data carries no {tool_name}, so the tool name is not in this artifact")

    foreign = [other for other in SUITE_PACKAGE_IDS if other != package_id and other.encode() in data]
    for other in foreign:
        problems.append(f"the data carries {other}: this is another plugin's artifact")
    print(f"    other suite package ids: {', '.join(foreign) if foreign else 'none of the other 2'}")


def check(path: Path) -> bool:
    binary = path.read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    problems: list[str] = []
    print(f"\n{path.name}  {len(binary)} bytes  sha256 {digest[:8]}")

    if binary[:8] != COMPONENT_PREAMBLE:
        print(f"  FAIL preamble {binary[:8].hex(' ')} is not a wasm component")
        return False

    try:
        modules = core_modules(binary)
        segments = [segment for module in modules for segment in core_data(module)]
        data = b"".join(segments)
        print(
            f"  {len(modules)} core modules, {len(segments)} data segments,"
            f" {len(data)} bytes of data scanned"
        )
        scan_for_keys(data, problems)
        check_identity(path, binary, data, problems)
    except (ValueError, IndexError, FileNotFoundError) as failure:
        print(f"  FAIL the artifact does not read as a well formed component: {failure}")
        return False

    expected = PINNED.get(path.name)
    if expected is None:
        problems.append(f"{path.name} is not one of the pinned artifacts")
        print("  digest: this file name is not pinned")
    else:
        size, prefix = expected
        if len(binary) != size:
            problems.append(f"size {len(binary)} is not the pinned {size}")
        if not digest.startswith(prefix):
            problems.append(f"sha256 {digest[:8]} is not the pinned {prefix}")
        print(f"  digest: pinned at {size} bytes and sha256 {prefix}")

    for problem in problems:
        print(f"  FAIL {problem}")
    if not problems:
        print("  PASS no key material in the shipped bytes, exports match the manifest, digest matches")
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
        f"\n{sum(results)} of {len(results)} components pass the artifact hygiene check."
        " Both proofs read the bytes, so re-run them on any build you like."
    )
    return 0 if all(results) and len(results) == len(PINNED) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

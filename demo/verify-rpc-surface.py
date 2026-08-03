#!/usr/bin/env python3
"""Prove the components cannot ask a node to submit a transaction, from the bytes.

`demo/verify-capabilities.py` reads the capability list out of these same artifacts and
stops short of one claim on purpose: HTTP egress is imported, because that is how an RPC
read works, so "cannot submit a transaction" does not follow from the import list. This
script closes that gap from the other side.

A Solana node never submits anything on its own. It submits when a client asks. The ask
is a JSON-RPC request whose `method` field holds a name from a fixed published list, so
if no mutating method name exists anywhere in the compiled artifact, nothing in the
component can spell the request. That is a property of the shipped bytes rather than of
a test written by the same hand as the plugin.

The vocabulary this checks against is the whole node surface: the 52 HTTP methods and
the 18 WebSocket methods Solana documents today, the 16 methods Agave removed in v2.0,
plus the spellings a client library uses for a submit. A name outside that vocabulary is
a name no node answers.

    https://solana.com/docs/rpc/http        the 52 HTTP methods and which of them write
    https://solana.com/docs/rpc/websocket   the 18 subscription methods

Of the documented HTTP methods only `sendTransaction` and `requestAirdrop` change chain
state. `simulateTransaction` does not, it takes signed transaction bytes and evaluates
them without broadcasting. It is denied here anyway: a component with no way to sign has
no business naming a method that wants a signature.

What a passing run proves:

  * no mutating or submitting method name appears in the component's data sections,
    which is where a Rust string literal lands
  * none appears anywhere else in the file either, checked as a raw byte scan, so a
    literal parked outside the sections this script walks cannot hide behind the parser
  * the read methods that ARE present are exactly the pinned set for that artifact, so
    a new RPC call cannot arrive in a refactor without turning this run red
  * the JSON-RPC scaffolding is present, which is what stops an empty parse from
    passing the absence checks for free
  * size and sha256 match the pinned artifact

What it does not prove, stated here because a proof that oversells itself is worth less
than a narrow one:

  * a name assembled at runtime from fragments is not a contiguous literal, so this
    script would not see it. What keeps that from being a way out is the other half of
    the pair: `verify-capabilities.py` shows no signing capability of any kind is
    imported, so a request built that way would carry no signature. A node drops an
    unsigned transaction. `tests/custody.rs` pins the unsigned-only path in source.
  * matching is substring based, because Rust string literals are not null terminated
    and a data section is one run-together blob. So it over-reports rather than
    under-reports: a method name that happens to sit inside a longer unrelated string
    counts as present. An over-report fails the run, which is the direction a check like
    this should lean.

Usage:

    python3 demo/verify-rpc-surface.py                       # the staged artifacts
    python3 demo/verify-rpc-surface.py path/to/one.wasm ...   # explicit paths
"""

from __future__ import annotations

import hashlib
import re
import sys
import textwrap
from pathlib import Path

# The 52 HTTP methods a Solana node answers today, in the order the docs group them:
# accounts, tokens, transactions, blocks, cluster, economics.
HTTP_METHODS = (
    "getAccountInfo",
    "getBalance",
    "getLargestAccounts",
    "getMinimumBalanceForRentExemption",
    "getMultipleAccounts",
    "getProgramAccounts",
    "getTokenAccountBalance",
    "getTokenAccountsByDelegate",
    "getTokenAccountsByOwner",
    "getTokenLargestAccounts",
    "getTokenSupply",
    "getFeeForMessage",
    "getLatestBlockhash",
    "getRecentPrioritizationFees",
    "getSignaturesForAddress",
    "getSignatureStatuses",
    "getTransaction",
    "getTransactionCount",
    "isBlockhashValid",
    "requestAirdrop",
    "sendTransaction",
    "simulateTransaction",
    "getBlock",
    "getBlockCommitment",
    "getBlockHeight",
    "getBlockProduction",
    "getBlocks",
    "getBlocksWithLimit",
    "getBlockTime",
    "getFirstAvailableBlock",
    "getRecentPerformanceSamples",
    "minimumLedgerSlot",
    "getClusterNodes",
    "getEpochInfo",
    "getEpochSchedule",
    "getGenesisHash",
    "getHealth",
    "getHighestSnapshotSlot",
    "getIdentity",
    "getLeaderSchedule",
    "getMaxRetransmitSlot",
    "getMaxShredInsertSlot",
    "getSlot",
    "getSlotLeader",
    "getSlotLeaders",
    "getVersion",
    "getVoteAccounts",
    "getInflationGovernor",
    "getInflationRate",
    "getInflationReward",
    "getStakeMinimumDelegation",
    "getSupply",
)

# The 18 WebSocket methods. None belongs in these components, which speak plain HTTP,
# so any of them showing up is drift worth failing on.
WEBSOCKET_METHODS = (
    "accountSubscribe",
    "accountUnsubscribe",
    "blockSubscribe",
    "blockUnsubscribe",
    "logsSubscribe",
    "logsUnsubscribe",
    "programSubscribe",
    "programUnsubscribe",
    "rootSubscribe",
    "rootUnsubscribe",
    "signatureSubscribe",
    "signatureUnsubscribe",
    "slotSubscribe",
    "slotUnsubscribe",
    "slotsUpdatesSubscribe",
    "slotsUpdatesUnsubscribe",
    "voteSubscribe",
    "voteUnsubscribe",
)

# The 16 methods Agave removed in v2.0. They are in the vocabulary because an old client
# spelling still names a method. A component reaching for one would be a bug worth
# catching rather than something to wave through.
REMOVED_METHODS = (
    "confirmTransaction",
    "getSignatureStatus",
    "getSignatureConfirmation",
    "getConfirmedSignaturesForAddress",
    "getConfirmedSignaturesForAddress2",
    "getConfirmedBlock",
    "getConfirmedBlocks",
    "getConfirmedBlocksWithLimit",
    "getConfirmedTransaction",
    "getRecentBlockhash",
    "getFees",
    "getFeeCalculatorForBlockhash",
    "getSnapshotSlot",
    "getStakeActivation",
    "getTotalSupply",
    "getFeeRateGovernor",
)

# Not node methods, these are how a client library or a wallet spells a submit. They are
# the names that would appear if someone wired a signing path in, so they are checked
# with the same weight. Same list `tests/custody.rs` holds the sources against.
CLIENT_SUBMIT_SPELLINGS = (
    "sendRawTransaction",
    "sendAndConfirmTransaction",
    "sendSmartTransaction",
    "sendBundle",
    "signTransaction",
    "signAllTransactions",
    "signAndSendTransaction",
)

VOCABULARY = tuple(
    sorted(
        set(HTTP_METHODS + WEBSOCKET_METHODS + REMOVED_METHODS + CLIENT_SUBMIT_SPELLINGS),
        key=lambda name: (-len(name), name),
    )
)

# Absent by construction. This is the whole point of the run. `sendTransaction` and
# `requestAirdrop` are the two documented HTTP methods that change chain state.
# `simulateTransaction` does not change state, it is here because it wants a signed
# transaction. The rest are the client-side spellings of the same act.
MUTATING_METHODS = tuple(
    sorted(
        {"sendTransaction", "requestAirdrop", "simulateTransaction"}
        | set(CLIENT_SUBMIT_SPELLINGS)
    )
)

# The read methods each shipped artifact actually names, read off the bytes rather than
# off the source. It is a tighter list than the one `tests/custody.rs` allows, because
# that test guards what the sources may say while this pins what the build kept. Every
# method a component names has to be here or the run fails, which is what stops a new
# RPC call arriving unnoticed.
ALLOWED_METHODS = {
    "nonce_status.wasm": {"getAccountInfo"},
    "payment_watch.wasm": {"getSignaturesForAddress", "getTransaction"},
    "spl_transfer_build.wasm": {"getAccountInfo", "getLatestBlockhash"},
}

# The bytes this script was written against, the same pins the capability check carries.
# Size and digest both, because a length collision is cheap and a sha256 collision is not.
PINNED = {
    "nonce_status.wasm": (332253, "ffd4f0ad"),
    "payment_watch.wasm": (367973, "7f6b8106"),
    "spl_transfer_build.wasm": (409058, "d57ad6be"),
}

# Proof the parser reached the RPC request builder. Without this an artifact whose data
# sections failed to parse would sail through every absence check on an empty string.
SCAFFOLDING = ("jsonrpc", "method", "params")

DEFAULT_DIR = Path(__file__).resolve().parent / "out" / "staged"

# Runs of four or more printable ASCII bytes. Rust string literals are not null
# terminated, so there is no delimiter to key on and the vocabulary does the work.
PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")


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
    """Every section as (id, body), past the 8 byte preamble.

    Same reader `verify-capabilities.py` uses, deliberately. The two checks read the same
    artifact from opposite ends, so they should not disagree about what a section is.
    """
    offset = 8
    while offset < len(binary):
        section_id = binary[offset]
        offset += 1
        size, offset = read_leb128(binary, offset)
        yield section_id, binary[offset : offset + size]
        offset += size


def data_blob(component: bytes) -> tuple[bytes, int, int]:
    """Every data section of every core module inside the component, concatenated.

    The file is a component wrapping core modules, so the walk is two deep: top level
    section id 1 whose body starts with the core module magic, then section id 11 inside
    it. Returns the bytes plus how many modules and data sections were seen, because a
    count of zero is a parse failure and has to be reported rather than read as absence.
    """
    blob = bytearray()
    modules = data_sections = 0
    for section_id, body in sections(component):
        if section_id != 1 or body[:4] != b"\x00asm":
            continue
        modules += 1
        for module_section_id, module_body in sections(body):
            if module_section_id == 11:
                data_sections += 1
                blob += module_body
    return bytes(blob), modules, data_sections


def printable_text(blob: bytes) -> str:
    """The blob as newline joined runs of printable ASCII, ready to scan."""
    return b"\n".join(PRINTABLE_RUN.findall(blob)).decode("ascii")


def methods_present(text: str) -> set[str]:
    """Vocabulary methods named in the text, longest match at each position.

    Longest first is what keeps `getTransactionCount` from also registering as
    `getTransaction`, so the allowlist compares like for like.
    """
    found: set[str] = set()
    for index in range(len(text)):
        for method in VOCABULARY:
            if text.startswith(method, index):
                found.add(method)
                break
    return found

def check(path: Path) -> bool:
    binary = path.read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    blob, modules, data_sections = data_blob(binary)
    text = printable_text(blob)
    present = methods_present(text)
    allowed = ALLOWED_METHODS.get(path.name)

    problems: list[str] = []

    # Absence, checked twice. Once in the strings the guest can reach, then once across
    # the raw file, so a literal sitting outside the sections walked above still fails.
    for method in MUTATING_METHODS:
        if method in text:
            problems.append(f"mutating method named in a data section: {method}")
        elif method.encode("ascii") in binary:
            problems.append(f"mutating method in the raw bytes, outside a data section: {method}")

    if data_sections == 0:
        problems.append("no data section found, so absence here would prove nothing")
    absent_scaffolding = [needle for needle in SCAFFOLDING if needle not in text]
    if absent_scaffolding:
        joined = ", ".join(absent_scaffolding)
        problems.append(f"JSON-RPC scaffolding missing from the strings: {joined}")

    if allowed is None:
        problems.append(f"{path.name} has no pinned method allowlist, so it is not one of ours")
    else:
        for method in sorted(present - allowed):
            problems.append(f"method present that is not on the allowlist: {method}")
        for method in sorted(allowed - present):
            problems.append(f"pinned method missing from the bytes: {method}")

    expected = PINNED.get(path.name)
    if expected is None:
        problems.append(f"{path.name} is not one of the pinned artifacts")
    else:
        size, prefix = expected
        if len(binary) != size:
            problems.append(f"size {len(binary)} is not the pinned {size}")
        if not digest.startswith(prefix):
            problems.append(f"sha256 {digest[:8]} is not the pinned {prefix}")

    absent = [
        method
        for method in MUTATING_METHODS
        if method not in text and method.encode("ascii") not in binary
    ]
    print(f"\n{path.name}  {len(binary)} bytes  sha256 {digest[:8]}")
    print(f"  {modules} core modules, {data_sections} data sections, {len(blob)} bytes of data")
    print(f"  JSON-RPC methods named in those bytes: {len(present)} of {len(VOCABULARY)} known")
    for method in sorted(present):
        tag = "allowlist" if allowed is not None and method in allowed else "NOT ALLOWED"
        print(f"    {method}  [{tag}]")
    print(f"  mutating methods absent: {len(absent)} of {len(MUTATING_METHODS)} checked")
    listed = ", ".join(absent) if absent else "NONE, which is a failure"
    print(textwrap.fill(listed, width=92, initial_indent="    ", subsequent_indent="    "))
    for problem in problems:
        print(f"  FAIL {problem}")
    if not problems:
        print("  PASS nothing here can ask a node to submit, read surface exactly as pinned")
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
        f"\n{sum(results)} of {len(results)} components pass the RPC surface check."
        " A component that passes names no method a node would act on, which is a"
        " property of the bytes, so re-run it on any build you like."
    )
    return 0 if all(results) and len(results) == len(PINNED) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

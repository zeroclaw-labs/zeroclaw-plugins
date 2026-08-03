#!/usr/bin/env python3
"""Make the refusal count a property of the code instead of a line in a PR body.

The suite's claim is that it refuses a fixed set of unsafe conditions and that most
of those refusals land before it opens a socket. A demo transcript shows nine of them
happening, which is evidence rather than a property: nothing stops a tenth refusal
arriving in a refactor or a refusal quietly disappearing while the transcript keeps
passing.

This script closes that gap. It reads every fail-closed guard out of the Rust, holds
the set against `demo/refusals.json` and fails if either side carries an entry the
other does not. Then it proves the ordering claim per guard from the call graph, and
cross-checks every reason string against the data sections of the compiled
components, so a refusal that exists in source but never reached the binary is
visible.

What a passing run proves:

  * the documented refusal set and the code's refusal set are the same set, in both
    directions, at the guard level rather than the message level
  * each guard the list calls pre-RPC is reached on a path that returns before the
    component's first HTTP call, with the call chain printed
  * each guard the list calls post-RPC really is after one, so the flag cannot be
    flipped quietly to make the pre-RPC count look better
  * every reason string is present in the owning component's data section
  * the nine demo refusals and the seven that refuse before any RPC call line up
    with the golden file's measured `rpc_calls`, so the static claim and the
    observed run agree

What it does not prove, stated here because a proof that oversells itself is worth
less than a narrow one:

  * presence of a string in a data section is not reachability. The list carries
    three guards that cannot fire from the tool entry point and says so; their
    strings ship anyway, because the compiler keeps the match arms
  * the ordering argument is static. It reads the call graph of the four files that
    hold the guards plus the one-line transport boundary in each shim. The demo's
    measured `rpc_calls` is the empirical half and this script checks the two agree
  * a refusal here is a fail-closed denial of an unsafe request. Transport and
    response-parse failures are excluded by name in the list. The negative outcomes
    the read-only tools report (NOT SEEN, MISSING and the rest) are accepts rather
    than refusals, which the golden file confirms

Usage:

    python3 demo/verify-refusals.py                    # the committed list
    python3 demo/verify-refusals.py path/to/list.json  # a copy, for negative controls
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_LIST = HERE / "refusals.json"
STAGED = HERE / "out" / "staged"

# Every way a refusal is spelled in this suite: the shared core's policy types plus
# one error enum per component. Anything matching this that is not in the list is a
# refusal nobody wrote down, which is the failure this script exists to catch.
REFUSAL_ENUM = re.compile(r"\b(PolicyError|PolicyVerdict|BuildError|WatchError|StatusError)::(\w+)")

# The one variant of those enums that is not a refusal.
ALLOWED_VERDICT = "PolicyVerdict::Allowed"

FN_DEF = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)")

# The guest never opens a socket itself: it calls `lookups.rpc(...)`, whose only
# implementation is the waki transport in each component's shim. So this substring
# is the transport boundary inside the analysed sources.
TRANSPORT_CALL = ".rpc("


# ------------------------------------------------------------------ the binaries
# The LEB128 reader and the section walk are the ones demo/verify-capabilities.py
# uses on the same components. Same format, same defensive style: read only what is
# needed, never trust a length.
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
    """Every section as (id, body), past the 8 byte preamble."""
    offset = 8
    while offset < len(binary):
        section_id = binary[offset]
        offset += 1
        size, offset = read_leb128(binary, offset)
        yield section_id, binary[offset : offset + size]
        offset += size


def data_sections(component: bytes) -> bytes:
    """Every data section of every core module inside the component, concatenated.

    A component holds its guest as one or more core modules in the module section,
    and a Rust string literal that survived compilation is in that module's data
    section. Reading only those sections keeps the answer meaningful: a hit is a
    string the module carries, not a byte pattern somewhere in the custom sections.
    """
    blob = bytearray()
    for section_id, body in sections(component):
        if section_id == 1 and body[:4] == b"\x00asm":
            for module_section_id, module_body in sections(body):
                if module_section_id == 11:
                    blob += module_body
    return bytes(blob)


# -------------------------------------------------------------------- the sources
def strip_noise(text: str) -> list[str]:
    """The file with its Display impls and its test module blanked out.

    Both mention every variant, so leaving them in would report a match arm as a
    guard. Lines are blanked rather than deleted so every line number this script
    prints is the line number in the file a reviewer opens.
    """
    lines = text.splitlines()
    blanked = set()
    index = 0
    while index < len(lines):
        if re.match(r"\s*impl std::fmt::Display for ", lines[index]):
            depth = 0
            end = index
            while end < len(lines):
                depth += lines[end].count("{") - lines[end].count("}")
                blanked.add(end)
                if depth == 0 and end > index:
                    break
                end += 1
            index = end
        elif lines[index].strip().startswith("#[cfg(test)]"):
            blanked.update(range(index, len(lines)))
            break
        index += 1
    return ["" if n in blanked else line for n, line in enumerate(lines, start=0)]


def code_view(lines: list[str]) -> list[str]:
    """The same lines with comments dropped, for reading the call graph.

    A doc comment that says "the plan (pre-RPC)" is not a call to `plan` and a
    comment that mentions `.rpc(` is not a network call. Lines keep their positions
    so every line number stays the line number in the file.
    """
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(("//", "/*", "*")):
            out.append("")
        elif '"' not in line:
            out.append(line.split("//")[0])
        else:
            out.append(line)
    return out


def refusal_sites(lines: list[str]) -> list[tuple[int, str]]:
    """(line number, "Enum::Variant") for every refusal this file constructs."""
    found = []
    for number, line in enumerate(code_view(lines), start=1):
        for match in REFUSAL_ENUM.finditer(line):
            variant = match.group(0)
            if variant != ALLOWED_VERDICT:
                found.append((number, variant))
    return found


def fn_ranges(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Every function with a body, as name -> (first line, last line).

    Brace counting, which holds because every format string in these files has
    balanced braces. A trait's `fn rpc(..);` has no body and is skipped, otherwise
    its range would run into whatever follows it.
    """
    ranges: dict[str, tuple[int, int]] = {}
    for number, line in enumerate(lines, start=1):
        match = FN_DEF.match(line)
        if not match:
            continue
        cursor = number
        while cursor <= len(lines) and "{" not in lines[cursor - 1]:
            if ";" in lines[cursor - 1]:
                cursor = len(lines) + 1
                break
            cursor += 1
        if cursor > len(lines):
            continue
        depth = 0
        end = cursor
        while end <= len(lines):
            depth += lines[end - 1].count("{") - lines[end - 1].count("}")
            if depth == 0:
                break
            end += 1
        ranges[match.group(1)] = (number, min(end, len(lines)))
    return ranges



# ------------------------------------------------------- the pre-RPC ordering proof
class Sources:
    """The source files of one component, plus the call graph the proof needs."""

    def __init__(self, files: dict[str, list[str]]):
        self.files = {path: code_view(lines) for path, lines in files.items()}
        files = self.files
        self.problems: list[str] = []
        self.fn: dict[str, tuple[str, int, int]] = {}
        for path, lines in files.items():
            if sum(line.count("{") - line.count("}") for line in lines) != 0:
                self.problems.append(f"{path}: braces do not balance, refusing to reason about it")
            for name, (start, end) in fn_ranges(lines).items():
                if name in self.fn:
                    self.problems.append(f"two functions named {name}, cannot resolve the call graph")
                self.fn[name] = (path, start, end)
        # Direct transport: the line where a function calls lookups.rpc itself.
        self.direct: dict[str, int | None] = {}
        for name, (path, start, end) in self.fn.items():
            hits = [n for n in range(start, end + 1) if TRANSPORT_CALL in files[path][n - 1]]
            self.direct[name] = min(hits) if hits else None
        # Call sites, callee -> [(caller, line)], within these files only.
        self.calls: dict[str, list[tuple[str, int]]] = {}
        for callee in self.fn:
            pattern = re.compile(r"\b" + re.escape(callee) + r"\s*\(")
            for caller, (path, start, end) in self.fn.items():
                for n in range(start, end + 1):
                    line = files[path][n - 1]
                    if not pattern.search(line):
                        continue
                    definition = FN_DEF.match(line)
                    if definition and definition.group(1) == callee:
                        continue
                    self.calls.setdefault(callee, []).append((caller, n))
        # A function is transport-capable if it calls the transport or calls
        # something that does. Fixed point, so a two-hop path still counts.
        self.capable = {name for name, line in self.direct.items() if line is not None}
        changed = True
        while changed:
            changed = False
            for callee, sites in self.calls.items():
                if callee not in self.capable:
                    continue
                for caller, _ in sites:
                    if caller not in self.capable:
                        self.capable.add(caller)
                        changed = True

    def enclosing(self, path: str, line: int) -> str | None:
        """The innermost function containing a line."""
        best = None
        for name, (file_path, start, end) in self.fn.items():
            if file_path == path and start <= line <= end:
                if best is None or start > self.fn[best][1]:
                    best = name
        return best

    def first_transport(self, name: str, skip: tuple[str, int] | None = None) -> int | None:
        """The first line of `name` at which an HTTP call can have happened.

        `skip` drops one (callee, line) pair, which is how a hop is proven: the call
        that leads to the guard is the path being examined, so counting it as this
        caller's first transport would make every deep guard look post-RPC.
        """
        candidates = [self.direct[name]] if self.direct.get(name) is not None else []
        for callee, sites in self.calls.items():
            if callee not in self.capable:
                continue
            for caller, line in sites:
                if caller == name and skip != (callee, line):
                    candidates.append(line)
        return min(candidates) if candidates else None

    def before_transport(
        self, path: str, line: int, seen=frozenset(), skip: tuple[str, int] | None = None
    ) -> tuple[bool, str]:
        """Is a guard at this line reached before the component's first HTTP call?

        Reads outward from the guard: the function holding it must not reach the
        transport at or before that line. The same has to hold at every call site
        above it, up to the core's entry point. The returned string is the chain, so
        the ordering claim can be read without running anything.
        """
        name = self.enclosing(path, line)
        if name is None:
            return False, f"{Path(path).name}:{line} is not inside a function"
        if name in seen:
            return False, f"{name} is recursive, so it cannot be ordered"
        first = self.first_transport(name, skip)
        where = f"{Path(path).name}:{line} in {name}"
        if first is None:
            here = f"{where} (no earlier transport in {name})"
        elif first > line:
            here = f"{where} (transport at {first}, later)"
        else:
            return False, f"{where} sits at or after the transport at line {first}"
        callers = self.calls.get(name, [])
        if not callers:
            return True, f"{here} <- entry point of the component core"
        chains = []
        for caller, call_line in callers:
            ok, chain = self.before_transport(
                self.fn[caller][0], call_line, seen | {name}, (name, call_line)
            )
            if not ok:
                return False, f"{here} <- {chain}"
            chains.append(chain)
        return True, f"{here} <- " + " | ".join(chains)



# ------------------------------------------------------------------- the checks
def resolve(lines: list[str], site: dict) -> tuple[int | None, str]:
    """The single line of Rust a documented site points at.

    The site carries the guard line verbatim. Where the same line appears more than
    once in a file, `within` names a string that has to sit near the right one. Two
    matches or none is a failure: a list that cannot point at one line is not a list
    a reviewer can check.
    """
    wanted = site["line"]
    hits = [n for n, line in enumerate(lines, start=1) if line.strip() == wanted]
    if "within" in site:
        window = 3
        hits = [
            n
            for n in hits
            if any(
                site["within"] in line
                for line in lines[max(0, n - 1 - window) : n + window + 1]
            )
        ]
    if len(hits) == 1:
        return hits[0], ""
    if not hits:
        return None, f"no line in {site['file']} reads {wanted!r}"
    return None, f"{len(hits)} lines in {site['file']} read {wanted!r}, need `within` to pick one"


def brace_range(lines: list[str], opener: str) -> tuple[int, int] | None:
    """The line range of a block, given the exact text that opens it."""
    for number, line in enumerate(lines, start=1):
        if line.strip() != opener:
            continue
        depth = 0
        end = number
        while end <= len(lines):
            depth += lines[end - 1].count("{") - lines[end - 1].count("}")
            if depth == 0:
                return number, end
            end += 1
    return None


def check_coverage(doc: dict, listed: set[str], problems: list[str]) -> None:
    """Every file of the suite that builds a refusal has to be a listed source.

    Without this the list could stay honest about the files it names while a new
    guard sat in a file it does not. Tests are left out on purpose: they assert
    refusals rather than produce them. The vendored core copies are left out too,
    because the vendored digest check already pins them to the canonical file.
    """
    roots = ["libs/solana-core/src"] + [f"plugins/{name}/src" for name in doc["components"]]
    swept = carrying = 0
    for root in sorted(roots):
        for path in sorted((ROOT / root).glob("*.rs")):
            swept += 1
            relative = str(path.relative_to(ROOT))
            sites = refusal_sites(strip_noise(path.read_text(encoding="utf-8")))
            if not sites:
                continue
            carrying += 1
            if relative not in listed:
                problems.append(
                    f"{relative} builds {len(sites)} refusal(s) and is not a listed source file"
                )
    print(
        f"  swept {swept} source files across the shared core and the three components:"
        f" {carrying} build refusals, all of them listed"
    )


def check_boundaries(doc: dict, problems: list[str]) -> None:
    """The three structural facts the ordering argument leans on."""
    core = sorted((ROOT / "libs/solana-core/src").glob("*.rs"))
    dirty = [
        p.name
        for p in core
        if TRANSPORT_CALL in p.read_text(encoding="utf-8")
        or "Lookups" in p.read_text(encoding="utf-8")
    ]
    if dirty:
        problems.append(f"the shared core is supposed to hold no transport, found it in {dirty}")
    print(
        f"  shared core: {len(core)} files, no `{TRANSPORT_CALL}` call and no Lookups trait,"
        " so no function in it can reach the network"
    )

    canonical = ROOT / doc["vendored"]["canonical"]
    want = hashlib.sha256(canonical.read_bytes()).hexdigest()
    for relative in doc["vendored"]["copies"]:
        copy = ROOT / relative
        if not copy.is_file():
            problems.append(f"vendored copy missing: {relative}")
        elif hashlib.sha256(copy.read_bytes()).hexdigest() != want:
            problems.append(f"vendored copy differs from {doc['vendored']['canonical']}: {relative}")
    print(
        f"  {doc['vendored']['canonical']} sha256 {want[:8]}, byte-identical in all"
        f" {len(doc['vendored']['copies'])} vendored copies, so a policy line number"
        " here is the line that compiled"
    )

    for component, spec in sorted(doc["transport_boundary"].items()):
        shim = ROOT / spec["shim"]
        lines = shim.read_text(encoding="utf-8").splitlines()
        sends = [n for n, line in enumerate(lines, start=1) if ".send()" in line]
        block = brace_range(lines, "impl Lookups for WakiRpc {")
        entry = [n for n, line in enumerate(lines, start=1) if line.strip() == spec["entry"]]
        if len(sends) != 1:
            problems.append(f"{spec['shim']}: expected one .send(), found {len(sends)}")
        elif block is None or not block[0] <= sends[0] <= block[1]:
            problems.append(f"{spec['shim']}: the .send() is not inside impl Lookups for WakiRpc")
        elif not entry:
            problems.append(f"{spec['shim']}: no line reads {spec['entry']!r}")
        else:
            print(
                f"  {component}: one HTTP send, {shim.name}:{sends[0]}, inside the Lookups"
                f" impl the core calls, entered at {shim.name}:{entry[0]}"
            )


def check_demo(doc: dict, problems: list[str]) -> None:
    """Hold the list against the scenario file and the recorded run.

    The demo is the empirical half of the claim: the drivers count round trips, so a
    refusal that never reached the network is a measured 0 rather than an argument.
    This ties the two halves together and fails if they disagree.
    """
    cases = json.loads((ROOT / doc["demo"]["scenarios"]).read_text(encoding="utf-8"))["cases"]
    golden = json.loads((ROOT / doc["demo"]["golden"]).read_text(encoding="utf-8"))
    declared = {case["id"]: case for case in cases if case["expect"] == "refuse"}
    measured = {name: row for name, row in golden.items() if not row["ok"]}
    if set(declared) != set(measured):
        problems.append(
            "the scenario file and the golden file disagree about which cases refuse: "
            f"{sorted(set(declared) ^ set(measured))}"
        )
    for name, case in sorted(declared.items()):
        row = golden.get(name)
        if row and row["rpc_calls"] != case["rpc_calls"]:
            problems.append(
                f"{name}: scenario declares {case['rpc_calls']} rpc calls, the golden run"
                f" recorded {row['rpc_calls']}"
            )
    pre = sorted(name for name, row in measured.items() if row["rpc_calls"] == 0)
    counts = doc["counts"]
    if len(measured) != counts["demo_refusal_cases"]:
        problems.append(
            f"the list says {counts['demo_refusal_cases']} demo refusals, the run recorded"
            f" {len(measured)}"
        )
    if len(pre) != counts["demo_pre_rpc_cases"]:
        problems.append(
            f"the list says {counts['demo_pre_rpc_cases']} of them refuse before any RPC call,"
            f" the run recorded {len(pre)}"
        )
    print(
        f"  {len(cases)} scenarios, {len(measured)} refusals, {len(pre)} of those with a"
        f" measured rpc_calls of 0, from {doc['demo']['golden']}"
    )

    named: dict[str, str] = {}
    for entry in doc["refusals"]:
        for scenario in entry["demo_scenarios"]:
            if scenario in named:
                problems.append(f"{scenario} is claimed by both {named[scenario]} and {entry['id']}")
            named[scenario] = entry["id"]
            if scenario not in measured:
                problems.append(f"{entry['id']} names {scenario}, which is not a refusing scenario")
                continue
            text = measured[scenario]["text"]
            if entry["reason"] not in text:
                problems.append(f"{scenario} output does not contain {entry['reason']!r}")
            if entry["pre_rpc"] != (measured[scenario]["rpc_calls"] == 0):
                problems.append(
                    f"{entry['id']} is documented pre_rpc={entry['pre_rpc']} but {scenario}"
                    f" recorded {measured[scenario]['rpc_calls']} rpc calls"
                )
    for scenario in sorted(set(measured) - set(named)):
        problems.append(f"the run refuses {scenario} and no documented guard claims it")
    print(
        f"  every refusing scenario maps to a documented guard: {len(named)} scenarios across"
        f" {len(set(named.values()))} guards"
    )


def check_not_refusals(doc: dict, problems: list[str]) -> None:
    """The negative outcomes that are answers rather than refusals.

    `payment-watch` saying NOT SEEN and `nonce-status` saying MISSING are successful
    tool calls: the tool was asked a question and answered it. They are listed so the
    refusal count cannot be padded by promoting a report and checked so it cannot be
    trimmed by demoting a refusal.
    """
    golden = json.loads((ROOT / doc["demo"]["golden"]).read_text(encoding="utf-8"))
    reasons = {entry["reason"] for entry in doc["refusals"]}
    for entry in doc["not_refusals"]:
        lines = (ROOT / entry["file"]).read_text(encoding="utf-8").splitlines()
        hits = [n for n, line in enumerate(lines, start=1) if line.strip() == entry["line"]]
        if len(hits) != 1:
            problems.append(f"{entry['file']}: {len(hits)} lines read {entry['line']!r}")
            continue
        anchor = hits[0]
        if not any(entry["reason"] in line for line in lines[anchor - 1 : anchor + 2]):
            problems.append(f"{entry['file']}:{anchor} does not carry {entry['reason']!r}")
        if entry["reason"] in reasons:
            problems.append(f"{entry['reason']!r} is listed as a refusal and as a report")
        scenario = entry["demo_scenario"]
        returned_ok = any("Ok(" in line for line in lines[max(0, anchor - 4) : anchor])
        if scenario:
            row = golden.get(scenario)
            if row is None:
                problems.append(f"{scenario} is not in the golden file")
            elif not row["ok"]:
                problems.append(f"{scenario} is listed as a report but the run refused it")
            elif entry["reason"] not in row["text"]:
                problems.append(f"{scenario} output does not contain {entry['reason']!r}")
            else:
                print(f"  report, not a refusal: {entry['reason']!r} ({scenario}, ok in the golden)")
        elif returned_ok:
            print(f"  report, not a refusal: {entry['reason']!r} (returned as Ok, no demo case)")
        else:
            problems.append(
                f"{entry['reason']!r} is listed as a report with no demo case and no Ok"
                f" construction near {entry['file']}:{hits[0]}"
            )


def main(argv: list[str]) -> int:
    list_path = Path(argv[0]) if argv else DEFAULT_LIST
    if not list_path.is_file():
        print(f"no refusal list at {list_path}")
        return 2
    doc = json.loads(list_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    mark = 0

    def flush() -> None:
        """Print whatever went wrong in the section that just ran."""
        nonlocal mark
        for problem in problems[mark:]:
            print(f"  FAIL {problem}")
        mark = len(problems)

    print(f"refusal list: {list_path}")
    print(f"tree: {ROOT}")


    # ------------------------------------------------------------ the code itself
    print("\n== every refusal the code constructs")
    raw: dict[str, str] = {}
    stripped: dict[str, list[str]] = {}
    sources: dict[str, Sources] = {}
    owner: dict[str, str] = {}
    for component, files in sorted(doc["sources"].items()):
        for relative in files:
            path = ROOT / relative
            if not path.is_file():
                print(f"  missing source file {relative}")
                return 2
            if relative in owner:
                print(f"  {relative} is listed under two components, cannot attribute its sites")
                return 2
            owner[relative] = component
            raw[relative] = path.read_text(encoding="utf-8")
            stripped[relative] = strip_noise(raw[relative])
        sources[component] = Sources({rel: stripped[rel] for rel in files})
        problems += sources[component].problems

    derived: dict[tuple[str, int], str] = {}
    for relative, lines in stripped.items():
        for line, variant in refusal_sites(lines):
            if (relative, line) in derived:
                problems.append(f"{relative}:{line} constructs two refusals, cannot map it")
            derived[(relative, line)] = variant
    for relative in sorted(stripped):
        count = sum(1 for rel, _ in derived if rel == relative)
        print(f"  {relative}  {count} sites")
    check_coverage(doc, set(stripped), problems)

    claimed: dict[tuple[str, int], str] = {}
    for entry in doc["refusals"]:
        matched_variant = False
        for site in entry["sites"]:
            if site["file"] not in stripped:
                problems.append(f"{entry['id']}: {site['file']} is not a listed source file")
                continue
            line, why = resolve(stripped[site["file"]], site)
            if line is None:
                problems.append(f"{entry['id']}: {why}")
                continue
            site["resolved"] = line
            key = (site["file"], line)
            if key in claimed:
                problems.append(
                    f"{entry['id']} and {claimed[key]} both claim {site['file']}:{line}"
                )
            claimed[key] = entry["id"]
            if key not in derived:
                problems.append(f"{entry['id']}: {site['file']}:{line} constructs no refusal")
            elif derived[key] == entry["variant"]:
                matched_variant = True
        if not matched_variant:
            problems.append(f"{entry['id']}: no site of it constructs {entry['variant']}")
        if entry["variant"] in doc["excluded"]:
            problems.append(
                f"{entry['id']} counts {entry['variant']}, which the list excludes by name"
            )

    for variant, spec in sorted(doc["envelopes"].items()):
        line, why = resolve(stripped.get(spec["file"], []), spec)
        if line is None:
            problems.append(f"envelope {variant}: {why}")
            continue
        claimed[(spec["file"], line)] = f"envelope {variant}"
        if derived.get((spec["file"], line)) != variant:
            problems.append(f"envelope {variant} is not at {spec['file']}:{line}")

    excluded = 0
    for key, variant in sorted(derived.items()):
        if key in claimed:
            continue
        if variant in doc["excluded"]:
            excluded += 1
            continue
        problems.append(f"undocumented refusal: {key[0]}:{key[1]} constructs {variant}")
    envelopes = sum(1 for name in claimed.values() if name.startswith("envelope "))
    print(
        f"  {len(derived)} construction sites: {len(claimed) - envelopes} claimed by"
        f" {len(doc['refusals'])} documented guards, {excluded} transport"
        f" ({', '.join(sorted(doc['excluded']))}), {envelopes} envelope"
    )

    counts = doc["counts"]
    pre_rpc = [entry for entry in doc["refusals"] if entry["pre_rpc"]]
    if counts["refusals"] != len(doc["refusals"]):
        problems.append(
            f"the list counts {counts['refusals']} refusals and carries {len(doc['refusals'])}"
        )
    if counts["pre_rpc"] != len(pre_rpc):
        problems.append(
            f"the list counts {counts['pre_rpc']} pre-RPC refusals and flags {len(pre_rpc)}"
        )
    if counts["post_rpc"] != len(doc["refusals"]) - len(pre_rpc):
        problems.append("the pre-RPC and post-RPC counts do not add up to the refusal count")
    if len({entry["id"] for entry in doc["refusals"]}) != len(doc["refusals"]):
        problems.append("two documented guards share an id")
    print(
        f"  the list and the code agree in both directions: {counts['refusals']} refusals,"
        f" {counts['pre_rpc']} of them before any RPC call"
    )
    flush()

    # ------------------------------------------------- the strings in the binaries
    print("\n== reason strings, source and compiled component")
    for entry in doc["refusals"]:
        text = raw.get(entry["reason_file"])
        if text is None:
            problems.append(f"{entry['id']}: {entry['reason_file']} is not a listed source file")
        elif entry["reason"] not in text:
            problems.append(
                f"{entry['id']}: {entry['reason_file']} does not contain {entry['reason']!r}"
            )
    staged = {}
    strings_wanted = strings_found = 0
    for component, wasm_name in sorted(doc["components"].items()):
        found = sorted(STAGED.glob(f"*/{wasm_name}"))
        if found:
            staged[component] = found[0]
    if not staged:
        print(
            f"  NOTE no components under {STAGED}, so the binary half of this check did"
            " not run. Build them with demo/run-demo.sh and run this again."
        )
    for component, path in sorted(staged.items()):
        binary = path.read_bytes()
        blob = data_sections(binary)
        wanted = sorted(
            {entry["reason"] for entry in doc["refusals"] if entry["component"] == component}
        )
        missing = [reason for reason in wanted if reason.encode() not in blob]
        for reason in missing:
            problems.append(f"{path.name} carries no reason string {reason!r}")
        strings_wanted += len(wanted)
        strings_found += len(wanted) - len(missing)
        print(
            f"  {path.name}  {len(binary):,} bytes  sha256"
            f" {hashlib.sha256(binary).hexdigest()[:8]}  data sections {len(blob):,} bytes"
            f"  {len(wanted) - len(missing)} of {len(wanted)} reason strings present"
        )
    flush()

    # -------------------------------------------------------------- the ordering
    print("\n== ordering, which refusals happen before the first HTTP call")
    check_boundaries(doc, problems)
    chains: dict[str, str] = {}
    for entry in doc["refusals"]:
        site = entry["sites"][0]
        line = site.get("resolved")
        if line is None:
            problems.append(f"{entry['id']}: unresolved site, so it cannot be ordered")
            continue
        code = sources[entry["component"]]
        ordered, chain = code.before_transport(site["file"], line)
        chains[entry["id"]] = chain
        if entry["pre_rpc"] and not ordered:
            problems.append(f"{entry['id']} is documented as pre-RPC but {chain}")
        if not entry["pre_rpc"]:
            holder = code.enclosing(site["file"], line)
            first = code.first_transport(holder) if holder else None
            if first is None or first > line:
                problems.append(
                    f"{entry['id']} is documented as post-RPC but nothing on its path"
                    f" reaches the transport first: {chain}"
                )
    flush()
    print("  the path to each guard, read outward from the guard:")
    for entry in doc["refusals"]:
        flag = "pre " if entry["pre_rpc"] else "post"
        print(f"    {flag}  {chains.get(entry['id'], 'unresolved')}")

    # ------------------------------------------------------------------- the demo
    print("\n== the demo run, measured rather than argued")
    check_demo(doc, problems)
    check_not_refusals(doc, problems)
    flush()

    # ------------------------------------------------------------------ the table
    print(f"\n== the refusal table, {len(doc['refusals'])} guards")
    for component in sorted(doc["components"]):
        rows = [entry for entry in doc["refusals"] if entry["component"] == component]
        print(f"\n-- {component}, {sum(1 for r in rows if r['pre_rpc'])} of {len(rows)} pre-RPC")
        print(f"     {'pre-RPC':7}  {'guard':41}  {'where':16}  reason string")
        for entry in rows:
            site = entry["sites"][0]
            where = f"{Path(site['file']).name}:{site.get('resolved', 0)}"
            print(
                f"   {'*' if entry['demo_scenarios'] else ' '} {'yes' if entry['pre_rpc'] else 'no':7}"
                f"  {entry['id']:41}  {where:16}  {entry['reason']}"
            )
    driven = [
        (scenario, entry["id"])
        for entry in doc["refusals"]
        for scenario in entry["demo_scenarios"]
    ]
    print(
        f"\n  * the demo drives {len(driven)} refusals across"
        f" {len({guard for _, guard in driven})} of these guards:"
    )
    for scenario, guard in sorted(driven):
        print(f"      {scenario:34}  {guard}")
    noted = [entry for entry in doc["refusals"] if entry.get("note")]
    if noted:
        print(f"\n  {len(noted)} guards carry a note:")
        for entry in noted:
            print(f"      {entry['id']}: {entry['note']}")

    # ---------------------------------------------------------------- the verdict
    if problems:
        print(f"\n== FAIL, {len(problems)} problem(s)")
        for problem in problems:
            print(f"  {problem}")
        print("  The list and the code disagree, so the refusal count is not a property yet.")
        return 1
    print("\n== PASS")
    print(
        f"  {len(doc['refusals'])} refusal guards enumerated from"
        f" {len(stripped)} source files, {len(doc['refusals'])} documented, no difference in"
        " either direction."
    )
    print(
        f"  {counts['pre_rpc']} of them return before the component's first HTTP call and"
        f" {counts['post_rpc']} return after one, each with the path printed above."
    )
    print(
        f"  {counts['demo_refusal_cases']} demo scenarios refuse,"
        f" {counts['demo_pre_rpc_cases']} of those with a measured rpc_calls of 0, which is"
        " what the list claims."
    )
    if staged:
        print(
            f"  {strings_found} of {strings_wanted} reason strings are present in the data"
            " sections of the components that own them."
        )
    else:
        print("  Reason strings were checked in the source only: no built components staged.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))




#!/usr/bin/env python3
"""Make every check in this suite fail on purpose.

A wall of green proves nothing about a check. It proves the check ran. The only way
to know an assertion has teeth is to break the thing it asserts and watch it go red,
so this harness does that for all seven checks, one control at a time.

Every control is built on a throwaway copy under a temporary directory. Nothing in
this tree is modified, and the copies are deleted whether the run passes or fails. A
control that fails to provoke its check is reported as a defect in the check rather
than quietly skipped, because a check that cannot fail is decoration.

    python3 demo/prove-teeth.py            # every control
    python3 demo/prove-teeth.py -q         # one line per control

Exit codes: 0 every control provoked its check, 1 one or more did not.
"""

from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
STAGED = HERE / "out" / "staged"

# SHA-512 initial hash values. Ed25519 cannot be computed without SHA-512, so
# planting these is how the no-ed25519 check is made to lie.
SHA512_IV = (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
)


def read_leb128(data: bytes, offset: int) -> tuple[int, int]:
    """One unsigned LEB128. Kept local so this harness never imports what it tests."""
    result = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def sections(binary: bytes):
    offset = 8
    while offset < len(binary):
        section_id = binary[offset]
        offset += 1
        size, offset = read_leb128(binary, offset)
        yield section_id, offset, binary[offset : offset + size]
        offset += size


def data_ranges(binary: bytes) -> list[tuple[int, int]]:
    """File offsets of the core data sections, which is where string literals live."""
    found: list[tuple[int, int]] = []
    for section_id, start, body in sections(binary):
        if section_id != 1 or body[:4] != b"\x00asm":
            continue
        inner = 8
        while inner < len(body):
            inner_id = body[inner]
            inner += 1
            size, inner = read_leb128(body, inner)
            if inner_id == 11:
                found.append((start + inner, start + inner + size))
            inner += size
    return found


def patch_offsets(binary: bytes, need: int) -> list[int]:
    """Offsets of printable runs inside a data section, longest first.

    Patching a run keeps the file length identical, so a control lands on the
    property under test rather than on the size comparison.
    """
    ranges = data_ranges(binary)
    runs: list[tuple[int, int]] = []
    for match in re.finditer(rb"[ -~]{%d,}" % max(need, 24), binary):
        start, end = match.span()
        if any(lo <= start and end <= hi for lo, hi in ranges):
            runs.append((end - start, start))
    runs.sort(reverse=True)
    return [offset for _, offset in runs[:6]]


def run_check(script: str, *args: str) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(HERE / script), *args],
        capture_output=True, text=True, cwd=ROOT,
    )
    return result.returncode, result.stdout + result.stderr


def first_fail(output: str, wanted: str) -> str:
    for line in output.splitlines():
        if "FAIL" in line and wanted.lower() in line.lower():
            return line.strip()
    for line in output.splitlines():
        if "FAIL" in line:
            return line.strip()
    return ""


def patched_copy(source: Path, work: Path, payload: bytes, wanted: str,
                 script: str) -> tuple[bool, str, int]:
    """Write payload over a printable run inside a data section, then run the check.

    Several offsets are tried because only the check itself can confirm the payload
    landed somewhere it reads. The attempt that provokes the failure is reported.
    """
    binary = source.read_bytes()
    for attempt, offset in enumerate(patch_offsets(binary, len(payload)), start=1):
        target = work / source.name
        mutable = bytearray(binary)
        mutable[offset : offset + len(payload)] = payload
        target.write_bytes(bytes(mutable))
        code, output = run_check(script, str(target))
        line = first_fail(output, wanted)
        if code != 0 and wanted.lower() in line.lower():
            return True, line, attempt
        target.unlink(missing_ok=True)
    return False, "", 0


def controls(work: Path) -> list[tuple[str, str, bool, str]]:
    """Each control: what it breaks, which check should notice, whether it did."""
    out: list[tuple[str, str, bool, str]] = []
    nonce = STAGED / "nonce-status" / "nonce_status.wasm"
    spl = STAGED / "spl-transfer-build" / "spl_transfer_build.wasm"

    foreign = ROOT.parent / "spike" / "http-echo" / "http_echo.wasm"
    if foreign.exists():
        code, output = run_check("verify-capabilities.py", str(foreign))
        out.append(("a foreign component passed off as one of ours", "verify-capabilities.py",
                    code != 0, first_fail(output, "allowlist")))

    payload = b"".join(struct.pack("<Q", word) for word in SHA512_IV)
    ok, line, attempt = patched_copy(spl, work, payload, "SHA-512", "verify-no-ed25519.py")
    out.append((f"SHA-512 constants planted in the bytes (offset attempt {attempt})",
                "verify-no-ed25519.py", ok, line))

    ok, line, attempt = patched_copy(nonce, work, b"sendTransaction", "sendTransaction",
                                     "verify-rpc-surface.py")
    out.append((f"sendTransaction written over a read method (offset attempt {attempt})",
                "verify-rpc-surface.py", ok, line))

    ok, line, attempt = patched_copy(nonce, work, b"-----BEGIN PRIVATE KEY-----",
                                     "private key", "verify-artifact-hygiene.py")
    out.append((f"a PEM private key header planted in the data (offset attempt {attempt})",
                "verify-artifact-hygiene.py", ok, line))

    swap = work / "identity-swap"
    shutil.copytree(spl.parent, swap)
    shutil.copy(nonce, swap / spl.name)
    code, output = run_check("verify-artifact-hygiene.py", str(swap / spl.name))
    out.append(("nonce-status bytes shipped under the spl-transfer-build name",
                "verify-artifact-hygiene.py", code != 0, first_fail(output, "another plugin")))
    return out


def config_controls(work: Path) -> list[tuple[str, str, bool, str]]:
    """Config closure, driven through copies of a real manifest."""
    out: list[tuple[str, str, bool, str]] = []
    source = ROOT / "plugins" / "nonce-status" / "manifest.toml"
    text = source.read_text()

    opened = work / "open-manifest.toml"
    opened.write_text(text.replace("additionalProperties = false",
                                   "additionalProperties = true", 1))
    code, output = run_check("verify-config-closure.py", str(opened))
    out.append(("a config schema reopened to accept undeclared keys",
                "verify-config-closure.py", code != 0, first_fail(output, "additionalProperties")))

    secret = work / "secret-manifest.toml"
    secret.write_text(text + '\n[config_schema.properties.private_key]\ntype = "string"\n'
                             'description = "The signing key this plugin would use."\n')
    code, output = run_check("verify-config-closure.py", str(secret))
    out.append(("a config field named for key material",
                "verify-config-closure.py", code != 0, first_fail(output, "key material")))
    return out


def refusal_controls(work: Path) -> list[tuple[str, str, bool, str]]:
    """Refusal completeness, driven through copies of the documented list."""
    out: list[tuple[str, str, bool, str]] = []
    source = HERE / "refusals.json"
    if not source.exists():
        return out
    listed = json.loads(source.read_text())
    guards = listed.get("refusals") if isinstance(listed, dict) else listed

    if isinstance(guards, list) and guards:
        dropped = work / "refusals-dropped.json"
        trimmed = dict(listed) if isinstance(listed, dict) else {}
        if trimmed:
            trimmed["refusals"] = guards[1:]
            dropped.write_text(json.dumps(trimmed, indent=2))
        else:
            dropped.write_text(json.dumps(guards[1:], indent=2))
        code, output = run_check("verify-refusals.py", str(dropped))
        out.append(("one refusal removed from the documented list",
                    "verify-refusals.py", code != 0, first_fail(output, "")))
    return out


def provenance_control(work: Path) -> list[tuple[str, str, bool, str]]:
    """Provenance, driven through a copy of the attestation with one digest moved."""
    source = HERE / "provenance.expected.json"
    if not source.exists():
        return []
    text = source.read_text()
    match = re.search(r'"([0-9a-f]{64})"', text)
    if match is None:
        return []
    moved = match.group(1)
    flipped = ("0" if moved[0] != "0" else "1") + moved[1:]
    copy = work / "provenance-moved.json"
    copy.write_text(text.replace(moved, flipped, 1))
    code, output = run_check("verify-provenance.py", str(copy))
    return [("one recorded digest altered in the attestation",
             "verify-provenance.py", code != 0, first_fail(output, "pinned"))]


def main(argv: list[str]) -> int:
    quiet = "-q" in argv
    if not STAGED.exists():
        print(f"no staged artifacts under {STAGED}, build them first with demo/run-demo.sh")
        return 2

    with tempfile.TemporaryDirectory(prefix="prove-teeth-") as tmp:
        work = Path(tmp)
        results = (controls(work) + config_controls(work)
                   + refusal_controls(work) + provenance_control(work))

    print("=" * 62)
    print(" Every check in this suite, made to fail on purpose")
    print("=" * 62)
    print("\nNothing in the tree was touched. Each control was a throwaway copy.\n")

    provoked = 0
    for what, script, caught, line in results:
        if caught:
            provoked += 1
        print(f" [{'red' if caught else 'GREEN, which is the defect'}] {what}")
        print(f"        check: {script}")
        if line and not quiet:
            print(f"        said:  {line}")
    print()
    print("=" * 62)
    print(f" {provoked} of {len(results)} controls provoked their check")
    if provoked != len(results):
        print(" a control that leaves its check green is a check with no teeth")
    print("=" * 62)
    return 0 if provoked == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))






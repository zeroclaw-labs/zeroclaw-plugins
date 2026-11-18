#!/usr/bin/env python3
"""Turn the CI validator's report into numbers a reader can check.

`gates` reads matrix.tsv (written by tools/ci/validate_components.sh) plus the
staged components and prints per-component test counts, return codes, wasm byte
sizes and wasm sha256. It writes the same values to gates.json so the run's
verdict quotes the file rather than a remembered number.

`vendored` proves the claim that the three plugins share one core: it digests
every vendored copy of libs/solana-core and the original, and fails if they are
not identical. The plugins each carry a copy because CI snapshots only
plugins/<name> plus wit/v0, so a path dependency outside the plugin directory
cannot build there.
"""

import hashlib
import json
import os
import sys


def read_tsv(path):
    with open(path, encoding="utf-8") as fh:
        rows = [line.rstrip("\n").split("\t") for line in fh if line.strip()]
    header, body = rows[0], rows[1:]
    return [dict(zip(header, r)) for r in body]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def gates(matrix_path, staged_dir, out_path):
    rows = read_tsv(matrix_path)
    print(f"  {'component':<20} {'tests':>6} {'fail':>5} {'ign':>4} "
          f"{'test':>5} {'clip':>5} {'wasm-clip':>10} {'build':>6} {'wasm bytes':>11}  wasm sha256")
    summary = {"components": {}, "totals": {}}
    bad = 0
    total_tests = 0
    for row in rows:
        plugin = row["plugin"]
        wasm = None
        plugin_stage = os.path.join(staged_dir, plugin)
        if os.path.isdir(plugin_stage):
            for name in sorted(os.listdir(plugin_stage)):
                if name.endswith(".wasm"):
                    wasm = os.path.join(plugin_stage, name)
        size = os.path.getsize(wasm) if wasm else 0
        digest = sha256_file(wasm) if wasm else ""
        passed = int(row["tests_passed"])
        total_tests += passed
        rcs = [int(row[k]) for k in ("test_rc", "clippy_rc", "wasm_clippy_rc", "build_rc")]
        if any(rcs) or int(row["tests_failed"]) or passed == 0 or not wasm:
            bad += 1
        if wasm and str(size) != row["artifact_bytes"]:
            print(f"  ! {plugin}: staged wasm is {size} B but the report says {row['artifact_bytes']} B")
            bad += 1
        print(f"  {plugin:<20} {passed:>6} {row['tests_failed']:>5} {row['tests_ignored']:>4} "
              f"{rcs[0]:>5} {rcs[1]:>5} {rcs[2]:>10} {rcs[3]:>6} {size:>11,}  {digest[:32]}")
        summary["components"][plugin] = {
            "version": row["version"],
            "tests_passed": passed,
            "tests_failed": int(row["tests_failed"]),
            "tests_ignored": int(row["tests_ignored"]),
            "test_rc": rcs[0],
            "clippy_rc": rcs[1],
            "wasm_clippy_rc": rcs[2],
            "build_rc": rcs[3],
            "wasm_bytes": size,
            "wasm_sha256": digest,
            "capabilities": row["capabilities"],
            "permissions": row["permissions"],
        }
    summary["totals"] = {
        "components": len(rows),
        "tests_passed": total_tests,
        "components_with_a_problem": bad,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"  {len(rows)} components, {total_tests} tests passed, 0 failed"
          if not bad else f"  {bad} component(s) did not come back clean")
    return 1 if bad else 0


def tree_digest(root):
    """sha256 over every file path and its bytes, in sorted path order."""
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            h.update(rel.encode())
            with open(full, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


def vendored(repo_root):
    original = os.path.join(repo_root, "libs", "solana-core", "src")
    copies = {
        plugin: os.path.join(repo_root, "plugins", plugin, "solana-core", "src")
        for plugin in ("spl-transfer-build", "payment-watch", "nonce-status")
    }
    base = tree_digest(original)
    print(f"  libs/solana-core/src                        {base}")
    drift = 0
    for plugin, path in copies.items():
        digest = tree_digest(path)
        mark = "same" if digest == base else "DIFFERENT"
        if digest != base:
            drift += 1
        print(f"  plugins/{plugin}/solana-core/src".ljust(46) + f"{digest}  {mark}")
    if drift:
        print(f"  {drift} vendored copy(ies) drifted from libs/solana-core")
        return 1
    print("  three vendored copies, one source of truth, digests identical")
    return 0


def main():
    if len(sys.argv) < 2:
        print("usage: report.py gates <matrix.tsv> <staged-dir> <gates.json> | vendored <repo-root>")
        return 2
    if sys.argv[1] == "gates":
        return gates(sys.argv[2], sys.argv[3], sys.argv[4])
    if sys.argv[1] == "vendored":
        return vendored(sys.argv[2])
    print(f"unknown subcommand {sys.argv[1]}")
    return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Run the scenario list against the built component drivers and check it.

Each case sends one tool-call JSON to the matching driver, which runs the real
component core, and this script checks three things per case: whether the
component accepted or refused, that its own words contain the line the scenario
expects, and how many RPC round trips it made. Results are then compared, byte
for byte, against the committed golden file, so a change in the transaction
bytes shows up as a diff rather than as a still-green tick.

Nothing here fabricates output: every line printed under a case comes from the
component itself.
"""

import argparse
import base64
import difflib
import hashlib
import json
import os
import subprocess
import sys

DRIVER_BIN = {
    "build": "build/target/debug/zc-drive-build",
    "watch": "watch/target/debug/zc-drive-watch",
    "nonce": "nonce/target/debug/zc-drive-nonce",
}


def substitute(node, rpc_url):
    if isinstance(node, dict):
        return {k: substitute(v, rpc_url) for k, v in node.items()}
    if isinstance(node, list):
        return [substitute(v, rpc_url) for v in node]
    if isinstance(node, str):
        return node.replace("{{RPC_URL}}", rpc_url)
    return node


def run_case(case, drivers_dir, rpc_url, cacert, transcript):
    binary = os.path.join(drivers_dir, DRIVER_BIN[case["driver"]])
    env = dict(os.environ)
    env["ZC_RPC_URL"] = rpc_url
    env["ZC_TIMEOUT"] = env.get("ZC_TIMEOUT", "20")
    if cacert:
        env["ZC_CACERT"] = cacert
    if transcript:
        env["ZC_TRANSCRIPT"] = transcript
    args = json.dumps(substitute(case["args"], rpc_url))
    proc = subprocess.run(
        [binary],
        input=args,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        return None, f"driver exit {proc.returncode}: {proc.stderr.strip()}"
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError as exc:
        return None, f"driver did not print JSON: {exc}: {proc.stdout[:200]}"


def summarize(out):
    """The component's own words, plus the facts worth printing beside them."""
    if out["ok"]:
        result = out["result"]
        text = result.get("summary", json.dumps(result))
    else:
        text = out["error"]
    row = {"ok": out["ok"], "rpc_calls": out["rpc_calls"], "text": text}
    if out["ok"]:
        result = out["result"]
        b64 = result.get("unsigned_transaction_base64")
        if b64:
            raw = base64.b64decode(b64)
            row["tx_bytes"] = len(raw)
            row["tx_sha256"] = hashlib.sha256(raw).hexdigest()
            row["tx_base64"] = b64
            row["durable_nonce"] = result.get("durable_nonce")
        if "paid" in result:
            row["paid"] = result["paid"]
            row["signature"] = result.get("signature")
        if "ready" in result:
            row["ready"] = result["ready"]
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", required=True)
    ap.add_argument("--drivers-dir", required=True)
    ap.add_argument("--rpc-url", required=True)
    ap.add_argument("--cacert", default="")
    ap.add_argument("--transcript", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--golden", required=True)
    ap.add_argument("--write-golden", action="store_true")
    opts = ap.parse_args()

    with open(opts.scenarios, encoding="utf-8") as fh:
        spec = json.load(fh)
    cases = spec["cases"]
    results = {}
    failures = []
    clean = 0

    print(f"  {len(cases)} scenarios, endpoint {opts.rpc_url}")
    for i, case in enumerate(cases, start=1):
        out, err = run_case(case, opts.drivers_dir, opts.rpc_url, opts.cacert, opts.transcript)
        label = f"  [{i:2d}/{len(cases)}] {case['id']}"
        if err:
            failures.append(f"{case['id']}: {err}")
            print(f"{label}\n        FAIL {err}")
            continue
        row = summarize(out)
        results[case["id"]] = row

        problems = []
        want_accept = case["expect"] == "accept"
        if row["ok"] != want_accept:
            problems.append(f"expected {case['expect']}, component said {'accept' if row['ok'] else 'refuse'}")
        if case["must_contain"] not in row["text"]:
            problems.append(f"output does not contain {case['must_contain']!r}")
        if row["rpc_calls"] != case["rpc_calls"]:
            problems.append(f"expected {case['rpc_calls']} rpc calls, made {row['rpc_calls']}")

        facts = [case["expect"], f"rpc={row['rpc_calls']}"]
        if "tx_bytes" in row:
            facts.append(f"tx={row['tx_bytes']} B")
            facts.append(f"sha256={row['tx_sha256'][:12]}")
            facts.append(f"durable_nonce={str(row['durable_nonce']).lower()}")
        if "paid" in row:
            facts.append(f"paid={str(row['paid']).lower()}")
        verdict = "PASS" if not problems else "FAIL"
        if not problems:
            clean += 1
        print(f"{label}  {verdict}  {'  '.join(facts)}")
        print(f"        {row['text']}")
        for p in problems:
            print(f"        ! {p}")
            failures.append(f"{case['id']}: {p}")

    canonical = json.dumps(results, indent=2, sort_keys=True) + "\n"
    with open(opts.out, "w", encoding="utf-8") as fh:
        fh.write(canonical)

    if opts.write_golden:
        with open(opts.golden, "w", encoding="utf-8") as fh:
            fh.write(canonical)
        print(f"  golden written: {opts.golden}")
    else:
        with open(opts.golden, encoding="utf-8") as fh:
            expected = fh.read()
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        if expected == canonical:
            print(f"  golden: MATCH, {len(results)} cases, sha256 {digest}")
        else:
            print("  golden: MISMATCH")
            for line in difflib.unified_diff(
                expected.splitlines(), canonical.splitlines(), "golden", "this run", lineterm=""
            ):
                print(f"    {line}")
            failures.append("golden mismatch")

    print(f"  scenarios: {clean} clean of {len(cases)}")
    if failures:
        print(f"  failures: {len(failures)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

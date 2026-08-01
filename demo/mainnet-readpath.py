#!/usr/bin/env python3
"""Read-only mainnet stage of the demo.

What it does: points the real components at a public mainnet RPC, read only,
and asks mainnet to simulate an unsigned transfer that spl-transfer-build
produced. simulateTransaction never broadcasts, so this costs nothing, needs no
key and moves nothing. The same bytes then go back with sigVerify on, where
mainnet rejects them, which is the proof that they really are unsigned.

What it is not: a settlement. Nothing here is signed, sent or paid, and there is
no keypair in this rig at all. A transaction accepted by mainnet simulation says
the build path produces valid transactions against real mainnet state. That is
the whole claim.

The sender is a public mainnet wallet nobody here controls. Simulation does not
need its signature and cannot move its funds; a funded public account is used
because we hold no mainnet key and do not want one inside an agent.

Every request and response is written to the artifact directory, so a reader can
check the claims against files instead of prose.
"""

import argparse
import base64
import datetime
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

MAINNET_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
# A public mainnet wallet with SOL and USDC. Read-only subject of the
# simulation, never a signer here.
DEFAULT_SENDER = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
# The desk's own wallet: ours, funded on devnet, empty on mainnet. Its mainnet
# token account does not exist, which is what makes the create-idempotent leg of
# the build show up in the simulation.
DEFAULT_RECIPIENT = "2PQcNtSophRAG7ZsHaDT87Zx8MNkCu3GPKsmrR2qthty"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
REFERENCE_UNUSED = "CxaaW7Fd6LfZAT3gVDEs5pxK2PT9T9nd7JfuAyYWHyFq"
ACCOUNT_ABSENT = "9yXPTQZhqq1yvG22NE8Vz4HobeXUJ1dwirgByV5EJt1"
DRIVER_BIN = {
    "build": "build/target/debug/zc-drive-build",
    "watch": "watch/target/debug/zc-drive-watch",
    "nonce": "nonce/target/debug/zc-drive-nonce",
}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Methods this script calls itself, filled in by rpc(). The census at the end
# proves the whole run stayed on read-only methods.
DIRECT_CALLS = []
WRITE_METHODS = (
    "sendTransaction",
    "requestAirdrop",
    "sendBundle",
    "signTransaction",
    "sendAndConfirmTransaction",
)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    for byte in raw:
        if byte:
            break
        out = "1" + out
    return out


def read_compact_u16(data, at):
    value = 0
    shift = 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, at
        shift += 7


def decode_unsigned(tx_base64):
    """Read back our own bytes: signature slots, header, account keys, programs.

    Anyone can run this against the base64 in the artifacts and get the same
    answer, which is the point of printing it.
    """
    raw = base64.b64decode(tx_base64)
    slots, at = read_compact_u16(raw, 0)
    signatures = raw[at: at + 64 * slots]
    message = raw[at + 64 * slots:]
    header = list(message[0:3])
    count, at = read_compact_u16(message, 3)
    keys = [b58encode(message[at + 32 * i: at + 32 * (i + 1)]) for i in range(count)]
    at += 32 * count
    blockhash = b58encode(message[at: at + 32])
    at += 32
    ix_count, at = read_compact_u16(message, at)
    programs = []
    for _ in range(ix_count):
        programs.append(keys[message[at]])
        at += 1
        accounts, at = read_compact_u16(message, at)
        at += accounts
        data_len, at = read_compact_u16(message, at)
        at += data_len
    return {
        "total_bytes": len(raw),
        "signature_slots": slots,
        "signatures_all_zero": all(b == 0 for b in signatures),
        "header_signers_readonly_signed_readonly_unsigned": header,
        "account_keys": keys,
        "recent_blockhash_or_nonce": blockhash,
        "instruction_programs": programs,
    }


def post(url, body, timeout=40):
    request = urllib.request.Request(
        url, data=body.encode(), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode()
    except urllib.error.HTTPError as err:  # a 403 body is evidence too
        return err.read().decode()


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    DIRECT_CALLS.append(method)
    raw = post(url, body)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"raw": raw}
    return {"request": json.loads(body), "response": parsed}


def run_driver(kind, args, rpc_url, drivers_dir, transcript):
    binary = os.path.join(drivers_dir, DRIVER_BIN[kind])
    if not os.path.isfile(binary):
        # Never skip on a missing artifact. A stage that cannot run has to say so
        # and take the exit code with it.
        sys.exit(f"error: driver binary missing: {binary}. Build it with demo/run-demo.sh stage 2.")
    env = dict(os.environ)
    env["ZC_RPC_URL"] = rpc_url
    env["ZC_TRANSCRIPT"] = transcript
    env["ZC_TIMEOUT"] = "40"
    proc = subprocess.run(
        [binary], input=json.dumps(args), capture_output=True, text=True, env=env, check=False
    )
    if proc.returncode != 0:
        return {"ok": False, "rpc_calls": 0, "error": f"driver exit {proc.returncode}: {proc.stderr.strip()}"}
    return json.loads(proc.stdout)


class Run:
    """Artifact writer and check log. Every check prints a real value."""

    def __init__(self, out_dir):
        self.out = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.checks = []
        self.notes = []

    def save(self, name, payload):
        with open(os.path.join(self.out, name), "w", encoding="utf-8") as fh:
            if isinstance(payload, str):
                fh.write(payload if payload.endswith("\n") else payload + "\n")
            else:
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
        return name

    def check(self, name, ok, detail, artifact=""):
        self.checks.append(
            {"check": name, "ok": bool(ok), "detail": detail, "artifact": artifact}
        )
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        print(f"        {detail}")
        if artifact:
            print(f"        artifact: {artifact}")
        return ok

    def note(self, name, detail, artifact=""):
        self.notes.append({"note": name, "detail": detail, "artifact": artifact})
        print(f"  NOTE  {name}")
        print(f"        {detail}")
        if artifact:
            print(f"        artifact: {artifact}")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=os.environ.get("MAINNET_RPC", DEFAULT_RPC))
    ap.add_argument("--sender", default=os.environ.get("MAINNET_SENDER", DEFAULT_SENDER))
    ap.add_argument("--recipient", default=os.environ.get("MAINNET_RECIPIENT", DEFAULT_RECIPIENT))
    ap.add_argument(
        "--out-dir",
        default=os.environ.get("MAINNET_OUT", os.path.join(here, "artifacts", "mainnet-readpath")),
    )
    ap.add_argument("--drivers-dir", default=os.path.join(here, "drivers"))
    opts = ap.parse_args()

    run = Run(opts.out_dir)
    transcript = os.path.join(run.out, "90-component-rpc-transcript.jsonl")
    if os.path.exists(transcript):
        os.remove(transcript)
    reference = "FPPZ8UK5r9BiNQ7N9DhGumcQkQJE9JXXvkCRvFG4d5X5"
    started = utc_now()
    head = subprocess.run(
        ["git", "-C", here, "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    ).stdout.strip()
    print(f"  endpoint {opts.rpc}")
    print(f"  artifacts {opts.out_dir}")
    run.save(
        "00-environment.txt",
        "\n".join(
            [
                f"run at            {started}",
                f"endpoint          {opts.rpc}",
                f"repo commit       {head}",
                f"sender            {opts.sender}   (public mainnet wallet, not ours, never signs here)",
                f"recipient         {opts.recipient}   (our desk wallet, empty on mainnet)",
                f"mint              {USDC}   (USDC)",
                f"reference         {reference}   (Solana Pay reference, synthetic)",
                "",
                "Read-only. Every call below is getGenesisHash, getVersion, getSlot,",
                "getAccountInfo, getLatestBlockhash, getSignaturesForAddress, getTransaction",
                "or simulateTransaction. simulateTransaction does not broadcast. No",
                "sendTransaction, no signature, no keypair, no wallet.",
            ]
        ),
    )

    # ---- cluster identity -------------------------------------------------
    identity = {m: rpc(opts.rpc, m, []) for m in ("getGenesisHash", "getVersion", "getSlot")}
    run.save("01-cluster-identity.json", identity)
    genesis = identity["getGenesisHash"]["response"].get("result")
    core = identity["getVersion"]["response"].get("result", {}).get("solana-core")
    slot = identity["getSlot"]["response"].get("result")
    if not run.check(
        "the endpoint really is Solana mainnet-beta",
        genesis == MAINNET_GENESIS,
        f"genesis hash {genesis}, solana-core {core}, slot {slot}",
        "01-cluster-identity.json",
    ):
        run.save("SUMMARY.json", {"started": started, "checks": run.checks, "notes": run.notes})
        return 1

    # ---- the sender we are about to simulate against ----------------------
    account = rpc(opts.rpc, "getAccountInfo", [opts.sender, {"encoding": "base64"}])
    run.save("02-sender-account.json", account)
    value = account["response"].get("result", {}).get("value") or {}
    run.check(
        "the sender is a funded wallet owned by the system program",
        value.get("owner") == "11111111111111111111111111111111" and value.get("lamports", 0) > 0,
        f"{value.get('lamports')} lamports, owner {value.get('owner')}, data space {value.get('space')}",
        "02-sender-account.json",
    )

    policy = {
        "rpc_url": opts.rpc,
        "allow_recipients": opts.recipient,
        "caps": f"SOL:0.01:9,{USDC}:25:6",
    }

    # ---- SOL transfer, built by the component, simulated by mainnet -------
    sol_args = {
        "sender": opts.sender,
        "recipient": opts.recipient,
        "amount": "0.01",
        "memo": "zeroclaw mainnet simulation only",
        "reference": reference,
        "__config": policy,
    }
    sol = run_driver("build", sol_args, opts.rpc, opts.drivers_dir, transcript)
    run.save("03-build-sol.json", {"args": sol_args, "component_output": sol})
    sol_tx = sol.get("result", {}).get("unsigned_transaction_base64", "")
    sol_decoded = decode_unsigned(sol_tx) if sol_tx else {}
    run.save("04-decoded-sol-transaction.json", sol_decoded)
    run.check(
        "spl-transfer-build produced an unsigned SOL transfer against live mainnet state",
        bool(sol.get("ok")) and sol_decoded.get("signatures_all_zero"),
        f"{sol_decoded.get('total_bytes')} bytes, {sol_decoded.get('signature_slots')} signature slot"
        f" left all zero, programs {', '.join(sol_decoded.get('instruction_programs', []))},"
        f" blockhash {sol_decoded.get('recent_blockhash_or_nonce')}, {sol.get('rpc_calls')} rpc call",
        "03-build-sol.json, 04-decoded-sol-transaction.json",
    )

    sim_opts = {
        "encoding": "base64",
        "sigVerify": False,
        "replaceRecentBlockhash": False,
        "commitment": "confirmed",
    }
    sim_sol = rpc(opts.rpc, "simulateTransaction", [sol_tx, sim_opts])
    run.save("05-simulate-sol.json", sim_sol)
    result = sim_sol["response"].get("result", {})
    v = result.get("value", {})
    run.check(
        "mainnet simulation ACCEPTED the unsigned SOL transfer",
        v.get("err") is None,
        f"err {v.get('err')}, fee {v.get('fee')} lamports, {v.get('unitsConsumed')} compute units,"
        f" simulated at slot {result.get('context', {}).get('slot')}."
        f" Logs: {' | '.join(v.get('logs') or [])}",
        "05-simulate-sol.json",
    )

    # ---- the same bytes with signature checking on -------------------------
    sim_sv = rpc(
        opts.rpc,
        "simulateTransaction",
        [sol_tx, {"encoding": "base64", "sigVerify": True, "commitment": "confirmed"}],
    )
    run.save("06-simulate-sol-sigverify-on.json", sim_sv)
    sv_err = sim_sv["response"].get("result", {}).get("value", {}).get("err")
    run.check(
        "the same bytes are rejected once signatures are checked, so they are genuinely unsigned",
        sv_err is not None,
        f"err {sv_err} with sigVerify true, against err null with sigVerify false",
        "06-simulate-sol-sigverify-on.json",
    )

    # ---- USDC transfer: real mint decimals, real token accounts ------------
    usdc_args = {
        "sender": opts.sender,
        "recipient": opts.recipient,
        "amount": "1",
        "mint": USDC,
        "memo": "zeroclaw mainnet simulation only",
        "reference": reference,
        "__config": policy,
    }
    usdc = run_driver("build", usdc_args, opts.rpc, opts.drivers_dir, transcript)
    run.save("07-build-usdc.json", {"args": usdc_args, "component_output": usdc})
    usdc_tx = usdc.get("result", {}).get("unsigned_transaction_base64", "")
    usdc_decoded = decode_unsigned(usdc_tx) if usdc_tx else {}
    run.save("08-decoded-usdc-transaction.json", usdc_decoded)
    run.check(
        "spl-transfer-build read the real USDC mint and built the transfer plus token account creation",
        bool(usdc.get("ok")) and len(usdc_decoded.get("instruction_programs", [])) == 3,
        f"{usdc_decoded.get('total_bytes')} bytes, {usdc.get('rpc_calls')} rpc calls,"
        f" programs {', '.join(usdc_decoded.get('instruction_programs', []))}",
        "07-build-usdc.json, 08-decoded-usdc-transaction.json",
    )

    sim_usdc = rpc(opts.rpc, "simulateTransaction", [usdc_tx, sim_opts]) if usdc_tx else {"response": {}}
    run.save("09-simulate-usdc.json", sim_usdc)
    usdc_result = sim_usdc["response"].get("result", {})
    uv = usdc_result.get("value", {})
    run.check(
        "mainnet simulation ACCEPTED the unsigned USDC transfer",
        bool(usdc_tx) and uv.get("err") is None,
        f"err {uv.get('err')}, fee {uv.get('fee')} lamports, {uv.get('unitsConsumed')} compute units,"
        f" simulated at slot {usdc_result.get('context', {}).get('slot')}."
        f" Logs: {' | '.join(uv.get('logs') or [])}",
        "09-simulate-usdc.json",
    )

    # ---- the policy still refuses, on the real endpoint --------------------
    over_cap = dict(sol_args, amount="5")
    refused = run_driver("build", over_cap, opts.rpc, opts.drivers_dir, transcript)
    run.save("10-refused-over-cap.json", {"args": over_cap, "component_output": refused})
    run.check(
        "the operator cap refuses 5 SOL against mainnet before any RPC call",
        not refused.get("ok") and refused.get("rpc_calls") == 0,
        f"{refused.get('error')} ({refused.get('rpc_calls')} rpc calls)",
        "10-refused-over-cap.json",
    )

    # ---- payment-watch reads mainnet history ------------------------------
    watch_args = {
        "reference": REFERENCE_UNUSED,
        "expected_amount": "1",
        "mint": USDC,
        "recipient": opts.recipient,
        "__config": {"rpc_url": opts.rpc},
    }
    watch = run_driver("watch", watch_args, opts.rpc, opts.drivers_dir, transcript)
    run.save("11-watch-unused-reference.json", {"args": watch_args, "component_output": watch})
    watch_text = (watch.get("result") or {}).get("summary", watch.get("error", ""))
    run.check(
        "payment-watch queried mainnet for an unused reference and reported nothing paid",
        bool(watch.get("ok")) and (watch.get("result") or {}).get("paid") is False,
        f"{watch_text} ({watch.get('rpc_calls')} rpc calls)",
        "11-watch-unused-reference.json",
    )

    # ---- nonce-status reads mainnet -------------------------------------
    nonce_args = {
        "account": ACCOUNT_ABSENT,
        "__config": {"rpc_url": opts.rpc, "nonce_account": ACCOUNT_ABSENT},
    }
    nonce = run_driver("nonce", nonce_args, opts.rpc, opts.drivers_dir, transcript)
    run.save("12-nonce-absent-account.json", {"args": nonce_args, "component_output": nonce})
    nonce_text = (nonce.get("result") or {}).get("summary", nonce.get("error", ""))
    run.check(
        "nonce-status read mainnet and reported the account absent instead of guessing",
        bool(nonce.get("ok")) and (nonce.get("result") or {}).get("ready") is False,
        f"{nonce_text} ({nonce.get('rpc_calls')} rpc calls)",
        "12-nonce-absent-account.json",
    )

    # ---- every method this run used, from the wire ------------------------
    component_methods = []
    if os.path.exists(transcript):
        with open(transcript, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    component_methods.append(json.loads(line)["request"]["method"])
                except (ValueError, KeyError):
                    component_methods.append("unparsed")
    used = sorted(set(DIRECT_CALLS) | set(component_methods))
    writes = [m for m in used if m in WRITE_METHODS]
    census = {
        "this_script": {m: DIRECT_CALLS.count(m) for m in sorted(set(DIRECT_CALLS))},
        "the_components": {m: component_methods.count(m) for m in sorted(set(component_methods))},
        "total_calls": len(DIRECT_CALLS) + len(component_methods),
        "write_methods_seen": writes,
    }
    run.save("95-method-census.json", census)
    run.check(
        "no write method was called anywhere in this run",
        not writes,
        f"{census['total_calls']} JSON-RPC calls over {len(used)} distinct methods: {', '.join(used)}",
        "95-method-census.json, 90-component-rpc-transcript.jsonl",
    )
    run.note(
        "what this stage does not prove",
        "Simulation is not settlement. Nothing here was signed, broadcast or paid,"
        " and this rig holds no keypair. The sender is a public wallet nobody here controls.",
    )

    failed = [c["check"] for c in run.checks if not c["ok"]]
    run.save(
        "SUMMARY.json",
        {
            "started": started,
            "finished": utc_now(),
            "endpoint": opts.rpc,
            "repo_commit": head,
            "checks_total": len(run.checks),
            "checks_failed": len(failed),
            "failed": failed,
            "checks": run.checks,
            "notes": run.notes,
        },
    )
    print(f"  {len(run.checks) - len(failed)} of {len(run.checks)} checks passed")
    if failed:
        print(f"  FAILED: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

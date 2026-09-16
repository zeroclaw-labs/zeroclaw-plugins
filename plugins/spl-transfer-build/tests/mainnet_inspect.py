#!/usr/bin/env python3
"""Independently decode and simulate one mainnet-beta unsigned transfer.

Read-only by construction: this script has no signing path and no keypair
argument. It decodes the plugin's returned bytes with an independent library
(`solders`), asserts the exact expected shape, re-derives both associated token
accounts, and simulates the same bytes against mainnet-beta with
`sigVerify=false`. It never signs and never submits.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

import httpx
from solders.message import to_bytes_versioned
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

ATA_PROGRAM = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
TOKEN_PROGRAM = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
MEMO_PROGRAM = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
TRANSFER_CHECKED = 12
ATA_CREATE_IDEMPOTENT = 1


def derive_ata(owner: Pubkey, mint: Pubkey) -> Pubkey:
    return Pubkey.find_program_address(
        [bytes(owner), bytes(TOKEN_PROGRAM), bytes(mint)], ATA_PROGRAM
    )[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--transaction", type=Path, required=True)
    ap.add_argument("--rpc-url", required=True)
    ap.add_argument("--sender", required=True)
    ap.add_argument("--mint", required=True)
    ap.add_argument("--recipient", required=True)
    ap.add_argument("--amount-raw", type=int, required=True)
    ap.add_argument("--decimals", type=int, required=True)
    ap.add_argument("--memo", required=True)
    args = ap.parse_args()

    b64 = args.transaction.read_text(encoding="ascii").strip()
    raw = base64.b64decode(b64, validate=True)
    checks: list[tuple[str, object]] = []
    checks.append(("transaction_bytes", len(raw)))
    checks.append(("transaction_sha256", hashlib.sha256(raw).hexdigest()))

    tx = VersionedTransaction.from_bytes(raw)
    checks.append(("reserialize_is_byte_identical", bytes(tx) == raw))

    sigs = tx.signatures
    checks.append(("signature_slots", len(sigs)))
    checks.append(("all_signature_slots_zero", all(bytes(s) == bytes(64) for s in sigs)))

    msg = tx.message
    checks.append(("message_is_v0", type(msg).__name__ == "MessageV0"))
    checks.append(("required_signers", msg.header.num_required_signatures))
    checks.append(("address_table_lookups", len(msg.address_table_lookups)))

    keys = list(msg.account_keys)
    sender = Pubkey.from_string(args.sender)
    mint = Pubkey.from_string(args.mint)
    recipient = Pubkey.from_string(args.recipient)
    checks.append(("fee_payer_is_sender", keys[0] == sender))

    sender_ata = derive_ata(sender, mint)
    recipient_ata = derive_ata(recipient, mint)
    checks.append(("derived_sender_ata", str(sender_ata)))
    checks.append(("derived_recipient_ata", str(recipient_ata)))

    programs = [str(keys[ix.program_id_index]) for ix in msg.instructions]
    checks.append(("instruction_programs", programs))

    found_ata = found_transfer = found_memo = False
    for ix in msg.instructions:
        program = keys[ix.program_id_index]
        data = bytes(ix.data)
        accounts = [keys[i] for i in ix.accounts]
        if program == ATA_PROGRAM:
            found_ata = True
            checks.append(("ata_ix_is_create_idempotent", list(data) == [ATA_CREATE_IDEMPOTENT]))
            checks.append(("ata_ix_targets_recipient_ata", recipient_ata in accounts))
        elif program == TOKEN_PROGRAM:
            found_transfer = True
            checks.append(("token_ix_discriminant", data[0]))
            amount = int.from_bytes(data[1:9], "little")
            checks.append(("token_ix_amount_raw", amount))
            checks.append(("token_ix_amount_matches", amount == args.amount_raw))
            checks.append(("token_ix_decimals", data[9]))
            checks.append(("token_ix_decimals_match", data[9] == args.decimals))
            checks.append(("token_ix_source_is_sender_ata", accounts[0] == sender_ata))
            checks.append(("token_ix_mint_is_configured_mint", accounts[1] == mint))
            checks.append(("token_ix_dest_is_recipient_ata", accounts[2] == recipient_ata))
            checks.append(("token_ix_authority_is_sender", accounts[3] == sender))
        elif program == MEMO_PROGRAM:
            found_memo = True
            checks.append(("memo_text_matches", data.decode("utf-8") == args.memo))
    checks.append(("has_ata_create", found_ata))
    checks.append(("has_transfer_checked", found_transfer))
    checks.append(("has_memo", found_memo))
    checks.append(
        ("message_sha256", hashlib.sha256(bytes(to_bytes_versioned(msg))).hexdigest())
    )

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "simulateTransaction",
        "params": [b64, {"sigVerify": False, "replaceRecentBlockhash": True,
                         "encoding": "base64", "commitment": "confirmed"}],
    }
    response = httpx.post(args.rpc_url, json=body, timeout=60.0)
    response.raise_for_status()
    sim = response.json()["result"]["value"]
    checks.append(("simulation_err", sim.get("err")))
    checks.append(("simulation_units_consumed", sim.get("unitsConsumed")))
    checks.append(("simulation_log_count", len(sim.get("logs") or [])))

    for key, value in checks:
        print(f"{key}: {json.dumps(value)}")

    failed = [k for k, v in checks if isinstance(v, bool) and not v]
    if sim.get("err") is not None:
        failed.append("simulation_err")
    if failed:
        print("FAILED_CHECKS: " + ",".join(failed), file=sys.stderr)
        return 1
    print("INDEPENDENT_MAINNET_INSPECTION_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Local fake Solana JSON-RPC, for the offline end-to-end run.

It is a FAKE. Nothing here is a cluster and no value in it is on-chain: the
blockhash, the nonce account, the mint and the one payment are fixed synthetic
fixtures, chosen so the whole demo is deterministic and runs with no network
beyond 127.0.0.1 and no credentials.

It speaks HTTPS on loopback with a self-signed certificate, because the
components refuse any rpc_url that is not https. That refusal is one of the
things the demo proves, so the fake meets the rule instead of the demo
loosening it.

Usage:
  fake-rpc.py --cert out/fake-cert.pem --key out/fake-key.pem \
              --port-file out/fake.port --log out/fake-rpc.jsonl

Every request and response is appended to the log as JSON lines, so the run's
RPC traffic can be read back after the fact.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Addresses. The first four match the constants in the components' own test
# suites (plugins/spl-transfer-build/tests/builder.rs), so a reader can line the
# demo up with the tests. The rest are derived from fixed labels:
# sha256("zeroclaw-demo/<label>"), which is also how a Solana Pay reference is
# generated in practice, at random and meaningless on its own.
SENDER = "9B5XszUGdMaxCZ7uSQhPzdks5ZQSmWxrmzCSvtJ6Ns6g"
RECIPIENT = "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN"
MINT6 = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
NONCE_OK = "8XkoSVfNbLKKzcpsTCyzysXbygqrGrbW8t5RS6Wxsdb1"
NONCE_WRONG_AUTHORITY = "D76rpNLGyDF8c6jgbqi2rXRieX4Z1q4BtkKAnKUJsNQv"
REFERENCE_PAID = "FPPZ8UK5r9BiNQ7N9DhGumcQkQJE9JXXvkCRvFG4d5X5"
SIGNATURE_PAID = (
    "45TB5n9LyxpkQq6AxxE27eqvm5xAUhscMFveT4E3zGvpysPbTQEJCR2EcW7DV9Dp47PiFxrDESxvAReScpU5vNDC"
)
SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
BLOCKHASH = "J7rBdM6AecPDEZp8aPq5iPSNKVkU5Q76F3oAV4eW5wsW"
SLOT = 401234567


def b58_decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def nonce_account_data(authority_b58):
    """80 bytes: versions tag 1, state tag 1, authority, durable nonce, fee.

    The durable nonce value is sha256("DURABLE_NONCE" || 0xAB*32), the exact
    digest pinned by libs/solana-core/src/nonce.rs's own test, so the fixture
    is a real domain-separated nonce shape rather than random bytes.
    """
    nonce = hashlib.sha256(b"DURABLE_NONCE" + bytes([171] * 32)).digest()
    return (
        (1).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + b58_decode(authority_b58)
        + nonce
        + (5000).to_bytes(8, "little")
    )


def mint_data(decimals):
    """82-byte SPL mint: decimals at offset 44, initialized flag at 45."""
    d = bytearray(82)
    d[44] = decimals
    d[45] = 1
    return bytes(d)


def account_value(data, owner, lamports, space):
    return {
        "data": [base64.b64encode(data).decode(), "base64"],
        "executable": False,
        "lamports": lamports,
        "owner": owner,
        "rentEpoch": 0,
        "space": space,
    }


def handle(req):
    method = req.get("method")
    params = req.get("params") or []
    if method == "getLatestBlockhash":
        return {
            "context": {"apiVersion": "0.0.0-local-fake", "slot": SLOT},
            "value": {"blockhash": BLOCKHASH, "lastValidBlockHeight": SLOT - 200},
        }
    if method == "getAccountInfo":
        key = params[0]
        if key == NONCE_OK:
            value = account_value(nonce_account_data(SENDER), SYSTEM_PROGRAM, 1447680, 80)
        elif key == NONCE_WRONG_AUTHORITY:
            value = account_value(nonce_account_data(RECIPIENT), SYSTEM_PROGRAM, 1447680, 80)
        elif key == MINT6:
            value = account_value(mint_data(6), TOKEN_PROGRAM, 1461600, 82)
        else:
            value = None
        return {"context": {"apiVersion": "0.0.0-local-fake", "slot": SLOT}, "value": value}
    if method == "getSignaturesForAddress":
        if params[0] == REFERENCE_PAID:
            return [
                {
                    "signature": SIGNATURE_PAID,
                    "slot": SLOT,
                    "err": None,
                    "memo": None,
                    "blockTime": 1769000000,
                    "confirmationStatus": "finalized",
                }
            ]
        return []
    if method == "getTransaction":
        if params[0] != SIGNATURE_PAID:
            return None
        bal = lambda amount: {
            "accountIndex": 2,
            "mint": MINT6,
            "owner": RECIPIENT,
            "programId": TOKEN_PROGRAM,
            "uiTokenAmount": {
                "amount": str(amount),
                "decimals": 6,
                "uiAmount": amount / 10**6,
                "uiAmountString": str(amount / 10**6),
            },
        }
        return {
            "slot": SLOT,
            "blockTime": 1769000000,
            "meta": {
                "err": None,
                "fee": 5000,
                "preTokenBalances": [bal(0)],
                "postTokenBalances": [bal(25000000)],
                "status": {"Ok": None},
            },
        }
    raise KeyError(method)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    log_path = None

    def log_message(self, *_args):
        pass  # the JSON-line log below is the record; stderr noise is not

    def do_POST(self):  # noqa: N802 (stdlib naming)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode()
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            self.send_error(400, "not json")
            return
        try:
            body = {"jsonrpc": "2.0", "id": req.get("id", 1), "result": handle(req)}
        except KeyError as missing:
            body = {
                "jsonrpc": "2.0",
                "id": req.get("id", 1),
                "error": {
                    "code": -32601,
                    "message": f"method {missing.args[0]} is not served by the local fake",
                },
            }
        payload = json.dumps(body).encode()
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"request": req, "response": body}) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--log", required=True)
    args = ap.parse_args()

    Handler.log_path = args.log
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    port = server.socket.getsockname()[1]
    with open(args.port_file, "w", encoding="utf-8") as fh:
        fh.write(str(port))
    print(f"local fake RPC listening on https://127.0.0.1:{port} (pid {os.getpid()})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

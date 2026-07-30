#!/usr/bin/env python3
"""Deterministic OpenAI-compatible oracle for the real mainnet-beta read-only run.

Mainnet is used for **read-only** paths only. The plugin cannot sign or submit,
so the run reads mint state, reads a blockhash, simulates, and returns unsigned
bytes. Nothing is signed. Nothing is submitted. No private key exists for any
address involved.

Two expectations are supported:

  --expect ok        the tool must return the strict unsigned-transfer output,
                     and the approval summary must carry the decoded recipient
                     and the UNSIGNED warning.
  --expect refusal   the tool must fail closed (no strict output anywhere in the
                     tool result) — used for the real mainnet Token-2022 mint,
                     which carries extensions the policy refuses.

The oracle validates the bounded tool result and prints one machine-checkable
line. It never echoes RPC bodies, account bytes, or unbounded tool text.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MAX_ECHO = 400


def sse(*events: dict[str, Any]) -> bytes:
    lines = [f"data: {json.dumps(event, separators=(',', ':'))}\n\n" for event in events]
    lines.append("data: [DONE]\n\n")
    return "".join(lines).encode()


def completion(message: dict[str, Any], finish_reason: str) -> bytes:
    return json.dumps(
        {
            "id": "chatcmpl-mainnet",
            "object": "chat.completion",
            "created": 0,
            "model": "mainnet-mock",
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        },
        separators=(",", ":"),
    ).encode()


def find_transfer_output(value: Any) -> dict[str, Any] | None:
    """Find the strict plugin output through ZeroClaw's tool-result envelope."""
    if isinstance(value, str):
        try:
            return find_transfer_output(json.loads(value))
        except json.JSONDecodeError:
            return None
    if isinstance(value, list):
        for item in value:
            found = find_transfer_output(item)
            if found is not None:
                return found
        return None
    if not isinstance(value, dict):
        return None
    if {
        "transaction_base64",
        "summary",
        "last_valid_block_height",
        "blockhash_mode",
    }.issubset(value):
        return value
    for item in value.values():
        found = find_transfer_output(item)
        if found is not None:
            return found
    return None


class ChatHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    recipient = ""
    mint = ""
    amount = ""
    memo = ""
    invoice_id = ""
    expect = "ok"

    def log_message(self, format: str, *args: object) -> None:
        return

    def send_body(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def reject(self, reason: str) -> None:
        body = json.dumps({"error": reason}, separators=(",", ":")).encode()
        self.send_body(422, "application/json", body)
        print(json.dumps({"accepted": False, "reason": reason}), flush=True)
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def respond(self, request: dict[str, Any], message: dict[str, Any], finish: str) -> None:
        if request.get("stream") is True:
            delta = {"role": "assistant"}
            delta.update(message)
            body = sse(
                {
                    "id": "chatcmpl-mainnet",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "mainnet-mock",
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
                },
                {
                    "id": "chatcmpl-mainnet",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "mainnet-mock",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                },
            )
            content_type = "text/event-stream"
        else:
            body = completion({"role": "assistant", **message}, finish)
            content_type = "application/json"
        self.send_body(200, content_type, body)

    def do_POST(self) -> None:
        if not self.path.endswith("/chat/completions"):
            self.reject(f"unexpected path: {self.path}")
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            request = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.reject("invalid JSON request")
            return

        messages = request.get("messages", [])
        tool_messages = [m for m in messages if m.get("role") == "tool"]
        if not tool_messages:
            self.emit_tool_call(request)
            return
        contents = [m.get("content") for m in tool_messages]
        if self.expect == "refusal":
            self.check_refusal(request, contents)
        else:
            self.check_success(request, contents)

    def emit_tool_call(self, request: dict[str, Any]) -> None:
        names = [
            tool.get("function", {}).get("name")
            for tool in request.get("tools", [])
            if tool.get("type") == "function"
        ]
        if "spl_transfer_build" not in names:
            self.reject(f"plugin tool was not advertised: {names}")
            return
        arguments = json.dumps(
            {
                "recipient": self.recipient,
                "amount": self.amount,
                "mint": self.mint,
                "memo": self.memo,
                "invoice_id": self.invoice_id,
            },
            separators=(",", ":"),
        )
        tool_call = {
            "id": "call_mainnet",
            "type": "function",
            "function": {"name": "spl_transfer_build", "arguments": arguments},
        }
        streaming = request.get("stream") is True
        self.respond(
            request,
            {"content": None, "tool_calls": [{"index": 0, **tool_call} if streaming else tool_call]},
            "tool_calls",
        )
        print(
            json.dumps(
                {
                    "accepted": True,
                    "request": 1,
                    "streaming": streaming,
                    "tool_advertised": "spl_transfer_build",
                    "expect": self.expect,
                }
            ),
            flush=True,
        )

    def check_success(self, request: dict[str, Any], contents: list[Any]) -> None:
        output = find_transfer_output(contents)
        if output is None:
            self.reject("tool result omitted the strict transfer output")
            return
        if output.get("blockhash_mode") != "recent":
            self.reject("tool result did not use recent blockhash mode")
            return
        summary = output.get("summary")
        if not isinstance(summary, str) or self.recipient not in summary:
            self.reject("approval summary omitted the decoded recipient")
            return
        if "UNSIGNED" not in summary:
            self.reject("approval summary omitted the unsigned warning")
            return
        reference = output.get("reference")
        if not isinstance(reference, str) or not reference:
            self.reject("tool result omitted the reconciliation reference")
            return
        try:
            transaction = base64.b64decode(output["transaction_base64"], validate=True)
        except (KeyError, TypeError, ValueError):
            self.reject("transaction_base64 is malformed")
            return
        if not transaction or len(transaction) > 1232:
            self.reject("unsigned transaction is empty or exceeds the packet limit")
            return

        digest = hashlib.sha256(transaction).hexdigest()
        height = output.get("last_valid_block_height")
        final_text = (
            f"MAINNET_AGENT_OK reference={reference} "
            f"last_valid_block_height={height} "
            f"transaction_bytes={len(transaction)} transaction_sha256={digest}"
        )
        self.respond(request, {"content": final_text}, "stop")
        print(
            json.dumps(
                {
                    "accepted": True,
                    "request": 2,
                    "expect": "ok",
                    "reference": reference,
                    "last_valid_block_height": height,
                    "transaction_bytes": len(transaction),
                    "transaction_sha256": digest,
                    "transaction_base64": output["transaction_base64"],
                }
            ),
            flush=True,
        )
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def check_refusal(self, request: dict[str, Any], contents: list[Any]) -> None:
        if find_transfer_output(contents) is not None:
            self.reject("policy was expected to refuse, but a transaction was returned")
            return
        echoed = " ".join(c for c in contents if isinstance(c, str))[:MAX_ECHO]
        final_text = "MAINNET_REFUSAL_OK no_transaction_returned"
        self.respond(request, {"content": final_text}, "stop")
        print(
            json.dumps(
                {
                    "accepted": True,
                    "request": 2,
                    "expect": "refusal",
                    "transaction_returned": False,
                    "tool_result_excerpt": echoed,
                }
            ),
            flush=True,
        )
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--mint", required=True)
    parser.add_argument("--amount", required=True)
    parser.add_argument("--memo", default="")
    parser.add_argument("--invoice-id", default="")
    parser.add_argument("--expect", choices=["ok", "refusal"], default="ok")
    args = parser.parse_args()
    ChatHandler.recipient = args.recipient
    ChatHandler.mint = args.mint
    ChatHandler.amount = args.amount
    ChatHandler.memo = args.memo
    ChatHandler.invoice_id = args.invoice_id
    ChatHandler.expect = args.expect
    server = ThreadingHTTPServer(("127.0.0.1", args.port), ChatHandler)
    print(json.dumps({"listening": f"127.0.0.1:{args.port}"}), flush=True)
    server.serve_forever()
    server.server_close()


if __name__ == "__main__":
    main()

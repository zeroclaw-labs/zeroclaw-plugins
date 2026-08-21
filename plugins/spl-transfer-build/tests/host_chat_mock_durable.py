#!/usr/bin/env python3
"""Deterministic OpenAI-compatible oracle for the real M4 durable-nonce agent run.

Mirrors host_chat_mock.py but validates the durable-nonce output shape
(blockhash_mode == "durable_nonce", nonce_account + nonce present, and no
last_valid_block_height), and captures only the public unsigned transaction.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def sse(*events: dict[str, Any]) -> bytes:
    lines = [f"data: {json.dumps(event, separators=(',', ':'))}\n\n" for event in events]
    lines.append("data: [DONE]\n\n")
    return "".join(lines).encode()


def completion(message: dict[str, Any], finish_reason: str) -> bytes:
    return json.dumps(
        {
            "id": "chatcmpl-m4",
            "object": "chat.completion",
            "created": 0,
            "model": "m4-mock",
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        },
        separators=(",", ":"),
    ).encode()


def find_transfer_output(value: Any) -> dict[str, Any] | None:
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
    if {"transaction_base64", "summary", "blockhash_mode"}.issubset(value):
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
    capture: Path | None = None

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
            delta = {"role": "assistant", **message}
            body = sse(
                {
                    "id": "chatcmpl-m4",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "m4-mock",
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
                },
                {
                    "id": "chatcmpl-m4",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "m4-mock",
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
                    "amount": "1.5",
                    "mint": "M4TEST",
                    "memo": "M4 durable acceptance",
                    "invoice_id": "m4-durable-2026-07-19",
                },
                separators=(",", ":"),
            )
            tool_call = {
                "id": "call_m4_durable",
                "type": "function",
                "function": {"name": "spl_transfer_build", "arguments": arguments},
            }
            streaming = request.get("stream") is True
            streamed_call = {"index": 0, **tool_call} if streaming else tool_call
            self.respond(request, {"content": None, "tool_calls": [streamed_call]}, "tool_calls")
            print(json.dumps({"accepted": True, "request": 1, "tool_advertised": "spl_transfer_build"}), flush=True)
            return

        output = find_transfer_output([m.get("content") for m in tool_messages])
        if output is None:
            self.reject("tool result omitted the strict transfer output")
            return
        if output.get("blockhash_mode") != "durable_nonce":
            self.reject(f"tool result did not use durable_nonce mode: {output.get('blockhash_mode')}")
            return
        if "last_valid_block_height" in output:
            self.reject("durable output must not include last_valid_block_height")
            return
        nonce_account = output.get("nonce_account")
        nonce = output.get("nonce")
        if not isinstance(nonce_account, str) or not nonce_account:
            self.reject("durable output omitted nonce_account")
            return
        if not isinstance(nonce, str) or not nonce:
            self.reject("durable output omitted nonce")
            return
        summary = output.get("summary")
        if not isinstance(summary, str) or self.recipient not in summary or "UNSIGNED" not in summary:
            self.reject("approval summary omitted the decoded recipient or unsigned warning")
            return
        if "Execution warning" not in summary or "durable_nonce" not in summary:
            self.reject("durable summary omitted the nonce-consumption warning")
            return
        try:
            transaction = base64.b64decode(output["transaction_base64"], validate=True)
        except (KeyError, TypeError, ValueError):
            self.reject("transaction_base64 is malformed")
            return
        if not transaction or len(transaction) > 1232:
            self.reject("unsigned transaction is empty or exceeds the packet limit")
            return

        if self.capture is not None:
            self.capture.parent.mkdir(parents=True, exist_ok=True)
            self.capture.write_text(output["transaction_base64"] + "\n", encoding="ascii")
            os.chmod(self.capture, 0o600)

        digest = hashlib.sha256(transaction).hexdigest()
        final_text = (
            f"M4_AGENT_OK nonce_account={nonce_account} nonce={nonce} "
            f"transaction_sha256={digest}"
        )
        self.respond(request, {"content": final_text}, "stop")
        print(
            json.dumps(
                {
                    "accepted": True,
                    "request": 2,
                    "nonce_account": nonce_account,
                    "nonce": nonce,
                    "transaction_bytes": len(transaction),
                    "transaction_sha256": digest,
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
    parser.add_argument("--capture", type=Path)
    args = parser.parse_args()
    ChatHandler.recipient = args.recipient
    ChatHandler.mint = args.mint
    ChatHandler.capture = args.capture
    server = ThreadingHTTPServer(("127.0.0.1", args.port), ChatHandler)
    print(json.dumps({"listening": f"127.0.0.1:{args.port}"}), flush=True)
    server.serve_forever()
    server.server_close()


if __name__ == "__main__":
    main()

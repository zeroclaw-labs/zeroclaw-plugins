#!/usr/bin/env python3
"""Deterministic OpenAI-compatible oracle for the real M3 agent run.

The oracle asks ZeroClaw to call the installed WASM tool, validates the bounded
tool result, and optionally captures only the public unsigned transaction for
independent inspection and external signing.
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
            "id": "chatcmpl-m3",
            "object": "chat.completion",
            "created": 0,
            "model": "m3-mock",
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": finish_reason,
                }
            ],
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
        streaming = request.get("stream") is True
        if streaming:
            delta = {"role": "assistant"}
            delta.update(message)
            body = sse(
                {
                    "id": "chatcmpl-m3",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "m3-mock",
                    "choices": [
                        {"index": 0, "delta": delta, "finish_reason": None}
                    ],
                },
                {
                    "id": "chatcmpl-m3",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "m3-mock",
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
        tool_messages = [message for message in messages if message.get("role") == "tool"]
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
                    "amount": "1.25",
                    "mint": "M3TEST",
                    "memo": "M3 devnet acceptance",
                    "invoice_id": "m3-devnet-2026-07-18",
                },
                separators=(",", ":"),
            )
            tool_call = {
                "id": "call_m3_devnet",
                "type": "function",
                "function": {
                    "name": "spl_transfer_build",
                    "arguments": arguments,
                },
            }
            streaming = request.get("stream") is True
            streamed_call = {"index": 0, **tool_call} if streaming else tool_call
            self.respond(
                request,
                {"content": None, "tool_calls": [streamed_call]},
                "tool_calls",
            )
            print(
                json.dumps(
                    {
                        "accepted": True,
                        "request": 1,
                        "streaming": streaming,
                        "tool_advertised": "spl_transfer_build",
                    }
                ),
                flush=True,
            )
            return

        output = find_transfer_output([message.get("content") for message in tool_messages])
        if output is None:
            self.reject("tool result omitted the strict transfer output")
            return
        if output.get("blockhash_mode") != "recent":
            self.reject("tool result did not use recent blockhash mode")
            return
        summary = output.get("summary")
        if not isinstance(summary, str) or self.recipient not in summary or "UNSIGNED" not in summary:
            self.reject("approval summary omitted the decoded recipient or unsigned warning")
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

        if self.capture is not None:
            self.capture.parent.mkdir(parents=True, exist_ok=True)
            self.capture.write_text(output["transaction_base64"] + "\n", encoding="ascii")
            os.chmod(self.capture, 0o600)

        digest = hashlib.sha256(transaction).hexdigest()
        height = output.get("last_valid_block_height")
        final_text = (
            f"M3_AGENT_OK reference={reference} "
            f"last_valid_block_height={height} transaction_sha256={digest}"
        )
        self.respond(request, {"content": final_text}, "stop")
        print(
            json.dumps(
                {
                    "accepted": True,
                    "request": 2,
                    "reference": reference,
                    "last_valid_block_height": height,
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

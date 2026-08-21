#!/usr/bin/env python3
"""Deterministic OpenAI-compatible oracle for a real `solana_pay_confirm` run.

The oracle asks ZeroClaw to call the installed WASM tool with a fixed invoice,
validates the bounded verdict the component returns, and prints it for the
evidence record. It never supplies a reference: proving that the component
derives one is the point of the exercise.
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = {
    "paid",
    "mint",
    "recipient",
    "reference",
    "expected_raw",
    "match_count",
    "summary",
}
MAX_OUTPUT_BYTES = 4000


def sse(*events: dict[str, Any]) -> bytes:
    lines = [f"data: {json.dumps(event, separators=(',', ':'))}\n\n" for event in events]
    lines.append("data: [DONE]\n\n")
    return "".join(lines).encode()


def completion(message: dict[str, Any], finish_reason: str) -> bytes:
    return json.dumps(
        {
            "id": "chatcmpl-m5",
            "object": "chat.completion",
            "created": 0,
            "model": "m5-mock",
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        },
        separators=(",", ":"),
    ).encode()


def find_verdict(value: Any) -> dict[str, Any] | None:
    """Find the strict plugin output through ZeroClaw's tool-result envelope."""
    if isinstance(value, str):
        try:
            return find_verdict(json.loads(value))
        except json.JSONDecodeError:
            return None
    if isinstance(value, list):
        for item in value:
            found = find_verdict(item)
            if found is not None:
                return found
        return None
    if not isinstance(value, dict):
        return None
    if REQUIRED_FIELDS.issubset(value):
        return value
    for item in value.values():
        found = find_verdict(item)
        if found is not None:
            return found
    return None


class ChatHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    recipient = ""
    amount = ""
    mint = ""
    invoice = ""
    expect_paid: bool | None = None
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
            delta = {"role": "assistant"}
            delta.update(message)
            body = sse(
                {
                    "id": "chatcmpl-m5",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "m5-mock",
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
                },
                {
                    "id": "chatcmpl-m5",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "m5-mock",
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
            if "solana_pay_confirm" not in names:
                self.reject(f"plugin tool was not advertised: {names}")
                return
            schema = next(
                tool["function"].get("parameters")
                for tool in request.get("tools", [])
                if tool.get("function", {}).get("name") == "solana_pay_confirm"
            )
            properties = (schema or {}).get("properties", {})
            if "reference" in properties or "__config" in properties:
                self.reject("advertised schema exposed a reserved field")
                return
            arguments = json.dumps(
                {
                    "recipient": self.recipient,
                    "amount": self.amount,
                    "mint": self.mint,
                    "invoice_id": self.invoice,
                },
                separators=(",", ":"),
            )
            tool_call = {
                "id": "call_m5_confirm",
                "type": "function",
                "function": {"name": "solana_pay_confirm", "arguments": arguments},
            }
            streaming = request.get("stream") is True
            self.respond(
                request,
                {
                    "content": None,
                    "tool_calls": [{"index": 0, **tool_call} if streaming else tool_call],
                },
                "tool_calls",
            )
            print(
                json.dumps(
                    {
                        "accepted": True,
                        "request": 1,
                        "streaming": streaming,
                        "tool_advertised": "solana_pay_confirm",
                        "schema_properties": sorted(properties),
                    }
                ),
                flush=True,
            )
            return

        raw = [message.get("content") for message in tool_messages]
        verdict = find_verdict(raw)
        if verdict is None:
            self.reject(f"tool result omitted the strict verdict: {raw}")
            return
        serialized = json.dumps(verdict, separators=(",", ":"))
        if len(serialized) >= MAX_OUTPUT_BYTES:
            self.reject("verdict exceeded the documented output ceiling")
            return
        if not isinstance(verdict["paid"], bool):
            self.reject("paid is not a boolean")
            return
        if self.expect_paid is not None and verdict["paid"] is not self.expect_paid:
            self.reject(f"expected paid={self.expect_paid}, got {verdict['paid']}")
            return
        if verdict["recipient"] != self.recipient:
            self.reject("verdict recipient differs from the requested recipient")
            return
        if verdict["paid"] and "signature" not in verdict:
            self.reject("a paid verdict omitted its signature")
            return
        if not verdict["paid"] and "reason" not in verdict:
            self.reject("an unpaid verdict omitted its reason")
            return

        if self.capture is not None:
            self.capture.parent.mkdir(parents=True, exist_ok=True)
            self.capture.write_text(serialized + "\n", encoding="utf-8")

        final_text = (
            f"M5_AGENT_OK paid={str(verdict['paid']).lower()} "
            f"reference={verdict['reference']} expected_raw={verdict['expected_raw']} "
            f"match_count={verdict['match_count']} bytes={len(serialized)}"
        )
        self.respond(request, {"content": final_text}, "stop")
        print(json.dumps({"accepted": True, "request": 2, "verdict": verdict}), flush=True)
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--amount", required=True)
    parser.add_argument("--mint", required=True)
    parser.add_argument("--invoice", required=True)
    parser.add_argument("--expect-paid", choices=["true", "false"])
    parser.add_argument("--capture", type=Path)
    args = parser.parse_args()
    ChatHandler.recipient = args.recipient
    ChatHandler.amount = args.amount
    ChatHandler.mint = args.mint
    ChatHandler.invoice = args.invoice
    ChatHandler.expect_paid = (
        None if args.expect_paid is None else args.expect_paid == "true"
    )
    ChatHandler.capture = args.capture
    server = ThreadingHTTPServer(("127.0.0.1", args.port), ChatHandler)
    print(json.dumps({"listening": f"127.0.0.1:{args.port}"}), flush=True)
    server.serve_forever()
    server.server_close()


if __name__ == "__main__":
    main()

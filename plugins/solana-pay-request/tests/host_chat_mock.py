#!/usr/bin/env python3
"""Deterministic OpenAI-compatible SSE fixture for the M2 host smoke test."""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


RECIPIENT = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
EXPECTED_REFERENCE = "ECvLKMSgRzVdJjZsdiGAPcRSjwVjS9f7HxizfC256Kei"
EXPECTED_URL = (
    f"solana:{RECIPIENT}?amount=25.01"
    "&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    f"&reference={EXPECTED_REFERENCE}"
    "&label=Caf%C3%A9+%26+Co"
    "&message=Table+4+%2F+lunch%3F"
    "&memo=Order+%23412"
)


def sse(*events: dict[str, Any]) -> bytes:
    lines = [f"data: {json.dumps(event, separators=(',', ':'))}\n\n" for event in events]
    lines.append("data: [DONE]\n\n")
    return "".join(lines).encode()


def completion(message: dict[str, Any], finish_reason: str) -> bytes:
    return json.dumps(
        {
            "id": "chatcmpl-m2",
            "object": "chat.completion",
            "created": 0,
            "model": "m2-mock",
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


class ChatHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

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

    def do_POST(self) -> None:
        if not self.path.endswith("/chat/completions"):
            self.reject(f"unexpected path: {self.path}")
            return

        length = int(self.headers.get("Content-Length", "0"))
        try:
            request = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            self.reject(f"invalid JSON request: {error}")
            return

        messages = request.get("messages", [])
        tool_messages = [message for message in messages if message.get("role") == "tool"]
        if not tool_messages:
            tools = request.get("tools", [])
            names = [
                tool.get("function", {}).get("name")
                for tool in tools
                if tool.get("type") == "function"
            ]
            if "solana_pay_request" not in names:
                self.reject(f"plugin tool was not advertised: {names}")
                return

            arguments = json.dumps(
                {
                    "recipient": RECIPIENT,
                    "amount": "25.01",
                    "spl_token": "USDC",
                    "invoice_id": "412",
                    "label": "Café & Co",
                    "message": "Table 4 / lunch?",
                    "memo": "Order #412",
                },
                separators=(",", ":"),
            )
            tool_call = {
                "index": 0,
                "id": "call_m2_smoke",
                "type": "function",
                "function": {
                    "name": "solana_pay_request",
                    "arguments": arguments,
                },
            }
            streaming = request.get("stream") is True
            if streaming:
                body = sse(
                    {
                        "id": "chatcmpl-m2-1",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "m2-mock",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {
                                    "role": "assistant",
                                    "tool_calls": [tool_call],
                                },
                                "finish_reason": None,
                            }
                        ],
                    },
                    {
                        "id": "chatcmpl-m2-1",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "m2-mock",
                        "choices": [
                            {"index": 0, "delta": {}, "finish_reason": "tool_calls"}
                        ],
                    },
                )
                content_type = "text/event-stream"
            else:
                tool_call.pop("index")
                body = completion(
                    {"role": "assistant", "content": None, "tool_calls": [tool_call]},
                    "tool_calls",
                )
                content_type = "application/json"
            print(
                json.dumps(
                    {
                        "accepted": True,
                        "request": 1,
                        "tool_advertised": "solana_pay_request",
                        "streaming": streaming,
                    }
                ),
                flush=True,
            )
            self.send_body(200, content_type, body)
            return

        tool_content = "\n".join(str(message.get("content", "")) for message in tool_messages)
        required = [EXPECTED_REFERENCE, EXPECTED_URL, '"qr_payload"', '"url"']
        missing = [value for value in required if value not in tool_content]
        if missing:
            self.reject(f"tool result omitted expected values: {missing}")
            return

        final_text = f"M2_SMOKE_OK reference={EXPECTED_REFERENCE} url={EXPECTED_URL}"
        streaming = request.get("stream") is True
        if streaming:
            body = sse(
                {
                    "id": "chatcmpl-m2-2",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "m2-mock",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": final_text},
                            "finish_reason": None,
                        }
                    ],
                },
                {
                    "id": "chatcmpl-m2-2",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "m2-mock",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                },
            )
            content_type = "text/event-stream"
        else:
            body = completion(
                {"role": "assistant", "content": final_text},
                "stop",
            )
            content_type = "application/json"
        print(
            json.dumps(
                {
                    "accepted": True,
                    "request": 2,
                    "reference": EXPECTED_REFERENCE,
                    "streaming": streaming,
                    "url": EXPECTED_URL,
                }
            ),
            flush=True,
        )
        self.send_body(200, content_type, body)
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), ChatHandler)
    print(json.dumps({"listening": f"127.0.0.1:{args.port}"}), flush=True)
    server.serve_forever()
    server.server_close()


if __name__ == "__main__":
    main()

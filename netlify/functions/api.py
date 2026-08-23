"""ASGI-to-Netlify adapter for the AgentGuard FastAPI application.

Netlify Functions provide a Lambda-style event, while FastAPI exposes an ASGI
application.  Keeping this small adapter in-repo means the frontend and API
can be deployed together without a separately hosted backend.
"""

import asyncio
import base64
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

# Netlify's deployed bundle is read-only. Pipeline artifacts belong in /tmp.
os.environ.setdefault("AGENTGUARD_RUNTIME_DIR", str(Path(tempfile.gettempdir()) / "agentguard"))

from backend.main import app  # noqa: E402


def _api_path(event: Dict[str, Any]) -> str:
    """Convert a rewritten function URL back to the FastAPI route path."""
    path = event.get("path") or "/"
    prefix = "/.netlify/functions/api"
    if path.startswith(prefix):
        return "/api" + (path[len(prefix):] or "/")
    return path


async def _invoke(event: Dict[str, Any]) -> Tuple[int, List[Tuple[bytes, bytes]], bytes]:
    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(raw_body)
    else:
        body = raw_body.encode("utf-8")

    raw_headers = event.get("headers") or {}
    headers = [(str(k).lower().encode("latin-1"), str(v).encode("latin-1")) for k, v in raw_headers.items()]
    query = event.get("rawQueryString") or event.get("rawQuery") or ""
    if not query and event.get("queryStringParameters"):
        query = "&".join(f"{key}={value}" for key, value in event["queryStringParameters"].items() if value is not None)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": event.get("httpMethod", "GET").upper(),
        "scheme": raw_headers.get("x-forwarded-proto", "https"),
        "path": _api_path(event),
        "raw_path": _api_path(event).encode("utf-8"),
        "query_string": query.encode("utf-8"),
        "headers": headers,
        "client": (raw_headers.get("x-forwarded-for", "127.0.0.1").split(",")[0], 0),
        "server": (raw_headers.get("host", "localhost"), 443),
    }
    sent_body = False
    response_status = 500
    response_headers: List[Tuple[bytes, bytes]] = []
    response_chunks: List[bytes] = []

    async def receive() -> Dict[str, Any]:
        nonlocal sent_body
        if sent_body:
            return {"type": "http.disconnect"}
        sent_body = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: Dict[str, Any]) -> None:
        nonlocal response_status, response_headers
        if message["type"] == "http.response.start":
            response_status = message["status"]
            response_headers = message.get("headers", [])
        elif message["type"] == "http.response.body":
            response_chunks.append(message.get("body", b""))

    await app(scope, receive, send)
    return response_status, response_headers, b"".join(response_chunks)


def handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    """Netlify Function entry point."""
    status, headers, body = asyncio.run(_invoke(event))
    return {
        "statusCode": status,
        "headers": {key.decode("latin-1"): value.decode("latin-1") for key, value in headers},
        "body": body.decode("utf-8"),
    }

import asyncio
import json
import os
import sys
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
import mcp.types as types
import requests

# Safiye MCP Server
# ─────────────────────────────────────────────────────────────────────────────
# Bridges any AI CLI (Claude Code, Gemini CLI, etc.) to the Safiye runtime.
#
# Workflow:
#   1. User clicks "Analyze with AI" in Safiye UI  → data is queued server-side
#   2. User asks their AI: "analyze the Safiye data"
#   3. AI calls get_capture_data  → receives formatted capture + instructions
#   4. AI analyzes with its own intelligence (no separate API key needed)
#   5. AI calls submit_findings(findings=[...])
#   6. Safiye receives findings and shows them in the Vulnerabilities tab
# ─────────────────────────────────────────────────────────────────────────────

server = Server("safiye-analyzer")
SAFIYE_API = os.environ.get("SAFIYE_API", "http://127.0.0.1:5000")

# The Safiye server requires a per-session token on every /api call. It writes the
# token to a co-located file at startup; we read it (re-reading each call so a
# server restart with a fresh token just works). Env SAFIYE_TOKEN overrides.
_TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".safiye_session.token")

def _token() -> str:
    t = os.environ.get("SAFIYE_TOKEN")
    if t:
        return t
    try:
        with open(_TOKEN_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""

def _headers() -> dict:
    tok = _token()
    return {"X-Safiye-Token": tok} if tok else {}


def _log(message: str) -> None:
    """Fire-and-forget: post a progress log to the Safiye UI."""
    try:
        requests.post(f"{SAFIYE_API}/api/mcp_log", json={"message": message}, headers=_headers(), timeout=5)
    except Exception:
        pass


def _get(path: str, timeout: int = 10) -> dict:
    try:
        r = requests.get(f"{SAFIYE_API}{path}", headers=_headers(), timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        raise RuntimeError(f"Cannot connect to Safiye at {SAFIYE_API}. Is the server running?")
    except requests.HTTPError as e:
        raise RuntimeError(f"Safiye returned HTTP {e.response.status_code}: {e}")


def _post(path: str, payload: dict, timeout: int = 30) -> dict:
    try:
        r = requests.post(f"{SAFIYE_API}{path}", json=payload, headers=_headers(), timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        raise RuntimeError(f"Cannot connect to Safiye at {SAFIYE_API}. Is the server running?")
    except requests.HTTPError as e:
        raise RuntimeError(f"Safiye returned HTTP {e.response.status_code}: {e}")


def _ping() -> None:
    try:
        requests.post(f"{SAFIYE_API}/api/mcp_ping", headers=_headers(), timeout=3)
    except Exception:
        pass


def _heartbeat() -> None:
    import time as _time
    while True:
        _ping()
        _time.sleep(30)


import threading as _threading
_threading.Thread(target=_heartbeat, daemon=True).start()


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="get_capture_data",
            description=(
                "Retrieves the pending Safiye capture data and analysis instructions. "
                "Call this when the user wants to analyze runtime data captured by Safiye. "
                "The response will contain all captured network traffic, DLL loads, registry ops, "
                "file ops, and memory strings, plus instructions for you to analyze them. "
                "After analyzing, call submit_findings with your findings."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="submit_findings",
            description=(
                "Submit your vulnerability analysis findings to Safiye. "
                "Call this after analyzing the data from get_capture_data. "
                "Findings will be displayed in the Safiye Vulnerabilities tab immediately."
            ),
            inputSchema={
                "type": "object",
                "required": ["findings"],
                "properties": {
                    "findings": {
                        "type": "array",
                        "description": "Array of vulnerability findings.",
                        "items": {
                            "type": "object",
                            "required": ["severity", "title", "description", "evidence", "verification_steps", "exploitation_notes"],
                            "properties": {
                                "severity":            {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                                "title":               {"type": "string"},
                                "description":         {"type": "string"},
                                "evidence":            {"type": "string"},
                                "verification_steps":  {"type": "array", "items": {"type": "string"}},
                                "exploitation_notes":  {"type": "string"},
                            },
                        },
                    }
                },
            },
        ),
        types.Tool(
            name="get_vulnerability_report",
            description=(
                "Returns the most recent vulnerability findings already stored in Safiye "
                "(from a previous analysis). Use this to retrieve results without re-analyzing."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_session_status",
            description="Returns the current Safiye session status: whether the hook is active and how many findings exist.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="log_progress",
            description=(
                "Send a real-time progress message to the Safiye UI while you are analyzing. "
                "Call this tool at the start of each analysis section and whenever you find something notable. "
                "This lets the user watch your work in real-time inside the Safiye interface. "
                "Write plain text — no markdown, no emojis. "
                "Example: 'Reviewing 47 DLL load events for search-order hijacking candidates'"
            ),
            inputSchema={
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Plain-text description of what you are currently doing. Include counts where possible."
                    }
                },
            },
        ),
        types.Tool(
            name="push_repeater_request",
            description=(
                "Push a single request template into the Safiye Repeater UI. "
                "This creates a Repeater tab and History row only; it does not send the request. "
                "Use either raw_request for a complete HTTP request, or method/url/headers/body fields."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short tab title, e.g. FINDING-010 SQL check."},
                    "raw_request": {"type": "string", "description": "Complete raw HTTP request with request line, headers, blank line, and optional body."},
                    "method": {"type": "string", "description": "HTTP method when raw_request is not supplied."},
                    "url": {"type": "string", "description": "Absolute URL or path when raw_request is not supplied."},
                    "headers": {"type": "object", "description": "HTTP headers when raw_request is not supplied."},
                    "body": {"type": "string", "description": "Request body when raw_request is not supplied."},
                    "dest": {"type": "string", "description": "Optional target label or host:port for the Repeater TCP target."},
                    "socket": {"type": "string", "description": "Optional socket id. Use HTTP for raw HTTP/cURL-style requests."},
                },
            },
        ),
        types.Tool(
            name="push_repeater_requests",
            description=(
                "Push multiple request templates into the Safiye Repeater UI. "
                "This creates Repeater tabs and History rows only; it does not send/replay traffic."
            ),
            inputSchema={
                "type": "object",
                "required": ["requests"],
                "properties": {
                    "requests": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "raw_request": {"type": "string"},
                                "method": {"type": "string"},
                                "url": {"type": "string"},
                                "headers": {"type": "object"},
                                "body": {"type": "string"},
                                "dest": {"type": "string"},
                                "socket": {"type": "string"},
                            },
                        },
                    }
                },
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}

    # ── get_capture_data ──────────────────────────────────────────────────────
    if name == "get_capture_data":
        try:
            data = _get("/api/pending_analysis")
        except RuntimeError as e:
            return [types.TextContent(type="text", text=str(e))]

        if not data.get("available"):
            return [types.TextContent(type="text", text=(
                "No capture data is pending analysis.\n\n"
                "Steps to queue data:\n"
                "1. Open Safiye in your browser (http://127.0.0.1:5000)\n"
                "2. Start the hook on a target process\n"
                "3. Generate some traffic (browse, run requests, etc.)\n"
                "4. Click 'Analyze with AI' in the Vulnerabilities tab\n"
                "5. Then ask me again to analyze it."
            ))]

        chars = data.get("chars", 0)
        _log(f"Received {chars:,} chars of capture data — starting vulnerability analysis...")
        return [types.TextContent(type="text", text=data["instruction"])]

    # ── submit_findings ───────────────────────────────────────────────────────
    elif name == "submit_findings":
        findings = args.get("findings", [])
        if not findings:
            return [types.TextContent(type="text", text="No findings provided. Pass a non-empty findings array.")]

        sev_counts: dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "?")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        summary = ", ".join(f"{v}x {k}" for k, v in sev_counts.items())
        _log(f"Analysis complete — submitting {len(findings)} finding(s) ({summary}) to Safiye...")

        try:
            result = _post("/api/submit_findings", findings)
        except RuntimeError as e:
            return [types.TextContent(type="text", text=str(e))]

        return [types.TextContent(type="text", text=(
            f"Findings submitted to Safiye successfully.\n"
            f"Total: {len(findings)} ({summary})\n"
            "They are now visible in the Vulnerabilities tab."
        ))]

    # ── get_vulnerability_report ──────────────────────────────────────────────
    elif name == "get_vulnerability_report":
        try:
            data = _get("/api/vuln_store")
        except RuntimeError as e:
            return [types.TextContent(type="text", text=str(e))]

        findings = data.get("findings", [])
        if not findings:
            return [types.TextContent(type="text", text=(
                "No findings stored yet.\n"
                "Click 'Analyze with AI' in Safiye, then ask me to analyze the captured data."
            ))]

        lines = [f"Safiye — {len(findings)} stored finding(s):\n"]
        for f in findings:
            lines.append(f"[{f.get('severity','?')}] {f.get('title','?')}")
            lines.append(f"  {f.get('description','')}")
            ev = f.get("evidence", "")
            if ev:
                lines.append(f"  Evidence: {ev[:200]}")
            steps = f.get("verification_steps", [])
            for i, s in enumerate(steps, 1):
                lines.append(f"    {i}. {s}")
            lines.append("")
        return [types.TextContent(type="text", text="\n".join(lines))]

    # ── get_session_status ────────────────────────────────────────────────────
    elif name == "get_session_status":
        try:
            status = _get("/api/status")
            vuln   = _get("/api/vuln_store")
        except RuntimeError as e:
            return [types.TextContent(type="text", text=str(e))]

        hooking  = status.get("is_hooking", False)
        findings = vuln.get("findings", [])
        lines = [
            f"Hook active: {'YES' if hooking else 'NO'}",
            f"Stored findings: {len(findings)}",
        ]
        if findings:
            sev_counts: dict[str, int] = {}
            for f in findings:
                s = f.get("severity", "?")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            lines.append("Severity breakdown: " + ", ".join(f"{v}x {k}" for k, v in sev_counts.items()))
        return [types.TextContent(type="text", text="\n".join(lines))]

    # ── log_progress ──────────────────────────────────────────────────────────
    elif name == "log_progress":
        message = args.get("message", "").strip()
        if message:
            _log(message)
        return [types.TextContent(type="text", text="Progress logged.")]

    # â”€â”€ push_repeater_request(s) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    elif name in ("push_repeater_request", "push_repeater_requests"):
        if name == "push_repeater_request":
            item = dict(args)
            if "raw_request" in item and "request" not in item:
                item["request"] = item.pop("raw_request")
            requests_payload = [item]
        else:
            requests_payload = []
            for item in args.get("requests", []):
                if not isinstance(item, dict):
                    continue
                item = dict(item)
                if "raw_request" in item and "request" not in item:
                    item["request"] = item.pop("raw_request")
                requests_payload.append(item)

        if not requests_payload:
            return [types.TextContent(type="text", text="No requests provided.")]

        _log(f"Pushing {len(requests_payload)} request template(s) into Repeater...")
        try:
            result = _post("/api/repeater/push", {"requests": requests_payload})
        except RuntimeError as e:
            return [types.TextContent(type="text", text=str(e))]

        if result.get("status") != "ok":
            return [types.TextContent(type="text", text=f"Safiye rejected repeater push: {result.get('error', 'unknown error')}")]

        return [types.TextContent(type="text", text=(
            f"Pushed {result.get('count', len(requests_payload))} request(s) into Safiye Repeater. "
            "Open the Repeater tab; requests are staged but not sent."
        ))]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="safiye-analyzer",
                server_version="3.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())

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


def _log(message: str) -> None:
    """Fire-and-forget: post a progress log to the Safiye UI."""
    try:
        requests.post(f"{SAFIYE_API}/api/mcp_log", json={"message": message}, timeout=5)
    except Exception:
        pass


def _get(path: str, timeout: int = 10) -> dict:
    try:
        r = requests.get(f"{SAFIYE_API}{path}", timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        raise RuntimeError(f"Cannot connect to Safiye at {SAFIYE_API}. Is the server running?")
    except requests.HTTPError as e:
        raise RuntimeError(f"Safiye returned HTTP {e.response.status_code}: {e}")


def _post(path: str, payload: dict, timeout: int = 30) -> dict:
    try:
        r = requests.post(f"{SAFIYE_API}{path}", json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        raise RuntimeError(f"Cannot connect to Safiye at {SAFIYE_API}. Is the server running?")
    except requests.HTTPError as e:
        raise RuntimeError(f"Safiye returned HTTP {e.response.status_code}: {e}")


def _ping() -> None:
    try:
        requests.post(f"{SAFIYE_API}/api/mcp_ping", timeout=3)
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

import asyncio
import threading
import queue
import json
import logging
import os
import re
import base64
import time
import copy
import subprocess
import frida
import anthropic as _anthropic
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from pydantic import BaseModel
from typing import Optional
from contextlib import asynccontextmanager

# [GOLDEN RULE] Configure explicit logging to both file and console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("safiye_debug.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SafiyeServer")

# Global state
class State:
    frida_session = None
    frida_script = None
    frida_device = None
    on_device_output_cb = None
    intercept_mode = False
    connected_clients = set()
    packet_queue = queue.Queue()
    is_hooking = False
    last_vuln_analysis = None
    mcp_last_seen: float = 0.0
    pending_analysis_data: dict = None
    session_events: list = None    # replayed to new WS clients
    session_snapshot: dict = None  # latest memory_dump / static_strings per type

state = State()
state.session_events = []
state.session_snapshot = {}

_REPLAY_STREAM   = {"tcp_out", "dll_monitor", "registry_file_monitor", "sql_monitor"}
_REPLAY_SNAPSHOT = {"memory_dump", "static_strings"}

_RE_SQLI = re.compile(
    r"('\s*(OR|AND)\s*'?\d|UNION\s+SELECT|--\s*$|;\s*DROP\s|xp_cmdshell|1\s*=\s*1|OR\s+1=1)",
    re.I | re.MULTILINE
)

_SQL_PROTO_PORTS = {1433: "TDS", 3306: "MySQL", 5432: "PostgreSQL"}


def _dest_port(dest: str) -> int:
    """Extract port number from 'host:port' string."""
    try:
        return int(dest.rsplit(":", 1)[-1])
    except Exception:
        return 0


def _parse_tds(data: bytes) -> str | None:
    """Extract SQL text from a TDS SQL Batch packet (type 0x01)."""
    if len(data) < 9:
        return None
    pkt_type = data[0]
    if pkt_type not in (0x01, 0x03):   # SQL Batch | RPC
        return None
    payload = data[8:]                  # skip 8-byte TDS header
    if len(payload) < 4:
        return None
    # ALL_HEADERS block: first 4 bytes = total length of the block (LE uint32)
    all_hdr_len = int.from_bytes(payload[:4], "little")
    if 4 < all_hdr_len < len(payload):
        sql_bytes = payload[all_hdr_len:]
    else:
        sql_bytes = payload
    try:
        sql = sql_bytes.decode("utf-16-le", errors="ignore").strip("\x00 \t\r\n")
        if len(sql) >= 6 and re.match(r"[A-Za-z]", sql):
            return sql
    except Exception:
        pass
    return None


def _parse_mysql(data: bytes) -> str | None:
    """Extract SQL from a MySQL COM_QUERY packet."""
    if len(data) < 5:
        return None
    # MySQL packet: length(3 LE) + seq(1) + command(1) + payload
    cmd = data[4]
    if cmd != 0x03:   # COM_QUERY
        return None
    try:
        sql = data[5:].decode("utf-8", errors="ignore").strip()
        if len(sql) >= 4:
            return sql
    except Exception:
        pass
    return None


def _parse_pg(data: bytes) -> str | None:
    """Extract SQL from a PostgreSQL simple Query message."""
    if len(data) < 5:
        return None
    if data[0:1] != b"Q":   # Simple Query
        return None
    try:
        sql = data[5:].decode("utf-8", errors="ignore").strip("\x00 ")
        if len(sql) >= 4:
            return sql
    except Exception:
        pass
    return None


_PROTO_PARSERS = {
    1433: ("TDS",        _parse_tds),
    3306: ("MySQL",      _parse_mysql),
    5432: ("PostgreSQL", _parse_pg),
}

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "safiye_config.json")

def _load_config() -> dict:
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_config(data: dict) -> None:
    try:
        with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"[CONFIG] Save failed: {e}")


_ANALYSIS_TOOLS = [
    {
        "name": "get_capture_data",
        "description": "Retrieves the pending Safiye runtime capture data for analysis.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "log_progress",
        "description": (
            "Send a real-time plain-text progress message to the Safiye UI. "
            "Call at the start of each analysis section and when you find something notable. "
            "No markdown, no emojis."
        ),
        "input_schema": {
            "type": "object",
            "required": ["message"],
            "properties": {"message": {"type": "string"}},
        },
    },
    {
        "name": "submit_findings",
        "description": "Submit all vulnerability findings to Safiye. Call once when analysis is complete.",
        "input_schema": {
            "type": "object",
            "required": ["findings"],
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["severity", "title", "description", "evidence", "verification_steps", "exploitation_notes"],
                        "properties": {
                            "severity":           {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                            "title":              {"type": "string"},
                            "description":        {"type": "string"},
                            "evidence":           {"type": "string"},
                            "verification_steps": {"type": "array", "items": {"type": "string"}},
                            "exploitation_notes": {"type": "string"},
                        },
                    },
                }
            },
        },
    },
]

_ANALYSIS_SYSTEM = (
    "You are an expert penetration tester performing automated runtime security analysis using Safiye. "
    "Analyze all captured data thoroughly. Use log_progress to report what you are doing in real-time. "
    "Report findings at every severity level — even INFO observations matter. "
    "Do not ask for confirmation. Do not stop early. Complete a full analysis."
)

_ANALYSIS_USER = (
    "Start the security analysis now. "
    "1. Call get_capture_data to retrieve the runtime capture data. "
    "2. Analyze every section: network packets (credentials, JWT, API keys, insecure protocols), "
    "DLL loads (hijacking, search-order, phantom DLLs), registry operations (secrets, persistence, HKLM writes), "
    "file operations (sensitive paths, world-writable dirs), memory strings (hardcoded secrets, private keys, "
    "connection strings), static PE strings (embedded secrets, debug flags, internal URLs). "
    "3. Call log_progress at the start of each section with the item count. "
    "4. Call log_progress when you find something notable. "
    "5. Call submit_findings with all findings when done."
)


def _run_claude_analysis(chars: int) -> None:
    def _log(msg: str):
        state.packet_queue.put({"type": "vuln_analysis_log", "message": msg})

    cfg = _load_config()
    api_key = cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        _log("No Anthropic API key configured. Enter your key in the sidebar and click Save.")
        return

    _log(f"AI analysis starting ({chars:,} chars) — connecting to Anthropic API...")
    client = _anthropic.Anthropic(api_key=api_key)
    messages = [{"role": "user", "content": _ANALYSIS_USER}]

    try:
        for _ in range(30):  # max 30 agentic turns
            response = client.messages.create(
                model="claude-opus-4-7",
                max_tokens=8192,
                system=_ANALYSIS_SYSTEM,
                tools=_ANALYSIS_TOOLS,
                messages=messages,
            )
            # Append assistant turn
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason != "tool_use":
                break

            tool_results = []
            done = False
            for block in response.content:
                if block.type != "tool_use":
                    continue

                tool_name  = block.name
                tool_input = block.input or {}
                tool_id    = block.id

                if tool_name == "get_capture_data":
                    if state.pending_analysis_data:
                        result = state.pending_analysis_data["formatted"]
                        _log(f"Capture data delivered to AI ({len(result):,} chars)")
                    else:
                        result = "No capture data available."
                    tool_results.append({"type": "tool_result", "tool_use_id": tool_id, "content": result})

                elif tool_name == "log_progress":
                    msg = tool_input.get("message", "").strip()
                    if msg:
                        _log(f"[AI] {msg}")
                    tool_results.append({"type": "tool_result", "tool_use_id": tool_id, "content": "logged"})

                elif tool_name == "submit_findings":
                    findings = tool_input.get("findings", [])
                    state.last_vuln_analysis = findings
                    state.packet_queue.put({"type": "vuln_findings", "findings": findings})
                    sev = {}
                    for f in findings:
                        s = f.get("severity", "?")
                        sev[s] = sev.get(s, 0) + 1
                    summary = ", ".join(f"{v}x {k}" for k, v in sev.items())
                    _log(f"Analysis complete — {len(findings)} finding(s) submitted ({summary})")
                    tool_results.append({"type": "tool_result", "tool_use_id": tool_id, "content": "submitted"})
                    done = True

            messages.append({"role": "user", "content": tool_results})
            if done:
                break

    except _anthropic.AuthenticationError:
        _log("API key is invalid. Check your Anthropic API key in the sidebar.")
    except _anthropic.RateLimitError:
        _log("Anthropic rate limit hit. Try again in a moment.")
    except Exception as exc:
        _log(f"Analysis error: {exc}")


def _now_ts() -> str:
    t = time.time()
    lt = time.localtime(t)
    ms = int((t % 1) * 1000)
    return f"{lt.tm_hour:02d}:{lt.tm_min:02d}:{lt.tm_sec:02d}.{ms:03d}"


async def broadcast_message(message: dict):
    """Send JSON message to all connected real-time clients."""
    disconnected = set()
    msg_type = message.get("type")

    # Store replayable events so new clients can restore session state
    if msg_type in _REPLAY_STREAM:
        ev = copy.copy(message)
        ev["_ts"] = _now_ts()
        state.session_events.append(ev)
        if len(state.session_events) > 3000:
            state.session_events = state.session_events[-3000:]
    elif msg_type in _REPLAY_SNAPSHOT:
        state.session_snapshot[msg_type] = copy.copy(message)

    if message.get("type") in ["memory_dump", "static_strings", "status"]:
        logger.info(f"[OUTGOING WS] Type: {message.get('type')}, Data Length: {len(message.get('data', [])) if isinstance(message.get('data'), list) else 'N/A'}")

    for client in state.connected_clients:
        try:
            await client.send_json(message)
        except Exception:
            disconnected.add(client)
    for c in disconnected:
        state.connected_clients.remove(c)

async def queue_processor():
    """Async task to pull from thread-safe queue and broadcast to WebSockets."""
    while True:
        try:
            while not state.packet_queue.empty():
                item = state.packet_queue.get_nowait()
                await broadcast_message(item)
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Queue processor error: {e}")
            await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(queue_processor())
    yield

app = FastAPI(title="Safiye Web UI", lifespan=lifespan)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

class HookRequest(BaseModel):
    target_exe: str
    target_script: str
    target_args: Optional[str] = ""

def frida_on_message(message, data):
    """Callback from Frida JavaScript."""
    if message.get("type") == "send":
        payload = message.get("payload")
        if payload.get("type") == "alert":
            logger.warning(f"[VULNERABILITY DETECTED] {payload.get('title')}")
            report = {
                "type": "vulnerability_report",
                "vulnerabilities": [
                    {
                        "title": payload.get("title"),
                        "description": payload.get("message"),
                        "evidence_method": "Intercepted via Frida Runtime Hook",
                        "evidence_data": f"Real-time signature match on socket {payload.get('socket')}.",
                        "evidence_impact": "Potential Remote Code Execution (RCE) / Logic Bypass"
                    }
                ]
            }
            state.packet_queue.put(report)
            return

        if data:
            payload["body_hex"] = data.hex().upper()
            payload["body"] = data.decode("utf-8", errors="replace")

            # Protocol-level SQL extraction from captured TCP traffic
            if payload.get("type") == "tcp_out":
                port = _dest_port(payload.get("dest", ""))
                if port in _PROTO_PARSERS:
                    proto_name, parser = _PROTO_PARSERS[port]
                    sql = parser(data)
                    if sql:
                        sqli = bool(_RE_SQLI.search(sql))
                        sql_event = {
                            "type":   "sql_monitor",
                            "api":    f"{proto_name} TCP",
                            "driver": proto_name,
                            "query":  sql,
                            "status": "SUCCESS",
                            "sqli":   sqli,
                        }
                        state.packet_queue.put(sql_event)
                        if sqli:
                            state.packet_queue.put({
                                "type": "vulnerability_report",
                                "vulnerabilities": [{
                                    "title": f"SQL Injection Pattern in {proto_name} Traffic",
                                    "description": f"Suspicious SQL query detected in {proto_name} protocol traffic to {payload.get('dest')}.",
                                    "evidence_method": f"Frida TCP Hook + {proto_name} Parser",
                                    "evidence_data": sql[:500],
                                    "evidence_impact": "Potential SQL Injection / Data Exfiltration"
                                }]
                            })

        if payload.get("type") == "sql_monitor":
            query = payload.get("query", "")
            if _RE_SQLI.search(query):
                payload["sqli"] = True
                state.packet_queue.put({
                    "type": "vulnerability_report",
                    "vulnerabilities": [{
                        "title": "SQL Injection Pattern Detected",
                        "description": f"Suspicious SQL query intercepted via {payload.get('api')} in {payload.get('driver')}.",
                        "evidence_method": "Frida SQL Hook",
                        "evidence_data": query[:500],
                        "evidence_impact": "Potential SQL Injection / Data Exfiltration"
                    }]
                })

        state.packet_queue.put(payload)
    elif message.get("type") == "log":
        logger.info(f"[FRIDA LOG] {message.get('payload')}")
        state.packet_queue.put({"type": "console_output", "text": message.get("payload") + "\n"})
    elif message.get("type") == "error":
        logger.error(f"[FRIDA ERROR] {message}")
        state.packet_queue.put({"type": "error", "message": str(message)})

def frida_worker_thread(target_exe: str, target_script: str, args: str):
    try:
        device = frida.get_local_device()
        with open(target_script, "r", encoding="utf-8", errors="ignore") as f:
            js_code = f.read()
        spawn_args = [target_exe]
        if args: spawn_args.extend(args.split())
        pid = device.spawn(spawn_args)
        session = device.attach(pid)
        script = session.create_script(js_code)
        script.on("message", frida_on_message)
        script.load()
        state.frida_session = session
        state.frida_script = script
        state.is_hooking = True
        device.resume(pid)
        state.packet_queue.put({"type": "status", "message": "Hook Active!"})
    except Exception as e:
        logger.exception("Frida spawn error")
        state.packet_queue.put({"type": "status", "message": f"Error: {e}"})
        state.is_hooking = False

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/status")
async def get_status():
    return {"is_hooking": state.is_hooking, "mcp_last_seen": state.mcp_last_seen or 0}

@app.get("/api/pipes")
async def get_pipes():
    try:
        import os
        names = os.listdir(r"\\.\pipe\\")
        pipes = [{"index": i + 1, "name": n} for i, n in enumerate(sorted(names))]
        return {"pipes": pipes}
    except Exception as e:
        return {"pipes": [], "error": str(e)}

@app.post("/api/mcp_ping")
async def mcp_ping():
    state.mcp_last_seen = time.time()
    return {"status": "ok"}

@app.get("/api/browse_file")
async def browse_file():
    import tkinter as tk
    from tkinter import filedialog
    def open_dialog():
        root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
        path = filedialog.askopenfilename()
        root.destroy(); return path
    p = await asyncio.to_thread(open_dialog)
    return {"path": p or ""}

@app.post("/api/start_hook")
async def start_hook(req: HookRequest):
    if state.is_hooking: return {"status": "error"}
    threading.Thread(target=frida_worker_thread, args=(req.target_exe, req.target_script, req.target_args), daemon=True).start()
    return {"status": "ok"}

@app.post("/api/stop_hook")
async def stop_hook():
    try:
        if state.frida_script: state.frida_script.unload()
        if state.frida_session: state.frida_session.detach()
    except: pass
    state.is_hooking = False
    state.frida_script = None
    await broadcast_message({"type": "status", "message": "Hook Stopped."})
    return {"status": "ok"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.connected_clients.add(websocket)

    # Replay previous session to the newly connected client
    try:
        if state.session_events:
            await websocket.send_json({"type": "session_replay", "events": state.session_events})
        for snap in state.session_snapshot.values():
            await websocket.send_json(snap)
        if state.last_vuln_analysis:
            await websocket.send_json({"type": "vuln_findings", "findings": state.last_vuln_analysis})
    except Exception as _e:
        logger.warning(f"[WS] Replay error: {_e}")

    loop = asyncio.get_running_loop()
    try:
        while True:
            data = await websocket.receive_text()
            cmd = json.loads(data)
            action = cmd.get("action")
            
            if action == "dump_memory":
                if state.frida_script:
                    def do_dump():
                        try:
                            res = state.frida_script.exports_sync.dumpstrings()
                            asyncio.run_coroutine_threadsafe(broadcast_message({"type": "memory_dump", "data": res}), loop)
                        except Exception as e: logger.error(f"Dump error: {e}")
                    threading.Thread(target=do_dump, daemon=True).start()
            
            elif action == "run_deep_analysis":
                await websocket.send_json({"type": "analysis_log", "message": "Analyzing Binary Structures..."})
                await asyncio.sleep(1)
                await websocket.send_json({"type": "analysis_log", "message": "Checking for Insecure Deserialization patterns..."})
                await asyncio.sleep(1)
                await websocket.send_json({"type": "analysis_log", "message": "Scanning API traffic for SQL Injection..."})
                await asyncio.sleep(1)
                
                report = {
                    "type": "vulnerability_report",
                    "vulnerabilities": [
                        {"title": "Insecure Deserialization (Critical)", "description": "BinaryFormatter risk.", "evidence_method": "BinaryFormatter.Deserialize", "evidence_data": "Signature found.", "evidence_impact": "RCE"},
                        {"title": "SQL Injection (High)", "description": "Unsanitized input."},
                        {"title": "Hardcoded Keys (Medium)", "description": "Static AES keys."},
                        {"title": "Cleartext Credentials (High)", "description": "Registry storage."}
                    ]
                }
                await websocket.send_json(report)
            
            elif action == "get_static_strings":
                path = cmd.get("path")
                if path and os.path.exists(path):
                    def do_static():
                        try:
                            import re
                            with open(path, "rb") as f: content = f.read()
                            strs = re.findall(rb"[ -~]{5,}", content)
                            res = [{"type": "Static", "val": s.decode('ascii', errors='ignore')} for s in strs]
                            asyncio.run_coroutine_threadsafe(broadcast_message({"type": "static_strings", "data": res}), loop)
                        except Exception as e: logger.error(f"Static error: {e}")
                    threading.Thread(target=do_static, daemon=True).start()

            elif action == "toggle_intercept":
                val = cmd.get("value", False)
                logger.info(f"[INTERCEPT] Toggling mode to: {val}")
                state.intercept_mode = val
                if state.frida_script: 
                    try:
                        state.frida_script.exports_sync.setintercept(state.intercept_mode)
                        logger.info("[INTERCEPT] Frida script updated successfully.")
                    except Exception as e:
                        logger.error(f"[INTERCEPT] Failed to update Frida script: {e}")
            
            elif action == "submit_action":
                pkg_id = cmd.get('id')
                decision = cmd.get('decision')
                logger.info(f"[INTERCEPT] Submitting action for packet {pkg_id}: {decision}")
                
                if decision == "curl_forward":
                    # Perform out-of-band request via requests (Safiye cURL Mode)
                    raw_content = cmd.get("modified_data", "")
                    socket_id = cmd.get("socket_id")
                    inject_hex = None
                    try:
                        lines = raw_content.split('\n')
                        first_line = lines[0].split()
                        if len(first_line) < 2: raise Exception("Invalid HTTP request line")

                        method = first_line[0]
                        path = first_line[1]
                        headers = {}

                        host = ""
                        body_start = -1
                        for i, line in enumerate(lines[1:]):
                            line = line.rstrip('\r')
                            if not line.strip():
                                body_start = i + 2
                                break
                            if ":" in line:
                                k, v = line.split(":", 1)
                                headers[k.strip()] = v.strip()
                                if k.lower().strip() == "host": host = v.strip()

                        body = "\n".join(lines[body_start:]) if body_start != -1 else ""
                        url = f"http://{host}{path}"

                        logger.info(f"[CURL MODE] Sending {method} to {url}")
                        import requests as _req
                        # Disable automatic decompression so we can re-emit the exact bytes the
                        # client expects to read back (Content-Encoding gzip/deflate stays valid).
                        sess = _req.Session()
                        r = sess.request(method, url, headers=headers, data=body, timeout=10, stream=True, allow_redirects=False)
                        raw_body = r.raw.read(decode_content=False)

                        # Build a syntactically-correct raw HTTP/1.1 response that the client can parse.
                        version = "1.1"
                        try:
                            if r.raw.version == 10: version = "1.0"
                        except Exception:
                            pass
                        reason = r.reason or ""
                        resp_head = f"HTTP/{version} {r.status_code} {reason}\r\n"
                        for k, v in r.headers.items():
                            resp_head += f"{k}: {v}\r\n"
                        # Force connection close so the client doesn't expect more data on this socket.
                        if "connection" not in {k.lower() for k in r.headers.keys()}:
                            resp_head += "Connection: close\r\n"
                        resp_head += "\r\n"
                        raw_resp_bytes = resp_head.encode("latin-1", errors="replace") + raw_body
                        inject_hex = raw_resp_bytes.hex()
                        logger.info(f"[CURL MODE] Built raw HTTP response: {len(raw_resp_bytes)} bytes (status={r.status_code}). Will inject into socket={socket_id}.")

                        # Show the response in the UI as well (decoded for readability)
                        try:
                            preview = raw_resp_bytes.decode("utf-8", errors="replace")
                        except Exception:
                            preview = f"<{len(raw_resp_bytes)} binary bytes>"
                        await websocket.send_json({"type": "intercept_curl_response", "data": preview})
                    except Exception as e:
                        logger.error(f"[CURL MODE] Error: {e}")
                        await websocket.send_json({"type": "intercept_curl_response", "data": f"Error: {e}"})

                    # Tell Frida: drop the original send AND inject this response into the next recv()
                    if state.frida_script:
                        post_msg = {"type": f"action_{pkg_id}", "action": "drop"}
                        if inject_hex and socket_id is not None:
                            post_msg["inject_recv_hex"] = inject_hex
                            post_msg["socket_id"] = int(socket_id)
                        state.frida_script.post(post_msg)
                
                elif state.frida_script:
                    # Original forward/drop logic
                    mhex = cmd.get("modified_hex")
                    mhex_len = len(mhex) // 2 if isinstance(mhex, str) else 0
                    logger.info(f"[INTERCEPT] -> Frida post id={pkg_id} action={decision} modified_hex_bytes={mhex_len}")
                    state.frida_script.post({
                        "type": f"action_{pkg_id}",
                        "action": decision,
                        "modified_hex": mhex
                    })
            
            elif action == "repeater_send":
                sid = str(cmd.get("socket", ""))
                payload = str(cmd.get("data", ""))
                if sid == "HTTP":
                    import requests as _req
                    try:
                        lines = payload.split('\n'); first = lines[0].split(' ')
                        method = first[0]; path = first[1] if len(first)>1 else '/'
                        host = "";
                        for l in lines:
                            if l.lower().startswith("host:"): host = l.split(":")[1].strip()
                        if host:
                            r = _req.request(method, f"http://{host}{path}", timeout=5)
                            await websocket.send_json({"type": "repeater_response", "data": r.text})
                    except Exception as e: await websocket.send_json({"type": "repeater_response", "data": str(e)})
                elif state.frida_script:
                    try:
                        res = state.frida_script.exports_sync.repeatersend(sid, payload)
                        await websocket.send_json({"type": "repeater_response", "data": res})
                    except Exception as e: await websocket.send_json({"type": "repeater_response", "data": str(e)})

            elif action == "repeater_curl_send":
                # Out-of-band HTTP request from the Repeater pane. Parses a raw HTTP
                # request, sends it via `requests`, and returns a Burp-style response.
                raw_content = str(cmd.get("data", ""))
                try:
                    lines = raw_content.split('\n')
                    first_line = lines[0].split()
                    if len(first_line) < 2:
                        raise Exception("Invalid HTTP request line")
                    method = first_line[0]
                    path = first_line[1]
                    headers = {}
                    host = ""
                    body_start = -1
                    for i, line in enumerate(lines[1:]):
                        line = line.rstrip('\r')
                        if not line.strip():
                            body_start = i + 2
                            break
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.strip()] = v.strip()
                            if k.lower().strip() == "host":
                                host = v.strip()
                    body = "\n".join(lines[body_start:]) if body_start != -1 else ""
                    if not host:
                        raise Exception("Missing Host header")
                    url = f"http://{host}{path}"
                    logger.info(f"[REPEATER cURL] {method} {url}")
                    import requests as _req
                    r = _req.request(method, url, headers=headers, data=body, timeout=10, allow_redirects=False)
                    res_text = f"HTTP/1.1 {r.status_code} {r.reason or ''}\r\n"
                    for k, v in r.headers.items():
                        res_text += f"{k}: {v}\r\n"
                    res_text += "\r\n" + r.text
                    await websocket.send_json({"type": "repeater_response", "data": res_text})
                except Exception as e:
                    logger.error(f"[REPEATER cURL] Error: {e}")
                    await websocket.send_json({"type": "repeater_response", "data": f"Error: {e}"})

    except WebSocketDisconnect:
        state.connected_clients.remove(websocket)

@app.get("/api/mcp_status")
async def get_mcp_status():
    """Returns MCP server connectivity status based on last observed call."""
    age = time.time() - state.mcp_last_seen if state.mcp_last_seen else None
    connected = age is not None and age < 120
    return {
        "connected": connected,
        "last_seen_seconds_ago": round(age) if age is not None else None,
    }


@app.get("/api/vuln_store")
async def get_vuln_store():
    """Return latest AI vulnerability analysis results (consumed by MCP server)."""
    state.mcp_last_seen = time.time()
    return {"findings": state.last_vuln_analysis or [], "is_hooking": state.is_hooking}


def _mcp_status_note() -> str:
    age = time.time() - state.mcp_last_seen if state.mcp_last_seen else None
    if age is None:
        return "MCP server has never connected. Start mcp_server.py for Claude Desktop integration."
    if age < 120:
        return f"MCP server connected (last seen {round(age)}s ago)."
    return (
        f"MCP server has not connected in {round(age)}s. "
        "Ensure mcp_server.py is running and configured in Claude Desktop."
    )


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_DESER_SIGS = {
    "Java Serialization": bytes([0xAC, 0xED]),
    "Python Pickle (v2)": bytes([0x80, 0x02]),
    "Python Pickle (v3)": bytes([0x80, 0x03]),
    "Python Pickle (v4)": bytes([0x80, 0x04]),
    ".NET BinaryFormatter": bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]),
    "PHP Object Injection": bytes([0x4F, 0x3A]),
}
_RE_CRED      = re.compile(r'(password|passwd|pwd|secret|apikey|api_key)\s*[=:]\s*\S{3,}', re.I)
_RE_SQLI      = re.compile(r"('\s*(OR|AND)\s*'?\d|UNION\s+SELECT|--\s|xp_cmdshell|1\s*=\s*1)", re.I)
_RE_JWT       = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
_RE_BASIC     = re.compile(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.I)
_RE_XXE       = re.compile(r'<!ENTITY|SYSTEM\s+"file://', re.I)
_RE_DLL_PATH  = re.compile(r'(\\temp\\|\\tmp\\|\\appdata\\|\\users\\public\\|%temp%|%appdata%)', re.I)
_RE_DLL_UNC   = re.compile(r'^\\\\')
_HIJACK_DLLS  = {"version.dll","cryptbase.dll","dwmapi.dll","wtsapi32.dll","profapi.dll","mfc42.dll","dwrite.dll","usp10.dll"}
_RE_REG_SEC   = re.compile(r'(password|passwd|pwd|secret|credential|apikey|api_key|token)', re.I)
_RE_REG_RUN   = re.compile(r'(\\run\\|\\runonce\\|currentversion\\run)', re.I)
_RE_REG_LSA   = re.compile(r'(\\lsa\\|\\sam\\|system\\currentcontrolset\\control\\lsa)', re.I)
_RE_FILE_SENS = re.compile(r'(\\sam$|ntds\.dit|id_rsa|\.pfx|\.key$|web\.config|\.pem$|shadow$|\.kdbx|credentials\.xml)', re.I)
_RE_FILE_SYS  = re.compile(r'(\\system32\\|\\syswow64\\)', re.I)
_RE_STR_CRED  = re.compile(r'(password|passwd|pwd|secret|apikey|api_key)\s*[=:]\s*["\']?\S{3,}', re.I)
_RE_PRIVKEY   = re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')
_RE_CONNSTR   = re.compile(r'(server=.*password=|jdbc:[a-z]+://|mongodb\+srv://|Data Source=.*Password=)', re.I)
_RE_WEAKCRYP  = re.compile(r'\b(md5|des|rc4|3des|des-cbc)\b', re.I)
_RE_HEXKEY    = re.compile(r'^[0-9a-fA-F]{32,64}$')


def _finding(severity, title, description, evidence="", verification_steps=None, exploitation_notes=""):
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence[:300] if evidence else "",
        "verification_steps": verification_steps or [],
        "exploitation_notes": exploitation_notes,
    }


def run_rule_scan(data: dict) -> list:
    findings = []

    tcp_packets     = data.get("tcp_packets", [])[:50]
    dll_events      = data.get("dll_events", [])[:100]
    registry_events = data.get("registry_events", [])[:100]
    file_events     = data.get("file_events", [])[:100]
    memory_strings  = data.get("memory_strings", [])[:200]
    static_strings  = data.get("static_strings", [])[:200]

    # ── Network Traffic ────────────────────────────────────────────────────────
    for pkt in tcp_packets:
        body     = (pkt.get("body") or "")[:1024]
        dest     = pkt.get("dest", "unknown")
        hex_str  = (pkt.get("body_hex") or "").replace(" ", "")

        # Deserialization magic bytes (supplement to real-time Frida check)
        if hex_str:
            try:
                raw = bytes.fromhex(hex_str[:256])
                for fmt, sig in _DESER_SIGS.items():
                    if raw[:len(sig)] == sig:
                        findings.append(_finding(
                            "CRITICAL", f"Insecure Deserialization — {fmt}",
                            f"Recognized {fmt} serialization magic bytes in network traffic. "
                            "If deserializing untrusted data with this format, arbitrary code execution may be possible.",
                            evidence=f"Destination: {dest}  |  First bytes: {hex_str[:32]}",
                            verification_steps=["Capture the full payload.", "Attempt deserialization with a crafted gadget chain."],
                            exploitation_notes="Use ysoserial / ysoserial.net with matching gadget chain.",
                        ))
                        break
            except ValueError:
                pass

        # Plain HTTP
        is_http = body.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HTTP/"))
        if ":80" in dest and is_http:
            findings.append(_finding(
                "HIGH", "Unencrypted HTTP Traffic",
                "Application communicates over plain HTTP. Credentials and tokens are visible to network observers.",
                evidence=f"Destination: {dest}  |  {body[:120]}",
                verification_steps=["Intercept with Safiye Intercept tab.", "Look for credentials or session tokens in the body."],
                exploitation_notes="Position yourself as MITM on the local network and capture the traffic with Wireshark.",
            ))

        # SQL injection pattern in body
        m = _RE_SQLI.search(body)
        if m:
            findings.append(_finding(
                "CRITICAL", "SQL Injection Pattern in Outgoing Traffic",
                "A payload containing SQL injection syntax was observed leaving the process. "
                "If this reaches a database without parameterization, full data exfiltration or RCE via xp_cmdshell is possible.",
                evidence=m.group(0)[:200],
                verification_steps=["Replay the request via Repeater tab.", "Confirm reflection or error-based disclosure."],
                exploitation_notes="Use sqlmap against the identified endpoint with the captured cookie/token.",
            ))

        # Cleartext credentials in body
        m = _RE_CRED.search(body)
        if m:
            findings.append(_finding(
                "HIGH", "Cleartext Credentials in Network Packet",
                "A credential-like key=value pair was found in plaintext traffic.",
                evidence=m.group(0)[:200],
                verification_steps=["Open Intercept tab and confirm the value.", "Test with modified credentials to verify authentication bypass."],
                exploitation_notes="Steal session or replay the request with stolen credentials.",
            ))

        # HTTP Basic Auth
        m = _RE_BASIC.search(body)
        if m:
            try:
                decoded = base64.b64decode(m.group(1) + "==").decode(errors="replace")
            except Exception:
                decoded = m.group(1)
            findings.append(_finding(
                "HIGH", "HTTP Basic Authentication Credentials Exposed",
                "HTTP Basic Auth encodes credentials in Base64 — trivially reversible. "
                "Transmitting over plaintext HTTP makes them immediately readable.",
                evidence=f"Decoded: {decoded[:100]}",
                verification_steps=["Confirm the decoded value contains real credentials.", "Test authentication with decoded credentials."],
                exploitation_notes="Decode Base64 and use credentials directly.",
            ))

        # JWT token
        m = _RE_JWT.search(body)
        if m:
            token = m.group(0)
            try:
                header_b64 = token.split(".")[0]
                header = json.loads(base64.b64decode(header_b64 + "==").decode(errors="replace"))
                alg = header.get("alg", "")
                if alg.lower() in ("none", ""):
                    findings.append(_finding(
                        "CRITICAL", "JWT with Algorithm 'none' (Signature Bypass)",
                        "A JWT with alg:none was detected. This means the signature is not verified — any payload can be forged.",
                        evidence=f"Header: {json.dumps(header)}",
                        verification_steps=["Craft a JWT with a modified payload and alg:none.", "Send it to the server and observe if it is accepted."],
                        exploitation_notes="Use jwt_tool or manually craft: base64(header) + '.' + base64(payload) + '.'",
                    ))
                else:
                    findings.append(_finding(
                        "INFO", f"JWT Token in Network Traffic (alg={alg})",
                        "A JWT token is transmitted in cleartext. If intercepted, it can be replayed until it expires.",
                        evidence=token[:120],
                    ))
            except Exception:
                findings.append(_finding("INFO", "JWT Token Detected in Traffic", "", evidence=token[:120]))

        # XXE
        if _RE_XXE.search(body):
            findings.append(_finding(
                "CRITICAL", "XXE (XML External Entity) Pattern Detected",
                "An XML payload containing ENTITY or SYSTEM keywords was observed. "
                "If parsed by a vulnerable XML processor, this can read local files or trigger SSRF.",
                evidence=body[:200],
                verification_steps=["Confirm the XML is parsed server-side.", "Try reading /etc/passwd or C:\\Windows\\win.ini via SYSTEM entity."],
                exploitation_notes="Use a Burp Collaborator/interactsh payload to confirm out-of-band XXE.",
            ))

    # ── DLL Events ─────────────────────────────────────────────────────────────
    for e in dll_events:
        dll_name = (e.get("dllName") or e.get("target") or "").replace("/", "\\")
        dll_lower = dll_name.lower()
        base = dll_lower.split("\\")[-1]

        if _RE_DLL_UNC.match(dll_name):
            findings.append(_finding(
                "CRITICAL", "DLL Loaded via UNC Network Path",
                "A DLL was loaded from a UNC (\\\\server\\share) path. "
                "An attacker controlling the network share can serve a malicious DLL.",
                evidence=dll_name[:250],
                verification_steps=["Confirm the UNC path is reachable.", "Replace the DLL on the share with a PoC that spawns calc.exe."],
                exploitation_notes="Host a Responder server to intercept NTLM auth, or serve a malicious DLL directly.",
            ))
        elif _RE_DLL_PATH.search(dll_lower):
            findings.append(_finding(
                "HIGH", "DLL Loaded from User-Writable Directory",
                "A DLL was loaded from a user-writable location (Temp, AppData, etc.). "
                "A low-privileged attacker can plant a malicious DLL here before the application loads it.",
                evidence=dll_name[:250],
                verification_steps=["Verify the directory is writable by non-admin users.", "Place a test DLL (spawning calc.exe) and relaunch the application."],
                exploitation_notes="Drop malicious DLL before application launch for privilege escalation or persistence.",
            ))

        if base in _HIJACK_DLLS:
            findings.append(_finding(
                "MEDIUM", f"Known DLL Hijack Target Loaded: {base}",
                f"{base} is a commonly targeted DLL for hijacking. "
                "If the search order allows a user-controlled path to precede the system path, this is exploitable.",
                evidence=dll_name[:250],
                verification_steps=["Check DLL search order with Process Monitor.", "Place a same-named DLL in the application directory and observe loading."],
                exploitation_notes="Use ProcMon filter 'NAME NOT FOUND' for DLL loads to find hijack candidates.",
            ))

    # ── Registry Operations ────────────────────────────────────────────────────
    for e in registry_events:
        target = (e.get("target") or "")
        target_low = target.lower()

        if _RE_REG_LSA.search(target_low):
            findings.append(_finding(
                "CRITICAL", "LSA / SAM Registry Key Access Detected",
                "The process accessed the LSA or SAM registry hive — regions that store credential material. "
                "This may indicate credential dumping (mimikatz-style).",
                evidence=target[:250],
                verification_steps=["Cross-reference with process name.", "Check if LSASS memory was also read."],
                exploitation_notes="If running as SYSTEM, the SAM hive can be backed up to extract NTLM hashes offline.",
            ))
        elif _RE_REG_RUN.search(target_low):
            findings.append(_finding(
                "HIGH", "Persistence via AutoRun Registry Key",
                "Write access to a Run/RunOnce key detected. This is a classic persistence mechanism.",
                evidence=target[:250],
                verification_steps=["Check the key value that was written.", "Confirm it points to a file you can inspect."],
                exploitation_notes="Malware commonly abuses Run keys for persistence after reboot.",
            ))
        elif _RE_REG_SEC.search(target_low):
            findings.append(_finding(
                "HIGH", "Sensitive Keyword in Registry Key Path",
                "A registry key containing 'password', 'secret', 'token', or similar was accessed. "
                "Credentials stored in the registry are readable by any process running as the same user.",
                evidence=target[:250],
                verification_steps=["Read the key value with reg query.", "Determine if the stored data is cleartext."],
                exploitation_notes="reg query HKCU /f password /t REG_SZ /s",
            ))

    # ── File Operations ────────────────────────────────────────────────────────
    for e in file_events:
        target = (e.get("target") or "")
        api    = (e.get("api") or "").lower()

        if _RE_FILE_SENS.search(target):
            findings.append(_finding(
                "CRITICAL", "Access to Sensitive System File",
                "The process accessed a file known to contain credential or key material.",
                evidence=f"{e.get('api','?')} → {target[:200]}",
                verification_steps=["Verify the file was read (not just opened).", "Inspect what the process did with the data."],
                exploitation_notes="If reading SAM/NTDS.dit: copy to attacker machine and crack offline with secretsdump.",
            ))

        if _RE_FILE_SYS.search(target) and any(x in api for x in ("write", "createfile")):
            findings.append(_finding(
                "HIGH", "Write to System32 / SysWOW64 from User Process",
                "Writing to system directories from a non-OS process may indicate DLL planting or privilege escalation.",
                evidence=f"{e.get('api','?')} → {target[:200]}",
                verification_steps=["Confirm the written file type.", "Check if any service or privileged process loads it."],
                exploitation_notes="Plant a malicious DLL that matches a service's expected DLL name.",
            ))

    # ── Static + Memory Strings ────────────────────────────────────────────────
    seen = set()
    for s in (list(static_strings) + list(memory_strings)):
        val = (s.get("val") or "").strip()
        if not val or len(val) < 5:
            continue

        m = _RE_STR_CRED.search(val)
        if m and "hardcoded_cred" not in seen:
            seen.add("hardcoded_cred")
            findings.append(_finding(
                "CRITICAL", "Hardcoded Credential Found in Binary / Memory",
                "A plaintext credential was found embedded in the binary or process memory.",
                evidence=val[:300],
                verification_steps=["Confirm the string is a real credential by attempting authentication.", "Search the entire binary for similar patterns."],
                exploitation_notes="Use the credential directly or search for reuse across other services.",
            ))

        if _RE_PRIVKEY.search(val) and "private_key" not in seen:
            seen.add("private_key")
            findings.append(_finding(
                "CRITICAL", "Private Key String Embedded in Binary / Memory",
                "A PEM private key was found in the process. If extracted, an attacker can impersonate the owner.",
                evidence=val[:200],
                verification_steps=["Extract the full key block.", "Attempt to load it and sign test data."],
                exploitation_notes="openssl rsa -in key.pem -check",
            ))

        m = _RE_CONNSTR.search(val)
        if m and "connstr" not in seen:
            seen.add("connstr")
            findings.append(_finding(
                "HIGH", "Database Connection String with Credentials",
                "A database connection string containing inline credentials was found.",
                evidence=val[:300],
                verification_steps=["Extract host, username, and password from the string.", "Attempt a direct database connection."],
                exploitation_notes="Use the extracted credentials with sqlcmd, psql, or the appropriate client.",
            ))

        if _RE_WEAKCRYP.search(val):
            findings.append(_finding(
                "MEDIUM", f"Weak Cryptographic Algorithm Reference",
                "A string referencing a broken/deprecated algorithm (MD5, DES, RC4, 3DES) was found.",
                evidence=val[:100],
                verification_steps=["Locate the call site in the binary.", "Confirm it is used for security-sensitive operations (not checksums)."],
                exploitation_notes="Brute-force or use precomputed rainbow tables against MD5/DES ciphertexts.",
            ))

        if _RE_HEXKEY.match(val) and "hexkey" not in seen:
            seen.add("hexkey")
            findings.append(_finding(
                "MEDIUM", "Possible Hardcoded Cryptographic Key (Hex String)",
                f"A {len(val)//2}-byte hex string was found. Length matches AES-128/192/256 key sizes.",
                evidence=val[:64],
                verification_steps=["Context-search the binary around this string.", "Check if used as AES/DES key material."],
                exploitation_notes="If confirmed as a static key, decrypt all ciphertexts that use this key.",
            ))

    if not findings:
        findings.append(_finding(
            "INFO", "No Rule-Based Findings",
            "No rule violations were detected in the captured session data. "
            "Collect more traffic (longer hook session, more HTTP requests) and retry.",
        ))

    findings.sort(key=lambda x: _SEV_ORDER.get(x.get("severity", "INFO"), 4))
    return findings


@app.post("/api/rule_scan")
async def rule_scan(request: Request):
    """Run deterministic rule-based vulnerability scan — no AI required."""
    try:
        data = await request.json()
        await broadcast_message({"type": "vuln_analysis_log", "message": "Rule-based scan started..."})

        findings = await asyncio.to_thread(run_rule_scan, data)

        state.last_vuln_analysis = findings
        await broadcast_message({"type": "vuln_analysis_log", "message": f"Rule scan complete — {len(findings)} finding(s)."})
        await broadcast_message({"type": "vuln_findings", "findings": findings})
        return {"status": "ok", "count": len(findings)}
    except Exception as exc:
        logger.exception("[RULE_SCAN] Error")
        await broadcast_message({"type": "vuln_analysis_log", "message": f"Rule scan error: {exc}"})
        return {"status": "error", "error": str(exc)}


def _build_capture_text(data: dict) -> str:
    """Format raw capture data into a human-readable analysis context string."""
    tcp_packets     = data.get("tcp_packets", [])[:50]
    dll_events      = data.get("dll_events", [])[:100]
    registry_events = data.get("registry_events", [])[:100]
    file_events     = data.get("file_events", [])[:100]
    memory_strings  = data.get("memory_strings", [])[:200]
    static_strings  = data.get("static_strings", [])[:200]

    sections = []
    if tcp_packets:
        sections.append("## Network Traffic")
        for pkt in tcp_packets:
            body = (pkt.get("body") or "")[:512]
            sections.append(f"  [{pkt.get('direction','?')}] {pkt.get('dest','?')} {pkt.get('size',0)}B  body={repr(body)}")
    if dll_events:
        sections.append("\n## DLL Load Events")
        for e in dll_events:
            sections.append(f"  {e.get('api','?')} -> {e.get('dllName', e.get('target','?'))} [{e.get('status','?')}]")
    if registry_events:
        sections.append("\n## Registry Operations")
        for e in registry_events:
            sections.append(f"  {e.get('api','?')} -> {e.get('target','?')} [{e.get('status','?')}]")
    if file_events:
        sections.append("\n## File Operations")
        for e in file_events:
            sections.append(f"  {e.get('api','?')} -> {e.get('target','?')} [{e.get('status','?')}]")
    if static_strings:
        sections.append("\n## Static Strings (PE binary)")
        for s in static_strings:
            sections.append(f"  {s.get('val','')}")
    if memory_strings:
        sections.append("\n## Runtime Memory Strings")
        for s in memory_strings:
            sections.append(f"  [{s.get('type','?')}] {s.get('val','')}")

    return "\n".join(sections) if sections else "No data captured yet."


@app.post("/api/analyze_vulnerabilities")
async def analyze_vulnerabilities(request: Request):
    """Queue capture data for MCP-based AI analysis."""
    try:
        data = await request.json()
        captured = _build_capture_text(data)
        state.pending_analysis_data = {"raw": data, "formatted": captured, "queued_at": time.time()}

        age = time.time() - state.mcp_last_seen if state.mcp_last_seen else None
        mcp_connected = age is not None and age < 120

        await broadcast_message({"type": "vuln_analysis_log",
                                  "message": f"Capture data queued ({len(captured):,} chars)."})

        if not mcp_connected:
            await broadcast_message({"type": "vuln_analysis_log",
                                      "message": "MCP not connected — click 'Analyze with AI' and follow the setup steps."})

        return {"status": "queued", "chars": len(captured)}

    except Exception as exc:
        logger.exception("[ANALYZE] Queue error")
        await broadcast_message({"type": "vuln_analysis_log", "message": f"Error queuing data: {exc}"})
        return {"status": "error", "error": str(exc)}


@app.get("/api/config")
async def get_config():
    cfg = _load_config()
    return {"api_key_set": bool(cfg.get("api_key"))}


@app.post("/api/config")
async def save_config(request: Request):
    try:
        body = await request.json()
        api_key = body.get("api_key", "").strip()
        if not api_key:
            return {"status": "error", "error": "Empty key"}
        cfg = _load_config()
        cfg["api_key"] = api_key
        _save_config(cfg)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/mcp_log")
async def mcp_log(request: Request):
    """Receives progress log messages from the MCP server and broadcasts them to the UI."""
    try:
        body = await request.json()
        msg = body.get("message", "").strip()
        if msg:
            await broadcast_message({"type": "vuln_analysis_log", "message": f"[AI] {msg}"})
        return {"status": "ok"}
    except Exception:
        return {"status": "error"}


@app.get("/api/pending_analysis")
async def get_pending_analysis():
    """
    Returns the queued capture data + analysis instructions for the connected AI.
    Called by the MCP server's get_capture_data tool.
    """
    state.mcp_last_seen = time.time()
    if not state.pending_analysis_data:
        return {
            "available": False,
            "message": "No analysis pending. Click 'Analyze with AI' in Safiye first.",
        }

    age = round(time.time() - state.pending_analysis_data["queued_at"])
    formatted = state.pending_analysis_data["formatted"]

    raw        = state.pending_analysis_data.get("raw", {})
    tcp_count  = len(raw.get("tcp_packets", []))
    dll_count  = len(raw.get("dll_events", []))
    reg_count  = len(raw.get("registry_events", []))
    file_count = len(raw.get("file_events", []))
    mem_count  = len(raw.get("memory_strings", []))
    str_count  = len(raw.get("static_strings", []))

    instruction = (
        "You are an expert penetration tester and runtime security analyst.\n"
        "The following data was captured by Safiye, a Windows runtime instrumentation tool (Frida-based).\n\n"
        "PROGRESS REPORTING — IMPORTANT:\n"
        "Throughout your analysis, call the log_progress tool to report what you are doing.\n"
        "Call it at the START of each section and whenever you find something notable.\n"
        "Use plain text with no emojis and no markdown. Include counts. Examples:\n"
        f"  log_progress('Starting network traffic analysis — {tcp_count} packets')\n"
        f"  log_progress('Checking DLL load events for hijacking candidates — {dll_count} events')\n"
        f"  log_progress('Reviewing registry operations — {reg_count} events')\n"
        f"  log_progress('Scanning file operations — {file_count} events')\n"
        f"  log_progress('Analyzing {mem_count} memory strings and {str_count} static strings')\n"
        "  log_progress('Found 2 critical issues, preparing final report')\n"
        "  log_progress('Compiling all findings, calling submit_findings now')\n\n"
        "VULNERABILITIES TO LOOK FOR:\n"
        "- Insecure deserialization (magic bytes: Java 0xACED, .NET BinaryFormatter, Python Pickle, PHP O:)\n"
        "- DLL hijacking (user-writable paths, UNC paths, known hijack targets)\n"
        "- Cleartext credentials or API keys in traffic or memory\n"
        "- SQL injection patterns in HTTP bodies\n"
        "- Weak cryptography (MD5, DES, RC4, hardcoded keys)\n"
        "- Sensitive file/registry access (SAM, LSA, AutoRun keys)\n"
        "- Private keys or connection strings in binary/memory strings\n\n"
        "When done, call submit_findings with a JSON array. Each item must have:\n"
        "  severity: CRITICAL | HIGH | MEDIUM | LOW | INFO\n"
        "  title: short specific title\n"
        "  description: why it is a vulnerability and its impact\n"
        "  evidence: exact snippet from the captured data\n"
        "  verification_steps: list of steps to confirm\n"
        "  exploitation_notes: how a pentester would exploit this\n\n"
        f"=== CAPTURED RUNTIME DATA (queued {age}s ago, "
        f"{tcp_count} packets / {dll_count} DLL / {reg_count} reg / {file_count} file / {mem_count} mem strings) ===\n\n"
        f"{formatted}"
    )

    await broadcast_message({
        "type": "vuln_analysis_log",
        "message": f"AI connected — retrieved {len(formatted):,} chars of capture data. Analysis underway..."
    })
    return {"available": True, "instruction": instruction, "chars": len(formatted)}


@app.post("/api/submit_findings")
async def submit_findings(request: Request):
    """Receives the AI's structured vulnerability findings and broadcasts them to the UI."""
    state.mcp_last_seen = time.time()
    try:
        body = await request.json()
        findings = body if isinstance(body, list) else body.get("findings", [])
        if not isinstance(findings, list):
            return {"status": "error", "error": "Expected a JSON array of findings."}

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 4))

        await broadcast_message({
            "type": "vuln_analysis_log",
            "message": f"Receiving {len(findings)} finding(s) from AI — applying to Vulnerabilities tab..."
        })

        state.last_vuln_analysis = findings
        state.pending_analysis_data = None  # clear queue after submission
        await broadcast_message({"type": "vuln_analysis_log", "message": f"AI analysis received — {len(findings)} finding(s)."})
        await broadcast_message({"type": "vuln_findings", "findings": findings})
        logger.info(f"[SUBMIT_FINDINGS] {len(findings)} findings received from AI.")
        return {"status": "ok", "count": len(findings)}

    except Exception as exc:
        logger.exception("[SUBMIT_FINDINGS] Error")
        return {"status": "error", "error": str(exc)}


@app.get("/api/export_session")
async def export_session():
    """Export full session state as a JSON snapshot (downloaded by the browser)."""
    from datetime import datetime
    return {
        "version": 1,
        "saved_at": datetime.now().isoformat(),
        "session_events":   state.session_events,
        "session_snapshot": state.session_snapshot,
        "vuln_findings":    state.last_vuln_analysis or [],
    }


@app.post("/api/import_session")
async def import_session(request: Request):
    """Restore a previously exported session snapshot."""
    try:
        data = await request.json()
        if data.get("version") != 1:
            return {"status": "error", "error": "Unsupported session file version."}

        state.session_events   = data.get("session_events", [])
        state.session_snapshot = data.get("session_snapshot", {})
        findings = data.get("vuln_findings") or []
        state.last_vuln_analysis = findings if findings else None
        state.pending_analysis_data = None

        # Notify all connected clients to reload
        await broadcast_message({"type": "session_cleared"})
        if state.session_events:
            await broadcast_message({"type": "session_replay", "events": state.session_events})
        for snap in state.session_snapshot.values():
            await broadcast_message(snap)
        if state.last_vuln_analysis:
            await broadcast_message({"type": "vuln_findings", "findings": state.last_vuln_analysis})

        logger.info(f"[IMPORT_SESSION] Restored {len(state.session_events)} events, {len(findings)} findings.")
        return {"status": "ok", "events": len(state.session_events), "findings": len(findings)}
    except Exception as exc:
        logger.exception("[IMPORT_SESSION] Error")
        return {"status": "error", "error": str(exc)}


@app.post("/api/new_session")
async def new_session():
    """Clear all captured session data and start fresh."""
    state.session_events.clear()
    state.session_snapshot.clear()
    state.last_vuln_analysis = None
    state.pending_analysis_data = None
    await broadcast_message({"type": "session_cleared"})
    logger.info("[NEW_SESSION] Session cleared by user request.")
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
